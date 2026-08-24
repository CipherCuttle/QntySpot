"""Offline hostile tests for the bounded V0C Solana/Jupiter substrate."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes
from qntyspot.economics import build_intent
from qntyspot.domain import Side
from qntyspot.errors import SafeHaltError, SolanaError, SolanaProtocolError
from qntyspot.policy import load_policy_file
from qntyspot.raw_evidence import RawEvidenceStore
from qntyspot.solana import (
    JUPITER_SWAP_V2_BUILD_ENDPOINT,
    QUALIFICATION_TAKER_ADDRESS,
    SOLANA_MAINNET_RPC_ENDPOINT,
    SPL_TOKEN_PROGRAM_ADDRESS,
    TOKEN_2022_PROGRAM_ADDRESS,
    JupiterV2Client,
    SolanaMarketObservationV0,
    SolanaRpcClient,
    SolanaShadowAdapter,
    load_decision,
    load_observation,
    policy_min_threshold_atomic,
    persist_decision,
    persist_observation,
    replay_shadow_decision,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "qualifications/solana_v0c/sol_usdc_buy.policy.json"
WSOL = "So11111111111111111111111111111111111111112"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
AMM = QUALIFICATION_TAKER_ADDRESS


def mint_bytes(decimals: int) -> str:
    data = bytearray(82)
    data[36:44] = (9_000_000_000_000).to_bytes(8, "little")
    data[44] = decimals
    data[45] = 1
    return base64.b64encode(bytes(data)).decode("ascii")


class FakeSolana:
    def __init__(self, *, owner: str = SPL_TOKEN_PROGRAM_ADDRESS, output_decimals: int = 6) -> None:
        self.owner = owner
        self.output_decimals = output_decimals
        self.calls = 0

    def __call__(self, payload: bytes) -> bytes:
        self.calls += 1
        request = json.loads(payload)
        method = request["method"]
        if method == "getLatestBlockhash":
            slot = 100 if self.calls == 1 else 101
            result = {
                "context": {"slot": slot},
                "value": {
                    "blockhash": QUALIFICATION_TAKER_ADDRESS,
                    "lastValidBlockHeight": 1150,
                },
            }
        elif method == "getBlockHeight":
            result = 1000 if self.calls <= 2 else 1001
        elif method == "getMultipleAccounts":
            result = {
                "context": {"slot": 100},
                "value": [
                    {
                        "data": [mint_bytes(9), "base64"],
                        "executable": False,
                        "lamports": 1,
                        "owner": self.owner,
                        "rentEpoch": 0,
                        "space": 82,
                    },
                    {
                        "data": [mint_bytes(self.output_decimals), "base64"],
                        "executable": False,
                        "lamports": 1,
                        "owner": self.owner,
                        "rentEpoch": 0,
                        "space": 82,
                    },
                ],
            }
        else:  # pragma: no cover - protects the fake from API drift
            raise AssertionError(method)
        return canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "result": result})


def build_response(*, route_bps: int = 10_000, include_alt: bool = False) -> dict[str, object]:
    instruction = {
        "programId": SPL_TOKEN_PROGRAM_ADDRESS,
        "accounts": [
            {"pubkey": QUALIFICATION_TAKER_ADDRESS, "isWritable": False, "isSigner": True}
        ],
        "data": "AA==",
    }
    response: dict[str, object] = {
        "inputMint": WSOL,
        "outputMint": USDC,
        "inAmount": "1000000000",
        "outAmount": "150000000",
        "otherAmountThreshold": "149250000",
        "swapMode": "ExactIn",
        "slippageBps": 50,
        "priceImpactPct": "0.001",
        "routePlan": [
            {
                "swapInfo": {
                    "ammKey": AMM,
                    "label": "Fixture AMM",
                    "inputMint": WSOL,
                    "outputMint": USDC,
                    "inAmount": "1000000000",
                    "outAmount": "150000000",
                },
                "percent": 100,
                "bps": route_bps,
            }
        ],
        "computeBudgetInstructions": [instruction],
        "setupInstructions": [],
        "swapInstruction": instruction,
        "cleanupInstruction": None,
        "otherInstructions": [],
        "tipInstruction": None,
        "addressesByLookupTableAddress": {
            AMM: [QUALIFICATION_TAKER_ADDRESS]
        } if include_alt else {},
        "blockhashWithMetadata": {
            "blockhash": list(range(32)),
            "lastValidBlockHeight": 1150,
            "fetchedAt": {"secs_since_epoch": 1700000090, "nanos_since_epoch": 0},
        },
    }
    return response


class FakeJupiter:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.calls = 0

    def __call__(self, _url: str, _query: bytes) -> bytes:
        self.calls += 1
        return canonical_json_bytes(self.response)


def make_adapter(*, solana: FakeSolana | None = None, jupiter_response: dict[str, object] | None = None):
    rpc = SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, transport=solana or FakeSolana())
    jup = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=FakeJupiter(jupiter_response or build_response()),
    )
    return SolanaShadowAdapter(rpc, jup)


def test_jupiter_usd_metadata_float_is_text_only_and_not_economic() -> None:
    response = build_response()
    response["routePlan"][0]["usdValue"] = 5.84  # type: ignore[index]
    client = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=lambda _url, _query: json.dumps(response).encode("utf-8"),
    )
    parsed = client.build(
        input_mint=WSOL,
        output_mint=USDC,
        amount_atomic=1_000_000_000,
        taker=QUALIFICATION_TAKER_ADDRESS,
        slippage_bps=50,
    )
    assert parsed["route_plan"][0]["usdValue"] == "5.84"


def test_raw_jupiter_evidence_is_persisted_before_semantic_rejection(tmp_path: Path) -> None:
    response = build_response()
    response["unexpected"] = True
    wire = json.dumps(response, separators=(",", ":")).encode("utf-8")
    store = RawEvidenceStore(tmp_path / "raw", max_response_bytes=2_000_000, max_total_bytes=2_000_000, max_records=4)
    client = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=lambda _url, _query: wire,
        evidence_store=store,
    )
    with pytest.raises(SolanaProtocolError, match="fields are not exact"):
        client.build(
            input_mint=WSOL,
            output_mint=USDC,
            amount_atomic=1_000_000_000,
            taker=QUALIFICATION_TAKER_ADDRESS,
            slippage_bps=50,
        )
    assert len(client.evidence_records) == 1
    record = client.evidence_records[0]
    assert store.read(record) == wire
    assert record.response_sha256 == hashlib.sha256(wire).hexdigest()
    assert "headers" not in record.request
    index_path = tmp_path / "raw-index.json"
    assert store.persist_index(index_path, [record])
    loaded = RawEvidenceStore.load_index(index_path)
    assert len(loaded) == 1
    assert loaded[0].response_sha256 == record.response_sha256


def test_raw_evidence_is_bounded_and_immutable(tmp_path: Path) -> None:
    store = RawEvidenceStore(tmp_path / "raw", max_response_bytes=256, max_total_bytes=256, max_records=1)
    request_body = b'{"jsonrpc":"2.0"}'
    record = store.capture(
        endpoint=SOLANA_MAINNET_RPC_ENDPOINT,
        method="POST",
        request_target=SOLANA_MAINNET_RPC_ENDPOINT,
        request_body=request_body,
        response_body=b"{}",
    )
    assert store.read(record) == b"{}"
    with pytest.raises(SolanaError, match="exceeds"):
        store.capture(
            endpoint=SOLANA_MAINNET_RPC_ENDPOINT,
            method="POST",
            request_target=SOLANA_MAINNET_RPC_ENDPOINT,
            request_body=request_body,
            response_body=b"x" * 257,
        )
    response_path = tmp_path / "raw" / record.response_path
    response_path.write_bytes(b"changed")
    with pytest.raises(SafeHaltError, match="digest mismatch"):
        store.read(record)


def test_live_shape_reaches_would_execute_and_records_exact_identity() -> None:
    policy = load_policy_file(POLICY_PATH)
    adapter = make_adapter(jupiter_response=build_response(include_alt=True))
    observation = adapter.observe(
        policy,
        "qualification-cycle",
        "SOL-USDC-1",
        now_epoch_s=1_700_000_100,
        taker=QUALIFICATION_TAKER_ADDRESS,
    )
    decision = adapter.shadow_decision(
        policy,
        "qualification-cycle",
        "SOL-USDC-1",
        now_epoch_s=1_700_000_100,
        observation=observation,
    )
    assert decision.decision == "WOULD_EXECUTE"
    assert observation.input_mint == WSOL
    assert observation.output_mint == USDC
    assert observation.input_decimals == 9
    assert observation.output_decimals == 6
    assert observation.input_token_program.value == "SPL_TOKEN"
    assert observation.transaction_semantics == "VERSION_0_ADDRESS_LOOKUP_TABLES"
    assert observation.program_ids == (SPL_TOKEN_PROGRAM_ADDRESS,)
    assert observation.requested_slippage_bps == 50
    assert observation.policy_min_threshold_atomic == 149_250_000
    assert observation.venue_threshold_atomic == 149_250_000
    assert decision.economic_action_id


def test_empty_lookup_map_is_not_silently_called_legacy() -> None:
    policy = load_policy_file(POLICY_PATH)
    observation = make_adapter(jupiter_response=build_response(include_alt=False)).observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    assert observation.transaction_semantics == "INLINE_ADDRESSES_ONLY_NOT_A_LEGACY_ASSERTION"


def test_token_2022_owner_cannot_be_confused_with_spl_token() -> None:
    policy = load_policy_file(POLICY_PATH)
    with pytest.raises(SafeHaltError, match="token-program"):
        make_adapter(solana=FakeSolana(owner=TOKEN_2022_PROGRAM_ADDRESS)).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )


def test_decimals_must_match_the_policy_not_a_display_label() -> None:
    policy = load_policy_file(POLICY_PATH)
    with pytest.raises(SafeHaltError, match="decimals"):
        make_adapter(solana=FakeSolana(output_decimals=9)).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )


def test_route_split_must_sum_to_ten_thousand_bps() -> None:
    policy = load_policy_file(POLICY_PATH)
    with pytest.raises(SafeHaltError, match="10000"):
        make_adapter(jupiter_response=build_response(route_bps=9999)).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )


def test_malformed_response_unknown_fields_and_serialized_payload_fail_closed() -> None:
    policy = load_policy_file(POLICY_PATH)
    unknown = build_response()
    unknown["unexpected"] = True
    with pytest.raises(SolanaProtocolError, match="fields are not exact"):
        make_adapter(jupiter_response=unknown).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )
    serialized = build_response()
    serialized["transaction"] = "AQ=="
    with pytest.raises(SafeHaltError, match="serialized"):
        make_adapter(jupiter_response=serialized).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )


def test_stale_slot_abstains_deterministically() -> None:
    policy = load_policy_file(POLICY_PATH)
    adapter = make_adapter()
    observation = adapter.observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    decision = adapter.shadow_decision(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100,
        observation=observation, current_slot=observation.slot_after + 151,
    )
    assert decision.decision == "ABSTAIN"
    assert "STALE_SLOT" in decision.reason_code


def test_rpc_surface_rejects_non_read_methods() -> None:
    adapter = make_adapter()
    with pytest.raises(SolanaProtocolError, match="method"):
        adapter.rpc._rpc.request("sendTransaction", [])


def test_quote_rechecks_exact_size_and_fetched_at_freshness() -> None:
    policy = load_policy_file(POLICY_PATH)
    adapter = make_adapter()
    observation = adapter.observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    bounds = build_intent(
        policy, "cycle", policy.level("SOL-USDC-1"), now_epoch_s=1_700_000_100
    ).bounds
    with pytest.raises(SafeHaltError, match="input size"):
        adapter.quote(replace(bounds, max_input_atomic=bounds.max_input_atomic + 1), now_epoch_s=1_700_000_100)
    with pytest.raises(SafeHaltError, match="stale"):
        adapter.quote(bounds, now_epoch_s=1_700_000_191)
    with pytest.raises(SafeHaltError, match="side"):
        adapter.quote(replace(bounds, side=Side.SELL), now_epoch_s=1_700_000_100)


def test_observation_decimal_fields_are_bound_to_mint_evidence() -> None:
    policy = load_policy_file(POLICY_PATH)
    observation = make_adapter().observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    with pytest.raises(SafeHaltError, match="decimals"):
        replace(observation, input_decimals=0)


def test_route_pair_and_amounts_must_reconcile_with_top_level_quote() -> None:
    policy = load_policy_file(POLICY_PATH)
    wrong_pair = build_response()
    wrong_pair["routePlan"][0]["swapInfo"]["inputMint"] = USDC  # type: ignore[index]
    with pytest.raises(SafeHaltError, match="requested pair"):
        make_adapter(jupiter_response=wrong_pair).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )
    wrong_amount = copy.deepcopy(build_response())
    wrong_amount["routePlan"][0]["swapInfo"]["outAmount"] = "149000000"  # type: ignore[index]
    with pytest.raises(SafeHaltError, match="reconcile"):
        make_adapter(jupiter_response=wrong_amount).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )


def test_multi_hop_route_conserves_intermediate_amounts() -> None:
    policy = load_policy_file(POLICY_PATH)
    response = copy.deepcopy(build_response())
    intermediate = QUALIFICATION_TAKER_ADDRESS
    response["routePlan"] = [
        {
            "swapInfo": {
                "ammKey": AMM,
                "label": "First hop",
                "inputMint": WSOL,
                "outputMint": intermediate,
                "inAmount": "1000000000",
                "outAmount": "150000000",
            },
            "percent": 100,
            "bps": 10000,
        },
        {
            "swapInfo": {
                "ammKey": AMM,
                "label": "Second hop",
                "inputMint": intermediate,
                "outputMint": USDC,
                "inAmount": "150000000",
                "outAmount": "150000000",
            },
            "percent": 100,
            "bps": 10000,
        },
    ]
    observation = make_adapter(jupiter_response=response).observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    assert len(observation.route_plan) == 2


def test_replay_and_persistence_are_byte_deterministic(tmp_path: Path) -> None:
    policy = load_policy_file(POLICY_PATH)
    adapter = make_adapter()
    observation = adapter.observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    decision = adapter.shadow_decision(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, observation=observation
    )
    obs_path = tmp_path / "obs.json"
    decision_path = tmp_path / "decision.json"
    persist_observation(obs_path, observation)
    persist_decision(decision_path, decision)
    loaded_observation = load_observation(obs_path)
    loaded_decision = load_decision(decision_path)
    replayed = replay_shadow_decision(
        policy, loaded_observation, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100,
    )
    assert loaded_observation.digest() == observation.digest()
    assert loaded_decision.digest() == decision.digest()
    assert replayed.canonical_object() == decision.canonical_object()


@pytest.mark.parametrize(
    ("out_amount", "slippage_bps", "expected"),
    [
        (10_000, 0, 10_000),
        (94_834_630, 50, 94_360_457),
        (1, 1, 1),
        (1, 10_000, 0),
        ((1 << 64) - 1, 0, (1 << 64) - 1),
        ((1 << 64) - 1, 10_000, 0),
    ],
)
def test_exact_in_policy_threshold_is_integer_ceiling(
    out_amount: int, slippage_bps: int, expected: int
) -> None:
    assert policy_min_threshold_atomic(out_amount, slippage_bps) == expected


def _parse_threshold_response(*, out_amount: int, threshold: int, slippage_bps: int) -> dict[str, object]:
    response = build_response()
    response["outAmount"] = str(out_amount)
    response["otherAmountThreshold"] = str(threshold)
    response["slippageBps"] = slippage_bps
    response["routePlan"][0]["swapInfo"]["outAmount"] = str(out_amount)  # type: ignore[index]
    client = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=FakeJupiter(response),
    )
    return client.build(
        input_mint=WSOL,
        output_mint=USDC,
        amount_atomic=1_000_000_000,
        taker=QUALIFICATION_TAKER_ADDRESS,
        slippage_bps=slippage_bps,
    )


@pytest.mark.parametrize(
    ("threshold", "accepted"),
    [
        (94_360_456, False),
        (94_360_457, True),
        (94_360_458, True),
        (94_834_630, True),
        (94_834_631, False),
        (0, False),
    ],
)
def test_exact_in_threshold_is_policy_ceiling_boundary_and_not_venue_equality(
    threshold: int, accepted: bool
) -> None:
    if accepted:
        parsed = _parse_threshold_response(
            out_amount=94_834_630, threshold=threshold, slippage_bps=50
        )
        assert parsed["requested_slippage_bps"] == 50
        assert parsed["policy_min_threshold_atomic"] == 94_360_457
        assert parsed["venue_threshold_atomic"] == threshold
    else:
        with pytest.raises(SafeHaltError):
            _parse_threshold_response(
                out_amount=94_834_630, threshold=threshold, slippage_bps=50
            )


def test_exact_in_threshold_boundary_values_and_large_uint64_output() -> None:
    assert _parse_threshold_response(out_amount=7, threshold=7, slippage_bps=0)[
        "policy_min_threshold_atomic"
    ] == 7
    assert _parse_threshold_response(out_amount=7, threshold=1, slippage_bps=10_000)[
        "policy_min_threshold_atomic"
    ] == 0
    assert _parse_threshold_response(
        out_amount=(1 << 64) - 1, threshold=(1 << 64) - 1, slippage_bps=0
    )["venue_threshold_atomic"] == (1 << 64) - 1


def test_frozen_r1_jupiter_response_replays_through_repaired_parser() -> None:
    evidence_root = ROOT / "qualifications/solana_v0c/RAW_EVIDENCE_V0"
    store = RawEvidenceStore(evidence_root)
    records = RawEvidenceStore.load_index(ROOT / "qualifications/solana_v0c/RAW_EVIDENCE_INDEX_V0.json")
    record = next(item for item in records if item.request["method"] == "GET")
    raw = store.read(record)
    client = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=lambda _url, _query: raw,
    )
    parsed = client.build(
        input_mint=WSOL,
        output_mint=USDC,
        amount_atomic=1_000_000_000,
        taker=QUALIFICATION_TAKER_ADDRESS,
        slippage_bps=50,
    )
    assert parsed["out_amount_atomic"] == 94_834_630
    assert parsed["requested_slippage_bps"] == 50
    assert parsed["policy_min_threshold_atomic"] == 94_360_457
    assert parsed["venue_threshold_atomic"] == 94_360_457


def test_frozen_r1_response_produces_observation_decision_and_deterministic_replay() -> None:
    evidence_root = ROOT / "qualifications/solana_v0c/RAW_EVIDENCE_V0"
    store = RawEvidenceStore(evidence_root)
    records = RawEvidenceStore.load_index(ROOT / "qualifications/solana_v0c/RAW_EVIDENCE_INDEX_V0.json")
    record = next(item for item in records if item.request["method"] == "GET")
    raw = store.read(record)
    rpc = SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, transport=FakeSolana())
    jupiter = JupiterV2Client(
        JUPITER_SWAP_V2_BUILD_ENDPOINT,
        transport=lambda _url, _query: raw,
    )
    adapter = SolanaShadowAdapter(rpc, jupiter)
    policy = load_policy_file(POLICY_PATH)
    observation = adapter.observe(
        policy,
        "r1-frozen-replay",
        "SOL-USDC-1",
        now_epoch_s=1_787_555_056,
        taker=QUALIFICATION_TAKER_ADDRESS,
    )
    decision = adapter.shadow_decision(
        policy,
        "r1-frozen-replay",
        "SOL-USDC-1",
        now_epoch_s=1_787_555_056,
        observation=observation,
    )
    replayed = replay_shadow_decision(
        policy,
        observation,
        "r1-frozen-replay",
        "SOL-USDC-1",
        now_epoch_s=1_787_555_056,
    )
    assert observation.schema == "SOLANA_MARKET_OBSERVATION_V0"
    assert decision.schema == "SHADOW_DECISION_V0"
    assert decision.decision == "ABSTAIN"
    assert decision.reason_code == "MIN_OUTPUT_BOUND+MAX_EXECUTABLE_PRICE"
    assert replayed.canonical_object() == decision.canonical_object()


def test_jupiter_stricter_threshold_is_accepted_and_looser_threshold_halts() -> None:
    response = build_response()
    response["otherAmountThreshold"] = "149250001"
    policy = load_policy_file(POLICY_PATH)
    observation = make_adapter(jupiter_response=response).observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    assert observation.policy_min_threshold_atomic == 149_250_000
    assert observation.venue_threshold_atomic == 149_250_001

    response["otherAmountThreshold"] = "149249999"
    with pytest.raises(SafeHaltError, match="policy minimum"):
        make_adapter(jupiter_response=response).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )
