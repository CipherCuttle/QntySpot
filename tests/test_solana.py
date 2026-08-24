"""Offline hostile tests for the bounded V0C Solana/Jupiter substrate."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes
from qntyspot.economics import build_intent
from qntyspot.domain import Side
from qntyspot.errors import SafeHaltError, SolanaProtocolError
from qntyspot.policy import load_policy_file
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


def test_jupiter_threshold_rounding_is_floor_and_policy_bound_is_separate() -> None:
    response = build_response()
    response["otherAmountThreshold"] = "149250001"
    policy = load_policy_file(POLICY_PATH)
    with pytest.raises(SafeHaltError, match="rounding"):
        make_adapter(jupiter_response=response).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )
