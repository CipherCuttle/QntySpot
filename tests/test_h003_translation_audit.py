"""Offline H003 subtask-E regression tests: instrument translation audit.

Pins the mechanical LONG/FLAT -> side mapping of the frozen
``sol_usdc_buy.policy.json`` (base=USDC, quote=WSOL, side=BUY), the exact
direction preservation of the mapped price convention, fail-closed behavior
under mutated mappings, and the non-reusability of the frozen BUY-direction
Jupiter fixture as LONG-entry (SELL-direction) evidence.

No network: every transport is a local fake and tests/conftest.py disables
sockets for the whole session.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from fractions import Fraction
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes
from qntyspot.domain import Side
from qntyspot.errors import SafeHaltError
from qntyspot.policy import load_policy_file
from qntyspot.solana import (
    JUPITER_SWAP_V2_BUILD_ENDPOINT,
    QUALIFICATION_TAKER_ADDRESS,
    SOLANA_MAINNET_RPC_ENDPOINT,
    SPL_TOKEN_PROGRAM_ADDRESS,
    JupiterV2Client,
    SolanaMarketObservationV0,
    SolanaRpcClient,
    SolanaShadowAdapter,
    _human_price,
    policy_min_threshold_atomic,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "qualifications/solana_v0c/sol_usdc_buy.policy.json"
AUDIT_PATH = ROOT / "qualifications/h003_bridge_v0/INSTRUMENT_TRANSLATION_AUDIT_V0.json"
DOC_PATH = ROOT / "docs/SOLANA_V0C.md"
FIXTURE_MANIFEST = (
    ROOT
    / "qualifications/solana_v0c/RAW_EVIDENCE_V0/manifests/"
    / "e8026c941442c95c8140918d188a9f35fcaa016d32db6e24aec7551432f66a1b"
    "-e15a23ae4934990954151588dc8743c90bbbf6a6178407543f0c46f9e0e62a78.json"
)

WSOL = "So11111111111111111111111111111111111111112"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
AMM = QUALIFICATION_TAKER_ADDRESS

# H003 upstream directions mapped onto THIS policy's sides. Derived
# mechanically: LONG acquires the research base asset SOL, which on this
# policy is the execution quote WSOL, and the side whose (input, output)
# refs receive WSOL is Side.SELL (SolanaShadowAdapter._refs). FLAT is the
# opposite side. If any of this regresses, these tests fail closed.
LONG_TO_SIDE = Side.SELL  # ExactIn USDC -> WSOL
FLAT_TO_SIDE = Side.BUY  # ExactIn WSOL -> USDC


def _audit() -> dict:
    return json.loads(AUDIT_PATH.read_text(encoding="utf-8"))


def _no_floats(obj: object) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise AssertionError("audit JSON contains a float")
    if isinstance(obj, dict):
        for value in obj.values():
            _no_floats(value)
    elif isinstance(obj, list):
        for value in obj:
            _no_floats(value)


def _validate_audit_mapping(audit: dict, policy_path: Path = POLICY_PATH) -> None:
    """Audit validator: every recorded mapping must be re-derivable from the
    frozen policy via the adapter's own side->(input, output) resolution.
    Any mutation (wrong mint, wrong decimals, inverted direction) raises."""
    policy = load_policy_file(policy_path)
    table = audit["mapping_table"]
    if policy.side.value != "BUY":
        raise AssertionError("policy side regression")
    if table["execution_base"]["mint_address"] != policy.base.ref.mint_address:
        raise AssertionError("audit base mint does not match the policy")
    if table["execution_quote"]["mint_address"] != policy.quote.ref.mint_address:
        raise AssertionError("audit quote mint does not match the policy")
    if table["execution_base"]["decimals"] != policy.base.decimals:
        raise AssertionError("audit base decimals do not match the policy")
    if table["execution_quote"]["decimals"] != policy.quote.decimals:
        raise AssertionError("audit quote decimals do not match the policy")
    long_side = Side(table["long"]["policy_side"])
    flat_side = Side(table["flat"]["policy_side"])
    # LONG must acquire the WSOL quote (SOL entry); FLAT must acquire the
    # USDC base (SOL exit), per SolanaShadowAdapter._refs resolution.
    if SolanaShadowAdapter._refs(policy, long_side)[1].mint_address != WSOL:
        raise AssertionError("audit LONG side does not acquire WSOL")
    if SolanaShadowAdapter._refs(policy, flat_side)[1].mint_address != USDC:
        raise AssertionError("audit FLAT side does not acquire USDC")
    if long_side is not Side.SELL or flat_side is not Side.BUY:
        raise AssertionError("audit LONG/FLAT side mapping inverted")
    if table["long"]["exactin_pair"] != "USDC->WSOL" or table["flat"]["exactin_pair"] != "WSOL->USDC":
        raise AssertionError("audit ExactIn pair mapping inverted")


def _mint_bytes(decimals: int) -> str:
    import base64

    data = bytearray(82)
    data[36:44] = (9_000_000_000_000).to_bytes(8, "little")
    data[44] = decimals
    data[45] = 1
    return base64.b64encode(bytes(data)).decode("ascii")


class _FakeSolana:
    """Local RPC fake: [9, 6] decimals for (input, output) mint accounts."""

    def __init__(self, *, output_decimals: int = 6) -> None:
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
                "value": {"blockhash": QUALIFICATION_TAKER_ADDRESS, "lastValidBlockHeight": 1150},
            }
        elif method == "getBlockHeight":
            result = 1000 if self.calls <= 2 else 1001
        elif method == "getMultipleAccounts":
            result = {
                "context": {"slot": 100},
                "value": [
                    {
                        "data": [_mint_bytes(9), "base64"],
                        "executable": False,
                        "lamports": 1,
                        "owner": SPL_TOKEN_PROGRAM_ADDRESS,
                        "rentEpoch": 0,
                        "space": 82,
                    },
                    {
                        "data": [_mint_bytes(self.output_decimals), "base64"],
                        "executable": False,
                        "lamports": 1,
                        "owner": SPL_TOKEN_PROGRAM_ADDRESS,
                        "rentEpoch": 0,
                        "space": 82,
                    },
                ],
            }
        else:  # pragma: no cover
            raise AssertionError(method)
        return canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "result": result})


class _FakeJupiter:
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response

    def __call__(self, _url: str, _query: bytes) -> bytes:
        return canonical_json_bytes(self.response)


def _build_response(*, out_amount: str = "150000000") -> dict[str, object]:
    """Frozen-fixture-shaped BUY (WSOL->USDC) Jupiter Swap V2 ExactIn response."""
    instruction = {
        "programId": SPL_TOKEN_PROGRAM_ADDRESS,
        "accounts": [{"pubkey": QUALIFICATION_TAKER_ADDRESS, "isWritable": False, "isSigner": True}],
        "data": "AA==",
    }
    return {
        "inputMint": WSOL,
        "outputMint": USDC,
        "inAmount": "1000000000",
        "outAmount": out_amount,
        "otherAmountThreshold": "149250000",
        "swapMode": "ExactIn",
        "slippageBps": 50,
        "priceImpactPct": "0",
        "routePlan": [
            {
                "swapInfo": {
                    "ammKey": AMM,
                    "label": "Fixture AMM",
                    "inputMint": WSOL,
                    "outputMint": USDC,
                    "inAmount": "1000000000",
                    "outAmount": out_amount,
                },
                "percent": 100,
                "bps": 10_000,
            }
        ],
        "computeBudgetInstructions": [instruction],
        "setupInstructions": [],
        "swapInstruction": instruction,
        "cleanupInstruction": None,
        "otherInstructions": [],
        "tipInstruction": None,
        "addressesByLookupTableAddress": {},
        "blockhashWithMetadata": {
            "blockhash": list(range(32)),
            "lastValidBlockHeight": 1150,
            "fetchedAt": {"secs_since_epoch": 1_700_000_090, "nanos_since_epoch": 0},
        },
    }


def _buy_observation() -> SolanaMarketObservationV0:
    rpc = SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, transport=_FakeSolana())
    jup = JupiterV2Client(JUPITER_SWAP_V2_BUILD_ENDPOINT, transport=_FakeJupiter(_build_response()))
    adapter = SolanaShadowAdapter(rpc, jup)
    policy = load_policy_file(POLICY_PATH)
    return adapter.observe(
        policy, "h003-audit-cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )


def _sell_shaped(observation: SolanaMarketObservationV0, *, usdc_in: int, wsol_out: int) -> SolanaMarketObservationV0:
    """Synthetic SELL-direction (USDC->WSOL) observation used ONLY for exact
    price arithmetic. It is never persisted, quoted, or replayed."""
    usdc_evidence = dict(observation.mint_account_evidence[1])  # USDC, 6 dec
    wsol_evidence = dict(observation.mint_account_evidence[0])  # WSOL, 9 dec
    threshold = policy_min_threshold_atomic(wsol_out, observation.requested_slippage_bps)
    route_plan = (
        {
            "bps": 10_000,
            "percent": 100,
            "swapInfo": {
                "ammKey": AMM,
                "label": "Fixture AMM",
                "inputMint": USDC,
                "outputMint": WSOL,
                "inAmount": str(usdc_in),
                "outAmount": str(wsol_out),
            },
        },
    )
    return dataclasses.replace(
        observation,
        side=Side.SELL,
        input_mint=USDC,
        output_mint=WSOL,
        input_decimals=6,
        output_decimals=9,
        requested_input_atomic=usdc_in,
        quoted_output_atomic=wsol_out,
        policy_min_threshold_atomic=threshold,
        venue_threshold_atomic=threshold,
        route_plan=route_plan,
        mint_account_evidence=(usdc_evidence, wsol_evidence),
    )


def test_mapping_table_is_pinned_to_the_frozen_policy() -> None:
    policy = load_policy_file(POLICY_PATH)
    assert policy.side is Side.BUY
    assert policy.base.ref.mint_address == USDC
    assert policy.base.decimals == 6
    assert policy.quote.ref.mint_address == WSOL
    assert policy.quote.decimals == 9
    assert policy.entry_ladder.side is Side.BUY
    assert policy.exit_ladder.side is Side.SELL
    assert policy.entry_ladder.levels[0].level_id == "SOL-USDC-1"
    assert policy.exit_ladder.levels[0].level_id == "USDC-SOL-1"
    # BUY spends the quote (WSOL) and receives the base (USDC).
    buy_input, buy_output = SolanaShadowAdapter._refs(policy, Side.BUY)
    assert (buy_input.mint_address, buy_output.mint_address) == (WSOL, USDC)
    sell_input, sell_output = SolanaShadowAdapter._refs(policy, Side.SELL)
    assert (sell_input.mint_address, sell_output.mint_address) == (USDC, WSOL)
    # The audit mapping is exactly the mechanically derived one.
    audit = _audit()
    assert audit["mapping_table"]["long"]["policy_side"] == LONG_TO_SIDE.value == "SELL"
    assert audit["mapping_table"]["flat"]["policy_side"] == FLAT_TO_SIDE.value == "BUY"
    _validate_audit_mapping(audit)


def test_audit_json_is_canonical_float_free_and_digest_consistent() -> None:
    raw = AUDIT_PATH.read_bytes()
    obj = json.loads(raw.decode("utf-8"))
    _no_floats(obj)
    # Canonical JSON discipline: sorted keys, minimal separators, ASCII.
    assert raw == canonical_json_bytes(obj) + b"\n"
    digest = obj["artifact_digest"]
    probe = {key: value for key, value in obj.items() if key != "artifact_digest"}
    assert digest == hashlib.sha256(canonical_json_bytes(probe)).hexdigest()
    assert obj["frozen_evidence"]["frozen_buy_fixture_reusable_for_long_entry"] is False
    assert obj["stop_conditions"]["code_contradiction_found"] is False


def test_direction_is_preserved_under_exact_arithmetic() -> None:
    observation = _buy_observation()
    assert (observation.input_mint, observation.output_mint) == (WSOL, USDC)
    # Research price P = USDC per SOL; execution acquisition price P_exec is
    # the same quantity through the 1:1 wrap: USDC per WSOL.
    low = _sell_shaped(observation, usdc_in=150_000_000, wsol_out=1_000_000_000)  # P_exec = 150/1
    high = _sell_shaped(observation, usdc_in=300_000_000, wsol_out=1_000_000_000)  # P_exec = 300/1
    # Exact human-scale execution prices (no floats anywhere).
    p_exec_low = Fraction(low.requested_input_atomic, 10**6) / Fraction(low.quoted_output_atomic, 10**9)
    p_exec_high = Fraction(high.requested_input_atomic, 10**6) / Fraction(high.quoted_output_atomic, 10**9)
    assert p_exec_high > p_exec_low  # higher SOL price => higher USDC per WSOL
    # The adapter's internal human price is the exact reciprocal: WSOL/USDC.
    average_low, _ = _human_price(low, Side.SELL)
    average_high, _ = _human_price(high, Side.SELL)
    assert average_low == 1 / p_exec_low
    assert average_high == 1 / p_exec_high
    assert average_high < average_low  # strictly decreasing in the research price
    # Side-dependent gate comparisons invert with the reciprocal so that the
    # acceptance SETS keep the research direction: entry (SELL) accepts only
    # low SOL prices; exit (BUY) accepts only high SOL prices.
    limit = Fraction(1, 200)  # strictly between average_high = 1/300 and average_low = 1/150
    entry_accepts_low = average_low >= limit  # SELL gate: fail when average < limit
    entry_accepts_high = average_high >= limit
    assert (entry_accepts_low, entry_accepts_high) == (True, False)
    exit_accepts_low = average_low <= limit  # BUY gate: fail when average > limit
    exit_accepts_high = average_high <= limit
    assert (exit_accepts_low, exit_accepts_high) == (False, True)


def test_mutated_mint_decimals_and_direction_fail_closed() -> None:
    audit = _audit()
    _validate_audit_mapping(audit)
    for mutation in (
        lambda a: a["mapping_table"]["execution_base"].update(mint_address="So11111111111111111111111111111111111111112"),
        lambda a: a["mapping_table"]["execution_quote"].update(decimals=6),
        lambda a: a["mapping_table"]["long"].update(policy_side="BUY"),
        lambda a: a["mapping_table"]["long"].update(exactin_pair="WSOL->USDC"),
    ):
        mutated = json.loads(json.dumps(audit))
        mutation(mutated)
        with pytest.raises(AssertionError):
            _validate_audit_mapping(mutated)
    # Adapter-level fail-closed: mutated on-chain decimals are rejected.
    policy = load_policy_file(POLICY_PATH)
    rpc = SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, transport=_FakeSolana(output_decimals=7))
    jup = JupiterV2Client(JUPITER_SWAP_V2_BUILD_ENDPOINT, transport=_FakeJupiter(_build_response()))
    with pytest.raises(SafeHaltError, match="decimals"):
        SolanaShadowAdapter(rpc, jup).observe(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
        )
    # Adapter-level fail-closed: a side-inverted observation cannot validate
    # against BUY-side intent bounds.
    adapter = SolanaShadowAdapter(
        SolanaRpcClient(SOLANA_MAINNET_RPC_ENDPOINT, transport=_FakeSolana()),
        JupiterV2Client(JUPITER_SWAP_V2_BUILD_ENDPOINT, transport=_FakeJupiter(_build_response())),
    )
    observation = adapter.observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, taker=QUALIFICATION_TAKER_ADDRESS
    )
    # A side-swapped observation cannot even be constructed without fresh,
    # direction-consistent mint-account evidence: the frozen BUY evidence
    # (WSOL in, USDC out) is rejected the moment the side flips.
    with pytest.raises(SafeHaltError, match="mint or token-program identity changed"):
        dataclasses.replace(
            observation,
            side=Side.SELL,
            input_mint=USDC,
            output_mint=WSOL,
            input_decimals=6,
            output_decimals=9,
        )


def test_frozen_buy_fixture_is_not_long_entry_evidence() -> None:
    manifest = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))
    target = manifest["request"]["target"]
    assert f"inputMint={WSOL}" in target
    assert f"outputMint={USDC}" in target  # BUY direction: WSOL -> USDC
    assert "amount=1000000000" in target
    assert "slippageBps=50" in target
    # The rule that forbids reuse across sides is on the books.
    assert "cannot be reused for a SELL quote" in DOC_PATH.read_text(encoding="utf-8")
    # And the audit records the verdict mechanically.
    audit = _audit()
    assert audit["frozen_evidence"]["frozen_buy_fixture_reusable_for_long_entry"] is False
    assert audit["frozen_evidence"]["required_for_long_entry"] == (
        "SELL-direction ExactIn USDC->WSOL observation (Subtask F, live read-only or abstain)"
    )
