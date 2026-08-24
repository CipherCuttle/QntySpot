#!/usr/bin/env python3
"""Run exactly one bounded, read-only Robinhood V0D qualification attempt."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qntyspot.canon import canonical_json_bytes
from qntyspot.policy import parse_policy
from qntyspot.raw_evidence import RawEvidenceStore
from qntyspot.robinhood import (
    QUALIFICATION_TAKER_ADDRESS,
    SPY_SYMBOL,
    USDG_ADDRESS,
    ChainlinkRobinhoodDirectoryClient,
    RobinhoodRestClient,
    RobinhoodRpcClient,
    RobinhoodShadowAdapter,
    ZeroXV2Client,
    persist_decision,
    persist_identity,
    persist_observation,
)


def _write_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise RuntimeError(f"immutable artifact collision: {path}")


def _policy_for_asset(token_address: str, token_decimals: int) -> Any:
    # This is a qualification-only policy. SPY is never a runtime default.
    document = {
        "schema": "qntyspot.policy.v0",
        "policy_name": "robinhood-v0d-spy-qualification",
        "side": "BUY",
        "base": {"ref": {"namespace": "evm", "chain_id": 4663, "contract_address": token_address}, "decimals": token_decimals, "display_symbol": SPY_SYMBOL},
        "quote": {"ref": {"namespace": "evm", "chain_id": 4663, "contract_address": USDG_ADDRESS}, "decimals": 6, "display_symbol": "USDG"},
        "entry_ladder": {"levels": [{"level_id": "E1", "trigger_price": "20000", "input_amount": "100"}, {"level_id": "E2", "trigger_price": "10000", "input_amount": "100"}]},
        "exit_ladder": {"levels": [{"level_id": "X1", "trigger_price": "10000", "input_ratio": "0.5"}, {"level_id": "X2", "trigger_price": "15000", "input_ratio": "0.5"}]},
        "capital": {"allocation_quote": "100", "per_order_cap_quote": "100", "per_instrument_cap_quote": "100", "per_network_cap_quote": "100", "global_portfolio_cap_quote": "1000", "reserved_cash_quote": "0"},
        "limits": {"max_executable_price": "20000", "min_executable_price": "0.1", "max_price_impact_bps": 1000, "max_slippage_bps": 100},
        "timing": {"valid_from_epoch_s": 1, "expiry_epoch_s": 4102444800, "quote_ttl_s": 30},
        "reentry": {"max_cycles": 1, "rearm_hysteresis_bps": 0, "rearm_cooldown_s": 1},
    }
    return parse_policy(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--now-epoch-s", type=int, required=True)
    parser.add_argument("--output", type=Path, default=Path("qualifications/robinhood_v0d"))
    args = parser.parse_args()
    api_key = os.environ.get("ZEROX_API_KEY")
    if not api_key:
        print("QNTY_SPOT_V0D_ROBINHOOD_SHADOW_BLOCKED_0X_API_KEY_REQUIRED")
        return 2

    output = args.output
    evidence_root = output / "RAW_EVIDENCE_V0"
    store = RawEvidenceStore(evidence_root, max_response_bytes=2_000_000, max_total_bytes=12_000_000, max_records=32)
    rest = RobinhoodRestClient(evidence_store=store)
    rpc = RobinhoodRpcClient(evidence_store=store)
    directory = ChainlinkRobinhoodDirectoryClient(evidence_store=store)
    zero_x = ZeroXV2Client(api_key=api_key, evidence_store=store)

    # Resolve the policy's exact Stock Token address from the authoritative
    # registry before the adapter performs its reconciled observation.
    asset = rest.asset(SPY_SYMBOL)
    policy = _policy_for_asset(asset["token_address"], asset["token_decimals"])
    _write_once(output / "POLICY_V0.json", canonical_json_bytes(policy.canonical))
    adapter = RobinhoodShadowAdapter(rest, rpc, directory, zero_x, symbol=SPY_SYMBOL)
    observation = adapter.observe(policy, "robinhood-v0d-cycle-0", "E1", now_epoch_s=args.now_epoch_s, taker=QUALIFICATION_TAKER_ADDRESS)
    decision = adapter.shadow_decision(policy, "robinhood-v0d-cycle-0", "E1", now_epoch_s=args.now_epoch_s, observation=observation)
    assert adapter.identity is not None
    persist_identity(output / "ROBINHOOD_ASSET_IDENTITY_V0.json", adapter.identity)
    persist_observation(output / "ROBINHOOD_MARKET_OBSERVATION_V0.json", observation)
    persist_decision(output / "SHADOW_DECISION_V0.json", decision)
    evidence_records = list(rest.evidence_records + rpc.evidence_records + directory.evidence_records + zero_x.evidence_records)
    evidence_index_digest = store.persist_index(output / "RAW_EVIDENCE_INDEX_V0.json", evidence_records)
    manifest = {
        "chain_id": 4663,
        "decision_digest": decision.digest(),
        "evidence_index_sha256": evidence_index_digest,
        "identity_digest": adapter.identity.digest(),
        "live_eligibility_confirmed": "NOT_EVALUATED",
        "observation_digest": observation.digest(),
        "policy_id": policy.policy_id,
        "schema": "ROBINHOOD_V0D_QUALIFICATION_MANIFEST_V0",
        "zero_x_read_count": zero_x.http.read_count,
    }
    if zero_x.http.read_count != 1:
        raise RuntimeError("V0D qualification used more than one 0x read")
    _write_once(output / "QUALIFICATION_MANIFEST_V0.json", canonical_json_bytes(manifest))
    print(json.dumps({"decision": decision.decision, "decision_digest": decision.digest(), "observation_digest": observation.digest(), "identity_digest": adapter.identity.digest(), "evidence_index_sha256": evidence_index_digest, "live_eligibility_confirmed": "NOT_EVALUATED"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
