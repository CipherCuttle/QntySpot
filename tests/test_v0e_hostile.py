"""Preregistered, deterministic hostile-failure matrix for V0E preparation."""

from __future__ import annotations

import ast
import io
import json
import socket
import threading
from dataclasses import replace
from pathlib import Path
from fractions import Fraction
from urllib.error import HTTPError

import pytest

from conftest import NOW, base_policy_doc, drive
from qntyspot.canon import canonical_json_bytes
from qntyspot.domain import Side
from qntyspot.economics import build_intent
from qntyspot.errors import (
    BudgetExceededError,
    DuplicateEconomicActionError,
    LevelNotExecutableError,
    SafeHaltError,
    StateTransitionError,
)
from qntyspot.ink import JsonRpcClient
from qntyspot.ledger import open_ledger, recover
from qntyspot.raw_evidence import RawEvidenceStore
from qntyspot.states import IntentState as S

from test_ink import (
    CODE_HASH,
    FakeRpc,
    INK_CHAIN_ID,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    adapter_pair,
    observed_adapter,
    policy_for_fixture,
)
from test_robinhood import (
    NOW as RH_NOW,
    TOKEN,
    UID,
    USDG_ADDRESS,
    SPY_SYMBOL,
    QUALIFICATION_TAKER_ADDRESS,
    asset_body,
    make_adapter as make_rh_adapter,
    price_body,
    robinhood_policy,
    zero_body,
)
from test_solana import (
    AMM,
    POLICY_PATH,
    SOLANA_MAINNET_RPC_ENDPOINT,
    SPL_TOKEN_PROGRAM_ADDRESS,
    TOKEN_2022_PROGRAM_ADDRESS,
    USDC,
    WSOL,
    QUALIFICATION_TAKER_ADDRESS as SOL_TAKER,
    FakeJupiter,
    FakeSolana,
    build_response,
    make_adapter as make_sol_adapter,
)
from v0e_support import (
    AmbientSecretTripwire,
    AuthorityTripwire,
    DeterministicClock,
    FaultStep,
    NetworkTripwire,
    Scenario,
    ScenarioOutcome,
    SideEffectTripwire,
    ScriptedRpcTransport,
    preregistered_scenarios,
    receipt_bytes,
    receipt_digest,
    receipt_for,
    wall_clock_tripwire,
)


ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "docs/V0E_HOSTILE_FAILURE_SUITE_PREREG_V0.md"
SCENARIOS = preregistered_scenarios(PREREG.read_text(encoding="utf-8"))


def _rpc_result(result: object) -> bytes:
    return canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "result": result})


def _transport_case(scenario: Scenario) -> None:
    fault = scenario.scenario_id
    if fault == "V0E-T01":
        transport = ScriptedRpcTransport((FaultStep("timeout", TimeoutError("fixture timeout")),))
    elif fault == "V0E-T02":
        transport = ScriptedRpcTransport((FaultStep("reset", ConnectionResetError("fixture reset")),))
    elif fault == "V0E-T03":
        transport = ScriptedRpcTransport((FaultStep("truncated", b'{"jsonrpc":"2.0"'),))
    elif fault == "V0E-T04":
        transport = ScriptedRpcTransport((FaultStep("malformed", b"{"),))
    elif fault == "V0E-T05":
        transport = ScriptedRpcTransport((FaultStep("duplicate", b'{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}'),))
    elif fault == "V0E-T06":
        transport = ScriptedRpcTransport((FaultStep("oversized", b"x" * 257),))
    else:
        raise AssertionError(f"not an RPC transport case: {fault}")
    client = JsonRpcClient(
        "https://fixture.invalid",
        max_retries=0,
        max_response_bytes=256,
        transport=transport,
    )
    try:
        client.request("eth_chainId", [])
    finally:
        assert transport.calls == 1


def _http_error_case(code: int) -> None:
    class ErrorOpener:
        def __init__(self) -> None:
            self.calls = 0

        def open(self, _request: object, timeout: int) -> object:
            del timeout
            self.calls += 1
            raise HTTPError(
                "https://fixture.invalid",
                code,
                "fixture HTTP failure",
                {},
                io.BytesIO(b'{"error":"fixture"}'),
            )

    from qntyspot.robinhood import RobinhoodRestClient

    client = RobinhoodRestClient()
    opener = ErrorOpener()
    client.assets_http.opener = opener
    try:
        client.asset(SPY_SYMBOL)
    finally:
        assert opener.calls == (2 if code == 429 or 500 <= code <= 599 else 1)


def _ink_case(scenario: Scenario) -> object:
    sid = scenario.scenario_id
    if sid == "V0E-T11":
        adapter, observation = observed_adapter()
        return adapter.shadow_decision(
            policy_for_fixture(), "cycle", "E1", now_epoch_s=NOW,
            observation=observation, current_common_block=observation.common_block + 13,
        )
    if sid == "V0E-T12":
        adapter, observation = observed_adapter()
        return adapter.shadow_decision(
            policy_for_fixture(), "cycle", "E1", now_epoch_s=NOW,
            observation=observation, current_common_block=observation.common_block - 1,
        )
    if sid == "V0E-T13":
        return adapter_pair(first=FakeRpc(chain_id=1), second=FakeRpc(chain_id=1)).observe()
    if sid == "V0E-T14":
        return adapter_pair(first=FakeRpc(head=100), second=FakeRpc(head=200)).observe()
    if sid in {"V0E-T15", "V0E-T16", "V0E-K01", "V0E-K04", "V0E-K05"}:
        first = FakeRpc()
        second = FakeRpc()
        if sid in {"V0E-T15", "V0E-K04"}:
            second.reserve0 = 999
        if sid in {"V0E-T16", "V0E-K01", "V0E-K05"}:
            second.reserve0 = 999
        return adapter_pair(first=first, second=second).observe()
    if sid in {"V0E-I03", "V0E-K03"}:
        return adapter_pair(factory="0x" + "12" * 20).observe()
    if sid == "V0E-K02":
        return adapter_pair(code=b"\x60\x00").observe()
    if sid == "V0E-K06":
        adapter, observation = observed_adapter()
        return adapter.shadow_decision(
            policy_for_fixture(), "cycle", "E1", now_epoch_s=NOW,
            observation=observation, current_common_block=observation.common_block + 13,
        )
    if sid == "V0E-K07":
        adapter, observation = observed_adapter(reserve0=1_000_000, reserve1=1_000_000)
        return adapter.shadow_decision(
            policy_for_fixture(), "cycle", "E1", now_epoch_s=NOW,
            observation=observation,
        )
    if sid == "V0E-K08":
        return adapter_pair(first=FakeRpc(factory="0x" + "12" * 20)).observe()
    if sid == "V0E-Q06":
        adapter, observation = observed_adapter(reserve0=600_000, reserve1=1_000_000)
        policy = replace(policy_for_fixture(), max_executable_price=Fraction(1))
        return adapter.shadow_decision(
            policy, "cycle", "E1", now_epoch_s=NOW,
            observation=observation,
        )
    if sid == "V0E-Q07":
        adapter, observation = observed_adapter()
        adapter._quote(observation, Side.BUY, 0)
    if sid == "V0E-Q08":
        adapter, observation = observed_adapter(reserve0=1_000_000, reserve1=1)
        return adapter.shadow_decision(
            policy_for_fixture(max_impact=1), "cycle", "E1", now_epoch_s=NOW,
            observation=observation,
        )
    raise AssertionError(f"not an Ink case: {sid}")


def _rh_case(scenario: Scenario, tmp_path: Path) -> object:
    sid = scenario.scenario_id
    kwargs: dict[str, object] = {}
    if sid == "V0E-I01":
        kwargs["rpc"] = {"wrong_chain": True, "block_timestamp": RH_NOW}
    if sid in {"V0E-I02", "V0E-I08"}:
        doc = json.loads(asset_body())
        doc["assets"][0]["deployments"][0]["contractAddress"] = "0x" + "99" * 20
        kwargs["http"] = {"asset": canonical_json_bytes(doc)}
    if sid == "V0E-I06":
        doc = json.loads(asset_body())
        doc["assets"][0]["tokenDecimals"] = 6
        kwargs["http"] = {"asset": canonical_json_bytes(doc)}
    if sid == "V0E-I07":
        doc = json.loads(asset_body())
        doc["assets"][0]["id"] = "0x" + "99" * 32
        kwargs["http"] = {"asset": canonical_json_bytes(doc)}
    if sid == "V0E-I09":
        doc = json.loads(price_body())
        doc["quotes"][0]["deployments"][0]["contractAddress"] = "0x" + "99" * 20
        kwargs["http"] = {"price": canonical_json_bytes(doc)}
    if sid == "V0E-I10":
        doc = json.loads(asset_body())
        doc["assets"][0]["currentMultiplier"] = "2"
        kwargs["http"] = {"asset": canonical_json_bytes(doc)}
    if sid in {"V0E-Q01", "V0E-Q02", "V0E-Q03", "V0E-Q04", "V0E-Q09", "V0E-Q11", "V0E-Q12", "V0E-Q14", "V0E-R15", "V0E-R16", "V0E-R17"}:
        raw = json.loads(zero_body())
        if sid == "V0E-Q01":
            raw["sellToken"] = TOKEN
        elif sid == "V0E-Q02":
            raw["sellAmount"] = "100000001"
        elif sid == "V0E-Q03":
            raw["minBuyAmount"] = "1"
        elif sid == "V0E-Q04":
            raw["sellAmount"] = "99999999"
        elif sid == "V0E-Q09":
            raw["route"]["fills"][0]["to"] = USDG_ADDRESS
        elif sid == "V0E-Q11":
            raw["transaction"]["to"] = "0x" + "00" * 20
        elif sid == "V0E-Q12":
            raw["transaction"]["value"] = "1"
        elif sid == "V0E-Q14":
            raw["transaction"]["data"] = "0x0"
        elif sid == "V0E-R15":
            raw = {"error": "RWA access unavailable"}
        elif sid == "V0E-R16":
            raw = {"error": "unsupported pair"}
        elif sid == "V0E-R17":
            raw["transaction"]["data"] = "0x0"
        kwargs["http"] = {"zero_quote": canonical_json_bytes(raw)}
    if sid == "V0E-Q10":
        raw = json.loads(zero_body())
        raw["route"]["fills"][0]["proportionBps"] = "9999"
        kwargs["http"] = {"zero_quote": canonical_json_bytes(raw)}
    if sid in {"V0E-R01", "V0E-R02", "V0E-R03", "V0E-R04", "V0E-R05", "V0E-R06", "V0E-R07", "V0E-R08", "V0E-R09", "V0E-R10", "V0E-R11", "V0E-R12", "V0E-R13", "V0E-R14", "V0E-Q15"}:
        asset_changes: dict[str, object] = {}
        price_changes: dict[str, object] = {}
        rpc_changes: dict[str, object] = {}
        if sid == "V0E-R01":
            asset_changes["currentMultiplier"] = "2"
        elif sid in {"V0E-R02", "V0E-Q15"}:
            rpc_changes["feed_answer"] = 22_500_000_000
        elif sid == "V0E-R03":
            asset_changes["currentMultiplier"] = "1"
        elif sid == "V0E-R04":
            asset_changes.update({"pendingMultiplier": "1.5", "pendingMultiplierEffectiveTime": "2028-01-15T08:00:00Z"})
        elif sid == "V0E-R05":
            asset_changes.update({"pendingMultiplier": "2", "pendingMultiplierEffectiveTime": "2026-01-15T08:00:00Z"})
        elif sid == "V0E-R06":
            rpc_changes["paused"] = True
        elif sid == "V0E-R07":
            price_changes["generatedAt"] = "2020-01-01T00:00:00Z"
        elif sid == "V0E-R08":
            rpc_changes["feed_answer"] = 0
        elif sid == "V0E-R09":
            price_changes["isTradingHalt"] = True
        elif sid == "V0E-R10":
            price_changes["generatedAt"] = "2020-01-01T00:00:00Z"
        elif sid == "V0E-R11":
            rpc_changes["feed_answer"] = 10_000_000_000
        elif sid == "V0E-R12":
            rpc_changes["feed_answer"] = 22_500_000_000
        elif sid == "V0E-R13":
            pass
        elif sid == "V0E-R14":
            asset_changes.update({"pendingMultiplier": "2", "pendingMultiplierEffectiveTime": "2028-01-15T08:00:00Z"})
            rpc_changes["feed_answer"] = 0
        kwargs["http"] = {
            "asset": asset_body(**asset_changes),
            "price": price_body(**price_changes),
        }
        kwargs["rpc"] = rpc_changes
    adapter, policy, _rpc, _store = make_rh_adapter(tmp_path, **kwargs)
    if sid == "V0E-R13":
        observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, taker=QUALIFICATION_TAKER_ADDRESS)
        assert observation.sequencer_status == "UNAVAILABLE_NOT_PUBLISHED"
        return "REJECTED"
    if sid in {"V0E-R02", "V0E-R04", "V0E-R06", "V0E-R07", "V0E-R09", "V0E-R10", "V0E-R11", "V0E-R12", "V0E-Q15"}:
        observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, taker=QUALIFICATION_TAKER_ADDRESS)
        return adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, observation=observation)
    return adapter.observe(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, taker=QUALIFICATION_TAKER_ADDRESS)


def _sol_case(scenario: Scenario) -> object:
    sid = scenario.scenario_id
    response = build_response()
    if sid == "V0E-I04":
        response["inputMint"] = USDC
    if sid == "V0E-I05" or sid == "V0E-S08":
        return make_sol_adapter(solana=FakeSolana(owner=TOKEN_2022_PROGRAM_ADDRESS)).observe(
            __import__("qntyspot.policy", fromlist=["load_policy_file"]).load_policy_file(POLICY_PATH),
            "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100,
            taker=SOL_TAKER,
        )
    if sid == "V0E-S01":
        response["otherAmountThreshold"] = "149249999"
    if sid == "V0E-S02":
        response["otherAmountThreshold"] = "149250001"
    if sid == "V0E-S03":
        response["outputMint"] = WSOL
    if sid == "V0E-S04":
        response["blockhashWithMetadata"] = {"blockhash": [1], "lastValidBlockHeight": 1150}
    if sid == "V0E-S05":
        response["addressesByLookupTableAddress"] = {AMM: ["bad"]}
    if sid == "V0E-S06":
        response["routePlan"][0]["swapInfo"]["ammKey"] = "bad"
    if sid in {"V0E-S09", "V0E-Q13"}:
        response["swapInstruction"]["accounts"][0]["isSigner"] = "yes"
    if sid == "V0E-Q13":
        response["swapInstruction"]["accounts"][0]["isWritable"] = "yes"
    from qntyspot.policy import load_policy_file
    policy = load_policy_file(POLICY_PATH)
    adapter = make_sol_adapter(jupiter_response=response)
    observation = adapter.observe(
        policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100,
        taker=SOL_TAKER,
    )
    if sid == "V0E-Q05":
        return adapter.shadow_decision(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_200,
            observation=observation, current_slot=observation.slot_after + 151,
        )
    if sid == "V0E-S07":
        return adapter.shadow_decision(
            policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100,
            observation=observation,
            current_block_height=observation.jupiter_last_valid_block_height,
        )
    if sid == "V0E-S02":
        return adapter.shadow_decision(policy, "cycle", "SOL-USDC-1", now_epoch_s=1_700_000_100, observation=observation)
    return observation


def _evidence_case(scenario: Scenario, tmp_path: Path) -> object:
    store = RawEvidenceStore(tmp_path / "raw", max_response_bytes=256, max_total_bytes=512, max_records=2)
    body = b'{"fixture":1}'
    record = store.capture(endpoint="https://fixture.invalid", method="GET", request_target="/x", request_body=None, response_body=body)
    sid = scenario.scenario_id
    if sid == "V0E-E01":
        (tmp_path / "raw" / record.response_path).write_bytes(b"tampered")
        return store.read(record)
    if sid == "V0E-E02":
        index = tmp_path / "index.json"
        store.persist_index(index, [record])
        index.write_bytes(b"tampered")
        return store.persist_index(index, [record])
    if sid == "V0E-E03":
        adapter, policy, _rpc, _store = make_rh_adapter(tmp_path / "rh")
        observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, taker=QUALIFICATION_TAKER_ADDRESS)
        decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=RH_NOW, observation=observation)
        from qntyspot.robinhood import load_decision, persist_decision
        path = tmp_path / "artifact.json"
        persist_decision(path, decision)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["digest"] = "0" * 64
        path.write_bytes(canonical_json_bytes(envelope))
        return load_decision(path)
    if sid == "V0E-E04":
        (tmp_path / "raw" / record.response_path).unlink()
        return store.read(record)
    if sid == "V0E-E05":
        return store.persist_index(tmp_path / "index.json", [record, record])
    if sid == "V0E-E06":
        forged = replace(record, response_path="../secret.bin")
        return store.read(forged)
    if sid == "V0E-E07":
        from qntyspot.robinhood import replay_shadow_decision

        adapter, policy, _rpc, _store = make_rh_adapter(tmp_path / "replay")
        observation = adapter.observe(
            policy, "cycle-0", "E1", now_epoch_s=RH_NOW,
            taker=QUALIFICATION_TAKER_ADDRESS,
        )
        decision = replay_shadow_decision(
            policy, observation, "cycle-0", "E1",
            now_epoch_s=observation.observation_time_epoch_s,
        )
        return ScenarioOutcome(
            "REJECTED", f"REPLAY_COMPLETED:{decision.decision}",
        )
    if sid == "V0E-E08":
        from qntyspot.robinhood import replay_shadow_decision

        adapter, policy, _rpc, _store = make_rh_adapter(tmp_path / "replay")
        observation = adapter.observe(
            policy, "cycle-0", "E1", now_epoch_s=RH_NOW,
            taker=QUALIFICATION_TAKER_ADDRESS,
        )
        with wall_clock_tripwire():
            decision = replay_shadow_decision(
                policy, observation, "cycle-0", "E1",
                now_epoch_s=observation.observation_time_epoch_s,
            )
        return ScenarioOutcome(
            "REJECTED", f"REPLAY_COMPLETED_WITHOUT_CLOCK:{decision.decision}",
        )
    if sid == "V0E-E09":
        from qntyspot.robinhood import replay_shadow_decision

        adapter, policy, _rpc, _store = make_rh_adapter(tmp_path / "replay")
        observation = adapter.observe(
            policy, "cycle-0", "E1", now_epoch_s=RH_NOW,
            taker=QUALIFICATION_TAKER_ADDRESS,
        )
        return replay_shadow_decision(
            policy, observation, "cycle-0", "E1",
            now_epoch_s=observation.observation_time_epoch_s + 1,
        )
    if sid == "V0E-E10":
        from qntyspot.robinhood import replay_shadow_decision

        adapter, policy, _rpc, _store = make_rh_adapter(tmp_path / "replay")
        observation = adapter.observe(
            policy, "cycle-0", "E1", now_epoch_s=RH_NOW,
            taker=QUALIFICATION_TAKER_ADDRESS,
        )
        first = replay_shadow_decision(
            policy, observation, "cycle-0", "E1",
            now_epoch_s=observation.observation_time_epoch_s,
        )
        second = replay_shadow_decision(
            policy, observation, "cycle-0", "E1",
            now_epoch_s=observation.observation_time_epoch_s,
        )
        assert canonical_json_bytes(first.canonical_object()) == canonical_json_bytes(second.canonical_object())
        assert first.digest() == second.digest()
        mutated = replace(
            observation,
            observation_time_epoch_s=observation.observation_time_epoch_s + 1,
        )
        return replay_shadow_decision(
            policy, mutated, "cycle-0", "E1",
            now_epoch_s=observation.observation_time_epoch_s,
        )
    if sid == "V0E-E11":
        secret = b"fixture-secret"
        from qntyspot.robinhood import ZeroXV2Client
        client = ZeroXV2Client(api_key=secret.decode(), transport=lambda *_args: secret)
        return client.quote(sell_token=USDG_ADDRESS, buy_token=TOKEN, sell_amount_atomic=1, taker=QUALIFICATION_TAKER_ADDRESS, slippage_bps=0, policy_min_output_atomic=1)
    if sid == "V0E-E12":
        return store.capture(endpoint="https://fixture.invalid", method="GET", request_target="/z", request_body=None, response_body=b"x" * 257)
    raise AssertionError(sid)


def _ledger_case(scenario: Scenario, tmp_path: Path) -> tuple[object, str | None, str | None]:
    from qntyspot.policy import parse_policy

    policy_doc = base_policy_doc()
    if scenario.scenario_id in {"V0E-C02", "V0E-C08", "V0E-C09"}:
        policy_doc["capital"].update(
            allocation_quote="100",
            per_instrument_cap_quote="100",
            per_network_cap_quote="100",
            global_portfolio_cap_quote="100",
        )
    policy = parse_policy(policy_doc)
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = str(tmp_path / "ledger.sqlite3")
    with open_ledger(db) as led:
        led.admit_policy(policy)
        cycle = led.open_cycle(policy, 0, now_epoch_s=NOW)
        intent = build_intent(policy, cycle, policy.level("E1"), now_epoch_s=NOW)
        led.create_intent(intent, now_epoch_s=NOW)
    sid = scenario.scenario_id
    if sid in {"V0E-C01", "V0E-C03"}:
        with open_ledger(db) as left, open_ledger(db) as right:
            with pytest.raises(DuplicateEconomicActionError):
                right.create_intent(intent, now_epoch_s=NOW)
            return "REJECTED", intent.economic_action_id, None
    if sid == "V0E-C02":
        with open_ledger(db) as led:
            drive(led, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED)
            second = build_intent(policy, cycle, policy.level("E2"), now_epoch_s=NOW)
            led.create_intent(second, now_epoch_s=NOW)
            drive(led, second.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def reserve_worker(action_id: str) -> None:
            with open_ledger(db) as worker:
                barrier.wait(timeout=5)
                try:
                    worker.transition(action_id, S.RESERVED, now_epoch_s=NOW)
                except BudgetExceededError:
                    outcomes.append("budget-exceeded")
                else:
                    outcomes.append("reserved")

        threads = [
            threading.Thread(target=reserve_worker, args=(intent.economic_action_id,)),
            threading.Thread(target=reserve_worker, args=(second.economic_action_id,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert all(not thread.is_alive() for thread in threads)
        assert sorted(outcomes) == ["budget-exceeded", "reserved"]
        with open_ledger(db) as led:
            active = led.connection.execute(
                "SELECT COUNT(*) FROM budget_reservations WHERE status = 'ACTIVE'"
            ).fetchone()[0]
            assert active == 1
        return "REJECTED", intent.economic_action_id, "ACTIVE"
    if sid in {"V0E-C04", "V0E-C05", "V0E-C06", "V0E-C07", "V0E-C08", "V0E-C09", "V0E-C10"}:
        with open_ledger(db) as led:
            states = () if sid == "V0E-C04" else (
                S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED,
            )
            if sid in {"V0E-C07", "V0E-C08", "V0E-C09", "V0E-C10"}:
                states += (S.SIGNED, S.SUBMITTED)
            drive(led, intent.economic_action_id, *states)
        with open_ledger(db) as restarted:
            actions = recover(restarted, now_epoch_s=NOW + 60)
            disposition = restarted.connection.execute("SELECT status FROM budget_reservations").fetchone()
            assert len(actions) == 1
            if sid in {"V0E-C04", "V0E-C05", "V0E-C06"}:
                assert actions[0].disposition.value == "ABANDON"
                assert actions[0].to_state is S.CANCELLED
            if sid in {"V0E-C07", "V0E-C10"}:
                assert actions[0].disposition.value == "RECONCILIATION_REQUIRED"
                assert actions[0].to_state is S.SAFE_HALT
                assert restarted.intent_state(intent.economic_action_id) is S.SAFE_HALT
            if sid in {"V0E-C08", "V0E-C09"}:
                assert disposition is not None and disposition[0] == "QUARANTINED"
                second = build_intent(policy, cycle, policy.level("E2"), now_epoch_s=NOW)
                restarted.create_intent(second, now_epoch_s=NOW)
                drive(restarted, second.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED)
                with pytest.raises(BudgetExceededError):
                    restarted.transition(second.economic_action_id, S.RESERVED, now_epoch_s=NOW)
            if sid == "V0E-C10":
                assert actions[0].disposition.value == "RECONCILIATION_REQUIRED"
            return (
                "RECONCILIATION_REQUIRED" if sid in {"V0E-C07", "V0E-C10"}
                else "QUARANTINED" if sid in {"V0E-C08", "V0E-C09"}
                else "ABSTAIN",
                intent.economic_action_id,
                None if disposition is None else disposition[0],
            )
    if sid in {"V0E-C08", "V0E-C09"}:
        raise AssertionError("handled above")
    raise AssertionError(sid)


def _state_case(scenario: Scenario, tmp_path: Path) -> object:
    from qntyspot.policy import parse_policy

    policy = parse_policy(base_policy_doc())
    tmp_path.mkdir(parents=True, exist_ok=True)
    with open_ledger(str(tmp_path / "states.sqlite3")) as led:
        led.admit_policy(policy)
        cycle = led.open_cycle(policy, 0, now_epoch_s=NOW)
        intent = build_intent(policy, cycle, policy.level("E1"), now_epoch_s=NOW)
        led.create_intent(intent, now_epoch_s=NOW)
        target = {
            "V0E-M01": S.SIGNED,
            "V0E-M02": S.FILLED,
            "V0E-M03": S.RECONCILED,
            "V0E-M04": S.SIGNED,
            "V0E-M05": S.TRIGGERED,
            "V0E-M06": S.SIGNED,
        }[scenario.scenario_id]
        if scenario.scenario_id == "V0E-M05":
            led.transition(intent.economic_action_id, S.SAFE_HALT, now_epoch_s=NOW)
        elif scenario.scenario_id == "V0E-M02":
            led.transition(intent.economic_action_id, S.TRIGGERED, now_epoch_s=NOW)
        elif scenario.scenario_id == "V0E-M03":
            drive(led, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED)
        elif scenario.scenario_id == "V0E-M04":
            drive(led, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED, S.SIGNED, S.SUBMITTED)
        else:
            assert led.intent_state(intent.economic_action_id) is S.ARMED
        return led.transition(intent.economic_action_id, target, now_epoch_s=NOW)


def _authority_case(scenario: Scenario) -> object:
    sources = tuple(ROOT.joinpath("qntyspot").rglob("*.py"))
    text = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    tree = [ast.parse(path.read_text(encoding="utf-8"), filename=str(path)) for path in sources]
    assert all(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"} for node in ast.walk(module)) for module in tree)
    assert "subprocess" not in text and "private_key" not in text and "seed_phrase" not in text

    if scenario.scenario_id == "V0E-A08":
        retry_transport = ScriptedRpcTransport(
            tuple(FaultStep(f"timeout-{index}", TimeoutError("bounded retry fixture")) for index in range(3))
        )
        with pytest.raises(Exception):
            JsonRpcClient("https://fixture.invalid", max_retries=2, transport=retry_transport).request(
                "eth_chainId", []
            )
        assert retry_transport.calls == 3

    from qntyspot.robinhood import ZeroXV2Client
    from qntyspot.errors import ZeroXApiKeyRequired

    calls = 0

    def transport(*_args: object) -> bytes:
        nonlocal calls
        calls += 1
        raise AssertionError("authority test reached a 0x transport")

    guard = AuthorityTripwire()
    with guard.installed():
        client = ZeroXV2Client(api_key=None, transport=transport)
        with pytest.raises(ZeroXApiKeyRequired):
            client.quote(
                sell_token=USDG_ADDRESS, buy_token=TOKEN, sell_amount_atomic=1,
                taker=QUALIFICATION_TAKER_ADDRESS, slippage_bps=0,
                policy_min_output_atomic=1,
            )
    assert guard.attempts == 0, guard.surfaces
    assert calls == 0
    assert not hasattr(socket, "_qntyspot_network_escape")
    return ScenarioOutcome("REJECTED", "AUTHORITY_BOUNDARY_REJECTED_WITHOUT_TRANSPORT")


def _run_case(scenario: Scenario, tmp_path: Path):
    if scenario.scenario_id in {f"V0E-T{index:02d}" for index in range(1, 11)}:
        if scenario.scenario_id in {"V0E-T07", "V0E-T08", "V0E-T09", "V0E-T10"}:
            operation = lambda: _http_error_case(
                {"V0E-T07": 400, "V0E-T08": 401, "V0E-T09": 429, "V0E-T10": 503}[scenario.scenario_id]
            )
        else:
            operation = lambda: _transport_case(scenario)
    elif scenario.scenario_id in {"V0E-T11", "V0E-T12", "V0E-T13", "V0E-T14", "V0E-T15", "V0E-T16"}:
        operation = lambda: _ink_case(scenario)
    elif scenario.scenario_id.startswith(("V0E-I", "V0E-Q", "V0E-R")):
        if scenario.scenario_id.startswith("V0E-R") or (scenario.scenario_id.startswith("V0E-I") and scenario.adapter == "Robinhood"):
            operation = lambda: _rh_case(scenario, tmp_path)
        elif scenario.adapter in {"Ink", "core"}:
            operation = lambda: _ink_case(scenario)
        elif scenario.adapter.startswith("Robinhood") or scenario.adapter == "0x fixture":
            operation = lambda: _rh_case(scenario, tmp_path)
        else:
            operation = lambda: _sol_case(scenario)
    elif scenario.scenario_id.startswith("V0E-S"):
        operation = lambda: _sol_case(scenario)
    elif scenario.scenario_id.startswith("V0E-K"):
        operation = lambda: _ink_case(scenario)
    elif scenario.scenario_id.startswith("V0E-E"):
        operation = lambda: _evidence_case(scenario, tmp_path)
    elif scenario.scenario_id.startswith("V0E-C"):
        def operation() -> object:
            result, action_id, disposition = _ledger_case(scenario, tmp_path)
            return ScenarioOutcome(result, result, action_id, disposition)
    elif scenario.scenario_id.startswith("V0E-M"):
        operation = lambda: _state_case(scenario, tmp_path)
    elif scenario.scenario_id.startswith("V0E-A"):
        operation = lambda: _authority_case(scenario)
    else:
        raise AssertionError(f"no V0E handler for {scenario.scenario_id}")

    tripwire = NetworkTripwire()
    secret_tripwire = AmbientSecretTripwire()
    side_effect_tripwire = SideEffectTripwire()
    with tripwire.installed(), secret_tripwire.installed(), side_effect_tripwire.installed():
        receipt = receipt_for(
            scenario,
            operation,
            network_read_count=lambda: tripwire.attempts,
            secret_read_count=lambda: secret_tripwire.attempts,
            signing_count=lambda: side_effect_tripwire.signing_attempts,
            approval_count=lambda: side_effect_tripwire.approval_attempts,
            broadcast_count=lambda: side_effect_tripwire.broadcast_attempts,
        )
    assert tripwire.attempts == 0, tripwire.surfaces
    assert secret_tripwire.attempts == 0, secret_tripwire.surfaces
    assert side_effect_tripwire.signing_attempts == 0
    assert side_effect_tripwire.approval_attempts == 0
    assert side_effect_tripwire.broadcast_attempts == 0
    return receipt


def test_v0e_registry_is_frozen_and_complete() -> None:
    assert SCENARIOS[0].scenario_id == "V0E-T01"
    assert SCENARIOS[-1].scenario_id == "V0E-A11"
    assert len(SCENARIOS) >= 100
    assert all(item.expected_terminal_class != "WOULD_EXECUTE" or item.scenario_id in {"V0E-S02", "V0E-K07"} for item in SCENARIOS)


def test_v0e_hostile_receipts_match_preregistration_and_are_deterministic(tmp_path: Path) -> None:
    first = [_run_case(scenario, tmp_path / "first" / scenario.scenario_id) for scenario in SCENARIOS]
    second = [_run_case(scenario, tmp_path / "second" / scenario.scenario_id) for scenario in SCENARIOS]
    mismatches = [
        (receipt.scenario_id, receipt.expected_terminal_class, receipt.observed_terminal_class, receipt.reason_code)
        for receipt in first
        if receipt.observed_terminal_class != receipt.expected_terminal_class
    ]
    assert not mismatches, mismatches
    assert receipt_bytes(first) == receipt_bytes(second)
    assert receipt_digest(first) == receipt_digest(second)
    assert all(receipt.network_read_count == 0 for receipt in first)
    assert all(receipt.secret_read_count == 0 for receipt in first)
    assert all(receipt.signing_count == 0 and receipt.broadcast_count == 0 for receipt in first)


def test_v0e_two_workers_same_action_have_one_winner(tmp_path: Path) -> None:
    from qntyspot.policy import parse_policy

    db = str(tmp_path / "race.sqlite3")
    policy = parse_policy(base_policy_doc())
    with open_ledger(db) as setup:
        setup.admit_policy(policy)
        cycle = setup.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle, policy.level("E1"), now_epoch_s=NOW)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def worker() -> None:
        with open_ledger(db) as led:
            barrier.wait(timeout=5)
            try:
                led.create_intent(intent, now_epoch_s=NOW)
            except DuplicateEconomicActionError:
                outcomes.append("duplicate")
            else:
                outcomes.append("created")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(outcomes) == ["created", "duplicate"]
