from __future__ import annotations

from dataclasses import replace

import pytest

import qntyspot.ink_v0f_execution as ink_execution
import qntyspot.ink_v0f_human_signing as human
from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import sha256_hex
from qntyspot.economics import build_intent
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.execution_contract import (
    ApprovalActionV0,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    SubmissionAcknowledgment,
)
from qntyspot.ink import INK_CHAIN_ID, KRAKMASK_ADDRESS, WETH9_ADDRESS
from qntyspot.ink_v0f_execution import INK_V0F_ROUTER_ADDRESS
from qntyspot.ink_v0f_human_signing import build_ink_v0f_approval_signing_request
from qntyspot.ledger import ExecutionRuntime, open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

NOW = 1_800_000_000
COMMIT = "11" * 20
IMPLEMENTATION = "22" * 32
VENUE = "inkyswap-v2-ink-mainnet"
TAKER = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1"

# Public, precomputed verification fixtures only. No signing material or
# signature construction exists in this test module.
ANCHOR = bytes.fromhex(
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
)
TRUST_BYTES = (
    b'{"minimum_authority_epoch":1,"public_key_fingerprint":'
    b'"3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f",'
    b'"root_id":"approval-test-root","schema":'
    b'"qntyspot.authority_root.v0.trust_config","signature_algorithm":"Ed25519",'
    b'"trust_config_version":1}'
)
TRUST_DIGEST = "36a84516a8ac512ee6cd8169264fa034008a4acdc80126a0783614c3d053d5e1"
RECEIPT_BYTES = (
    b'{"authority_epoch":1,"authority_policy":{"authority_root_id":'
    b'"approval-test-root","granted_level":3,"max_cumulative_atomic":'
    b'"1000000000000000","max_reservation_atomic":"1000000000000000",'
    b'"not_after_epoch_s":1800000600,"not_before_epoch_s":1799999990,'
    b'"permitted_implementation_digest":'
    b'"2222222222222222222222222222222222222222222222222222222222222222",'
    b'"permitted_network_id":"evm:57073","permitted_repository_commit":'
    b'"1111111111111111111111111111111111111111","permitted_taker_address":'
    b'"0x1a642f0e3c3af545e7acbd38b07251b3990914f1","permitted_venue_id":'
    b'"inkyswap-v2-ink-mainnet","schema":"qntyspot.program_b.v0.authority_policy"},'
    b'"authority_policy_digest":'
    b'"171eb95c036c365e6972c0fcd8cf70e22c4c438dfc0a8e980b9728953807568a",'
    b'"grant_id":"1641da1eaa4766d1143f94e113cd11d274041769b7f1de0ff101bb6acce0898a",'
    b'"issued_at_epoch_s":1799999995,"public_key_fingerprint":'
    b'"3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f",'
    b'"receipt_id":"d3cf0bb3a57d98d0a45dbb6ceadd3b2ef7d075add30bba24688231121014c225",'
    b'"root_id":"approval-test-root","schema":"qntyspot.authority_root.v0.grant",'
    b'"serial":1,"signature":'
    b'"d41ab151d4b90ff9e4d8a13a740a5de30ea959b8fe6857377870630321ad6c5b'
    b'b0a7e981529457d346c13829d13e7a0185aad7136e55f6a51ec9261b7da15f09",'
    b'"signature_algorithm":"Ed25519"}'
)
RAW_APPROVAL = bytes.fromhex(
    "02f8b182def101830f4240843b9aca008301388094"
    "32bcb803f696c99eb263d60a05cafd8689026575"
    "80b844095ea7b3"
    "000000000000000000000000a8c1c38ff57428e5c3a34e0899be5cb385476507"
    "000000000000000000000000000000000000000000000000000000000001e240"
    "c001"
    "a042d411a9d7bfa19904c1aa97a6782dd222ff900613532cba0d916df87025cddf"
    "a013f6258942e37209e31cd93b2646bb661e049da97f4b32b860302059d69b374a"
)
RAW_APPROVAL_SHA256 = (
    "2f769696ffd42d462895ce60bb4ea8cbb1145efa396b13a3979356f011f1c7a6"
)
RAW_APPROVAL_TX = (
    "0xce6ad8b246c36ae583c03525cb897cd0d94c27f0c4baf0bd30c62a887b443d4b"
)


def _policy_doc() -> dict[str, object]:
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "approval-exact-runtime-test",
        "side": "BUY",
        "base": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": KRAKMASK_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "KRAKMASK",
        },
        "quote": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": WETH9_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "WETH",
        },
        "entry_ladder": {
            "levels": [
                {
                    "level_id": "E1",
                    "trigger_price": "1",
                    "input_amount": "0.001",
                }
            ]
        },
        "exit_ladder": {
            "levels": [
                {
                    "level_id": "X1",
                    "trigger_price": "1",
                    "input_ratio": "1",
                }
            ]
        },
        "capital": {
            "allocation_quote": "0.001",
            "per_order_cap_quote": "0.001",
            "per_instrument_cap_quote": "0.001",
            "per_network_cap_quote": "0.001",
            "global_portfolio_cap_quote": "0.001",
            "reserved_cash_quote": "0",
        },
        "limits": {
            "max_executable_price": "2",
            "min_executable_price": "0.5",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": NOW - 10,
            "expiry_epoch_s": NOW + 600,
            "quote_ttl_s": 300,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
        "recycling": {
            "profit_recycle_ratio": "0",
            "banked_profit_ratio": "1",
        },
    }


def _verified_grant(*, policy_id: str) -> tuple[ExecutionSessionV0, object]:
    trusted = load_trusted_authority_root(
        TRUST_BYTES,
        expected_config_digest=TRUST_DIGEST,
        anchor_bytes=ANCHOR,
    )
    receipt = AuthorityGrantReceiptV0.from_bytes(RECEIPT_BYTES)
    session = ExecutionSessionV0(
        repository_commit=COMMIT,
        implementation_digest=IMPLEMENTATION,
        runtime_identity="cpython-test",
        db_schema_version=1,
        policy_id=policy_id,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address=TAKER,
        network_id=f"evm:{INK_CHAIN_ID}",
        venue_id=VENUE,
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=NOW - 1,
        session_ordinal=0,
    )
    return session, verify_authority_grant(
        receipt=receipt,
        trusted_root=trusted,
        session=session,
        now_epoch_s=NOW,
    )


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", TAKER)
    monkeypatch.setattr(ink_execution, "INK_V0F_TAKER_ADDRESS", TAKER)

    policy = parse_policy(_policy_doc())
    ledger = open_ledger(str(tmp_path / "approval-runtime.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    ):
        ledger.transition(intent.economic_action_id, state, now_epoch_s=NOW)

    session, grant = _verified_grant(policy_id=policy.policy_id)
    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(session, grant, now_epoch_s=NOW)
    runtime.reserve_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
    )

    allowance = 123_456
    approval = ApprovalActionV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        taker_address=TAKER,
        token_address=KRAKMASK_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        requested_allowance_atomic=allowance,
        observed_prior_allowance_atomic=0,
        authority_policy_digest=session.authority_policy_digest,
        deadline_epoch_s=NOW + 300,
        economic_action_id=intent.economic_action_id,
    )
    envelope = ExecutionEnvelopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        chain_id=INK_CHAIN_ID,
        taker_address=TAKER,
        input_instrument_id=intent.bounds.input_instrument_id,
        output_instrument_id=intent.bounds.output_instrument_id,
        max_input_atomic=allowance,
        min_output_atomic=1,
        transaction_to=INK_V0F_ROUTER_ADDRESS,
        transaction_value_atomic=0,
        calldata_sha256="33" * 32,
        calldata_length=1,
        allowance_target=INK_V0F_ROUTER_ADDRESS,
        account_nonce=2,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling_atomic=1_000_000_000,
        max_priority_fee_per_gas_ceiling_atomic=1_000_000,
        deadline_epoch_s=NOW + 300,
        authority_policy_digest=session.authority_policy_digest,
        plan_id="44" * 32,
        quote_id="approval-test-quote",
        quote_observation_digest="55" * 32,
        venue_block_number=1,
        constructed_at_epoch_s=NOW,
    )
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=session,
        approval_nonce=1,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=1_000_000_000,
        max_priority_fee_per_gas_ceiling=1_000_000,
        constructed_at_epoch_s=NOW,
    )
    with ledger.connection:
        ledger.connection.execute(
            "INSERT INTO approval_actions "
            "(approval_action_id, session_id, session_identity_digest, "
            "economic_action_id, taker_address, token_address, spender_address, "
            "requested_allowance_atomic, observed_prior_allowance_atomic, "
            "authority_policy_digest, lifecycle, deadline_epoch_s, created_at_epoch_s) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?)",
            (
                approval.approval_action_id,
                session.session_id,
                session.identity_digest,
                intent.economic_action_id,
                TAKER,
                KRAKMASK_ADDRESS,
                INK_V0F_ROUTER_ADDRESS,
                str(allowance),
                "0",
                session.authority_policy_digest,
                NOW + 300,
                NOW,
            ),
        )
        ledger.connection.execute(
            "INSERT INTO external_actions "
            "(external_action_id, kind, economic_action_id, approval_action_id, session_id) "
            "VALUES (?, 'APPROVAL', NULL, ?, ?)",
            (
                approval.approval_action_id,
                approval.approval_action_id,
                session.session_id,
            ),
        )
    return ledger, runtime, session, grant, request


def _admit(runtime, request, session, grant):
    signed = runtime.admit_ink_v0f_signed_approval(
        request,
        RAW_APPROVAL,
        session,
        grant,
        frozen_at_epoch_s=NOW,
    )
    assert signed.transaction_hash == RAW_APPROVAL_TX
    assert signed.signed_bytes_sha256 == RAW_APPROVAL_SHA256
    return signed


def test_approval_exact_bytes_are_durable_guarded_and_submitted_once(
    tmp_path, monkeypatch
) -> None:
    ledger, runtime, session, grant, request = _setup(tmp_path, monkeypatch)
    signed = _admit(runtime, request, session, grant)

    row = ledger.connection.execute(
        "SELECT * FROM signed_transactions WHERE signed_transaction_id = ?",
        (signed.signed_transaction_id,),
    ).fetchone()
    assert row is not None
    assert row["origin"] == "APPROVAL"
    assert row["external_action_id"] == request.approval_action_id
    assert row["approval_action_id"] == request.approval_action_id
    assert row["envelope_id"] is None
    assert row["raw_signed_sha256"] == sha256_hex(RAW_APPROVAL)

    class Transport:
        def __init__(self) -> None:
            self.calls: list[bytes] = []

        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            self.calls.append(payload)
            return signed.transaction_hash

    transport = Transport()
    attempt = runtime.submit_ink_v0f_signed_approval(
        signed,
        RAW_APPROVAL,
        transport,
        session,
        grant,
        provider_id="ink-provider-0",
        submitted_at_epoch_s=NOW,
    )
    assert attempt.acknowledgment is SubmissionAcknowledgment.ACCEPTED
    assert transport.calls == [RAW_APPROVAL]
    assert ledger.intent_state(request.economic_action_id) is IntentState.RESERVED

    attempts = ledger.connection.execute(
        "SELECT attempt_ordinal, acknowledgment, error_class "
        "FROM submission_attempts WHERE signed_transaction_id = ? "
        "ORDER BY attempt_ordinal",
        (signed.signed_transaction_id,),
    ).fetchall()
    assert [tuple(row) for row in attempts] == [
        (0, "UNKNOWN", "PreTransportGuard"),
        (1, "ACCEPTED", None),
    ]

    with pytest.raises(SafeHaltError, match="retransmission"):
        runtime.submit_ink_v0f_signed_approval(
            signed,
            RAW_APPROVAL,
            transport,
            session,
            grant,
            provider_id="ink-provider-0",
            submitted_at_epoch_s=NOW + 1,
        )
    assert transport.calls == [RAW_APPROVAL]


def test_pretransport_guard_survives_hard_abort_and_blocks_retry(
    tmp_path, monkeypatch
) -> None:
    ledger, runtime, session, grant, request = _setup(tmp_path, monkeypatch)
    signed = _admit(runtime, request, session, grant)

    class HardAbort:
        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            raise KeyboardInterrupt("simulated process death at transport seam")

    with pytest.raises(KeyboardInterrupt):
        runtime.submit_ink_v0f_signed_approval(
            signed,
            RAW_APPROVAL,
            HardAbort(),
            session,
            grant,
            provider_id="ink-provider-0",
            submitted_at_epoch_s=NOW,
        )

    rows = ledger.connection.execute(
        "SELECT attempt_ordinal, acknowledgment, error_class "
        "FROM submission_attempts WHERE signed_transaction_id = ?",
        (signed.signed_transaction_id,),
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        (0, "UNKNOWN", "PreTransportGuard"),
    ]

    class MustNotRun:
        def __init__(self) -> None:
            self.called = False

        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            self.called = True
            return signed.transaction_hash

    transport = MustNotRun()
    with pytest.raises(SafeHaltError, match="retransmission"):
        runtime.submit_ink_v0f_signed_approval(
            signed,
            RAW_APPROVAL,
            transport,
            session,
            grant,
            provider_id="ink-provider-0",
            submitted_at_epoch_s=NOW + 1,
        )
    assert transport.called is False


def test_approval_admission_rejects_mutated_bytes_without_durable_row(
    tmp_path, monkeypatch
) -> None:
    ledger, runtime, session, grant, request = _setup(tmp_path, monkeypatch)
    mutated = bytearray(RAW_APPROVAL)
    mutated[-1] ^= 1

    with pytest.raises(EnvelopeValidationError):
        runtime.admit_ink_v0f_signed_approval(
            request,
            bytes(mutated),
            session,
            grant,
            frozen_at_epoch_s=NOW,
        )
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM signed_transactions"
    ).fetchone()[0] == 0


def test_approval_submission_refuses_changed_payload_before_guard_or_transport(
    tmp_path, monkeypatch
) -> None:
    ledger, runtime, session, grant, request = _setup(tmp_path, monkeypatch)
    signed = _admit(runtime, request, session, grant)

    class NoTransport:
        def __init__(self) -> None:
            self.called = False

        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            self.called = True
            return signed.transaction_hash

    transport = NoTransport()
    changed = RAW_APPROVAL + b"\x00"
    with pytest.raises(EnvelopeValidationError, match="mutated|length|hash"):
        runtime.submit_ink_v0f_signed_approval(
            signed,
            changed,
            transport,
            session,
            grant,
            provider_id="ink-provider-0",
            submitted_at_epoch_s=NOW,
        )
    assert transport.called is False
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM submission_attempts"
    ).fetchone()[0] == 0
