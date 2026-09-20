from __future__ import annotations

from dataclasses import replace

import pytest
import rlp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_keys import keys

import qntyspot.ink_v0f_execution as ink_execution
import qntyspot.ink_v0f_human_signing as human
from qntyspot.authority_root import (
    ED25519_SIGNATURE_ALGORITHM,
    TRUST_CONFIG_SCHEMA,
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex
from qntyspot.economics import build_intent
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.execution_contract import (
    AuthorityLevel,
    AuthorityPolicyRefV0,
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
ROOT_ID = "approval-test-root"
COMMIT = "11" * 20
IMPLEMENTATION = "22" * 32
VENUE = "inkyswap-v2-ink-mainnet"


def _int_bytes(value: int) -> bytes:
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def _sign_type2(fields: dict[str, object], key: keys.PrivateKey) -> bytes:
    from qntyspot.keccak import keccak256

    unsigned = [
        _int_bytes(int(fields["chainId"])),
        _int_bytes(int(fields["nonce"])),
        _int_bytes(int(fields["maxPriorityFeePerGas"])),
        _int_bytes(int(fields["maxFeePerGas"])),
        _int_bytes(int(fields["gas"])),
        bytes.fromhex(str(fields["to"])[2:]),
        _int_bytes(int(fields["value"])),
        bytes.fromhex(str(fields["data"])[2:]),
        [],
    ]
    message_hash = keccak256(b"\x02" + rlp.encode(unsigned))
    signature = key.sign_msg_hash(message_hash)
    return b"\x02" + rlp.encode(
        unsigned
        + [
            _int_bytes(signature.v),
            _int_bytes(signature.r),
            _int_bytes(signature.s),
        ]
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


def _verified_grant(
    *,
    taker: str,
    policy_id: str,
) -> tuple[ExecutionSessionV0, object]:
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("42" * 32))
    anchor = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = sha256_hex(anchor)
    trust_doc = {
        "minimum_authority_epoch": 1,
        "public_key_fingerprint": fingerprint,
        "root_id": ROOT_ID,
        "schema": TRUST_CONFIG_SCHEMA,
        "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
        "trust_config_version": 1,
    }
    trust_bytes = canonical_json_bytes(trust_doc)
    trusted = load_trusted_authority_root(
        trust_bytes,
        expected_config_digest=sha256_hex(trust_bytes),
        anchor_bytes=anchor,
    )
    authority = AuthorityPolicyRefV0(
        authority_root_id=ROOT_ID,
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit=COMMIT,
        permitted_implementation_digest=IMPLEMENTATION,
        permitted_network_id=f"evm:{INK_CHAIN_ID}",
        permitted_taker_address=taker,
        permitted_venue_id=VENUE,
        max_reservation_atomic=10**15,
        max_cumulative_atomic=10**15,
        not_before_epoch_s=NOW - 10,
        not_after_epoch_s=NOW + 600,
    )
    unsigned = AuthorityGrantReceiptV0(
        root_id=ROOT_ID,
        public_key_fingerprint=fingerprint,
        signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
        authority_epoch=1,
        serial=1,
        issued_at_epoch_s=NOW - 5,
        authority_policy=authority,
        signature=bytes(64),
    )
    receipt = replace(unsigned, signature=signing_key.sign(unsigned.signed_body_bytes))
    session = ExecutionSessionV0(
        repository_commit=COMMIT,
        implementation_digest=IMPLEMENTATION,
        runtime_identity="cpython-test",
        db_schema_version=1,
        policy_id=policy_id,
        authority_policy_digest=authority.authority_policy_digest,
        taker_address=taker,
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
    wallet_key = keys.PrivateKey(bytes.fromhex("01" * 32))
    from qntyspot.keccak import keccak256

    taker = "0x" + keccak256(wallet_key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(ink_execution, "INK_V0F_TAKER_ADDRESS", taker)

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

    session, grant = _verified_grant(taker=taker, policy_id=policy.policy_id)
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
        taker_address=taker,
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
        taker_address=taker,
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
                taker,
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
    raw = _sign_type2(request.eip1559_signing_fields(), wallet_key)
    return ledger, runtime, session, grant, request, raw


def test_approval_exact_bytes_are_durable_and_submitted_once(tmp_path, monkeypatch) -> None:
    ledger, runtime, session, grant, request, raw = _setup(tmp_path, monkeypatch)

    signed = runtime.admit_ink_v0f_signed_approval(
        request,
        raw,
        session,
        grant,
        frozen_at_epoch_s=NOW,
    )
    row = ledger.connection.execute(
        "SELECT * FROM signed_transactions WHERE signed_transaction_id = ?",
        (signed.signed_transaction_id,),
    ).fetchone()
    assert row is not None
    assert row["origin"] == "APPROVAL"
    assert row["external_action_id"] == request.approval_action_id
    assert row["approval_action_id"] == request.approval_action_id
    assert row["envelope_id"] is None
    assert row["raw_signed_sha256"] == sha256_hex(raw)

    class Transport:
        def __init__(self) -> None:
            self.calls: list[bytes] = []

        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            self.calls.append(payload)
            return signed.transaction_hash

    transport = Transport()
    attempt = runtime.submit_ink_v0f_signed_approval(
        signed,
        raw,
        transport,
        session,
        grant,
        provider_id="ink-provider-0",
        submitted_at_epoch_s=NOW,
    )
    assert attempt.acknowledgment is SubmissionAcknowledgment.ACCEPTED
    assert transport.calls == [raw]
    # Approval transport evidence must not transition the economic SELL/entry
    # intent. It remains RESERVED until approval reconciliation and the later
    # swap path act on it.
    assert ledger.intent_state(request.economic_action_id) is IntentState.RESERVED
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM submission_attempts WHERE signed_transaction_id = ?",
        (signed.signed_transaction_id,),
    ).fetchone()[0] == 1

    with pytest.raises(SafeHaltError, match="retransmission"):
        runtime.submit_ink_v0f_signed_approval(
            signed,
            raw,
            transport,
            session,
            grant,
            provider_id="ink-provider-0",
            submitted_at_epoch_s=NOW + 1,
        )
    assert transport.calls == [raw]


def test_approval_admission_rejects_mutated_bytes_without_durable_row(
    tmp_path, monkeypatch
) -> None:
    ledger, runtime, session, grant, request, raw = _setup(tmp_path, monkeypatch)
    mutated = bytearray(raw)
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


def test_approval_submission_refuses_changed_payload_before_transport(
    tmp_path, monkeypatch
) -> None:
    _ledger, runtime, session, grant, request, raw = _setup(tmp_path, monkeypatch)
    signed = runtime.admit_ink_v0f_signed_approval(
        request,
        raw,
        session,
        grant,
        frozen_at_epoch_s=NOW,
    )

    class NoTransport:
        def __init__(self) -> None:
            self.called = False

        def submit_exact_signed_bytes(self, payload: bytes) -> str:
            self.called = True
            return signed.transaction_hash

    transport = NoTransport()
    changed = raw + b"\x00"
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
