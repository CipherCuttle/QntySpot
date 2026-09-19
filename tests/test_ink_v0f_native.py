from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import qntyspot.ink_v0f_native as native
from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex
from qntyspot.domain import Side
from qntyspot.economics import build_intent
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.execution_contract import (
    AuthorityLevel,
    AuthorityPolicyRefV0,
    ExecutionSessionV0,
)
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_BYTECODE_SHA256,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkShadowAdapter,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    consume_ink_v0f_router_artifact,
)
from qntyspot.ink_v0f_human_signing import InkV0FSignerStateObservationV0
from qntyspot.ink_v0f_preauth import (
    InkV0FLiveVerifier,
    InkV0FRouterObservationV0,
)
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.ledger import open_ledger
from qntyspot.ledger.execution import ExecutionRuntime
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

ROOT = Path(__file__).resolve().parents[1]
ROUTER_ARTIFACT = ROOT / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
RISK_ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
NOW = 1_800_000_000


def observation() -> InkMarketObservationV0:
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=INK_CHAIN_ID,
        pool_address=INKYSWAP_V2_POOL,
        factory_address=INKYSWAP_V2_FACTORY,
        token0=KRAKMASK_ADDRESS,
        token1=WETH9_ADDRESS,
        common_block=123,
        provider_heads={INK_RPC_ENDPOINTS[0]: 125, INK_RPC_ENDPOINTS[1]: 124},
        bytecode_present=True,
        bytecode_sha256=INKYSWAP_V2_BYTECODE_SHA256,
        bytecode_length=1,
        reserve0_atomic=10**21,
        reserve1_atomic=10**21,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
    )


def router_observation(router, obs: InkMarketObservationV0) -> InkV0FRouterObservationV0:
    return InkV0FRouterObservationV0(
        chain_id=INK_CHAIN_ID,
        router_address=router.address,
        common_block=obs.common_block,
        provider_heads=dict(obs.provider_heads),
        bytecode_sha256=router.deployed_bytecode_sha256,
        bytecode_length=router.deployed_bytecode_length,
        factory_address=router.factory_address,
        weth_address=router.weth_address,
        provider_evidence=({}, {}),
    )


def policy_doc() -> dict:
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-native-buy",
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
                {"level_id": "E1", "trigger_price": "1", "input_amount": "0.001"}
            ]
        },
        "exit_ladder": {
            "levels": [{"level_id": "X1", "trigger_price": "1", "input_ratio": "1"}]
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
            "max_executable_price": "1.005",
            "min_executable_price": "0.995",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": NOW - 10,
            "expiry_epoch_s": NOW + 3600,
            "quote_ttl_s": 600,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
    }


def reserved_entry():
    ledger = open_ledger()
    policy = parse_policy(policy_doc())
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
        IntentState.RESERVED,
    ):
        ledger.transition(intent.economic_action_id, state, now_epoch_s=NOW)
    return ledger, policy, intent


def session(policy_id: str) -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="11" * 20,
        implementation_digest="22" * 32,
        runtime_identity="cpython-test",
        db_schema_version=1,
        policy_id=policy_id,
        authority_policy_digest="33" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id=f"evm:{INK_CHAIN_ID}",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=NOW,
        session_ordinal=0,
    )


def build_preview_and_envelope():
    ledger, policy, intent = reserved_entry()
    risk = consume_ink_v0f_risk_artifact(RISK_ARTIFACT.read_bytes())
    router = consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes())
    obs = observation()
    quote = InkShadowAdapter._quote(obs, Side.BUY, intent.bounds.max_input_atomic)
    sess = session(policy.policy_id)
    preview = native.build_ink_v0f_native_buy_preview(
        policy=risk,
        router=router,
        observation=obs,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=sess,
        account_nonce=0,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=NOW + 1,
    )
    envelope = native.build_ink_v0f_native_execution_envelope(
        preview,
        router_observation(router, obs),
        policy=risk,
        session=sess,
    )
    return ledger, policy, intent, risk, router, obs, sess, preview, envelope


def test_native_selector_and_codec_are_canonical() -> None:
    assert native.SWAP_EXACT_ETH_FOR_TOKENS_SELECTOR.hex() == "7ff36ab5"
    calldata = native.encode_swap_exact_eth_for_tokens(
        amount_out_min_atomic=123,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=456,
    )
    assert len(calldata) == 228
    assert native.decode_swap_exact_eth_for_tokens(calldata) == (
        123,
        (WETH9_ADDRESS, KRAKMASK_ADDRESS),
        INK_V0F_TAKER_ADDRESS,
        456,
    )


def test_native_buy_has_exact_value_and_no_approval() -> None:
    _, _, intent, risk, _, _, _, preview, envelope = build_preview_and_envelope()
    assert preview.amount_in_native_atomic == intent.bounds.max_input_atomic
    assert preview.amount_in_native_atomic == 10**15
    assert preview.scope.min_value_atomic == preview.amount_in_native_atomic
    assert preview.scope.max_value_atomic == preview.amount_in_native_atomic
    assert envelope.transaction_value_atomic == preview.amount_in_native_atomic
    assert envelope.max_input_atomic == preview.amount_in_native_atomic
    assert envelope.allowance_target is None
    assert envelope.input_instrument_id == risk.quote_instrument_id
    fields = preview.eip1559_signing_fields()
    assert fields["to"] == INK_V0F_ROUTER_ADDRESS
    assert fields["value"] == 10**15
    assert str(fields["data"]).startswith("0x7ff36ab5")


def test_native_envelope_tamper_fails() -> None:
    from dataclasses import replace

    _, _, _, risk, router, obs, sess, preview, envelope = build_preview_and_envelope()
    ro = router_observation(router, obs)
    native.assert_ink_v0f_native_execution_envelope_admissible(
        envelope,
        preview,
        ro,
        policy=risk,
        session=sess,
        now_epoch_s=NOW + 2,
    )
    with pytest.raises(Exception):
        native.assert_ink_v0f_native_execution_envelope_admissible(
            replace(envelope, transaction_value_atomic=envelope.max_input_atomic - 1),
            preview,
            ro,
            policy=risk,
            session=sess,
            now_epoch_s=NOW + 2,
        )


def test_caller_built_native_revalidation_is_rejected() -> None:
    _, _, _, _, _, _, _, preview, _ = build_preview_and_envelope()
    with pytest.raises(SafeHaltError, match="produced by live revalidator"):
        native.InkV0FNativeSameAmountRevalidationV0(
            preview=preview,
            market_observation_digest="11" * 32,
            router_observation_digest="22" * 32,
            signer_state_digest="33" * 32,
            native_balance_observation_digest="44" * 32,
            fresh_quote_output_atomic=preview.quoted_output_atomic,
            fresh_required_min_output_atomic=preview.amount_out_min_atomic,
            common_block=preview.quote_common_block,
            revalidated_at_epoch_s=NOW + 2,
        )


def test_live_native_revalidation_preserves_frozen_transaction(monkeypatch) -> None:
    ledger, _, intent, risk, router, obs, sess, preview, envelope = build_preview_and_envelope()
    verifier = InkV0FLiveVerifier(
        (
            JsonRpcClient(INK_RPC_ENDPOINTS[0], transport=lambda _: b""),
            JsonRpcClient(INK_RPC_ENDPOINTS[1], transport=lambda _: b""),
        ),
        router,
    )
    router_obs = router_observation(router, obs)
    signer_obs = InkV0FSignerStateObservationV0(
        common_block=obs.common_block,
        account_nonce=envelope.account_nonce,
        base_fee_per_gas=1,
        block_hash="0x" + "44" * 32,
        provider_evidence=({}, {}),
    )
    balance_obs = native.InkV0FNativeBalanceObservationV0(
        common_block=obs.common_block,
        balance_atomic=3 * 10**15,
        provider_evidence=(
            {"endpoint": INK_RPC_ENDPOINTS[0], "balance_atomic": 3 * 10**15},
            {"endpoint": INK_RPC_ENDPOINTS[1], "balance_atomic": 3 * 10**15},
        ),
    )
    monkeypatch.setattr(InkV0FLiveVerifier, "observe_market", lambda self: obs)
    monkeypatch.setattr(
        InkV0FLiveVerifier,
        "observe_router_for_market",
        lambda self, market: router_obs,
    )
    monkeypatch.setattr(
        native,
        "observe_ink_v0f_signer_state_for_market",
        lambda verifier, market: signer_obs,
    )
    monkeypatch.setattr(
        native,
        "observe_ink_v0f_native_balance_for_market",
        lambda verifier, market: balance_obs,
    )

    revalidation = native.revalidate_ink_v0f_native_same_amount(
        live_verifier=verifier,
        risk_policy=risk,
        router_identity=router,
        ledger=ledger,
        intent=intent,
        session=sess,
        envelope=envelope,
        now_epoch_s=NOW + 2,
    )
    fields = revalidation.eip1559_signing_fields()
    assert fields["value"] == envelope.max_input_atomic
    assert fields["nonce"] == envelope.account_nonce
    assert fields["data"] == "0x" + preview.calldata.hex()
    assert revalidation.preview.scope.scope_digest == preview.scope.scope_digest

    with pytest.raises(EnvelopeValidationError, match="frozen envelope identity"):
        native.validate_ink_v0f_native_signed_buy(
            revalidation,
            replace(envelope, deadline_epoch_s=envelope.deadline_epoch_s + 1),
            b"not-signed-bytes",
            admitted_at_epoch_s=NOW + 3,
        )



def test_native_revalidation_refuses_balance_below_input_plus_gas(monkeypatch) -> None:
    ledger, _, intent, risk, router, obs, sess, _, envelope = build_preview_and_envelope()
    verifier = InkV0FLiveVerifier(
        (
            JsonRpcClient(INK_RPC_ENDPOINTS[0], transport=lambda _: b""),
            JsonRpcClient(INK_RPC_ENDPOINTS[1], transport=lambda _: b""),
        ),
        router,
    )
    router_obs = router_observation(router, obs)
    signer_obs = InkV0FSignerStateObservationV0(
        common_block=obs.common_block,
        account_nonce=envelope.account_nonce,
        base_fee_per_gas=1,
        block_hash="0x" + "55" * 32,
        provider_evidence=({}, {}),
    )
    too_low = native.InkV0FNativeBalanceObservationV0(
        common_block=obs.common_block,
        balance_atomic=envelope.transaction_value_atomic,
        provider_evidence=(
            {"endpoint": INK_RPC_ENDPOINTS[0], "balance_atomic": envelope.transaction_value_atomic},
            {"endpoint": INK_RPC_ENDPOINTS[1], "balance_atomic": envelope.transaction_value_atomic},
        ),
    )
    monkeypatch.setattr(InkV0FLiveVerifier, "observe_market", lambda self: obs)
    monkeypatch.setattr(
        InkV0FLiveVerifier,
        "observe_router_for_market",
        lambda self, market: router_obs,
    )
    monkeypatch.setattr(
        native,
        "observe_ink_v0f_signer_state_for_market",
        lambda verifier, market: signer_obs,
    )
    monkeypatch.setattr(
        native,
        "observe_ink_v0f_native_balance_for_market",
        lambda verifier, market: too_low,
    )

    with pytest.raises(SafeHaltError, match="worst-case gas"):
        native.revalidate_ink_v0f_native_same_amount(
            live_verifier=verifier,
            risk_policy=risk,
            router_identity=router,
            ledger=ledger,
            intent=intent,
            session=sess,
            envelope=envelope,
            now_epoch_s=NOW + 2,
        )



def test_native_revalidation_refuses_cross_action_envelope_before_rpc() -> None:
    ledger, _, intent, risk, router, _, sess, _, envelope = build_preview_and_envelope()
    verifier = InkV0FLiveVerifier(
        (
            JsonRpcClient(INK_RPC_ENDPOINTS[0], transport=lambda _: b""),
            JsonRpcClient(INK_RPC_ENDPOINTS[1], transport=lambda _: b""),
        ),
        router,
    )
    with pytest.raises(SafeHaltError, match="another economic action"):
        native.revalidate_ink_v0f_native_same_amount(
            live_verifier=verifier,
            risk_policy=risk,
            router_identity=router,
            ledger=ledger,
            intent=intent,
            session=sess,
            envelope=replace(envelope, economic_action_id="aa" * 32),
            now_epoch_s=NOW + 2,
        )



def authorized_runtime_for_native_buy():
    ledger = open_ledger()
    policy = parse_policy(policy_doc())
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

    key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ink-v0f-native-preauth-test").digest()
    )
    anchor = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = sha256_hex(anchor)
    authority = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit="11" * 20,
        permitted_implementation_digest="22" * 32,
        permitted_network_id="evm:57073",
        permitted_taker_address=INK_V0F_TAKER_ADDRESS,
        permitted_venue_id="inkyswap-v2-ink-mainnet",
        max_reservation_atomic=10**15,
        max_cumulative_atomic=10**15,
        not_before_epoch_s=NOW,
        not_after_epoch_s=NOW + 900,
    )
    unsigned = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint=fingerprint,
        signature_algorithm="Ed25519",
        authority_epoch=6,
        serial=1,
        issued_at_epoch_s=NOW,
        authority_policy=authority,
        signature=b"\x00" * 64,
    )
    receipt = replace(unsigned, signature=key.sign(unsigned.signed_body_bytes))
    trust_bytes = canonical_json_bytes(
        {
            "minimum_authority_epoch": 1,
            "public_key_fingerprint": fingerprint,
            "root_id": "qnty-authority-root-v0",
            "schema": "qntyspot.authority_root.v0.trust_config",
            "signature_algorithm": "Ed25519",
            "trust_config_version": 1,
        }
    )
    trusted = load_trusted_authority_root(
        trust_bytes,
        expected_config_digest=sha256_hex(trust_bytes),
        anchor_bytes=anchor,
    )
    sess = replace(
        session(policy.policy_id),
        authority_policy_digest=receipt.authority_policy_digest,
    )
    verified = verify_authority_grant(
        receipt=receipt,
        trusted_root=trusted,
        session=sess,
        now_epoch_s=NOW,
    )
    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(sess, verified, now_epoch_s=NOW)
    runtime.reserve_action(
        intent.economic_action_id,
        session=sess,
        verified_grant=verified,
        now_epoch_s=NOW,
    )
    return runtime, ledger, intent, sess, verified


def test_native_buy_preauth_is_durable_and_has_zero_approval_rows(monkeypatch) -> None:
    runtime, ledger, intent, sess, verified = authorized_runtime_for_native_buy()
    risk = consume_ink_v0f_risk_artifact(RISK_ARTIFACT.read_bytes())
    router = consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes())
    obs = observation()
    verifier = InkV0FLiveVerifier(
        (
            JsonRpcClient(INK_RPC_ENDPOINTS[0], transport=lambda _: b""),
            JsonRpcClient(INK_RPC_ENDPOINTS[1], transport=lambda _: b""),
        ),
        router,
    )
    ro = router_observation(router, obs)
    monkeypatch.setattr(InkV0FLiveVerifier, "observe_market", lambda self: obs)
    monkeypatch.setattr(
        InkV0FLiveVerifier,
        "observe_router_for_market",
        lambda self, market: ro,
    )

    envelope = runtime.record_ink_v0f_native_buy_preauth(
        live_verifier=verifier,
        risk_policy=risk,
        router_identity=router,
        intent=intent,
        session=sess,
        verified_grant=verified,
        account_nonce=0,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=NOW + 1,
        now_epoch_s=NOW + 1,
    )
    assert envelope.transaction_value_atomic == envelope.max_input_atomic
    assert envelope.allowance_target is None
    assert ledger.held_atomic() == 10**15
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM execution_envelopes"
    ).fetchone()[0] == 1
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM approval_actions"
    ).fetchone()[0] == 0
