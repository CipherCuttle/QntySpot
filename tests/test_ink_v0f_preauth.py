from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from fractions import Fraction

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import qntyspot.ink_v0f_preauth as preauth

from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0
from qntyspot.execution_contract import (
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    Capability,
    ExecutionSessionV0,
)
from qntyspot.economics import build_intent
from qntyspot.ledger import ExecutionRuntime, open_ledger
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    InkV0FApprovalCallV0,
    InkV0FHumanSigningPreviewV0,
    InkV0FRouterIdentityV0,
    InkV0FSwapCallV0,
    encode_approve,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.ink_v0f_preauth import (
    ERC20_ALLOWANCE_SELECTOR,
    ROUTER_FACTORY_SELECTOR,
    ROUTER_WETH_SELECTOR,
    InkV0FLiveVerifier,
    assert_ink_v0f_approval_admissible,
    assert_ink_v0f_execution_envelope_admissible,
    build_ink_v0f_approval_action,
    build_ink_v0f_execution_envelope,
)
from qntyspot.keccak import keccak256
from qntyspot.domain import Side
from qntyspot.ink_v0f_risk import InkV0FRiskPolicyV0
from qntyspot.prelive_economics import DustLiveConcurrencyV0
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState


FAKE_CODE = bytes.fromhex("60016000556002600055")
FAKE_CODE_HASH = hashlib.sha256(FAKE_CODE).hexdigest()
FAKE_CODE_LENGTH = len(FAKE_CODE)


def word(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def address_word(address: str) -> str:
    return "0" * 24 + address[2:]


def fake_router_identity() -> InkV0FRouterIdentityV0:
    identity = object.__new__(InkV0FRouterIdentityV0)
    object.__setattr__(identity, "address", INK_V0F_ROUTER_ADDRESS)
    object.__setattr__(identity, "chain_id", INK_CHAIN_ID)
    object.__setattr__(identity, "contract_name", "UniswapV2Router02")
    object.__setattr__(identity, "deployed_bytecode_length", FAKE_CODE_LENGTH)
    object.__setattr__(identity, "deployed_bytecode_sha256", FAKE_CODE_HASH)
    object.__setattr__(identity, "factory_address", INKYSWAP_V2_FACTORY)
    object.__setattr__(identity, "weth_address", WETH9_ADDRESS)
    object.__setattr__(identity, "artifact_digest", "00" * 32)
    return identity


class FakeRpc:
    def __init__(
        self,
        *,
        head: int = 105,
        factory: str = INKYSWAP_V2_FACTORY,
        weth: str = WETH9_ADDRESS,
        allowance: int = 0,
        code: bytes = FAKE_CODE,
    ) -> None:
        self.head = head
        self.factory = factory
        self.weth = weth
        self.allowance = allowance
        self.code = code
        self.block_tags: list[str] = []

    def __call__(self, payload: bytes) -> bytes:
        request = json.loads(payload)
        method = request["method"]
        params = request["params"]
        if method == "eth_chainId":
            result = hex(INK_CHAIN_ID)
        elif method == "eth_blockNumber":
            result = hex(self.head)
        elif method == "eth_getCode":
            self.block_tags.append(params[1])
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            self.block_tags.append(params[1])
            data = params[0]["data"]
            if data == "0x" + ROUTER_FACTORY_SELECTOR.hex():
                result = "0x" + address_word(self.factory)
            elif data == "0x" + ROUTER_WETH_SELECTOR.hex():
                result = "0x" + address_word(self.weth)
            elif data.startswith("0x" + ERC20_ALLOWANCE_SELECTOR.hex()):
                result = "0x" + word(self.allowance)
            else:
                raise AssertionError(f"unexpected eth_call data {data}")
        else:
            raise AssertionError(f"unexpected method {method}")
        return canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "result": result})


def market_observation() -> InkMarketObservationV0:
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=INK_CHAIN_ID,
        pool_address=INKYSWAP_V2_POOL,
        factory_address=INKYSWAP_V2_FACTORY,
        token0=KRAKMASK_ADDRESS,
        token1=WETH9_ADDRESS,
        common_block=100,
        provider_heads={INK_RPC_ENDPOINTS[0]: 105, INK_RPC_ENDPOINTS[1]: 104},
        bytecode_present=True,
        bytecode_sha256="11" * 32,
        bytecode_length=1,
        reserve0_atomic=10**21,
        reserve1_atomic=10**21,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
    )


def verifier(monkeypatch, *, first: FakeRpc | None = None, second: FakeRpc | None = None):
    monkeypatch.setattr(preauth, "INK_V0F_ROUTER_BYTECODE_SHA256", FAKE_CODE_HASH)
    monkeypatch.setattr(preauth, "INK_V0F_ROUTER_BYTECODE_LENGTH", FAKE_CODE_LENGTH)
    a = first or FakeRpc(head=105)
    b = second or FakeRpc(head=104)
    return InkV0FLiveVerifier(
        (
            JsonRpcClient(INK_RPC_ENDPOINTS[0], transport=a),
            JsonRpcClient(INK_RPC_ENDPOINTS[1], transport=b),
        ),
        fake_router_identity(),
    ), a, b


def session() -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="11" * 20,
        implementation_digest="22" * 32,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="33" * 32,
        authority_policy_digest="44" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=1_800_000_000,
        session_ordinal=0,
    )


def preview() -> InkV0FHumanSigningPreviewV0:
    sess = session()
    approval = InkV0FApprovalCallV0(
        token_address=WETH9_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        amount_atomic=10**15,
        calldata=encode_approve(INK_V0F_ROUTER_ADDRESS, 10**15),
    )
    swap_data = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=10**15,
        amount_out_min_atomic=900_000_000_000_000,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=1_800_000_600,
    )
    swap = InkV0FSwapCallV0(
        amount_in_atomic=10**15,
        amount_out_min_atomic=900_000_000_000_000,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=1_800_000_600,
        calldata=swap_data,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        economic_action_id="55" * 32,
        authority_policy_digest=sess.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=INK_V0F_TAKER_ADDRESS,
        target_address=INK_V0F_ROUTER_ADDRESS,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=hashlib.sha256(swap_data).hexdigest(),
        calldata_length=len(swap_data),
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
    )
    return InkV0FHumanSigningPreviewV0(
        side=Side.BUY,
        router_address=INK_V0F_ROUTER_ADDRESS,
        quote_observation_digest="66" * 32,
        quote_common_block=100,
        quoted_output_atomic=10**15,
        approval=approval,
        swap=swap,
        signed_bytes_scope=scope,
        constructed_at_epoch_s=1_800_000_001,
    )


def test_selectors_are_exact() -> None:
    assert ROUTER_FACTORY_SELECTOR == keccak256(b"factory()")[:4]
    assert ROUTER_WETH_SELECTOR == keccak256(b"WETH()")[:4]
    assert ERC20_ALLOWANCE_SELECTOR == keccak256(b"allowance(address,address)")[:4]


def test_router_and_allowance_are_verified_at_market_common_block(monkeypatch) -> None:
    live, left, right = verifier(monkeypatch)
    market = market_observation()
    router_observation = live.observe_router_for_market(market)
    allowance = live.observe_allowance_for_market(market, token_address=WETH9_ADDRESS)
    assert router_observation.common_block == market.common_block == 100
    assert router_observation.factory_address == INKYSWAP_V2_FACTORY
    assert router_observation.weth_address == WETH9_ADDRESS
    assert allowance.allowance_atomic == 0
    assert all(tag == "0x64" for tag in left.block_tags + right.block_tags)


def test_router_bytecode_or_provider_disagreement_fails_closed(monkeypatch) -> None:
    bad = FakeRpc(code=b"\x60\x00")
    live, _, _ = verifier(monkeypatch, second=bad)
    with pytest.raises(SafeHaltError, match="bytecode"):
        live.observe_router_for_market(market_observation())

    live, _, _ = verifier(monkeypatch, second=FakeRpc(allowance=1))
    with pytest.raises(SafeHaltError, match="disagree"):
        live.observe_allowance_for_market(market_observation(), token_address=WETH9_ADDRESS)


def test_stale_market_block_fails_closed(monkeypatch) -> None:
    live, _, _ = verifier(monkeypatch, first=FakeRpc(head=200), second=FakeRpc(head=199))
    market = replace(
        market_observation(),
        provider_heads={INK_RPC_ENDPOINTS[0]: 200, INK_RPC_ENDPOINTS[1]: 199},
    )
    with pytest.raises(SafeHaltError, match="too old"):
        live.observe_router_for_market(market)


def test_envelope_is_exactly_derived_from_preview_and_router_observation(monkeypatch) -> None:
    live, _, _ = verifier(monkeypatch)
    p = preview()
    ro = live.observe_router_for_market(market_observation())
    env = build_ink_v0f_execution_envelope(p, ro, session())
    assert env.economic_action_id == p.signed_bytes_scope.economic_action_id
    assert env.transaction_to == INK_V0F_ROUTER_ADDRESS
    assert env.calldata_sha256 == hashlib.sha256(p.swap.calldata).hexdigest()
    assert env.venue_block_number == 100
    assert env.max_input_atomic == p.swap.amount_in_atomic
    assert env.min_output_atomic == p.swap.amount_out_min_atomic
    assert_ink_v0f_execution_envelope_admissible(
        env, p, ro, session(), now_epoch_s=1_800_000_100
    )
    with pytest.raises(EnvelopeValidationError, match="differs"):
        assert_ink_v0f_execution_envelope_admissible(
            replace(env, transaction_value_atomic=1),
            p,
            ro,
            session(),
            now_epoch_s=1_800_000_100,
        )


def test_approval_requires_same_block_zero_prior_allowance_and_exact_amount(monkeypatch) -> None:
    live, _, _ = verifier(monkeypatch)
    p = preview()
    allowance = live.observe_allowance_for_market(
        market_observation(), token_address=WETH9_ADDRESS
    )
    approval = build_ink_v0f_approval_action(p, allowance, session())
    assert approval.requested_allowance_atomic == p.approval.amount_atomic
    assert approval.observed_prior_allowance_atomic == 0
    assert approval.spender_address == INK_V0F_ROUTER_ADDRESS
    assert_ink_v0f_approval_admissible(
        approval, p, allowance, session(), now_epoch_s=1_800_000_100
    )

    nonzero = replace(allowance, allowance_atomic=1)
    with pytest.raises(EnvelopeValidationError, match="zero prior allowance"):
        build_ink_v0f_approval_action(p, nonzero, session())


def test_preauth_runtime_method_is_in_level_three_but_has_no_split_persistence_escape() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert Capability.CONSTRUCT_ENVELOPE in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.AUTHORIZE_APPROVAL in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.PRODUCE_SIGNATURE not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert hasattr(ExecutionRuntime, "record_ink_v0f_preauth_bundle")
    assert not hasattr(ExecutionRuntime, "record_ink_v0f_execution_envelope")
    assert not hasattr(ExecutionRuntime, "record_ink_v0f_approval_action")


def test_persistence_api_cannot_accept_caller_built_preauth_facts() -> None:
    params = inspect.signature(
        ExecutionRuntime.record_ink_v0f_preauth_bundle
    ).parameters
    assert "preview" not in params
    assert "router_observation" not in params
    assert "allowance_observation" not in params
    assert "envelope" not in params
    assert "approval" not in params
    assert "live_verifier" in params
    assert "risk_policy" in params
    assert "router_identity" in params
    assert "intent" in params


def test_full_cap_reservation_is_not_double_counted_during_preauth(
    monkeypatch,
    tmp_path,
) -> None:
    cap = 10**15
    doc = {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-preauth-cap-regression",
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
            "levels": [
                {"level_id": "X1", "trigger_price": "2", "input_ratio": "1"}
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
            "valid_from_epoch_s": 1_799_999_900,
            "expiry_epoch_s": 1_800_003_600,
            "quote_ttl_s": 30,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
    }
    policy = parse_policy(doc)
    ledger = open_ledger(str(tmp_path / "preauth-cap.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=1_800_000_000)
    intent = build_intent(
        policy,
        cycle_id,
        policy.level("E1"),
        now_epoch_s=1_800_000_000,
    )
    assert intent.quote_exposure_atomic == cap
    ledger.create_intent(intent, now_epoch_s=1_800_000_000)
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    ):
        ledger.transition(intent.economic_action_id, state, now_epoch_s=1_800_000_000)

    authority_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ink-v0f-preauth-cap-regression").digest()
    )
    anchor = authority_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = sha256_hex(anchor)
    authority = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        permitted_repository_commit="11" * 20,
        permitted_implementation_digest="22" * 32,
        permitted_network_id="evm:57073",
        permitted_taker_address=INK_V0F_TAKER_ADDRESS,
        permitted_venue_id="inkyswap-v2-ink-mainnet",
        max_reservation_atomic=cap,
        max_cumulative_atomic=cap,
        not_before_epoch_s=1_800_000_000,
        not_after_epoch_s=1_800_000_900,
    )
    unsigned = AuthorityGrantReceiptV0(
        root_id="qnty-authority-root-v0",
        public_key_fingerprint=fingerprint,
        signature_algorithm="Ed25519",
        authority_epoch=1,
        serial=1,
        issued_at_epoch_s=1_800_000_000,
        authority_policy=authority,
        signature=b"\x00" * 64,
    )
    receipt = replace(
        unsigned,
        signature=authority_key.sign(unsigned.signed_body_bytes),
    )
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
    root = load_trusted_authority_root(
        trust_bytes,
        expected_config_digest=sha256_hex(trust_bytes),
        anchor_bytes=anchor,
    )
    sess = replace(
        session(),
        repository_commit="11" * 20,
        implementation_digest="22" * 32,
        policy_id=policy.policy_id,
        authority_policy_digest=receipt.authority_policy_digest,
    )
    verified = verify_authority_grant(
        receipt=receipt,
        trusted_root=root,
        session=sess,
        now_epoch_s=1_800_000_000,
    )

    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(
        sess,
        verified,
        now_epoch_s=1_800_000_000,
    )
    runtime.reserve_action(
        intent.economic_action_id,
        session=sess,
        verified_grant=verified,
        now_epoch_s=1_800_000_000,
    )
    assert ledger.held_atomic() == cap

    live, _, _ = verifier(monkeypatch)
    constrained_market = replace(
        market_observation(),
        reserve0_atomic=10**17,
        reserve1_atomic=10**17,
    )
    monkeypatch.setattr(live, "observe_market", lambda: constrained_market)
    risk = InkV0FRiskPolicyV0(
        repository_identity="CipherCuttle/QntySpot",
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        pool_address=INKYSWAP_V2_POOL,
        base_instrument_id=f"evm:57073:{KRAKMASK_ADDRESS}",
        quote_instrument_id=f"evm:57073:{WETH9_ADDRESS}",
        max_entry_atomic=cap,
        max_cumulative_entry_atomic=cap,
        concurrency=DustLiveConcurrencyV0(1, 1, 1, 1),
        max_price_impact_bps=100,
        max_slippage_bps=50,
        max_grant_duration_s=900,
        profit_recycle_ratio=Fraction(0, 1),
        banked_profit_ratio=Fraction(1, 1),
    )
    approval, envelope = runtime.record_ink_v0f_preauth_bundle(
        live_verifier=live,
        risk_policy=risk,
        router_identity=fake_router_identity(),
        intent=intent,
        session=sess,
        verified_grant=verified,
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1_800_000_001,
        now_epoch_s=1_800_000_001,
    )
    assert approval.requested_allowance_atomic == envelope.max_input_atomic
    assert 0 < envelope.max_input_atomic < cap
    assert ledger.held_atomic() == cap
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM approval_actions"
    ).fetchone()[0] == 1
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM execution_envelopes"
    ).fetchone()[0] == 1


def test_atomic_bundle_contract_freezes_one_exact_input_amount(monkeypatch) -> None:
    live, _, _ = verifier(monkeypatch)
    p = preview()
    market = market_observation()
    router_observation = live.observe_router_for_market(market)
    allowance = live.observe_allowance_for_market(market, token_address=WETH9_ADDRESS)
    approval = build_ink_v0f_approval_action(p, allowance, session())
    envelope = build_ink_v0f_execution_envelope(p, router_observation, session())
    assert approval.economic_action_id == envelope.economic_action_id
    assert approval.requested_allowance_atomic == envelope.max_input_atomic
