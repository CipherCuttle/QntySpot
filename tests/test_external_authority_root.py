"""Offline contract vectors for the independently rooted authority consumer.

The fixture contains only a throwaway public Ed25519 anchor and detached
signatures.  No private material is stored or read by the test suite.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

import pytest

from conftest import NOW
from qntyspot.authority_root import (
    AUTHORITY_ROOT_CONTRACT_VERSION,
    ED25519_SIGNATURE_ALGORITHM,
    TRUST_CONFIG_SCHEMA,
    AuthorityGrantReceiptV0,
    AuthorityIssuancePolicyV0,
    TrustedAuthorityRootV0,
    VerifiedAuthorityGrantV0,
    assert_effective_capital_within,
    assert_issuance_request_admissible,
    effective_authority_level,
    effective_capabilities,
    effective_capital_ceilings,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex
from qntyspot.errors import AuthorityCeilingError, AuthorityVerificationError, SessionIdentityError
from qntyspot.execution_contract import (
    LADDER,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    Capability,
    ExecutionSessionV0,
)
from qntyspot.ledger import ExecutionRuntime, assert_execution_replay_equivalence, open_ledger


ANCHOR = bytes.fromhex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
ANCHOR_FINGERPRINT = "34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e"
TRUST_CONFIG_DIGEST = "2a331617377dd39fe619b5eb7ca2ada6f937412246fdf15fd47a13c80ebda0d4"
COMMIT = "d3ed5d04f5a635d258ecdf2e0509719adde2947b"
IMPLEMENTATION_DIGEST = "11" * 32
TAKER = "0x00000000000000000000000000000000000000aa"
ROOT_ID = "qnty-authority-root-v0"
NETWORK_ID = "evm:4663"
VENUE_ID = "zero-x-allowance-holder"
RESERVED_SCOPE_ALIASES = ("*", "any", "ANY", " any ", "latest", "LATEST", " latest ")
AUTHORITY_SCOPE_FIELDS = (
    "permitted_repository_commit",
    "permitted_implementation_digest",
    "permitted_network_id",
    "permitted_taker_address",
    "permitted_venue_id",
)

SHADOW_SIGNATURE = bytes.fromhex(
    "9c21d092e59b19d65b003e51d8079a8df22aee58610a67010c5cd391409ac635"
    "30c505204e23616f4621802d46b6741689edbc64785c134f8066e6e489036703"
)
HIGH_SIGNATURE = bytes.fromhex(
    "49165dbf6d36c45d53c19fc180fe2f306c022717e8b19c731312b2be111df619"
    "c3e05ab933b8ed8eed6b178be41df8fcc8f58595f76a13443d797dad7980d509"
)
NEXT_EPOCH_SIGNATURE = bytes.fromhex(
    "8b7b621f41e5c293b3cc7a3c7a8c9773195815414a1a7cb892d801311b11d413"
    "58f2d634f39ca6a922f6f6e01cf8ce9856462a799a8e1088829cc67db93e8c0d"
)


def _trust_config_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "minimum_authority_epoch": 7,
            "public_key_fingerprint": ANCHOR_FINGERPRINT,
            "root_id": ROOT_ID,
            "schema": TRUST_CONFIG_SCHEMA,
            "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
            "trust_config_version": 1,
        }
    )


def _root_for(root_id: str) -> TrustedAuthorityRootV0:
    config = {
        "minimum_authority_epoch": 7,
        "public_key_fingerprint": ANCHOR_FINGERPRINT,
        "root_id": root_id,
        "schema": TRUST_CONFIG_SCHEMA,
        "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
        "trust_config_version": 1,
    }
    config_bytes = canonical_json_bytes(config)
    return load_trusted_authority_root(
        config_bytes,
        expected_config_digest=sha256_hex(config_bytes),
        anchor_bytes=ANCHOR,
    )


@pytest.fixture
def trusted_root() -> TrustedAuthorityRootV0:
    return load_trusted_authority_root(
        _trust_config_bytes(),
        expected_config_digest=TRUST_CONFIG_DIGEST,
        anchor_bytes=ANCHOR,
    )


def _policy(level: AuthorityLevel) -> AuthorityPolicyRefV0:
    return AuthorityPolicyRefV0(
        authority_root_id=ROOT_ID,
        granted_level=level,
        permitted_repository_commit=COMMIT,
        permitted_implementation_digest=IMPLEMENTATION_DIGEST,
        permitted_network_id=NETWORK_ID,
        permitted_taker_address=TAKER,
        permitted_venue_id=VENUE_ID,
        max_reservation_atomic=1_000_000,
        max_cumulative_atomic=4_000_000,
        not_before_epoch_s=NOW - 100,
        not_after_epoch_s=NOW + 900,
    )


def _receipt(
    level: AuthorityLevel = AuthorityLevel.SHADOW,
    *,
    authority_epoch: int = 8,
    serial: int = 1,
) -> AuthorityGrantReceiptV0:
    return AuthorityGrantReceiptV0(
        root_id=ROOT_ID,
        public_key_fingerprint=ANCHOR_FINGERPRINT,
        signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
        authority_epoch=authority_epoch,
        serial=serial,
        issued_at_epoch_s=NOW - 10,
        authority_policy=_policy(level),
        signature=(
            SHADOW_SIGNATURE
            if level is AuthorityLevel.SHADOW and authority_epoch == 8
            else NEXT_EPOCH_SIGNATURE
            if level is AuthorityLevel.SHADOW
            else HIGH_SIGNATURE
        ),
    )


def _session(receipt: AuthorityGrantReceiptV0) -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit=COMMIT,
        implementation_digest=IMPLEMENTATION_DIGEST,
        runtime_identity="cpython-3.14",
        db_schema_version=1,
        policy_id="22" * 32,
        authority_policy_digest=receipt.authority_policy_digest,
        taker_address=TAKER,
        network_id=NETWORK_ID,
        venue_id=VENUE_ID,
        venue_adapter_version="v0",
        started_at_epoch_s=NOW - 60,
        session_ordinal=0,
    )


@pytest.fixture
def shadow_receipt() -> AuthorityGrantReceiptV0:
    return _receipt()


@pytest.fixture
def shadow_verified(
    trusted_root: TrustedAuthorityRootV0, shadow_receipt: AuthorityGrantReceiptV0
) -> VerifiedAuthorityGrantV0:
    return verify_authority_grant(
        receipt=shadow_receipt.serialized,
        trusted_root=trusted_root,
        session=_session(shadow_receipt),
        now_epoch_s=NOW,
    )


def test_valid_shadow_grant_is_canonical_and_round_trips(
    trusted_root: TrustedAuthorityRootV0, shadow_receipt: AuthorityGrantReceiptV0
) -> None:
    parsed = AuthorityGrantReceiptV0.from_bytes(shadow_receipt.serialized)
    assert parsed == shadow_receipt
    assert parsed.serialized == shadow_receipt.serialized
    verified = verify_authority_grant(
        receipt=parsed,
        trusted_root=trusted_root,
        session=_session(parsed),
        now_epoch_s=NOW,
    )
    assert verified.receipt_id == parsed.receipt_id
    assert verified.signed_body_digest == parsed.signed_body_digest
    assert "anchor_bytes" not in parsed.to_object()
    assert "public_key" not in parsed.to_object()


def test_root_config_is_explicit_digest_pinned_and_never_defaulted() -> None:
    assert AUTHORITY_ROOT_CONTRACT_VERSION.endswith("_V0")
    with pytest.raises(AuthorityVerificationError, match="digest"):
        load_trusted_authority_root(
            _trust_config_bytes(),
            expected_config_digest="00" * 32,
            anchor_bytes=ANCHOR,
        )
    with pytest.raises(AuthorityVerificationError, match="canonical"):
        load_trusted_authority_root(
            b" " + _trust_config_bytes(),
            expected_config_digest=sha256_hex(b" " + _trust_config_bytes()),
            anchor_bytes=ANCHOR,
        )


@pytest.mark.parametrize(
    "case",
    [
        "bad_signature",
        "wrong_root",
        "wrong_key_fingerprint",
        "old_epoch",
        "expired",
        "not_yet_valid",
        "wrong_commit",
        "wrong_implementation_digest",
        "wrong_network",
        "wrong_taker",
        "wrong_venue",
        "mutated_body_after_signature",
        "signature_substitution",
    ],
)
def test_hostile_receipt_variants_fail_closed(
    case: str,
    trusted_root: TrustedAuthorityRootV0,
    shadow_receipt: AuthorityGrantReceiptV0,
) -> None:
    receipt = shadow_receipt
    root = trusted_root
    session = _session(receipt)
    now = NOW
    if case == "bad_signature":
        receipt = replace(receipt, signature=bytes(64))
    elif case == "wrong_root":
        root = _root_for("other-authority-root")
    elif case == "wrong_key_fingerprint":
        receipt = replace(receipt, public_key_fingerprint="00" * 32)
    elif case == "old_epoch":
        receipt = replace(receipt, authority_epoch=6)
    elif case == "expired":
        now = NOW + 901
    elif case == "not_yet_valid":
        now = NOW - 101
    elif case == "wrong_commit":
        session = replace(session, repository_commit="b" * 40)
    elif case == "wrong_implementation_digest":
        session = replace(session, implementation_digest="00" * 32)
    elif case == "wrong_network":
        session = replace(session, network_id="evm:1")
    elif case == "wrong_taker":
        session = replace(session, taker_address="0x00000000000000000000000000000000000000bb")
    elif case == "wrong_venue":
        session = replace(session, venue_id="other-venue")
    elif case == "mutated_body_after_signature":
        receipt = replace(receipt, issued_at_epoch_s=NOW - 9)
    elif case == "signature_substitution":
        receipt = replace(receipt, signature=bytes.fromhex("ab" * 64))
    with pytest.raises(AuthorityVerificationError):
        verify_authority_grant(
            receipt=receipt,
            trusted_root=root,
            session=session,
            now_epoch_s=now,
        )


def test_repository_and_implementation_bindings_remain_independent(
    trusted_root: TrustedAuthorityRootV0,
    shadow_receipt: AuthorityGrantReceiptV0,
) -> None:
    session = _session(shadow_receipt)
    with pytest.raises(AuthorityVerificationError, match="repository commit"):
        verify_authority_grant(
            receipt=shadow_receipt,
            trusted_root=trusted_root,
            session=replace(session, repository_commit="b" * 40),
            now_epoch_s=NOW,
        )
    with pytest.raises(AuthorityVerificationError, match="implementation digest"):
        verify_authority_grant(
            receipt=shadow_receipt,
            trusted_root=trusted_root,
            session=replace(session, implementation_digest="00" * 32),
            now_epoch_s=NOW,
        )


def test_old_epoch_is_rejected_even_when_the_signature_is_valid(
    trusted_root: TrustedAuthorityRootV0, shadow_receipt: AuthorityGrantReceiptV0
) -> None:
    assert shadow_receipt.authority_epoch < trusted_root.minimum_authority_epoch + 2
    with pytest.raises(AuthorityVerificationError, match="minimum epoch"):
        verify_authority_grant(
            receipt=replace(shadow_receipt, authority_epoch=6),
            trusted_root=trusted_root,
            session=_session(shadow_receipt),
            now_epoch_s=NOW,
        )


def test_higher_external_grant_cannot_escape_shadow_source_ceiling(
    trusted_root: TrustedAuthorityRootV0,
) -> None:
    high = _receipt(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)
    verified = verify_authority_grant(
        receipt=high,
        trusted_root=trusted_root,
        session=_session(high),
        now_epoch_s=NOW,
    )
    assert effective_authority_level(
        source_phase_ceiling=AuthorityLevel.SHADOW,
        verified_grant=verified,
        now_epoch_s=NOW,
    ) is AuthorityLevel.SHADOW
    assert effective_capabilities(
        source_phase_ceiling=AuthorityLevel.SHADOW,
        verified_grant=verified,
        now_epoch_s=NOW,
    ) == LADDER[AuthorityLevel.SHADOW]
    assert Capability.PRODUCE_SIGNATURE not in effective_capabilities(
        source_phase_ceiling=AuthorityLevel.SHADOW,
        verified_grant=verified,
        now_epoch_s=NOW,
    )
    assert Capability.SUBMIT_EXACT_BYTES not in effective_capabilities(
        source_phase_ceiling=AuthorityLevel.SHADOW,
        verified_grant=verified,
        now_epoch_s=NOW,
    )
    with pytest.raises(AuthorityCeilingError, match="current reviewed phase"):
        effective_capabilities(
            source_phase_ceiling=AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER,
            verified_grant=verified,
            now_epoch_s=NOW,
        )


def test_both_gates_are_required() -> None:
    with pytest.raises(AuthorityVerificationError, match="verified grant"):
        effective_capabilities(
            source_phase_ceiling=AuthorityLevel.SHADOW,
            verified_grant=None,  # type: ignore[arg-type]
            now_epoch_s=NOW,
        )
    with pytest.raises(TypeError):
        VerifiedAuthorityGrantV0()  # type: ignore[call-arg]


def test_capital_is_always_the_minimum_of_local_and_external_ceilings(
    shadow_verified: VerifiedAuthorityGrantV0,
) -> None:
    assert effective_capital_ceilings(
        local_per_action_atomic=2_000_000,
        local_cumulative_atomic=8_000_000,
        verified_grant=shadow_verified,
        now_epoch_s=NOW,
    ) == (1_000_000, 4_000_000)
    with pytest.raises(AuthorityCeilingError, match="per-action"):
        assert_effective_capital_within(
            requested_atomic=1_000_001,
            held_atomic=0,
            local_per_action_atomic=2_000_000,
            local_cumulative_atomic=8_000_000,
            verified_grant=shadow_verified,
            now_epoch_s=NOW,
        )
    with pytest.raises(AuthorityCeilingError, match="cumulative"):
        assert_effective_capital_within(
            requested_atomic=1,
            held_atomic=4_000_000,
            local_per_action_atomic=2_000_000,
            local_cumulative_atomic=8_000_000,
            verified_grant=shadow_verified,
            now_epoch_s=NOW,
        )


@pytest.mark.parametrize("alias", RESERVED_SCOPE_ALIASES)
@pytest.mark.parametrize("field_name", AUTHORITY_SCOPE_FIELDS)
def test_authority_policy_rejects_reserved_exact_scope_aliases(
    field_name: str, alias: str
) -> None:
    with pytest.raises((AuthorityCeilingError, SessionIdentityError)):
        replace(_policy(AuthorityLevel.SHADOW), **{field_name: alias})


@pytest.mark.parametrize("alias", RESERVED_SCOPE_ALIASES)
@pytest.mark.parametrize(
    "field_name",
    ("allowed_network_ids", "allowed_taker_addresses", "allowed_venue_ids"),
)
def test_issuance_policy_rejects_reserved_exact_scope_aliases(
    field_name: str, alias: str
) -> None:
    values = {
        "allowed_network_ids": (NETWORK_ID,),
        "allowed_taker_addresses": (TAKER,),
        "allowed_venue_ids": (VENUE_ID,),
    }
    values[field_name] = (alias,)
    with pytest.raises(AuthorityVerificationError):
        AuthorityIssuancePolicyV0(
            root_id=ROOT_ID,
            repository_identity="CipherCuttle/QntySpot",
            maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
            allowed_network_ids=values["allowed_network_ids"],
            allowed_taker_addresses=values["allowed_taker_addresses"],
            allowed_venue_ids=values["allowed_venue_ids"],
            max_reservation_atomic=1_000_000,
            max_cumulative_atomic=4_000_000,
            max_grant_duration_s=1_000,
        )


@pytest.mark.parametrize("alias", RESERVED_SCOPE_ALIASES)
@pytest.mark.parametrize("field_name", AUTHORITY_SCOPE_FIELDS)
def test_authority_receipt_rejects_reserved_exact_scope_aliases(
    field_name: str, alias: str
) -> None:
    policy = _policy(AuthorityLevel.SHADOW)
    object.__setattr__(policy, field_name, alias)
    with pytest.raises(AuthorityVerificationError):
        AuthorityGrantReceiptV0(
            root_id=ROOT_ID,
            public_key_fingerprint=ANCHOR_FINGERPRINT,
            signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
            authority_epoch=8,
            serial=1,
            issued_at_epoch_s=NOW - 10,
            authority_policy=policy,
            signature=bytes(64),
        )


@pytest.mark.parametrize("alias", RESERVED_SCOPE_ALIASES)
@pytest.mark.parametrize("field_name", AUTHORITY_SCOPE_FIELDS)
def test_issuance_request_rejects_reserved_exact_scope_aliases(
    field_name: str, alias: str
) -> None:
    issuer_policy = AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE_ID,),
        max_reservation_atomic=1_000_000,
        max_cumulative_atomic=4_000_000,
        max_grant_duration_s=1_000,
    )
    request = _policy(AuthorityLevel.RECONCILE_ONLY)
    object.__setattr__(request, field_name, alias)
    with pytest.raises(AuthorityVerificationError):
        assert_issuance_request_admissible(
            issuer_policy,
            request,
            repository_identity="CipherCuttle/QntySpot",
        )


def test_anyswap_like_venue_identity_remains_an_exact_identity() -> None:
    issuer_policy = AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=("anyswap-v1",),
        max_reservation_atomic=1_000_000,
        max_cumulative_atomic=4_000_000,
        max_grant_duration_s=1_000,
    )
    request = replace(_policy(AuthorityLevel.RECONCILE_ONLY), permitted_venue_id="anyswap-v1")
    assert_issuance_request_admissible(
        issuer_policy,
        request,
        repository_identity="CipherCuttle/QntySpot",
    )


def test_verified_grant_is_revalidated_at_every_consumption_time(
    shadow_verified: VerifiedAuthorityGrantV0,
) -> None:
    with pytest.raises(AuthorityCeilingError, match="not valid"):
        effective_authority_level(
            source_phase_ceiling=AuthorityLevel.SHADOW,
            verified_grant=shadow_verified,
            now_epoch_s=NOW - 101,
        )
    with pytest.raises(AuthorityCeilingError, match="not valid"):
        effective_capabilities(
            source_phase_ceiling=AuthorityLevel.SHADOW,
            verified_grant=shadow_verified,
            now_epoch_s=NOW + 900,
        )
    with pytest.raises(AuthorityCeilingError, match="not valid"):
        effective_capital_ceilings(
            local_per_action_atomic=2_000_000,
            local_cumulative_atomic=8_000_000,
            verified_grant=shadow_verified,
            now_epoch_s=NOW + 900,
        )
    with pytest.raises(AuthorityCeilingError, match="not valid"):
        assert_effective_capital_within(
            requested_atomic=1,
            held_atomic=0,
            local_per_action_atomic=2_000_000,
            local_cumulative_atomic=8_000_000,
            verified_grant=shadow_verified,
            now_epoch_s=NOW + 900,
        )


def test_parser_rejects_canonicalization_duplicate_keys_and_policy_digest_mutation(
    shadow_receipt: AuthorityGrantReceiptV0,
) -> None:
    raw = shadow_receipt.serialized
    with pytest.raises(AuthorityVerificationError, match="canonical"):
        AuthorityGrantReceiptV0.from_bytes(json.dumps(json.loads(raw), indent=2).encode())
    with pytest.raises(AuthorityVerificationError, match="duplicate"):
        AuthorityGrantReceiptV0.from_bytes(
            raw.replace(b'"authority_epoch":8,', b'"authority_epoch":8,"authority_epoch":8,', 1)
        )
    document = json.loads(raw)
    document["authority_policy_digest"] = "00" * 32
    with pytest.raises(AuthorityVerificationError, match="digest"):
        AuthorityGrantReceiptV0.from_bytes(canonical_json_bytes(document))


def test_wildcard_scope_is_not_an_exact_grant() -> None:
    with pytest.raises(AuthorityCeilingError, match="wildcard"):
        AuthorityPolicyRefV0(
            authority_root_id=ROOT_ID,
            granted_level=AuthorityLevel.SHADOW,
            permitted_repository_commit=COMMIT,
            permitted_implementation_digest=IMPLEMENTATION_DIGEST,
            permitted_network_id="*",
            permitted_taker_address=TAKER,
            permitted_venue_id=VENUE_ID,
            max_reservation_atomic=1,
            max_cumulative_atomic=1,
            not_before_epoch_s=NOW,
            not_after_epoch_s=NOW + 1,
        )


def test_issuer_policy_seam_is_narrow_and_does_not_issue() -> None:
    issuer_policy = AuthorityIssuancePolicyV0(
        root_id=ROOT_ID,
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.RECONCILE_ONLY,
        allowed_network_ids=(NETWORK_ID,),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(VENUE_ID,),
        max_reservation_atomic=1_000_000,
        max_cumulative_atomic=4_000_000,
        max_grant_duration_s=1_000,
    )
    assert_issuance_request_admissible(
        issuer_policy,
        _policy(AuthorityLevel.RECONCILE_ONLY),
        repository_identity="CipherCuttle/QntySpot",
    )
    with pytest.raises(AuthorityVerificationError, match="issuer policy"):
        assert_issuance_request_admissible(
            issuer_policy,
            _policy(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER),
            repository_identity="CipherCuttle/QntySpot",
        )


def test_sqlite_persists_external_epoch_and_rejects_local_rollback(
    tmp_path,
    trusted_root: TrustedAuthorityRootV0,
    shadow_verified: VerifiedAuthorityGrantV0,
) -> None:
    with open_ledger(str(tmp_path / "authority.sqlite3")) as ledger:
        runtime = ExecutionRuntime(ledger)
        assert runtime.record_verified_authority(shadow_verified, accepted_at_epoch_s=NOW)
        assert not runtime.record_verified_authority(shadow_verified, accepted_at_epoch_s=NOW + 1)
        next_epoch = _receipt(authority_epoch=9, serial=2)
        next_verified = verify_authority_grant(
            receipt=next_epoch,
            trusted_root=trusted_root,
            session=_session(next_epoch),
            now_epoch_s=NOW,
        )
        assert runtime.record_verified_authority(next_verified, accepted_at_epoch_s=NOW + 2)
        row = ledger.connection.execute("SELECT * FROM authority_root_state").fetchone()
        assert row["highest_accepted_epoch"] == 9
        assert row["minimum_authority_epoch"] == 7
        assert row["root_id"] == ROOT_ID
        with pytest.raises(sqlite3.IntegrityError, match="rollback"):
            ledger.connection.execute(
                "UPDATE authority_root_state SET highest_accepted_epoch = 7 "
                "WHERE trust_config_digest = ?",
                (TRUST_CONFIG_DIGEST,),
            )
        assert_execution_replay_equivalence(ledger)


def test_sqlite_authority_root_state_blocks_hostile_sql_but_allows_high_water_advance(
    tmp_path,
    shadow_verified: VerifiedAuthorityGrantV0,
) -> None:
    with open_ledger(str(tmp_path / "authority-state.sqlite3")) as ledger:
        runtime = ExecutionRuntime(ledger)
        assert runtime.record_verified_authority(shadow_verified, accepted_at_epoch_s=NOW)
        conn = ledger.connection
        state_key = (TRUST_CONFIG_DIGEST,)

        hostile_updates = (
            ("trust_config_digest", "aa" * 32),
            ("root_id", "other-root"),
            ("public_key_fingerprint", "bb" * 32),
            ("minimum_authority_epoch", 8),
            ("highest_accepted_epoch", 7),
            ("highest_accepted_receipt_id", "cc" * 32),
            ("highest_accepted_at_epoch_s", NOW - 1),
        )
        for column, value in hostile_updates:
            with pytest.raises(sqlite3.IntegrityError, match="rollback"):
                conn.execute(
                    f"UPDATE authority_root_state SET {column} = ? "
                    "WHERE trust_config_digest = ?",
                    (value, *state_key),
                )

        with pytest.raises(sqlite3.IntegrityError, match="non-deletable"):
            conn.execute(
                "DELETE FROM authority_root_state WHERE trust_config_digest = ?",
                state_key,
            )

        conn.execute(
            "UPDATE authority_root_state SET highest_accepted_epoch = ?, "
            "highest_accepted_receipt_id = ?, highest_accepted_at_epoch_s = ? "
            "WHERE trust_config_digest = ?",
            (9, "dd" * 32, NOW + 1, TRUST_CONFIG_DIGEST),
        )
        row = conn.execute(
            "SELECT * FROM authority_root_state WHERE trust_config_digest = ?",
            state_key,
        ).fetchone()
        assert row["highest_accepted_epoch"] == 9
        assert row["highest_accepted_receipt_id"] == "dd" * 32
        assert row["highest_accepted_at_epoch_s"] == NOW + 1


def test_expired_verified_grant_cannot_be_recorded(
    tmp_path,
    shadow_verified: VerifiedAuthorityGrantV0,
) -> None:
    with open_ledger(str(tmp_path / "expired-authority.sqlite3")) as ledger:
        with pytest.raises(AuthorityVerificationError, match="acceptance time"):
            ExecutionRuntime(ledger).record_verified_authority(
                shadow_verified,
                accepted_at_epoch_s=NOW + 900,
            )


def test_runtime_will_not_record_an_unverified_receipt(tmp_path, shadow_receipt) -> None:
    with open_ledger(str(tmp_path / "authority.sqlite3")) as ledger:
        runtime = ExecutionRuntime(ledger)
        with pytest.raises(AuthorityVerificationError, match="verified"):
            runtime.record_verified_authority(shadow_receipt, accepted_at_epoch_s=NOW)
