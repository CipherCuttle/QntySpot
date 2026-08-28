# QntySpot external authority-root contract V0

~~~
CONTRACT                  = QNTY_SPOT_EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0
CANONICAL_QNTYSPOT_PARENT = d3ed5d04f5a635d258ecdf2e0509719adde2947b
PROGRAM_A                 = CLOSED
PROGRAM_B                 = CONTRACT CLOSED
PROGRAM_B1                = CANONICAL PASS / EXTERNAL ROOT DEFERRED
AUTHORITY                 = ROBINHOOD_SHADOW_READ_ONLY
PHASE_GRANTED_AUTHORITY   = LEVEL 0 (SHADOW)
SIGNING_AUTHORIZED        = NO
LIVE_CAPITAL_AUTHORIZED   = NO
CAPITAL_AUTHORITY         = NONE
~~~

This phase freezes the artifact boundary for an independently rooted
authority verifier. It is a contract and consumer implementation only. It
does not create, deploy, or invoke an issuer and does not authorize signing,
approval, submission, testnet execution, mainnet execution, account mutation,
or capital.

## Authority separation

QntySpot is the authority consumer. A future `QntyAuthorityRoot` is the
authority issuer and root verifier. QntySpot never stores the issuer's private
material, self-issues a grant, or trusts an anchor merely because a receipt
contains it. The cross-repository boundary is serialized artifacts and
digests; QntySpot does not import or depend on an authority-root checkout.

QntyPolicyGate remains an external Git-governance root. Its independent
deployment digest pattern is reused only as a trust-configuration pattern.
It does not prove runtime authority and is not a trading-authority service.
No QntyPolicyGate source or configuration was changed for this phase.

## Dual control

The effective authority rule is normative:

~~~
EFFECTIVE_AUTHORITY = MIN(
    QNTYSPOT_SOURCE_PHASE_CEILING,
    VERIFIED_EXTERNAL_GRANT_LEVEL,
)
~~~

An external receipt is necessary for future authority above `SHADOW`, but it
is never sufficient. Raising the reviewed source ceiling is also necessary,
but never sufficient. If either gate refuses, the result fails closed. The
current source ceiling is `SHADOW`, so even a valid receipt claiming
`AUTONOMOUS_BOUNDED_SIGNER` produces `SHADOW` capabilities and no signing or
submission capability.

Capital is intersected in the same direction:

~~~
effective_per_action = MIN(local_policy_per_action, external_max_reservation)
effective_cumulative = MIN(local_policy_cumulative, external_max_cumulative)
~~~

The external root can only provide an upper bound. It cannot override a
stricter local policy, and this phase has no capital authority regardless of
the computed contract ceilings.

## Frozen artifacts

### `TrustedAuthorityRootV0`

The operator/deployment boundary supplies, explicitly and outside QntySpot
source:

- `root_id`
- `signature_algorithm = Ed25519`
- `public_key_fingerprint` (SHA-256 of the 32-byte public anchor)
- `minimum_authority_epoch`
- `trust_config_version`
- a digest of the canonical trust configuration
- the matching public verification anchor

`load_trusted_authority_root(...)` requires canonical JSON bytes, an explicit
expected digest, and explicit anchor bytes. It reads no environment, clock,
filesystem, or ambient configuration and has no silent default. The anchor is
not serialized into a grant and is never accepted from a grant body.

### `AuthorityGrantReceiptV0`

The canonical signed body contains:

- `schema`, `root_id`, `signature_algorithm`, `public_key_fingerprint`
- positive `authority_epoch`, positive `serial`, and `issued_at_epoch_s`
- the complete existing `AuthorityPolicyRefV0` canonical object
- `authority_policy_digest`
- deterministic `grant_id`

The policy binds the exact repository commit, implementation digest, network,
taker address, venue, authority level, per-action ceiling, cumulative ceiling,
`not_before_epoch_s`, and `not_after_epoch_s`. All scopes are exact in V0:
wildcards, `latest`, and `any` forms are not accepted. Every grant expires;
an infinite interval is not a valid contract.

Ed25519 signs the complete canonical body. The serialized receipt adds the
signature and derived `receipt_id`. The receipt carries no private material,
transaction signature, or profitability/scientific/legal claim.

Identity formulas are:

~~~
authority_policy_digest = SHA256(canonical_json(AuthorityPolicyRefV0))
grant_id               = SHA256(canonical_json(
    {schema, root_id, authority_epoch, serial, authority_policy_digest}
))
signed_body_digest     = SHA256(canonical_signed_body_bytes)
receipt_id             = SHA256(canonical_json(
    {schema, grant_id, root_id, signature_algorithm,
     public_key_fingerprint, signed_body_digest, signature_digest}
))
~~~

`grant_id` excludes timestamps. `receipt_id` does not hash itself, so neither
identity is circular.

### `VerifiedAuthorityGrantV0`

This result is opaque and can only be constructed by successful
`verify_authority_grant(...)`. Verification requires the external root,
Ed25519 signature, canonical encoding, matching root and fingerprint,
minimum epoch, explicit time interval, exact session binding, authority-policy
digest, and every repository/implementation/network/taker/venue/ceiling
field. A caller cannot set a boolean to manufacture a verified result.

## Epoch, persistence, and outage semantics

`authority_epoch` is a positive monotone integer. A receipt below the
operator-pinned `minimum_authority_epoch` is rejected. QntySpot persists the
highest accepted epoch, root identity, fingerprint, minimum epoch, receipt
identity, and acceptance time in the `authority_root_state` SQLite table,
scoped by the external trust-configuration digest. A SQLite trigger rejects
root identity changes and rollback for that configuration.

This local row is continuity evidence, not rollback-proof trust. The external
operator/deployment minimum remains authoritative. Short-lived grants plus
the externally pinned minimum are sufficient for V0; distributed PKI and
consensus are deferred.

An authority-root outage prevents new issuance because no issuer is available.
It does not prevent QntySpot from reconciling already-existing external facts.

## Issuance boundary

Future issuance is an explicit operator action. The issuer must validate a
request against an independent `AuthorityIssuancePolicyV0` seam covering the
maximum level, exact allowed networks/venues/takers, maximum ceilings,
maximum duration, and QntySpot repository identity. No code path, adaptive
loop, or agent may request or receive more authority automatically. The first
issuer implementation must grant no more authority than the next test-only
phase requires; mainnet live-capital authority is not a default permission.

## Offline vectors and threat coverage

The focused offline suite contains deterministic vectors for:

`VALID_SHADOW_GRANT`, `BAD_SIGNATURE`, `WRONG_ROOT`,
`WRONG_KEY_FINGERPRINT`, `OLD_EPOCH`, `EXPIRED`, `NOT_YET_VALID`,
`WRONG_COMMIT`, `WRONG_IMPLEMENTATION_DIGEST`, `WRONG_NETWORK`,
`WRONG_TAKER`, `WRONG_VENUE`, `PER_ACTION_TOO_LARGE`,
`CUMULATIVE_TOO_LARGE`, `HIGHER_GRANT_THAN_SOURCE_CEILING`,
`MUTATED_BODY_AFTER_SIGNATURE`, `CANONICALIZATION_DIFFERENCE`, duplicate
keys, signature substitution, forged verified objects, and wildcard scope.

The vectors contain only a throwaway public anchor and detached signatures;
no production root secret or trading account secret is present. They defend
against self-issuance, receipt-supplied anchors, root replacement, source
ceiling bypass, replay/rollback, expiry reuse, commit/implementation/network/
taker/venue copying, ceiling widening, canonicalization ambiguity, signature
substitution, duplicate identities, wildcard authority, and accidental key
tracking. Evidence remains non-escalating: the root says only that this exact
deployment/action scope is permitted; it says nothing about profitability,
signals, strategy quality, user eligibility, or scientific validity.

## Terminal semantics

Successful completion of this phase is:

~~~
QNTY_SPOT_EXTERNAL_AUTHORITY_ROOT_CONTRACT_FROZEN_PASS
EXTERNAL_ROOT_CONTRACT_FROZEN      = YES
EXTERNAL_ROOT_IMPLEMENTED          = NO
EXTERNAL_ROOT_ACTUALLY_INDEPENDENT = NO
~~~

The next phase is `QNTY_AUTHORITY_ROOT_IMPLEMENTATION_V0`. Robinhood testnet
qualification does not begin in this phase.
