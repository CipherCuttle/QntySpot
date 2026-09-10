# Qnty accepted execution intent publication authentication V0

This phase closes the origin-authentication gap left intentionally by the dynamic V2 consumer.

## Goal

Authenticate that the exact `QNTY_ACCEPTED_EXECUTION_INTENT_V2` bytes were signed by a dedicated Qnty publication root, without granting any economic authority.

## Trust model

The publication trust root is separate from the economic authority root.

- root id: `qnty-accepted-intent-publication`
- purpose: `QNTY_ACCEPTED_INTENT_ORIGIN_AUTHENTICATION_ONLY`
- signature algorithm: Ed25519
- trust configuration: explicit canonical JSON plus independently supplied digest and 32-byte public key
- no ambient environment trust
- no private-key loading or receipt issuance in QntySpot

The signed publication receipt binds:

- exact received artifact SHA-256
- accepted-intent V2 `intent_digest`
- Qnty repository identity
- Qnty repository commit
- publication epoch and serial
- publication root identity and public-key fingerprint
- V2 schema name/version

The exact artifact SHA-256 deliberately distinguishes byte-identical transport from merely equivalent JSON. A changed trailing newline, reserialization, or any other byte substitution requires a new valid publication signature.

## Successful verification

Successful verification yields an opaque `VerifiedQntyPublicationV0` object and evidence with:

- `origin_authentication = VERIFIED_BY_QNTY_PUBLICATION_ROOT`
- `publication_authentication = VERIFIED`
- `trusted_transport_required = SATISFIED`
- `policy_bridge_eligible = YES`
- `policy_admission_authorized = NO`

`policy_bridge_eligible = YES` means only that a later, separately reviewed policy bridge may accept this verified proof object as an input. It is not permission to evaluate policy or execute.

## Frozen non-authority boundary

This phase does not:

- import Qnty or QntyLab runtime code
- recompute research
- issue publication receipts
- load publication private keys
- reuse the economic authority-root contract
- select a QntySpot side
- evaluate policy
- request a quote
- access venue/network execution paths
- construct or sign transactions
- submit transactions
- authorize capital

An authenticated `TARGET_CHANGE` therefore remains observational. QntySpot still emits `qntyspot_execution_action_authorized = NO` and `policy_evaluation_required = NO`.

## Key separation

Production deployment must provision a dedicated publication key. The publication key must not be the economic authority-root key. Domain separation is also enforced in the signed body through the publication-only schema, root id, and purpose.

## Next phase

The next bounded phase is the Qnty publication issuer / key-provisioning seam that produces real signed publication receipts for V2 artifacts. Only after a real producer-issued receipt is available should a separately reviewed QntySpot policy bridge consume `VerifiedQntyPublicationV0`.
