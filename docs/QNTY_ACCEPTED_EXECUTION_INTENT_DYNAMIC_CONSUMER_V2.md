# Qnty accepted execution intent dynamic consumer V2

This phase consumes `QNTY_ACCEPTED_EXECUTION_INTENT_V2` as an immutable external artifact while preserving the V1 consumer unchanged.

## Upstream evidence

- Qnty V2 contract merge: `3cfe0d607920313c8f2ec21e1511a195f5f63d38`
- Qnty V2 publication merge: `2ebed2af94127f2e018de46069d1bbe27178ca8a`
- Published fixture intent digest: `18d9f32c5afe5ba3c6f15b4596d4bb44a1ef9c8175e6d4715c9ccba23508f48f`
- Published fixture file SHA-256: `262f2eeea5c7fea979f1500538ffd146686e9c4ac8069a1ac5ae4d3ae7cd76db`

The fixture digest is evidence only. Runtime admission does not pin this event-specific digest and new intents from the same governed H003 lineage do not require a source edit.

## Boundary

The consumer validates canonical JSON, the V2 content digest, exact schema fields, the no-authority block, governed research identity, Qnty/QntyLab provenance claims, acceptance-record binding, and decision derivation for both `NO_ACTION` and `TARGET_CHANGE`.

A V2 content digest proves integrity of the supplied bytes; it does not by itself authenticate that those bytes were actually transported from Qnty. Therefore the V2 consumer explicitly returns `origin_authentication = UNPROVEN_BY_V2_BYTES`, `trusted_transport_required = YES`, and `policy_admission_authorized = NO`.

Even a structurally valid `TARGET_CHANGE` remains observational only. It does not select a QntySpot side, evaluate policy, request a quote, access a network, sign, submit, or authorize capital.

## Next boundary

Before a dynamic V2 `TARGET_CHANGE` may wake QntySpot policy, add a separate authenticated publication/transport proof that cryptographically or repository-verifiably binds the received bytes to Qnty. Do not weaken this by treating a self-consistent SHA-256 or caller-supplied provenance string as origin authentication.
