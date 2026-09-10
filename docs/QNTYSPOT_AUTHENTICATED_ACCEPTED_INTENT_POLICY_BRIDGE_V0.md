# QNTYSPOT_AUTHENTICATED_ACCEPTED_INTENT_POLICY_BRIDGE_V0

## Purpose

Convert a cryptographically authenticated Qnty accepted-intent target change into a deterministic request for **policy evaluation only**.

This is the first boundary allowed to wake the policy layer after Qnty publication authentication. It is not policy admission and it is not execution.

## Input authority

The bridge does **not** trust a caller-retained `VerifiedQntyPublicationV0`. Python object immutability is not an authentication boundary: hostile in-process code can manufacture or mutate objects with low-level object primitives.

The admissible bridge inputs are therefore explicit immutable byte inputs plus the independently supplied publication trust material:

- exact accepted-intent bytes
- exact publication-receipt bytes
- canonical publication trust-config bytes
- independently supplied expected trust-config digest
- public Ed25519 anchor bytes
- explicit QntySpot consumer commit

At the point of policy-bridge consumption, the bridge reloads the trust root and calls `authenticate_accepted_execution_intent_v2` again. Only the proof created inside that same bridge call is consumed. Caller-constructed, retained, subclassed, or low-level-mutated proof objects are not bridge inputs.

This repeated verification is deliberate trust-boundary work, not strategy recomputation: QntySpot still does not recompute Qnty/QntyLab research.

## Transition behavior

- re-authenticated `NO_ACTION` → no policy request (`None`)
- re-authenticated `TARGET_CHANGE` → one immutable `AcceptedIntentPolicyEvaluationRequestV0`

The TARGET_CHANGE request binds:

- Qnty publication receipt id
- signed publication-body digest
- publication trust-config digest
- accepted-intent digest
- Qnty repository commit declared by the publication receipt
- QntySpot repository commit used by the authenticated consumer
- QntySpot accepted-intent consumer implementation version
- effective source timestamp
- previous and current research targets

The request id is deterministic over those fields plus the request schema and `TARGET_CHANGE` transition.

## Deliberate non-authority

The request is `UNBOUND` to any executable PolicyV0 and explicitly requires an independent policy binding.

It carries no instrument, venue, amount, quote, executable price, slippage, taker, transaction, network id, or signed bytes. It cannot import or call the PolicyV0 parser, execution contract, economic authority root, network clients, or environment configuration.

Every economic authority field remains `NO`:

- policy admission
- economic action
- network activity
- signing
- submission
- capital

A policy evaluator may later consume this request only under a separately governed contract that binds it to an independently admitted PolicyV0. That future phase must not reinterpret this request as execution authority.

## Deployment identity

`qntyspot/accepted_intent_policy_bridge.py` is an authority-binding runtime source input. The deployment-identity manifest includes it for current builds while preserving pre-bridge historical source manifests and digests.

## Closure target

`QNTYSPOT_AUTHENTICATED_ACCEPTED_INTENT_POLICY_BRIDGE_V0_CLOSED_PASS` requires:

- real signed NO_ACTION remains inert after re-authentication
- signed TARGET_CHANGE deterministically emits exactly one policy-evaluation request
- retained, subclassed, low-level-forged, or mutated proof objects cannot substitute for signed bytes
- tampered accepted-intent bytes fail publication re-authentication
- mutable receipt/trust objects are not accepted at the bridge byte boundary
- request is immutable and canonical
- no executable policy/economic fields leak into the request
- no policy parser, execution, authority-root, network, or ambient-state dependency
- deployment identity advances intentionally while historical identities remain unchanged
- full QntySpot suite and authority-continuity checks pass
- no Critical/High hostile-review finding remains
