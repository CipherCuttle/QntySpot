# QNTYSPOT_AUTHENTICATED_ACCEPTED_INTENT_POLICY_BRIDGE_V0

## Purpose

Convert a cryptographically authenticated Qnty accepted-intent target change into a deterministic request for **policy evaluation only**.

This is the first boundary allowed to wake the policy layer after Qnty publication authentication. It is not policy admission and it is not execution.

## Input authority

The only admissible input is `VerifiedQntyPublicationV0`, produced by `authenticate_accepted_execution_intent_v2` after verification against an explicit external Qnty publication trust root.

Raw V2 bytes, parsed JSON, self-consistent intent objects, and caller-constructed projections are not admissible bridge inputs.

## Transition behavior

- authenticated `NO_ACTION` → no policy request (`None`)
- authenticated `TARGET_CHANGE` → one immutable `AcceptedIntentPolicyEvaluationRequestV0`

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

- real authenticated NO_ACTION remains inert
- authenticated TARGET_CHANGE deterministically emits exactly one policy-evaluation request
- unverified inputs fail closed
- request is immutable and canonical
- no executable policy/economic fields leak into the request
- no policy parser, execution, authority-root, network, or ambient-state dependency
- deployment identity advances intentionally while historical identities remain unchanged
- full QntySpot suite and authority-continuity checks pass
- no Critical/High hostile-review finding remains
