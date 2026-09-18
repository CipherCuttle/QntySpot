# Ink V0F signed swap admission and zero-money rehearsal

This phase prepares the last pre-Level-3 boundary for Ink V0F.

The binding source ceiling remains:

`RECONCILE_ONLY`

No transaction is submitted by this phase.

## Exact signed swap admission

The human-controlled signer returns complete EIP-1559 bytes.

QntySpot accepts those bytes only when all of the following are true:

- the same-amount revalidation record was produced by the live revalidation path;
- chain id is Ink mainnet;
- recovered sender is the frozen taker;
- target is the frozen InkySwap router;
- native value is zero;
- calldata is byte-for-byte identical to the frozen swap request;
- nonce equals the frozen swap nonce;
- gas and EIP-1559 fee fields remain within the frozen ceilings;
- the complete byte string cryptographically re-validates against the same scope.

The byte string is not re-serialized or modified.

## Revalidation remains a proof-of-path fact

`InkV0FSameAmountRevalidationV0` is now fenced so caller-built instances cannot
masquerade as the result of live pool/router/allowance/nonce/base-fee checks.

The revalidation receives a deterministic `revalidation_id` binding:

- exact swap scope;
- market observation;
- router observation;
- allowance observation;
- signer-state observation;
- fresh quote output;
- fresh admissible minimum output.

## Zero-money rehearsal

The rehearsal runner takes:

- canonical session;
- canonical intent;
- canonical frozen envelope;
- exact-byte-validated signed swap admission;
- explicit rehearsal timestamp.

It does **not** accept:

- a transport;
- an RPC provider;
- a submission callback;
- a chain observation.

The mock submission records:

`transport_invoked = false`

`external_effect = false`

The rehearsal reconciliation record is a separate simulation-only type:

`persistable_as_chain_truth = false`

`external_effect = false`

`SIMULATED_CONFIRMED_NO_CHAIN_EFFECT`

It is intentionally not a `ChainObservationV0` and cannot be passed off as
real reconciliation evidence.

## Authority boundary

This phase does not call the generic durable exact-byte admission or submission
entrypoints. Those remain capability-gated above the current source ceiling.

Still forbidden:

- signature production;
- approval submission;
- swap submission;
- raw transaction broadcast;
- live capital movement;
- source authority transition.

## What this prepares

After this phase is merged and reviewed, the remaining path is:

1. explicit source transition from `RECONCILE_ONLY` to
   `HUMAN_SIGNED_EXECUTION`;
2. refresh the QntyAuthorityRoot runtime binding against the new canonical
   QntySpot implementation digest;
3. issue one short-lived Level-3 grant bound to the exact runtime/taker/Ink
   scope;
4. run a zero-money Level-3 rehearsal;
5. only then consider the first dust live execution under the frozen 0.001 WETH
   ceiling.
