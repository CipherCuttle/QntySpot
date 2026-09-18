# Ink V0F router/envelope pre-authorization

This phase prepares the final Level-3 runtime seams while the binding source
ceiling remains `RECONCILE_ONLY`.

## Same-block live router verification

`InkV0FLiveVerifier` reuses the strict two-provider Ink JSON-RPC client and
requires the same provider endpoints and exact common block as the market
observation that justified the quote.

At that common block, both providers must agree on:

- router runtime bytecode SHA-256 and length;
- `factory()` = the pinned InkySwap V2 factory;
- `WETH()` = the pinned Ink WETH contract;
- the relevant ERC-20 `allowance(taker, router)`.

Any wrong chain, stale common block, provider lag, provider disagreement,
bytecode change, factory change, WETH change, malformed ABI result, or allowance
disagreement fails closed.

## Dormant Level-3 records

The phase adds exact builders/validators for the existing generic
`ExecutionEnvelopeV0` and `ApprovalActionV0`.

The Ink envelope is derived entirely from the reviewed human-signing preview,
same-block router observation, and execution session. It is pinned to:

- exact economic action;
- exact taker and chain;
- exact WETH/KRAKMASK direction;
- exact router target;
- zero native value;
- exact calldata digest/length;
- exact amount in / minimum out;
- exact nonce, gas and fee ceilings;
- exact grant digest;
- quote block and evidence digests.

The first-live approval path additionally requires an independently observed
**zero** prior allowance and constructs only the exact amount required by the
swap. Non-zero standing allowance fails closed for this first dust phase.

The runtime persistence entrypoints remain guarded by
`CONSTRUCT_ENVELOPE` / `AUTHORIZE_APPROVAL`. Since the binding source
ceiling is still Level 1, these entrypoints are unreachable in this phase.


## Level-3 persistence trust boundary

The durable runtime does not accept a caller-built preview, router observation,
or allowance observation. Once Level 3 is separately authorized, the runtime
entrypoint must first pass the effective-authority gate and then:

1. re-read the frozen pool through the canonical two Ink RPC endpoints;
2. choose impact-capped input from the durable intent using the stricter local
   and external impact ceiling;
3. recompute the V2 quote;
4. verify the router at the same market block;
5. rebuild the human-signing preview from durable ledger state;
6. for approvals, re-read allowance at that same block;
7. re-check the durable reservation/bounds inside the write transaction before
   committing the envelope or approval.

This prevents a preconstructed Python record from substituting for live venue
verification at the eventual Level-3 persistence boundary.


## Atomic approval/swap amount binding

The first-live durable API records approval + swap preauthorization as one
transactional bundle derived from one live market snapshot. The requested ERC-20
allowance must equal the swap input exactly.

The runtime does not expose separate public Ink approval/envelope persistence
entrypoints. This prevents a later liquidity change from silently resizing the
swap below an already-authorized allowance and leaving residual router spending
authority. A later human-signing phase must revalidate the **same frozen input
amount** before swap signing; if that amount is no longer safe, execution must
stop and the approval must be revoked/cleared rather than resized.
