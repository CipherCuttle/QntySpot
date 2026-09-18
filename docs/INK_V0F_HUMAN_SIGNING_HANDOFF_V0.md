# Ink V0F human-signing handoff — offline preview phase

This phase proves deterministic transaction material for the first Ink dust-live
path without raising QntySpot's binding source authority above
`RECONCILE_ONLY`.

## Frozen legacy router identity

KRAKMASK is a legacy InkyPump V1 token whose bonded liquidity remains on an
InkySwap/Uniswap V2 pair. The official legacy deployment identifies the V1
Uniswap V2 router on Ink mainnet as:

`0xa8c1c38ff57428e5c3a34e0899be5cb385476507`

The verified deployed `UniswapV2Router02` bytecode is pinned by SHA-256:

`64ec5d32d5ce6eb632cad54cb7de2653e7aec19fdad0b641b16c0b1a1f52ba7b`

Its verified constructor binds the already-pinned InkySwap factory
`0x458c5d5b75ccba22651d2c5b61cb1ea1e0b0f95d` and Ink WETH
`0x4200000000000000000000000000000000000006`.

Canonical router evidence lives in
`artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json`.

## Preview contract

The offline preview:

- reuses the canonical reserve-derived Ink V2 quote;
- refuses caller-forged quote amounts;
- supports exactly WETH -> KRAKMASK BUY and KRAKMASK -> WETH SELL;
- uses `swapExactTokensForTokens` with a two-token path;
- sets the recipient to the exact first-live taker;
- sets native transaction value to zero;
- sets `amountOutMin` to the stricter of the economic price floor and a
  quote-relative 50-bps slippage floor;
- emits an exact-amount ERC-20 `approve(router, amount)` preview rather than
  an unlimited approval;
- requires a durably RESERVED intent and exact stored bounds;
- derives BUY held capital/concurrency from the ledger rather than caller input;
- derives SELL input capacity from settled ledger inventory;
- emits `ExactSignedBytesScopeV0` so future externally signed bytes can be
  checked for sender, chain, target, calldata, nonce, gas and fee ceilings.

The preview deliberately does not persist an execution envelope, authorize an
approval, sign, submit, broadcast, or move capital.

## Remaining live gates

Before Level 3 can be authorized, the runtime still needs:

1. two-provider live verification of router bytecode/factory/WETH identity;
2. a durable Ink-specific envelope/approval admission path rather than the
   current 0x-specific envelope validator;
3. an explicit human-controlled signing workflow;
4. production AuthorityRoot trust pins and a fresh short-lived grant bound to
   the final Level-3 QntySpot merge identity;
5. live balance/allowance/gas readiness and zero-money rehearsal.

The funded taker currently holds native ETH according to the user's transfer.
This phase does not wrap it or authorize a WETH approval.
