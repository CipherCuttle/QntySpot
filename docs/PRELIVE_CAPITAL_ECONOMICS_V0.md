# Pre-live capital economics V0

This document freezes the additive economics hardening required before a
QntySpot dust-live phase can be considered. It grants no signing, submission,
approval, or live-capital authority.

## 1. Liquidity may narrow an intent, never widen it

A PolicyV0 entry still defines the maximum authorized input and its minimum
output at the policy limit price. A later venue/liquidity check may choose a
smaller exact input, but the minimum output must be prorated at the same price
and rounded upward.

For committed bounds (I_max, O_min) and selected input I:

O_required = ceil(O_min * I / I_max)

The execution envelope may use I <= I_max; it may never carry an output floor
below O_required.

This preserves deterministic EconomicActionID and PolicyV0 identity while
allowing the venue layer to execute less than the strategy desired maximum.

## 2. Ink price-impact sizing

The Ink V2 adapter may reduce a desired exact input using the pinned reserves
and the existing exact Uniswap-V2 quote equation. The selector is fail-closed:

- if the desired input already satisfies max_price_impact_bps, keep it;
- otherwise compute a conservative upper region from the exact continuous V2
  curve;
- require at least one output-atomic unit of rounding margin;
- verify the selected integer input again through the canonical integer quote;
- if no safely verifiable amount exists, abstain.

The sizing function cannot increase the policy amount and cannot override
capital caps, executable-price bounds, stale-observation checks, or authority.

## 3. First-live concurrency is explicit

DustLiveConcurrencyV0 freezes four independent ceilings:

- global open positions;
- open positions on one network;
- open positions in one instrument;
- in-flight ENTRY actions.

The entry guard is intentionally not an exit guard. Position ceilings must
never prevent exposure reduction, reconciliation, or settlement.

These values are not inserted into the currently frozen authority-root schema.
A future V0F authority grant must bind them before they become a live runtime
admission gate.

## 4. Profit is not gross sale proceeds

compute_profit_allocation uses exact weighted-average cost basis.

- BUY quote spend plus explicit quote-denominated external costs increases cost
  basis.
- SELL releases the proportional cost basis and subtracts explicit
  quote-denominated external costs from proceeds.
- Only positive realized PnL is eligible for recycling or banking.
- Recycling and banking round down to integer quote atomic units.
- Losses create no recyclable capital.
- Unsold inventory keeps its remaining cost basis.

The existing FillReceiptV0 fee_atomic does not define one universal
denomination across venues. This contract therefore refuses to guess. A future
live settlement-accounting bridge must normalize gas or venue costs into
explicit quote atomic units before calling the recycling allocator.

## 5. Authority boundary

This phase remains offline and pre-live. It does not access signing material,
create approvals, construct or submit a live transaction, broadcast, deploy
capital, enable autonomous execution, or change SIGNING_AUTHORIZED or
LIVE_CAPITAL_AUTHORIZED.

The next authority transition remains the separately reviewed authority-root
implementation followed by a venue-specific dust-live phase.
