# Robinhood V0D qualification attempt

This directory contains the frozen bytes from the single bounded live
qualification attempt. The attempt failed closed before the 0x request because
the public RPC latest-block timestamp was ahead of the explicit local
observation timestamp. No second live request was made.

Frozen authoritative SPY registry reconciliation:

- chain: `4663`
- deployment: `0x117cc2133c37B721F49dE2A7a74833232B3B4C0C`
- UID: `0x000000000000000000000000000000001c6f27a62789417d8ed359ed3c2d3da1`
- decimals: `18`
- current multiplier: `1.000000000000000000`
- pending multiplier: none
- status: `ASSET_STATUS_ACTIVE`
- trading capabilities: all captured market/extended/overnight fractional and whole states were `TRADING_STATUS_TRADABLE`
- USDG: `0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`

`LIVE_ELIGIBILITY_CONFIRMED = NOT_EVALUATED`.

The raw evidence is content-addressed and immutable. It contains no API key or
authorization header. No 0x quote, signature, approval, transaction
submission, wallet mutation, or live-capital operation occurred.
