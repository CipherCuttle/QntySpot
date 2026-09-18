# Ink V0F external risk consumer

QntySpot consumes the frozen Ink V0F dust-risk artifact produced by the
independent `CipherCuttle/QntyAuthorityRoot` repository.

Source merge:

`4f32c5b984e91c1b0704081cb4173666ec24251b`

Canonical artifact digest:

`c7058aec58f3fbcb4f2b390a6eac35bdb9d8cab2484a2ff22731f2dc586e8ee3`

The vendored artifact is byte-identical to the authority-root canonical
artifact. QntySpot verifies the SHA-256 before parsing it and refuses modified
or noncanonical bytes.

The consumer exposes only deterministic pre-live admission checks. An ENTRY
must match the exact Ink/InkySwap/KRAKMASK-WETH scope and remain within:

- 0.001 WETH per-entry capital;
- 0.001 WETH cumulative entry capital;
- one global/network/instrument open position;
- one in-flight ENTRY;
- 100 bps price impact;
- 50 bps slippage.

The consumed policy also freezes first-dust economics at 0% profit recycling
and 100% banking.

This phase does not issue or consume a live authority receipt, access signing
material, construct or submit transactions, or enable capital. Existing
`SIGNING_AUTHORIZED = NO`, `LIVE_CAPITAL_AUTHORIZED = NO`, and
`CAPITAL_AUTHORITY = NONE` remain unchanged.
