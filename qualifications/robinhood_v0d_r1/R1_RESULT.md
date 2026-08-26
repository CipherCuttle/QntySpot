# R1 result — blocked before complete observation

The one authorized R1 live qualification reached the intended Robinhood and
Chainlink read paths and attempted exactly one 0x quote. The 0x endpoint
returned HTTP 400. The run therefore stopped closed before a complete market
observation, shadow decision, or qualification manifest could be persisted.

Captured raw evidence counts:

- Robinhood REST: 2 (`/rhj/assets`, `/rhj/prices/SPY`)
- Robinhood RPC: 14
- Chainlink: 4 (directory plus feed code, decimals, and latest-round reads)
- 0x: 1 attempted quote; the pre-hardening transport did not retain the
  `HTTPError` body, so no 0x response bytes are claimed as captured

The raw evidence confirms the authoritative SPY deployment and chain 4663
path before the 0x failure. No signing, approval, broadcast, wallet mutation,
or live-capital operation occurred. No second R1 attempt is authorized.
