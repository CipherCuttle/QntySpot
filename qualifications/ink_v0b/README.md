# Ink V0B bounded qualification

This directory contains one write-once read-only qualification against Ink
mainnet. The records are canonical JSON envelopes; each envelope's `digest`
is the SHA-256 of its `record`.

- Observation: block `54049289`, both official RPC providers agreed.
- Buy fixture: policy level `E1`, input `0.0001 WETH` (`100000000000000` atomic).
- Sell fixture: policy level `X1`, inventory `0.000002 KRAKMASK`, so the
  configured 50% exit ratio quotes `0.000001 KRAKMASK`.
- Both shadow decisions were `WOULD_EXECUTE` under the frozen policy.
- These records are market-quote evidence only. No transaction object,
  approval, signature, or broadcast was produced.

The observation can be loaded and both decisions replayed without network
access using `qntyspot.ink.load_*` and `replay_shadow_decision`.
