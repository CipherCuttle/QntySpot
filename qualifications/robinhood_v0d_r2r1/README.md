# Robinhood V0D R2R1 qualification

This directory contains the single post-repair, read-only qualification
episode authorized after `robinhood_v0d_r2/`. The command requires both
environment inputs:

```bash
ZEROX_API_KEY=... \
QNTYSPOT_QUALIFICATION_TAKER=0x... \
python3 scripts/qualify_robinhood_v0d.py \
  --output qualifications/robinhood_v0d_r2r1
```

The taker is a public EVM identity only. The command never reads key
material, signs, approves, broadcasts, mutates a wallet, or deploys capital.
The API key is held in memory for the bounded 0x read and is not persisted in
qualification evidence.
