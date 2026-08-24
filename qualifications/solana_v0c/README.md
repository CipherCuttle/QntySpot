# Solana V0C bounded qualification

This directory is the frozen technical qualification fixture for
`QNTY_SPOT_V0C_SOLANA_SHADOW`. It is not an asset recommendation or a token
selection mechanism.

| Fact | Frozen value |
|---|---|
| Cluster | Solana `mainnet-beta` |
| Public RPC | `https://api.mainnet.solana.com` |
| Jupiter read endpoint | `https://api.jup.ag/swap/v2/build` |
| Input mint | WSOL `So11111111111111111111111111111111111111112` |
| Output mint | USDC `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Token program | SPL Token for both mints: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` |
| Input decimals | 9 |
| Output decimals | 6 |
| Exact input size | 1 WSOL = `1000000000` atomic units |
| Quote mode | Jupiter Swap V2 `ExactIn` read with no API key |

The policy file freezes the exact pair and size before the live command is
run. The adapter verifies the mint accounts and decimals from finalized RPC,
then validates Jupiter's exact-input quote, route split, instruction program
identities, instruction encodings, blockhash freshness, and explicit
version-0/address-lookup-table metadata. No serialized payload is accepted as
trusted evidence, and no signer or submission path exists.

Run exactly one bounded qualification from the repository root:

```text
python3 scripts/qualify_solana_v0c.py
```

The resulting JSON files are immutable canonical evidence and are replayed by
the offline test suite.
