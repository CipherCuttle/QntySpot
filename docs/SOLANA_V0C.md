# Solana V0C read-only semantics

The current phase is `QNTY_SPOT_V0C_SOLANA_SHADOW` with public reads only.
The adapter uses the current official interfaces verified on 2026-08-24:

- Jupiter Developer Platform setup and keyless access:
  <https://developers.jup.ag/docs/portal/setup>
- Jupiter Swap V2 build response and parameters:
  <https://developers.jup.ag/docs/api-reference/swap/build>
- Jupiter migration from V1 Metis to Swap V2:
  <https://developers.jup.ag/docs/swap/migration/metis-to-build>
- Solana `getMultipleAccounts`:
  <https://solana.com/docs/rpc/http/getmultipleaccounts>
- Solana `getLatestBlockhash` and finalized commitment:
  <https://solana.com/docs/rpc/http/getlatestblockhash>
- Solana versioned transactions and address lookup tables:
  <https://solana.com/docs/core/transactions/versioned-transactions>

## Boundaries

`qntyspot/solana.py` has no asset search, ticker lookup, key input, signer,
transaction serializer, submitter, or live-capital operation. Its Jupiter
client is a bounded HTTPS GET client with no API-key or ambient-secret path.
Its Solana client admits only finalized `getLatestBlockhash`,
`getBlockHeight`, and `getMultipleAccounts` reads.

The policy supplies the exact mint pair, cluster, token-program identities,
decimals, ladder level, and atomic input size. The adapter verifies each mint
account's owner program and serialized mint decimals. Legacy SPL and
Token-2022 are distinct identity values even if the mint address is the same.

## Quote and evidence rules

- Jupiter `ExactIn` `inAmount` must equal the intent's integer atomic input.
- `inputMint` and `outputMint` must equal the policy-bound pair exactly.
- The frozen observation also records the generic economic side, so a BUY
  observation cannot be reused for a SELL quote with the same instrument IDs.
- Source-leg route `bps` must be present and sum to `10000`; source-leg
  `percent` must sum to `100`, while intermediate hops are checked through
  exact amount conservation and graph reachability.
- Jupiter's route `usdValue` is non-economic metadata. If present as a JSON
  decimal number, it is parsed exactly with `Decimal` and canonicalized to
  text; it never enters amount, price, threshold, or policy arithmetic.
- Every route account, instruction program, instruction account, lookup table,
  and lookup address must be canonical base58 public-key text.
- Instruction data is validated as canonical base64 and stored only as length
  plus SHA-256 evidence. It is never parsed into or treated as a trusted
  executable object.
- The Jupiter `otherAmountThreshold` must equal the exact floor of the
  reported output after the requested slippage. Policy output bounds remain
  stricter where applicable and use the core's ceiling direction.
- A non-empty `addressesByLookupTableAddress` map is recorded as explicit
  `VERSION_0_ADDRESS_LOOKUP_TABLES`. A missing map fails closed. An empty map
  is recorded as `INLINE_ADDRESSES_ONLY_NOT_A_LEGACY_ASSERTION`.
- The Jupiter blockhash must still be ahead of the current finalized block
  height, the RPC slot window must be within the configured bound, and the
  explicit Jupiter `fetchedAt` must not exceed the explicit replay time or
  quote-age bound.

The V0C qualification fixture is frozen in
`qualifications/solana_v0c/sol_usdc_buy.policy.json`. It is a high-liquidity
technical fixture only, not a recommendation.
