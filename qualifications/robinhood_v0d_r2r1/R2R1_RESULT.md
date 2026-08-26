# Robinhood V0D R2R1 result — valid quote, eligibility not confirmed

```text
VERDICT = V0D_R2R1_NOT_QUALIFIED_FOR_LIVE_EXECUTION
R2R1_LIVE_EPISODE_CONSUMED = YES
ZEROX_REQUEST_ATTEMPTS = 1
HTTP_STATUS = 200
ZEROX_RESULT_CLASSIFICATION = VALID_QUOTE_WITH_BALANCE_ISSUE_AND_ALLOWANCE_ISSUE
```

The one authorized post-repair episode used the operator-configured public
taker exactly as supplied:

```text
taker = 0x1324d87e24E1657F6fe6805dE814Bb6873052106
```

The request reached the 0x AllowanceHolder firm-quote endpoint and returned a
structurally valid `exact-in` quote with `liquidityAvailable = true`. The
sanitized response is preserved at
`RAW_EVIDENCE_V0/responses/db4e0a58679aff7fadabe7a60aaa1cde6575987695afb6c385a4f3c3e502e036.bin`.
Its response SHA-256 is
`db4e0a58679aff7fadabe7a60aaa1cde6575987695afb6c385a4f3c3e502e036`.

The quote also reports distinct execution prerequisites:

```text
BALANCE_ISSUE = PRESENT (USDG actual 0; expected 100000000)
ALLOWANCE_ISSUE = PRESENT (actual 0; spender 0x0000000000001ff3684f28c67538d4d072c22734)
```

These issues are not malformed input and are not collapsed into an
authentication or entitlement failure. The captured quote was reparsed
offline after admitting and validating its deterministic `mode = exact-in`
field. The offline replay produced shadow decision `WOULD_EXECUTE`, which is
an economic/policy result only; it is not a live execution or entitlement
claim.

```text
ROBINHOOD_RECONCILIATION = PASSED (1 asset read, 1 price read, 14 RPC reads)
CHAINLINK_RECONCILIATION = PASSED (directory and feed reads)
ZEROX_AUTH = NO_AUTHENTICATION_FAILURE_OBSERVED
ZEROX_RWA_ACCOUNT_ENTITLEMENT = NOT_EVALUATED
TAKER_AUTHORIZATION = NOT_EVALUATED
BUY_TOKEN_AUTHORIZATION = NOT_EVALUATED
SELL_TOKEN_AUTHORIZATION = NOT_EVALUATED
LIQUIDITY_AVAILABLE = YES
QUOTE_VALIDATION = PASSED OFFLINE (exact-in, frozen pair, amount, route, and bounds)
LIVE_ELIGIBILITY_CONFIRMED = NO
```

No signature, approval, broadcast, wallet mutation, or capital deployment was
performed. Request headers, including the 0x API key, are not persisted in
the evidence manifests; the repository scan found no API-key occurrence in
the R2R1 artifacts.

The live parser initially stopped on the newly observed top-level `mode`
field. This was repaired offline by requiring `mode = exact-in`; no second
live request was made.

```text
SECRET_LEAK_SCAN = NOT_FOUND
SIGNATURE_COUNT = 0
APPROVAL_COUNT = 0
BROADCAST_COUNT = 0
WALLET_MUTATION_COUNT = 0
CAPITAL_DEPLOYED = 0
HOSTILE_REVIEW = INDEPENDENT LOCAL HOSTILE AUDIT PASSED
CRITICAL = 0
HIGH = 0
TARGETED_REREVIEW_USED = NO
```
