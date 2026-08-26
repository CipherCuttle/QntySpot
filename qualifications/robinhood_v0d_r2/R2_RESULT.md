# R2 result — failed closed on the 0x request

```text
VERDICT = V0D_R2_NOT_QUALIFIED
R2_LIVE_EPISODE_CONSUMED = YES
ZEROX_REQUEST_ATTEMPTS = 1
ZEROX_CLASSIFICATION = INVALID_REQUEST
```

The frozen V0D command reached the single bounded 0x Swap API v2
AllowanceHolder quote request and received HTTP `400`.

Provider error:

```json
{"name":"INPUT_INVALID","message":"The input is invalid","data":{"zid":"0x73cf7b284ffd6d9e32f6ec33","details":[{"field":"taker","reason":"Invalid ethereum user address. User address must be greater than 0x000000000000000000000000000000000000ffff"}]}}
```

This is classified as `INVALID_REQUEST`. It is not classified as an
authentication failure or an entitlement failure. No retry or request change
was made, and no R3 was created.

Request identity, excluding secret headers:

```text
method       = GET
endpoint     = https://api.0x.org/swap/allowance-holder/quote
chainId      = 4663
sellToken    = 0x5fc5360d0400a0fd4f2af552add042d716f1d168
buyToken     = 0x117cc2133c37b721f49de2a7a74833232b3b4c0c
sellAmount   = 100000000
slippageBps  = 100
taker        = 0x0000000000000000000000000000000000000001
```

The raw response is preserved at
`RAW_EVIDENCE_V0/responses/9786d75be7c16ab7a4f239ab8bc69a4dd304ff2f1109363f2330a7f4803182e1.bin`
with response SHA-256
`9786d75be7c16ab7a4f239ab8bc69a4dd304ff2f1109363f2330a7f4803182e1`.
The response evidence contains no authentication header. The frozen failure
path did not persist the in-memory local observation timestamp because it
aborted before a complete observation or qualification manifest existed.

Reconciliation completed before the 0x request: one Robinhood asset read, one
Robinhood price read, fourteen Robinhood RPC reads, and one Chainlink
directory read. No quote, decision, approval, signature, broadcast, wallet
mutation, or live-capital operation occurred.
