# Ink V0F Native SELL — Serial 8 Closure V0

Status: CLOSED / READ-ONLY FORENSIC CLOSURE

Branch:
`ops/ink-v0f-native-sell-roundtrip-v0`

Closure engineering head before this document:
`6466c2c9190130d1b991c17ee829e2ae911753ff`

PR:
`CipherCuttle/QntySpot#52`

PR state requirement:
- OPEN
- DRAFT
- DO NOT MERGE

## Authority state

Serial 8 was genuinely issued and is consumed.

`SERIAL8_AUTHORIZATION_CONSUMED=true`

Serial 8 is closed to all new live attempts.

`SERIAL 8 CLOSED`

No serial 9 authority exists.

`SERIAL 9 NOT AUTHORIZED`

This document grants no signing, approval, SELL, revoke, BUY, broadcast, merge,
or fresh grant authority.

## External-effect verdict

Final classification:

`SAFE_STOP / NO_EXTERNAL_EFFECT`

### Public-chain evidence

Wallet:
`0x3e604Be3293D930069D0805E85379E0cA5Fa01Cb`

KRAKMASK:
`0x32bCB803f696C99Eb263D60a05CAfD8689026575`

Original BUY:
`0xa02d78dece891ba72dc1c8b4d363be7482e988d5487cb46567b52453db7e2ae7`

Public Ink Blockscout observations after the serial-8 incident:

- exact KRAKMASK balance:
  `4396392944674627615414`
- exact native ETH balance:
  `1999871292488141 wei`
- pending transactions:
  none
- address transaction history:
  exactly two transactions
  1. original wallet funding
  2. original BUY above
- there is no post-BUY wallet approval, SELL, or revoke transaction
- token-transfer history contains only the original BUY receipt into the wallet

These balances are byte-for-byte/numerically identical to the frozen
pre-serial-8 expected balances.

The verified KRAKMASK ABI exposes standard ERC-20 `approve` / `allowance`
and does not expose an EIP-2612-style `permit` path. With no post-BUY outgoing
wallet transaction, there is no serial-8 approval transaction and no path
observed by which serial 8 could have established a fresh router allowance
without a wallet transaction.

Therefore the observed chain state is consistent only with:

`SAFE_STOP / NO_EXTERNAL_EFFECT`

for the bounded serial-8 operator episode.

## Historical run evidence

The serial-8 driver history recorded:

`SERIAL 8 ISSUED`

followed by:

`REFUSED: <value>: value needs 31 fractional digits, limit is 30`

Subsequent resume attempts recorded:

`SERIAL 8 ISSUED`

`REFUSED: partial prepare successor policy is not expired`

The historical driver did not visibly reach:

- PREPARED
- APPROVAL_SIGNING
- APPROVAL_CONFIRMED
- SELL_SIGNING

The absence of those log phases was not used alone as proof. The public-chain
state above is the decisive external-effect evidence.

## Root-cause closure

Two interacting defects were repaired.

### Decimal normalization / fallible-work ordering

The serial-8 prepare path could perform durable ledger mutation before all
deterministic decimal/schema construction had completed. A later canonical
decimal validation could therefore fail after state had already advanced.

The repaired path constructs and validates deterministic/fallible objects
before the first durable carry where practical and persists a resumable prepare
plan in the ledger.

### Active-successor recovery deadlock

Historical recovery treated an active successor as abandoned until its policy
expired. That could overlap badly with a short-lived authority grant and force
recovery to wait until roughly the same period in which the grant was no longer
usable.

The repaired model uses a durable prepare state machine and resumes the same
prepare when the persisted state matches. Restart does not create another carry
solely because the process restarted.

## Engineering closure

The repaired branch includes:

- resumable durable prepare records
- monotone prepare phases
- deterministic successor identity
- exactly-once carry protection
- frozen preauth/envelope reconstruction
- signed/external-state fail-closed checks
- persistent non-issuing driver state
- operator helper path + SHA binding
- explicit frozen-runtime import binding
- durable-prepare-aware preflight
- crash/restart regression coverage

Latest verified engineering head before this closure document:

`6466c2c9190130d1b991c17ee829e2ae911753ff`

GitHub checks on that exact head:

- `qntyspot-full-suite`: PASS
- `qntyspot-authority-continuity`: PASS

## Future episode readiness

Engineering status:

`READY FOR A FUTURE AUTHORIZED SERIAL-9 EPISODE`

This statement means the repaired operator/driver architecture is ready for a
future separately authorized episode.

It does NOT authorize serial 9.

A future serial-9 episode must still begin with a fresh read-only execution-host
preflight that verifies at minimum:

- intended frozen repository/runtime binding
- current implementation digest
- serial-8 historical residue is treated as historical recovery state, never
  resurrected for signing
- no signed transaction residue
- no external-action guard conflict
- wallet nonce and pending nonce
- exact KRAKMASK balance
- exact native ETH balance
- router allowance
- fresh quote/slippage state
- fresh AuthorityRoot receipt bound to the exact reviewed implementation
- explicit owner live authority for that episode

Failure of any required precondition => SAFE STOP.

## Frozen next state

`SERIAL 8 CLOSED`

`SAFE_STOP / NO_EXTERNAL_EFFECT`

`SERIAL 9 NOT AUTHORIZED`

`PR #52 OPEN / DRAFT / DO NOT MERGE`

No action in this document may be interpreted as authority to issue a grant,
access private-key contents, prompt for a wallet password, sign, approve,
broadcast, SELL, revoke, BUY, or merge.
