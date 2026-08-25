# QntySpot V0E hostile-failure suite preregistration V0

Status: **FROZEN BEFORE V0E PREP IMPLEMENTATION**

This document is the preregistration contract for the preparation branch
`feat/v0e-hostile-failure-suite-prep`. It does not close V0D or authorize V0E
as the canonical successor. The suite is deterministic and offline: all
transport responses are synthetic or already-captured fixtures, and no 0x
request is made.

## 1. Threat model

The suite assumes an adversary can control, truncate, replay, delay, reorder,
duplicate, mutate, or contradict public-read responses; corrupt locally stored
evidence; race workers; kill a process at a ledger boundary; and inject data
that resembles a secret. It also assumes a venue can return an HTTP error,
malformed protocol object, stale observation, inconsistent identity, or an
apparently executable quote that is weaker than policy.

The protected invariant is:

> No external ambiguity, corrupted evidence, duplicate worker, stale state,
> malformed venue response, transport disagreement, or restart condition may
> silently become executable economic authority.

Every case must resolve to deterministic rejection, `ABSTAIN`, `SAFE_HALT`,
`RECONCILIATION_REQUIRED`, or a `QUARANTINED` reservation. No hostile case
may produce an unreviewed executable action or duplicate economic action.

## 2. Test taxonomy and terminal classes

The taxonomy is deliberately protocol-oriented rather than coverage-oriented:

* `TRANSPORT`: bounded reads, retry bounds, HTTP/RPC envelopes, chain context.
* `IDENTITY`: exact chain, address, UID, mint, program, decimal, and metadata facts.
* `QUOTE`: exact amounts, limits, route, target, calldata, and reference agreement.
* `RH`: Robinhood multiplier, oracle, status, REST, Chainlink, and synthetic 0x.
* `SOL`: Jupiter/Solana mint, program, route, blockhash, ALT, and account facts.
* `INK`: dual RPC, pool/factory/code, reserves, common block, and integer quote facts.
* `EVIDENCE`: immutable bytes, manifests, associations, bounds, and replay.
* `CONCURRENCY`: exactly-once identity, atomic caps, crashes, and quarantine.
* `STATE`: legal ordering and persistence boundaries.
* `AUTHORITY`: static/dynamic proof that no secret, signer, or network escape exists.

`REJECTED` means the parser or domain boundary refused the input. `ABSTAIN`
means a deterministic shadow decision did not authorize the action.
`SAFE_HALT` means ambiguity or contradiction stops progress. `RECONCILIATION_REQUIRED`
means restart found an outcome that may already exist externally.
`QUARANTINED` is the reservation disposition attached to `SAFE_HALT`; it is
not permission to retry.

## 3. Immutable scenario registry

The IDs below are stable. The implementation may add helper cases, but may not
change an ID's injected fault or expected terminal class to make a failing
test pass. `adapter` identifies the real boundary exercised by the case.

| ID | adapter | injected fault | expected terminal |
|---|---|---|---|
| `V0E-T01` | Ink RPC | timeout before response | `SAFE_HALT` |
| `V0E-T02` | Ink RPC | connection reset | `SAFE_HALT` |
| `V0E-T03` | Ink RPC | truncated body | `REJECTED` |
| `V0E-T04` | Ink RPC | malformed JSON | `REJECTED` |
| `V0E-T05` | Ink RPC | duplicate JSON keys | `REJECTED` |
| `V0E-T06` | Ink RPC | oversized body | `REJECTED` |
| `V0E-T07` | Robinhood REST | HTTP 400 | `SAFE_HALT` |
| `V0E-T08` | Robinhood REST | HTTP 401/403 | `SAFE_HALT` |
| `V0E-T09` | Robinhood REST | HTTP 429 | `SAFE_HALT` |
| `V0E-T10` | Robinhood REST | HTTP 500/503 | `SAFE_HALT` |
| `V0E-T11` | Ink RPC | stale block | `ABSTAIN` |
| `V0E-T12` | Ink RPC | future block beyond bound | `SAFE_HALT` |
| `V0E-T13` | Ink RPC | providers disagree on chain ID | `SAFE_HALT` |
| `V0E-T14` | Ink RPC | providers disagree on block/hash | `SAFE_HALT` |
| `V0E-T15` | Ink RPC | internally inconsistent facts | `SAFE_HALT` |
| `V0E-T16` | Ink RPC | response changes between pinned reads | `SAFE_HALT` |
| `V0E-I01` | Robinhood | wrong EVM chain | `SAFE_HALT` |
| `V0E-I02` | Robinhood | wrong contract | `SAFE_HALT` |
| `V0E-I03` | Ink | wrong factory/pool | `SAFE_HALT` |
| `V0E-I04` | Solana | wrong mint | `SAFE_HALT` |
| `V0E-I05` | Solana | wrong token program | `SAFE_HALT` |
| `V0E-I06` | Robinhood | wrong decimals | `SAFE_HALT` |
| `V0E-I07` | Robinhood | wrong UID | `SAFE_HALT` |
| `V0E-I08` | Robinhood | wrong deployment | `SAFE_HALT` |
| `V0E-I09` | Robinhood | symbol correct, address wrong | `SAFE_HALT` |
| `V0E-I10` | Robinhood | address correct, metadata wrong | `SAFE_HALT` |
| `V0E-Q01` | Robinhood 0x | quote pair mutation | `SAFE_HALT` |
| `V0E-Q02` | Robinhood 0x | amount mutation | `SAFE_HALT` |
| `V0E-Q03` | Robinhood 0x | minOut weaker than policy | `SAFE_HALT` |
| `V0E-Q04` | Robinhood 0x | maxInput weaker than policy | `SAFE_HALT` |
| `V0E-Q05` | Solana Jupiter | stale quote | `ABSTAIN` |
| `V0E-Q06` | Ink | impossible price | `ABSTAIN` |
| `V0E-Q07` | core | zero/negative amount | `REJECTED` |
| `V0E-Q08` | Ink | extreme price impact | `ABSTAIN` |
| `V0E-Q09` | Robinhood 0x | route endpoint mutation | `SAFE_HALT` |
| `V0E-Q10` | Robinhood 0x | malformed route proportions | `SAFE_HALT` |
| `V0E-Q11` | Robinhood 0x | transaction target mutation | `REJECTED` |
| `V0E-Q12` | Robinhood 0x | transaction native-value mutation | `SAFE_HALT` |
| `V0E-Q13` | Solana Jupiter | unexpected writable/program semantics | `REJECTED` |
| `V0E-Q14` | Robinhood 0x | malformed calldata | `REJECTED` |
| `V0E-Q15` | Robinhood 0x | quote reference disagreement | `ABSTAIN` |
| `V0E-R01` | Robinhood | multiplier is not 1 | `SAFE_HALT` |
| `V0E-R02` | Robinhood | multiplier applied twice | `ABSTAIN` |
| `V0E-R03` | Robinhood | multiplier omitted | `SAFE_HALT` |
| `V0E-R04` | Robinhood | pending transition before deadline | `SAFE_HALT` |
| `V0E-R05` | Robinhood | transition already effective | `SAFE_HALT` |
| `V0E-R06` | Robinhood | `oraclePaused` | `ABSTAIN` |
| `V0E-R07` | Robinhood | stale Chainlink | `ABSTAIN` |
| `V0E-R08` | Robinhood | zero/negative Chainlink answer | `SAFE_HALT` |
| `V0E-R09` | Robinhood | REST trading halt | `ABSTAIN` |
| `V0E-R10` | Robinhood | stale REST quote | `ABSTAIN` |
| `V0E-R11` | Robinhood | raw-underlying confused with token-adjusted price | `ABSTAIN` |
| `V0E-R12` | Robinhood | Chainlink price multiplied incorrectly | `ABSTAIN` |
| `V0E-R13` | Robinhood | missing sequencer feed fabricated as DOWN | `REJECTED` |
| `V0E-R14` | Robinhood | explicit liveness inconsistency | `SAFE_HALT` |
| `V0E-R15` | 0x fixture | simulated RWA-access error | `REJECTED` |
| `V0E-R16` | 0x fixture | simulated unsupported pair | `REJECTED` |
| `V0E-R17` | 0x fixture | simulated malformed executable quote | `REJECTED` |
| `V0E-S01` | Solana Jupiter | threshold one atomic unit looser | `SAFE_HALT` |
| `V0E-S02` | Solana Jupiter | stricter venue threshold | `WOULD_EXECUTE` |
| `V0E-S03` | Solana | wrong mint | `SAFE_HALT` |
| `V0E-S04` | Solana | malformed versioned transaction metadata | `REJECTED` |
| `V0E-S05` | Solana | ALT mismatch | `REJECTED` |
| `V0E-S06` | Solana Jupiter | route/program mutation | `REJECTED` |
| `V0E-S07` | Solana | stale blockhash/context | `ABSTAIN` |
| `V0E-S08` | Solana | Token-2022 mismatch | `SAFE_HALT` |
| `V0E-S09` | Solana | unexpected account authority semantics | `REJECTED` |
| `V0E-K01` | Ink | dual RPC disagreement | `SAFE_HALT` |
| `V0E-K02` | Ink | pool bytecode mismatch | `SAFE_HALT` |
| `V0E-K03` | Ink | factory identity mismatch | `SAFE_HALT` |
| `V0E-K04` | Ink | reserve mutation | `SAFE_HALT` |
| `V0E-K05` | Ink | common-block mismatch | `SAFE_HALT` |
| `V0E-K06` | Ink | stale reserve observation | `ABSTAIN` |
| `V0E-K07` | Ink | integer quote edge case | `WOULD_EXECUTE` |
| `V0E-K08` | Ink | fee-contract mismatch | `SAFE_HALT` |
| `V0E-E01` | evidence | response bytes modified | `SAFE_HALT` |
| `V0E-E02` | evidence | manifest modified | `SAFE_HALT` |
| `V0E-E03` | evidence | digest mismatch | `SAFE_HALT` |
| `V0E-E04` | evidence | missing response | `SAFE_HALT` |
| `V0E-E05` | evidence | duplicate evidence record | `REJECTED` |
| `V0E-E06` | evidence | wrong request/response association | `SAFE_HALT` |
| `V0E-E07` | replay | replay attempts network access | `REJECTED` |
| `V0E-E08` | replay | replay attempts wall-clock access | `REJECTED` |
| `V0E-E09` | replay | altered timestamp | `SAFE_HALT` |
| `V0E-E10` | replay | non-byte-identical result | `SAFE_HALT` |
| `V0E-E11` | evidence | secret substring in response/evidence | `SAFE_HALT` |
| `V0E-E12` | evidence | evidence store bounds exceeded | `REJECTED` |
| `V0E-C01` | ledger | two workers same EconomicActionID | `REJECTED` |
| `V0E-C02` | ledger | two workers reserve same remaining budget | `REJECTED` |
| `V0E-C03` | ledger | two daemon identities same action | `REJECTED` |
| `V0E-C04` | ledger | crash before reservation | `ABSTAIN` |
| `V0E-C05` | ledger | crash after reservation | `ABSTAIN` |
| `V0E-C06` | ledger | crash before submit persistence | `ABSTAIN` |
| `V0E-C07` | recovery | unknown outcome on restart | `RECONCILIATION_REQUIRED` |
| `V0E-C08` | ledger | SAFE_HALT releases committed capital | `QUARANTINED` |
| `V0E-C09` | ledger | quarantined capital omitted from caps | `QUARANTINED` |
| `V0E-C10` | recovery | unknown outcome auto-retried | `RECONCILIATION_REQUIRED` |
| `V0E-M01` | state | `ARMED -> SIGNED` | `REJECTED` |
| `V0E-M02` | state | `TRIGGERED -> FILLED` | `REJECTED` |
| `V0E-M03` | state | `RESERVED -> RECONCILED` | `REJECTED` |
| `V0E-M04` | state | `SUBMITTED -> SIGNED` | `REJECTED` |
| `V0E-M05` | state | `SAFE_HALT -> automatic retry` | `REJECTED` |
| `V0E-M06` | ledger | persistence before future boundary | `REJECTED` |
| `V0E-A01` | static | private-key file read | `REJECTED` |
| `V0E-A02` | static | seed phrase handling | `REJECTED` |
| `V0E-A03` | static | wallet secret access | `REJECTED` |
| `V0E-A04` | static | subprocess wallet CLI | `REJECTED` |
| `V0E-A05` | static | signer construction | `REJECTED` |
| `V0E-A06` | static | approval transaction | `REJECTED` |
| `V0E-A07` | static | broadcast | `REJECTED` |
| `V0E-A08` | static | hidden retry path | `REJECTED` |
| `V0E-A09` | offline suite | accidental network call | `REJECTED` |
| `V0E-A10` | offline suite | `ZEROX_API_KEY` required | `REJECTED` |
| `V0E-A11` | evidence | secret serialized in failure receipt | `REJECTED` |

`WOULD_EXECUTE` appears only for benign boundary controls (`V0E-S02` and
`V0E-K07`). They are not hostile successes: they prove that a stricter venue
threshold and exact integer arithmetic remain admissible while the attack
variant is rejected. No hostile scenario may resolve to `WOULD_EXECUTE`.

## 4. Adapters covered

The real bounded public-read seams are covered: Ink JSON-RPC and shadow
adapter, Solana RPC/Jupiter and shadow adapter, Robinhood REST/RPC/Chainlink/
synthetic 0x and shadow adapter, raw evidence store/replay, the SQLite ledger,
restart recovery, state transitions, and static authority guards.

Robinhood and 0x cases use only synthetic or already-captured offline bytes.
The suite does not read `ZEROX_API_KEY`; a fixture credential is passed only
to the in-memory client where the existing client contract requires one, and
secret-substring capture is tested.

## 5. Authority boundary

This is preparation under `AUTHORITY = ROBINHOOD_SHADOW_READ_ONLY` inherited
from V0D. It grants no signer, key, wallet, approval, broadcast, venue
submission, live-capital, or successor-phase authority. No live qualification
is part of this branch. QntySpot does not inherit authority from sibling
repositories.

## 6. Completion criteria

`PREP_PASS` requires all registered cases to match this table, two identical
runs to produce byte-identical canonical receipts, zero real network reads,
zero secret reads, zero signatures/approvals/broadcasts/live-capital actions,
database-enforced exactly-once identity, no automatic retry after an unknown
outcome, quarantine preservation, and evidence-tamper detection.

`PREP_PASS` is not `V0E_CLOSED_PASS`.

## 7. Exclusions

No live network; 0x key use; live Robinhood, Jupiter, or Ink; signer,
private-key, wallet, approval, transaction submission, live capital, V0F/V0G/
V0H, or OpenSea/NFT work. This branch does not close V0D and may not become
the canonical successor until the final V0D tree is reconciled and the full
three-adapter suite is run against it.

## 8. Reopen criteria

Reopen this preregistration if a scenario's identity or expected class must
change, if a false-pass is found, if a real protocol failure shape cannot be
represented by the fixture, if any evidence/receipt is nondeterministic, if a
Critical/High authority or duplicate-execution gap is found, or when final
V0D reconciliation changes an adapter contract. A failing implementation is
fixed against this frozen expectation; the expectation is not tuned after
execution merely to make the suite pass.
