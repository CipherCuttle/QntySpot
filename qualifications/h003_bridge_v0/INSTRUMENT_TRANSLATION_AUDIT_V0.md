# H003_INSTRUMENT_TRANSLATION_AUDIT_V0

Phase: `QNTY_H003_SOL_TO_QNTYSPOT_SHADOW_BRIDGE_V0` — Subtask E (instrument
translation audit + WSOL-ExactIn-vs-side=BUY mechanical resolution).

Authority: read-only audit. No signer, no key handling, no capital authority,
no network. The frozen policy
[`sol_usdc_buy.policy.json`](../solana_v0c/sol_usdc_buy.policy.json), the
adapter code, the frozen Solana V0C fixtures, and
[`H003_SIGNAL_INTENT_V0.json`](H003_SIGNAL_INTENT_V0.json) were **not**
modified. Machine-readable form: [`INSTRUMENT_TRANSLATION_AUDIT_V0.json`](INSTRUMENT_TRANSLATION_AUDIT_V0.json)
(artifact digest `e599340ab6eeb3a8125233c5b74e4bd1ab28b756ab64caade2fd96dc757a76bc`,
canonical JSON, no floats; sidecar `INSTRUMENT_TRANSLATION_AUDIT_V0.sha256`).

## Inputs

| Input | Reference |
| --- | --- |
| Frozen policy | `qualifications/solana_v0c/sol_usdc_buy.policy.json` — `side=BUY`, `base=USDC` (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, 6 dec, lines 5–15), `quote=WSOL` (`So11111111111111111111111111111111111111112`, 9 dec, lines 16–26); entry level `SOL-USDC-1` (line 30), exit level `USDC-SOL-1` (line 39) |
| Upstream signal | `H003_SIGNAL_INTENT_V0.json` — digest `9a855a3362b33561be7e578e29218b2b42e80e36431998909ced5472e5f18a52`, `causal_target_t_plus_1 = LONG`, source semantic `BINANCE_SPOT_SOLUSDT_1H` (USDT quote) |
| Frozen fixture | `qualifications/solana_v0c/RAW_EVIDENCE_V0/manifests/e8026c94…e62a78.json` — GET `swap/v2/build?amount=1000000000&inputMint=So111…11112&outputMint=EPjFW…TDt1v&slippageBps=50` (Jupiter ExactIn WSOL→USDC) |
| Acceptance receipt | `H003_ACCEPTANCE_V0.json`, digest `b14816a19757f517a1056ae0bc71cfedac004edd8ffeac4b5e85be8e8fb5bdfc` |

## Mechanical resolution (verbatim verdict)

> **Given the policy's mint assignment `base=USDC` and `quote=WSOL`, policy
> `side=BUY` means spend quote (WSOL) and receive base (USDC) —
> [`qntyspot/solana.py:1215`](../../qntyspot/solana.py:1215) returns
> `(quote, base)` for `Side.BUY` — so a Jupiter ExactIn `WSOL→USDC` quote IS
> the internally consistent evidence for `side=BUY` on this policy. The frozen
> fixture (ExactIn WSOL→USDC, amount=1000000000 WSOL atomic, slippageBps=50)
> is therefore valid BUY-side evidence for this policy. In SOL-direction
> research semantics this BUY side is a **SOL-EXIT** (dispose SOL for USDC).
> Consequently the H003 `LONG` target (acquire SOL) requires the opposite
> `side=SELL` (ExactIn `USDC→WSOL`), and per
> [`docs/SOLANA_V0C.md:36-37`](../../docs/SOLANA_V0C.md:36) the frozen BUY
> observation cannot be reused as SELL quote evidence even for the identical
> mint pair. The policy NAME `sol_usdc_buy` is potentially misleading: read as
> "SOL vs USDC, BUY" a reader may assume BUY acquires SOL, but the code binds
> BUY to acquiring the policy's **base** asset USDC. No reinterpretation of
> the policy, adapter, or fixtures was made or is required.**

## LONG / FLAT → side mapping conclusion

| Research target | Policy side (this policy) | ExactIn pair | Policy level-id mechanics |
| --- | --- | --- | --- |
| `LONG` (acquire SOL) | **SELL** | USDC → WSOL | exit ladder `USDC-SOL-1` carries `side.opposite = SELL` ([`policy.py:257-263`](../../qntyspot/policy.py:257), [`domain.py:61-63`](../../qntyspot/domain.py:61)) |
| `FLAT` (dispose SOL) | **BUY** | WSOL → USDC | entry ladder `SOL-USDC-1` carries `side = BUY` ([`policy.py:250-256`](../../qntyspot/policy.py:250)) |

The ladder KIND names (`ENTRY`/`EXIT`) are relative to the policy's **base**
instrument (USDC), not to the research SOL position: on this policy the
"entry" ladder executes `side=BUY` = WSOL→USDC = the SOL-EXIT direction, and
the "exit" ladder executes `side=SELL` = USDC→WSOL = the SOL-ENTRY direction.
The H003 bridge consumes DIRECTION (`LONG`/`FLAT`) and must map it onto the
side that acquires SOL (`SELL` on this policy), not onto the ladder named
"entry". This naming collision is recorded as a hazard; nothing was edited.

## Frozen fixture reusability for the LONG entry

**NO.** The frozen WSOL→USDC BUY observation is EXIT-direction evidence only.
[`docs/SOLANA_V0C.md:36-37`](../../docs/SOLANA_V0C.md:36) forbids reusing a
BUY observation for a SELL quote with the same instrument IDs, and the adapter
enforces it twice: side mismatch fails closed in `_validate_bounds`
([`solana.py:1323-1324`](../../qntyspot/solana.py:1323)) and in `quote()`
([`solana.py:1349-1350`](../../qntyspot/solana.py:1349)). The LONG entry
requires a fresh **SELL-direction (ExactIn USDC→WSOL)** observation, which
Subtask F must obtain live (read-only, no signer) or abstain.

## Per-axis verdicts

### A. SOL ↔ WSOL semantic mapping — MATERIAL, PASS

Research base asset is native SOL (Binance SOLUSDT spot). Execution asset for
the LONG entry is the WSOL SPL mint `So111…11112` (9 decimals per policy line
23, enforced against mint-account evidence at
[`solana.py:1242-1247`](../../qntyspot/solana.py:1242)). WSOL is a distinct
SPL token; holding it is a claim on SOL at 1:1 by the wrapped-SOL program, but
unwrapping to native SOL and the rent-exempt minimum balance are operational
post-trade mechanics, **not** signal-semantics facts. The semantic mapping is
1:1; the token-identity binding (exact mint, token program, decimals) is
enforced fail-closed by the adapter.

### B. USDT ↔ USDC quote substitution — MATERIAL, PASS

Research quote is USDT; execution quote is USDC (distinct issuer/asset/chain;
6 decimals per policy line 12). The **signal semantics are unaffected**: the
H003 rule `sign(ma48 − ma192)` is computed upstream on SOLUSDT closes and only
the DIRECTION (`LONG`/`FLAT`) crosses the bridge — never a USDT price level.
**Binding rule:** every policy price level and bound (`trigger_price`,
`max_executable_price`, `min_executable_price`, capital caps) is denominated
in the execution quote USDC and must be set in USDC terms derived from
USDC-quoted observations. USDT levels from Binance must **never** be reused as
USDC policy levels; doing so would inject a cross-asset basis error into every
gate comparison.

### C. Price direction/unit convention — MATERIAL, PASS

Research price: USDT per SOL (close of bar t). For the LONG entry the mapped
side is SELL (axis E). A SELL observation on this policy is ExactIn
USDC→WSOL, so `requested_input_atomic` is USDC atomic and
`quoted_output_atomic` is WSOL atomic. Exact formula from
[`solana.py:1173-1177`](../../qntyspot/solana.py:1173):

```
average = (quoted_output_atomic * 10^input_decimals)
        / (requested_input_atomic * 10^output_decimals)
        = WSOL_human / USDC_human          (quote-per-base)
```

i.e. `average ≈ 1 / P_sol` under the 1:1 wrap, where `P_sol` is the familiar
USDC-per-SOL research price. The decision gate
([`solana.py:1414-1415`](../../qntyspot/solana.py:1414)) rejects the rung when
`average < limit_price` (`MIN_EXECUTABLE_PRICE`), where `limit_price` is
quote-per-base for both sides ([`economics.py:56-68`](../../qntyspot/economics.py:56)).
**Direction preservation (exact, order-theoretic):** the execution acquisition
price `P_exec = USDC_human / WSOL_human` is definitionally monotone with the
research price `P_sol` (higher SOL price ⇒ higher USDC paid per WSOL
acquired). The internal `average = WSOL/USDC = 1/P_exec` is a strictly
**decreasing** function of `P_sol`, and the side-dependent comparisons invert
with it: the SELL (LONG entry) gate accepts exactly when
`P_sol ≤ 1/limit_price` — entry at low SOL prices ("buy low") — and the
BUY/exit gate ([`solana.py:1412-1413`](../../qntyspot/solana.py:1412), fail
when `average > limit_price`) accepts exactly when `P_sol ≥ 1/limit_price` —
exit at high SOL prices ("sell high"). For any two market states
`P1 < P2`: whenever the entry gate accepts at `P2` it also accepts at `P1`,
and whenever the exit gate accepts at `P1` it also accepts at `P2`, so the
acceptance sets are the correct low-price entry interval and high-price exit
interval. Ordering is preserved end-to-end through the (side, gate) pair.
Recorded explicitly: the raw `_human_price` number under this policy is the
**reciprocal** of the research price; it must not be silently read as a
USDC-per-SOL price.

### D. Decimals and atomic conversion — MATERIAL, PASS

WSOL = 9 decimals, USDC = 6 decimals, USDT = 6 decimals on its own chain
(Binance-side decimals are display-only for the research series and never
enter QntySpot arithmetic). All atomic conversion happens via
`to_atomic`/`from_atomic` ([`canon.py:173-195`](../../qntyspot/canon.py:173))
at policy-defined decimals: capital caps
([`policy.py:292-308`](../../qntyspot/policy.py:292)), entry amounts
([`policy.py:384-396`](../../qntyspot/policy.py:384)), minimum outputs
([`economics.py:84-89`](../../qntyspot/economics.py:84)). On-chain decimals
are cross-checked against the policy per side in
[`solana.py:1242-1247`](../../qntyspot/solana.py:1242) and
[`solana.py:1325-1328`](../../qntyspot/solana.py:1325). The frozen BUY
observation carries `input_decimals=9` (WSOL in) / `output_decimals=6`
(USDC out), matching the BUY branch.

### E. LONG → entry direction — MATERIAL, PASS

See the mapping table above; verified against
[`policy.py:229-233`](../../qntyspot/policy.py:229) (side parsed once),
[`policy.py:250-263`](../../qntyspot/policy.py:250) (entry ladder gets
`side`, exit ladder gets `side.opposite`),
[`domain.py:57-63`](../../qntyspot/domain.py:57) (`Side`, `opposite`),
[`solana.py:1210-1215`](../../qntyspot/solana.py:1210) (`_refs`), and the
level ids `SOL-USDC-1` / `USDC-SOL-1`. **LONG ⇒ side=SELL (USDC→WSOL);
FLAT ⇒ side=BUY (WSOL→USDC) on this policy.**

### F. WSOL-ExactIn-vs-side=BUY resolution — MATERIAL, PASS

The mechanical answer is stated verbatim above. `_refs`
([`solana.py:1210-1215`](../../qntyspot/solana.py:1210)) resolves BUY to
`(input=WSOL, output=USDC)`; `_validate_bounds`
([`solana.py:1325-1326`](../../qntyspot/solana.py:1325)) expects BUY input
decimals = quote decimals (9) and output decimals = base decimals (6);
`_human_price` BUY gives WSOL-per-USDC (quote-per-base)
([`solana.py:1168-1172`](../../qntyspot/solana.py:1168)) and the BUY gate
fails when `average > limit_price`
([`solana.py:1412-1413`](../../qntyspot/solana.py:1412)). The frozen fixture's
request (`inputMint=So111…11112`, `outputMint=EPjFW…TDt1v`,
`amount=1000000000`, `slippageBps=50`) is internally consistent with
`side=BUY`. The name `sol_usdc_buy` is potentially misleading relative to
SOL-direction semantics; the audit records this explicitly. **No silent
reinterpretation.**

### G. Frozen BUY fixture reuse for the LONG entry — MATERIAL, PASS (verdict: NOT REUSABLE)

Covered above: [`docs/SOLANA_V0C.md:36-37`](../../docs/SOLANA_V0C.md:36) rule
plus fail-closed side checks at
[`solana.py:1323-1324`](../../qntyspot/solana.py:1323) and
[`solana.py:1349-1350`](../../qntyspot/solana.py:1349).

## STOP conditions

- **None triggered.** No code site contradicts the mechanical reading: the
  `Side` enum and `opposite` ([`domain.py:57-63`](../../qntyspot/domain.py:57)),
  the entry/exit side assignment ([`policy.py:250-263`](../../qntyspot/policy.py:250)),
  `_refs`, `_human_price`, `_validate_bounds`, and the decision gate are all
  mutually consistent with the resolution above. No existing-code defect
  requiring a patch was found; no policy JSON, adapter code, or frozen fixture
  was altered. No live RPC/Jupiter call was performed (Subtask F scope).

## Regression guard

`tests/test_h003_translation_audit.py` pins the mapping table (mints,
decimals, LONG→SELL / FLAT→BUY), an exact-arithmetic direction-preservation
check, fail-closed behavior under mutated mappings, and the non-reusability of
the frozen BUY fixture for the LONG entry. All offline.
