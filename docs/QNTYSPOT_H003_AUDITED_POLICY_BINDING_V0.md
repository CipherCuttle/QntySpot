# QNTYSPOT_H003_AUDITED_POLICY_BINDING_V0

## Purpose

Bind a cryptographically authenticated H003 `TARGET_CHANGE` to the already-frozen QntySpot Solana PolicyV0 and the already-frozen H003 instrument-translation audit.

This phase does **not** create a policy and does **not** reinterpret the research signal. It inherits the existing audited mechanical mapping:

- H003 `LONG` → PolicyV0 `side=SELL` → ExactIn `USDC→WSOL` → candidate level `USDC-SOL-1`
- H003 `FLAT` → PolicyV0 `side=BUY` → ExactIn `WSOL→USDC` → candidate level `SOL-USDC-1`

The naming hazard remains explicit: because the frozen policy has `base=USDC`, `quote=WSOL`, and `side=BUY`, its BUY side acquires USDC and therefore represents a **SOL exit**, while its SELL side acquires WSOL and represents a **SOL entry**.

## Governed inputs

The binding is valid only when all of the following independently agree:

1. The Qnty accepted-intent and publication receipt reauthenticate through `QNTYSPOT_AUTHENTICATED_ACCEPTED_INTENT_POLICY_BRIDGE_V0` from exact signed bytes and explicit public trust material.
2. Translation audit digest is exactly `e599340ab6eeb3a8125233c5b74e4bd1ab28b756ab64caade2fd96dc757a76bc`.
3. Frozen policy document SHA-256 is exactly `cfa4edc38f2f71bcefbbe5affb1a82b79744627945f2cb95fc88321253d655ee`.
4. The audit self-digest, schema, authority-none declaration, source semantic, stop conditions, and frozen BUY-fixture non-reusability all verify.
5. The exact policy parses as `qntyspot.policy.v0` and still has the audited Solana mainnet-beta USDC/WSOL mints, decimals, token program, side, and ladder level identities.
6. Both LONG and FLAT mappings in the audit still match the parsed PolicyV0 mechanics.

The audit/policy digests are **governance anchors**, not event-specific accepted-intent allowlists. New authenticated H003 signal events do not require a source edit.

## Output

For `NO_ACTION`, the phase returns no binding evidence and does not parse or touch the policy/audit surface.

For authenticated `TARGET_CHANGE`, it emits canonical JSON evidence containing:

- upstream policy-request id
- accepted-intent digest
- research-identity digest
- Qnty and QntySpot provenance commits
- translation-audit digest
- exact policy document digest and parsed `policy_id`
- previous/current target
- audited PolicyV0 side
- audited candidate level ids
- audited ExactIn direction

The evidence has its own deterministic `binding_digest`.

The output is **not an authentication credential or authority token**. A later boundary must recompute or independently verify the same signed intent, receipt, trust root, audit and policy bytes; it must not trust a retained Python object or arbitrary self-consistent binding JSON.

## Non-authority boundary

Even after successful binding:

- policy admission: **NO**
- market observation: **NO**
- network activity: **NO**
- quote evaluation: **not performed**
- policy timing evaluation: **not performed**
- economic action: **NO**
- capital reservation: **NO**
- signing: **NO**
- submission: **NO**
- capital authority: **NO**

The binding only proves which already-governed PolicyV0 mechanics correspond to the authenticated research target.

## Next gate

The next meaningful gate after closure is a read-only policy-observation qualification. For a current `FLAT→LONG` H003 transition it must obtain a fresh **SELL-direction ExactIn USDC→WSOL** observation or abstain. The frozen BUY/WSOL→USDC observation is explicitly non-reusable for LONG entry.

That next gate must still not construct/sign/submit a transaction or grant capital authority.

## Closure target

`QNTYSPOT_H003_AUDITED_POLICY_BINDING_V0_CLOSED_PASS` requires:

- signed NO_ACTION remains inert
- signed FLAT→LONG binds to SELL / USDC→WSOL / `USDC-SOL-1`
- exact audit and exact policy are digest-pinned
- self-consistent modified audit is rejected
- altered policy bytes are rejected
- tampered signed intent cannot reach binding
- canonical deterministic binding evidence
- no amount/price/quote/transaction authority appears in output
- no Solana adapter, network, execution-contract, economic-authority-root, or ambient-state dependency
- deployment identity advances intentionally while historical identities stay reproducible
- full QntySpot suite and authority-continuity checks pass
- one bounded hostile review leaves no unresolved Critical/High/P1 blocker
