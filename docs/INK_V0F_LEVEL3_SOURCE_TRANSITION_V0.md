# Ink V0F Level-3 source transition

This phase changes one authority fact:

`PHASE_GRANTED_AUTHORITY_LEVEL = HUMAN_SIGNED_EXECUTION`

It does not provision a production grant and does not grant QntySpot any
signature-production capability.

## Effective-authority law

Runtime authority remains:

`MIN(SOURCE_PHASE_CEILING, VERIFIED_EXTERNAL_GRANT_LEVEL)`

Therefore:

- no verified grant -> no Level-1+ runtime action;
- a Level-1 grant -> effective Level 1;
- a Level-2 grant -> effective Level 2;
- a Level-3 grant -> effective Level 3;
- a Level-4 grant -> clipped to effective Level 3.

`PRODUCE_SIGNATURE` exists only at Level 4, so it is unreachable in this
phase even if the external grant claims Level 4.

## Level-3 capabilities

With a current exact Level-3 external grant, the already-reviewed runtime may:

- reserve bounded capital;
- observe and reconcile chain truth;
- construct the frozen Ink V0F envelope;
- authorize only the exact bounded approval;
- validate complete bytes signed by the human-controlled account;
- submit only those exact validated bytes.

The transition does not add a new transaction builder, signer, key reader,
secret source, asset selector, venue discovery path, or retry policy.

## Still forbidden

- private-key, seed, mnemonic, or signer-secret access;
- QntySpot signature production;
- autonomous signing;
- arbitrary transaction construction;
- transaction mutation after human signing;
- unlimited approvals;
- execution outside the frozen Ink V0F venue/taker/risk scope;
- execution without a current exact external grant;
- production live execution before the separately reviewed grant/rehearsal
  sequence.

## Deployment state

The package marker is:

`INK_V0F_HUMAN_SIGNED_EXECUTION_PREGRANT`

`SIGNING_AUTHORIZED = false` means QntySpot cannot produce signatures.

`LIVE_CAPITAL_AUTHORIZED = false` means this source transition does not
provision the production Level-3 grant. It does not weaken the runtime's
independent grant gate.

## Required next sequence

After this transition is reviewed and merged:

1. derive the canonical merged QntySpot implementation digest;
2. update QntyAuthorityRoot to bind that exact commit/digest and the already
   frozen Ink V0F scope;
3. review and merge that authority binding;
4. issue one short-lived Level-3 grant only for the exact taker/network/venue
   and frozen 0.001 WETH ceilings;
5. run the zero-money Level-3 rehearsal using the real capability gates but no
   broadcast;
6. only after that evidence passes may a separate first-dust execution be
   considered.

No production grant is issued in this phase.
