# QNTY_PUBLICATION_INTEROP_V0

## Purpose

Prove that the producer-authored publication receipt merged in `CipherCuttle/Qnty` is consumed byte-for-byte by the merged QntySpot publication verifier without introducing runtime coupling or execution authority.

## Frozen source

- Qnty fixture source merge: `610f66f6c5660e09a6c0560ae1b4262f0bfd5578`
- Qnty source path: `tests/fixtures/QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.json`
- imported receipt SHA-256: `9087abfbded6eba0947f29fbbeb005d0f230669f97a3cacd59bbaab689890c8e`
- receipt id: `393a5decca6d325acd72f9016e8004022a6234460007552573ba172983cb1488`
- accepted-intent artifact SHA-256: `262f2eeea5c7fea979f1500538ffd146686e9c4ac8069a1ac5ae4d3ae7cd76db`
- receipt-declared Qnty accepted-intent commit: `2ebed2af94127f2e018de46069d1bbe27178ca8a`
- QntySpot interop base: `0bfec38c0695b002830d52ed4c8968d48bbdfbb9`

The Qnty fixture source merge and the commit declared inside the receipt are intentionally distinct. The first identifies where the producer-authored compatibility fixture became canonical in Qnty. The second identifies the Qnty commit whose published V2 accepted-intent artifact is authenticated by that receipt.

## Trust boundary

This qualification uses fixed public verification material only. It does not create, import, access, derive, or store a private signing key.

Passing interoperability proves only:

1. the copied receipt bytes are exactly the merged Qnty fixture bytes by pinned digest and source metadata;
2. the receipt cryptographically authenticates the exact accepted-intent V2 bytes under the test publication root;
3. Qnty and QntySpot agree on the publication receipt schema and signed-body semantics.

It does **not** authorize policy admission, policy evaluation, network access, signing, submission, venue activity, or capital.

## Closure target

`QNTY_TO_QNTYSPOT_PUBLICATION_INTEROP_V0_CLOSED_PASS` requires the focused interoperability test and the full QntySpot CI gates to pass with no Critical/High hostile-review finding.

Production publication-root provisioning and any policy bridge are later, separately authorized phases.
