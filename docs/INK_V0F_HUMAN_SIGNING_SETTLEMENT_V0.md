# Ink V0F human signing, approval settlement, and same-amount revalidation

This phase prepares the externally controlled signer path while the binding
QntySpot source ceiling remains `RECONCILE_ONLY`.

It does **not** authorize transaction submission or signature production.

## Approval/signing sequence

The first-live sequence is frozen as:

1. durable exact approval + swap preauthorization already exists;
2. approval signing request is built for the exact ERC-20 amount;
3. approval nonce must satisfy:
   `swap_nonce = approval_nonce + 1`;
4. the external signer returns complete EIP-1559 bytes;
5. QntySpot validates sender, chain, token target, calldata, nonce, gas and fee
   ceilings without changing the byte string;
6. two canonical Ink providers independently observe the approval transaction;
7. successful settlement requires both chain finality and an exact post-settlement
   allowance read;
8. before swap signing, QntySpot re-reads pool, router, allowance, taker nonce and
   common-block base fee;
9. the preauthorized swap input and calldata remain frozen.

## Approval settlement

ERC-20 approval receipts are not modelled as swaps. They therefore use a
dedicated approval observation record that contains transaction/block/receipt
facts but no invented input/output transfer amounts.

Two-provider contradictions, reorg-like observations, or an acknowledged
transaction that disappears produce `AMBIGUOUS`.

A confirmed approval is `SETTLED` only when:

`observed_allowance == requested_allowance == frozen_swap_input`

Any confirmed allowance mismatch enters `SAFE_HALT`.

If the observed allowance is non-zero in a halt state, the next permitted
human-controlled recovery action is an exact revoke-to-zero request.

## Revoke path

The revoke request is:

`approve(frozen_router, 0)`

It targets the same ERC-20 contract and the same frozen router. Signed revoke
bytes receive the same cryptographic and byte-exact validation as approval
bytes.

A revoke is complete only when chain truth is confirmed and a later two-provider
allowance observation reports exactly zero.

## Same-amount pre-sign revalidation

Fresh market data does not create a new swap.

The runtime verifies the **existing** preauthorized swap against fresh facts:

- exact allowance still equals the frozen input;
- current confirmed nonce equals the frozen swap nonce;
- common-block base fee does not exceed the frozen fee ceiling;
- router identity is unchanged;
- the exact frozen input still passes the current risk checks;
- the frozen minimum output is not looser than the fresh admissible floor;
- the fresh quote can still satisfy the frozen minimum output.

If any check fails:

`STOP / REVOKE`

The runtime must not:

- increase the amount;
- shrink the amount;
- regenerate a different calldata payload;
- lower the frozen minimum output;
- silently advance the nonce.

## EXIT symmetry

The same approval/signing/settlement/revalidation machinery applies to EXIT.

For EXIT the approved token is KRAKMASK and the swap path is:

`KRAKMASK -> WETH`

The existing preview path continues to bind exit size to settled ledger
inventory. This phase does not create a separate exit authority path.

## Authority status

Binding source ceiling:

`RECONCILE_ONLY`

Still forbidden:

- signature production;
- approval submission;
- swap submission;
- autonomous execution;
- private signing material ingestion.
