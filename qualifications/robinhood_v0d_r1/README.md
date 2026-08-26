# Robinhood V0D R1 qualification

This directory is reserved for the one additional bounded live qualification
authorized after the original failed attempt under `qualifications/robinhood_v0d/`.
The original evidence is preserved and is not rewritten.

The R1 harness captures `observation_time_epoch_s` from the wall clock as an
integer immediately before the live observation call. The resulting
observation persists the RPC timestamp, signed future skew, and the fixed
30-second shadow bound. Raw HTTP responses are content-addressed before
semantic parsing. The 0x credential is used only in memory and is never
persisted in evidence or artifacts.

No signing, approval, broadcast, wallet mutation, or live-capital operation is
authorized by or performed by this qualification.
