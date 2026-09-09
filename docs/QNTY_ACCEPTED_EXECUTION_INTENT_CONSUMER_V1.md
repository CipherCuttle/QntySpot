# Qnty accepted execution intent consumer V1

This phase consumes exactly one immutable external artifact:
`QNTY_ACCEPTED_EXECUTION_INTENT_V1`.

## Provenance pre-flight

`qnty_source_commit` is classified as `ACCEPTANCE_SOURCE_COMMIT`. The
canonical Qnty merge `382cb00ca4868811e994801fa6fee4ca6932927c` adds the
accepted-intent producer, while its parent `cfee758e9b37037c0f6ef33ea43e43df55cf5f2a`
is the Qnty acceptance source named by the producer and embedded in the
artifact. QntySpot preserves the embedded field and pins the producer merge
separately.

The consumer also pins QntyLab source commit
`d7ed51f02e2e9a0a5fde74b54f6b8b9174847c7c`, handoff schema
`H003_SIGNAL_INTENT_V0`, and acceptance schema `H003_ACCEPTANCE_V0`.

## Boundary

The consumer validates canonical JSON bytes, duplicate-key rejection, digest
recomputation, governed research identity, and the no-authority block. It
does not import Qnty or QntyLab runtime code, recompute H003, accept the raw
H003 handoff, repeat Qnty acceptance, evaluate policy thresholds, request a
quote, access a network, sign, submit, or move capital.

For the canonical artifact, `LONG -> LONG` is `NO_ACTION`; the projected side
is `NONE`, and all policy/venue/network requirements are `NO`.
