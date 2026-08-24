"""The chain / venue truth boundary.

NOTHING IN THIS MODULE IS IMPLEMENTED. These are typing protocols that
describe where a future adapter attaches. There is no default implementation,
no registry, no discovery, and no import of any network library. Importing
this module cannot cause a request, a signature, or a key read.

THE RULE THESE PROTOCOLS EXIST TO ENCODE
----------------------------------------
* Chain or venue truth is authoritative for what actually filled.
* The local ledger is authoritative for what was intended.
* Reconciliation is the only bridge, and its only output is a
  :class:`~qntyspot.domain.FillReceiptV0`.
* Ambiguity -- a missing transaction, a contradictory receipt, two candidate
  settlements for one action -- produces ``SAFE_HALT``. It never produces a
  speculative reconstruction, a retry, or an assumed outcome.

WHY THE INTERFACES LOOK LIKE THIS
---------------------------------
``ExecutionVenueAdapter.encode`` takes an :class:`ExecutionPlanV0` whose
``bounds`` already carry the absolute economic limit. An adapter's job is to
put those bounds *inside* the transaction or order it builds, not to check
them beforehand. An adapter that can only check is an adapter that can be
front-run past its own policy.

FUTURE_DEFERRED -- NFT execution
--------------------------------
A future OpenSea/Seaport adapter would introduce its own Instrument and Intent
semantics behind this same ``ExecutionVenueAdapter`` seam. V0A adds no
Seaport-specific type, no collection or trait model, no floor-price concept
and no bidding state. The single accommodation the core makes is
:class:`~qntyspot.identity.AssetClass`, so that fungibility is a stated fact
rather than an unstated assumption.
"""

from __future__ import annotations

from typing import Protocol, Sequence, runtime_checkable

from .domain import EconomicBounds, ExecutionPlanV0, FillReceiptV0, QuoteV0

__all__ = [
    "QuoteSource",
    "ExecutionVenueAdapter",
    "ChainTruthSource",
    "Reconciler",
]


@runtime_checkable
class QuoteSource(Protocol):
    """Supplies a pinned quote for an intent. NOT IMPLEMENTED IN V0A."""

    def quote(self, bounds: EconomicBounds, *, now_epoch_s: int) -> QuoteV0:
        ...


@runtime_checkable
class ExecutionVenueAdapter(Protocol):
    """Turns a plan into something a venue accepts. NOT IMPLEMENTED IN V0A.

    The returned payload must encode ``plan.bounds`` as venue-enforced limits.
    Returning a payload whose limits are looser than the plan's bounds is a
    defect, not a tuning choice.
    """

    venue_id: str

    def encode(self, plan: ExecutionPlanV0) -> bytes:
        ...


@runtime_checkable
class ChainTruthSource(Protocol):
    """Reads settled facts from a chain or venue. NOT IMPLEMENTED IN V0A."""

    def settlements(self, external_ref: str) -> Sequence[FillReceiptV0]:
        ...


@runtime_checkable
class Reconciler(Protocol):
    """Converts external truth into canonical receipts. NOT IMPLEMENTED IN V0A.

    An implementation must raise :class:`~qntyspot.errors.SafeHaltError` rather
    than return a best guess whenever the external picture is incomplete or
    self-contradictory.
    """

    def reconcile(
        self, economic_action_id: str, *, now_epoch_s: int
    ) -> Sequence[FillReceiptV0]:
        ...
