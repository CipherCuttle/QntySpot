"""Portfolio budget: every cap, and the concurrent over-allocation case.

This is the invariant that matters most when several assets move at once. The
test that earns its place here is the last one: two workers, two connections,
one unit of remaining budget.
"""

from __future__ import annotations

import threading

import pytest

from conftest import NOW, base_policy_doc, drive
from qntyspot.economics import build_intent
from qntyspot.errors import BudgetExceededError
from qntyspot.ledger import open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState as S

TO_RESERVED = (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED)


def caps(**overrides: str) -> dict:
    doc = base_policy_doc()
    doc["capital"].update(overrides)
    return doc


def arm(ledger, policy, cycle_id, level_id: str):
    intent = build_intent(policy, cycle_id, policy.level(level_id), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    return intent


def setup(doc) -> tuple:
    policy = parse_policy(doc)
    ledger = open_ledger()
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    return ledger, policy, cycle_id


def reserve(ledger, intent) -> None:
    drive(ledger, intent.economic_action_id, *TO_RESERVED)


def test_a_reservation_moves_capital_from_available_to_held() -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    assert ledger.held_atomic() == 0
    intent = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, intent)
    assert ledger.held_atomic() == 100_000_000
    assert ledger.held_atomic(policy_id=policy.policy_id) == 100_000_000
    assert ledger.held_atomic(network_id=policy.network_id) == 100_000_000


def test_release_returns_capital_on_cancellation() -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    intent = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, intent)
    ledger.transition(intent.economic_action_id, S.CANCELLED, now_epoch_s=NOW)
    assert ledger.held_atomic() == 0


@pytest.mark.parametrize("terminal", [S.CANCELLED, S.EXPIRED, S.REJECTED])
def test_endings_that_prove_nothing_happened_release_the_reservation(terminal) -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    intent = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, intent)
    ledger.transition(intent.economic_action_id, terminal, now_epoch_s=NOW)
    assert ledger.held_atomic() == 0
    status = ledger.connection.execute(
        "SELECT status FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0]
    assert status == "RELEASED"


def test_safe_halt_quarantines_capital_instead_of_releasing_it() -> None:
    """An unknown outcome must not free capital for someone else to spend.

    A halted action may still settle. If its budget were returned to the pool,
    the portfolio could commit the same capital a second time and end up over
    its cap the moment the original lands.
    """
    ledger, policy, cycle_id = setup(base_policy_doc())
    intent = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, intent)
    ledger.transition(intent.economic_action_id, S.SAFE_HALT, now_epoch_s=NOW)
    assert ledger.held_atomic() == 100_000_000
    status = ledger.connection.execute(
        "SELECT status FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0]
    assert status == "QUARANTINED"
    ledger.integrity_check()


def test_quarantined_capital_still_blocks_new_reservations() -> None:
    ledger, policy, cycle_id = setup(
        caps(allocation_quote="150", per_instrument_cap_quote="1000",
             per_network_cap_quote="1000", global_portfolio_cap_quote="1000")
    )
    first = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, first)
    ledger.transition(first.economic_action_id, S.SAFE_HALT, now_epoch_s=NOW)
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, policy, cycle_id, "E2"))


def test_a_filled_action_commits_rather_than_releases_its_capital() -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    intent = arm(ledger, policy, cycle_id, "E1")
    drive(ledger, intent.economic_action_id, *TO_RESERVED, S.SIGNED, S.SUBMITTED,
          S.INCLUDED, S.CONFIRMED, S.RECONCILED, S.FILLED)
    assert ledger.held_atomic() == 100_000_000
    status = ledger.connection.execute(
        "SELECT status FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0]
    assert status == "COMMITTED"


def test_a_sell_leg_reserves_nothing() -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    intent = build_intent(
        policy, cycle_id, policy.level("X1"), now_epoch_s=NOW, inventory_atomic=10**18
    )
    ledger.create_intent(intent, now_epoch_s=NOW)
    reserve(ledger, intent)
    assert ledger.held_atomic() == 0
    assert (
        ledger.connection.execute("SELECT COUNT(*) FROM budget_reservations").fetchone()[0]
        == 0
    )


# -- each cap, in isolation -------------------------------------------------


def test_the_policy_allocation_cap_binds() -> None:
    # allocation 150 admits E1 (100) but not E1 + E2 (200).
    ledger, policy, cycle_id = setup(
        caps(allocation_quote="150", per_instrument_cap_quote="1000",
             per_network_cap_quote="1000", global_portfolio_cap_quote="1000")
    )
    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, policy, cycle_id, "E2"))
    assert ledger.held_atomic() == 100_000_000


def test_the_per_instrument_cap_binds() -> None:
    ledger, policy, cycle_id = setup(
        caps(per_instrument_cap_quote="200", per_network_cap_quote="1000",
             global_portfolio_cap_quote="1000")
    )
    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    reserve(ledger, arm(ledger, policy, cycle_id, "E2"))
    assert ledger.held_atomic(instrument_id=policy.instrument_id) == 200_000_000


def test_the_per_network_cap_binds_across_two_instruments() -> None:
    """Each instrument is within its own cap; together they exceed the network."""
    shared = dict(
        allocation_quote="100",
        per_order_cap_quote="100",
        per_instrument_cap_quote="100",
        per_network_cap_quote="150",
        global_portfolio_cap_quote="1000",
    )
    first = caps(**shared)
    first["entry_ladder"]["levels"] = [
        {"level_id": "E1", "trigger_price": "0.9", "input_amount": "100"}
    ]
    ledger, policy, cycle_id = setup(first)

    second = caps(**shared)
    second["policy_name"] = "sibling-on-same-network"
    second["base"]["ref"]["contract_address"] = (
        "0xc0ffee0000000000000000000000000000000007"
    )
    second["entry_ladder"]["levels"] = [
        {"level_id": "F1", "trigger_price": "0.9", "input_amount": "100"}
    ]
    sibling = parse_policy(second)
    ledger.admit_policy(sibling)
    sibling_cycle = ledger.open_cycle(sibling, 0, now_epoch_s=NOW)

    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    assert ledger.held_atomic(network_id=policy.network_id) == 100_000_000
    # The sibling is inside its own instrument cap but would breach the
    # shared network cap of 150.
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, sibling, sibling_cycle, "F1"))
    assert ledger.held_atomic(network_id=policy.network_id) == 100_000_000


def test_the_global_cap_net_of_reserved_cash_binds() -> None:
    ledger, policy, cycle_id = setup(
        caps(
            allocation_quote="200",
            per_instrument_cap_quote="200",
            per_network_cap_quote="200",
            global_portfolio_cap_quote="200",
            reserved_cash_quote="150",
        )
    )
    # Spendable is 200 - 150 = 50, below a single 100 rung.
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    assert ledger.held_atomic() == 0


def test_the_per_order_cap_binds_even_when_the_portfolio_is_empty() -> None:
    doc = caps(per_order_cap_quote="100")
    ledger, policy, cycle_id = setup(doc)
    intent = arm(ledger, policy, cycle_id, "E1")
    # Force an oversized exposure past the parse-time check to prove the
    # database-side guard is independently effective.
    ledger.connection.execute(
        "UPDATE intents SET quote_exposure_atomic = ? WHERE economic_action_id = ?",
        (str(100_000_001), intent.economic_action_id),
    )
    with pytest.raises(BudgetExceededError):
        reserve(ledger, intent)
    assert ledger.held_atomic() == 0


def test_a_failed_reservation_takes_no_budget_and_leaves_no_row() -> None:
    ledger, policy, cycle_id = setup(
        caps(allocation_quote="150", per_instrument_cap_quote="1000",
             per_network_cap_quote="1000", global_portfolio_cap_quote="1000")
    )
    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    loser = arm(ledger, policy, cycle_id, "E2")
    with pytest.raises(BudgetExceededError):
        reserve(ledger, loser)
    assert ledger.held_atomic() == 100_000_000
    assert (
        ledger.connection.execute("SELECT COUNT(*) FROM budget_reservations").fetchone()[0]
        == 1
    )
    # The loser stayed where it was; the failed transition did not land.
    assert ledger.intent_state(loser.economic_action_id) is S.SIMULATED
    ledger.integrity_check()


def test_releasing_capital_makes_it_available_again() -> None:
    ledger, policy, cycle_id = setup(
        caps(allocation_quote="150", per_instrument_cap_quote="1000",
             per_network_cap_quote="1000", global_portfolio_cap_quote="1000")
    )
    first = arm(ledger, policy, cycle_id, "E1")
    reserve(ledger, first)
    second = arm(ledger, policy, cycle_id, "E2")
    with pytest.raises(BudgetExceededError):
        reserve(ledger, second)
    ledger.transition(first.economic_action_id, S.CANCELLED, now_epoch_s=NOW)
    # `second` is already SIMULATED from the failed attempt; only the
    # reservation step is retried, and it now fits.
    ledger.transition(second.economic_action_id, S.RESERVED, now_epoch_s=NOW)
    assert ledger.held_atomic() == 100_000_000


def test_the_tightest_global_cap_wins_across_policies() -> None:
    """Admitting a policy with a larger cap must not widen the portfolio."""
    generous = caps(global_portfolio_cap_quote="10000", per_network_cap_quote="10000",
                    per_instrument_cap_quote="200", allocation_quote="200")
    ledger, policy, cycle_id = setup(generous)

    strict = caps(global_portfolio_cap_quote="150", per_network_cap_quote="150",
                  per_instrument_cap_quote="150", allocation_quote="150",
                  per_order_cap_quote="100")
    strict["policy_name"] = "strict-sibling"
    strict["base"]["ref"]["contract_address"] = "0xc0ffee0000000000000000000000000000000009"
    strict["entry_ladder"]["levels"] = [
        {"level_id": "S1", "trigger_price": "0.9", "input_amount": "100"}
    ]
    strict_policy = parse_policy(strict)
    ledger.admit_policy(strict_policy)

    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, policy, cycle_id, "E2"))
    assert ledger.held_atomic() == 100_000_000


def test_a_second_quote_numeraire_is_refused_rather_than_silently_summed() -> None:
    ledger, policy, cycle_id = setup(base_policy_doc())
    other = base_policy_doc()
    other["policy_name"] = "eth-quoted"
    other["quote"]["ref"]["contract_address"] = "0xc0ffee000000000000000000000000000000000e"
    other["quote"]["decimals"] = 18
    with pytest.raises(Exception, match="single quote instrument"):
        ledger.admit_policy(parse_policy(other))


def test_caps_are_exact_far_beyond_64_bit_range() -> None:
    """An 18-decimal quote overflows SQLite INTEGER; the ledger must not."""
    doc = base_policy_doc()
    doc["quote"]["decimals"] = 18
    doc["capital"].update(
        allocation_quote="200",
        per_order_cap_quote="100",
        per_instrument_cap_quote="200",
        per_network_cap_quote="200",
        global_portfolio_cap_quote="200",
    )
    ledger, policy, cycle_id = setup(doc)
    assert policy.budget.global_cap_atomic == 200 * 10**18 > 2**63
    reserve(ledger, arm(ledger, policy, cycle_id, "E1"))
    reserve(ledger, arm(ledger, policy, cycle_id, "E2"))
    assert ledger.held_atomic() == 200 * 10**18
    ledger.integrity_check()


# -- the concurrent case ----------------------------------------------------


def test_concurrent_intents_cannot_over_allocate_the_last_of_the_budget(tmp_path) -> None:
    """Two workers, two connections, room for exactly one.

    Both are already SIMULATED before the race, so the only thing being
    contended is the reservation itself. Exactly one must win, the other must
    deterministically abstain, and the held total must never exceed the cap.
    """
    doc = caps(
        allocation_quote="150",
        per_order_cap_quote="100",
        per_instrument_cap_quote="150",
        per_network_cap_quote="150",
        global_portfolio_cap_quote="150",
    )
    policy = parse_policy(doc)
    db = str(tmp_path / "budget-race.sqlite3")

    with open_ledger(db) as setup_ledger:
        setup_ledger.admit_policy(policy)
        cycle_id = setup_ledger.open_cycle(policy, 0, now_epoch_s=NOW)
        contenders = []
        for level_id in ("E1", "E2"):
            intent = build_intent(policy, cycle_id, policy.level(level_id), now_epoch_s=NOW)
            setup_ledger.create_intent(intent, now_epoch_s=NOW)
            drive(setup_ledger, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED,
                  S.SIMULATED)
            contenders.append(intent)

    barrier = threading.Barrier(len(contenders))
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker(intent) -> None:
        with open_ledger(db) as led:
            barrier.wait(timeout=30)
            try:
                led.transition(intent.economic_action_id, S.RESERVED, now_epoch_s=NOW)
                result = "reserved"
            except BudgetExceededError:
                result = "abstained"
            except Exception as exc:  # pragma: no cover - surfaced on failure
                result = f"error:{exc!r}"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in contenders]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert sorted(outcomes) == ["abstained", "reserved"], outcomes
    with open_ledger(db) as led:
        assert led.held_atomic() == 100_000_000
        assert led.held_atomic() <= policy.budget.global_cap_atomic
        assert (
            led.connection.execute(
                "SELECT COUNT(*) FROM budget_reservations WHERE status = 'ACTIVE'"
            ).fetchone()[0]
            == 1
        )
        led.integrity_check()


def test_many_concurrent_workers_never_exceed_the_cap(tmp_path) -> None:
    """Eight workers, room for three. Scaled up, the invariant must hold."""
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"] = [
        {"level_id": f"E{i}", "trigger_price": f"0.{9 - i}", "input_amount": "10"}
        for i in range(8)
    ]
    doc["capital"].update(
        allocation_quote="30",
        per_order_cap_quote="10",
        per_instrument_cap_quote="30",
        per_network_cap_quote="30",
        global_portfolio_cap_quote="30",
    )
    policy = parse_policy(doc)
    db = str(tmp_path / "budget-race-many.sqlite3")

    with open_ledger(db) as setup_ledger:
        setup_ledger.admit_policy(policy)
        cycle_id = setup_ledger.open_cycle(policy, 0, now_epoch_s=NOW)
        contenders = []
        for level in policy.entry_ladder.levels:
            intent = build_intent(policy, cycle_id, level, now_epoch_s=NOW)
            setup_ledger.create_intent(intent, now_epoch_s=NOW)
            drive(setup_ledger, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED,
                  S.SIMULATED)
            contenders.append(intent)

    barrier = threading.Barrier(len(contenders))
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker(intent) -> None:
        with open_ledger(db) as led:
            barrier.wait(timeout=30)
            try:
                led.transition(intent.economic_action_id, S.RESERVED, now_epoch_s=NOW)
                result = "reserved"
            except BudgetExceededError:
                result = "abstained"
            except Exception as exc:  # pragma: no cover - surfaced on failure
                result = f"error:{exc!r}"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker, args=(i,)) for i in contenders]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert outcomes.count("reserved") == 3, outcomes
    assert outcomes.count("abstained") == 5, outcomes
    with open_ledger(db) as led:
        assert led.held_atomic() == 30_000_000
        led.integrity_check()


def test_committed_capital_keeps_counting_because_v0a_does_not_recycle() -> None:
    """Realized proceeds do not return to the budget in V0A.

    ``profit_recycle_ratio`` is parsed and carried in the policy, but nothing
    in the offline core spends against it. Treating filled capital as still
    deployed is the conservative direction, and it is the behaviour a future
    recycling phase has to deliberately change.
    """
    ledger, policy, cycle_id = setup(
        caps(allocation_quote="150", per_instrument_cap_quote="1000",
             per_network_cap_quote="1000", global_portfolio_cap_quote="1000")
    )
    first = arm(ledger, policy, cycle_id, "E1")
    drive(ledger, first.economic_action_id, *TO_RESERVED, S.SIGNED, S.SUBMITTED,
          S.INCLUDED, S.CONFIRMED, S.RECONCILED, S.FILLED)
    assert ledger.held_atomic() == 100_000_000
    with pytest.raises(BudgetExceededError):
        reserve(ledger, arm(ledger, policy, cycle_id, "E2"))
