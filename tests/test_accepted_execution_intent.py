from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qntyspot.accepted_execution_intent import (
    ACCEPTANCE_SOURCE_COMMIT,
    CANONICAL_ARTIFACT_DIGEST,
    QNTY_INTENT_PRODUCER_CANONICAL_MERGE,
    QNTYSPOT_IMPLEMENTATION_VERSION,
    AcceptedIntentRejected,
    consume_accepted_execution_intent,
)
from qntyspot.canon import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "qualifications/h003_bridge_v0/QNTY_ACCEPTED_EXECUTION_INTENT_V1.json"
FIXTURE_SHA = ROOT / "qualifications/h003_bridge_v0/QNTY_ACCEPTED_EXECUTION_INTENT_V1.sha256"
QNTYSPOT_COMMIT = "af3a51a1968d52b6b1a50a86ef4e9506dfd6db0d"


def _intent() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_canonical_fixture_is_consumed_as_no_action() -> None:
    output = consume_accepted_execution_intent(FIXTURE, qntyspot_commit=QNTYSPOT_COMMIT)

    assert output["schema_name"] == "QNTYSPOT_ACCEPTED_INTENT_DECISION_V1"
    assert output["input_intent_digest"] == CANONICAL_ARTIFACT_DIGEST
    assert output["qnty_producer"] == {
        "acceptance_schema": "H003_ACCEPTANCE_V0",
        "canonical_merge": QNTY_INTENT_PRODUCER_CANONICAL_MERGE,
        "qnty_source_commit": ACCEPTANCE_SOURCE_COMMIT,
        "repository": "CipherCuttle/Qnty",
    }
    assert output["qntyspot_implementation"] == {
        "commit": QNTYSPOT_COMMIT,
        "repository": "CipherCuttle/QntySpot",
        "version": QNTYSPOT_IMPLEMENTATION_VERSION,
    }
    assert output["decision"] == {
        "current_target": "LONG",
        "execution_action_required": False,
        "previous_target": "LONG",
        "transition": "NO_ACTION",
    }
    assert output["projection"] == {
        "consumer_result": "NO_ACTION",
        "jupiter_quote_required": "NO",
        "network_required": "NO",
        "policy_evaluation_required": "NO",
        "qntyspot_side": "NONE",
    }


def test_fixture_bytes_and_output_digest_are_canonical() -> None:
    raw = FIXTURE.read_bytes()
    intent = _intent()
    assert raw == canonical_json_bytes(intent) + b"\n"
    assert FIXTURE_SHA.read_text(encoding="utf-8") == (
        "8a4f6d90c2e18aaffcab8b5fadbb56e86d80bf1cad95b8741c52ed317f39244a  "
        "QNTY_ACCEPTED_EXECUTION_INTENT_V1.json\n"
    )
    assert hashlib.sha256(raw).hexdigest() == "8a4f6d90c2e18aaffcab8b5fadbb56e86d80bf1cad95b8741c52ed317f39244a"

    output = consume_accepted_execution_intent(raw, qntyspot_commit=QNTYSPOT_COMMIT)
    probe = dict(output)
    probe["decision_digest"] = ""
    assert output["decision_digest"] == hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.replace(b'"schema_name":"QNTY_ACCEPTED_EXECUTION_INTENT_V1"', b'"schema_name":"WRONG"'),
        lambda raw: raw.replace(
            b'"intent_digest":"f3cd36b567f4083229a9bd097123a77913533ef87515e5d85ac8ba08a3e6893f"',
            b'"intent_digest":"' + b"0" * 64 + b'"',
        ),
        lambda raw: raw.replace(b'"authority":{', b'"authority":{"extra":1},"authority":{'),
        lambda raw: raw.replace(b'"execution_action_required":false', b'"execution_action_required":0.0'),
        lambda raw: raw.replace(b'"qnty_source_commit":"cfee758e9b37037c0f6ef33ea43e43df55cf5f2a"', b'"qnty_source_commit":"382cb00ca4868811e994801fa6fee4ca6932927c"'),
    ],
)
def test_mutations_fail_closed(mutate) -> None:
    mutated = mutate(FIXTURE.read_bytes())
    with pytest.raises(AcceptedIntentRejected):
        consume_accepted_execution_intent(mutated, qntyspot_commit=QNTYSPOT_COMMIT)


def test_qntyspot_commit_is_explicit_and_validated() -> None:
    with pytest.raises(AcceptedIntentRejected, match="qntyspot_commit"):
        consume_accepted_execution_intent(FIXTURE, qntyspot_commit="ambient")


def test_no_sibling_runtime_imports_or_raw_handoff_authority() -> None:
    source = (ROOT / "qntyspot/accepted_execution_intent.py").read_text(encoding="utf-8")
    assert "import Qnty" not in source
    assert "import QntyLab" not in source
    assert "H003_SIGNAL_INTENT_V0" in source
    assert "qntyspot_side" in source
