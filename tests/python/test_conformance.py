"""Test the conformance transport, not an implementation of the MAML language."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("conformance_runner", ROOT / "tools/check_conformance.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def cases():
    return runner.load_suite(ROOT / "conformance/v1.json")


def responses(rows):
    return "\n".join(json.dumps({"id": c["id"], "result": c["expect"]}) for c in rows)


def test_fixture_validation_does_not_claim_implementation_conformance():
    result = subprocess.run([sys.executable, str(ROOT / "tools/check_conformance.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "No implementation was tested" in result.stdout
    assert len(cases()) >= 40


def test_exact_responses_and_reordered_responses_pass():
    rows = cases()
    assert runner.check_responses(rows, responses(rows)) == []
    assert runner.check_responses(rows, responses(list(reversed(rows)))) == []


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "malformed", "wrong"])
def test_incomplete_or_incorrect_output_fails(mutation):
    rows = cases()[:2]
    lines = responses(rows).splitlines()
    if mutation == "missing":
        lines.pop()
    elif mutation == "duplicate":
        lines.append(lines[0])
    elif mutation == "unknown":
        lines.append(json.dumps({"id": "unknown", "result": {"status": "ok"}}))
    elif mutation == "malformed":
        lines.append("not json")
    else:
        lines[0] = json.dumps({"id": rows[0]["id"], "result": {"status": "no_match", "schema": []}})
    assert runner.check_responses(rows, "\n".join(lines))


def test_full_width_capture_is_not_accepted_as_a_json_number():
    row = next(c for c in cases() if c["id"] == "pointer_full_width_unmapped")
    bad = json.loads(responses([row]))
    bad["result"]["match"]["captures"]["pointer"]["value"] = 18446744073709551615
    assert runner.check_responses([row], json.dumps(bad))


def test_projection_result_order_is_not_a_language_requirement():
    row = next(c for c in cases() if c["id"] == "projection_preserves_kind")
    response = json.loads(responses([row]))
    response["result"]["values"].reverse()
    assert runner.check_responses([row], json.dumps(response)) == []


def test_duplicate_projected_values_are_not_silently_removed_by_runner():
    row = next(c for c in cases() if c["id"] == "projection_filters_absent")
    response = json.loads(responses([row]))
    response["result"]["values"] *= 2
    assert runner.check_responses([row], json.dumps(response))


@pytest.mark.parametrize("mutation", ["duplicate_id", "unknown_operation", "numeric_address", "invalid_bytes"])
def test_invalid_fixture_format_is_rejected(tmp_path, mutation):
    rows = cases()[:1]
    if mutation == "duplicate_id":
        rows *= 2
    elif mutation == "unknown_operation":
        rows[0]["request"]["operation"] = "surprise"
    elif mutation == "numeric_address":
        rows[0]["request"]["image"]["base"] = 0
    else:
        rows[0]["request"]["image"]["bytes"] = "G0"
    path = tmp_path / "vectors.json"
    path.write_text(json.dumps({"format": "maml-conformance-v1", "cases": rows}))
    with pytest.raises(runner.ConformanceError):
        runner.load_suite(path)


def test_adapter_process_receives_requests_without_expected_answers(tmp_path):
    rows = cases()[:2]
    # A controlled transport fixture: this is deliberately not a language adapter.
    script = tmp_path / "transport.py"
    answers = {c["id"]: c["expect"] for c in rows}
    script.write_text("import json, sys\nanswers = " + repr(answers) + "\n"
                      "for line in sys.stdin:\n"
                      "    request = json.loads(line)\n"
                      "    assert set(request) == {'id', 'request'}\n"
                      "    print(json.dumps({'id': request['id'], 'result': answers[request['id']]}))\n")
    assert runner.run_adapter(rows, [sys.executable, str(script)], timeout=5) == []


def test_adapter_nonzero_exit_is_a_failure():
    with pytest.raises(runner.ConformanceError, match="exit"):
        runner.run_adapter(cases()[:1], [sys.executable, "-c", "raise SystemExit(3)"], timeout=5)


def test_adapter_timeout_is_a_failure():
    with pytest.raises(runner.ConformanceError, match="timed out"):
        runner.run_adapter(cases()[:1], [sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.05)
