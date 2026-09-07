"""Validate MAML vectors, or check a language implementation via a JSONL adapter."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
KINDS = {"CursorAddress", "ResolvedRelativeTarget", "AbsolutePointerValue"}
OPERATIONS = {"compile", "match_at", "project", "lookup", "unique_matches"}
STATUSES = {"ok", "no_match", "compile_error", "schema_error", "cardinality_error"}


class ConformanceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConformanceError(message)


def integer(text):
    require(isinstance(text, str) and re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,15})", text),
            f"expected canonical unsigned 64-bit hex string, got {text!r}")
    return int(text, 16)


def capture(value):
    require(isinstance(value, dict) and set(value) == {"value", "kind", "space"},
            "capture must have value, kind, and space")
    integer(value["value"])
    require(value["kind"] in KINDS, "unknown capture kind")
    require(isinstance(value["space"], str) and value["space"], "missing capture address space")


def schema(names):
    require(isinstance(names, list) and all(isinstance(n, str) and n for n in names),
            "schema must be a list of names")
    require(len(names) == len(set(names)), "schema names must be unique")


def match_record(record):
    require(isinstance(record, dict) and set(record) == {"offset", "captures"},
            "match must have offset and captures")
    integer(record["offset"])
    require(isinstance(record["captures"], dict), "captures must be an object")
    for name, value in record["captures"].items():
        require(isinstance(name, str) and name, "empty capture name")
        capture(value)


def validate_request(request):
    require(isinstance(request, dict), "request must be an object")
    require(request.get("dialect") == "maml-v1", "request must explicitly select maml-v1")
    op = request.get("operation")
    require(op in OPERATIONS, "unknown operation")
    fields = {
        "compile": {"pattern"},
        "match_at": {"pattern", "image", "start_offset"},
        "project": {"name", "schema", "matches", "unique"},
        "lookup": {"name", "schema", "match"},
        "unique_matches": {"matches"},
    }
    require(set(request) == fields[op] | {"dialect", "operation"}, "incorrect request fields")
    if op in {"compile", "match_at"}:
        require(isinstance(request["pattern"], str), "pattern must be text")
    if op == "match_at":
        image = request["image"]
        require(isinstance(image, dict) and set(image) == {"base", "bytes", "pointer_map"},
                "image must have base, bytes, and pointer_map")
        integer(image["base"])
        require(isinstance(image["bytes"], str) and
                re.fullmatch(r"(?:[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2})*)?", image["bytes"]) is not None,
                "image bytes must be space-separated hex pairs")
        integer(request["start_offset"])
        require(isinstance(image["pointer_map"], list), "pointer_map must be a list")
        seen = set()
        for entry in image["pointer_map"]:
            require(isinstance(entry, dict) and set(entry) == {"value", "address"}, "invalid mapping")
            integer(entry["value"])
            integer(entry["address"])
            require(entry["value"] not in seen, "duplicate pointer mapping")
            seen.add(entry["value"])
    if op in {"lookup", "project"}:
        schema(request["schema"])
        require(isinstance(request["name"], str) and request["name"], "missing lookup name")
    if op in {"project", "unique_matches"}:
        require(isinstance(request["matches"], list), "matches must be a list")
        for record in request["matches"]:
            match_record(record)
    if op == "project":
        require(type(request["unique"]) is bool, "unique must be boolean")
        for record in request["matches"]:
            require(set(record["captures"]) <= set(request["schema"]), "capture outside schema")
    if op == "lookup":
        match_record(request["match"])
        require(set(request["match"]["captures"]) <= set(request["schema"]), "capture outside schema")


def validate_result(result, operation):
    require(isinstance(result, dict) and isinstance(result.get("status"), str), "invalid result")
    status = result["status"]
    require(status in STATUSES, "unknown result status")
    if status in {"compile_error", "schema_error"}:
        require(set(result) == {"status", "code"} and isinstance(result["code"], str), "invalid error result")
        require(operation in ({"compile", "match_at"} if status == "compile_error" else {"lookup", "project"}),
                "error status incompatible with operation")
    elif status == "cardinality_error":
        require(operation in {"unique_matches", "project"} and set(result) == {"status"}, "invalid cardinality result")
    elif operation in {"compile", "match_at"}:
        require(status == "ok" or (operation == "match_at" and status == "no_match"), "invalid match status")
        fields = {"status", "schema"}
        if operation == "match_at" and status == "ok":
            fields.add("match")
        require(set(result) == fields, "incorrect compile/match result fields")
        schema(result["schema"])
        if "match" in result:
            match_record(result["match"])
            require(set(result["match"]["captures"]) <= set(result["schema"]), "capture outside schema")
    else:
        require(status == "ok", "invalid result status for operation")
        field = {"project": "values", "lookup": "value", "unique_matches": "match"}[operation]
        require(set(result) == {"status", field}, "incorrect operation result fields")
        if operation == "project":
            require(isinstance(result[field], list), "values must be a list")
            for value in result[field]:
                capture(value)
        elif operation == "lookup" and result[field] is not None:
            capture(result[field])
        elif operation == "unique_matches":
            match_record(result[field])


def load_suite(path):
    try:
        data = json.loads(Path(path).read_text())
        require(isinstance(data, dict) and set(data) == {"format", "cases"} and
                data["format"] == "maml-conformance-v1", "unsupported fixture format")
        require(isinstance(data["cases"], list) and data["cases"], "fixture suite is empty")
        ids = set()
        for case in data["cases"]:
            require(isinstance(case, dict) and set(case) == {"id", "request", "expect"}, "invalid case")
            require(isinstance(case["id"], str) and re.fullmatch(r"[a-z][a-z0-9_]*", case["id"]), "invalid case id")
            require(case["id"] not in ids, "duplicate case id")
            ids.add(case["id"])
            validate_request(case["request"])
            validate_result(case["expect"], case["request"]["operation"])
        return data["cases"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ConformanceError(f"{path}: {exc}") from exc


def canonical(result):
    result = dict(result)
    if "schema" in result:
        result["schema"] = sorted(result["schema"])
    if "values" in result:
        # Ignore order, not multiplicity: an adapter must perform deduplication itself.
        result["values"] = sorted(result["values"], key=lambda v: json.dumps(v, sort_keys=True))
    return json.dumps(result, sort_keys=True)


def check_responses(cases, output):
    expected = {c["id"]: c for c in cases}
    seen, errors = set(), []
    for index, line in enumerate(output.splitlines(), 1):
        try:
            response = json.loads(line)
            require(isinstance(response, dict) and set(response) == {"id", "result"}, "invalid response envelope")
            key = response["id"]
            require(isinstance(key, str) and key in expected, "unknown response id")
            require(key not in seen, f"duplicate response: {key}")
            seen.add(key)
            validate_result(response["result"], expected[key]["request"]["operation"])
            if canonical(response["result"]) != canonical(expected[key]["expect"]):
                errors.append(f"{key}: expected {canonical(expected[key]['expect'])}; got {canonical(response['result'])}")
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"response line {index}: {exc}")
    errors.extend(f"missing response: {key}" for key in expected.keys() - seen)
    return errors


def run_adapter(cases, command, timeout):
    payload = "".join(json.dumps({"id": c["id"], "request": c["request"]}) + "\n" for c in cases)
    try:
        proc = subprocess.run(command, input=payload, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ConformanceError("adapter timed out") from exc
    except OSError as exc:
        raise ConformanceError(f"cannot start adapter: {exc}") from exc
    if proc.returncode:
        raise ConformanceError(f"adapter exit {proc.returncode}: {proc.stderr.strip()}")
    return check_responses(cases, proc.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=ROOT / "conformance/v1.json")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--adapter", nargs=argparse.REMAINDER, help="executable and arguments; must be the last option")
    args = parser.parse_args(argv)
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be finite and positive")
    if args.adapter == []:
        parser.error("--adapter requires an executable")
    try:
        cases = load_suite(args.suite)
        if args.adapter is None:
            print(f"Validated {len(cases)} conformance vectors. No implementation was tested.")
            return 0
        errors = run_adapter(cases, args.adapter, args.timeout)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"Adapter passed all {len(cases)} vectors. This is bounded conformance evidence, not complete language coverage.")
        return 0
    except ConformanceError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
