#!/usr/bin/env python3
"""Validate shipped schemas, examples, and representative invalid inputs."""

from copy import deepcopy
from importlib.metadata import version
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent.parent


def read_json(path):
    return json.loads((ROOT / path).read_text())


def changed(document, path, replacement):
    result = deepcopy(document)
    target = result
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    return result


def main():
    print(f"jsonschema {version('jsonschema')}; draft 2020-12")
    validators = {}
    for kind in ["config", "cached-claims"]:
        path = f"schemas/progress-panel-{kind}.schema.json"
        schema = read_json(path)
        Draft202012Validator.check_schema(schema)
        validators[kind] = Draft202012Validator(schema)
        print(f"PASS schema: {path}")

    config = read_json("examples/prototype/.progress-checker/config.json")
    claims = read_json("examples/prototype/.progress-checker/state.json")
    examples = [
        ("config", "config.example.json", read_json("config.example.json")),
        ("config", "prototype config", config),
        ("cached-claims", "prototype cached claims", claims),
        ("cached-claims", "empty cached claims", changed(claims, ["milestones"], [])),
    ]
    for label, parallelism, timeout in [
        ("minimum integer bounds", 1, 1),
        ("maximum Rust integer bounds", 4294967295, 18446744073709551615),
    ]:
        bounded = changed(config, ["execution", "max_parallel"], parallelism)
        bounded["execution"]["default_timeout_seconds"] = timeout
        bounded["checks"][0]["timeout_seconds"] = timeout
        examples.append(("config", label, bounded))
    for path in [".", "./src", "src/..hidden", "src\\..hidden", "..\n", "src/..\n",
                 "Caf\u00e9/assets", "folder:assets", "1:assets"]:
        examples.append(("config", f"literal relative path {path!r}", changed(config, ["checks", 0, "cwd"], path)))
    # Rust does not treat these code points as whitespace, unlike some regex engines.
    for value in ["\x1c", "\ufeff"]:
        examples.append(("config", f"non-whitespace ID {value!r}", changed(config, ["project_id"], value)))
    for kind, label, example in examples:
        validators[kind].validate(example)
        print(f"PASS example: {label}")

    invalid = []
    for path in [[], ["panel"], ["execution"], ["fingerprint"], ["checks", 0],
                 ["milestones", 0], ["milestones", 0, "criteria", 0]]:
        invalid.append(("config", f"unknown field at {path}",
                        changed(config, path + ["unknown_field"], True)))
    for path in [[], ["milestones", 0]]:
        invalid.append(("cached-claims", f"unknown cached field at {path}",
                        changed(claims, path + ["unknown_field"], True)))
    for claim in ["verified", "failed", "stale"]:
        invalid.append(("cached-claims", f"forged claim {claim}",
                        changed(claims, ["milestones", 0, "implementation_claim"], claim)))
    for kind, document in [("config", config), ("cached-claims", claims)]:
        invalid.append((kind, f"unsupported {kind} version",
                        changed(document, ["schema_version"], 2)))
    for path in [["execution", "max_parallel"], ["execution", "default_timeout_seconds"],
                 ["checks", 0, "timeout_seconds"]]:
        invalid.append(("config", f"zero execution value at {path}", changed(config, path, 0)))
        for value in [-1, True]:
            invalid.append(("config", f"invalid integer {value!r} at {path}", changed(config, path, value)))
    for path, overflow in [
        (["execution", "max_parallel"], 4294967296),
        (["execution", "default_timeout_seconds"], 18446744073709551616),
        (["checks", 0, "timeout_seconds"], 18446744073709551616),
    ]:
        invalid.append(("config", f"Rust integer overflow at {path}", changed(config, path, overflow)))
    # Rust 1.95 char::is_whitespace(): six ASCII code points plus 19 Unicode points.
    whitespace = "\t\n\v\f\r \u0085\u00a0\u1680" + "".join(chr(point) for point in range(0x2000, 0x200B)) + "\u2028\u2029\u202f\u205f\u3000"
    for value in whitespace:
        invalid.append(("config", f"whitespace-only ID U+{ord(value):04X}", changed(config, ["project_id"], value)))
    for value in [[], [" "], ["bad\0executable"], ["cargo", "bad\0argument"]]:
        invalid.append(("config", f"invalid argv {value!r}", changed(config, ["checks", 0, "argv"], value)))
    for unsafe in ["", " ", "/tmp", "../outside", "src/../../outside", "C:\\outside",
                   "C:outside", "\\\\server\\share", "src\\..\\outside", "src\0outside"]:
        invalid.append(("config", f"unsafe cwd {unsafe!r}", changed(config, ["checks", 0, "cwd"], unsafe)))
        for field in ["extra_inputs", "exclude_outputs"]:
            invalid.append(("config", f"unsafe {field} {unsafe!r}",
                            changed(config, ["fingerprint", field], [unsafe])))
    invalid.append(("config", "no required criteria",
                    changed(config, ["milestones", 0, "criteria", 0, "required"], False)))
    invalid.append(("config", "empty criteria", changed(config, ["milestones", 0, "criteria"], [])))
    for kind, label, document in invalid:
        if not list(validators[kind].iter_errors(document)):
            raise AssertionError(f"Schema accepted negative control: {label}")
        print(f"PASS rejected: {label}")

    # These intentionally invalid runtime configurations illustrate what a schema
    # cannot establish. They are not valid examples or approved execution inputs.
    duplicated_check = deepcopy(config)
    other_check = deepcopy(duplicated_check["checks"][0])
    other_check["kind"] = "different-kind"
    duplicated_check["checks"].append(other_check)
    duplicated_claim = deepcopy(claims)
    other_claim = deepcopy(duplicated_claim["milestones"][0])
    other_claim["implementation_claim"] = "planned"
    duplicated_claim["milestones"].append(other_claim)
    runtime_only = [
        ("config", "same check ID in different objects", duplicated_check),
        ("config", "unknown check reference", changed(config, ["milestones", 0, "criteria", 0, "check_id"], "missing")),
        ("config", "unknown milestone reference", changed(config, ["milestones", 0, "depends_on"], ["missing"])),
        ("config", "milestone self-cycle", changed(config, ["milestones", 0, "depends_on"], [config["milestones"][0]["id"]])),
        ("cached-claims", "same cached milestone ID in different objects", duplicated_claim),
        ("cached-claims", "different cached project ownership", changed(claims, ["project_id"], "other-project")),
    ]
    for kind, label, document in runtime_only:
        validators[kind].validate(document)
        print(f"PASS runtime-only boundary: {label}")
    print(f"Schema validation passed: 2 schemas, {len(examples)} positive examples, {len(invalid)} negative controls.")
    print(f"Checked {len(runtime_only)} runtime-only boundaries: schema acceptance never implies valid IDs, references, cycles, or ownership.")
    print("JSON Schema treats integral floating values (e.g. 1.0) as integers; Rust requires integer JSON tokens.")


def validate_phase1():
    """Wire constraints are distinct from runtime trust and evidence validation."""
    paths = {
        "trust": "schemas/progress-checker-trust.schema.json",
        "result": "schemas/progress-checker-result.schema.json",
        "status": "schemas/progress-checker-result.schema.json",
    }
    positives = []
    negatives = []
    approval = read_json("examples/phase1/approval.example.json")
    positives.append(("trust", "illustrative approval binding", approval))
    for path in [[], ["binding"], ["binding", "environment"]]:
        negatives.append(("trust", f"unknown approval field at {path}",
                          changed(approval, path + ["unexpected"], True)))
    for path, value in [(["schema_version"], 2),
                        (["binding_digest"], "sha256:example"),
                        (["binding", "sandbox_profile"], "unsandboxed"),
                        (["binding", "environment", "HOME"], "/home/example"),
                        (["binding", "argv"], []),
                        (["binding", "argv"], ["/usr/bin/true\0"]),
                        (["binding", "cwd"], "../outside"),
                        (["binding", "config_hash"], "bad"),
                        (["binding", "executable_hash"], "bad"),
                        (["binding", "sandbox_binary_hash"], "bad")]:
        negatives.append(("trust", f"invalid approval {path}", changed(approval, path, value)))
    result = read_json("examples/phase1/result.example.json")
    status = read_json("examples/phase1/status.example.json")
    positives.extend([("result", "immutable run record", result),
                      ("status", "output-only computed status", status)])
    for path in [[], ["before"], ["after"], ["evidence"], ["evidence", "source"],
                 ["result"], ["result", "stdout"], ["result", "stderr"]]:
        negatives.append(("result", f"unknown result field at {path}",
                          changed(result, path + ["unexpected"], True)))
    for path, value in [(["schema_version"], 2), (["duration_ms"], -1),
                        (["duration_ms"], 18446744073709551616),
                        (["started_at"], "not-a-UTC-time"),
                        (["evidence", "outcome"], "verified"),
                        (["evidence", "freshness"], "green"),
                        (["before", "fingerprint"], "bad"),
                        (["result", "exit_code"], 2147483648),
                        (["result", "outcome"], "verified")]:
        negatives.append(("result", f"invalid result {path}", changed(result, path, value)))
    negatives.append(("result", "edited derived progress", changed(result, ["progress"], status["progress"])))
    negatives.append(("result", "edited derived verification", changed(result, ["evidence", "verified"], True)))
    unavailable = changed(result, ["after"], None)
    unavailable["evidence"]["outcome"] = "unknown"
    unavailable["evidence"]["freshness"] = "pending"
    unavailable["result"]["outcome"] = "unknown"
    unavailable["result"]["exit_code"] = None
    unavailable["result"]["reason"] = "source fingerprint unavailable after run"
    positives.append(("result", "unknown outcome without source-after", unavailable))
    for path, value in [(["progress", "percent"], 101),
                        (["progress", "verified"], -1),
                        (["progress", "unexpected"], True),
                        (["progress", "milestones", 0, "unexpected"], True)]:
        negatives.append(("status", f"invalid status {path}", changed(status, path, value)))
    for kind, path in paths.items():
        schema = read_json(path)
        if kind == "status":
            schema["$ref"] = "#/$defs/status"
        Draft202012Validator.check_schema(schema)
        validators = Draft202012Validator(schema)
        for example_kind, label, document in positives:
            if example_kind == kind:
                validators.validate(document)
                print(f"PASS Phase 1 example: {label}")
        for example_kind, label, document in negatives:
            if example_kind == kind:
                if not list(validators.iter_errors(document)):
                    raise AssertionError(f"Schema accepted negative control: {label}")
                print(f"PASS Phase 1 rejected: {label}")
    print(f"Phase 1 validation passed: {len(set(paths.values()))} schemas, {len(positives)} positive examples, {len(negatives)} negative controls.")


def validate_phase2():
    """Strict IPC envelope and command-input controls; no execution approval."""
    schema = read_json("schemas/progress-checker-service.schema.json")
    Draft202012Validator.check_schema(schema)
    request_validator = Draft202012Validator(schema)
    response_schema = deepcopy(schema)
    response_schema["$ref"] = "#/$defs/response"
    response_validator = Draft202012Validator(response_schema)
    operations = [
        {"operation": "project"}, {"operation": "progress"},
        {"operation": "milestones", "scope": True},
        {"operation": "subscribe", "after_revision": None},
        {"operation": "set_claim", "milestone_id": "fixture", "claim": "implemented", "note": "local claim", "expected_revision": 3},
        {"operation": "run_checks", "check_ids": ["safe"], "idempotency_key": "run-once", "expected_config_hash": "sha256:" + "a" * 64, "expected_revision": 3},
        {"operation": "get_run", "run_id": "run-1"},
        {"operation": "get_log", "run_id": "run-1", "check_id": "safe", "offset": 0, "limit": 32768},
        {"operation": "cancel_run", "run_id": "run-1", "expected_revision": 3},
    ]
    requests = [{"schema_version": 1, "request_id": "request-1", "operation": op} for op in operations]
    good = {"schema_version": 1, "request_id": "request-1", "service_instance_id": "instance-1", "revision": 3, "result": {}}
    error = changed(good, ["error"], {"code": "conflict", "message": "revision changed"})
    del error["result"]
    for document in requests:
        request_validator.validate(document)
    for document in [good, error]:
        response_validator.validate(document)
    invalid_requests = [changed(requests[0], ["schema_version"], 2), changed(requests[0], ["argv"], ["sh"]), changed(requests[0], ["request_id"], "../secret"), changed(requests[4], ["operation", "claim"], "verified"), changed(requests[4], ["operation", "note"], "bad\0note"), changed(requests[5], ["operation", "check_ids"], ["safe", "safe"]), changed(requests[5], ["operation", "expected_config_hash"], "bad"), changed(requests[5], ["operation", "argv"], ["sh"]), changed(requests[7], ["operation", "limit"], 32769), changed(requests[8], ["operation", "expected_revision"], -1)]
    invalid_responses = [changed(good, ["schema_version"], 2), changed(good, ["revision"], -1), changed(good, ["service_instance_id"], ""), changed(good, ["error"], error["error"]), changed(error, ["error", "unexpected"], True)]
    missing = deepcopy(good)
    del missing["result"]
    invalid_responses.append(missing)
    for validator, documents in [(request_validator, invalid_requests), (response_validator, invalid_responses)]:
        for document in documents:
            assert list(validator.iter_errors(document)), document
    summary = read_json("examples/phase1/result.example.json")
    summary["current_freshness"] = "stale"
    summary["result"].pop("stdout")
    summary["result"].pop("stderr")
    summary_schema = deepcopy(schema)
    summary_schema["$ref"] = "#/$defs/get_run_result"
    summary_validator = Draft202012Validator(summary_schema)
    summary_validator.validate(summary)
    for stream in ["stdout", "stderr"]:
        assert list(summary_validator.iter_errors(changed(summary, ["result", stream], {"text": "secret payload", "truncated": False})))
    variant_schema = deepcopy(schema)
    variant_schema["$ref"] = "#/$defs/get_run_result"
    variant_validator = Draft202012Validator(variant_schema)
    base_evidence = read_json("examples/phase1/result.example.json")["evidence"]
    variants = []
    for state, outcome in [("running", None), ("finished", "unknown"), ("finished", "cancelled")]:
        evidence = deepcopy(base_evidence)
        evidence.update(execution_state=state, outcome=outcome, freshness="pending", log_ref=None, log_sha256=None)
        variants.append(evidence)
    for evidence in variants:
        variant_validator.validate(evidence)
    batch_schema = deepcopy(schema)
    batch_schema["$ref"] = "#/$defs/batch_run"
    batch_validator = Draft202012Validator(batch_schema)
    missing_child = {"run_id": "missing-child", "execution_state": "finished", "outcome": "unknown", "current_freshness": "pending"}
    batch = {"run_id": "batch", "check_ids": ["safe"], "run_ids": ["child"], "expected_config_hash": "sha256:" + "a" * 64, "revision": 3, "cancel_requested": True, "execution_state": "finished", "runs": variants + [missing_child]}
    batch_validator.validate(batch)
    assert list(batch_validator.iter_errors(changed(batch, ["runs", 3, "outcome"], "passed")))
    assert list(batch_validator.iter_errors(changed(batch, ["runs", 3, "verified"], True)))
    print("PASS Phase 2 run variants: active, cancelled, recovered unknown, and missing historical child; rejected invented passing/verified fallback.")

    print(f"Phase 2 validation passed: 1 service schema, {len(requests) + 2} positive examples, {len(invalid_requests) + len(invalid_responses)} negative controls.")


def validate_service_report(path):
    """Validate captured full IPC envelopes and their operation-specific results."""
    schema = read_json("schemas/progress-checker-service.schema.json")
    validators = {}
    for kind in ["response", "snapshot", "log_page", "batch_acceptance", "batch_run", "cancel_result", "get_run_result"]:
        definition = deepcopy(schema)
        definition["$ref"] = "#/$defs/" + kind
        validators[kind] = Draft202012Validator(definition)
    counts = {}
    report = json.loads(Path(path).read_text())
    for operation in report["operations"]:
        response = operation["response"]
        validators["response"].validate(response)
        counts["envelope"] = counts.get("envelope", 0) + 1
        if "result" not in response:
            continue
        result = response["result"]
        kind = {"project": "snapshot", "progress": "snapshot", "set_claim": "snapshot", "subscribe": "snapshot", "get_log": "log_page", "run_checks": "batch_acceptance", "cancel_run": "cancel_result"}.get(operation["operation"])
        if operation["operation"] == "get_run":
            kind = "get_run_result"
        if kind:
            validators[kind].validate(result)
            counts[kind] = counts.get(kind, 0) + 1
    print("PASS actual service outputs: " + json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
    validate_phase1()
    validate_phase2()
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-report", type=Path)
    args = parser.parse_args()
    if args.service_report:
        validate_service_report(args.service_report)
