These fixtures illustrate Phase 1 JSON shapes. They are not execution approval or evidence.

- `approval.example.json` matches the separate local approval schema, with placeholder hashes and nonexistent example paths. Runtime authorization must reject it.
- `result.example.json` matches the immutable `RunRecord` output schema, with illustrative identities/log hashes. It cannot be imported to grant verification.
- `status.example.json` matches the output-only status definition in the result schema. Computed progress is never accepted as persisted input.

Run `python3 scripts/demo-checker.py` for a generated synthetic fixture and interactive review of its exact command. `checker-core/examples/config.json` is a validation/unit-test fixture, not a ready-to-run approval.
