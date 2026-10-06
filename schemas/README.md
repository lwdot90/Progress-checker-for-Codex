# Native checker JSON contracts

These JSON Schema draft 2020-12 files document the native checker's contracts:

- `progress-panel-config.schema.json` is the project configuration accepted by
  plan submission. Its filename reflects the earlier panel prototype; the
  native MCP adapter embeds this schema directly.
- `progress-checker-result.schema.json` describes immutable command-run records
  and output-only status, progress, and milestone evaluations.
- `progress-checker-service.schema.json` describes Unix-service request/response
  envelopes and operation-specific snapshots, logs, run summaries, batches,
  and cancellation results.
- `progress-checker-trust.schema.json` describes an exact local execution grant.
  A JSON document that matches it is not an authenticated approval.

Rust in `checker-core`, `checker-service`, and `checker-mcp` is the authoritative
validator. Schemas cannot enforce ownership, peer credentials, canonical paths,
ID uniqueness across different objects, dependency cycles, executable hashes,
authenticated storage, or current source fingerprints. JSON Schema integer
validation also accepts integral numeric values that Rust's integer-token
deserializer rejects.

The service enforces a 256 KiB encoded frame limit. MCP adds bounded discovery,
strict argument validation, and output schemas. A well-formed request grants
no command approval. Explicit request metadata `_meta.openai/readOnly=true`
filters discovery to six read-only tools and refuses all four mutations before
service access; Codex filesystem sandbox policy is a separate setting.

Passing records must survive integrity and freshness checks before the engine
derives verification. Full logs are available only through explicit bounded
retrieval. Run summaries omit stdout/stderr payloads. No schema, implementation
claim, or accepted plan supplies permission to execute a check.
