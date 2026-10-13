The original JSON Schemas describe the Phase 0 embedded panel:

- `progress-panel-config.schema.json` describes `.progress-checker/config.json` and the existing project examples. Execution and fingerprint definitions are validated but remain inert.
- `progress-panel-cached-claims.schema.json` describes the optional sibling `state.json` used by the prototype. It accepts only `planned` and `implemented`; restored claims remain unvalidated with unknown freshness.

Both use JSON Schema draft 2020-12 and reject unknown fields. Rust is the authoritative runtime validator. ID uniqueness, references, milestone dependency cycles, and cached claim ownership are runtime checks. Schema `uniqueItems` compares whole objects; it cannot ensure unique IDs when other fields differ. Both layers require at least one required criterion for every milestone. Missing cached claims default to planned. These schemas do not describe evidence, derived verification results, a checker service, or MCP payloads.

Numeric bounds match the Rust types: positive `u32` parallelism (maximum 4,294,967,295) and positive `u64` timeouts (maximum 18,446,744,073,709,551,615). JSON Schema treats mathematically integral numbers such as `1.0` as integers; the Rust JSON deserializer still requires integer tokens. Nonempty-string patterns use Rust 1.95's explicit whitespace set, and path patterns treat the actual end of a string as a component boundary, including when a filename contains a trailing newline.

Configured working directories and fingerprint patterns must be project-relative and cannot contain parent-traversal components, absolute roots, drive prefixes, or NUL bytes. This is lexical validation. A future execution phase must resolve symlinks against an approved root and enforce its separate trust and sandbox policy before reading inputs or running commands.

The corresponding Rust types and config tests live in `prototype-overlay/codex-rs/tui/src/progress_panel_config.rs` and `progress_panel_config_tests.rs`. The panel tests exercise cached claim restoration and invalid state handling. Schema structure and runtime validation have separate responsibilities; a JSON Schema pass does not approve execution or verify progress.

From the project root, validate both schemas, the shipped fixtures, and negative controls with dependencies kept in project-local `uv` directories:

```bash
UV_CACHE_DIR="$PWD/.local/uv-cache" \
UV_PYTHON_INSTALL_DIR="$PWD/.local/uv-python" \
uv run --no-project --with jsonschema==4.26.0 python scripts/validate-schemas.py
```

The recorded run and control counts are in `.local/bootstrap/schema-validation.log`.

Phase 1 adds `progress-checker-trust.schema.json` for the separately stored exact local approval. Its fixed environment and sandbox profile match `checker-core/src/security.rs`. Unknown fields, alternate sandbox profiles, arbitrary environments, malformed hashes, and relative root/working-directory paths are rejected. Canonical path ownership, executable/bwrap content-hash equality, executable resolution, digest equality, and functioning OS restrictions remain runtime checks. An approval example passing this schema is never permission to execute it.

The fixture in `examples/phase1/approval.example.json` contains placeholder hashes and paths, so runtime authorization must reject it. Schema validation includes Phase 1 controls as well as all unchanged Phase 0 cases.

`progress-checker-result.schema.json` describes the immutable Phase 1 `RunRecord` emitted by the checker. Its `$defs/status` describes the output-only status response; `$defs/evidence` describes the latest evidence embedded in both records. All nested records reject unknown fields. UTC timestamps, hash syntax, terminal outcomes, freshness, integer bounds, and log record shapes are checked. The private authenticated storage envelope is an implementation detail outside this wire schema.

`Status`, `Progress`, and milestone evaluations are output only in Rust. They are never deserialized as persistence or mutation inputs. Even a run record containing `passed` and `current` must pass authenticated-store integrity, newest-attempt selection, log-content hash, command/configuration/environment identity, and freshly recomputed fingerprint checks before the engine derives verification. Schema acceptance alone grants none of these. The illustrative result/status fixtures contain placeholder evidence, never an approved or authenticated run.

Phase 2 adds `progress-checker-service.schema.json`. Its default definition validates the nine Unix-service request operations. `$defs/response` validates the shared versioned response envelope used by Unix IPC and MCP `structuredContent`, with exactly one result or error. `$defs/snapshot` and `$defs/log_page` describe read-only snapshot and paginated log results. Embedded configuration and status definitions are copied from the existing schemas without changing their semantics.

The service enforces a 256 KiB frame limit; schemas validate parsed JSON and cannot enforce encoded byte length. Rust bounds UTF-8 note bytes while JSON Schema counts Unicode code points. Same-user peer authentication, canonical-root binding, response correlation, monotonic service revisions, durable idempotency, approval ownership, and evidence validity remain runtime checks. A well-formed request never grants execution permission. Operation-specific result selection must be checked against the request; the envelope's `result` accepts arbitrary JSON because its shape depends on the operation.

Phase 2 snapshot definitions also include service health, active evidence, and per-check run timing metadata. Separate batch acceptance, batch run-summary, child run-summary, and cancellation definitions describe the service's operation-specific outputs. These are output contracts, not evidence mutation inputs. Validate a captured service smoke report with:

```bash
UV_CACHE_DIR="$PWD/.local/uv-cache" uv run --offline --with jsonschema==4.26.0 \
  python scripts/validate-schemas.py --service-report .local/service-smoke-third/report.json
```

This validates complete IPC envelopes before selecting each nested result definition. The nested status has its own engine revision; it is not the outer service envelope. MCP discovery output-schema validation is separately recorded in `.local/mcp-boundaries-third/output-schema-validation.json`.

Both batch and individual service `GetRun` results exclude stdout/stderr payloads. Their strict summary definitions reject those fields; logs are available only through explicit bounded `GetLog` retrieval. Full immutable run records remain the Phase 1 storage contract. Historical `current_freshness` is derived against the current snapshot and remains separate from the immutable evidence freshness.
