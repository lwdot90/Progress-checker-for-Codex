# Platform development checks and their limits

A bounded development check can provide useful feedback inside the existing
checker sandbox while host-dependent regression execution is being repaired.
It is additional coverage. It must not replace `engineering-unit-tests`, remove
its assertions, relabel its failures, or establish native platform support.
`scripts/check-platform-development.sh` implements the diagnostic subset described
below. This document records scope; it records no test execution or pass.

## Suggested whitelist coverage

| Filter or fixture | What it can establish | What it cannot establish |
| --- | --- | --- |
| `platform::` core unit tests | Parsing, identity fixtures and fail-closed APIs included in the current host's compiled code | Windows/macOS target-only code, native sandbox execution or installation |
| `environment::` fixture tests | RPM/dpkg parsing, mutation detection and cache refusal for supplied temporary inputs | Live Ubuntu package inventory completeness or trusted executable environment |
| `fingerprint::` unit tests | Full-content framing, source mutation detection, explicit input rules and fixture monitor behavior | End-to-end latency or every native filesystem semantic |
| `engine::environment_framing_tests` | Environment identity framing over supplied data | Live trusted environment collection or execution approval |
| Gateway and MCP host unit tests | Host-compatible protocol/stdio and refusal behavior selected by those crates | Full service approval, sandbox execution or native Windows runtime |
| Exact runner sanitizer tests | Known credential normalization, overlap, bounded truncation and terminal escape handling | Actual sandboxed stdout/stderr redaction, descendant containment or arbitrary project-secret discovery |
| Mocked packaging Python tests | Header/version validation and bounded archive refusal logic | Native binary dependency closure, runtime behavior, signed distribution or successful installation |
| Static source/artifact tests | Versions, notices, historical hashes, module/workspace membership and CI declarations | Actual native compiler success or runtime qualification |

Current pure runner cases suitable for exact selection are
`strips_terminal_sequences_controls_and_redacts_secrets`,
`credential_normalization_preserves_newlines_and_removes_controls`,
`overlapping_credentials_do_not_expose_suffixes_or_rewrite_markers`,
`credential_split_at_capture_limit_is_hidden_and_output_stays_bounded`,
`split_utf8_at_capture_limit_cannot_expose_credential_prefix`,
`oversized_output_is_drained_and_bounded`,
`malformed_utf8_cannot_expand_past_the_display_limit`, and
`only_final_trusted_exit_code_confirms_successful_sandbox_launch`.
The async log cases construct in-memory log tasks or bounded duplex streams; they do not launch
approved commands. Use full test paths with `--exact`; broad words such as
`credential` also select the real subprocess test and do not define pure scope.

## Required boundaries

- Source `scripts/prototype-env.sh` before every Rust command. Root runs Cargo.
- Register the development check explicitly in the accepted plan, with its own
  criteria and coverage. Changed argv/config requires the relevant human CLI
  approval; repository instructions do not approve execution.
- Keep the full workspace regression definition and host-dependent assertions
  required. A development pass cannot verify milestones whose criteria include
  actual runner output or approval/service integration.
- Keep `cargo check --workspace --all-targets --locked` on actual Fedora, Ubuntu,
  macOS and native Windows CI runners. Do not exclude the native gateway or
  experimental modules to obtain a misleading workspace pass.
- Print selected filters and resulting test counts. A misspelled filter producing
  zero tests is missing coverage, not a successful tested criterion.
- Distinguish host-independent API fixtures from `cfg(target_os)` tests. Linux
  cannot run Windows/macOS-only assertions merely because the module exists.
- Record blocked/skipped native scenarios explicitly. Do not use WSL as proof of
  native Windows support or mocked receipts as authenticated checker evidence.

The wrapper also invokes pure packaging, Ubuntu/Windows/platform-support,
recipient preparation, gateway stdio and static source artifact Python suites.
These fixture and mock checks do not authenticate external recipient reports.
Its per-filter output guard rejects zero passing tests.

The development wrapper is not qualified by this document. Root reviews its
actual filters, plan binding and output before accepting any result as fresh
evidence. A passing subset retains the full suite and native runtime gaps.
