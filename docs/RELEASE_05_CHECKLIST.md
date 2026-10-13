# 0.5 candidate release checklist

0.5.0-dev is a source candidate. Installed 0.4, its marketplace payload and all
older frozen archives keep their identities. This checklist does not establish
Windows, Ubuntu or macOS support. Each platform must qualify its own package
and security implementation; a Linux run cannot verify another platform.

## Before freezing a candidate

- Resolve the configured regression-suite sandbox/host mismatch without making
  security tests pass by disabling isolation or fabricating approval.
- Record fresh passing checker evidence against the final source fingerprint.
  User-reported host passes are useful diagnostic observations, not equivalent
  to configured checker evidence.
- Build with the project-local toolchain; regenerate notices if the lock changes.
  Packaging must reject binaries whose version differs from source/manifest.
- Package into a new candidate directory. Compute its SHA-256 and freeze these
  bytes under a new identity; never overwrite 0.2.1, 0.3 or 0.4 artifacts.
- Register a candidate-specific check with an immutable archive identity and
  recipient job identity, then obtain exact human CLI approval. Keep older check
  definitions intact. The root agent submits this scope addition through the
  running checker using current revision/config hash.

## Static artifact check

`scripts/check-release-candidate.py --archive PATH --sha256 HASH --version 0.5.0-dev`
checks the archive identity, safe unique paths, exact file checksum coverage,
required files, manifest/inventory version and executable bits, and retained
historical archive hashes. It does not extract or execute the package and cannot
prove binary version, installability, startup or sandbox behavior. Run it only
through the configured, human-approved candidate check when used as acceptance.
The source packaging guard separately checks built binary versions.

## Recipient runtime qualification

Use an isolated standard Codex profile and a separate ordinary Git worktree on
an explicitly supported recipient. Make the source checkout and Rust unavailable
to the installed runtime. Keep a second unrelated project's records/settings to
check preservation. Record exact OS/architecture, Codex version, candidate hash,
plugin-cache identity and CLI/MCP versions. Capture public tool receipts and
sanitized logs, never private grants or evidence databases.

| Step | Action | Required observation |
| --- | --- | --- |
| Install | Install the separately pinned candidate through the native custom marketplace/browser | Skill and expected tools load; no source/Rust dependency; no check runs or implicit grants on startup |
| Track | Activate the recipient worktree; repeat with a concurrent session | Both roots are explicitly correct; one writer for the same root; existing config/instructions preserved |
| Refuse | Request a configured check before approval | No execution; actionable human approval instruction; normal Codex prompts still work |
| Approve | Human uses the packaged CLI in a separate interactive terminal while Codex remains open | Exact argv/root/config shown; only the human confirms; agent never supplies confirmation |
| Pass | Run that check through the same open MCP session | Fresh passing evidence verifies only covered claimed criteria; read-only callers cannot mutate |
| Stale | Edit a tracked source file without changing the check definition | Old evidence becomes stale; unchanged command grant remains reusable |
| Fail | Run against deliberately broken code | Failing output is recorded; no verified completion; secrets covered by redaction policy absent from logs |
| Restore | Repair the code and run again | New current pass replaces failed/stale status honestly |
| Revise | Change the configured check through an accepted plan revision | Old exact-command grant invalidated; unapproved revised command refused |
| Restart | Close/restart service and reconnect installed plugin | Claims and evidence retained, writer identity renewed, no checks run automatically |
| Separate | Track a second project and request cross-root mutation | Separate claims/evidence; immutable connection cannot switch roots |
| Update | Upgrade an isolated installed 0.4 profile to the candidate | Settings, both project records, state binding and managed instructions preserved; no startup checks |
| Remove | Remove only the candidate plugin | Unrelated settings and project evidence remain; plugin no longer discovers; no orphan writer claim without observation |

Exercise missing/noninteractive confirmation, expired/reused approval challenges,
wrong-project approval and unavailable checker as separate negative cases. Run
these through existing reviewed live-acceptance machinery where applicable;
never alter private grants to simulate results. If the recipient prevents nested
sandboxes, report that limitation and qualify actual approved execution on a
recipient with the required sandbox facilities rather than weaken the runtime.

## Release decision and remaining user work

Root reviews all receipts and current progress, publishes the new immutable
payload/catalog/archive only after qualification, and changes installation
instructions to its actual pins. Keep 0.4 instructions until then. Archive
inspection alone is insufficient. A consenting unfamiliar user's actual trial
and feedback remain a separate tracked milestone; do not invent a participant.

### Root next actions

1. Register candidate-integrity and recipient-runtime milestones/checks without
   changing frozen release bindings; obtain the required human approvals.
2. Resolve regression execution and finish platform-specific implementation.
3. Build/package candidate bytes and add their explicit identity to the plan.
4. Execute the static check and the recipient matrix, review receipts, then
   record implementation claims and current verification separately.
5. Publish only qualified targets and list remaining targets as unsupported.

## Regression and observation artifacts

`scripts/test-native-packaging.py` contains host-independent image/header,
mocked native version output, wrong-host refusal and static archive safety
regressions. No test launches a native binary. Root can include it in a reviewed,
exactly approved configured regression command; its presence is not a pass.

[`platform-qualification.schema.json`](../schemas/platform-qualification.schema.json)
bounds public platform receipts. Schema conformity does not authenticate a
report or grant approval. The configured collector must validate original
receipts and exact job/runtime identities before the checker records evidence.

### Proposed source/artifact regression command

Root may register `/usr/bin/python3 scripts/check-native-source-artifacts.py`
with repository cwd and a 120-second timeout as a separate static check, or add
it to the reviewed engineering wrapper and obtain the approval required by the
changed definition. It checks source/manifest/notices agreement, retained frozen
archives, native gateway workspace membership, all-target native compile gate
coverage and declared experimental modules. It never builds or runs primitives.

Keep `cargo check --workspace --all-targets --locked` in each actual native CI
job; static declaration checks cannot prove target-specific code compiles.
Do not exclude unsupported platform primitives or the gateway to manufacture a
passing full-workspace claim. Native runtime qualification remains separate.
