# Progress Checker for Codex

The current goal is native Codex installation: `/plugins` → Add Marketplace → `lwdot90/Progress-checker-for-Codex` → Install Progress Checker, then say “Track this project.” The 0.4 beta and native marketplace are published; native installation passed its published HTTPS trial, and the final human approval trial remains pending. The published 0.3 archive remains available through its [installation guide](../dist/0.3.0-dev/INSTALL.md). The new approval flow keeps Codex and its checker running while you review an exact command in your own terminal.

Historical project-bound release: use the [0.2.1 guide](../dist/0.2.1-dev/INSTALL.md). The prepared archive and `SHA256SUMS` are in `dist/0.2.1-dev/`. Install once for an existing Git project; subsequent standard Codex sessions start the checker automatically. Progress appears through tools and conversation. The embedded panel requires the optional maintained fork.

The historical Progress Checker **0.2.1-dev** release is a local plugin for standard Codex. It provides ten MCP tools, a planning skill, managed project instructions, and automatic checker startup. Ask Codex to propose a plan, record implemented work, or report progress using saved check evidence. There is no persistent progress display in standard Codex; the plugin reports results in the conversation.

The frozen Linux archive completed all eight local delivery milestones on 2026-10-06, including the approved standard Codex workflow. See [PLUGIN.md](../PLUGIN.md#qualification-and-release-status) for the exact archive, historical evidence and coverage limits. Documentation edits can make the repository's earlier evidence stale; ask the running checker for current progress. An independent-computer execution trial and public publication remain separate launch work. This is a development package, qualified locally on Fedora 44 x86_64 with Codex 0.160.0.

The persistent text section below the conversation and `/progress` visibility commands belong to the optional maintained Codex fork, pinned to commit `a956835d020762cb2b570053af06f643a11c0ecc`. The plugin archive contains no Codex executable and needs no recipient Rust installation or source build. The historical checker and fork development records below remain available in [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) and [COMPATIBILITY.json](../COMPATIBILITY.json). Plugin installation and use are covered by the [short guide](../dist/0.2.1-dev/INSTALL.md) and [detailed guide](../plugins/README.md).

The pinned Git checkout, Rust 1.95.0, and local build helpers are installed under `.local/`. The recorded Phase 0 baseline passed real-terminal smoke checks for configured, unconfigured, disabled, and invalid-config launches, resizing with an unsent draft, visibility restoration, and immediate toggle/exit persistence. Upstream Bazel lockfile update/check passed without changing `MODULE.bazel.lock`. Its corrected full TUI run recorded 5,630 passed, four failed, and eight skipped tests; a separate 79-test focused retry closed those four failures. Upstream lint, formatting, rebuilt-CLI smoke, and source/overlay/patch round trips passed for that baseline. The expanded Phase 2 live-service panel has separate terminal and packaging proof below. `upstream-base/` is the verified partial source reference, and `prototype-overlay/` contains modified and new files.

## Phase 1: local verification delivered

Phase 1 is delivered as an independent local Rust CLI. It adds an independent Rust checker for one explicitly approved local command, evidence fingerprints, milestone evaluation, and atomic JSON persistence. Timeout, cancellation, stale-evidence detection, and execution-permission checks passed. The [final Rust run](../.local/bootstrap/checker-tests-final.log) passed all 45 tests (42 core and 3 CLI), [strict Clippy](../.local/bootstrap/checker-clippy.log) passed with warnings denied, formatting checks passed, and the [final checker binary built successfully](../.local/bootstrap/checker-build-final.log). The [final synthetic CLI report](../.local/checker-smoke/final/report.json) passed all 24 assertions across 29 operations, including approval refusal, verification, stale evidence, timeout, cancellation, and corrupt-snapshot recovery. Rust tests additionally cover authenticated-record tamper detection and recovery of interrupted running attempts. Phase 0 remains the validated panel prototype described below. Repository configuration cannot grant execution permission, and opening the panel continues to execute no project checks. Phase 2 adds the shared service and live-panel integration described below; native Codex MCP and final adapter wire acceptance passed.

### Phase 1 execution boundary

The checker targets Linux and uses `/usr/bin/bwrap` with isolated network and process namespaces, a new session without the caller's controlling terminal, read-only `/usr`, an isolated `/proc`, minimal `/dev`, and a temporary `/tmp`. Only the chosen project is writable. There is no unsandboxed fallback: an unavailable or denied sandbox must refuse execution. The command uses an executable-plus-arguments array, with its absolute executable resolving under `/usr`; it does not implicitly invoke a shell. Executable and sandbox binaries must be root-owned regular files, not group/world writable, and at most 64 MiB. A shell explicitly named in the approved argument array may run a project script inside the sandbox. Tool-binary changes require renewed approval.

Local approval binds the canonical project root, exact configuration and command hashes, executable and sandbox-binary content hashes, arguments, working directory, fixed environment, and sandbox profile. Approval comes from a human-facing interactive flow and is stored outside repository configuration. The fixed environment is `PATH=/usr/bin:/bin`, `HOME=/tmp`, and `LANG=C.UTF-8`, without inherited environment variables or the host home directory. Files inside the project—including ignored files containing secrets—remain accessible to an approved command. Approval must disclose that access. A terminal prompt is a frontend safeguard, not proof of human identity: another local process can create a pseudo-terminal. Owner-only trust files also do not protect against another process with the same user ID and direct filesystem access. Agents must not synthesize approval for real projects. Approval does not bind a source fingerprint; source changes invalidate evidence, while the same approved command may be rerun. The [synthetic sandbox probe report](../.local/bootstrap/phase1-sandbox-probes.json) records successful isolation checks: an outside-project marker and host `.ssh` were invisible, `/usr` was read-only, only loopback appeared in the network namespace, and the synthetic project remained writable. These probes created no command approval and ran no repository command. The final runner/core tests passed as part of the 45-test workspace run; the final synthetic CLI acceptance passed.

### Phase 1 command interface

The independent binary is named `progress-checker`. Its commands are:

```text
progress-checker --root /path/to/project validate
progress-checker --root /path/to/project checks
progress-checker --root /path/to/project status
progress-checker --root /path/to/project claim milestone-id implemented --expected-revision N
progress-checker --root /path/to/project approve check-id
progress-checker --root /path/to/project run check-id
```

`validate`, `checks`, and `status` execute no configured command. Claims accept `planned` or `implemented`; verification is derived from evidence. `claim` requires the revision returned by `status` to prevent lost updates. `approve` displays the exact binding and requires an interactive terminal plus the exact phrase `approve check-id`; it has no automatic yes flag. `run` waits for the result, and Ctrl-C requests cancellation. JSON is the machine-readable output. A completed failing check is a successfully retrieved result (exit 0), while operational errors exit 1 and argument errors exit 2. In the current Phase 2 binary, `status`, `claim`, and `run` attach to the running service. `validate`, `checks`, and `approve` require its exclusive writer lock, so perform them while the service is stopped.

By default, private state and approvals live under `$XDG_DATA_HOME/progress-checker`, or `$HOME/.local/share/progress-checker` when XDG is unset, in a directory keyed to the canonical worktree. `--state-dir /absolute/private/base` overrides that base. The base must stay outside the project so an approved command cannot rewrite its own trust or verification records. The local wrappers are available for building, testing, and running the independent workspace (final Rust tests, strict lint, formatting, and synthetic CLI acceptance passed):

```bash
bash scripts/build-checker.sh
bash scripts/test-checker.sh
bash scripts/run-checker.sh --root /path/to/project validate
```

They reuse the project-local Rust toolchain and keep checker build output in `.local/checker-target`. The run wrapper preserves the caller's working directory. The delivered Phase 1 interface was a separate CLI contract. In Phase 2, these wrappers use the shared service; the embedded panel displays its current verification when launched with that service’s socket.

The Phase 1 wire contracts are [the trust schema](../schemas/progress-checker-trust.schema.json) and [the result/status schema](../schemas/progress-checker-result.schema.json). [Illustrative examples](../examples/phase1/README.md) contain placeholder paths and hashes; they grant no execution permission and are not verification evidence. Runtime checks recompute verification from authenticated stored attempts, log hashes, exact definitions, and fresh fingerprints. Editing a JSON result or claim to say `verified` cannot establish verification. Actual generated smoke artifacts also [passed schema validation](../.local/bootstrap/schema-actual-e2e-final.json): 18 status outputs, 8 immutable run records, 8 decoded log results, and 8 start-evidence records, with zero errors.

### Independent checker demo

Once the checker binary is built, run this from an interactive terminal:

```bash
python3 scripts/demo-checker.py
```

The demo creates a fresh Git fixture and separate private state under `.local/checker-demo/session-*`. It displays the exact `/usr/bin/python3 check.py` sandbox approval for you to review. To approve this isolated fixture command, type `approve demo-check` at its prompt. It starts one service, records two implementation claims, and expects the passing check to verify both milestones. Edit the fixture's `feature.txt`, then run the printed status command to see evidence become stale. The files and evidence remain available for review. The current demo leaves its service running and prints its PID and stop command; stop it after reviewing staleness. Use the Phase 2 demo below to open the embedded panel. The user exercised the earlier Phase 1 interactive demo: a passing check verified both milestones, and editing the same fixture changed freshness to stale and verification to 0/2. This is human-reported evidence, separate from automated reports.

## Phase 2: shared service and panel integration delivered

Phase 2 delivers one local service writer shared by the embedded panel and a root-bound MCP STDIO adapter using protocol version `2025-06-18`. Both clients consume the same revisioned evidence. The service queues previously approved checks; startup executes no configured project command. MCP cannot create command approvals or widen the approved execution boundary.

The frozen pre-plugin checker workspace passed all **77 tests** (3 CLI, 56 core, 10 MCP, and 8 service), with zero failures or ignored tests, in [.local/bootstrap/checker-optimized-native-tests.log](../.local/bootstrap/checker-optimized-native-tests.log). [Strict lint](../.local/bootstrap/checker-optimized-native-clippy.log), [formatting](../.local/bootstrap/checker-optimized-native-fmt.log), and [checker/service/MCP builds](../.local/bootstrap/checker-optimized-native-build.log) passed. The expanded [Codex TUI full run](../.local/bootstrap/phase2-tui-full-final.log) recorded **5,651 passed, one timed out, and eight skipped**. That unchanged question-layout test passed in a separate [isolated retry](../.local/bootstrap/tui-question-focused.log) in 13.937 seconds under the same 60-second deadline. All 5,652 executed cases have therefore passed across the two runs. Final Codex lint, formatting, and the rebuilt CLI passed. The [two-terminal report](../.local/phase2-terminal/20261003T085132Z-184430/report.json) passed 11 assertions with zero provider requests, including matching panel/MCP snapshots, responsive unsent drafts during an approved synthetic check, resize/hide/show, scrollable details/logs, source staleness, and service loss. Both windows shared one writer. The [artifact receipt](../.local/bootstrap/phase2-artifact-identity-final.json) binds that tested Codex binary to the unchanged source and patch.

The [optimized service run](../.local/service-optimized/report.json) passed all **25 assertions**; [freshness controls](../.local/freshness-optimized/report.json) passed six. Their 240 actual envelopes passed schema validation. On the documented Fedora Linux machine (Intel Core i5-8265U, 8 logical CPUs, 7,761,784 KiB RAM), 20 warm fixture samples measured snapshot-read p95 at **19.798 ms** and accepted-run-start p95 at **42.850 ms**, below 250 ms. These service reports capture the final CLI and an earlier MCP adapter; final native/wire reports below independently validate the final adapter. The [earlier run under concurrent load](../.local/project-final-service/report.json) failed the target at 349.158 ms accepted-start p95 and is retained. These warm fixture measurements are separate from the full-source pilot below; cold startup and arbitrary projects have not been benchmarked.

Final-binary [IPC security checks](../.local/ipc-final3/run-b3sf7kf2/report.json) passed six groups. [MCP boundary/schema checks](../.local/mcp-final3/output-schema-validation.json) passed 26 assertions and validated 14 actual tool results. [Oversized-response checks](../.local/mcp-large-final3/output-schema-validation.json) passed two assertions and validated a bounded error that preserved the RPC ID and kept the STDIO session usable. [Native metadata controls](../.local/mcp-native-final/output-schema-validation.json) passed five assertions and validated four results. That frozen adapter returns all eight tools by default; only explicit request metadata `_meta.openai/readOnly=true` filters discovery to five tools and denies the three mutations before service access. Codex’s filesystem sandbox setting does not itself set that metadata. The frozen [batch probe](../.local/batch-final3/run-cu6q9sqn/report.json) passed three sequential execution/idempotency controls. The [frozen native Codex demo](../.local/demo-phase2-acceptance/success-report.json) connected all eight tools and passed its 60-second quiet run. The full evidence matrix is [.local/bootstrap/phase2-acceptance.md](../.local/bootstrap/phase2-acceptance.md).

### Launch the maintained-fork panel with an explicit service

This development workflow uses an explicitly started service for the maintained-fork panel. The native plugin’s automatic launcher and installer are described in [PLUGIN.md](../PLUGIN.md). The service is hosted by the trusted checker CLI. Build it, validate the chosen Git project's configuration, and review each configured command before starting the service. Approval is an interactive human action and is bound to the selected root and private state base:

```bash
bash scripts/build-service.sh
bash scripts/run-checker.sh --root /absolute/project --state-dir /absolute/private/state validate
bash scripts/run-checker.sh --root /absolute/project --state-dir /absolute/private/state checks
bash scripts/run-checker.sh --root /absolute/project --state-dir /absolute/private/state approve check-id
bash scripts/run-service.sh --root /absolute/project --state-dir /absolute/private/state
```

`serve` stays in the foreground and prints a readiness JSON line to stderr containing `socket` and `service_instance_id`. Keep it running. In another terminal, supply that exact socket to the modified Codex panel:

```bash
PROGRESS_CHECKER_SOCKET="/absolute/private/state/ipc-...sock" \
  scripts/run-prototype.sh --cd /absolute/project
```

Without `PROGRESS_CHECKER_SOCKET`, the panel shows its cached unvalidated claims. Selecting a socket enables the shared-service view; a lost connection displays unavailable status without converting cached claims into verification. Panel launch executes no configured check.

The MCP adapter attaches to the same service. For direct STDIO clients, start it with the same root and state base:

```bash
bash scripts/run-checker-mcp.sh --root /absolute/project --state-dir /absolute/private/state
```

For the direct MCP development workflow, add this entry to `config.toml` in the selected `CODEX_HOME` (the run wrapper defaults to `.local/codex-home`). Replace the three absolute paths with this checkout, the chosen project, and its private state base:

```toml
[mcp_servers.progress_checker]
command = "/absolute/progress-checker/scripts/run-checker-mcp.sh"
args = ["--root", "/absolute/project", "--state-dir", "/absolute/private/state"]
```

The MCP configuration and panel socket must target the same service. MCP startup creates no approval and runs no check. Use `status` for the current revision, then `claim` or an explicitly approved `run` while the service remains active.

Historical run retrieval preserves the original immutable evidence, including the freshness recorded when that evidence was produced. Use the returned `current_freshness` to judge a retrieved run now; do not interpret historical `evidence.freshness: "current"` as current verification. The shared progress snapshot remains the authority for today’s verified milestone count.

The isolated human demo is `python3 scripts/demo-phase2.py`. It requires built checker/service/MCP and modified Codex binaries: run `bash scripts/build-service.sh` and `bash scripts/build-prototype.sh` first. It presents the exact synthetic fixture command for interactive approval, starts the service, runs the approved fixture check, and opens the live panel with an explicit MCP configuration in a fresh Codex home. Edit its printed `source.txt` in another terminal to test stale evidence, and use `/progress` and `/quit` to test the panel. The [frozen native demo receipt](../.local/demo-phase2-acceptance/success-report.json) passed with running-process and after-run receipts for the final CLI, MCP and Codex binaries. All eight MCP tools connected; a 60-second quiet run had no unavailable frames, startup errors or provider requests. Details/log pagers closed with `q`, `/quit` exited 0, and no service/MCP processes or sockets leaked. The [approval-cancel control](../.local/demo-phase2-acceptance/cancel-report.json) exited 1 without leaks. [Earlier attempts](../.local/demo-phase2-acceptance/history.md) retain the corrected metadata defect and an unexplained transient EAGAIN unavailable frame; the successful quiet run does not establish availability under arbitrary load. The [named checker demo](../.local/demo-checker-final3/report.json) separately passed interactive synthetic approval, source-stale status, and its printed stop command against the final CLI.

## Phase 3: representative project pilot passed

The authorized pilot uses a disposable Git copy of the actual project files. Its [configuration](../examples/pilot/config.json) maps two milestones to baseline Git-blob validation and exact combined/staged patch round trips, with an explicit dependency between them. The [pilot instructions](../examples/pilot/README.md) and `scripts/pilot-project.py` define failure controls, performance observations, restart recovery, and rollback checks. The [actual pilot report](../.local/pilot-optimized/report.json) passed all **31 assertions** against 235 source files totaling 4,917,632 bytes. Both real checks passed; corrupting a tracked patch or upstream baseline immediately removed verification and made the corresponding real verifier fail. Exact restoration required new passing checks, and restarting restored durable current evidence under a new service identity. [Run evidence](../.local/pilot-optimized/run-evidence.json) summarizes 28 immutable attempts without exporting private trust keys. Twenty warm samples per operation measured snapshot-read p95 at **62.227 ms** and accepted-run-start p95 at **128.982 ms**, below the 250 ms target on this machine. The [first unoptimized pilot](../.local/pilot/report.json) failed the read target at 547.741 ms and is retained. Optimizing SHA-256 in the development profile resolved that measured bottleneck; fingerprints still read fresh source bytes. Cold starts, other machines, and future upstream upgrades remain unqualified.

Luis owns maintenance of this local project. Updating the pinned Codex revision requires a separate candidate checkout, verified baseline and helper pins, refreshed patches, the applicable upstream build/test/lint/format workflow, and repeated service/MCP/terminal acceptance before switching binaries. Keep the previous tested binaries, patch set, and private evidence for rollback. Stop the foreground service before changing checker binaries. From this project's root, review reverse application before reverting a source patch:

```bash
git -C .local/source/codex apply --reverse --check "$PWD/patches/codex-progress-panel.patch"
```

Switching or reversing source does not replace an already compiled executable. Evidence must be revalidated under the selected checker version. This records local responsibility and an upgrade workflow without promising ongoing upstream compatibility.

## Prepare locally

This workspace is already prepared. Skip the bootstrap and use the local environment below. For a fresh copy with no `.local/source/codex`, run setup explicitly from this directory:

```bash
bash scripts/prepare-prototype.sh
```

The [independent fresh setup report](../.local/bootstrap/fresh-prepare-report.json) passed pinned-source, 68-file overlay, actual local Rust/helper installation, and safe repeat-refusal checks. Immediate before/after setup snapshots of home settings matched. This exercised setup only; an independent fresh build and test run was not performed. A later unrelated Codex settings change is recorded separately in the report.

The script fetches the exact upstream commit into a detached Git checkout, verifies its baseline files using their recorded Git blob hashes, and checks and applies `patches/codex-progress-panel.patch`. It verifies Rustup's installer against the official companion SHA-256 file before execution, then installs Rust and checksum-pinned prebuilt helpers locally: `just` 1.58.0, `cargo-nextest` 0.9.146, DotSlash 0.5.9, and Bazel 9.0.0. It refuses to replace `.local/source/codex`, changes no global settings or shell startup files, and runs no helper compilation, Codex build, or project checks. `curl`, `git`, and Python 3 are required; the upstream formatter also needs `uv` (already available here).

The combined patch includes a release lockfile repair: 159 local workspace package versions change from `0.0.0` to `0.160.0`, matching this release's manifests. External dependency versions remain unchanged. Keeping real Git metadata is required for upstream formatting and source verification.

For review, the patch is split into seven stages under `patches/`: `00-release-lockfile.patch`, `01-claim-schema.patch`, `02-service-client.patch`, `03-log-details.patch`, `04-embedded-panel.patch`, `05-panel-regression-tests.patch`, and `06-integration-regression-tests.patch`. Apply these in numeric order when using the split patches; the setup script applies the combined patch once. The [final packaging report](../.local/bootstrap/phase2-packaging-final.json) passed exact combined/staged application and reversal, independent-copy round trips, and live parity for 79 immutable baseline blobs and 68 overlay files. Each of the seven stages has fewer than 800 changed lines.

Verify the combined and staged patch round trips without downloading source or installing Rust (Python 3.11+ and Git required):

```bash
python3 scripts/verify-patches.py
```

Use the installed toolchain and caches, then follow the upstream validation workflow from this directory:

```bash
source scripts/prototype-env.sh
just --justfile .local/source/codex/justfile fmt
scripts/build-prototype.sh
scripts/test-prototype.sh
just --justfile .local/source/codex/justfile fix -p codex-tui
just --justfile .local/source/codex/justfile fmt
scripts/bazel-lock-prototype.sh
```

The environment script keeps Rust, helper binaries, dependency caches, and build output under `.local/` (the configured `.local/uv-python` path is optional and unused here), uses one compiler job with debug symbols and incremental compilation disabled, and the test wrapper defaults to two test threads. Set `PROTOTYPE_TEST_THREADS` to override that count. The test wrapper clears `NO_COLOR` for upstream tests that assert ANSI bytes. The wrappers accept additional nextest or Cargo arguments. Build the CLI before the full TUI suite because some upstream terminal tests require its executable. The Bazel wrapper runs upstream `just bazel-lock-update` and `just bazel-lock-check` from the pinned checkout with caches under `.local/bazel`; this gate is required because the patch repairs `Cargo.lock`. Its completed result is in [.local/bootstrap/bazel-lock.log](../.local/bootstrap/bazel-lock.log), and `MODULE.bazel.lock` remains byte-identical to upstream. Review any missing upstream prerequisites reported by these commands. The historical Phase 0 corrected full run plus focused retry closed its failures; the expanded Phase 2 full run plus unchanged isolated retry is recorded above; final upstream lint/format and artifact checks passed. The final rebuilt CLI smoke checks also passed. Once tests pass, the upstream instructions say to run `just fix`, then format, and avoid rerunning tests solely after formatting or lint fixes.

## Try the built panel

Copy `examples/prototype/.progress-checker/` into the root of a Git repository you choose for the demo. From this project's root, launch the modified binary with that repository as its working directory:

```bash
scripts/run-prototype.sh --cd /path/to/chosen/git/repository
```

The run wrapper defaults Codex's data directory to `.local/codex-home`, unless you explicitly provide `CODEX_HOME`. No installed authentication is copied. If the chosen provider needs authentication, sign in locally with `scripts/run-prototype.sh login` before launching it.

The Phase 0 fixture reads the nearest opted-in configuration within that worktree and restores sample claims as **unvalidated**, with **freshness unknown**. Phase 2 connects the panel to the service’s verified snapshot when its socket is supplied, as shown above. `/progress` toggles visibility, `/progress details milestone-id` opens milestone criteria, and `/progress log check-id` opens a bounded log pager. The pagers use Page Up/Down to scroll and `q` to return to the composer. Visibility is saved per canonical configuration in the selected Codex data directory. Narrow terminals show a compact summary. A repository without an opted-in configuration has no panel.

The sample Cargo commands are illustrative and are not executed on launch. Phase 0 cached claims live in `state.json`, separate from milestone definitions in `config.json`. The shared service owns verification records and command execution; the panel consumes its snapshots. Commands require separate exact local approval. Completed acceptance and the remaining compatibility limits are recorded in [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) and [COMPATIBILITY.json](../COMPATIBILITY.json).

The Phase 0 file contracts are described by [the config schema](../schemas/progress-panel-config.schema.json) and [the cached-claims schema](../schemas/progress-panel-cached-claims.schema.json). The Rust parser also checks references, duplicate IDs, and dependency cycles; these schemas contain no verification evidence or result format.

## Offline terminal demo

After building the modified binary, review it in an interactive terminal without signing in:

```bash
python3 scripts/demo-prototype.py
```

This creates an isolated Git fixture with the three sample milestones: two implemented claims and one planned claim, all unvalidated. Its project, Codex settings, visibility preference, and report stay under `.local/demo/`. Use `/progress` to hide/show, resize the terminal to inspect the compact panel, and use `/quit` to exit. A localhost mock provider rejects model inference; no login is copied and no configured project commands run.

For automated terminal checks without signing in or making model inference requests, keep using the local smoke test:

```bash
python3 scripts/smoke-prototype.py \
  --binary .local/source/codex/codex-rs/target/debug/codex
```

It uses a localhost mock provider and checks configured, unconfigured, and invalid-config launches, resize behavior, hide/show, restored visibility, and that configured project commands remain unexecuted. By default, isolated fixtures, Codex homes, terminal transcripts, screen captures, and `report.json` stay under `.local/smoke/`. The script runs the already built binary; it does not build or install anything.

The final smoke run against the rebuilt binary is recorded in [.local/smoke/20261003T085338Z-185608/report.json](../.local/smoke/20261003T085338Z-185608/report.json). The matching [artifact receipt](../.local/bootstrap/phase2-artifact-identity-final.json) records Codex 0.160.0, with SHA-256 `acf22cecb034c821a90a53f3007395b2ddc747c40f55e8724d1dadfd30d86734`. Its [wide capture](../.local/smoke/20261003T085338Z-185608/opted-in/first-launch/wide-panel.txt) and [narrow capture](../.local/smoke/20261003T085338Z-185608/opted-in/first-launch/narrow-panel.txt) show the panel inside the actual modified Codex TUI. All four launch cases and the rapid-exit persistence diagnostic passed, with no configured check executed and no model request. The rapid-exit diagnostic disables Codex's paste-burst heuristic so immediate synthetic Enter presses are dispatched as commands; ordinary launch checks use the normal input setting. These startup observations do not establish the later checker performance targets.

The prepared checkout and independent fresh setup passed the recorded gates; independent fresh compilation and tests remain unperformed. Local maintenance belongs to Luis, with the pinned-upgrade and rollback workflow above.
