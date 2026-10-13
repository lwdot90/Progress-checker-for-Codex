# Native platform compile gates

The `Native platform compile gates` workflow compiles the entire workspace,
including test targets, on Fedora 44, Ubuntu 24.04, macOS ARM64 (`macos-15`), and native
Windows x86_64 with MSVC. Windows runs on `windows-2022`; it does not use WSL.
The Fedora job uses a Fedora container on a Linux runner.

The logs report the runner architecture, Rust host triple, compiler version,
and Cargo version, and explicitly state that compilation is not runtime support.
Modules wired into the workspace library are included in the full workspace
compile, including native platform implementations guarded for that target.
Unreferenced prototype files are not compiled; they must be wired into the
library before their implementation can receive a compile result.

Each job is a required engineering signal: compilation errors fail the job.
There is no `continue-on-error`, no placeholder success for missing backends,
and no reduced Windows target that hides a failing service or CLI. Matrix jobs
continue independently so one failure does not prevent results from the others.

## What the workflow establishes

A passing job establishes that the checked-out source compiles on the listed
runner and toolchain. It does not establish that command isolation, executable
trust, private state permissions, human approval, IPC authentication, or
installation work correctly. No supported-platform or release claim should be
made from compilation alone.

The workflow does not execute tests or configured project checks. Runtime
qualification requires an approved, separate procedure on each platform,
including adversarial checks against the native isolation and private state
implementations. A Fedora container compile is also not a replacement for the
existing clean-recipient Fedora runtime qualification.

## Current gaps and qualification

This workflow is newly prepared; no remote run result has been observed here.
At preparation, core security and plan persistence still contained Unix-specific
interfaces, while the runner used Linux bubblewrap. Native platform backends
are being developed separately. A failing macOS or Windows job is an exposed
porting gap, not an unexpected release regression. Do not mark these platforms
supported until the full native runtime and installation criteria pass.

Ubuntu additionally needs its package inventory provider and actual bubblewrap
execution qualified. macOS needs native isolation and executable identity
qualification. Native Windows needs its native sandbox, filesystem/ACL trust,
authenticated IPC, inventory, and packaging qualified. WSL results cannot satisfy
the Windows job or Windows acceptance criteria.

## Toolchain and reproducibility

Every Rust command sources `scripts/prototype-env.sh`; Rust and Cargo state stay
under the checkout's `.local` directory. The jobs use `--locked`, so dependency
resolution cannot silently alter `Cargo.lock`. The workflow reads the exact compiler version from `rust-toolchain.toml`
(currently 1.95.0), and asserts the native Rust host triple for each job. This
compiler pin does not establish a minimum supported Rust version or pin the
entire hosted runner image. The Python gateway sources receive syntax compilation
only; no gateway process is started.

Runner labels and architecture were checked against [GitHub’s hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Windows diagnostic artifact for a recipient

After its strict native compile gate succeeds, the Windows job builds the CLI,
MCP adapter and Rust gateway as debug `.exe` files. It executes none of those
binaries in CI. The uploaded `windows-native-debug-COMMIT` artifact contains
`bin/`, a reviewed PowerShell collector, and `artifact-manifest.json` recording
the full source commit, Cargo.lock SHA256, version, target, profile and exact
SHA256 values for every supplied payload file (the manifest itself is excluded
from its recursive file map). Root and dependency license notices, the complete
existing third-party license inventory/material, and the recipient guide are
included. Only the fixed three executables are candidates for metadata probes. It is a CI diagnostic artifact, not a release, installer,
supported platform claim or evidence of passing native execution checks.

The recipient needs no Rust compiler, Python, Visual Studio or SDK to inspect
this artifact and run the collector. The separate Windows recipient guide
explains the bounded metadata smoke procedure. Runtime qualification remains
outstanding after successful version output.

Uploads fail if files are missing and expire after 14 days. Checkout and upload
actions are pinned to reviewed commit IDs from their official `v4` tags.
Artifact behavior follows [GitHub's artifact documentation](https://docs.github.com/en/actions/tutorials/store-and-share-data)
and [the official upload action](https://github.com/actions/upload-artifact).

The Windows diagnostic build alone uses `-C target-feature=+crt-static` with the
explicit MSVC target, following [Rust's C runtime linkage reference](https://doc.rust-lang.org/reference/linkage.html).
The exact flags are recorded in the manifest. Static CRT linkage reduces the
Visual C++ runtime deployment dependency; it does not establish a complete DLL
closure, eliminate Windows system DLL dependencies, or qualify the executable.
The earlier workspace compile gate retains its normal compilation flags.

Before upload, Windows PowerShell parses the collector without invoking it,
extracts only its literal embedded CSharp source from the AST, and compiles that
source to a DLL. It does not evaluate script expressions, call probe methods,
create a child process, or run the collector. This compilation does not qualify
its native runtime behavior. Pushes to feature branches also receive these
compile/build gates and diagnostic artifacts.

## Retrieve a Windows diagnostic artifact when CI has produced one

No artifact download or successful native workflow run is asserted by these
instructions. The owner should complete the steps below once the reviewed
feature branch has run in GitHub Actions.

1. Open the repository's [Actions page](https://github.com/lwdot90/Progress-checker-for-Codex/actions)
   and select **Native platform compile gates**. Select the push run for
   `native-platforms-0.5`, or the manually requested run for that branch, at the
   exact reviewed source commit. Read the full 40-character commit SHA; branch
   names alone are insufficient because they can move.
2. Open **Compile / Native Windows x86_64 MSVC**. Confirm that the strict compile,
   native build, collector compilation, artifact preparation and upload steps
   all succeeded. A missing or failed upload means no bundle is ready to share.
   This checks build provenance; it does not qualify native runtime support.
3. Return to the run summary and download the artifact named
   `windows-native-debug-FULL_SOURCE_COMMIT`. GitHub artifact downloads may
   require signing in. Artifacts expire after 14 days; use a new reviewed run if
   the artifact has expired. Do not substitute a similarly named release archive.
4. Inspect the downloaded ZIP and `artifact-manifest.json`. Its `source_commit`
   must equal the full reviewed run commit and artifact suffix. Its status must
   say **unqualified diagnostic build; not a supported release**, with
   `runtime_tests_executed: false` and
   `complete_dll_closure_qualified: false`. Compare the manifest file hashes to
   the extracted payload, including the collector and license material.
5. Calculate the ZIP's SHA-256 and supply it separately with the exact commit and
   ZIP when inviting the recipient. For example, in PowerShell:

   ```powershell
   Get-FileHash -Algorithm SHA256 -LiteralPath .\windows-native-debug-COMMIT.zip
   ```

   Use the actual downloaded filename. A checksum supplied through the same
   untrusted channel as a modified ZIP is not independent provenance.
6. Send the recipient the included `WINDOWS_FRIEND_TRIAL.md` guide and label the
   ZIP **unqualified native Windows diagnostics**. The bounded version collector
   is the first smoke procedure; installation, approval and check execution
   remain blocked and are not part of this invitation.

The owner should retain the actual Actions run URL, commit SHA, artifact name and
ZIP checksum with the recipient feedback. Avoid recording a fictional artifact
URL before the workflow has completed and the artifact is available.
