# Native macOS engineering status

Native macOS is **not qualified or released**. The supported published plugin
remains the existing Linux release. Do not install an experimental artifact as
though its sandbox and approval flow have been verified.

## Implemented boundaries and remaining execution blockers

The native compile workflow runs `cargo check --workspace --all-targets` on a
macOS runner. It is a compile gate, not native runtime evidence. The source has
macOS same-user Unix-socket authentication through `getpeereid`, runtime identity
collection and sandbox profile/probe scaffolding. These components do not form
a qualified end-to-end execution backend yet.

The service permits ordinary same-user messages, but grants **no macOS approval
authority** from `getpeereid`: a UID does not identify the CLI image, process
lifetime or human terminal. A native approval broker must establish those
identities before challenge/commit can be enabled. Current approval and runner
paths fail closed on macOS.

Sandbox inheritance also does not establish cleanup. A descendant can detach
from the process group; proving inherited access restrictions is separate from
proving every descendant terminates on timeout, cancellation or gateway exit.
Detached-child lifetime containment remains an execution blocker. No unsandboxed
fallback is provided.

## Artifact preparation

`scripts/package-macos.py` prepares architecture-specific experimental archives
on a native macOS host. It accepts `aarch64-apple-darwin` (Apple silicon) and
`x86_64-apple-darwin` (Intel), requires thin Mach-O binaries matching that host,
and checks both executable versions against Cargo and the plugin manifest.
It preserves the frozen published payload. Existing package directories and
archives are refused rather than replaced.

Prerequisites are Git, Python **3.11 or newer**, matching native Rust-built
executables, and current dependency notices. Python's exact absolute path is
written into the staged wrapper shebangs; the same path must exist on recipients.
macOS's bundled Python is not an established prerequisite. Relocatable Python
discovery still needs a recipient installer design.

The wrapper's Python launch dependency is separate from check-executable trust:
an explicit Homebrew Python path in a shebang does not make that interpreter an
approved check executable. The experimental inventory permits root-owned system
paths only. Packaging preflights root-owned, non-writable, content-readable
`/System/Library/CoreServices/SystemVersion.plist` and `/usr/lib/dyld` and records
their hashes. Missing identities fail closed; native evidence has not established
that the loader path exists on every target OS or that this identifies complete
dependency closure.

The compile workflow now installs the Rust version pinned in
`rust-toolchain.toml` (**1.95.0**), rather than floating `stable`. The current
license inventory records `1.95.0-x86_64-unknown-linux-gnu` Rust standard-library
material. Matching the version and Cargo lockfile does not establish macOS target
provenance: capture the actual native compiler/target, linker and standard-library
inputs, and regenerate/review appropriate license inventory before distribution.
The package guards validate existing notice hashes; they do not attest which
compiler or libraries produced supplied Mach-O binaries.

After building on a native host with the project-local Rust environment:

```bash
python3 scripts/package-macos.py \
  --target aarch64-apple-darwin \
  --binary-dir .local/checker-target/aarch64-apple-darwin/release \
  --python /opt/homebrew/bin/python3
```

For an Intel host select `x86_64-apple-darwin` and its actual Python path.
This command is artifact preparation, not an installation recommendation.

## Required qualification before user installation

- Compile and exercise the native process, IPC, filesystem and sandbox backend.
- Establish a minimum macOS version for each architecture and record native
  build provenance. Dependency license inventory must match that build.
- Prove sandbox-denied access to private approvals/state, home secrets and
  networking; check cancellation, timeouts, symlinks and executable identity.
- Exercise fresh installation, tracking, exact human approval, stale evidence,
  restart, updates and removal on clean recipient accounts.
- Replace Linux package inventory assumptions with explicit macOS dependency
  identities; do not report missing RPM as a successful inventory.
- Decide Developer ID signing and notarization before distributing broadly.
  These experimental archives are unsigned and unnotarized. Do not instruct
  users to disable Gatekeeper to conceal missing release qualification.

No native macOS host was used to qualify this packaging implementation. It
intentionally rejects Linux-host packaging and mismatched executable formats.

## Helper signing preparation

`scripts/prepare-macos-helper.py` accepts an existing canonical helper bundle,
explicit runtime files, reviewed signing identifier/team and certificate hash.
It generates deterministic child entitlement bytes and a JSON signing plan
containing exact command argument arrays. It never invokes `codesign`, launches
the helper or claims a verified signature. The two child sandbox keys follow
[Apple's sandbox inheritance requirements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html).

The generated Developer ID requirement constrains the Apple anchor, helper
identifier, Developer ID issuer/application certificate OIDs and team, following
[Apple's signing requirement explanation](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).
These are requested policy inputs, not observed signing identity. Actual
Security.framework verification and extracted entitlements remain required.

Review and sign nested code before its containing bundle with separate
entitlements; the plan avoids `--deep` signing, following
[Apple's distribution signing procedure](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/).
The unsigned input hashes cannot populate a signed runtime contract: signing
changes file contents, so rehash the actual signed files afterward. Entitlement
bytes and unsigned content hashes can be reproduced; timestamped signatures
are not promised to be byte-identical.

## Native signing preflight collector

`scripts/qualify-macos.py` is available for a future native-host review. It uses
the actual host's `codesign` to verify an explicit Developer ID requirement,
extracts the signed child entitlements and observes the Hardened Runtime flag.
Output and execution time are bounded. It binds helper and archive hashes before
and after observation and refuses existing receipt destinations.

This script has **not been run on macOS**. Even successful signing observations
write `qualified: false`, `execution_support: false` and exit **2 / blocked**.
They do not prove protected installed identity, archive membership, helper
version, runtime closure, a sandboxed parent, human approval or descendant
cleanup. The source candidate version is recorded separately from unobserved
helper version. Native tests and clean recipient evidence remain pending.

## Marketplace and lifecycle preparation

`scripts/prepare-macos-marketplace.py` stages a checksummed macOS payload and
`MACOS_MARKETPLACE_PROPOSAL.json`. It requires the source candidate version,
matching architecture metadata and current lockfile/license inventory. Future
dependency changes therefore require regenerated notices before staging.

The proposed marketplace is separate for Apple silicon and Intel. No automatic
architecture selector is assumed, and this script does not write an active
Codex marketplace catalog, modify the existing Fedora entry, publish, install,
update or remove anything. The payload still contains the gateway candidate:
its native macOS lifecycle has not been qualified, so the proposal remains
`install_ready: false` and `publish_ready: false`.

Before enabling installer/update/removal, qualify that Codex manages only its
plugin cache and that the service has quiesced safely. Keep the existing canonical
private-state binding, project plans, claims, approvals and evidence through an
update or removal. A change to the runtime profile or source version must be
explicit and stale affected evidence; it cannot silently reuse a Linux approval.
No package script is allowed to erase private state or rewrite records to make
an update appear verified.
