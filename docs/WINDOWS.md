# Native Windows support

Native Windows is planned and is **not qualified or available to users yet**.
The published 0.4 payload is a Linux package. WSL is a separate Linux environment;
it does not establish native Windows support.

## Packaging work prepared

`scripts/package-windows.py` prepares a development ZIP on native Windows after
native binaries exist. It requires x86_64 PE images named `progress-checker.exe`,
`progress-checker-mcp.exe`, and `checker-global.exe`. Every executable must answer
`--version` with its name and the source manifest version. The packager verifies
license inventory hashes, generates file checksums, refuses archive replacement,
and marks the archive unqualified. It excludes Linux shell/Python launchers.

The required native `checker-global.exe` has a Rust source candidate in
`checker-global/`; it is not yet a qualified recipient binary. It must discover and track projects, retain the single writer,
route MCP requests, and select a protected per-user state directory without
requiring `/usr/bin/python3`. The generated MCP definition starts that gateway
with no arguments; the gateway must support that contract. ZIP extraction alone
is not an installer. Native Codex marketplace installation remains to be exercised.

After implementation, the packaging command on Windows is:

```powershell
python scripts/package-windows.py --bin-dir .local/checker-target/release --output .local/windows-package
```

Python 3.11 or later and `scripts/windows_artifact_process.py` are **builder
tool requirements**, not recipient runtime dependencies. The ZIP contains native
executables and DLLs; it bundles no Python interpreter or Linux launcher. Include non-system runtime DLLs using repeated
`--runtime-dll` arguments and provide one corresponding
`--runtime-dll-license DLL_NAME=LICENSE_PATH` for each DLL. These files are
redistribution material supplied by the builder; their presence is not a DLL
dependency audit or a legal compatibility determination. The receipt explicitly
records that dependency auditing has not been performed. PE validation and version matching do not determine
whether DLL dependencies are complete or whether Authenticode signatures are
trusted. Those require native dependency auditing and release qualification.

## Runtime work still required

The current source has Unix file-descriptor and permission operations, Unix-domain
service connections, Unix signals, hardcoded `/usr/bin/git`, RPM inventory, and
Linux bubblewrap sandboxing. Creating a ZIP does not make these portable.

Windows needs protected named-pipe IPC with user authentication and ACLs;
private state and atomic updates protected by Windows ACLs; race-resistant file
opening and replacement; explicit executable and dependency identity; native Git
selection; process-tree cancellation; and restricted command execution with home,
network and private-state access denied. A Job Object alone does not provide the
required filesystem or network isolation. Until a native confinement backend is
qualified, checks must fail closed rather than execute unrestricted commands.

Reparse points, junctions, case-insensitive paths, drive boundaries and shared
file handles need explicit coverage. Human approval must remain outside the MCP
interface, bound to exact commands and invalidated by plan or runtime changes.

## Required recipient qualification

Record Windows edition/build, architecture, native Codex version, binary hashes,
DLL identities and confinement profile. Exercise install, first tracking, human
approval, passing/failing checks, source staleness, changed-plan approval
invalidation, denial of private-state/home/network access, cancellation of child
processes, writer restart, update and uninstall. An actual clean Windows host must
produce the evidence; Linux cross-compilation cannot establish those behaviors.

## Installation scaffold

`scripts/install-windows.ps1 -Action Validate -Archive PATH -ArchiveSha256 HASH`
inspects a development ZIP in temporary staging: archive hash, bounded extraction,
checksums, PE architecture, and matching package/manifest version metadata. It
does not launch executables or access checker state. Its output explicitly says
that runtime binary version verification and installation are unavailable.
`Install` refuses activation until native bounded version probing, ACL checks and
release qualification are integrated. `Remove` only accepts a recognized dedicated
development installation marker; it never removes evidence state or marketplace
profiles. No qualified Windows installer or updater is supplied yet.
