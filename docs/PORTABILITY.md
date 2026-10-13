# Ubuntu portability assessment

Scope: source inspection and a migration proposal. Ubuntu is **not yet supported**. No Ubuntu build, installation, sandbox execution or compatibility pass is claimed here. The frozen 0.4 package is unchanged.

## Why RPM is required

`checker-core/src/environment.rs` queries `/usr/bin/rpm` against `/usr/lib/sysimage/rpm` for installed package names, versions, releases and architectures. Its process-local cache keys the RPM executable and database files by inode, device, size, mtime and ctime, watches the WAL, and checks the key again after collection. Missing inventory, races, collector failures and excessive output/time fail closed.

`checker-core/src/engine.rs::source` sorts that inventory and hashes it with the current command/executable bindings and `/proc/sys/kernel/osrelease`. This helps invalidate evidence after compiler or system-library packages change even when the project source does not. RPM is not used as the check runner or installer. Removing the query without a replacement would weaken freshness; installing RPM on Ubuntu would inventory the wrong package manager.

## Ubuntu implementation proposal

1. Add an internal Linux inventory provider for dpkg alongside RPM. Select from fixed trusted system paths, not repository configuration, mutable PATH lookup or a caller-supplied command. Hash the provider identity and inventory format into the environment signature so changing providers makes old evidence stale.
2. On Ubuntu, use `/usr/bin/dpkg-query --show` with an explicit format containing package name, architecture, version and installation status. `dpkg-query` queries installed database status by default. Include transitional/error package states in the normalized output; reject malformed or incomplete output rather than silently omitting entries. [Ubuntu dpkg-query manual](https://manpages.ubuntu.com/manpages/jammy/man1/dpkg-query.1.html).
3. Key `/var/lib/dpkg/status`, the directory and pending update fragments under `/var/lib/dpkg/updates`, together with the trusted executable. Ensure the snapshot is stable before and after collection; refuse results during uncertain transitions. Cover atomic database replacements and update fragments in cache invalidation. Keep the existing size/time limits and fail closed behavior. Review the database update semantics before choosing the final cache key.
4. Preserve RPM behavior and tests on Fedora. Add provider-focused tests for database mutation, same-length rewrite, collector failure, malformed output, changed provider and preservation of stale evidence. Package provenance and approval binding must not become caller-overridable.
5. Build a separately versioned package against a documented minimum glibc and verify its dynamic dependencies. The existing binary requires glibc 2.39+; assess Ubuntu 24.04 x86_64 as the initial candidate rather than advertising all Ubuntu releases. Verify Python, Git and bubblewrap executable locations on the actual target.
6. Run source-free installation, project tracking, exact human approval, passing/failing checks, source/environment staleness, shared-writer restart, changed-version update and removal in an ordinary Ubuntu environment. Retain existing Fedora checks. Container namespace exceptions cannot establish ordinary-host compatibility.

## Sandbox and runtime work

`checker-core/src/security.rs` binds the hash of `/usr/bin/bwrap` into approval and constructs restricted filesystem mounts. `checker-core/src/runner.rs` uses Linux memfd and process groups for bounded output, timeout and descendant cleanup. Installing bubblewrap alone does not establish that its namespaces can be created under the target machine's policy.

Ubuntu AppArmor can restrict unprivileged user namespaces, requiring applications to be explicitly allowed. Check the actual package/profile combination and report actionable setup failures; do not instruct users to disable system protections globally to obtain a passing trial. [Ubuntu AppArmor documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/).

The Python launchers use `/usr/bin/python3` and `/usr/bin/git` as deliberate executable choices. Those locations need target verification; general PATH discovery would require a trusted resolution and approval policy. The proposed first Ubuntu release retains Python instead of introducing an unrelated runtime rewrite.

## macOS is a separate port

Replacing RPM is insufficient for macOS. The runner currently returns an unknown outcome outside Linux. Security and service code also depend on Linux process identity, procfs, namespaces and bubblewrap. A macOS port needs a reviewed sandbox and descendant cleanup, trusted process/TTY identity for human approval, an environment freshness model, compatible packaging, and its own adversarial and recipient trials. No macOS support claim is made.

## Decision

Prioritize a dpkg inventory provider and a source-free Ubuntu 24.04 x86_64 qualification in a new release after the current first-use workflow succeeds. This assessment implements the investigation milestone; it does not implement Ubuntu support. The next implementation plan must add explicit provider and platform checks before code is shipped.
