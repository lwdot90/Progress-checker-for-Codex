# Ubuntu recipient qualification

Ubuntu support is in development. The frozen 0.4 package has no Ubuntu qualification. The initial target is **Ubuntu 24.04 x86_64**, using an ordinary account and a system Python interpreter.

## Reproducible prerequisite receipt

`scripts/qualify-ubuntu.py` is a bounded observation scaffold. It verifies a reviewed archive checksum and records actual OS identity and system tool versions. It refuses root, other distributions, other Ubuntu releases and other architectures. It neither installs the plugin nor approves or runs checks. Its receipt always says `incomplete`.

On the target machine, after the artifact and exact command have been reviewed:

```bash
/usr/bin/python3 scripts/qualify-ubuntu.py \
  --archive /absolute/path/to/reviewed-package.tar.gz \
  --sha256 REVIEWED_ARCHIVE_SHA256 \
  --output /absolute/path/to/new-ubuntu-prerequisites.json
```

Use the archive checksum published with that specific candidate. Do not substitute the current Fedora package as evidence for a new Ubuntu build. Output uses exclusive creation to preserve previous receipts; use a new filename for another observation.

## Required recipient trial

The root agent must register explicit acceptance commands in the project plan. An actual human must approve each exact command using the packaged CLI before the checker executes it. This scaffold cannot supply those approvals.

The complete trial must establish:

1. A separately versioned artifact built for the documented minimum glibc, with matching manifest and backend versions.
2. Source-free installation, native Codex discovery and project tracking without a source checkout or development toolchain.
3. Human terminal approval, an actual passing check and an actual failing check.
4. Source changes and dpkg environment changes invalidating prior evidence.
5. Shared-writer restart, changed-version update and removal preserving intended project files and state.
6. Sandbox denial of host home, private checker state and network, plus timeout and descendant cleanup.

Retain public receipts, artifact hashes, command definitions, test logs and limitations. Never copy private approval records into public documentation. Preserve Fedora qualification alongside Ubuntu evidence.

## Containers and ordinary hosts

A rootless container can help reproduce packaging and package inventory. A pinned image digest is required for a reproducible container trial. A container that denies nested user namespaces cannot establish checker execution support. Giving a fixture extra privileges does not establish ordinary-host compatibility.

Ubuntu 24.04 AppArmor policy must be assessed on an ordinary host or VM. Report specific setup failures and reviewed narrow policy changes; do not disable system protection globally to obtain a passing result.

Ubuntu documents that applications requiring unprivileged user namespaces need permission in their AppArmor profile. Record the actual enforcing profile and denial messages for the selected system bubblewrap and checker executable paths. A Podman default profile describes the container process; it does not establish the policy used by the installed native service. `no-new-privileges` and dropped capabilities in the prerequisite container are restrictions on that fixture, not evidence that the production nested sandbox works. See [Ubuntu AppArmor documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/).

As observed on the development host, Podman 5.8.7 is available, but no local Ubuntu image was present. No image was pulled, container started or recipient check executed for this scaffold.

### Prepared Podman recipe

On the development host, `--prepare-podman ubuntu@sha256:REVIEWED_DIGEST` writes a JSON recipe instead of observing or executing anything. Combine it with the archive/checksum arguments above and a new output file in a dedicated fixture directory. The recipe includes a Containerfile and argument arrays for build and execution. Verify that the official image digest actually identifies Ubuntu 24.04 x86_64, review the generated commands and substitute the reviewed Containerfile, empty build context and built image ID before approval.

The run uses rootless identity mapping, a non-root account, no network, a read-only root filesystem, dropped capabilities and normal host security profiles. Only the selected archive, this harness and a dedicated output directory are mounted. Inputs are not relabeled; on SELinux hosts, use dedicated input copies with a reviewed label rather than relabeling the checkout. The output directory may receive a private container label. Apt packages remain unpinned, so record installed inventory and the final image ID; this is prepared scaffolding, not a fully reproducible qualified artifact. No build, pull or run has been performed.

An optional `--apt-sources-file /absolute/path/to/reviewed-ubuntu.sources` hashes a reviewed deb822 file and adds a Containerfile `COPY` instruction. Copy those exact bytes into the otherwise minimal build context under the recorded name. Review that all enabled repositories use the intended immutable snapshot and that no extra base-image source list remains enabled. The script does not validate repository semantics or establish reproducibility; its output keeps `reproducible_build_established` false. `--artifact-profile debug|release|unknown` records a declaration without inspecting archive members or claiming a release build.

See [the portability assessment](PORTABILITY.md) for the dpkg provider and environment freshness requirements.

## Source-free package compatibility audit

Read-only ELF inspection on 2026-10-12 examined the development host's existing debug binaries without executing them. This describes those bytes, not a rebuilt Ubuntu candidate:

The [machine-readable compatibility notice](receipts/ubuntu-runtime-prerequisites.json) explicitly records that no Ubuntu runtime, package inventory or artifact execution was observed.

| Binary | SHA-256 | Highest required glibc symbol version |
| --- | --- | --- |
| `progress-checker` | `950896b854cfa2aec994047cbdc73e16d9ece4680ab41c009cd188654d86bab3` | `GLIBC_2.39` |
| `progress-checker-mcp` | `ae427b26f693215314ae76e7dea214b4b999fccfbafd26eacfdc459a11571ab5` | `GLIBC_2.34` |

Both are x86-64 ELF PIE executables with interpreter `/lib64/ld-linux-x86-64.so.2`. Their dynamic dependencies are `libgcc_s.so.1`, `libm.so.6`, `libc.so.6` and `ld-linux-x86-64.so.2`. Inspect the actual release binaries again: a matching glibc symbol floor is necessary but does not prove runtime or sandbox compatibility. These observations exclude debug artifacts from support claims.

Ubuntu Noble's published [bubblewrap manual](https://manpages.ubuntu.com/manpages/noble/man1/bwrap.1.html), currently associated with package version `0.9.0-1ubuntu0.3`, documents `--json-status-fd`. The runner uses that option to monitor sandbox lifecycle. Verify the installed target executable and actual status protocol during acceptance; the manual alone is not execution evidence. No fallback that drops lifecycle monitoring is proposed.

The installed wrappers use `/usr/bin/python3` and standard-library modules, including Unix `fcntl` in the service launcher. Source packaging helpers use standard-library `tomllib`, which requires Python 3.11 or newer; packaging belongs in the controlled builder, not on the source-free recipient. Verify the packaged launchers against the actual Ubuntu system Python. Recipient dependencies must include Git, bubblewrap, dpkg-query and the ELF runtime libraries above, with no Rust toolchain requirement.

### Candidate builder and pins

Prepare an x86-64 Ubuntu 24.04 builder from an independently verified immutable official image digest. Use the repository's exact Rust toolchain **1.95.0**, project-local Rust/Cargo homes and unchanged `Cargo.lock`; only the root agent runs Cargo and must source `scripts/prototype-env.sh`. The builder needs a C linker and libc development files, Python 3.11+ for packaging, Git, and binutils for ELF inspection. Package a separately versioned Linux x86-64 candidate rather than relabeling frozen Fedora artifacts.

Before any accepted build, record the image digest, apt repository snapshot or exact package-version inventory, Rust distribution checksum and toolchain identity, source revision and lockfile hash. The prepared recipe does not currently pin apt snapshots; resolve those inputs before describing the build as reproducible. Keep a separate source-free recipient image with no compiler or Cargo, installed runtime package inventory, a recorded built image ID and ordinary UID 1000. Official base images may already have UID 1000, so the recipe reuses it instead of requiring creation of a conflicting user.

After root-approved build commands, inspect ELF dependencies and glibc version requirements again, package-version consistency, archive hashes and legal inventory. Then register and human-approve recipient acceptance commands. No builder, image pull or recipient launch has occurred during this audit.

## Ordinary-host human qualification checklist

The following inputs are still missing. A prepared container recipe or prerequisite receipt does not satisfy them:

- An ordinary Ubuntu 24.04 x86-64 host or VM, its image provenance, kernel version, system Python/Git/bubblewrap/dpkg package versions and an ordinary recipient account.
- An independently verified builder image digest and exact repository snapshot/package inputs; the current recipe deliberately supplies no invented digest.
- A fresh candidate source revision, exact Rust/toolchain provenance, release-profile binaries and archive, public checksums, legal inventory and ELF inspection from that build.
- A source-free recipient project and separate human terminal, with the precise accepted milestone plan, registered command definitions, configuration hash and current revision.
- Actual enforcing AppArmor profile identity and relevant audit messages for the installed paths. Any necessary policy change must be narrowly reviewed; global disablement is not qualification.
- A prior qualified artifact for the changed-version update case, and explicit expectations for project-file/state preservation on update and removal.

With those inputs present, the human and checker must retain public evidence for each step:

1. Install the reviewed archive without mounting the source checkout or developer home; confirm native Codex discovery and matching backend/manifest versions.
2. Track the isolated project and inspect its exact check definitions. Confirm no configured command runs during startup or tracking.
3. In the separate human terminal, approve the exact command through the packaged CLI. The agent must not enter the confirmation. Retain the public approval binding summary, never private grant bytes.
4. Run the approved passing case through the checker, then a defined failing case. Record real outcomes and bounded logs.
5. Change the relevant source and observe stale evidence. Separately exercise a reviewed dpkg environment mutation or provider fixture demonstrating real environment freshness; do not silently install or remove host packages.
6. Restart clients/service, then update to the changed artifact and remove it. Inspect the declared preservation expectations and absence of unintended runtime processes.
7. Execute separately registered and human-approved adversarial checks for network denial, host-home/private-state denial, descendant cleanup and timeout. Record any AppArmor or namespace denial as a failed or blocked capability rather than a pass.
8. Read the checker progress snapshot and publish only current passing evidence with actual target/platform/artifact identities. Keep container and ordinary-host evidence scopes distinct.

The compatibility notice records older inspected debug bytes; editing the helper does not turn that notice into a receipt for the new helper or a fresh release build. Generate new recipient receipts from the reviewed helper revision and retain its source hash with execution evidence when the approved trial occurs.
