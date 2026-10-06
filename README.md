# Progress Checker for Codex

Install once globally, then say **“Track this project”** in your Codex projects.
Progress Checker proposes explicit milestones and reports progress using current
local check evidence. Implementation claims and verification stay separate.
Standard Codex shows progress in conversation through eleven MCP tools and a skill.
This source distribution contains no Codex fork or persistent terminal panel.

## Install the beta

Download the **0.3.0-dev** Linux archive and SHA256SUMS from the
[releases page](https://github.com/lwdot90/Progress-checker-for-Codex/releases).
From the download folder:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.3.0-dev-linux-x86_64.tar.gz
cd progress-checker-0.3.0-dev-linux-x86_64
python3 install.py
```

Restart Codex, open a Git project, and say **“Track this project.”** Review the
proposed milestones and acceptance checks. For another project, open another
Codex session and say the same thing. No reinstall or state-directory argument
is needed. Each project keeps separate plans, claims, evidence and command grants.

Supported beta: **Fedora 44 x86_64**, tested with Codex 0.160.0. Runtime requires
Python 3.11+ at /usr/bin/python3, Git at /usr/bin/git, glibc 2.39+, /usr/bin/rpm
and /usr/lib/sysimage/rpm. Approved checks require /usr/bin/bwrap with working
Linux namespaces. Recipients need no Rust or source checkout.

Close sessions using the plugin before update/removal. From the extracted archive:

```sh
python3 install.py update
python3 install.py remove
```

These actions apply globally; removal preserves project files and evidence.
[INSTALL.md](dist/0.3.0-dev/INSTALL.md) covers legacy migration and profile options.
Planning and progress reads need no execution approval. For each new or changed
check, the agent supplies an exact human CLI command: review and confirm it in
your terminal before execution. Stop project checker sessions before approval.
An unchanged grant supports later runs; plan revisions revoke grants.

## Qualification and limits

The frozen 0.3.0-dev archive SHA-256 is
`0169944a42895eb37a1b279316052fbf566e6a7d436ce53eef95d55060176d9b`.
Ten MCP unit tests and 75 native global integration assertions passed. A source-free
Fedora recipient sandbox also passed a previously human-approved synthetic check
through the new global gateway, with current passing evidence.
[QUALIFICATION.json](QUALIFICATION.json) records coverage and limits.

Codex launches bundled servers from the plugin cache, so the skill supplies the
current session's Git root explicitly. The plugin cannot independently infer or
attest that root; it returns the canonical root for confirmation. Each connection
stays bound to one project. It never approves or executes checks on installation,
tracking or startup. The outer test container allowed nested namespaces using
seccomp=unconfined, label=disable and unmask=ALL, while using UID1000, no network,
zero capabilities and no host mounts. Default container policy compatibility,
other platforms and ordinary recipient machines remain unqualified. No recipient
model prompt was sent; the earlier authenticated host workflow qualified 0.2.1.

The service stores private evidence outside each repository, keyed by canonical
root. Checks verify only their declared coverage. Same-user direct tampering with
private approval records is outside the human-authentication guarantee. If the
checker is unavailable, continue normal work and report progress as unverified.
Public directory availability is pending; use the GitHub installer.

Report beta issues at the [issue tracker](https://github.com/lwdot90/Progress-checker-for-Codex/issues)
with OS, Codex version, checksum and a redacted error. Do not attach credentials,
private state, approval records or unredacted logs.

## Build the native plugin from source

The workspace contains `checker-core`, the human CLI, the Unix service, and the
MCP adapter. Python launchers, installer, and the skill live under `plugins/`.
The installer adds a state-only global `mcp.json`; explicit legacy `--project`
installation still writes a project-bound definition. The
versioned [schemas](schemas/README.md) document relevant JSON contracts; Rust
validation is authoritative.

Developers need Linux x86_64, Python 3.11+, Git, curl, a native C build toolchain,
`/usr/bin/sqlite3` for RPM snapshot tests, and Rust 1.95.0. Keep the Rust toolchain and dependency cache in this checkout by
sourcing `scripts/prototype-env.sh` before every Rust command. A fresh checkout
can install the official Rustup bootstrap locally without changing shell
startup files or the global toolchain:

```bash
set -euo pipefail
source scripts/prototype-env.sh
mkdir -p "$PROTOTYPE_ROOT/.local/bootstrap"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
  --output "$PROTOTYPE_ROOT/.local/bootstrap/rustup-init"
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 \
  --output "$PROTOTYPE_ROOT/.local/bootstrap/rustup-init.sha256"
python3 - <<'PY'
import hashlib, os, re
from pathlib import Path
directory = Path(os.environ['PROTOTYPE_ROOT']) / '.local/bootstrap'
fields = (directory / 'rustup-init.sha256').read_text().split()
if not fields or not re.fullmatch(r'[0-9a-f]{64}', fields[0]):
    raise SystemExit('Malformed official Rustup checksum')
if hashlib.sha256((directory / 'rustup-init').read_bytes()).hexdigest() != fields[0]:
    raise SystemExit('Rustup checksum mismatch')
PY
chmod u+x "$PROTOTYPE_ROOT/.local/bootstrap/rustup-init"
"$PROTOTYPE_ROOT/.local/bootstrap/rustup-init" -y --no-modify-path --profile minimal \
  --default-host x86_64-unknown-linux-gnu --default-toolchain 1.95.0 \
  --component rustfmt --component clippy --component rust-docs
source scripts/prototype-env.sh
cargo fetch --locked
bash scripts/build-service.sh
```

The wrappers place outputs under `.local/checker-target`; one compiler job and
disabled debug symbols/incremental compilation reduce memory use. Native
development requires neither the Codex source checkout nor fork build helpers.

Run the backend's automated tests when reviewing source changes:

```bash
bash scripts/test-checker.sh
```

Package the already-built CLI and MCP adapter:

```sh
python3 scripts/package-plugin.py
```

This creates a development archive under `.local/plugin-build`. Package it
from its extracted directory using `install.py`; `plugins/install.py` expects
the package's `plugin/` and `checksums.json` layout. The packaging script checks
the retained dependency-license hashes against `Cargo.lock`. If dependencies
change, fetch the complete lockfile and regenerate notices with:

```bash
source scripts/prototype-env.sh
cargo fetch --locked
python3 scripts/generate-plugin-notices.py
```

The generator requires the locally installed Rust documentation component.
Review dependency-license changes and qualify newly built package bytes before
publishing a replacement. The release archive is distributed separately from
Git; this source checkout includes its guide and checksum, not its binaries.

## License

Progress Checker's backend and native plugin use [Apache-2.0](LICENSE).
Retain [NOTICE](NOTICE), the [third-party notices](plugins/progress-checker/THIRD_PARTY_NOTICES.md),
and the complete dependency-license inventory when redistributing. The
inventory covers all 110 external packages in `Cargo.lock`, including optional,
build, test, and other-platform dependencies; it is not a linked-binary SBOM.
Codex is obtained separately. This project is not authored by OpenAI.
