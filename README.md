# Progress Checker for Codex

Progress Checker is a local Codex plugin for planning milestones and reporting
progress from current check evidence. It starts its checker automatically when
Codex needs it. Implementation claims and verified progress remain separate:
only a passing, approved check against the current project files supplies
verification.

This repository contains the native plugin and Rust backend for the Linux
**0.2.1-dev beta**. Standard Codex presents progress in conversation through ten
MCP tools and a planning skill. This source distribution contains no Codex fork
or executable and does not provide a persistent terminal panel.

## Install the beta

Download the Linux archive, `SHA256SUMS`, and `INSTALL.md` from the
[latest release](https://github.com/lwdot90/Progress-checker-for-Codex/releases/latest).
GitHub may list a beta only on the [releases page](https://github.com/lwdot90/Progress-checker-for-Codex/releases),
because prereleases are excluded from its latest-release redirect. Use the
accompanying [installation guide](dist/0.2.1-dev/INSTALL.md).

The supported beta target is Fedora 44 x86_64. Qualification used Fedora 44
and standard Codex 0.160.0 with native plugin support. Recipients need Python
3.11+ at `/usr/bin/python3`, Git at `/usr/bin/git`, glibc 2.39+, and
`/usr/bin/bwrap` with working Linux namespaces for check execution. Model prompts
use the recipient's existing Codex authentication. Environment freshness also requires
`/usr/bin/rpm` and the RPM database at `/usr/lib/sysimage/rpm`. Rust and this checkout are
unnecessary for the release archive.

From the folder containing the three downloaded release files:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.2.1-dev-linux-x86_64.tar.gz
cd progress-checker-0.2.1-dev-linux-x86_64
python3 install.py install --project /absolute/path/to/your/project
```

`--project` must identify the existing Git worktree root; find it with
`git rev-parse --show-toplevel`. Keep the installer's output, including its
`state_directory`. Restart Codex in that project. Installation preserves
unrelated settings and adds a managed section to `AGENTS.md`; the detailed guide
explains profile choices and `--skip-agent-instructions`.

Ask Codex to propose milestones and observable acceptance checks from your
requirements, show the plan for your review, and submit the accepted complete
plan. Ask it to record implemented work and read Progress Checker when reporting
progress. Source edits make previous evidence stale. Plan/config revisions
invalidate command grants, including revisions that retain the same command.

For each new or changed check, print its exact approval command from the
extracted archive:

```sh
./plugin/bin/checker-project approval-command --root /absolute/path/to/your/project \
  --state-dir STATE_DIRECTORY --check CHECK_ID
```

Close project Codex sessions and any independently started checker service,
then run the printed command yourself in a terminal. Review the exact command
and confirm it only if you accept its sandbox access. Reopen Codex and request
the approved check. An agent must never answer that confirmation prompt.
An unchanged grant can cover later runs; ordinary progress reads and prompts
need no command approval. There is no batch-approval feature.

Close project sessions before updating or removing the plugin. Use the
installer from a newly extracted archive and retain the original project,
Codex profile, data directory, and any customized executable path:

```sh
python3 install.py update --project /absolute/path/to/your/project
python3 install.py list --project /absolute/path/to/your/project
python3 install.py remove --project /absolute/path/to/your/project
```

Updates retain the installed state binding and evidence. Removal preserves
project configuration and private evidence. Details are in
[the installation guide](dist/0.2.1-dev/INSTALL.md) and
[the package documentation](plugins/README.md).

## Qualification and limits

The frozen 0.2.1-dev release archive is identified by SHA-256
`404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029`.
It completed the local development delivery checks and authenticated standard
Codex workflow on 2026-10-06. Source-free recipient qualification covered native
discovery, installation, upgrade, configuration/state retention, and removal.
Approved check execution was exercised on the development host; the clean
recipient fixture's nested sandbox did not establish recipient execution
support. An unavailable sandbox refuses checks.

Those results apply to the frozen archive and tested environment. A build from
this source produces a separate artifact that requires its own checks and
checksum. Other operating systems, Codex versions, and ordinary recipient
execution environments are unqualified. Public directory availability is not
established; use the release installer. The installer creates an explicit
worktree/state binding and a local marketplace, so copying the plugin directory
alone is insufficient.

The service stores evidence outside the repository in a private state
directory. Verification remains limited to each check's declared coverage.
Same-user processes that can directly alter private approval files are outside
the human-authentication guarantee. If the checker is unavailable, continue
normal Codex work and report progress as unverified.

For beta issues, include the operating system, Codex version, package checksum,
and a redacted error at the
[issue tracker](https://github.com/lwdot90/Progress-checker-for-Codex/issues).
Do not attach credentials, private state, approval records, or unredacted logs.

## Build the native plugin from source

The workspace contains `checker-core`, the human CLI, the Unix service, and the
MCP adapter. Python launchers, installer, and the skill live under `plugins/`.
The installer adds the worktree-specific `mcp.json` during installation. The
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
