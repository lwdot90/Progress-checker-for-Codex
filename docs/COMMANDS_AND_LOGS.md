# Commands and log privacy

The published 0.4 beta uses a restricted Linux runner. The 0.5 source candidate retains that boundary and improves version reporting and known-argument redaction; it has not replaced the installed 0.4 payload.

## Supported commands

The initial executable must resolve to an executable, root-owned file under `/usr`, with no group/other write permission. The checker binds its content hash and the bubblewrap binary hash to human approval. Executables are invoked directly, without shell expansion unless you explicitly select a system shell as the approved program.

The environment is fixed: `PATH=/usr/bin:/bin`, `HOME=/tmp`, `LANG=C.UTF-8`. Networking is disabled. The worktree is writable and `/usr` is mounted read-only; the user's real home and private checker storage are not mounted into the check. A trusted check can read ignored files inside the worktree, so keep project secrets out of a test fixture and approve only commands you trust with the project.

Practical choices are `/usr/bin/python3` for project scripts or standard-library tests, and a system-installed `/usr/bin/node` for scripts and dependencies contained in the project. The [working greeting example](../examples/first-check/README.md) uses a real unittest under this policy. Exact paths and executable ownership must be checked on the supported host.

User-managed venv, nvm, pyenv and `~/.cargo/bin` executables are not supported as independent approved runtimes. A symlink that resolves to the system Python may be accepted as that system executable; this does not preserve virtual-environment interpreter behavior. The real home, external libraries and tool caches remain unavailable. Install needed project libraries inside the worktree and use an explicit project test wrapper with the system interpreter, reviewing that wrapper's imports; this is different from transparently supporting every environment manager.

For Node, project `node_modules` can be read from the worktree, but npm's home cache and online dependency installation are unavailable. Rust checks need a trusted system toolchain and dependencies already accessible inside the sandbox; a home-installed Rust toolchain or a network download is not a supported shortcut.

## Why an executable hash is insufficient

A user-managed interpreter can load scripts, shared libraries, activation state and package caches from writable home directories. Hashing only its launcher does not bind those dependencies, and mounting the real home can expose checker approvals, account credentials and unrelated files. A future expanded runtime profile needs explicit dependency/mount binding, update invalidation, home/state isolation, shebang/interpreter treatment and adversarial tests. Keep the current restriction until that design is reviewed and qualified.

## What the 0.5 source candidate redacts

The runner now derives known sensitive values from explicit approved argument forms such as `--api-key=value`, `--password value`, `--client-secret=value` and `TOKEN=value`. These values are replaced in stdout/stderr before bounded logs are persisted. Terminal escapes and unsafe control characters are stripped before matching; a capture ending partway through a known value is hidden conservatively. Real runner tests exercise both output streams.

This does **not** automatically discover arbitrary secrets printed from project files. It does not scan the host environment or private checker records for credentials. Keep credentials out of command arguments and checker configuration: argument redaction does not hide them from the configuration, approval definition or OS process listing. No universal secret-free log guarantee is made. Review logs before sharing them publicly.

## Version status

The frozen published plugin is 0.4.0-dev and its older Rust backend reports 0.2.1. The next source candidate consistently reports 0.5.0-dev from Cargo, the manifest, native gateway, CLI and MCP. Packaging checks compiled binaries before creating an archive, so an old 0.2.1 executable cannot silently become part of a new 0.5 package. Historical payloads, archive checksums and release tags are preserved.
