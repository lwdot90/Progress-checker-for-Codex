# Install Progress Checker once

Fedora 44 x86_64 beta, tested with Codex 0.160.0. Requires Python 3.11+, Git,
glibc 2.39+, /usr/bin/rpm and /usr/lib/sysimage/rpm. Approved checks require
working bubblewrap namespaces. No Rust or source checkout required.

Download the archive and SHA256SUMS from the release. From the download folder:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.3.0-dev-linux-x86_64.tar.gz
cd progress-checker-0.3.0-dev-linux-x86_64
python3 install.py
```

That installs the plugin globally for your Codex profile. Restart Codex, open a
Git project, and say **“Track this project.”** For another project, open another
Codex session and say the same thing. You do not reinstall the plugin.

Review the proposed milestones before accepting the plan. Ask **“What’s the
progress?”** to read implementation claims and current verification.
Checks need your separate terminal approval; the agent supplies the exact command.
Installation and tracking never approve or run checks.

## Update or remove

Close sessions using this plugin. From the extracted archive:

```sh
python3 install.py update
python3 install.py remove
```

Both apply globally. Removal preserves your projects, plans, managed instructions,
and private evidence. Updates preserve the configured private state directory.

## Existing 0.2.1 installations

Project-bound entries remain separate. To remove a legacy entry, use the old
installer with `remove --project /absolute/project/root`; this preserves project
configuration and evidence. Then use the globally installed plugin in a new session.
Default state locations are unchanged. If a legacy installation uses a custom
state directory, retain it using `--state-dir` when installing globally or keep
that project-bound entry. Do not silently migrate to another evidence store.

## How project selection works

Codex launches bundled MCP servers from the plugin cache. The skill passes the
current session's Git worktree root explicitly; the plugin cannot independently
infer or attest that root. It returns the canonical root for confirmation before
plan or claim changes. Each connection stays bound to one project, and the existing
backend separates evidence and approvals by canonical root. If tracking fails,
normal Codex work remains available.

See the archive README for approval details, profile options and limitations.
The earlier 0.2.1 qualification applies only to that frozen archive. New package
qualification is recorded separately; public directory listing remains pending.
