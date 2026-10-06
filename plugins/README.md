# Progress Checker plugin

Install once for your Codex profile, then use it in your projects.
Supported beta: Fedora 44 x86_64 and standard Codex 0.160.0.
Runtime prerequisites: Python 3.11+ at /usr/bin/python3, Git at /usr/bin/git,
glibc 2.39+, /usr/bin/rpm and /usr/lib/sysimage/rpm. Approved checks also need
/usr/bin/bwrap with working namespaces. Recipients need no Rust or source build.

## Install once

Download the release archive and SHA256SUMS. From that download directory:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.3.0-dev-linux-x86_64.tar.gz
cd progress-checker-0.3.0-dev-linux-x86_64
python3 install.py
```

Restart Codex. Open any Git project and say:

> Track this project. Propose milestones and acceptance checks for my review.

The skill passes the current session's Git worktree root to checker_track_project.
Codex starts bundled MCP servers in the plugin cache; this plugin cannot
independently infer or attest the session root. It returns the canonical root
for the agent to confirm before changing plans or claims. Each MCP connection
stays bound to one project; use separate sessions for different repositories.
Tracking creates an empty plan only when missing and preserves existing plans.
It adds a managed AGENTS.md section while preserving user instructions.
Installation itself writes no project files or plans and starts no checks.

Each project has its own plan, implementation claims, evidence and exact command
grants. Standard Codex reports progress in conversation. The persistent terminal
panel belongs to the optional maintained fork.

## Update and remove

Close Codex sessions using this plugin. From the extracted new archive:

```sh
python3 install.py update
python3 install.py list
python3 install.py remove
```

Update is global, once per profile. Removal preserves every project configuration,
managed instructions and private evidence. It disables/removes the plugin, not
project tracking records. If you used --codex-home, --data-home or --state-dir,
retain those choices. Custom state bindings cannot be changed silently.

Legacy installations using `--project /absolute/worktree` remain supported. They
are separate plugin entries; remove those entries with the same `--project`
argument when migrating. Global installation does not silently remove them.
The default private state base remains ~/.local/share/progress-checker, so
existing projects using that base retain their evidence. For custom legacy state,
choose the same --state-dir when installing globally or continue the legacy entry.

## Verification approval

Planning, claims and progress reads need no execution approval. For each new or
changed check, Codex prints the packaged human CLI approval command with the
correct project and state path. Review it in your own terminal; agents must never
answer its confirmation. Stop the project's checker sessions before approval,
then reopen Codex and request the check. Source edits stale evidence but keep an
unchanged grant; plan revisions invalidate grants. No check runs on installation,
tracking or service startup. Same-user direct tampering with private state is
outside the human-authentication guarantee.

If the checker is unavailable, continue normal work and report progress as
unverified. Directory listing approval remains separate from GitHub distribution.
The previous 0.2.1-dev qualification does not verify these new 0.3.0-dev bytes.
