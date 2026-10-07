# Progress Checker plugin

Install once for your Codex profile, then use it in your projects. The
**0.4.0-dev is available through the native custom marketplace.**
Native installation passed local and published HTTPS trials. The final human
live-approval trial remains pending; earlier archives do not verify this release.

Supported beta target: Fedora 44 x86_64 and standard Codex 0.160.0.
Runtime prerequisites: Python 3.11+ at /usr/bin/python3, Git at /usr/bin/git,
glibc 2.39+, /usr/bin/rpm and /usr/lib/sysimage/rpm. Approved checks also need
/usr/bin/bwrap with working namespaces. Recipients need no Rust or source build.

## Install once

Once the candidate is published, use the native Codex plugin browser:

1. Open `/plugins` and choose **Add marketplace**.
2. Enter `lwdot90/Progress-checker-for-Codex`.
3. Select **Progress Checker** and choose **Install**.
4. Start a new chat if Codex requests one so the plugin tools and skill load.
5. Open the Git project you want to track and say:

> Track this project. Propose milestones and acceptance checks for my review.

This is a Git custom marketplace. Availability in Codex's universal plugin
directory is separate and is not claimed. New users do not need an archive
installer or a terminal installation command.

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

## Verification approval

Planning, claims and progress reads need no execution approval. For each new or
changed check, Codex prints the packaged human CLI approval command with the
correct project and state path. **Keep Codex open.** Run that command yourself in
a separate interactive terminal, review the exact check definition, and confirm
only if you trust it. Agents must never answer the confirmation. Approval saves
a grant; it does not execute the check. Return to the same Codex chat and request
the approved check.

There is no approval MCP tool. Plans and instructions cannot approve execution.
Source edits stale evidence but keep an unchanged grant; plan revisions invalidate
grants. No check runs on installation, tracking or service startup. Same-user
direct tampering with private state is outside the human-authentication guarantee.

## Update, remove and migrate

For a native browser installation, manage the plugin through `/plugins` in the
same Codex profile. Load an update in a new chat if requested. Removal preserves
project plans, managed project instructions and private evidence; it removes the
plugin rather than the tracking records. Updates must retain the state binding.

The archive installer remains a fallback for offline setup and existing custom
profiles or state locations. From a trusted, checksum-verified extracted archive,
close sessions using that installation before an archive update or removal:

```sh
python3 install.py update
python3 install.py list
python3 install.py remove
```

For a first fallback installation, use `python3 install.py`. Retain any original
`--codex-home`, `--data-home` and `--state-dir` arguments. Custom state bindings
cannot be changed silently.

Legacy installations using `--project /absolute/worktree` are separate plugin
entries. Use that same argument to update or remove them; a native installation
does not silently migrate or remove them. The default private state base remains
`~/.local/share/progress-checker`. If a legacy installation uses a custom state
base, keep using it through the archive installer with the same `--state-dir`, or
continue the legacy entry until an explicit migration is arranged. Do not enable
both entries for one project without reviewing their state bindings. Older
packages retain their own approval instructions; the live approval flow above
belongs to 0.4.0-dev.

If the checker is unavailable, continue normal work and report progress as
unverified. The frozen 0.2.1-dev and 0.3.0-dev archives retain their identities;
neither supplies verification for the new 0.4.0-dev package or marketplace flow.
