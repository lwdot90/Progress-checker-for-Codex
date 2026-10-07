# Progress Checker for Codex

Track explicit milestones and report progress from current local check evidence.
Implementation claims stay separate from verification. Install once, then use
Progress Checker in your Git projects.

## Install in Codex

**0.4.0-dev is available through the custom marketplace.** Native installation
has passed qualification; the final human approval trial remains pending.

1. Open `/plugins` → **Add marketplace** and enter
   `lwdot90/Progress-checker-for-Codex`.
2. Select **Progress Checker** → **Install**. Start a new chat if requested.
3. Open your Git project and say **“Track this project.”**

This is a custom Git marketplace; a universal plugin-directory listing is not
claimed. New users need no archive installer, Rust toolchain or source build.
For another project, open another Codex session and say the same thing.

Review the proposed milestones and acceptance checks before accepting the plan.
Ask **“What's the progress?”** for implementation claims and current verification.
Tracking confirms the project root and preserves existing plans. Standard Codex
reports progress in conversation. Installation, tracking and service startup
never approve or run checks.

## Requirements

Supported beta target: **Fedora 44 x86_64**, standard **Codex 0.160.0**.
See [0.4 qualification](QUALIFICATION-0.4.json) for exact tested versions and limits. Runtime needs
Python 3.11+ at `/usr/bin/python3`, Git at `/usr/bin/git`, glibc 2.39+,
`/usr/bin/rpm` and `/usr/lib/sysimage/rpm`. Approved checks also need
`/usr/bin/bwrap` with working Linux namespaces. Use your normal Codex
authentication and project trust settings.

## Approve a check while Codex stays open

Plans and plugin tools cannot approve execution. For each new or changed check,
Codex supplies the packaged CLI command with the exact project and state binding.
**Keep Codex open**, run that command yourself in a separate interactive terminal,
review the exact definition and confirm only if you trust it. An agent must never
answer the prompt. Approval saves a grant; it does not execute the check.
Return to the same chat and ask Codex to run the approved check.

There is no approval MCP tool. Source changes can make passing evidence stale
while preserving an unchanged grant. Accepted plan revisions invalidate grants.
Only fresh passing evidence for the required criteria counts as verification.
If the checker is unavailable, continue normal work and report progress as
unverified.

## Update, remove or migrate

Manage a browser installation through `/plugins` in the same Codex profile.
Start a new chat to load an update if requested. Removal preserves project
plans, managed instructions and private evidence.

The default private state base is `$XDG_DATA_HOME/progress-checker`, normally
`~/.local/share/progress-checker`; each canonical Git worktree has separate
records. When upgrading an older archive installation,
close its project Codex sessions and stop its old writer **once before switching
versions**. Remove the old plugin entry using its original installer and profile
arguments, then enable the native plugin. This upgrade step is separate from
ordinary 0.4 approval, which keeps Codex open. Do not delete private state.

For legacy project-bound entries, retain the original `--project` argument when
removing them. If you used custom `--state-dir`, `--codex-home` or `--data-home`
locations, retain those bindings through the archive installer or continue the
legacy entry until an explicit migration is arranged. Native installation does
not silently migrate custom state. The
[0.3 archive guide](dist/0.3.0-dev/INSTALL.md) documents the fallback and older
installation behavior.

## Release status

The frozen **0.3.0-dev** archive retains SHA-256:

```text
0169944a42895eb37a1b279316052fbf566e6a7d436ce53eef95d55060176d9b
```

Its [qualification record](QUALIFICATION.json),
[installation guide](dist/0.3.0-dev/INSTALL.md) and
[releases page](https://github.com/lwdot90/Progress-checker-for-Codex/releases)
remain available. That historical qualification does not verify the new 0.4
package, native browser installation or live approval. Other platforms and
ordinary recipient machines remain unqualified.

Report beta issues at the
[issue tracker](https://github.com/lwdot90/Progress-checker-for-Codex/issues)
with your OS, Codex version and a redacted error. Do not attach credentials or
private state.

Progress Checker uses [Apache-2.0](LICENSE). Retain [NOTICE](NOTICE) and the
[third-party notices](plugins/progress-checker/THIRD_PARTY_NOTICES.md) when
redistributing. Codex is obtained separately; this project is not authored by
OpenAI.
