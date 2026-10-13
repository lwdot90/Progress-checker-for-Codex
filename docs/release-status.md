# Release and support details

The custom Git marketplace offers 0.4.0-dev, a beta for Fedora 44 x86_64. Its native installation and tool discovery have recorded development coverage. A live interactive human approval followed by a passing check in the same chat remains pending. Current project verification must be read from the running checker.

The package requires Python 3.11+ at `/usr/bin/python3`, Git at `/usr/bin/git`, glibc 2.39+, RPM at `/usr/bin/rpm`, the RPM database at `/usr/lib/sysimage/rpm`, and bubblewrap at `/usr/bin/bwrap` with working Linux namespaces. Additional operating systems and ordinary recipient machines are unqualified. [Ubuntu investigation](PORTABILITY.md) explains the remaining work.

The 0.4 payload is pinned to `6cec3dbc00c417bd05b5b4b1b3a61ad01ef44371`; the frozen archive SHA-256 is `4bd153b6c43b843114f76228382c9c76ebb7c3553e1d776cb31c77a8a07c7228`. The archives and payload remain unchanged by documentation improvements.

## Existing installations

The native plugin discovers ordinary default project records. The default private storage base is `$XDG_DATA_HOME/progress-checker`, usually `~/.local/share/progress-checker`. Each Git worktree has separate records. Custom legacy state/profile bindings are not migrated automatically. Keep the old binding until an explicit migration is prepared, and do not delete private records.

Older running writers need a one-time close/reopen during an upgrade. Routine 0.4 approval keeps the current Codex chat and writer open.

## Historical records

[Public beta and qualification records](https://github.com/lwdot90/Progress-checker-for-Codex) include `QUALIFICATION-0.4.json`, `QUALIFICATION.json`, `LAUNCH_PLAN.md` and `DIRECTORY_READINESS.md`. They describe dated observations and their limits; they do not establish current project verification. These records remain available without occupying the quickstart.

The project is distributed through its custom Git marketplace. OpenAI universal-directory review is a separate external action and is not an installation prerequisite.
