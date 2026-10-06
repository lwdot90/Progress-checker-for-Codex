# Progress Checker 0.2.1-dev

A local plugin for standard Codex. Install it once for an existing Git project;
the checker starts automatically in later sessions. No Rust or source checkout
is required on the recipient's computer.

This development package completed all eight local delivery milestones on
2026-10-06, including the authenticated standard Codex workflow. Independent
recipient-machine execution and public publication remain separate launch work.
The dated qualification applies to the frozen archive; read the checker for
current repository progress after later edits.

## Install

The supported beta target is Fedora 44 x86_64 with Codex 0.160.0.
Requirements: authenticated standard Codex with native plugin support, Python
3.11+ at `/usr/bin/python3`, Git at `/usr/bin/git`, glibc 2.39+, and bubblewrap
at `/usr/bin/bwrap` with Linux namespaces available for check execution.
Environment freshness requires `/usr/bin/rpm` and the RPM database at
`/usr/lib/sysimage/rpm`; other distribution layouts are unsupported.

Use the exact Git worktree root for `--project`, rather than a subdirectory.
Run `git rev-parse --show-toplevel` in your project to find that path.

From the folder containing this guide, archive and `SHA256SUMS`:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.2.1-dev-linux-x86_64.tar.gz
cd progress-checker-0.2.1-dev-linux-x86_64
python3 install.py install --project /absolute/path/to/your/project
```

Keep the installer's output, including its `state_directory`. Restart Codex in
that project and trust the project when prompted. Installation adds managed
Progress Checker instructions to `AGENTS.md`, preserving existing instructions.

## Use

Ask Codex:

> Use Progress Checker to propose milestones and acceptance checks for this
> project. Show me the plan before submitting it.

After accepting the plan, ask:

> Record the work that is implemented and report progress using Progress Checker.

Standard Codex reports progress in normal conversation; there is no persistent
plugin panel. Implemented claims and verified progress are separate. A check must
pass against the current project files to supply verification. Source edits make
evidence stale without revoking the exact command grant. Plan revisions revoke
grants; new or changed definitions require fresh manual approval.

For a new or changed check, print its exact approval command from the extracted
package (`STATE` is the installer's `state_directory`):

```sh
./plugin/bin/checker-project approval-command --root /absolute/path/to/your/project \
  --state-dir STATE --check CHECK_ID
```

Close Codex sessions and any separately started checker for that project. Run
the printed command yourself, review the definition, and answer its confirmation.
Reopen Codex and ask it to run the approved check. Ordinary progress reads need
no approval and no manual service startup.

If approval reports `another checker owns this worktree`, no approval was saved.
Close every Codex session using that project, including the conversation that
requested approval. If you started a checker with `serve` in another terminal,
stop it with Ctrl-C there. Then retry the same approval command before reopening
Codex.

## Update or remove

Close project Codex sessions first. Use the installer from the new archive for
an update; keep the original project/profile/data locations:

```sh
python3 install.py update --project /absolute/path/to/your/project
python3 install.py list --project /absolute/path/to/your/project
python3 install.py remove --project /absolute/path/to/your/project
```

Updates retain the installed state binding and evidence. Removal preserves project
configuration and private evidence. If you customized
`--codex`, `--codex-home` or `--data-home`, supply those same options for each action.

## Plugin versus fork

The plugin provides planning, claims, verification, logs and automatic local
service management through tools and conversation. The embedded progress panel
and `/progress` visibility commands require the maintained Codex fork. This
archive includes no Codex executable.

The archived `README.md` predates qualification; use this accompanying guide for
the current qualification statement. The extracted README also provides detailed
prerequisites, approval instructions, licenses and limitations. Share this archive,
`SHA256SUMS` and this guide together; identify it as a development package.

## Additional sandbox qualification

A source-free Fedora 44 recipient sandbox passed 75 packaging assertions plus
human-approved check execution, restart retention, edit staleness, failure
handling, and update/removal evidence retention. Removal changes managed
instructions, so retained evidence becomes stale. The outer container used
zero capabilities, UID 1000, no network or host mounts, and relaxed namespace
policy (seccomp=unconfined, label=disable, unmask=ALL). This trial did not send
an authenticated model request or qualify default container policies.
