# Progress Checker 0.2.1-dev

This development archive installs a local Progress Checker plugin into standard Codex for an existing Git worktree. It includes the checker executables, automatic service launcher, ten MCP tools, a planning skill, and managed project instructions. Recipients do not need Rust or the developer's source checkout.

Standard Codex reports progress in normal conversation through the tools and skill; it has no persistent progress panel. The embedded panel and `/progress` commands require the optional maintained Codex fork. This archive includes no fork or Codex executable.

## Requirements and qualification

The observed development environment is **Fedora 44, Linux x86_64, standard Codex 0.160.0** with native plugin support. Other Codex versions and operating systems are not qualified.

- Python **3.11 or newer** at `/usr/bin/python3` and Git at `/usr/bin/git`.
- glibc **2.39 or newer**, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, and the `ld-linux-x86-64.so.2` loader.
- `/usr/bin/rpm` and the Fedora RPM database at `/usr/lib/sysimage/rpm` for environment freshness.
- bubblewrap at `/usr/bin/bwrap`, with permitted Linux namespaces, for approved check execution. An unavailable sandbox refuses execution.
- A trusted existing Git worktree and a private data location outside it.
- Normal Codex authentication in the selected profile for model prompts. The installer does not copy credentials.

The frozen archive with SHA256 `404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029` completed the actual standard Codex pilot and seven configured acceptance checks on 2026-10-06, yielding **8/8 verified milestones** at source fingerprint `fd72644a8822c7741c33f1628f59e36dc11ef96e5b25fc0bf2b17c24e8563e51`. This is historical qualification of that frozen package in the stated development environment. Later repository documentation edits make current tracker evidence stale; they do not change the archive. An approved check on an independent recipient machine, general availability, public hosting, and public directory availability remain unqualified. This is **0.2.1-dev**.

## Install

Keep the archive, `SHA256SUMS`, and accompanying `INSTALL.md` together. Verify the download, then extract it and run the installer:

```sh
set -eu
sha256sum -c SHA256SUMS
tar -xzf progress-checker-0.2.1-dev-linux-x86_64.tar.gz
cd progress-checker-0.2.1-dev-linux-x86_64
python3 install.py install --project /absolute/path/to/project
```

`--project` must identify the exact Git worktree root. The installer checks package file hashes, copies the plugin into a local marketplace outside the repository, and registers it with Codex. It disables this plugin globally and enables it for the chosen project's `.codex/config.toml`, preserving unrelated settings. Existing `.progress-checker/config.json` is retained; an unconfigured project receives an empty opt-in configuration.

The installer prints the marketplace path and `state_directory`. Keep that output. Defaults use `CODEX_HOME`, or `~/.codex`, for the Codex profile, and `XDG_DATA_HOME`, or `~/.local/share`, for data. Use explicit locations when needed:

```sh
python3 install.py install --project /absolute/path/to/project \
  --codex /absolute/path/to/codex \
  --codex-home /absolute/path/to/codex-profile \
  --data-home /absolute/path/to/private-data
```

Keep **the same Codex executable, Codex home and data home** for later actions. Changing these locations selects different profile or state data. An isolated Codex home needs its own authentication.

If this project already has checker evidence in a custom private directory, add
`--state-dir /absolute/path/to/existing/state` during installation. The state
directory and repository must not overlap. Updates retain the installed state
binding automatically; an explicit conflicting path is refused. Installing the
plugin does not move or copy existing evidence.

Installation adds a small managed `AGENTS.md` section by default. Add `--skip-agent-instructions` to leave that file unchanged. Existing instructions outside the managed section are preserved; edited or ambiguous managed markers are rejected for review. Restart Codex in the chosen repository and accept its project-trust prompt as appropriate. `/mcp verbose` should identify `progress_checker` and its ten tools.

## Plan and use the checker

Ask Codex to propose milestones, observable acceptance criteria, check definitions, and dependencies from your requirements. Review the scope before submission. `checker_submit_plan` updates the accepted complete configuration using the current revision and config hash from `checker_get_project`; `checker_get_plan_history` explains added, removed and changed scope.

The remaining tools read milestones, progress, runs and bounded logs; record planned/implemented claims; queue previously approved checks; and request cancellation. Claims and queued runs are not verification. Only current passing evidence for the required criteria can verify a milestone, and dependencies can block it. Editing source files makes prior evidence stale; it does not by itself revoke an exact command approval. Plan revisions revoke execution grants, and new or changed check definitions require fresh exact human approval.

The plugin binds to the worktree selected during installation. Its launcher starts or attaches to the service automatically; there is no routine per-session service command. Concurrent sessions share one writer. Closing the final session stops a launcher-owned service; a separately started service is left running. Startup executes no configured check. If the checker is unavailable, continue normal Codex work and treat progress as unverified. An independent watcher cleans up an owned writer after a session is killed. A kill during the brief writer-startup window can still leave a service until a later session reconciles it.

Explicit MCP metadata `_meta.openai/readOnly=true` exposes six read-only tools and denies four mutations, including plan submission. Codex filesystem sandbox policy is a separate setting.

## Approve one exact check manually

Repository definitions, managed instructions and plugin tools cannot approve command execution. Use the printed `state_directory` and the chosen project's root. From the extracted archive, ask the helper to print the approval command:

```sh
./plugin/bin/checker-project approval-command \
  --root /absolute/path/to/project \
  --state-dir /absolute/path/to/private-data/progress-checker \
  --check check-id
```

The helper prints **only the exact CLI command to stdout**, with a manual-review reminder on stderr; it does not approve or run the check. Close Codex sessions and stop any independently running checker service for that project first. Review the printed command, then run it yourself in an interactive human terminal. The checker displays the exact definition and requires confirmation. Approve only if you accept that command and its sandbox access to the worktree, including ignored files. An agent must not feed the confirmation prompt. Restart Codex afterward and request the approved check through `checker_run_checks`.

The helper is also available as `plugins/progress-checker/bin/checker-project` below the marketplace directory printed by installation. Use the installed helper after the extracted archive has been removed.

## Update, list and remove

Close plugin sessions before updating or removing. Extract the **new** archive into a new directory and run its installer there. Reuse the original project, Codex home and data home; also supply the original `--codex` path if it was customized:

```sh
python3 install.py update --project /absolute/path/to/project \
  --codex-home /original/codex-profile --data-home /original/private-data
python3 install.py list --project /absolute/path/to/project \
  --codex-home /original/codex-profile --data-home /original/private-data
python3 install.py remove --project /absolute/path/to/project \
  --codex-home /original/codex-profile --data-home /original/private-data
```

`update` requires an existing installation and refreshes the packaged plugin and Codex cache while retaining the state binding and evidence. Keep the prior archive for recovery. `list` queries Codex's plugin inventory for this project's marketplace. `remove` unregisters the plugin/marketplace and removes its settings and managed instructions while preserving `.progress-checker/config.json` and private evidence. Removal is not a data-erasure action.

To manage only the instructions, use `./plugin/bin/checker-project install --root PROJECT` or `remove --root PROJECT`. Reinstalling a matching managed block makes no change; removing it leaves other instructions intact and does not uninstall the plugin.

## Package contents and limits

Review `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `checksums.json`, and `plugin/third-party/inventory.json` in this archive. The project uses Apache 2.0; dependencies retain their own license texts and notices. File checksums detect changes against this package's manifest; they are not a signed publisher identity.

Execution is local and requires exact human approval. Same-user processes with direct access to private approval files are outside human-authentication guarantees. Passing a check proves only its stated coverage. No hosted checker or additional paid checker API is required; Codex access remains separate. Public hosting and directory availability have not been established for this development release.
