# Observe a first-user installation

This is a procedure for a real, voluntary trial. It is not a completed trial report. Developer runs, agent demonstrations and synthetic fixtures remain separate from independent-user feedback.

## Choose a supported artifact

| Platform | User installation status |
| --- | --- |
| Fedora 44 x86_64 | Published 0.4.0-dev beta; use its documented prerequisites and limitations. |
| Ubuntu | Native support under development; no qualified recipient release. |
| macOS | Native support under development; no qualified recipient release. |
| Native Windows | Native support requested and under development; no qualified recipient release. |

WSL is not native Windows and cannot satisfy the Windows trial. A compiled backend or an experimental archive alone does not establish platform support. Read [release status](release-status.md) and [current platform engineering status](PLATFORM_SUPPORT.md) before inviting a participant; qualify a new platform artifact before asking an unfamiliar user to rely on it.

## Read implementation and verification separately

Platform APIs, inventory providers, gateway code and packaging scaffolds can be implemented while installation remains unavailable. Native APIs in source do not prove that the packaged plugin builds, confines checks or preserves approvals correctly on a recipient machine.

Read status in this order:

| Reported state | Meaning for a trial |
| --- | --- |
| Planned | Accepted scope exists; implementation is still required. |
| Implemented | The agent records that the code or documentation was delivered. This is a claim, not passing evidence. |
| Verified | Current passing evidence covers the required criteria and prerequisites for that milestone. It proves its stated coverage only. |
| Stale | Previous evidence no longer matches current inputs; rerun the appropriate approved checks. |
| Blocked | A required prerequisite or execution condition prevents verification; retain the limitation explicitly. |

Adding accepted scope changes the denominator; it does not erase unfinished work. The current expansion adds nine requirements to the prior twenty-six, yielding thirty-five tracked milestones. This is a dated explanation of the plan expansion, not a live completion count. Ask the running checker for current counts, scope history and evidence freshness. User-facing installation pages should describe artifact availability without hardcoding a project completion percentage.

A Linux passing check cannot qualify native Windows or macOS. Native Windows stays unavailable until native builds, protected IPC/state, exact human approval, restricted execution and the recipient lifecycle have actual evidence. New platform source primitives keep that work visible without promising a working installation.

### Proposed concise platform messages

- Published Fedora beta: “Fedora 44 x86_64 beta available. Review prerequisites before installing.”
- Ubuntu: “Ubuntu support is in development. No qualified user package is available.”
- Native macOS: “Native macOS support is in development. Installation is not yet available.”
- Native Windows: “Native Windows support is in development. Installation is not yet available. WSL does not qualify this platform.”
- Experimental backend unavailable: “This development backend cannot activate safely. No check was run.”

These strings are proposals for product copy; they are not observations of implemented interface behavior.

## Installation text to give participants

**Fedora 44 x86_64:** “You can try the 0.4.0-dev beta. Check the [installation guide](USER_GUIDE.md#install) first: it requires the documented system Python, Git, glibc, RPM and bubblewrap setup. In Codex, open `/plugins`, add `lwdot90/Progress-checker-for-Codex` as a marketplace, install Progress Checker and open a new chat if prompted. In your disposable Git project, say ‘Track this project’ and confirm its reported root. This is a development beta; installation does not run your project checks.”

**Ubuntu:** “There is no qualified Ubuntu installation yet. Do not install RPM to make the Fedora package appear supported. The target is Ubuntu 24.04 x86_64, but package compatibility, namespace/AppArmor behavior and the full recipient workflow still need qualification. See the [Ubuntu work](UBUNTU.md).”

**macOS:** “There is no qualified macOS installation yet. Experimental packages require native architecture-matched executables and recipient runtime delivery that remains under development. No published minimum macOS version or ordinary-user prerequisite set has been qualified. See the [native macOS work](MACOS.md).”

**Native Windows:** “There is no native Windows user package yet. The native gateway, protected approval transport, restricted check execution and recipient lifecycle must be completed and qualified. A development ZIP or WSL installation is not native Windows support. See the [native Windows work](WINDOWS.md).”

Do not substitute an experimental packaging command for an installation guide. When a platform release is qualified, replace its unavailable text with the artifact identity, supported OS versions, actual prerequisites and tested install/update/removal instructions.

## Consent and setup

Invite someone who has not helped build the plugin. Explain what is being observed, that participation is voluntary, and that they can stop or decline publication. Obtain separate agreement before recording their screen or publishing identifiable feedback. Do not send invitations or contact someone on the user's behalf without authorization.

Use a disposable copy of a small Git project without personal data. The [first-check example](../examples/first-check/README.md) provides one. Record the actual OS, architecture, Codex version, plugin version and artifact identity. Let the participant follow the public installation guide; record where assistance was needed rather than presenting an assisted step as independently discovered.

## Tasks to observe

1. Install from the documented user channel, without a source checkout or Rust toolchain.
2. Open the project and say “Track this project.” Confirm the returned root and preserve the example's existing plan.
3. Ask for progress before execution. Distinguish an implementation claim from a passing check.
4. Ask for the exact approval command. The participant reviews and confirms it in their own interactive terminal while the Codex chat remains open. The observer and agent must not enter the confirmation for them.
5. Return to the same chat and run the approved check. Capture its public run ID and stated coverage.
6. Break the greeting, observe stale evidence, rerun the unchanged check and observe failure. Restore it and obtain a fresh pass.
7. Close and reopen the project session; confirm progress and project binding persist.
8. If a reviewed update is available, observe update and state retention. Otherwise mark update “not attempted.” Observe removal and preservation of the project and its evidence.

Record unexpected prompts, errors, elapsed time and any help given. Do not turn a stalled or failed step into a pass. Stop dependent steps when prerequisites fail.

## Error text and safe recovery

These are proposed explanations for trial observers to give users, not a claim that every experimental backend already displays these exact messages.

| Situation | Explanation and recovery |
| --- | --- |
| Linux payload opened on native Windows or macOS | “This package requires Linux. Native support is not released. Stop this installation and follow the platform status page; do not replace binaries or disable sandbox checks.” Remove the experimental plugin through Codex if desired, preserving project files and private records. |
| Experimental native Windows gateway cannot activate | “The native backend is incomplete; no check was run. This development package is not ready for user installation.” Keep the public error and artifact identity for a report. Do not use WSL as proof that native activation works. |
| Ubuntu package or namespace prerequisite is missing | “This Ubuntu artifact has not completed qualification. Do not install RPM or disable AppArmor globally to make the Fedora package run.” Record the actual error and stop dependent trial steps. |
| Example finds the parent repository | “The example must be a separate Git worktree outside the checker checkout.” Create a new disposable copy, including its hidden configuration, initialize that copy with Git and open a new project chat. Preserve the mistakenly selected project's state; never delete it as a reset. |
| Connection is already bound to another project | “This connection cannot switch projects.” Open a new chat in the intended worktree and explicitly track it. Do not repoint the connection's private state. |
| Approval is absent or invalidated | “The exact current definition needs your approval.” Review the supplied command yourself in an interactive terminal. The agent must not enter the confirmation. Do not copy an approval record from another project or version. |
| Evidence is stale after an edit | “The prior result no longer matches current inputs.” Review the change and rerun the unchanged approved check, or review and approve a revised definition. Staleness does not require deleting the plan or evidence. |

For an unavailable plugin or writer, preserve project configuration and private records, capture the public error, and use the documented restart/update procedure for that artifact. Do not kill unrelated processes or remove state directories as a generic recovery step. Normal Codex work can continue while checker verification is unavailable; report that work as unverified.

## Ask for feedback

Ask whether the status report revealed anything useful beyond a normal agent reply or CI, whether the second-terminal approval was understandable, and whether the participant would use it again. Record their words only with consent. Avoid leading them toward a positive response.

## Publish a bounded receipt

A receipt should include the date, artifact identity, environment, tasks attempted, observed results, help required and unresolved issues. Describe an anonymous participant unless they consent to identification. Share only approved excerpts or screenshots; omit credentials, paths containing personal information and private approval/evidence files.

A completed first-user trial does not qualify another operating system or a later artifact. Keep the checklist of observed tasks distinct from configured acceptance checks and their freshness. Link consented feedback using the [beta feedback template](https://github.com/lwdot90/Progress-checker-for-Codex/issues/new?template=beta-feedback.md); do not invent a participant, quote or result.
