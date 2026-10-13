# First-user trial

Use this guide if you are trying Progress Checker for the first time. The beta currently supports Fedora 44 x86_64. Ubuntu, macOS and Windows are not yet supported.

Choose an ordinary Git project you already use and one small change with an acceptance check you understand. Use sample data and avoid sharing credentials or private checker files. This trial is voluntary; report only observations you are comfortable publishing.

1. Follow the [installation guide](USER_GUIDE.md#install).
2. In your project, say **“Track this project.”** Confirm that Codex reports the intended project.
3. Describe the small change and ask Codex for a milestone with an acceptance check. Review the command, what it proves and the plan before accepting it.
4. Let Codex implement the change. Ask **“What’s the progress?”** Observe the difference between its implementation claim and verification.
5. Ask for the approval command. Keep Codex open and run that command yourself in another interactive terminal. Review and confirm the exact check if you trust it; then return to the same chat and ask Codex to run it.
6. Read the result. A failure should leave the criterion unverified; a pass can verify only its stated coverage and verified prerequisites. Ask Codex for the run ID so you can reference the public result.
7. Make a small source edit and ask for progress again. Observe whether the earlier result is out of date. If you want to rerun an unchanged check, it should reuse its approval; an accepted plan change requires fresh approval.

Record your OS, Codex and plugin versions, the steps you actually completed, and where you needed help. In particular: did the report reveal anything useful that a normal agent reply or your CI would have missed? Was the second terminal tolerable? Would you use this on another feature?

Use the [beta feedback template](https://github.com/lwdot90/Progress-checker-for-Codex/issues/new?template=beta-feedback.md). A partial or failed trial is useful feedback. No completed trial or participant is claimed until there is an actual report. Developer and agent demonstrations are tracked separately.
