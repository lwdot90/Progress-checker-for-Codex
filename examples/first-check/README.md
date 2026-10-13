# Your first real check

This tiny project uses the Python standard library and `/usr/bin/python3`, which fits the current Linux command policy. It already contains a one-milestone checker plan.

Use it with the published **Fedora 44 x86_64 beta** and its [documented prerequisites](../../docs/release-status.md) and [installation guide](../../docs/USER_GUIDE.md#install). Ubuntu, macOS and **native Windows** support is under development and has no qualified recipient release. This example's `/usr/bin/python3` command is not a native Windows command; WSL does not establish native Windows support.

Allow a few minutes for the trial. It demonstrates one greeting assertion, not complete project correctness.

Copy this complete folder, including its hidden `.progress-checker` directory, to a new folder **outside the Progress Checker checkout**. Initialize that copy with `git init`, and open it in a separate Codex session with Progress Checker installed. The copy must be its own Git worktree; tracking a nested folder would otherwise select the parent repository.

Optionally, run the example directly yourself from the copied folder. This checks the sample, but it does not create Progress Checker verification:

```bash
/usr/bin/python3 -m unittest -v test_greeting
```

Then try these three prompts in Codex:

```text
Track this project; preserve its existing greeting plan.
Review the greeting implementation and record it as implemented if it meets the criterion.
Show me the approval command for greeting-tests.
```

Keep Codex open. Run the supplied approval command yourself in a second interactive terminal and review its exact definition. Return to the same chat, ask Codex to run `greeting-tests`, and ask “What's the progress?” A passing current check can verify the greeting milestone.

Change `greeting.py` to return `"Hi!"` and ask for progress again: the earlier result should become out of date. Ask Codex to rerun the unchanged check; its saved approval can be reused and the test should fail. Restore the original implementation and rerun for a fresh pass.

This is an example to run voluntarily. Copying it, opening the project, or tracking it never approves or executes the check.

For an observed trial with someone new to the plugin, follow [the first-user trial procedure](../../docs/FIRST_USER_TRIAL.md). No independent-user result is claimed by these instructions.
