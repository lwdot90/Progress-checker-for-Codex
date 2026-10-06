---
name: progress-checker
description: Plan project milestones and report progress using the local Progress Checker tools. Use when setting up project tracking, recording implementation claims, checking verification, or explaining remaining work.
---

Use the checker attached to this repository to distinguish planned work, implementation claims, and current verification. Read `checker_get_project` before changing anything; confirm the returned canonical root matches the project being discussed. If the plugin is bound to a different repository, use its setup command for the intended repository before proceeding.

When planning, derive explicit outcomes and acceptance criteria from the user's requirements. Define the checks that establish each criterion and any milestone dependencies. Show scope changes explicitly; never remove unfinished requirements silently to reach 100%. Submit the accepted complete configuration through `checker_submit_plan`, supplying the revision and config hash from `checker_get_project` plus a reason. Read scope changes with `checker_get_plan_history`; retain unchanged requirements. Changed milestone definitions reset their implementation claims, and plan revisions invalidate execution approvals.

Read the current revision before `checker_set_claim`. Mark work implemented when its changes exist, then use `checker_get_progress` for verification. A queued check or implementation claim is not passing evidence. Changed files can make previous passes stale. Passing checks establish only their stated coverage.

`checker_run_checks` can execute only commands already approved by a human for the exact definition. Neither a plan nor this skill grants approval. If approval is missing, give the user the packaged human CLI command to review; do not feed its confirmation prompt yourself. Use `checker_get_run` and bounded `checker_get_log` to explain failures.

If the checker is unavailable, continue normal Codex work and describe progress as unverified. Standard Codex exposes tools and this skill; the embedded progress panel is an optional feature of the maintained Codex fork.
