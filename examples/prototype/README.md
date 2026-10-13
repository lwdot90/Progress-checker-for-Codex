# Phase 0 panel fixture

After validating the modified Codex build, copy the `.progress-checker` directory into the root of a Git repository chosen for the prototype. Its `config.json` opts that project into the embedded panel and supplies three illustrative milestones. From this project's root, launch it with `scripts/run-prototype.sh --cd /path/to/chosen/git/repository`; see the root README for local login and validation. Stock Codex does not display this panel.

Use `/progress` to hide or show the panel. Visibility is saved per worktree under the selected Codex data directory (the wrapper defaults to `.local/codex-home`); it does not alter these fixtures. The full source, Rust toolchain, helpers, and build caches live under this project's `.local/` directory.

The configuration defines milestones and acceptance criteria; implementation claims belong only in `state.json`. This sample has two `implemented` claims and one `planned` claim. They are demonstration labels, not assertions about work completed in the chosen repository.

See the [config schema](../../schemas/progress-panel-config.schema.json) and [cached-claims schema](../../schemas/progress-panel-cached-claims.schema.json) for the Phase 0 file contracts. References, duplicate IDs, and dependency cycles are also checked by the Rust parser.

The minimal Phase 0 cached claim-state format is:

```json
{
  "schema_version": 1,
  "project_id": "progress-panel-demo",
  "milestones": [
    {
      "milestone_id": "project-opt-in",
      "implementation_claim": "implemented"
    }
  ]
}
```

`project_id` must match the configuration. Each `milestone_id` names a configured milestone, and `implementation_claim` is either `planned` or `implemented`. Unclaimed milestones default to `planned`. Restore this state as **unvalidated**, with **freshness unknown**. The fixture contains no check results, evidence, derived completion statuses, or verified milestones; Phase 0 performs no verification.

The Cargo commands and integration-test names in `config.json` are illustrative and may not exist in the chosen repository. Phase 0 only reads the configuration and cached claims; it never executes these commands. Opening an opted-in project does not authorize command execution.

This repository-local `state.json` is a read-only sample input for the first prototype. The later checker service will own runtime state outside tracked source; this fixture is not that service's result format or persistence implementation.
