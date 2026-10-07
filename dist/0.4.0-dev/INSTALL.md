# Progress Checker 0.4.0-dev

Fedora 44 x86_64 beta candidate. Native marketplace installation is available. The final human approval
trial remains pending; see the repository qualification record.
This is a custom Git marketplace, not a universal-directory listing.

Requires Python 3.11+ at `/usr/bin/python3`, Git at `/usr/bin/git`, glibc 2.39+,
`/usr/bin/rpm` and `/usr/lib/sysimage/rpm`. Approved checks also require
`/usr/bin/bwrap` with working Linux namespaces. No Rust or source build is needed.

## Install once

1. In Codex, open `/plugins`, choose **Add marketplace**, and enter
   `lwdot90/Progress-checker-for-Codex`.
2. Select **Progress Checker**, choose **Install plugin**, and start a new chat
   so its tools and skill load.
3. In the Git project you want to track, say **“Track this project. Propose
   milestones and acceptance checks for my review.”**

Review the proposed plan before accepting it. Ask **“What's the progress?”**
to read implementation claims and current verification. Use a separate Codex
session for another project; no additional installation is needed.

## Approve a check while Codex stays open

For a new or changed check, the agent supplies the exact packaged CLI approval
command with your project and state paths. **Keep Codex open.** Run that command
yourself in a separate interactive terminal, review the check definition, and
confirm only if you trust it. Agents must never answer the confirmation.

Approval saves a grant; it does not execute the check. Return to the same chat
and request the approved check. Source edits can stale evidence while retaining
an unchanged grant; plan revisions invalidate grants. Installation, tracking and
service startup never approve or run checks.

## Optional: migrate an older installation

If your existing installation uses a custom `--state-dir` or data location,
retain that explicit binding through the archive installer or existing legacy
entry. Browser installation cannot automatically migrate it. Codex does not
forward `XDG_DATA_HOME` to bundled MCP by default: setting it in your shell alone
does not preserve a custom state base. Do not enable both entries against
different stores and assume their progress is shared.

For an installation using the default state base, an existing archive can already
register `progress-global` from a local source. Remove that registration before
adding the Git source. If an older version is active, close its Codex sessions once
so its old service exits; then run these native commands in your terminal:

```sh
codex plugin remove progress-checker@progress-global
codex plugin marketplace remove progress-global
```

Then follow the three installation steps above. Native removal deletes the
plugin cache/registration and preserves project configuration, managed
instructions and external evidence. The default state base remains
`~/.local/share/progress-checker`. This one-time upgrade restart is separate
from routine 0.4 check approval, which keeps Codex open.

## Limits

The skill supplies the current session's Git root explicitly; the plugin cannot
independently infer or attest it. Confirm the returned canonical root before
changing plans or claims. Each connection remains bound to one project.
Implementation claims are not passing evidence. Other platforms, public-directory
availability and this candidate's native browser flow remain unqualified.
