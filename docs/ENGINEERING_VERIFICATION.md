# Engineering regression verification

The workspace regression suite exercises executable ownership, process state,
service sockets and nested sandbox behavior. A full host run and a configured
check inside the restricted product sandbox have different environments. A
passing host run is useful diagnostic information; it cannot replace fresh
passing evidence for `engineering-unit-tests`.

## Current boundary

Do not expose the host home, private checker state or host service sockets to
make fixture tests pass. Do not run the registered command directly to bypass
its approval gate. Do not synthesize grants or import handwritten evidence.

`scripts/prepare-engineering-recipient.py` prepares a bounded public source
snapshot under `.local`. It copies reviewed source roots, refuses symlinks,
records every input hash, and creates a public job descriptor. It performs no
build, check execution, approval or container launch. Its descriptor explicitly
states that qualification is unavailable.

Preparation example:

```sh
python3 scripts/prepare-engineering-recipient.py \
  --output .local/engineering-recipient-review
```

## Remaining implementation

1. Split environment-independent regressions from recipient integration cases
   without dropping assertions or changing their required coverage.
2. Pin a clean recipient image, actual Rust toolchain, offline dependencies and
   copied source manifest. Preserve system executable ownership in that image.
3. Implement a bounded external job adapter that binds those exact inputs and
   commands. An independently operated terminal must obtain the required human
   approval; the agent must not answer the confirmation prompt.
4. Revalidate immutable inputs immediately before execution and generate the
   result during that run. A sandboxed acceptance command must independently
   validate the bound result through a trusted adapter, not an arbitrary file.
5. Revise the project plan and check definitions explicitly. Changed definitions
   invalidate existing approvals and need new exact human approval.

Until that adapter and its trust validation exist, the engineering regression
milestones remain unverified. Source snapshot hashes are preparation records,
not execution evidence. A clean recipient experiment also does not by itself
qualify native Windows, Ubuntu or macOS.

## Platform development diagnostic roster

The separately approved `scripts/check-platform-development.sh` runs platform,
environment, fingerprint and environment-framing unit suites, plus nine exact
runner cases covering controls, credential normalization, overlapping and
crossing credential intervals, capture-boundary truncation, split UTF-8,
bounded output, malformed UTF-8 and trusted sandbox exit-status parsing.
The crossing-interval case is
`runner::tests::crossing_credential_intervals_hide_the_entire_union`.
Gateway and MCP unit suites and mocked/static Python packaging, recipient and
source-artifact checks complete the diagnostic. Every Cargo selection must
report at least one passing test. This roster creates no approval or native
qualification and does not replace the full engineering acceptance check.
