# Platform support status

This table separates published behavior, source implementation and recipient verification. New native primitives and package preparation scripts do not establish a supported platform. The frozen 0.4 Linux payload remains unchanged.

| Target | Current delivery / source work | Verification still required |
| --- | --- | --- |
| Fedora 44 x86_64 | Published Linux payload; historical Fedora recipient work and first-use observations exist. The current source candidate contains further changes. | Root Linux typecheck passed during this development round; it is not recipient qualification. Fresh regression and complete release qualification for the candidate, including exact human approval, restricted checks, update and removal. Historical receipts cannot verify changed source. |
| Ubuntu x86_64 | dpkg inventory provider implemented in source alongside RPM; Linux runtime and packaging work in progress. No qualified Ubuntu user release. | Ordinary Ubuntu host, namespace/AppArmor policy, trusted executable paths, glibc/dependency compatibility, inventory mutation freshness and source-free recipient lifecycle. |
| Native Windows x86_64 | Native gateway skeleton, named-pipe/peer-lifetime foundations, LPAC attribute and Job Object primitives, inventory/identity work and ZIP preparation. Native approval transport and restricted execution remain fail closed. No user release. | Root cross-target typechecks passed for Windows GNU and MSVC; neither is native runtime or recipient evidence. Complete native build integration, authenticated ACL-protected IPC/state, exact human-terminal approval, dependency identity, race-resistant paths, filesystem/network confinement, process cleanup and clean-recipient install/update/removal. |
| Native macOS Apple silicon / Intel | Experimental process, inventory and sandbox work; architecture-specific packaging scaffold. No qualified user release. | Root cross-target typecheck passed for Apple-silicon macOS; no native macOS runtime or recipient pass is claimed, and Intel remains separate. Complete native build and backend integration, approval/IPC identity, private-state protection, sandbox denial probes, dependency freshness, relocatable runtime delivery, signing/notarization decision and clean-recipient lifecycle per architecture. |
| WSL2 | Separate, lower-priority Linux-environment prerequisite observation and qualification scaffold. Neither native Windows support nor a qualified WSL release. | Underlying Linux distribution qualification plus an actual WSL2 Linux-filesystem recipient trial, Windows/WSL/Linux version receipt, restricted checks and shutdown/reconnect lifecycle. Windows drive mounts require separate evaluation. |

## Release prerequisites shared by every target

- Bind human approval to the exact command, executable/dependencies, source, environment and working directory; invalidate grants when their binding changes.
- Keep approval unavailable through MCP and preserve private evidence outside project-controlled files.
- Prove restricted checks cannot access private state, unrelated home secrets or networking; timeout and cancellation must clean up descendants and bound logs.
- Demonstrate source and environment mutation make evidence stale rather than preserving a false passing result.
- Exercise installation, first tracking, passing/failing checks, restart, changed-version update and removal with a source-free artifact on the actual target.
- Retain build provenance and fresh passing receipts. An observation, successful cross-compilation or implementation claim does not satisfy recipient qualification.

Native Windows is an independent workstream. WSL cannot satisfy its acceptance criteria. See [native Windows](WINDOWS.md), [native macOS](MACOS.md), [Ubuntu investigation](PORTABILITY.md) and [WSL2](WSL2.md) for details. The Ubuntu investigation document describes the original migration proposal; inspect current source and current evidence before interpreting its older implementation wording.

## Registered qualification gates

`scripts/check-platform-support.py --platform ubuntu|macos|windows|wsl2` is the fail-closed qualification entrypoint. It currently exits **2 / BLOCKED** for every target, including a matching native host, because a trusted original recipient collector is missing. It accepts no human report or external receipt as proof. WSL kernel hints do not prove WSL2 or native Windows. Ubuntu's gate requires an ordinary Ubuntu host rather than silently substituting WSL.

The current runner explicitly returns an unknown execution outcome outside Linux; native Windows AppContainer/ACL confinement and native macOS sandbox enforcement plus detached-descendant cleanup are unqualified. Platform primitives and packaging scripts cannot change that result. Unit tests of this guard exercise its refusal behavior; passing those tests does not verify a platform release.
