//! Native Windows execution boundary, deliberately unavailable until qualified.
//!
//! A Job Object controls lifetime, not filesystem/network isolation. A restricted
//! token alone does not implement the Linux runner's no-home/no-state contract.
//! Do not turn this gate into `std::process::Command` as a fallback.
//!
//! Integration: runner dispatch may use `unavailable_reason()` for Outcome::Unknown.
//! This module must not create authorization, accept an agent-supplied capability
//! boolean, or report a passing check without an actual contained child process.
//!
//! Microsoft primary documentation consulted 2026-10-12:
//! - https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
//! - https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
//! - https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
//! - https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
//! - https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
//! Ordinary AppContainer baseline access and broker-created processes require
//! explicit threat-model review; API availability is not a qualification result.

/// Public diagnostic: unsupported execution is different from a failing check.
pub const UNAVAILABLE_REASON: &str =
    "native Windows restricted execution is not implemented or qualified; no command was started";

/// Required native implementation work, in launch order. These describe code and
/// adversarial qualification requirements; they are not runtime evidence.
pub const REQUIRED_GUARANTEES: &[&str] = &[
    "Revalidate the existing human grant against exact argv, environment, cwd, source, and executable identity",
    "Open canonical executable/project handles and reject junction/reparse-point escapes and replacement races",
    "Construct an LPAC/AppContainer identity without network capabilities or loopback exemptions",
    "Grant only isolated project snapshot and required runtime reads; never grant caller home or checker state",
    "Build explicit UTF-16 environment and lossless approved-argument command line without a shell",
    "Create a suspended child with explicit application path and restricted inherited pipe handles",
    "Assign child to a non-inheritable kill-on-close Job Object with both breakaway flags disabled before resume",
    "Abort and terminate suspended child if any security capability, ACL, job, or handle restriction fails",
    "On timeout/cancellation/drop terminate the job, wait for descendants, and bound log drainage",
    "Qualify filesystem, network, broker/WMI escape, argument roundtrip, and detached descendant adversarial probes on Windows",
];

/// Fail closed independently of host discovery. Available Win32 APIs alone are
/// insufficient evidence that a particular launch satisfies the policy.
pub fn unavailable_reason() -> &'static str {
    UNAVAILABLE_REASON
}
