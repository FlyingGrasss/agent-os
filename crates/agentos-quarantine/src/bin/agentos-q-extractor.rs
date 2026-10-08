//! A reference quarantined extractor.
//!
//! The child binary [`host::SandboxedExtractor`](crate::host::SandboxedExtractor)
//! spawns. It is a separate binary rather than a function in this crate because
//! the engine has to initialise *after* confinement: a model client that opened
//! its socket before `landlock_restrict_self` would be holding a live socket in a
//! process whose `socket(2)` is about to be denied. A separate binary makes
//! "initialise after confinement" the only order there is.
//!
//! # The engine is a no-op, and that is the point
//!
//! This binary never reads the document and never names a value. It exists so
//! that I2 can be *demonstrated* against a real kernel rather than argued about:
//! `agentos-quarantine`'s escape tests point [`SandboxedExtractor`] at this binary
//! and assert that it is confined - no socket, no path, no `/etc/passwd`, only
//! the descriptor it was handed.
//!
//! Wiring an actual model in is a deployment decision, not a crate decision. When
//! that happens it goes behind the same [`ExtractionEngine`] trait, inside this
//! same `main`, after the same [`serve`] call. Nothing about the boundary moves.
//!
//! # What a real engine may and may not do here
//!
//! By the time an engine runs, `Confine::apply` and `apply_seccomp` have both
//! returned success and the attestation has been checked. So an engine may read
//! the document descriptor, compute, and return values. It may not open a path,
//! open a socket, or spawn a process - those syscalls are `EACCES` and `ENOSYS`
//! respectively, and no amount of trying changes that.
//!
//! What it *can* still do is return whatever it likes as a value. That is why
//! every value is validated against the schema host-side and a field that fails
//! its constraint is quarantined rather than coerced.
//!
//! # Why this file still builds on Windows
//!
//! [`serve_on_stdin`] is Linux-only, because it applies Landlock and seccomp. The
//! binary is still compiled everywhere so that a Windows build of the workspace
//! does not need a cfg in every dependent manifest, and so the refusal is a
//! visible runtime exit rather than a link error somebody works around by
//! removing the dependency.

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
fn run() -> i32 {
    use agentos_quarantine::{serve_on_stdin, Limits, NoEngine};
    let limits = Limits::default();
    serve_on_stdin(&NoEngine, &limits)
}

/// Not a Linux target: this binary cannot confine anything, so it refuses.
///
/// The exit code is deliberately distinct from every `serve` exit code, so a
/// caller that somehow ended up here cannot mistake it for a refusal from a
/// confined extractor.
#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    eprintln!(
        "agentos-q-extractor requires a Linux host: the extractor applies Landlock and seccomp, \
         neither of which exists on this target. Refusing rather than reading the document \
         unconfined."
    );
    78 // EX_CONFIG
}

fn main() -> std::process::ExitCode {
    // One exit path. Nothing runs after `serve`, because continuing would mean
    // running code in a process the confinement was installed to cover.
    std::process::ExitCode::from(run().clamp(0, 255) as u8)
}