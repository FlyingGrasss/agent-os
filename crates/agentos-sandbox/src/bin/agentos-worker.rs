//! The confined worker image for the pool tests.
//!
//! The pool daemon forks this binary and confines it. It must be a plain main
//! that never drags in the test harness, because the seccomp profile for a
//! worker does not honour any thread-spawning syscall; a libtest process
//! attempting to run a `#[test]` cannot even start. The worker loop itself lives
//! in the library as [`agentos_sandbox::pool::serve_worker`], and this main only
//! supplies the descriptor.
//!
//! `CONTROL_FD_ENV` names the control socket; it is set by the daemon's
//! environment construction rather than by an argv entry so the command line
//! stays exactly what the caller asked for - the same reason the real
//! interpreter has a line like this.
//!
//! # Why this file still builds on Windows
//!
//! The worker loop is Unix-only, because the pool is `fork`/`execveat` plus a
//! Unix control socket. The binary is still compiled everywhere so that a
//! Windows build of the workspace needs no cfg in every dependent manifest, and
//! so the refusal is a visible runtime exit rather than a link error somebody
//! works around by deleting the dependency. Same reasoning, and same exit code
//! convention, as `agentos-q-extractor`.

#[cfg(unix)]
const CONTROL_FD_ENV: &str = "AGENTOS_SANDBOX_POOL_CTL_FD";

/// `EX_SOFTWARE`: distinct from every code `serve_worker` returns, so a caller
/// that somehow reached this binary on the wrong platform cannot mistake it for
/// a worker's own refusal.
#[cfg(not(unix))]
const EXIT_UNSUPPORTED_HOST: i32 = 70;

#[cfg(unix)]
fn run() -> ! {
    use agentos_sandbox::pool::serve_worker;
    let fd = std::env::var(CONTROL_FD_ENV)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or_else(|| std::process::exit(70));
    serve_worker(fd)
}

/// Not a Unix target: this binary cannot be confined, so it refuses.
///
/// Reading a request without confinement would be worse than refusing. The pool
/// exists to make "every worker is confined" true by construction, and an image
/// that quietly served requests unconfined would be a hole in exactly the
/// property the pool is for.
#[cfg(not(unix))]
fn run() -> ! {
    eprintln!(
        "agentos-worker requires a Unix host: the pool forks and confines its workers with \
         execveat and a control socket, and neither exists on this target. Refusing rather than \
         serving requests unconfined."
    );
    std::process::exit(EXIT_UNSUPPORTED_HOST)
}

fn main() {
    run()
}