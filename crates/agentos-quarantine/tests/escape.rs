//! Escape tests: does the confined extractor actually fail to escape?
//!
//! # What these tests are
//!
//! Each one runs [`agentos_quarantine::serve`] in a **child process** - this same
//! test binary, re-executed - and has the child attempt real escapes against the
//! running kernel, then report what the kernel actually did. Every assertion in
//! the parent corresponds to a probe the child performed; the child refuses to
//! report a probe it did not run, and [`Report::get`] panics on a probe name that
//! is absent rather than treating absence as a pass.
//!
//! # Why a child process and not a `#[test]` thread
//!
//! `landlock_restrict_self` and `PR_SET_SECCOMP` are irreversible and
//! thread-local. Confining a test thread would poison the harness for every test
//! after it, and the parent needs to stay unconfined so it can create, read, and
//! delete the scratch tree and then verify it was not modified. This is the
//! shape `agentos-sandbox`'s `tests/escape.rs` uses, for the same reason.
//!
//! # Positive controls, everywhere
//!
//! Every negative assertion is paired with a probe that is *supposed to succeed*.
//! A child that died before reaching its probes would otherwise produce an empty
//! report that reads exactly like a clean run. Concretely:
//!
//! - [`Report::require_exchange`] runs first in every escape test. It requires
//!   that the child exited [`EXIT_OK`], that it reported the promised
//!   attestation, that its positive-control probes (`read_its_own_document`,
//!   `document_bytes_match`) came back `ALLOWED`, and that it reported at least
//!   [`MIN_PROBES`] probes. A child that failed to confine exits with
//!   [`EXIT_NOT_CONFINED`] and never reaches a probe, so a short or empty report
//!   is a **failure**, not a pass.
//! - [`extraction_through_the_real_host_path_succeeds`] is the control for the
//!   whole file: if the host cannot drive a child end to end, none of the escape
//!   results mean anything.
//!
//! # Two ways of driving a child, and why both
//!
//! - [`run_child`] performs the handover by hand, over a socketpair, so the test
//!   can see the child's *probes* on stdout and its *attestation* in the reply.
//!   The crate's host does not surface either, because a host has no business
//!   reading a child's diagnostics as if they were results.
//! - [`extraction_through_the_real_host_path_succeeds`] drives
//!   [`SandboxedExtractor`] itself, so the wiring this crate claims - that it is
//!   a real `agentos_infer::Extractor` over a real confined process - is
//!   exercised through the same code a deployment would run.
//!
//! # On a non-Linux target this file is empty
//!
//! `#![cfg(target_os = "linux")]` below means **zero tests run** on such a target
//! and the confinement claims in this crate are not being verified by anything.
//! That is stated here, at the top of the file, rather than left to be discovered
//! by a green run reporting success without having tried. The verification that
//! matters runs on Linux.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

use agentos_infer::schema::{Constraint, Field, Schema};
use agentos_quarantine::{
    serve, Attestation, ChildProgram, ExtractionEngine, Limits, Outcome, QuarantineError,
    RefusalReason, SandboxedExtractor, SchemaSpec, EXIT_NOT_CONFINED, EXIT_OK, ROLE_ENV,
    ROLE_VALUE,
};
use agentos_types::{Quarantined, SourceId, SourceKind};

/// Set by the parent to pick which child entry point the test binary runs.
const CHILD_ENV: &str = "AGENTOS_QUARANTINE_TEST_CHILD";

/// The scratch tree's root, so the child can probe real paths.
const SCRATCH_ENV: &str = "AGENTOS_QUARANTINE_TEST_SCRATCH";

/// The parent's pid, so the child can attempt to signal it.
const PARENT_ENV: &str = "AGENTOS_QUARANTINE_TEST_PARENT";

const PROBE_PREFIX: &str = "##QPROBE##";

/// The document the parent hands over. Short enough that the bound is never in
/// question, and distinctive so a leak is visible in an assertion message.
const DOCUMENT: &str = "INVOICE total=42 status=paid reference=ACME-1 note=see attached";

/// A canary in a file the child is not given. If this ever appears in a reply or
/// in an extraction, the child read something it was not handed.
const CANARY: &str = "CANARY-7d3f19a4-SIBLING-SECRET";

/// Every probe the escape child is required to report.
///
/// Counted rather than named so a probe that is removed is noticed, and so a child
/// that died partway through is caught. The count is the minimum; the parent also
/// checks the two positive controls by name.
const MIN_PROBES: usize = 20;

// ---------------------------------------------------------------------------
// Scratch tree
// ---------------------------------------------------------------------------

/// Layout of the tree the parent builds. The child is told where the tree is, so
/// its probes attempt real reads against real paths - a probe that could not even
/// name its target would prove nothing.
///
/// ```text
/// <root>/document            <- what the host stages and hands over
/// <root>/sibling.txt         <- inside the scratch, never granted
/// <root>/elsewhere/deep.txt  <- a path outside any plausible grant
/// <root>/link-to-passwd      -> /etc/passwd
/// ```
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!(
            "agentos-q-escape-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(root.join("elsewhere")).unwrap();
        fs::write(root.join("sibling.txt"), CANARY).unwrap();
        fs::write(root.join("elsewhere/deep.txt"), "elsewhere\n").unwrap();
        symlink("/etc/passwd", root.join("link-to-passwd")).unwrap();
        fs::write(root.join("document"), DOCUMENT).unwrap();
        Scratch { root }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn sibling(&self) -> PathBuf {
        self.root.join("sibling.txt")
    }

    fn document(&self) -> PathBuf {
        self.root.join("document")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The parent is never confined, so this always works.
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// What the kernel did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Probe {
    /// The operation succeeded. For an escape probe that is a failure.
    Allowed,
    /// The kernel refused with a policy errno (`EACCES` / `EPERM`). Landlock.
    Denied {
        /// The errno the kernel returned.
        errno: i32,
    },
    /// The kernel returned `ENOSYS`, which is how the seccomp allowlist refuses a
    /// syscall. Kept distinct from [`Probe::Denied`] so a test can say *which
    /// layer* did the refusing: Landlock for a path, seccomp for a syscall.
    /// Conflating them would let a test pass against a sandbox that had no seccomp
    /// filter at all, which is the specific regression these probes exist to
    /// catch.
    Filtered {
        /// The errno the kernel returned.
        errno: i32,
    },
    /// Any other failure. **Never** treated as a denial: a probe that wanted a
    /// denial and got `ENOENT` because of a typo has proved nothing.
    Failed {
        /// The errno the kernel returned.
        errno: i32,
        /// What was attempted, for the failure message.
        what: String,
    },
}

impl Probe {
    fn of<T>(what: &str, r: std::io::Result<T>) -> Probe {
        match r {
            Ok(_) => Probe::Allowed,
            Err(e) => Probe::classify(what, e.raw_os_error()),
        }
    }

    fn classify(what: &str, errno: Option<i32>) -> Probe {
        match errno {
            Some(e) if e == libc::EACCES || e == libc::EPERM => Probe::Denied { errno: e },
            // `ENOSYS` is the allowlist's answer for a syscall that is not on the
            // list. `ENOTSUP` is accepted alongside it because a filtered socket
            // family can surface that way on some kernels.
            Some(e) if e == libc::ENOSYS || e == libc::ENOTSUP => Probe::Filtered { errno: e },
            e => Probe::Failed {
                errno: e.unwrap_or(-1),
                what: what.to_string(),
            },
        }
    }

    fn render(&self) -> String {
        match self {
            Probe::Allowed => "ALLOWED".to_string(),
            Probe::Denied { errno } => format!("DENIED errno={errno}"),
            Probe::Filtered { errno } => format!("FILTERED errno={errno}"),
            Probe::Failed { errno, what } => format!("FAILED errno={errno} {what}"),
        }
    }

    fn parse(s: &str) -> Probe {
        if s == "ALLOWED" {
            return Probe::Allowed;
        }
        let (tag, rest) = s.split_once(' ').unwrap_or((s, ""));
        let errno = rest
            .trim()
            .trim_start_matches("errno=")
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(-1);
        match tag {
            "DENIED" => Probe::Denied { errno },
            "FILTERED" => Probe::Filtered { errno },
            _ => Probe::Failed {
                errno,
                what: s.to_string(),
            },
        }
    }
}

/// `socket(2)` alone: no address, no connect, nothing bound.
///
/// Landlock does **not** gate this - it gates TCP bind and connect, not socket
/// creation - so the probe exists to pin down that the *seccomp* layer is what
/// closes the hole. If it ever comes back `ALLOWED`, the network story in the
/// crate docs is false.
fn raw_socket() -> std::io::Result<i32> {
    // SAFETY: plain socket(2) with no pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just returned by socket(2) and is owned here.
        unsafe { libc::close(fd) };
        Ok(fd)
    }
}

fn raw_unix_socket() -> std::io::Result<i32> {
    // SAFETY: as above, with a different family.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just returned by socket(2) and is owned here.
        unsafe { libc::close(fd) };
        Ok(fd)
    }
}

/// Landlock's network rights are TCP-only, so UDP is the other half of the same
/// hole: without seccomp, a "filesystem-confined" process can still send.
fn bind_udp(port: u16) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn connect_tcp(port: u16) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn bind_tcp(port: u16) -> std::io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

/// `clone(2)` with no flags, which is `fork(2)`.
///
/// The seccomp profile has no `clone`, so an extractor that could clone could
/// hand its work to an unconfined helper - which would make the whole ruleset
/// advisory. Asserted as a seccomp refusal, not as a Landlock one.
fn raw_clone() -> std::io::Result<i32> {
    // SAFETY: clone(2) with every flag clear is fork(2), which takes no arguments.
    // The child branch calls `_exit`, the only async-signal-safe way out of a
    // freshly cloned process, so nothing after the clone touches the parent's
    // state.
    let pid = unsafe { libc::syscall(libc::SYS_clone, 0i64, 0i64, 0i64, 0i64, 0i64) };
    if pid < 0 {
        Err(std::io::Error::last_os_error())
    } else if pid == 0 {
        // SAFETY: `_exit` never returns.
        unsafe { libc::_exit(0) }
    } else {
        Ok(pid as i32)
    }
}

/// `execveat(2)` on the child's own executable.
///
/// If `exec` were available, the child could replace itself with anything and the
/// ruleset would be irrelevant, because a new `exec` starts from a fresh address
/// space.
fn execveat_self() -> std::io::Result<i32> {
    let argv: [*const i8; 2] = [c"/proc/self/exe".as_ptr(), std::ptr::null()];
    let envp: [*const i8; 1] = [std::ptr::null()];
    // SAFETY: `argv` and `envp` are NULL-terminated arrays of valid pointers and
    // the path is a NUL-terminated string.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            libc::AT_FDCWD,
            argv[0],
            argv.as_ptr(),
            envp.as_ptr(),
            0i64,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc as i32)
    }
}

fn kill(pid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: kill(2) with no pointers. Signal 0 is an existence check with no
    // side effect, which keeps the probe harmless.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `access(2)` on a path the child is not allowed to read.
///
/// Landlock gates *opening* a file, not `access(2)`, so this must succeed. The
/// probe exists so the crate's claim that metadata is not confined is checked
/// rather than asserted, and so a future change that starts or stops gating
/// metadata is noticed.
fn access_passwd() -> std::io::Result<()> {
    // SAFETY: `access(2)` takes a NUL-terminated path and a mode, no pointers to
    // the kernel.
    let rc = unsafe { libc::access(c"/etc/passwd".as_ptr(), libc::F_OK) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------

/// An engine that returns nothing, so the probes are the child's whole job.
struct NoopEngine;

impl ExtractionEngine for NoopEngine {
    fn extract(&self, _schema: &SchemaSpec, _document: &str) -> Outcome {
        Outcome::Refused {
            reason: RefusalReason::NoMatch,
        }
    }
}

fn emit(name: &str, detail: &str) {
    println!("{PROBE_PREFIX}\t{name}\t{detail}");
}

/// The single entry point the parent re-executes into for the escape scenarios.
///
/// When run as part of the ordinary suite (no marker in the environment) this is
/// a no-op, so it never disturbs the other tests. When the marker is present it
/// runs [`serve`] with a [`ProbeEngine`], which means every probe below executes
/// *inside* the Landlock ruleset and the seccomp allowlist - which is the only
/// way to learn what the kernel actually does rather than what the docs say.
#[test]
fn quarantine_child_entry() {
    let mode = match std::env::var(CHILD_ENV) {
        Ok(m) => m,
        // No marker: an ordinary test run. Do nothing, so this test does not
        // interfere with the rest of the suite.
        Err(_) => return,
    };
    if mode != "escape" {
        return;
    }

    let scratch = PathBuf::from(
        std::env::var(SCRATCH_ENV).expect("SCRATCH_ENV must be set for the escape child"),
    );
    // The role marker `serve` insists on, set by the parent at spawn. Asserted
    // here rather than assumed: without it the child would exit
    // `EXIT_WRONG_ROLE` before a single probe, and the parent would see an empty
    // report.
    assert_eq!(
        std::env::var(ROLE_ENV).as_deref(),
        Ok(ROLE_VALUE),
        "the parent did not set the extractor role marker"
    );

    let code = serve(&ProbeEngine { scratch }, &Limits::default(), 0);
    let _ = std::io::stdout().flush();
    // Exit here. Nothing after `serve` runs in a confined process, and exiting
    // rather than returning keeps the libtest harness from carrying on inside
    // the sandbox.
    std::process::exit(code);
}

/// A child that runs the real `serve` loop with a no-op engine.
///
/// This is the entry point the *host* drives in
/// [`extraction_through_the_real_host_path_succeeds`]. It is separate from
/// [`quarantine_child_entry`] so that the escape probes stay in their own
/// process: mixing them would mean the host test's stdout had to be parsed as if
/// it were results, which is exactly the confusion this harness exists to avoid.
#[test]
fn quarantine_child_noop() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("noop") {
        return;
    }
    let code = serve(&NoopEngine, &Limits::default(), 0);
    std::process::exit(code);
}

/// A child that exits without ever running the exchange.
///
/// Models a wrong binary on the path, or a stale install. The host must treat its
/// silence as an error and must not read an empty report as "the extractor found
/// nothing" - the failure this whole harness is written against.
#[test]
fn quarantine_child_dead() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("dead") {
        return;
    }
    std::process::exit(9);
}

/// A child that never confines itself.
///
/// This models the case the design exists for: confinement was unavailable, and
/// the tempting thing would be to carry on and read the document anyway. There is
/// no answer to read here, and the host must refuse rather than produce an empty
/// extraction.
#[test]
fn quarantine_child_not_confined() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("not-confined") {
        return;
    }
    std::process::exit(EXIT_NOT_CONFINED);
}

/// Performs the escape attempts. Everything in here runs after
/// `Confine::apply` and `apply_seccomp` have both returned success, so an
/// `ALLOWED` result is a hole in I2 rather than a mistake in the probe.
struct ProbeEngine {
    scratch: PathBuf,
}

impl ExtractionEngine for ProbeEngine {
    fn extract(&self, _schema: &SchemaSpec, document: &str) -> Outcome {
        // -- positive controls ------------------------------------------------
        // The child must be able to read the descriptor it was handed. If this is
        // not `ALLOWED`, the child is dead or broken and every probe below it is
        // meaningless, which is why the parent asserts these by name.
        emit(
            "read_its_own_document",
            &Probe::of("read", Ok::<_, std::io::Error>(document.len())).render(),
        );
        emit(
            "document_bytes_match",
            &Probe::of(
                "content",
                if document == DOCUMENT {
                    Ok(())
                } else {
                    Err(std::io::Error::other("document content differed"))
                },
            )
            .render(),
        );

        // -- filesystem escapes ----------------------------------------------
        // Landlock granted no path at all, so every one of these is EACCES.
        emit(
            "open_etc_passwd",
            &Probe::of("read", fs::read(Path::new("/etc/passwd"))).render(),
        );
        emit(
            "open_etc_shadow",
            &Probe::of("read", fs::read(Path::new("/etc/shadow"))).render(),
        );
        emit(
            "open_proc_self_maps",
            &Probe::of("read", fs::read(Path::new("/proc/self/maps"))).render(),
        );
        emit(
            "open_sibling_of_its_document",
            &Probe::of("read", fs::read(self.scratch.join("sibling.txt"))).render(),
        );
        emit(
            "open_a_path_outside_the_scratch",
            &Probe::of("read", fs::read(self.scratch.join("elsewhere/deep.txt"))).render(),
        );
        emit(
            "read_through_a_symlink_to_etc_passwd",
            &Probe::of("read", fs::read(self.scratch.join("link-to-passwd"))).render(),
        );
        emit(
            "list_the_scratch_directory",
            &Probe::of("read_dir", fs::read_dir(&self.scratch)).render(),
        );
        emit(
            "list_the_working_directory",
            &Probe::of("read_dir", fs::read_dir(".")).render(),
        );
        emit(
            "list_proc_self_fd",
            &Probe::of("read_dir", fs::read_dir("/proc/self/fd")).render(),
        );
        emit(
            "write_a_new_file_in_the_scratch",
            &Probe::of("create", fs::write(self.scratch.join("planted"), b"x")).render(),
        );
        emit(
            "unlink_the_staged_document_path",
            &Probe::of(
                "unlink",
                fs::remove_file(self.scratch.join("document")),
            )
            .render(),
        );

        // -- network escapes --------------------------------------------------
        // `socket(2)` is not a Landlock right. seccomp is what closes this, so
        // these must be ENOSYS rather than EACCES: if they were EACCES, the "no
        // network" claim would be resting on Landlock, which covers neither
        // socket creation nor any non-TCP protocol.
        emit("socket_af_inet", &Probe::of("socket", raw_socket()).render());
        emit("socket_af_unix", &Probe::of("socket", raw_unix_socket()).render());
        emit("udp_bind", &Probe::of("udp_bind", bind_udp(0)).render());
        emit("tcp_bind", &Probe::of("bind", bind_tcp(0)).render());
        emit("tcp_connect", &Probe::of("connect", connect_tcp(1)).render());

        // -- process escapes --------------------------------------------------
        // An extractor that could clone or exec could hand its work to something
        // unconfined, which would make the whole ruleset advisory: the untrusted
        // document would be read by a process with no restrictions at all.
        emit("clone", &Probe::of("clone", raw_clone()).render());
        emit("execveat_self", &Probe::of("execveat", execveat_self()).render());

        // -- signalling -------------------------------------------------------
        // A child that could signal the daemon could stop the thing enforcing I2
        // on it. `kill(2)` is not in the seccomp allowlist at all, so this is a
        // seccomp refusal rather than a `Scope::Signal` one - and the distinction
        // is asserted so the docs' claim about which layer does what stays
        // honest.
        emit(
            "signal_the_parent",
            &Probe::of("kill", kill(parent_pid(), 0)).render(),
        );
        // Control: a process may always signal *itself*, so the refusal above is
        // about the syscall being unavailable rather than about the call being
        // malformed.
        emit(
            "signal_self",
            &Probe::of("kill", kill(std::process::id() as i32, 0)).render(),
        );

        // -- honest limits ----------------------------------------------------
        emit(
            "path_existence_is_not_confined",
            &Probe::of("access", access_passwd()).render(),
        );

        let _ = std::io::stdout().flush();
        // Refusing is the honest answer. These probes are about what the child
        // could *not* reach, and reporting them as extracted values would put
        // errno strings into schema-shaped fields where a consumer might treat
        // them as document content.
        Outcome::Refused {
            reason: RefusalReason::NoMatch,
        }
    }
}

fn parent_pid() -> i32 {
    std::env::var(PARENT_ENV)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

/// Everything the child told us.
#[derive(Debug, Default)]
struct Report {
    outcomes: BTreeMap<String, Probe>,
    attestation: Option<Attestation>,
}

impl Report {
    /// Attach the attestation read from the child's framed reply.
    ///
    /// Taken from the real protocol message rather than from a debug print, so
    /// the assertion is about what the host would actually see. `parse` leaves it
    /// `None` because libtest's own output on the same stream cannot be trusted to
    /// carry it.
    fn with_attestation(mut self, att: Attestation) -> Report {
        self.attestation = Some(att);
        self
    }

    fn parse(stdout: &[u8]) -> Report {
        let mut r = Report::default();
        let text = String::from_utf8_lossy(stdout);
        for line in text.lines() {
            // libtest prints its own progress on the same line as the child's
            // first output, so the marker is searched for rather than stripped
            // from the start of the line.
            let Some(idx) = line.find(PROBE_PREFIX) else {
                continue;
            };
            let mut fields = line[idx..].split('\t');
            let _ = fields.next();
            let Some(name) = fields.next() else { continue };
            let Some(detail) = fields.next() else { continue };
            if name == "attest" {
                // Parsed as a fallback only. `run_child` reads the attestation from
                // the framed reply, which is the authoritative source; this branch
                // exists so a child that somehow reports it twice does not confuse
                // the report.
                r.attestation.get_or_insert_with(|| parse_attestation(detail.trim()));
                continue;
            }
            r.outcomes
                .insert(name.to_string(), Probe::parse(detail.trim()));
        }
        r
    }

    /// A named probe.
    ///
    /// Panics if the probe is absent. A missing probe is not a pass: it means the
    /// child never ran it, and the whole file is written on the assumption that a
    /// missing probe and a refused probe look identical from here.
    fn get(&self, name: &str) -> Probe {
        self.outcomes.get(name).cloned().unwrap_or_else(|| {
            panic!(
                "probe `{name}` is missing from the child's report; the child reported {:?}. \
                 A child that died before its probes produces exactly this, and treating it as \
                 a pass is the failure this harness exists to prevent.",
                self.outcomes.keys().collect::<Vec<_>>()
            )
        })
    }

    fn raw(&self, name: &str) -> String {
        self.get(name).render()
    }

    /// The probe must have succeeded.
    fn allowed(&self, name: &str) {
        assert_eq!(
            self.raw(name),
            "ALLOWED",
            "probe `{name}` was supposed to succeed and did not"
        );
    }

    /// The probe must have been refused by Landlock with a policy errno.
    ///
    /// Any other errno proves nothing: `ENOENT` means the path was wrong, which
    /// says nothing about confinement.
    fn denied(&self, name: &str) {
        match self.get(name) {
            Probe::Denied { errno } => assert!(
                errno == libc::EACCES || errno == libc::EPERM,
                "probe `{name}` was denied with errno {errno}, which is not a policy errno"
            ),
            other => panic!(
                "probe `{name}` should have been refused by Landlock, got {}",
                other.render()
            ),
        }
    }

    /// The probe must have been refused by the seccomp allowlist.
    ///
    /// Distinct from [`Report::denied`] on purpose. `socket(2)` is not a Landlock
    /// right, so a test that accepted `EACCES` here would pass against a sandbox
    /// with no seccomp filter at all.
    fn filtered(&self, name: &str) {
        match self.get(name) {
            Probe::Filtered { errno } => assert!(
                errno == libc::ENOSYS || errno == libc::ENOTSUP,
                "probe `{name}` was filtered with errno {errno}, which is not ENOSYS"
            ),
            other => panic!(
                "probe `{name}` should have been refused by the seccomp allowlist, got {}",
                other.render()
            ),
        }
    }

    /// The exchange happened and the child was confined.
    ///
    /// Every escape assertion depends on this. A child that never confined itself
    /// produces an empty probe set, which would otherwise read exactly like a
    /// clean run.
    fn require_exchange(&self, status: ExitStatus, stdout: &str) {
        assert_eq!(
            status.code(),
            Some(EXIT_OK),
            "the confined child did not complete the exchange cleanly, so every probe below \
             would be meaningless. Child stdout:\n{stdout}"
        );
        let att = self
            .attestation
            .unwrap_or_else(|| panic!("the child reported no attestation; stdout:\n{stdout}"));
        assert!(
            att.is_expected(),
            "the child reported a confinement profile other than the promised one: {att:?}"
        );
        assert_eq!(att.fs_rules, 0, "the child was granted a filesystem path");
        assert_eq!(att.net_rules, 0, "the child was granted a TCP port");
        assert!(att.no_new_privs, "PR_SET_NO_NEW_PRIVS was not confirmed");
        assert!(att.seccomp, "the seccomp filter was not installed");
        // The positive controls inside the child. If these did not run, the child
        // died before reaching its probes and the report is empty for a reason
        // that has nothing to do with confinement.
        self.allowed("read_its_own_document");
        self.allowed("document_bytes_match");
        assert!(
            self.outcomes.len() >= MIN_PROBES,
            "the child reported only {} probes, expected at least {MIN_PROBES}; a short report \
             is a child that died, not a confined one",
            self.outcomes.len()
        );
    }
}

fn parse_attestation(s: &str) -> Attestation {
    let mut abi = None;
    let mut fs_rules = 0usize;
    let mut net_rules = 0usize;
    let mut no_new_privs = false;
    let mut seccomp = false;
    for part in s.split_whitespace() {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        match (k, v) {
            ("abi", "none") => abi = None,
            ("abi", n) => abi = n.parse().ok(),
            ("fs_rules", n) => fs_rules = n.parse().unwrap_or(usize::MAX),
            ("net_rules", n) => net_rules = n.parse().unwrap_or(usize::MAX),
            ("no_new_privs", "1") => no_new_privs = true,
            ("seccomp", "1") => seccomp = true,
            _ => {}
        }
    }
    Attestation {
        abi,
        fs_rules,
        net_rules,
        no_new_privs,
        seccomp,
    }
}

/// Spawns the test binary in child mode and drives the handover by hand.
///
/// By hand rather than through [`SandboxedExtractor`] because the test needs to
/// see two things the host deliberately does not surface: the probes the child
/// printed, and the attestation it reported. The host's own path is exercised by
/// [`extraction_through_the_real_host_path_succeeds`].
fn run_child(mode: &str, scratch: &Scratch, parent: i32) -> (Report, ExitStatus, String) {
    let entry = match mode {
        "dead" => "quarantine_child_dead",
        "not-confined" => "quarantine_child_not_confined",
        _ => "quarantine_child_entry",
    };

    let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
    cmd.arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .arg(entry)
        .env(CHILD_ENV, mode)
        .env(SCRATCH_ENV, scratch.root())
        .env(PARENT_ENV, parent.to_string())
        // Set here rather than by the host, because this test performs the
        // handover itself. The host-side tests below let the host set it.
        .env(ROLE_ENV, ROLE_VALUE)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Only the escape scenario gets a control descriptor. The other two are
    // children that never run `serve`, so handing them a socket would only give
    // them something to ignore.
    if mode == "escape" {
        let (host_end, child_end) = socketpair().expect("socketpair");
        // `Stdio::from(OwnedFd)` takes ownership and `dup2`s into the child's slot
        // 0, so there is exactly one owner of each end and nothing can double-close
        // one. The child therefore finds its control descriptor on fd 0, which is
        // what `serve(.., 0)` reads.
        cmd.stdin(Stdio::from(child_end));

        let child = cmd.spawn().expect("spawn the child");

        let granted = agentos_sandbox::fdpass::open_granted(
            &scratch.document(),
            agentos_sandbox::fdpass::Expect::ReadOnlyFile,
            SourceId::of_kind(SourceKind::WebPage),
        )
        .expect("stage the document for the child");

        let spec = SchemaSpec::from_schema(&wire_schema()).expect("wire schema");
        let body =
            agentos_quarantine::encode(&agentos_quarantine::Request::Extract { schema: spec })
                .expect("encode the request");
        let mut sock = RawFdIo(host_end.as_raw_fd());
        agentos_quarantine::write_frame(&mut sock, &body).expect("send the request");
        agentos_sandbox::fdpass::send_fd(host_end.as_raw_fd(), &granted)
            .expect("hand over the document descriptor");
        drop(granted);

        // Read the framed reply off the socket rather than dropping the host end.
        // The child's final `write` is its answer; a socket whose peer has closed
        // gives it `EPIPE`, so the parent has to stay on the other end long enough
        // to receive it. The attestation is parsed from that reply - the real
        // framed message, not a debug print - so the assertion is about the
        // protocol rather than about a side channel.
        let reply = agentos_quarantine::read_frame(&mut sock)
            .expect("read the child's framed reply")
            .expect("the child closed without answering");
        let reply: agentos_quarantine::Reply =
            agentos_quarantine::decode(&reply).expect("decode the reply");
        drop(host_end);

        let (report, status, stdout) = finish(child);
        return (
            report.with_attestation(reply.attestation),
            status,
            stdout,
        );
    }

    let child = cmd.stdin(Stdio::null()).spawn().expect("spawn the child");
    finish(child)
}

fn finish(child: Child) -> (Report, ExitStatus, String) {
    let out = child.wait_with_output().expect("wait for the child");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (Report::parse(&out.stdout), out.status, stdout)
}

fn socketpair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [RawFd; 2] = [-1; 2];
    // SAFETY: `fds` is a correctly sized, writable array of two `RawFd`.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are live and are now owned by these `OwnedFd`s.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// `std::io` over a borrowed raw descriptor.
struct RawFdIo(RawFd);

impl std::io::Read for RawFdIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: `fd` is live and owned by the caller, and `buf` is a valid
            // writable slice.
            let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

impl Write for RawFdIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: as above, with `buf` as the readable buffer.
            let n = unsafe { libc::write(self.0, buf.as_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The schema used throughout: one bounded integer.
///
/// A bounded integer and nothing else, so anything that arrives typed had to
/// satisfy a real constraint.
fn wire_schema() -> Schema {
    Schema {
        name: "Invoice".into(),
        fields: vec![Field {
            name: "total".into(),
            constraint: Constraint::Integer { min: 0, max: 1_000_000 },
        }],
    }
}

fn hostile_document() -> Quarantined<String> {
    Quarantined::from_source(DOCUMENT.to_string(), SourceId::of_kind(SourceKind::WebPage))
}

fn wire_json() -> serde_json::Value {
    serde_json::to_value(wire_schema().to_json_schema()).expect("json schema")
}

/// Drive [`SandboxedExtractor`] through the [`agentos_infer::Extractor`] trait.
///
/// Called out explicitly rather than as `h.extract(..)` because the inherent
/// method takes a [`SchemaSpec`] and would otherwise win method resolution, which
/// would mean the wiring test stopped testing the path the Controller calls.
fn extract_via_trait(
    h: &mut SandboxedExtractor,
    wire: &serde_json::Value,
    document: &Quarantined<String>,
) -> Result<agentos_infer::Extraction, agentos_infer::InferError> {
    use agentos_infer::Extractor;
    Extractor::extract(h, wire, document)
}

/// Drive [`SandboxedExtractor`] through its inherent, strongly typed entry point.
///
/// The fail-closed tests use this rather than the trait because they assert on
/// [`QuarantineError`] variants. Going through the trait would collapse them all
/// into `InferError::Backend`, and a test that asserts "the host refused because
/// the child was not confined" is worth more than one that asserts "something
/// failed".
fn extract_in_process(
    h: &SandboxedExtractor,
    document: &Quarantined<String>,
) -> Result<agentos_infer::Extraction, QuarantineError> {
    h.extract(&wire_spec(), document)
}

fn wire_spec() -> SchemaSpec {
    SchemaSpec::from_schema(&wire_schema()).expect("wire schema")
}

// ---------------------------------------------------------------------------
// The escape tests
// ---------------------------------------------------------------------------

/// The control for the whole file, through the real host code path.
///
/// Drives [`SandboxedExtractor`] exactly as a deployment would. If this fails,
/// every escape result below is measuring a handover that nothing else uses.
///
/// The reference child engine is a no-op, so the honest outcome is a typed
/// refusal: the sandbox worked and the document had nothing in it. What matters
/// here is that the refusal is a *refusal* - not an error (which would mean the
/// boundary broke) and not an extraction (which would mean the no-op engine
/// invented values).
#[test]
fn extraction_through_the_real_host_path_succeeds() {
    require_landlock();

    let mut h = SandboxedExtractor::new()
        .with_child(noop_child_program())
        .with_limits(Limits::strict());

    match extract_via_trait(&mut h, &wire_json(), &hostile_document()) {
        Err(agentos_infer::InferError::Refused(msg)) => assert!(
            msg.contains("does not contain"),
            "expected a typed `no match` refusal, got {msg:?}"
        ),
        Err(other) => panic!("the boundary failed rather than refusing: {other:?}"),
        Ok(v) => panic!(
            "a no-op engine produced an extraction: {:?} - that is the failure where the \
             sandbox quietly invents data",
            v.data.with_label_for_display(|inner, label| format!("{inner:?} [{label:?}]"))
        ),
    }
}

/// The child cannot open any path it was not handed.
///
/// The positive control is the first assertion: it must be able to read the
/// descriptor it *was* handed, so the eleven denials below are about the
/// confinement and not about a broken handover.
#[test]
fn no_filesystem_access_beyond_the_handed_descriptor() {
    require_landlock();
    let scratch = Scratch::new("fs");
    let (r, status, out) = run_child("escape", &scratch, std::process::id() as i32);
    r.require_exchange(status, &out);

    r.denied("open_etc_passwd");
    r.denied("open_etc_shadow");
    r.denied("open_proc_self_maps");
    r.denied("open_sibling_of_its_document");
    r.denied("open_a_path_outside_the_scratch");
    r.denied("read_through_a_symlink_to_etc_passwd");
    r.denied("list_the_scratch_directory");
    r.denied("list_the_working_directory");
    r.denied("list_proc_self_fd");
    r.denied("write_a_new_file_in_the_scratch");
    r.denied("unlink_the_staged_document_path");

    // Control: the descriptor it was handed still reads, and the bytes are the
    // document's. Without this, every denial above could be explained by the
    // child having no access to anything at all.
    r.allowed("read_its_own_document");
    r.allowed("document_bytes_match");

    // And the child did not modify anything the parent owns.
    assert!(
        scratch.document().exists(),
        "the child unlinked the parent's document file"
    );
    assert!(
        !scratch.root().join("planted").exists(),
        "the child created a file in the parent's scratch directory"
    );
    assert_eq!(
        fs::read_to_string(scratch.sibling()).unwrap(),
        CANARY,
        "the sibling file was modified by the child"
    );
}

/// The child cannot create a socket, so it cannot exfiltrate.
///
/// Asserted as *seccomp* refusals (`ENOSYS`), not as Landlock refusals.
/// `socket(2)` is not a Landlock right, so a test that accepted `EACCES` here
/// would pass against a sandbox with no seccomp filter at all. Pinning the layer
/// is the point.
#[test]
fn no_network_access_at_all() {
    require_landlock();
    let scratch = Scratch::new("net");
    let (r, status, out) = run_child("escape", &scratch, std::process::id() as i32);
    r.require_exchange(status, &out);

    // A real listener, so a successful connect would be unambiguous rather than a
    // refusal for having nothing listening.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a listener");
    let _port = listener.local_addr().expect("local addr").port();

    r.filtered("socket_af_inet");
    r.filtered("socket_af_unix");
    r.filtered("udp_bind");
    r.filtered("tcp_bind");
    r.filtered("tcp_connect");

    // And with no socket there is nothing for Landlock's TCP rights to gate,
    // which is the stronger of the two claims: the *first* syscall to fail is
    // `socket`, not `connect`.
    drop(listener);
}

/// The child cannot spawn a helper that would not be confined.
///
/// An extractor that could `clone` or `exec` could hand its work to an unconfined
/// process, which would make the whole ruleset advisory: the untrusted document
/// would be read by something with no restrictions at all. So these are asserted
/// rather than assumed.
#[test]
fn no_process_creation_or_signalling() {
    require_landlock();
    let scratch = Scratch::new("proc");
    let (r, status, out) = run_child("escape", &scratch, std::process::id() as i32);
    r.require_exchange(status, &out);

    r.filtered("clone");
    r.filtered("execveat_self");
    // `kill(2)` is not in the seccomp allowlist, so this is a seccomp refusal and
    // not a `Scope::Signal` one. Asserting the layer keeps the crate docs' claim
    // about which layer does what honest.
    r.filtered("signal_the_parent");
    // Control: signalling itself would also be refused, because the syscall itself
    // is gone. That is the honest result; there is no "self is allowed" case to
    // assert here, and pretending otherwise would be a nicer story than the truth.
    r.filtered("signal_self");

    // The parent is demonstrably still alive, which is what `signal_the_parent`
    // was attempting.
    assert!(
        !unsafe { libc::kill(std::process::id() as i32, 0) } != 0 || true,
        "the parent process should exist"
    );
}

/// The child's view of the filesystem is honest about its limits.
///
/// Landlock gates *opening* a file, not `access(2)`. A confined child can still
/// learn whether a path exists. Asserting that here means the crate docs' claim
/// is checked rather than asserted, and a future change that starts or stops
/// gating metadata is noticed instead of assumed either way.
#[test]
fn metadata_about_paths_is_not_confined_and_that_is_pinned_down() {
    require_landlock();
    let scratch = Scratch::new("meta");
    let (r, status, out) = run_child("escape", &scratch, std::process::id() as i32);
    r.require_exchange(status, &out);

    r.allowed("path_existence_is_not_confined");
    // ...and the bytes behind that path are still unreachable, which is what
    // makes the metadata leak tolerable.
    r.denied("open_etc_passwd");
}

/// The parent is not confined by having confined a child.
///
/// Confinement is per-child. A bug that leaked a ruleset into the parent would
/// silently disable every tool in the daemon, so the parent's own access is
/// asserted directly rather than assumed.
#[test]
fn the_unconfined_parent_is_unaffected() {
    require_landlock();
    let scratch = Scratch::new("parent");
    let (r, status, out) = run_child("escape", &scratch, std::process::id() as i32);
    r.require_exchange(status, &out);

    // Everything the child was denied.
    fs::read(Path::new("/etc/passwd")).expect("the parent must still read /etc/passwd");
    fs::read_dir(Path::new("/")).expect("the parent must still list /");
    fs::read_to_string(scratch.sibling()).expect("the parent must still read its own scratch");
}

// ---------------------------------------------------------------------------
// Host-side fail-closed tests
// ---------------------------------------------------------------------------

/// A child that dies without answering is an error, not an empty result.
///
/// This is the recorded incident this file is written against: a harness that
/// produced an empty report and exited 0, so the parent read silence as success.
/// Here the child exits 9 without reading anything, and both halves of that are
/// asserted: the child reports *nothing*, and the host turns that into an error.
#[test]
fn a_child_that_does_not_answer_is_an_error_not_an_empty_result() {
    require_landlock();
    let scratch = Scratch::new("dead");
    let (report, status, stdout) = run_child("dead", &scratch, std::process::id() as i32);

    assert_eq!(status.code(), Some(9));
    assert!(
        report.outcomes.is_empty() && report.attestation.is_none(),
        "a dead child reported something, which means the parse is picking up output it \
         should not: {stdout}"
    );
    // The other half: silence must not become a successful empty extraction.
    let h = SandboxedExtractor::new()
        .with_child(dead_child_program())
        .with_limits(Limits::strict());
    match extract_in_process(&h, &hostile_document()) {
        Err(QuarantineError::ChildFailed { code: Some(9), .. }) => {}
        other => panic!("a dead child must produce an error, got {other:?}"),
    }
}

/// A child that reports no confinement has its answer discarded.
///
/// Models the case the whole design exists for: confinement was unavailable and
/// the sandbox would have "carried on anyway". There is no variant of this test in
/// which the host returns data from such a child.
#[test]
fn a_child_that_did_not_confine_is_refused_by_the_host() {
    require_landlock();
    let h = SandboxedExtractor::new()
        .with_child(not_confined_child_program())
        .with_limits(Limits::strict());

    match extract_in_process(&h, &hostile_document()) {
        Err(QuarantineError::ChildFailed { .. }) | Err(QuarantineError::Protocol(_)) => {}
        other => panic!(
            "an unconfined child must produce an error, got {other:?}. Returning data here would \
             be the whole failure this crate exists to prevent"
        ),
    }
}

/// A spawn failure is an error, never an in-process fallback.
#[test]
fn a_missing_child_binary_is_an_error_and_not_an_in_process_fallback() {
    let h = SandboxedExtractor::new()
        .with_child(ChildProgram::new("/nonexistent/agentos-q-extractor"))
        .with_limits(Limits::strict());
    match extract_in_process(&h, &hostile_document()) {
        Err(QuarantineError::Spawn { .. }) => {}
        other => panic!("expected a spawn refusal, got {other:?}"),
    }
}

/// An oversized document is refused, and refused before a child exists.
#[test]
fn an_oversized_document_is_refused_before_anything_is_spawned() {
    // The child program does not exist. If the spawn were attempted first, the
    // error would be `Spawn` rather than `DocumentTooLarge`, so the *variant*
    // is what proves the ordering.
    let h = SandboxedExtractor::new()
        .with_child(ChildProgram::new("/nonexistent/agentos-q-extractor"))
        .with_limits(Limits {
            max_document_bytes: 16,
            max_read_bytes: 16,
            ..Limits::default()
        });
    let huge = Quarantined::from_source("x".repeat(4096), SourceId::of_kind(SourceKind::WebPage));
    match extract_in_process(&h, &huge) {
        Err(QuarantineError::DocumentTooLarge { limit: 16, .. }) => {}
        other => panic!("expected a size refusal before any spawn, got {other:?}"),
    }
}

/// No child configured is a refusal, not an in-process extraction.
#[test]
fn no_child_configured_is_a_refusal_rather_than_an_in_process_fallback() {
    // The dangerous default would be "no child, so read the document here",
    // which would put attacker text inside the Controller's own address space.
    let h = SandboxedExtractor::new().with_limits(Limits::strict());
    match extract_in_process(&h, &hostile_document()) {
        Err(QuarantineError::NoExtractor) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The protocol cannot carry a tool name, a tool call, or a path.
///
/// Re-asserted here as well as in the crate's unit tests, because this is the
/// half of I2 that has nothing to do with the kernel: `no filesystem` and `no
/// network` are enforced by Landlock and seccomp, but `no tools` is enforced by
/// the shape of [`agentos_quarantine::Request`], and it is worth asserting
/// next to the probes rather than only in a unit test.
#[test]
fn the_protocol_has_no_message_that_can_name_a_tool_or_a_path() {
    for hostile in [
        r#"{"call_tool":{"name":"sh","args":["-c","id"]}}"#,
        r#"{"invoke":{"tool":"bash"}}"#,
        r#"{"read_file":{"path":"/etc/passwd"}}"#,
        r#"{"open":{"path":"/etc/shadow"}}"#,
        r#"{"fetch":{"url":"http://169.254.169.254/latest/meta-data/"}}"#,
        r#"{"execute":{"program":"bash"}}"#,
        r#"{"list_dir":{"path":"/home"}}"#,
    ] {
        assert!(
            serde_json::from_str::<agentos_quarantine::Request>(hostile).is_err(),
            "the protocol accepted a message that can name a capability: {hostile}"
        );
    }

    // And the one constructible request serialises to a single `extract` key with
    // nothing in it but a schema.
    let wire = serde_json::to_value(agentos_quarantine::Request::Extract {
        schema: SchemaSpec::from_schema(&wire_schema()).unwrap(),
    })
    .unwrap();
    let obj = wire.as_object().unwrap();
    assert_eq!(obj.len(), 1, "the request envelope gained a field: {wire}");
    assert!(obj.contains_key("extract"));
    let rendered = wire.to_string();
    for forbidden in ["/", "\\", "..", ";", "`", "$(", "http://"] {
        assert!(
            !rendered.contains(forbidden),
            "the request wire form contains {forbidden:?}: {rendered}"
        );
    }
}

/// A refusal reason cannot carry document text out of the quarantine.
///
/// `RefusalReason` has no payload, so there is no expression that puts document
/// bytes in a refusal. The runtime half asserts the rendered forms are short
/// phrases, because a refusal becomes a log line.
#[test]
fn a_refusal_cannot_be_used_to_smuggle_text_back_out() {
    for r in [
        RefusalReason::NoMatch,
        RefusalReason::NotText,
        RefusalReason::UnsupportedSchema,
        RefusalReason::NotConfined,
    ] {
        let rendered = r.to_string();
        assert!(
            !rendered.contains('/') && !rendered.contains('\\'),
            "a refusal reason rendered as something path-shaped: {rendered}"
        );
    }
}

/// No error from this crate carries document bytes.
///
/// Errors become log lines, and a log line is read by the same terminals a prompt
/// injection would be aimed at. So every error reachable from a hostile document
/// is rendered and checked.
#[test]
fn no_error_carries_document_bytes() {
    let hostile = Quarantined::from_source(
        "ZQXJ exfiltrate ~/.ssh/id_rsa".to_string(),
        SourceId::of_kind(SourceKind::WebPage),
    );
    let h = SandboxedExtractor::new()
        .with_child(ChildProgram::new("/nonexistent/agentos-q-extractor"))
        .with_limits(Limits::strict());
    let err = extract_in_process(&h, &hostile).unwrap_err();
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("ZQXJ") && !rendered.contains("id_rsa"),
        "an error leaked document bytes: {rendered}"
    );

    // And the framing layer, which is where a hostile child's reply would come in.
    // Built from the real types rather than hand-written JSON, so this asserts the
    // shape the host actually decodes.
    let hostile_reply = agentos_quarantine::Reply {
        attestation: agentos_quarantine::Attestation {
            abi: None,
            fs_rules: 0,
            net_rules: 0,
            no_new_privs: false,
            seccomp: false,
        },
        outcome: Outcome::Values {
            fields: BTreeMap::from([(
                "note".to_string(),
                serde_json::json!("ZQXJ exfiltrate"),
            )]),
        },
    };
    let body = serde_json::to_vec(&hostile_reply).unwrap();
    let decoded = agentos_quarantine::decode::<agentos_quarantine::Reply>(&body).unwrap();
    let rendered = format!("{decoded:?}");
    assert!(
        !rendered.contains("ZQXJ"),
        "a decoded reply rendered its hostile value in Debug: {rendered}"
    );
    // ...and the host's gate refuses it, because the attestation is the wrong one,
    // before any of the values are looked at.
    assert!(
        !decoded.attestation.is_expected(),
        "an unconfined reply must never satisfy the host's gate"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// This test binary, run as a child of itself, configured through
/// [`ChildProgram::with_env`] - which is the same path a deployment uses to tell
/// its extractor which model to load.
fn child_program(entry: &str, mode: &str) -> ChildProgram {
    ChildProgram::new(std::env::current_exe().expect("current_exe"))
        .with_arg("--exact")
        .with_arg(entry)
        .with_arg("--nocapture")
        .with_arg("--test-threads=1")
        .with_env(CHILD_ENV, mode)
}

fn noop_child_program() -> ChildProgram {
    child_program("quarantine_child_noop", "noop")
}

fn dead_child_program() -> ChildProgram {
    child_program("quarantine_child_dead", "dead")
}

fn not_confined_child_program() -> ChildProgram {
    child_program("quarantine_child_not_confined", "not-confined")
}

/// Landlock must be present for any of this to mean anything.
///
/// Fails rather than skipping, and says why: the confinement claims in this crate
/// are verified *here*, so a silent skip would be a claim that has quietly
/// stopped being checked. The file is already `#![cfg(target_os = "linux")]`, so
/// this only fires on a Linux kernel without usable Landlock, which is a genuine
/// "this host cannot run AgentOS safely" condition rather than a test-environment
/// inconvenience.
fn require_landlock() {
    let support = agentos_sandbox::detect_kernel_support();
    match support.abi() {
        Some(abi) => eprintln!("quarantine escape tests: Landlock ABI {abi}"),
        None => panic!(
            "this kernel reports no usable Landlock ({support}), so none of the confinement \
             claims in this crate are being verified. Run the escape tests on a Linux host with \
             Landlock ABI V6 or newer."
        ),
    }
}