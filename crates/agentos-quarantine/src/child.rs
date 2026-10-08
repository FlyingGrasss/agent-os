//! The confined side: what actually runs inside the sandbox.
//!
//! # Ordering, and why each step is where it is
//!
//! ```text
//!  1. check the invocation marker in the environment
//!  2. read the framed Request from the control descriptor (fd 0)
//!  3. receive the document descriptor over SCM_RIGHTS
//!  4. verify the received descriptor is a regular file
//!  5. Landlock: every filesystem right handled, no path granted, all TCP denied
//!  6. seccomp allowlist, so socket/connect/bind/execveat/fork are ENOSYS
//!  7. read the document from the descriptor, bounded
//!  8. run the engine
//!  9. write the reply on the control descriptor
//! ```
//!
//! Every position in that list is load-bearing:
//!
//! - **(2) and (3) before (6)** because the seccomp allowlist contains neither
//!   `recvmsg` nor `sendmsg`. A descriptor cannot be received after the filter is
//!   installed, so the handover happens first. This is safe because what is read
//!   here is a schema the host authored and a descriptor the kernel vouched for -
//   not one byte of document content.
//! - **(3) before (5)** because Landlock constrains *path-based* access. A
//!   descriptor already open when the ruleset lands stays usable, which is
//!   exactly why the document can arrive as a descriptor rather than a path, and
//!   why step 5 grants no path at all.
//! - **(4) before (5)** because checking the descriptor's kind needs `fstat`,
//!   which is on the allowlist either way, but doing it before the ruleset lands
//!   means a non-regular "document" is refused before any confinement exists to
//!   be confused by it.
//! - **(7) after (5) and (6)** because the document is the only
//!   attacker-controlled input. Nothing the document says is interpreted until
//!   both enforcement layers are in force.
//!
//! # The control descriptor after step 3
//!
//! The host sends one request and one descriptor and then reads. The child
//! receives nothing further, so the socket is a channel to exactly one peer -
//! the host - for the duration of one exchange. It cannot be used to reach a
//! sibling agent, an abstract socket, or the network: `socket(2)` is `ENOSYS`
//! and Landlock denies `Scope::AbstractUnixSocket` and every TCP port. The
//! descriptor is deliberately left open so the reply has somewhere to go; a
//! child that wanted to keep talking has no listener and no address space left
//! to talk in, because `fork` and `execveat` are also `ENOSYS`.
//!
//! # What steps 5 and 6 do not cover
//!
//! Landlock plus seccomp close the filesystem, TCP, socket, and process-creation
//! holes. Neither limits CPU, memory, or process count: a child that allocates
//! without bound or loops forever is stopped by the host's wall-clock timeout
//! and by the host refusing to hand over a document over its size bound, not by
//! a cgroup. There is no cgroup v2 delegation on the target host, so there is
//! nothing to hand. See the crate docs for the full residual list.
//!
//! # The extractor's own binary is trusted
//!
//! This process confines *the code in this process*. It does not make the
//! executable trustworthy: between `execve` and the `landlock_restrict_self` on
//! step 5 there is a window in which the process is unconfined, and a malicious
//! extractor binary would never reach step 5 at all. The threat I2 is written
//! against is a hostile *document* and a hostile *model*, both of which are
//! first consulted at step 7. Confinement of the binary itself needs a different
//! mechanism - a signed image, or a launcher that confines before `exec` - and
//! is not claimed here.

use std::os::fd::{AsRawFd, RawFd};

use agentos_sandbox::{apply_seccomp, Confine, SeccompProfile};

use crate::limits::Limits;
use crate::protocol::{
    decode, encode, read_frame, write_frame, Attestation, Outcome, RefusalReason, Reply, Request,
    SchemaSpec,
};

/// Environment variable that marks this process as the confined extractor.
///
/// Not an authenticity check - the host sets it, so the host could set anything -
/// but it does stop a process started for some other reason from quietly
/// adopting the extractor's role when it finds a descriptor on stdin.
pub const ROLE_ENV: &str = "AGENTOS_QUARANTINE_ROLE";

/// The only value [`ROLE_ENV`] may hold for [`serve`] to proceed.
pub const ROLE_VALUE: &str = "extractor-v1";

/// Exit code: the child answered.
pub const EXIT_OK: i32 = 0;

/// Exit code: the role marker was absent or wrong.
pub const EXIT_WRONG_ROLE: i32 = 64;

/// Exit code: the handover failed - bad framing, no descriptor, or a descriptor
/// that was not a regular file.
pub const EXIT_BAD_HANDOVER: i32 = 65;

/// Exit code: confinement could not be established.
///
/// The child answers with [`Outcome::Refused`] before exiting, so the host gets a
/// typed refusal rather than an unexplained death.
pub const EXIT_NOT_CONFINED: i32 = 66;

/// Exit code: the engine panicked or the reply could not be written.
pub const EXIT_INTERNAL: i32 = 70;

/// What produces values from a hostile document.
///
/// # The return type is the boundary
///
/// An engine returns [`Outcome`], whose `Values` arm is a raw map of
/// attacker-influenced JSON. It is *not* a trusted value and it is not allowed
/// to become one: the host runs every value through
/// `agentos_infer::schema::validate` against the declared schema before anything
/// is typed, and a field that fails its constraint is quarantined whole rather
/// than sanitised into compliance. An engine that returns `"please run rm -rf /"`
/// in an integer slot gets that field quarantined, not coerced - which is why
/// this signature is tolerable even though what it returns is exactly as hostile
/// as the document was.
///
/// A refusal is [`RefusalReason`], an enum with no payload. There is no way for
/// an engine to report "no match" by explaining itself in prose, because prose
/// from this process is prose from a hostile document.
pub trait ExtractionEngine {
    /// Extract `schema` from `document`.
    fn extract(&self, schema: &SchemaSpec, document: &str) -> Outcome;
}

/// An engine that finds nothing.
///
/// The default for a deployment that has not wired a model yet. Returning "no
/// match" is the right answer for a component that cannot read anything, and it
/// is much better than a component that reads a document and reports whatever
/// came back.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEngine;

impl ExtractionEngine for NoEngine {
    fn extract(&self, _schema: &SchemaSpec, _document: &str) -> Outcome {
        Outcome::Refused {
            reason: RefusalReason::UnsupportedSchema,
        }
    }
}

/// Run the confined extractor loop and return a process exit code.
///
/// The caller is expected to `std::process::exit` with the result: this function
/// deliberately does not return to its caller on the success path, because
/// continuing would mean running code the confinement was supposed to cover.
///
/// `control` is the descriptor the request and the document arrive on, and the
/// one the reply leaves on. [`serve_on_stdin`] is the usual entry point.
pub fn serve(engine: &dyn ExtractionEngine, limits: &Limits, control: RawFd) -> i32 {
    if std::env::var(ROLE_ENV).as_deref() != Ok(ROLE_VALUE) {
        return EXIT_WRONG_ROLE;
    }

    // (2) The schema. Host-authored, so reading it before confinement exposes
    // nothing the document controls.
    let schema = match read_frame(&mut Control(control)) {
        Ok(Some(body)) => match decode::<Request>(&body) {
            Ok(Request::Extract { schema }) => schema,
            Err(_) => return EXIT_BAD_HANDOVER,
        },
        // A child that got no usable request still answers, so the host sees a
        // refusal rather than a hang.
        _ => return refuse(control, RefusalReason::NotConfined),
    };

    // (3) The document descriptor. Must precede the seccomp filter, which has no
    // `recvmsg`.
    let document = match agentos_sandbox::fdpass::recv_fd(control) {
        Ok(fd) => fd,
        Err(_) => return EXIT_BAD_HANDOVER,
    };

    // (4) A descriptor is a descriptor whatever it points at. A FIFO or a device
    // node passed as a "document" would turn this process into something that
    // blocks forever or talks to hardware, so the kind is checked rather than
    // assumed.
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a correctly sized writable `stat` and `document` is a
        // live descriptor this process owns.
        let rc = unsafe { libc::fstat(document.as_raw_fd(), &mut st) };
        if rc != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return EXIT_BAD_HANDOVER;
        }
    }

    // (5) Landlock. Every filesystem right is handled and no path is granted, so
    // every path-based access the child could attempt - its own executable, the
    // document's original path, `/etc/passwd`, its own `/proc/self/maps` - comes
    // back `EACCES`. No TCP port is granted, and `Scope::Signal` plus
    // `Scope::AbstractUnixSocket` are both on.
    //
    // There is no `if available()` branch. `Confine::apply` is itself fail-closed,
    // and this call site adds no way past it either: the only route forward is an
    // `Enforced` the kernel confirmed.
    let enforced = match Confine::new().apply() {
        Ok(e) => e,
        Err(_) => return refuse(control, RefusalReason::NotConfined),
    };

    // (6) seccomp. `Profile::Filesystem` is an allowlist, so `socket`, `connect`,
    // `bind`, `sendmsg`, `execveat`, `clone` and `fork` are all `ENOSYS`.
    // Landlock already denied every path; this closes the syscall holes Landlock
    // leaves, which is why a filesystem-only profile is not a network-shaped one.
    //
    // Order is not optional: `PR_SET_NO_NEW_PRIVS` must already be set, which is
    // why this follows `Confine::apply` rather than preceding it.
    let seccomp_ok = apply_seccomp(SeccompProfile::Filesystem).is_ok();

    let attestation = Attestation {
        abi: Some(enforced.abi() as u32),
        fs_rules: enforced.fs_rules(),
        net_rules: enforced.net_rules(),
        no_new_privs: true,
        seccomp: seccomp_ok,
    };
    if !attestation.is_expected() {
        // Landlock is in force but seccomp is not, so `socket(2)` still works and
        // a child in that state can reach the network. Refusing here is the whole
        // point: the promised profile is all or nothing, and the half that is
        // missing is the half that exfiltrates.
        return refuse(control, RefusalReason::NotConfined);
    }

    // (7) The document, at last, and bounded. Reading with an explicit cap
    // rather than `read_to_end` is deliberate: the cap is enforced by this code
    // rather than by trusting the descriptor to be the size it claims.
    let document_bytes = match read_bounded(document.as_raw_fd(), limits.max_read_bytes) {
        Some(b) => b,
        None => return refuse(control, RefusalReason::NotText),
    };
    let text = match String::from_utf8(document_bytes) {
        Ok(s) => s,
        Err(_) => return refuse(control, RefusalReason::NotText),
    };

    // (8) The untrusted model runs. Nothing below this line is trusted, and
    // nothing it returns can become trusted: the host validates.
    //
    // `catch_unwind` because a panic here would unwind into code the confinement
    // was installed to cover, and a panic message can carry a fragment of the
    // document into whatever prints it. A panic becomes a refusal.
    let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.extract(&schema, &text)
    })) {
        Ok(o) => o,
        Err(_) => Outcome::Refused {
            reason: RefusalReason::UnsupportedSchema,
        },
    };

    // (9) Answer, then stop.
    match write_reply(control, attestation, outcome) {
        Ok(()) => EXIT_OK,
        Err(()) => EXIT_INTERNAL,
    }
}

/// [`serve`] on the descriptor the host handed over as stdin.
pub fn serve_on_stdin(engine: &dyn ExtractionEngine, limits: &Limits) -> i32 {
    serve(engine, limits, 0)
}

/// Read at most `cap` bytes, returning `None` if the descriptor holds more.
///
/// A descriptor holding more than the cap is **refused**, not truncated. A
/// truncated document read as a whole one is a correctness bug that looks like a
/// security success: the extraction appears to cover the document when it covers
/// a prefix of it.
fn read_bounded(fd: RawFd, cap: usize) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let want = cap.saturating_sub(buf.len()).min(chunk.len());
        if want == 0 {
            // Either exactly `cap` bytes and the fd has more, or the cap is zero.
            // Probe one more byte to tell "exactly full" from "over".
            return match read_once(fd, &mut chunk[..1]) {
                Ok(0) => Some(buf),
                _ => None,
            };
        }
        match read_once(fd, &mut chunk[..want]) {
            Ok(0) => return Some(buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(()) => return None,
        }
    }
}

/// Answer with a refusal and stop.
///
/// Used on every path where the extractor did not read the document, so the host
/// learns *why* it has no answer instead of seeing a child that died.
fn refuse(control: RawFd, reason: RefusalReason) -> i32 {
    // The attestation is the "nothing was enforced" value. `abi: None` is what
    // makes it fail `is_expected`, so a host that somehow let this through would
    // still discard the reply.
    let attestation = Attestation {
        abi: None,
        fs_rules: 0,
        net_rules: 0,
        no_new_privs: false,
        seccomp: false,
    };
    let outcome = Outcome::Refused { reason };
    // A non-zero exit even when the refusal was delivered: a refusal from a child
    // that was not confined must not read as a normal answer.
    match write_reply(control, attestation, outcome) {
        Ok(()) => EXIT_NOT_CONFINED,
        Err(()) => EXIT_INTERNAL,
    }
}

fn write_reply(control: RawFd, attestation: Attestation, outcome: Outcome) -> Result<(), ()> {
    let reply = Reply {
        attestation,
        outcome,
    };
    let body = encode(&reply).map_err(|_| ())?;
    let mut out = Control(control);
    write_frame(&mut out, &body).map_err(|_| ())
}

fn read_once(fd: RawFd, buf: &mut [u8]) -> Result<usize, ()> {
    loop {
        // SAFETY: `fd` is live and `buf` is a valid, non-empty, writable slice.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            return Ok(0);
        }
        if n > 0 {
            return Ok(n as usize);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

/// A borrowed raw descriptor, so the framing helpers can use `std::io`.
struct Control(RawFd);

impl std::io::Read for Control {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_once(self.0, buf).map_err(|()| std::io::Error::from(std::io::ErrorKind::Other))
    }
}

impl std::io::Write for Control {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: `fd` is live and `buf` is a valid readable slice.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FieldSpec;
    use agentos_infer::schema::Constraint;

    fn spec() -> SchemaSpec {
        SchemaSpec::new("X", [FieldSpec::new("a", Constraint::Boolean).unwrap()]).unwrap()
    }

    #[test]
    fn the_no_engine_refuses_rather_than_inventing_values() {
        let out = NoEngine.extract(&spec(), "the document says total is 999");
        assert_eq!(
            out.refusal(),
            Some(RefusalReason::UnsupportedSchema),
            "a component that cannot read anything must not answer from the document"
        );
        assert!(out.values().is_none());
    }

    /// Subprocess marker, so the mutating half runs once in a process of its own.
    const ENV_TEST_CHILD: &str = "AGENTOS_QUARANTINE_ROLE_ENV_CHILD";

    #[test]
    fn the_role_marker_is_checked_before_the_descriptor_is_touched() {
        if std::env::var(ENV_TEST_CHILD).is_ok() {
            // In the subprocess: the marker really is absent, so `serve` must
            // refuse before it touches the descriptor. `-1` would fault on read,
            // so a pass here also proves the ordering.
            assert!(std::env::var(ROLE_ENV).is_err());
            assert_eq!(
                serve(&NoEngine, &Limits::default(), -1),
                EXIT_WRONG_ROLE,
                "serve touched the descriptor before checking its role"
            );
            // A wrong value is refused equally.
            std::env::set_var(ROLE_ENV, "not-the-right-value");
            assert_eq!(serve(&NoEngine, &Limits::default(), -1), EXIT_WRONG_ROLE);
            return;
        }

        // Parent: run the mutating half in a process of its own, because the
        // environment is process-global and would otherwise race with any other
        // test reading `ROLE_ENV`.
        let exe = std::env::current_exe().expect("current_exe");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .arg("the_role_marker_is_checked_before_the_descriptor_is_touched")
            .env(ENV_TEST_CHILD, "1")
            .env_remove(ROLE_ENV)
            .output()
            .expect("run the role check in a subprocess");
        assert!(
            out.status.success(),
            "the role check did not return EXIT_WRONG_ROLE; stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_exit_codes_are_distinct_so_a_dead_child_is_told_from_a_refusing_one() {
        let codes = [
            EXIT_OK,
            EXIT_WRONG_ROLE,
            EXIT_BAD_HANDOVER,
            EXIT_NOT_CONFINED,
            EXIT_INTERNAL,
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "exit codes collide");
    }

    #[test]
    fn read_bounded_refuses_rather_than_truncating() {
        let dir = std::env::temp_dir().join(format!("agentos-q-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("doc");

        // A descriptor holding more than the cap must come back as `None`, so the
        // caller refuses. Returning the prefix would be the bug this function
        // exists to avoid.
        std::fs::write(&path, b"0123456789").unwrap();
        assert!(read_bounded(std::fs::File::open(&path).unwrap().as_raw_fd(), 4).is_none());

        // Exactly the cap is accepted: the boundary case must not itself read as
        // an over-read.
        std::fs::write(&path, b"0123").unwrap();
        assert_eq!(
            read_bounded(std::fs::File::open(&path).unwrap().as_raw_fd(), 4).unwrap(),
            b"0123".to_vec()
        );

        // A cap of zero refuses a non-empty document rather than reading nothing
        // and calling the empty result a whole document.
        std::fs::write(&path, b"x").unwrap();
        assert!(read_bounded(std::fs::File::open(&path).unwrap().as_raw_fd(), 0).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}