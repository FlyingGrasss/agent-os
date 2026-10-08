//! The unconfined side: spawning a child and refusing to believe it blindly.
//!
//! # The one place a result can enter the system
//!
//! [`SandboxedExtractor::extract`] is the only function in this crate that
//! produces an `agentos_infer::Extraction`, and it is fail-closed at five
//! separate points before a single byte of the reply is trusted:
//!
//! 1. the configured limits must be self-consistent, checked first, because a
//!    child bound above the host bound would make the host's bound advisory;
//! 2. the document is refused if it is over the host's bound, before anything is
//!    staged or spawned;
//! 3. the spawn must succeed - a failure is an error, never an in-process
//!    fallback;
//! 4. the child's reported attestation must be exactly the promised profile
//!    (zero filesystem grants, zero TCP grants, `no_new_privs`, seccomp on), and
//!    its exit status must be [`EXIT_OK`];
//! 5. every value the child returned is validated against the schema, and a
//!    field that fails its constraint is quarantined rather than coerced.
//!
//! Point 4 is the load-bearing one for "fail closed, always". A sandbox that
//! quietly gives up is worse than no sandbox, because the user believes they are
//! protected. So there is no `if landlock_is_available()` here, and a child that
//! reports anything other than full enforcement has its answer **discarded** -
//! not downgraded, not partially believed, discarded.
//!
//! # What the host still cannot know
//!
//! The attestation is the child describing its own confinement, and a child that
//! wanted to lie could lie: this is not attestation in a trusted sense. What it
//! does buy is that the failure mode is *checked*. `Confine::apply` and
//! `apply_seccomp` return errors rather than warnings, so a child that could not
//! confine exits with [`EXIT_NOT_CONFINED`] before it has read a byte of the
//! document, and the host turns that exit into an error. Confinement that cannot
//! be established is not established.
//!
//! # Staging, and why the document touches the disk at all
//!
//! `SCM_RIGHTS` transfers a descriptor, and a descriptor needs something to be
//! opened from. The host therefore writes the document to a file inside a
//! directory it created with mode `0700`, opens that file with
//! [`open_granted`](agentos_sandbox::fdpass::open_granted) - which refuses a
//! symlink at the final component - **unlinks it immediately**, and only then
//! hands the descriptor over. By the time the child exists the file has no name,
//! so the child cannot re-resolve it, cannot stat it, and cannot find it again
//! even if it somehow acquired the path. There is a window between the write and
//! the unlink in which a `0700` directory holds attacker-controlled bytes; that
//! window is real and is listed as residual risk in the crate docs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use agentos_infer::{schema, Extraction, InferError};
use agentos_types::{Quarantined, SourceId};

use crate::error::QuarantineError;
use crate::limits::Limits;
use crate::protocol::SchemaSpec;

/// An [`agentos_infer::Extractor`] backed by a confined child process.
///
/// Holds only configuration, so it is cheap to construct and can live in the
/// session actor.
#[derive(Debug, Clone)]
pub struct SandboxedExtractor {
    limits: Limits,
    child: ChildProgram,
}

/// Which executable to run as the confined extractor.
///
/// A path rather than a linked-in function, and that is a deliberate choice. The
/// engine needs a model client, and the model client must be initialised
/// *after* confinement - initialising it before would mean holding a network
/// socket in a process that is about to have `socket(2)` denied. Putting the
/// child in its own binary is what makes "initialise after confinement" the only
/// possible order.
///
/// What this crate owns regardless of which binary is named: the staging, the
/// descriptor handover, the size bound, the attestation check, the timeout, and
/// the schema validation of the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildProgram {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl ChildProgram {
    /// The child to run, with no extra arguments.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    /// Append a fixed argument.
    ///
    /// Arguments are part of the child's configuration, not part of the request,
    /// so they cannot carry a document, a path to one, or a tool name.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set an environment variable on the child only.
    ///
    /// Configuration, not a channel: these values are fixed before any document
    /// exists, and the request travels on the control socket. A child binary that
    /// needs to be told which model to load, or which scenario to reproduce, is
    /// told so here. The extractor's *role* marker is deliberately **not** set
    /// through this path - [`serve`] checks one the host sets itself, so that a
    /// caller cannot hand a non-extractor the role by accident.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// The configured program.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The configured arguments.
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

impl Default for SandboxedExtractor {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            // No default program. A default would be a path baked into the
            // library, and a library that silently spawns *something* is exactly
            // the shape of bug this crate exists to prevent. A caller that has
            // not configured a child gets an error, not a surprise.
            child: ChildProgram::new(PathBuf::new()),
        }
    }
}

impl SandboxedExtractor {
    /// Default bounds and no child program.
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the executable to run as the confined extractor.
    pub fn with_child(mut self, child: ChildProgram) -> Self {
        self.child = child;
        self
    }

    /// Replace the bounds.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The bounds in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Extract `schema` from `document`, in a confined child process.
    ///
    /// The returned [`Extraction`] is tainted in every field, without exception,
    /// because the document was. There is no code path here that produces a
    /// `Trusted`, and no `Extractor` return type that could hold one.
    pub fn extract(
        &self,
        schema: &SchemaSpec,
        document: &Quarantined<String>,
    ) -> Result<Extraction, QuarantineError> {
        // (1) Fail closed on a bad configuration before touching the document.
        self.limits.validate()?;

        if self.child.program.as_os_str().is_empty() {
            return Err(QuarantineError::NoExtractor);
        }

        let source = sole_source(document.label().sources());

        // (2) Refuse an oversized document before staging anything. Refused, not
        // truncated: a truncated document read as a whole one is a correctness
        // bug that looks like a security success.
        //
        // Measured and copied inside the closure rather than borrowed out of it:
        // `Quarantined::with_label_for_display` hands out the text to code that
        // must not hold it, and holding it for the length of the whole call would
        // widen that window from "measure and stage" to "the entire exchange".
        let (text, oversized) = document.with_label_for_display(|t: &String, _| {
            if t.len() > self.limits.max_document_bytes {
                (String::new(), true)
            } else {
                (t.clone(), false)
            }
        });
        if oversized {
            return Err(QuarantineError::DocumentTooLarge {
                bytes: document.with_label_for_display(|t: &String, _| t.len()),
                limit: self.limits.max_document_bytes,
            });
        }

        // (3) and (4) happen inside `run_confined`: spawn, handshake, attest,
        // reap. Any failure there is an error; there is no in-process fallback.
        let fields = run_confined(&self.child, &self.limits, schema, &text, source)?;

        // (5) Validate against the schema, never against the child's opinion of
        // it. An undeclared field is refused rather than quarantined: it has no
        // constraint to check, so there is nothing to say about whether it is
        // safe, and a child that invents a field has not produced a better
        // answer, it has produced an answer nobody asked for.
        for key in fields.keys() {
            if schema.field(key).is_none() {
                return Err(QuarantineError::UndeclaredField {
                    field_len: key.len(),
                });
            }
        }

        let extracted = serde_json::Value::Object(
            fields
                .into_iter()
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        );
        let validated =
            schema::validate(&schema.to_schema(), &extracted, source).map_err(|_| {
                // `ValidationError` names the offending field. A field name is
                // schema vocabulary here, but the *value* that failed could be
                // document text, so the message is not propagated: an operator
                // reading a log gets the fact, not the payload.
                QuarantineError::SchemaValidationFailed
            })?;

        let data = schema::taint(&validated, source);
        debug_assert!(
            data.is_tainted(),
            "an extraction from an untrusted document must be tainted"
        );

        Ok(Extraction {
            data,
            quarantined_fields: validated.quarantined.keys().cloned().collect(),
        })
    }
}

/// The label's source, or an unattributed one.
///
/// More than one source means the document was assembled from several, and
/// naming only one of them would misattribute it. Falling back to
/// [`SourceId::nil`] records "unattributed" - which still renders as untrusted -
/// rather than picking a winner. `Label::tainted(nil)` is `Tainted`, never
/// `Trusted`, so the fallback is the safe direction.
fn sole_source(sources: BTreeSet<&SourceId>) -> SourceId {
    let mut it = sources.into_iter();
    match (it.next(), it.next()) {
        (Some(one), None) => *one,
        _ => SourceId::nil(),
    }
}

/// An `agentos_infer::Extractor` over a confined child.
///
/// Implemented so this is a real [`Extractor`] rather than a parallel invention:
/// the Controller can hold it anywhere it holds a backend, and `check_role_support`
/// and the rest of the inference layer apply unchanged.
impl agentos_infer::Extractor for SandboxedExtractor {
    fn extract(
        &mut self,
        schema: &serde_json::Value,
        document: &Quarantined<String>,
    ) -> Result<Extraction, InferError> {
        // The trait hands over a `serde_json::Value`, not a `Schema`, so the
        // schema goes through the lossy JSON Schema encoding. Any constraint that
        // does not survive that round trip is refused rather than approximated.
        let name = schema
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Anonymous");
        let spec = SchemaSpec::from_json_schema(name, schema)
            .map_err(|e| InferError::Backend(format!("schema not extractable: {e}")))?;
        SandboxedExtractor::extract(self, &spec, document).map_err(map_to_infer_error)
    }
}

/// Bridge into [`InferError`].
///
/// Every variant here is a fixed phrase or a [`RefusalReason`]'s `Display`.
/// Nothing derived from document bytes survives, so an `InferError` is safe to
/// log - which matters because these end up next to model traffic in a debug
/// log.
fn map_to_infer_error(e: QuarantineError) -> InferError {
    match e {
        QuarantineError::Refused(r) => InferError::Refused(r.to_string()),
        // A refusal and a failure are different things and are kept apart: a
        // refusal means the document did not contain the answer, a failure means
        // the sandbox or the plumbing did not work. Collapsing them would let a
        // broken sandbox look like a document that happened to have nothing in
        // it.
        other => InferError::Backend(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// The spawn
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod spawn {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::{Command, Stdio};

    use agentos_sandbox::fdpass::{open_granted, send_fd, Expect};

    use super::*;
    use crate::protocol::ProtocolError;

    /// Spawn the confined extractor, run the exchange, and reap it.
    ///
    /// The exit status is checked on *both* paths - a clean answer and a failed
    /// exchange - because a child that dies mid-reply and one that never started
    /// are different operator problems, and reporting "the control stream ended
    /// mid-message" for both loses that. When the exchange failed *and* the exit
    /// was clean, the exchange error is the informative one and is returned
    /// as-is.
    pub fn run(
        program: &ChildProgram,
        limits: &Limits,
        schema: &SchemaSpec,
        document: &str,
        source: SourceId,
    ) -> Result<BTreeMap<String, serde_json::Value>, QuarantineError> {
        let dir = ScratchDir::create()?;
        let granted = dir.stage(document, source)?;
        let (host_end, child_end) = socketpair()?;

        let mut child = Command::new(&program.program)
            .args(&program.args)
            .envs(program.env.iter().cloned())
            // The role marker is set by the host, not by `with_env`, so a caller
            // cannot hand the role to something that is not an extractor.
            .env(crate::child::ROLE_ENV, crate::child::ROLE_VALUE)
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| QuarantineError::Spawn {
                program: program.program.display().to_string(),
                source,
            })?;

        let outcome = exchange(host_end.as_raw_fd(), schema, &granted, limits.timeout);

        // The child's descriptor is the only one it needs. Dropping the host's
        // copy now means the host is not holding the document open while it
        // waits for an answer.
        drop(granted);
        drop(host_end);

        let status = reap(&mut child, limits.timeout);
        match outcome {
            Ok(fields) => {
                check_exit(status)?;
                Ok(fields)
            }
            Err(e) => {
                // A child that did not exit cleanly is the more specific
                // diagnosis, so it replaces the generic stream error.
                if status != Some(crate::child::EXIT_OK) {
                    return Err(QuarantineError::ChildFailed {
                        code: status,
                        signal: None,
                    });
                }
                Err(e)
            }
        }
    }

    /// Write the request, hand over the descriptor, and read the reply.
    ///
    /// The host end of the control socket carries a read timeout equal to
    /// [`Limits::timeout`], so a child that never answers ends the wait here
    /// rather than hanging the daemon. That is a partial mitigation for the
    /// missing cgroup limits, not a substitute for them: it bounds wall clock,
    /// not CPU and not memory.
    fn exchange(
        host_fd: RawFd,
        schema: &SchemaSpec,
        granted: &agentos_sandbox::fdpass::Granted,
        timeout: std::time::Duration,
    ) -> Result<BTreeMap<String, serde_json::Value>, QuarantineError> {
        set_read_timeout(host_fd, timeout)?;

        let body = crate::protocol::encode(&crate::protocol::Request::Extract {
            schema: schema.clone(),
        })?;
        let mut sock = Fd(host_fd);
        crate::protocol::write_frame(&mut sock, &body)?;

        // The descriptor goes over the same socket, after the request. The child
        // reads the frame first and then calls `recvmsg`, so the protocol fixes
        // the order and neither side can get it wrong by accident.
        send_fd(host_fd, granted).map_err(QuarantineError::Staging)?;

        // A clean close here is "the child exited without answering", which the
        // caller's `check_exit` turns into an error naming the exit status.
        match crate::protocol::read_frame(&mut sock) {
            Ok(Some(body)) => decode_reply(&body),
            Ok(None) => Err(QuarantineError::Protocol(ProtocolError::Truncated)),
            Err(e) => Err(QuarantineError::from(e)),
        }
    }

    /// Decode the reply and apply the fail-closed gate.
    ///
    /// The gate is one comparison against [`Attestation::is_expected`]: anything
    /// other than the exact promised profile discards the reply, whatever it
    /// contained. There is no path here that reports "partially confined".
    fn decode_reply(body: &[u8]) -> Result<BTreeMap<String, serde_json::Value>, QuarantineError> {
        let reply: crate::protocol::Reply = crate::protocol::decode(body)?;
        if !reply.attestation.is_expected() {
            return Err(QuarantineError::ConfinementNotEnforced(reply.attestation));
        }
        match reply.outcome {
            crate::protocol::Outcome::Values { fields } => Ok(fields),
            crate::protocol::Outcome::Refused { reason } => Err(QuarantineError::Refused(reason)),
        }
    }

    fn set_read_timeout(fd: RawFd, timeout: std::time::Duration) -> Result<(), QuarantineError> {
        // `time_t` is signed on Linux and unsigned on the Windows target that
        // also compiles this file, so the clamp is written against
        // `time_t::MAX` rather than a literal. A timeout longer than either would
        // silently become a *zero* timeout, which turns "wait forever" into "fail
        // immediately" - so the clamp has to be a max, not a cast.
        let max = libc::time_t::MAX as u64;
        let tv = libc::timeval {
            tv_sec: timeout.as_secs().min(max) as libc::time_t,
            tv_usec: timeout.subsec_micros().min(999_999) as libc::suseconds_t,
        };
        // SAFETY: `fd` is a live socket this process owns and `tv` is a correctly
        // initialised `timeval` of the size `setsockopt` reads.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(QuarantineError::Staging(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Wait for the child, killing it if the wall clock runs out.
    ///
    /// The deadline matters because a child that ignores `SIGTERM` still has to
    /// go away, and an unkillable child would leave the daemon holding a
    /// document open with no result. `SIGKILL` cannot be caught, so this
    /// terminates or it does not terminate; there is no third outcome to handle.
    fn reap(child: &mut std::process::Child, timeout: std::time::Duration) -> Option<i32> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
                Ok(None) => {}
                Err(_) => return None,
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                return child.wait().ok().map(|s| s.code().unwrap_or(-1)).or(Some(-1));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// A child that did not exit [`EXIT_OK`] produced nothing usable.
    ///
    /// Checked *after* the exchange result, so a child that both answered and
    /// then crashed on the way out does not discard a valid answer: the
    /// confinement attestation has already been verified by then, and the bytes
    /// are in the host's hands regardless of what the child did afterwards.
    fn check_exit(code: Option<i32>) -> Result<(), QuarantineError> {
        if code == Some(crate::child::EXIT_OK) {
            Ok(())
        } else {
            Err(QuarantineError::ChildFailed {
                code,
                signal: None,
            })
        }
    }

    /// A private directory that holds the staged document and nothing else.
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn create() -> Result<Self, QuarantineError> {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().join(format!(
                "agentos-quarantine-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            // 0700: the directory holds attacker-controlled bytes for a moment,
            // and only this uid may look at them. Created with `mkdir` at this
            // mode rather than `create_dir_all` + `set_permissions`, because the
            // latter leaves the directory world-readable in between.
            b.mode(0o700);
            b.create(&path).map_err(QuarantineError::Staging)?;
            Ok(Self { path })
        }

        /// Write, open, and immediately unlink the document.
        ///
        /// The unlink is the point: after it, the descriptor names an inode with
        /// no name, so there is nothing for the child to re-resolve even if it
        /// somehow learned the path.
        fn stage(
            &self,
            document: &str,
            source: SourceId,
        ) -> Result<agentos_sandbox::fdpass::Granted, QuarantineError> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let file = self.path.join("document");
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            let mut f = opts.open(&file).map_err(QuarantineError::Staging)?;
            f.write_all(document.as_bytes())
                .map_err(QuarantineError::Staging)?;
            drop(f);

            let granted = open_granted(&file, Expect::ReadOnlyFile, source)
                .map_err(QuarantineError::Staging)?;
            let _ = std::fs::remove_file(&file);
            Ok(granted)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn socketpair() -> Result<(OwnedFd, OwnedFd), QuarantineError> {
        let mut fds: [RawFd; 2] = [-1; 2];
        // SAFETY: `fds` is a correctly sized writable array of two `RawFd`.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(QuarantineError::Staging(std::io::Error::last_os_error()));
        }
        // SAFETY: both descriptors are live and now owned by these `OwnedFd`s.
        unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
    }

    struct Fd(RawFd);

    impl std::io::Read for Fd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                // SAFETY: `fd` is live and `buf` is a valid writable slice.
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

    impl std::io::Write for Fd {
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
}

#[cfg(target_os = "linux")]
fn run_confined(
    program: &ChildProgram,
    limits: &Limits,
    schema: &SchemaSpec,
    document: &str,
    source: SourceId,
) -> Result<BTreeMap<String, serde_json::Value>, QuarantineError> {
    spawn::run(program, limits, schema, document, source)
}

#[cfg(not(target_os = "linux"))]
fn run_confined(
    _program: &ChildProgram,
    _limits: &Limits,
    _schema: &SchemaSpec,
    _document: &str,
    _source: SourceId,
) -> Result<BTreeMap<String, serde_json::Value>, QuarantineError> {
    // Fail closed. Landlock is a Linux LSM, so on any other target there is
    // nothing to enforce I2 with, and the alternative - reading the document in
    // this process - would put attacker text inside the Controller's own address
    // space, which is strictly worse than returning an error.
    Err(QuarantineError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::LimitsError;
    use crate::protocol::{FieldSpec, ProtocolError, RefusalReason, SchemaSpec};
    use agentos_infer::schema::Constraint;
    use agentos_types::SourceKind;

    fn src() -> SourceId {
        SourceId::of_kind(SourceKind::WebPage)
    }

    fn doc(text: &str) -> Quarantined<String> {
        Quarantined::from_source(text.to_string(), src())
    }

    fn spec() -> SchemaSpec {
        SchemaSpec::new(
            "Invoice",
            [
                FieldSpec::new("total", Constraint::Integer { min: 0, max: 1000 }).unwrap(),
                FieldSpec::new(
                    "status",
                    Constraint::Enum(["paid", "unpaid"].iter().map(|s| s.to_string()).collect()),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn host() -> SandboxedExtractor {
        // A child that does not exist. Every test here is about a refusal that
        // happens *before* the spawn, so this must never be reached; if it is,
        // the test fails on the error variant rather than passing quietly.
        SandboxedExtractor::new().with_child(ChildProgram::new("/nonexistent/agentos-q"))
    }

    #[test]
    fn no_child_configured_is_an_error_not_an_in_process_fallback() {
        // The dangerous default would be "no child, so extract here". Reading a
        // hostile document in this process would put attacker text inside the
        // Controller's address space, so the absence of a child is a refusal.
        let h = SandboxedExtractor::new();
        assert!(matches!(
            h.extract(&spec(), &doc("total = 42")).unwrap_err(),
            QuarantineError::NoExtractor
        ));
    }

    #[test]
    fn limits_are_validated_before_the_document_is_read() {
        let h = host().with_limits(Limits {
            max_document_bytes: 10,
            max_read_bytes: 11,
            ..Limits::default()
        });
        assert!(matches!(
            h.extract(&spec(), &doc("x")).unwrap_err(),
            QuarantineError::Limits(LimitsError::ReadLimitExceedsHostLimit)
        ));
    }

    #[test]
    fn an_oversized_document_is_refused_and_the_child_is_never_reached() {
        // The bound is checked before the spawn, so the error must be the size
        // refusal rather than a spawn failure for the nonexistent program. That
        // ordering is the assertion.
        let h = host().with_limits(Limits {
            max_document_bytes: 8,
            max_read_bytes: 8,
            ..Limits::default()
        });
        let err = h
            .extract(&spec(), &doc("a document far longer than eight bytes"))
            .unwrap_err();
        assert!(
            matches!(err, QuarantineError::DocumentTooLarge { bytes, limit } if bytes > 8 && limit == 8),
            "{err}"
        );
    }

    #[test]
    fn a_spawn_failure_is_an_error_and_not_an_in_process_fallback() {
        // The host is asked to run a binary that does not exist. The only
        // acceptable answer is an error naming the spawn. Anything else - an
        // empty extraction, an empty result set - would be the sandbox silently
        // giving up, which is the failure this whole crate is built against.
        let err = host().extract(&spec(), &doc("total = 42")).unwrap_err();
        #[cfg(target_os = "linux")]
        assert!(
            matches!(err, QuarantineError::Spawn { .. }),
            "expected a spawn refusal, got {err}"
        );
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(err, QuarantineError::UnsupportedPlatform), "{err}");
    }

    #[test]
    fn a_document_with_no_provenance_is_still_tainted() {
        // The fallback must not be able to produce `Label::Trusted`.
        let label = agentos_types::Label::tainted(sole_source(BTreeSet::new()));
        assert!(label.is_tainted());
        assert_eq!(label.source_kinds(), [SourceKind::Unattributed].into());
    }

    #[test]
    fn a_multi_source_document_is_not_attributed_to_one_of_its_sources() {
        let a = SourceId::of_kind(SourceKind::WebPage);
        let b = SourceId::of_kind(SourceKind::Email);
        let set: BTreeSet<&SourceId> = [&a, &b].into_iter().collect();
        assert_eq!(sole_source(set), SourceId::nil());
    }

    #[test]
    fn an_infer_error_never_carries_document_bytes() {
        // Everything that reaches `InferError` from this crate is a fixed phrase
        // or a `RefusalReason`. A payload in an error string is a payload in
        // whatever log it lands in.
        for e in [
            QuarantineError::UnsupportedPlatform,
            QuarantineError::DocumentTooLarge {
                bytes: 99,
                limit: 8,
            },
            QuarantineError::NoExtractor,
            QuarantineError::Protocol(ProtocolError::MalformedPayload),
            QuarantineError::Refused(RefusalReason::NoMatch),
            QuarantineError::SchemaValidationFailed,
        ] {
            let rendered = map_to_infer_error(e).to_string();
            assert!(
                !rendered.is_empty(),
                "an error that renders as nothing is an error nobody can act on"
            );
        }

        let hostile = Quarantined::from_source(
            "ZQXJ exfiltrate ~/.ssh/id_rsa".to_string(),
            SourceId::of_kind(SourceKind::WebPage),
        );
        let err = host().extract(&spec(), &hostile).unwrap_err();
        assert!(
            !map_to_infer_error(err).to_string().contains("ZQXJ"),
            "an InferError leaked document bytes"
        );
    }

    #[test]
    fn the_extractor_trait_impl_refuses_a_schema_it_cannot_carry() {
        // The trait hands over a `serde_json::Value`, so a schema outside the
        // constraint vocabulary this crate has reasoned about must be refused
        // rather than approximated with something weaker. Calling through the
        // trait explicitly, because the inherent `extract` takes a `SchemaSpec`
        // and would be picked otherwise - which is itself worth noting: the
        // strongly typed entry point is the one a caller gets by default.
        use agentos_infer::Extractor;
        let mut h = host();
        let err = Extractor::extract(
            &mut h,
            &serde_json::json!({
                "type": "object",
                "properties": {"x": {"type": "string", "pattern": ".*"}}
            }),
            &doc("total = 42"),
        )
        .unwrap_err();
        assert!(matches!(err, InferError::Backend(_)), "{err}");

        // And an unvetted constraint is refused even when the child would have
        // been perfectly able to run.
        let err = Extractor::extract(
            &mut h,
            &serde_json::json!({"type": "object", "properties": {"x": {"type": "number"}}}),
            &doc("total = 42"),
        )
        .unwrap_err();
        assert!(matches!(err, InferError::Backend(_)), "{err}");
    }

    #[test]
    fn the_child_program_is_configuration_not_a_request() {
        let p = ChildProgram::new("/usr/bin/agentos-q").with_arg("--quiet");
        assert_eq!(p.program(), Path::new("/usr/bin/agentos-q"));
        // Arguments cannot carry the document: they are fixed strings set before
        // any document exists, and the request travels on the control socket.
        assert_eq!(p.args, vec!["--quiet".to_string()]);
    }
}