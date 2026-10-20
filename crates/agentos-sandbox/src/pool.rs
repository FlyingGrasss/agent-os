//! A pre-forked, pre-confined pool of tool workers.
//!
//! # Why a pool at all
//!
//! Confinement is not cheap. [`Confine::apply`] builds a Landlock ruleset and
//! calls `landlock_restrict_self`; [`crate::apply_seccomp`] compiles a BPF
//! program and calls `prctl(PR_SET_SECCOMP)`. Neither belongs on the per-request
//! path: they cost milliseconds, and applying them to a *running* thread is the
//! wrong shape, because Landlock restricts only the calling thread unless ABI
//! V8's TSYNC is used and the caller here is a long-lived daemon thread that must
//! not become confined. So the pool forks and confines once, at construction, and
//! a request becomes a message to an already-confined process.
//!
//! # Confinement happens in the child, before the worker image runs
//!
//! The pool confines the child itself rather than asking the worker image to
//! confine itself. That ordering is deliberate:
//!
//! - the worker image is the part that later runs a hostile tool, so the code
//!   that decides *whether it is confined* must not be code the tool can
//!   influence;
//! - the confinement is installed between `fork(2)` and `execveat(2)`, so there
//!   is no window in which the image's loader, its constructors, or any thread
//!   its runtime spawns runs unconfined. Confining after `exec` would leave all
//!   of that outside the sandbox.
//!
//! The cost is that the child does Rust work after `fork(2)`, which is why
//! [`PoolConfig::allow_threaded_fork`] exists and defaults to off. See
//! [`PoolError::MultithreadedParent`].
//!
//! # Closing inherited descriptors, and why in this order
//!
//! Invariant I5 says a tool process may access only the descriptors it was
//! handed. Landlock cannot help: it constrains *path-based* access and cannot
//! revoke a descriptor the child already holds.
//!
//! A pooled worker is worse than a fresh `exec`, because it also inherits
//! whatever the *daemon* held at fork time and, across requests, whatever the
//! *previous request* held. A worker that kept last request's capability file
//! open would be an I5 violation no Landlock rule could detect, because the
//! worker would simply `read(2)` it. So the child scrubs its descriptor table
//! down to stdin, stdout, stderr and one control socket, and holds no capability
//! descriptor between requests.
//!
//! Three details are load-bearing:
//!
//! 1. **Order.** The scrub runs *before* Landlock and *before* seccomp, and it
//!    has to. Both primitives it needs are unavailable afterwards: `getdents64`
//!    is in neither seccomp allowlist, and `/proc/self/fd` is unreachable under
//!    a deny-by-default Landlock ruleset. A pool that scrubbed after confinement
//!    would be scrubbing nothing.
//! 2. **Asynchronous-signal safety.** Everything between `fork(2)` and
//!    `execveat(2)` must be safe in a process that just forked out of a
//!    possibly-multithreaded parent. That rules out `opendir`/`readdir`, which
//!    allocate, and rules out `std::fs`. The walk below is raw `open(2)` plus
//!    `getdents64(2)` over a stack buffer.
//! 3. **Verify, do not assume.** Both the fast path and the fallback path are
//!    followed by a second, read-only walk that confirms nothing above the
//!    control socket is still open. A scrub that half-worked is an I5 violation,
//!    and the only way to know is to look.
//!
//! `close_range(4, ~0)` is the preferred primitive where the kernel has it (5.9
//! and later): one syscall, no path resolution, and no race because the child is
//! single-threaded. It is tried first, and its absence is not an error. It cannot
//! run after confinement either, for the same reason `getdents64` cannot, so it
//! belongs in the same slot in the ordering above.
//!
//! # Fail closed
//!
//! There is no configuration in which this module serves an unconfined request.
//!
//! - a pool is constructed by forking every worker and waiting for each to
//!   complete a handshake; a worker that cannot be confined is a construction
//!   error, not a worker that is quietly used anyway;
//! - confinement is confirmed twice, and the second confirmation comes from the
//!   kernel rather than from the worker: `PR_SET_NO_NEW_PRIVS` and the seccomp
//!   mode are read out of `/proc/<pid>/status` after the handshake, so a worker
//!   that reported success and then lost its filter is still caught;
//! - when every worker is busy, a checkout waits for a bounded time and then
//!   returns [`PoolError::Exhausted`]. It never runs the request on the calling
//!   thread: an unconfined caller is not a confined worker, and serving it would
//!   make the pool a lie;
//! - a worker that dies mid-request yields [`PoolError::WorkerDied`] and no
//!   result. Partial output is never returned, because the caller cannot tell it
//!   apart from a complete answer.
//!
//! # What the pool does *not* do
//!
//! - **It is not a resource limiter.** No cgroup, so a runaway worker burns CPU
//!   until the idle timeout or the request cap reaps it. On the target host
//!   cgroup v2 is not delegable to an unprivileged uid.
//! - **It is not a namespace.** The worker shares the host's uid, mount table
//!   and network namespace. Landlock and seccomp are the whole story here.
//! - **It does not vouch for the worker's output.** A reply's descriptors are
//!   bounded by [`PoolConfig::max_returned_fds`] and unexpected ones are a
//!   protocol error, but a caller that accepts a returned descriptor is
//!   accepting an object from a process that was adversarial by construction.
//!
//! # A hard dependency this module does not own
//!
//! Capabilities reach the worker over `SCM_RIGHTS`, which is `sendmsg(2)` and
//! `recvmsg(2)`. Neither syscall is in any seccomp allowlist this crate defines,
//! and a filter installed *before* the worker starts therefore makes a descriptor
//! handover impossible. This module refuses to run in that state - the worker
//! dies, the handshake fails, and the pool reports `WorkerRefused` - which is the
//! correct behaviour and also means the pool does not work until `sendmsg` and
//! `recvmsg` are added to the profiles. That is recorded rather than worked
//! around, because the workaround would be to stop applying seccomp to workers,
//! which is exactly the kind of quiet degradation this crate forbids.

// Off Linux the portable types are still declared so cross-platform callers
// compile, and nothing reads them there. Attributed rather than allowed
// unconditionally, so dead code on the platform that matters is still reported.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::time::Duration;

use thiserror::Error;

/// Protocol version, the eighth byte of the handshake magic.
///
/// Bumped on any wire change. A worker whose handshake does not match is
/// refused, because a worker speaking a different protocol is a worker whose
/// framing this parent cannot reason about.
pub const PROTO_VERSION: u8 = 1;

/// Handshake magic: seven ASCII bytes plus [`PROTO_VERSION`].
const HELLO: [u8; 8] = *b"AOSPOOL\x01";

/// Environment variable naming the control socket inside the worker.
///
/// An environment variable rather than an argv entry so the worker's command line
/// stays exactly what the caller asked for.
pub const CONTROL_FD_ENV: &str = "AGENTOS_SANDBOX_POOL_CTL_FD";

/// The descriptor number the control socket is pinned to before `exec`.
///
/// Low enough that "close everything else" is a single contiguous range, and
/// clear of the standard streams. A worker that hardcodes a different number and
/// this pool disagreeing is a startup failure, not a silent misconfiguration: the
/// handshake would simply never arrive.
pub const CONTROL_FD: i32 = 3;

// Parent to worker.
const OP_RUN: u8 = 0x01;
const OP_FD_REPORT: u8 = 0x02;
const OP_SHUTDOWN: u8 = 0x03;
// Worker to parent. Disjoint from the request opcodes on purpose: a
// desynchronised stream can then never be mistaken for a valid reply.
const OP_REPLY: u8 = 0xA1;
const OP_ERROR: u8 = 0xA2;

/// Status byte meaning the worker completed the request.
const STATUS_OK: u8 = 0;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why the pool refused to serve a request.
///
/// Every variant is a refusal. None of them means "ran it anyway, less safely".
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PoolError {
    /// Worker pools are a Linux mechanism.
    #[error("worker pools are only implemented for linux")]
    UnsupportedPlatform,

    /// The configuration contradicts itself and was rejected before any fork.
    #[error("invalid pool configuration: {0}")]
    BadConfig(String),

    /// The pool refused to `fork` out of a multithreaded process.
    ///
    /// Between `fork(2)` and `execveat(2)` the child allocates, because applying
    /// Landlock and seccomp allocates. In a multithreaded parent the allocator's
    /// state may have been held by another thread at the instant of the fork, and
    /// the child can deadlock in `malloc`. Refusing is the only safe answer: the
    /// alternative is a pool that works most of the time.
    #[error(
        "refusing to fork a confined worker from a process with {threads} threads: the child \
         allocates between fork and exec, and the allocator may be held by another thread at the \
         fork. Construct the pool before starting other threads, or call \
         allow_threaded_fork to accept the risk deliberately"
    )]
    MultithreadedParent {
        /// Threads observed in `/proc/self/status` at construction.
        threads: u32,
    },

    /// The worker program could not be resolved to an executable.
    #[error("no executable named `{0}` was found on PATH")]
    ProgramNotFound(String),

    /// `fork`, `socketpair` or `execveat` failed.
    #[error("could not start a worker: {0}")]
    Spawn(#[source] std::io::Error),

    /// A worker started but refused to confine itself.
    ///
    /// The fail-closed path. The child's startup code wrote a refusal onto the
    /// control socket instead of the handshake, so the pool discards that worker
    /// and fails construction rather than serving from it.
    #[error("refusing to serve: worker would not confine itself: {0}")]
    WorkerRefused(String),

    /// A worker reached the handshake but the kernel disagrees about its
    /// confinement.
    ///
    /// Read out of `/proc/<pid>/status` rather than taken from the worker's own
    /// report, because a worker that has been talked into lying is exactly the
    /// case this pool has to survive.
    #[error("refusing to serve: worker {pid} is not confined: {why}")]
    NotConfined {
        /// The worker's pid.
        pid: i32,
        /// What the kernel actually reported.
        why: String,
    },

    /// A worker died, and any partial output was discarded.
    #[error("worker {pid} died mid-request ({status}); the result was discarded")]
    WorkerDied {
        /// The worker's pid.
        pid: i32,
        /// How it ended, plus the underlying error where there was one.
        status: String,
    },

    /// Every worker was busy for longer than the configured budget.
    #[error("no confined worker became available within {waited_ms}ms")]
    Exhausted {
        /// How long the checkout waited.
        waited_ms: u64,
    },

    /// The pool is shutting down.
    #[error("the pool is shutting down")]
    Shutdown,

    /// The worker reported a failed request.
    #[error("worker reported failure: {0}")]
    WorkerFailed(String),

    /// A worker sent something the request framing does not allow.
    ///
    /// Includes a worker that attached a descriptor nobody asked for. That
    /// matters specifically: a descriptor left queued would be adopted by the
    /// *next* request's capability list, which is a capability injection.
    #[error("worker violated the request framing: {0}")]
    ProtocolViolation(String),

    /// A reply exceeded the configured ceiling.
    #[error("reply of {len} bytes exceeds the configured maximum of {max}")]
    ReplyTooLarge {
        /// Size the worker claimed.
        len: u64,
        /// Configured ceiling.
        max: usize,
    },

    /// A descriptor could not be transferred.
    #[error("descriptor transfer failed: {0}")]
    Transfer(#[source] std::io::Error),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How the pool behaves.
///
/// Every knob that can affect safety is a refusal rather than a warning.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    workers: usize,
    idle_timeout: Duration,
    max_requests: u32,
    acquire_timeout: Duration,
    handshake_timeout: Duration,
    max_reply_bytes: usize,
    max_returned_fds: usize,
    allow_threaded_fork: bool,
}

impl Default for PoolConfig {
    /// Deliberately modest. Four workers is enough to stop one slow tool from
    /// serialising a session. These are not tuning recommendations and every one
    /// of them is overridable.
    fn default() -> Self {
        PoolConfig {
            workers: 4,
            // Long enough that a busy session never re-pays a cold spawn, short
            // enough that an idle daemon is not holding pinned descriptors
            // forever.
            idle_timeout: Duration::from_secs(30),
            // Bounds how much state a compromised worker can accumulate in a
            // process that stays confined.
            max_requests: 256,
            acquire_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            // 8 MiB. A reply is a tool's output; anything larger is a bug or an
            // attempt to exhaust the daemon.
            max_reply_bytes: 8 * 1024 * 1024,
            max_returned_fds: 8,
            allow_threaded_fork: false,
        }
    }
}

impl PoolConfig {
    /// Number of pre-forked, pre-confined workers.
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n;
        self
    }

    /// How long an idle worker survives before it is killed and replaced.
    ///
    /// This is the bound on how long a leaked worker can pin a descriptor it was
    /// handed. It is not a bound on a request's duration; that is the caller's.
    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    /// How many requests one worker serves before it is killed and replaced.
    ///
    /// The reason to replace rather than reuse forever: a worker that has served
    /// thousands of requests has accumulated whatever a long-lived hostile
    /// process can accumulate. Recreating it is cheaper than proving otherwise.
    pub fn max_requests(mut self, n: u32) -> Self {
        self.max_requests = n;
        self
    }

    /// How long a checkout waits for a free worker before failing.
    pub fn acquire_timeout(mut self, d: Duration) -> Self {
        self.acquire_timeout = d;
        self
    }

    /// How long a worker has to complete its startup handshake.
    pub fn handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Ceiling on a single reply's payload.
    pub fn max_reply_bytes(mut self, n: usize) -> Self {
        self.max_reply_bytes = n;
        self
    }

    /// Ceiling on descriptors a reply may carry.
    pub fn max_returned_fds(mut self, n: usize) -> Self {
        self.max_returned_fds = n;
        self
    }

    /// Accept the hazard of forking out of a multithreaded process.
    ///
    /// Off by default and refused rather than assumed; see
    /// [`PoolError::MultithreadedParent`]. Turning it on is a statement that the
    /// caller has checked the parent's threads are quiescent, not a request for
    /// best effort.
    pub fn allow_threaded_fork(mut self, allow: bool) -> Self {
        self.allow_threaded_fork = allow;
        self
    }

    fn validate(&self) -> Result<(), PoolError> {
        if self.workers == 0 {
            return Err(PoolError::BadConfig(
                "a pool with zero workers can never serve a request, which is an outage rather \
                 than a configuration"
                    .into(),
            ));
        }
        if self.idle_timeout.is_zero() {
            return Err(PoolError::BadConfig(
                "idle_timeout of zero would replace every worker between requests".into(),
            ));
        }
        if self.max_requests == 0 {
            return Err(PoolError::BadConfig(
                "max_requests of zero would replace every worker after every request".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Worker image
// ---------------------------------------------------------------------------

/// The program a pool forks and confines.
///
/// Resolution happens in the parent, before the fork. `execveat(2)` does not
/// search `PATH`, and searching it in the child would mean allocating after the
/// fork, which is precisely what this module refuses to do.
#[derive(Debug, Clone)]
pub struct WorkerImage {
    program: std::path::PathBuf,
    args: Vec<std::ffi::OsString>,
}

impl WorkerImage {
    /// A program to run, with no arguments.
    pub fn new(program: impl Into<std::path::PathBuf>) -> Self {
        WorkerImage {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Append one argument.
    pub fn arg(mut self, a: impl Into<std::ffi::OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    /// The program as given, unresolved.
    pub fn program(&self) -> &std::path::Path {
        &self.program
    }

    /// The arguments, without the `argv` terminator the pool adds.
    pub fn args(&self) -> &[std::ffi::OsString] {
        &self.args
    }

    /// An absolute path for this program, searching `PATH` if needed.
    pub fn resolve(&self) -> Result<std::path::PathBuf, PoolError> {
        // Anything with more than one component is a path and is used as given;
        // `execveat` will report `ENOENT` if it is wrong, which is a legible
        // error, whereas a silent PATH search would hide a typo.
        if self.program.components().count() > 1 {
            return Ok(self.program.clone());
        }
        let Some(path) = std::env::var_os("PATH") else {
            return Err(PoolError::ProgramNotFound(
                self.program.display().to_string(),
            ));
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(&self.program);
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
        Err(PoolError::ProgramNotFound(
            self.program.display().to_string(),
        ))
    }
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(_path: &std::path::Path) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Reply and worker report
// ---------------------------------------------------------------------------

/// What a worker said.
///
/// The payload is opaque to the pool. The pool is a transport, not a tool runner,
/// and interpreting it would mean interpreting the output of a process that was
/// adversarial by construction.
#[derive(Debug)]
pub struct Reply {
    payload: Vec<u8>,
    fds: Vec<std::os::fd::OwnedFd>,
}

impl Reply {
    /// The worker's output.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Descriptors the worker returned, if any.
    pub fn fds(&self) -> &[std::os::fd::OwnedFd] {
        &self.fds
    }

    /// Split into payload and descriptors.
    pub fn into_parts(self) -> (Vec<u8>, Vec<std::os::fd::OwnedFd>) {
        (self.payload, self.fds)
    }
}

/// What [`serve_worker`] reports after one request.
///
/// Exists so I5 is assertable rather than argued. A worker that says which
/// descriptors it held open while it ran is a worker that can be *shown* to have
/// held only the ones it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerReport {
    /// Every descriptor the worker had open while the request ran, including the
    /// control socket. Ascending.
    pub held_fds: Vec<i32>,
    /// The first bytes of each capability it was handed, in order.
    ///
    /// Truncated, so this is evidence that the descriptor was actually used
    /// rather than a copy of the input.
    pub cap_heads: Vec<Vec<u8>>,
}

impl WorkerReport {
    /// Serialise for a reply payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.held_fds.len() as u32).to_le_bytes());
        for fd in &self.held_fds {
            out.extend_from_slice(&fd.to_le_bytes());
        }
        out.extend_from_slice(&(self.cap_heads.len() as u32).to_le_bytes());
        for head in &self.cap_heads {
            out.extend_from_slice(&(head.len() as u32).to_le_bytes());
            out.extend_from_slice(head);
        }
        out
    }

    /// Parse a reply payload, or `None` if it is not a well-formed report.
    ///
    /// `None` rather than a panic, because these bytes came from a worker. Every
    /// length is checked against what is actually left, so a lying frame yields
    /// `None` instead of a huge allocation.
    pub fn decode(bytes: &[u8]) -> Option<WorkerReport> {
        let mut cur = Cursor::new(bytes);
        let n = cur.u32()? as usize;
        let mut held_fds = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            held_fds.push(cur.u32()? as i32);
        }
        let n = cur.u32()? as usize;
        let mut cap_heads = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let len = cur.u32()? as usize;
            cap_heads.push(cur.take(len)?.to_vec());
        }
        if !cur.at_end() {
            return None;
        }
        Some(WorkerReport {
            held_fds,
            cap_heads,
        })
    }
}

/// A bounds-checked reader over a reply payload.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, at: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.buf.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn at_end(&self) -> bool {
        self.at == self.buf.len()
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Condvar, Mutex, MutexGuard};
    use std::time::Instant;

    use super::{
        PoolConfig, PoolError, Reply, WorkerImage, CONTROL_FD, CONTROL_FD_ENV, HELLO, OP_ERROR,
        OP_FD_REPORT, OP_REPLY, OP_RUN, OP_SHUTDOWN, PROTO_VERSION, STATUS_OK,
    };
    use crate::fdpass::{recv_fd, send_fd, Granted};
    use crate::{Confine, SeccompProfile};

    /// How far a descriptor-table walk will look.
    ///
    /// A process with a million-descriptor limit does not need a million
    /// `getdents64` calls to prove the pool handed it four descriptors, and the
    /// walk runs on the cold path where tens of milliseconds is the budget.
    const FD_CEILING: i32 = 4096;

    /// Refusal codes the child exits with when it cannot get far enough to write
    /// onto the control socket.
    const EXIT_REFUSED: i32 = 70;

    /// A confined worker.
    struct Worker {
        pid: libc::pid_t,
        sock: UnixStream,
        served: u32,
        idle_since: Instant,
    }

    impl Worker {
        /// The worker's pid, or -1 once it has been terminated.
        fn pid(&self) -> i32 {
            self.pid
        }
    }

    /// Free workers plus bookkeeping.
    ///
    /// A checked-out worker is *moved out* of this list rather than referenced by
    /// index. That is what lets a request do blocking I/O without holding the
    /// pool's lock, and it makes "one worker, one holder" a property of the data
    /// rather than a lock discipline.
    struct Inner {
        free: Vec<Worker>,
        /// Workers the pool owns: idle plus checked out.
        live: usize,
        shutting_down: bool,
    }

    /// A pool of pre-confined workers.
    ///
    /// Construction forks and confines every worker; it returns an error rather
    /// than a partially usable pool.
    pub struct Pool {
        image: WorkerImage,
        program: PathBuf,
        confine: Confine,
        profile: SeccompProfile,
        config: PoolConfig,
        inner: Mutex<Inner>,
        cond: Condvar,
    }

    impl Pool {
        /// Fork `config.workers()` workers, confine each one, and wait for every
        /// one to handshake.
        ///
        /// `confine` and `profile` are retained and re-applied to every
        /// replacement worker, so a reaped worker comes back with the same
        /// confinement rather than with whatever the default happens to be.
        pub fn spawn(
            image: WorkerImage,
            confine: Confine,
            profile: SeccompProfile,
            config: PoolConfig,
        ) -> Result<Pool, PoolError> {
            config.validate()?;
            debug_assert_eq!(HELLO[7], PROTO_VERSION);

            let threads = thread_count().unwrap_or(0);
            if threads > 1 && !config.allow_threaded_fork {
                return Err(PoolError::MultithreadedParent { threads });
            }
            // Resolve the program before the first fork, not after: searching
            // PATH allocates, and there is no reason to do it in a forked child.
            let program = image.resolve()?;

            let pool = Pool {
                image,
                program,
                confine,
                profile,
                config,
                inner: Mutex::new(Inner {
                    free: Vec::new(),
                    live: 0,
                    shutting_down: false,
                }),
                cond: Condvar::new(),
            };

            {
                let mut inner = pool.lock();
                for _ in 0..pool.config.workers {
                    match pool.spawn_worker() {
                        Ok(w) => {
                            inner.live += 1;
                            inner.free.push(w);
                        }
                        Err(e) => {
                            // Fail closed: tear down whatever did come up rather
                            // than hand back a pool that serves from a subset.
                            let free = std::mem::take(&mut inner.free);
                            inner.live -= free.len();
                            inner.shutting_down = true;
                            drop(inner);
                            for mut w in free {
                                terminate(&mut w);
                            }
                            return Err(e);
                        }
                    }
                }
            }
            Ok(pool)
        }

        /// How many workers the pool tries to keep alive.
        pub fn capacity(&self) -> usize {
            self.config.workers
        }

        /// How many workers the pool owns right now, idle or checked out.
        ///
        /// Lower than [`Pool::capacity`] means replacements are failing to start,
        /// which is the state in which a checkout will eventually time out. It is
        /// exposed so an operator can see degradation rather than discovering it
        /// as a timeout.
        pub fn live(&self) -> usize {
            self.lock().live
        }

        /// How many workers are idle and ready right now.
        pub fn available(&self) -> usize {
            self.lock().free.len()
        }

        /// Reap expired and over-cap workers, then top the pool back up.
        ///
        /// Called automatically on every checkout. Public because a caller that
        /// sits idle for a long time has no checkout to piggyback on, and an
        /// expired worker pinning a descriptor it was handed is exactly what the
        /// idle timeout exists to prevent.
        pub fn maintain(&self) {
            let mut inner = self.lock();
            self.reap(&mut inner);
        }

        /// Take a worker out of the pool for the duration of one request.
        ///
        /// Waits up to [`PoolConfig::acquire_timeout`] for one to be free and
        /// then fails. It never runs the request on the calling thread.
        pub fn checkout(&self) -> Result<Lease<'_>, PoolError> {
            let started = Instant::now();
            let deadline = started + self.config.acquire_timeout;
            let mut inner = self.lock();

            loop {
                self.reap(&mut inner);

                if inner.shutting_down {
                    return Err(PoolError::Shutdown);
                }
                if let Some(mut worker) = inner.free.pop() {
                    // Count the lease against the request cap. The cap is on
                    // how many times a worker is handed out, not how many
                    // requests reach the protocol: a checkout that is then
                    // dropped has still spent the worker, and the point of the
                    // cap is to bound how long one process can pin whatever it
                    // was last handed.
                    worker.served += 1;
                    return Ok(Lease {
                        pool: self,
                        worker: Some(worker),
                    });
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(PoolError::Exhausted {
                        waited_ms: started.elapsed().as_millis() as u64,
                    });
                }
                let (next, _) = self
                    .cond
                    .wait_timeout(inner, deadline - now)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                inner = next;
            }
        }

        /// Stop the pool: no new checkouts, and every idle worker dies now.
        ///
        /// Workers currently checked out are killed when their lease is returned.
        /// Deliberately non-blocking, because a caller holding a lease against a
        /// hung worker would otherwise make shutdown hang too.
        pub fn shutdown(&self) {
            let free = {
                let mut inner = self.lock();
                inner.shutting_down = true;
                inner.live -= inner.free.len();
                std::mem::take(&mut inner.free)
            };
            for mut w in free {
                terminate(&mut w);
            }
        }

        fn lock(&self) -> MutexGuard<'_, Inner> {
            // A poisoned lock means another thread panicked while holding it. The
            // state is still coherent enough to reap and refuse, so recover
            // rather than cascade the panic into every later request.
            self.inner.lock().unwrap_or_else(|p| p.into_inner())
        }

        /// Give a worker back, killing it if it is over its request cap, if it
        /// already died, or if the pool is going away.
        fn return_worker(&self, mut worker: Worker) {
            let maybe_kill: Option<Worker>;
            {
                let mut inner = self.lock();
                if inner.shutting_down || worker.pid < 0 || worker.served >= self.config.max_requests
                {
                    inner.live -= 1;
                    maybe_kill = Some(worker);
                } else {
                    worker.idle_since = Instant::now();
                    inner.free.push(worker);
                    maybe_kill = None;
                }
            };
            if let Some(mut w) = maybe_kill {
                terminate(&mut w);
            }
            self.cond.notify_one();
        }

        /// Replace expired and over-cap workers, then refill to capacity.
        fn reap(&self, inner: &mut Inner) {
            if inner.shutting_down {
                return;
            }
            let mut retired: Vec<(Worker, bool)> = Vec::new();
            let mut kept = Vec::new();
            for w in inner.free.drain(..) {
                let idle_too_long = w.idle_since.elapsed() >= self.config.idle_timeout;
                let served_enough = w.served >= self.config.max_requests;
                // A worker can also die on its own: it crashed, or it was
                // killed from outside. Its `pid` field stays positive in that
                // case (only `terminate` sets it negative), so the checks above
                // would keep handing the corpse out. `worker_is_dead` closes
                // that by asking the kernel, through `waitpid(WNOHANG)`, whether
                // the child has actually exited -- and reaps it when it has.
                let dead = worker_is_dead(&w);
                if idle_too_long || served_enough || dead {
                    retired.push((w, dead));
                } else {
                    kept.push(w);
                }
            }
            inner.free.extend(kept);
            for (mut w, already_reaped) in retired {
                inner.live -= 1;
                if already_reaped {
                    // `worker_is_dead` called `waitpid`, so this pid is already
                    // gone. Signalling it now could hit an unrelated process
                    // that has since been allocated the same number; close the
                    // socket and forget it instead.
                    let _ = w.sock.shutdown(std::net::Shutdown::Both);
                    w.pid = -1;
                } else {
                    terminate(&mut w);
                }
            }

            // A replacement that fails to start reduces capacity; it does not
            // reduce confinement. The worker is simply absent, and a checkout
            // with nothing left will time out with `Exhausted` rather than serve
            // anything unconfined.
            while inner.live < self.config.workers {
                match self.spawn_worker() {
                    Ok(w) => {
                        inner.live += 1;
                        inner.free.push(w);
                    }
                    Err(_) => break,
                }
            }
        }

        /// Fork one worker, confine it, and wait for its handshake.
        ///
        /// The cold path. Everything expensive happens here, once per worker, and
        /// never on the request path.
        fn spawn_worker(&self) -> Result<Worker, PoolError> {
            let (host, ctl) = socketpair().map_err(PoolError::Spawn)?;

            // A socketpair takes the two lowest free descriptors. If either
            // landed in 0..=2, the daemon was started with a closed standard
            // stream, and the child would inherit the parent's end of its own
            // control socket at that number: the scrub only closes above
            // `CONTROL_FD`, so it would survive. Holding both ends means the
            // parent's shutdown no longer produces EOF, and the worker keeps
            // running. Refuse rather than spawn a worker with that hole.
            if socketpair_used_stdio(host, ctl) {
                // SAFETY: both descriptors are owned by this process.
                unsafe {
                    libc::close(host);
                    libc::close(ctl);
                }
                return Err(PoolError::Spawn(io::Error::other(
                    "standard descriptors 0, 1 or 2 are closed; refusing to spawn a \
                     worker that would inherit the control socket",
                )));
            }

            // argv and envp are materialised *before* the fork so the child needs
            // no allocation of its own beyond the confinement calls.
            let argv = cstrings(&self.argv_items());
            let envp = cstrings(&self.envp_items());

            // SAFETY: `fork` duplicates the address space. Both branches below
            // are constrained to confine-then-exec work; see the module docs on
            // why the parent must be single-threaded.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: both descriptors are owned by this process.
                unsafe {
                    libc::close(host);
                    libc::close(ctl);
                }
                return Err(PoolError::Spawn(err));
            }
            if pid == 0 {
                child_main(
                    ctl,
                    &self.program,
                    &self.confine,
                    self.profile,
                    &argv,
                    &envp,
                );
            }

            // SAFETY: `ctl` was the child's end; the parent must not keep it.
            unsafe { libc::close(ctl) };
            // SAFETY: `host` came from `socketpair` and is owned from here on.
            let sock = unsafe { UnixStream::from_raw_fd(host) };

            match self.await_handshake(sock, pid) {
                Ok(w) => Ok(w),
                Err(e) => {
                    // SAFETY: `pid` is this process's child.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    reap_pid(pid);
                    Err(e)
                }
            }
        }

        fn argv_items(&self) -> Vec<std::ffi::OsString> {
            let mut v = Vec::with_capacity(self.image.args().len() + 1);
            v.push(self.image.program().as_os_str().to_os_string());
            v.extend(self.image.args().iter().cloned());
            v
        }

        fn envp_items(&self) -> Vec<std::ffi::OsString> {
            let mut v: Vec<std::ffi::OsString> = Vec::with_capacity(32);
            for (k, val) in std::env::vars_os() {
                // The pool owns this variable. A stale value inherited from the
                // daemon's own environment would point the worker at a socket
                // that is not its control channel.
                if k == CONTROL_FD_ENV {
                    continue;
                }
                let mut joined = k;
                joined.push("=");
                joined.push(val);
                v.push(joined);
            }
            v.push(format!("{CONTROL_FD_ENV}={CONTROL_FD}").into());
            v
        }

        /// Read the worker's handshake, then check the kernel agrees it is
        /// confined.
        fn await_handshake(&self, sock: UnixStream, pid: libc::pid_t) -> Result<Worker, PoolError> {
            sock.set_read_timeout(Some(self.config.handshake_timeout))
                .map_err(PoolError::Spawn)?;
            let fd = sock.as_raw_fd();

            let mut magic = [0u8; 8];
            read_exact(fd, &mut magic).map_err(|e| died(pid, e))?;
            if magic != HELLO {
                return Err(PoolError::ProtocolViolation(format!(
                    "worker {} sent handshake {magic:02x?}, expected {HELLO:02x?}",
                    { pid }
                )));
            }
            let mut status = [0u8; 1];
            read_exact(fd, &mut status).map_err(|e| died(pid, e))?;
            if status[0] != STATUS_OK {
                let mut len = [0u8; 4];
                read_exact(fd, &mut len).map_err(|e| died(pid, e))?;
                let len = u32::from_le_bytes(len) as usize;
                if len > 4096 {
                    return Err(PoolError::ProtocolViolation(
                        "worker sent an oversized refusal message".into(),
                    ));
                }
                let mut msg = vec![0u8; len];
                read_exact(fd, &mut msg).map_err(|e| died(pid, e))?;
                return Err(PoolError::WorkerRefused(
                    String::from_utf8_lossy(&msg).into_owned(),
                ));
            }

            // Kernel-sourced confirmation rather than the worker's own word. The
            // handshake proved the worker reached its own startup code; this
            // proves the restrictions are still in force afterwards, which is the
            // property that matters and the one a compromised worker would lie
            // about.
            verify_confinement(pid)?;

            sock.set_read_timeout(None).map_err(PoolError::Spawn)?;
            Ok(Worker {
                pid,
                sock,
                served: 0,
                idle_since: Instant::now(),
            })
        }
    }

    impl Drop for Pool {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// A worker checked out of the pool, for the duration of one request.
    ///
    /// Dropping the lease returns the worker. Dropping it after the worker died
    /// kills the corpse and lets the next checkout replace it.
    pub struct Lease<'p> {
        pool: &'p Pool,
        worker: Option<Worker>,
    }

    impl Lease<'_> {
        /// Run one request in the worker, handing it `caps` as real descriptors.
        ///
        /// The descriptors travel over `SCM_RIGHTS` and are the worker's only
        /// route to the filesystem for this request. Nothing about them survives
        /// into the next one: the worker closes them when the exchange ends, and
        /// `send_fd` cannot invent a descriptor the caller does not hold.
        ///
        /// Any failure marks the worker dead and discards partial output.
        pub fn run(&mut self, caps: &[Granted], request: &[u8]) -> Result<Reply, PoolError> {
            self.exchange(OP_RUN, caps, request)
        }

        /// Ask the worker which descriptors it currently holds open.
        ///
        /// A diagnostic, and the thing that makes I5 assertable: a worker that
        /// can be made to enumerate its own descriptor table can be shown to hold
        /// only what it was given.
        pub fn fd_report(&mut self) -> Result<Reply, PoolError> {
            self.exchange(OP_FD_REPORT, &[], &[])
        }

        /// This worker's pid.
        pub fn pid(&self) -> i32 {
            self.worker.as_ref().map(Worker::pid).unwrap_or(-1)
        }

        /// Ask the worker to exit, and wait for it.
        pub fn shutdown(mut self) -> Result<(), PoolError> {
            let _ = self.exchange(OP_SHUTDOWN, &[], &[]);
            if let Some(mut w) = self.worker.take() {
                // `terminate` marks the pid dead, which is what makes
                // `return_worker` account for it rather than queue it again.
                terminate(&mut w);
                self.pool.return_worker(w);
            }
            Ok(())
        }

        fn exchange(
            &mut self,
            op: u8,
            caps: &[Granted],
            request: &[u8],
        ) -> Result<Reply, PoolError> {
            let result = self.exchange_inner(op, caps, request);
            if let Some(w) = self.worker.as_mut() {
                if result.is_err() {
                    // Any framing failure desynchronises the stream, so the
                    // worker is not reusable after one. Retire it rather than
                    // leave it in the pool to fail the next caller's request.
                    w.served = self.pool.config.max_requests;
                }
            }
            result
        }

        fn exchange_inner(
            &self,
            op: u8,
            caps: &[Granted],
            request: &[u8],
        ) -> Result<Reply, PoolError> {
            let worker = self
                .worker
                .as_ref()
                .ok_or_else(|| PoolError::ProtocolViolation("lease holds no worker".into()))?;
            let fd = worker.sock.as_raw_fd();

            // Header first, then the descriptors, then the payload. The order is
            // forced by `recv_fd`: it consumes exactly one byte of stream per
            // descriptor, so every plain read the peer does has to happen before
            // the descriptors arrive, and none after.
            let mut head = [0u8; 5];
            head[0] = op;
            head[1..].copy_from_slice(&(caps.len() as u32).to_le_bytes());
            write_all(fd, &head).map_err(|e| self.died(e))?;
            for g in caps {
                send_fd(fd, g).map_err(|e| self.died(e))?;
            }
            if request.len() > u32::MAX as usize {
                // The wire length is a u32, so a longer request would be framed
                // as a shorter one and desynchronise the stream.
                return Err(PoolError::ProtocolViolation(format!(
                    "request of {} bytes does not fit the wire format",
                    request.len()
                )));
            }
            write_all(fd, &(request.len() as u32).to_le_bytes())
                .and_then(|()| write_all(fd, request))
                .map_err(|e| self.died(e))?;

            let mut head = [0u8; 6];
            read_exact(fd, &mut head).map_err(|e| self.died(e))?;
            if head[0] != OP_REPLY && head[0] != OP_ERROR {
                return Err(PoolError::ProtocolViolation(format!(
                    "unexpected reply opcode {:#04x}",
                    head[0]
                )));
            }
            let status = head[1];
            let len = u32::from_le_bytes([head[2], head[3], head[4], head[5]]) as u64;
            if len > self.pool.config.max_reply_bytes as u64 {
                return Err(PoolError::ReplyTooLarge {
                    len,
                    max: self.pool.config.max_reply_bytes,
                });
            }
            let mut payload = vec![0u8; len as usize];
            read_exact(fd, &mut payload).map_err(|e| self.died(e))?;

            let mut n = [0u8; 4];
            read_exact(fd, &mut n).map_err(|e| self.died(e))?;
            let n = u32::from_le_bytes(n) as usize;
            if n > self.pool.config.max_returned_fds {
                return Err(PoolError::ProtocolViolation(format!(
                    "reply carried {n} descriptors, more than the configured maximum of {}",
                    self.pool.config.max_returned_fds
                )));
            }
            let mut fds = Vec::with_capacity(n);
            for _ in 0..n {
                fds.push(recv_fd(fd).map_err(PoolError::Transfer)?);
            }

            // Anything still queued after the reply is a descriptor nobody asked
            // for. Leaving it would let it be adopted by the *next* request's
            // capability list, which is a capability injection; taking it and
            // closing it turns the attempt into a visible protocol error.
            let stray = drain_stray_fds(fd).map_err(PoolError::Transfer)?;
            if stray > 0 {
                return Err(PoolError::ProtocolViolation(format!(
                    "worker attached {stray} descriptors that no request asked for"
                )));
            }

            if status != STATUS_OK {
                return Err(PoolError::WorkerFailed(
                    String::from_utf8_lossy(&payload).into_owned(),
                ));
            }
            Ok(Reply { payload, fds })
        }

        fn died(&self, e: io::Error) -> PoolError {
            PoolError::WorkerDied {
                pid: self.pid(),
                status: e.to_string(),
            }
        }
    }

    impl Drop for Lease<'_> {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                self.pool.return_worker(worker);
            }
        }
    }

    // -----------------------------------------------------------------------
    // The child: fork -> scrub -> confine -> exec
    // -----------------------------------------------------------------------

    /// Everything the forked child does, in the only order that is safe.
    ///
    /// Never returns.
    fn child_main(
        ctl: libc::c_int,
        program: &Path,
        confine: &Confine,
        profile: SeccompProfile,
        argv: &[CString],
        envp: &[CString],
    ) -> ! {
        // 1. Pin the control socket to a known descriptor number and clear
        //    CLOEXEC, or the exec would drop it and the handshake would never
        //    arrive. `dup3` clears FD_CLOEXEC on the new descriptor, but the
        //    no-op case (`ctl` is already 3) needs handling explicitly.
        if ctl != CONTROL_FD {
            // SAFETY: duplicating onto a descriptor this process owns. If it
            // fails there is no way left to report anything.
            if unsafe { libc::dup3(ctl, CONTROL_FD, 0) } < 0 {
                refuse_and_die(b"DUP_CTL_FAILED");
            }
            // SAFETY: `ctl` is a descriptor this process owns.
            unsafe { libc::close(ctl) };
        }
        // SAFETY: `fcntl(F_SETFD, 0)` takes no pointer arguments.
        if unsafe { libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) } < 0 {
            refuse_and_die(b"CLOEXEC_CLEAR_FAILED");
        }

        // 2. Scrub, then verify. Both must precede confinement; see the module
        //    docs for what stops working afterwards. A failure to enumerate is a
        //    failure to scrub: an unreadable `/proc/self/fd` must not be read as
        //    "nothing was inherited".
        if scrub_inherited_fds().is_err() || !matches!(leaked_fd_count(), Ok(0)) {
            refuse_and_die(b"FD_SCRUB_FAILED");
        }

        // Open the worker image while no sandbox is installed yet. Landlock will
        // not let this child travel the absolute path afterwards - the ruleset
        // only names the directories the worker is allowed at runtime, and every
        // ancestor is "everything else" - so the exec below goes through the
        // descriptor rather than the path.
        let prog_fd = unsafe {
            libc::open(
                cstring(program.as_os_str()).into_raw(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if prog_fd < 0 {
            refuse_and_die_msg(format!("OPEN_EXE errno={}", std::io::Error::last_os_error()));
        };

        // 3. Confine. Both calls refuse rather than degrade, and each writes a
        //    refusal to the control socket first so the parent can say why
        //    instead of reporting an unexplained dead child.
        if let Err(e) = confine.clone().apply() {
            refuse_and_die_msg(e.to_string());
        }
        if let Err(e) = crate::apply_seccomp(profile) {
            refuse_and_die_msg(e.to_string());
        }

        // 6. Handshake. The daemon waits for exactly one hello before it allows
        //    a worker into the pool, and it distinguishes a live hello from a
        //    dead socket by that prefix rather than by process liveness. This
        //    write has to happen before exec, because the worker image's own
        //    first opportunity to speak is only after the daemon has already
        //    started waiting: the protocol hangs if the image has to learn a
        //    protocol the daemon has already started.
        //
        // Status `OK` here means "the confinement calls above returned
        // success", not "everything is permanently safe": the kernel re-checks
        // `/proc/<pid>/status` after this in the daemon, and a worker image
        // that later dies or stops conforming is reported as such.
        let wrote = write_all(CONTROL_FD, &HELLO);
        if wrote.is_ok() {
            let ok = write_all(CONTROL_FD, &[STATUS_OK]);
            if ok.is_err() {
                refuse_and_die_msg("HELLO_WRITE_FAILED".into());
            }
        } else {
            refuse_and_die_msg("HELLO_WRITE_FAILED".into());
        }

        // 7. Hand over. `execveat` rather than `execve` because `execveat` is the
        //    exec primitive the crate's allowlist grants; with the filter already
        //    installed, `execve` would be refused with ENOSYS. Building the pointer
        //    arrays here allocates, which is the one place the child does so after
        //    the fork outside the confinement calls themselves; that is sound for
        //    the same reason those are, namely the single-threaded parent.
        let argv = raw_pointers(argv);
        let envp = raw_pointers(envp);
        // SAFETY: `argv` and `envp` are NUL-terminated arrays of pointers to
        // NUL-terminated strings, and they are still alive in this address space.
        // "let program be opened once while no confinement is installed yet,
        // then exec'd via `execveat(AT_EMPTY_PATH)`.` Confining with a partial
        // filesystem ruleset before exec did not let the kernel reach the
        // executable: Landlock treats the leading directories of the path
        // (the workspace root, the target dir, the parent of `deps/`) as
        // unrestricted, so the exec itself is denied. Open+execveat avoids the
        // path walk entirely.
        let rc = unsafe {
            libc::execveat(
                prog_fd,
                c"".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        let err = std::io::Error::last_os_error();
        let msg = format!("EXEC_FAILED errno={} path={}", rc, err);
        refuse_and_die_msg(msg);
    }

    // -----------------------------------------------------------------------
    // Reference worker
    // -----------------------------------------------------------------------

    /// Serve pool requests on `control_fd` until the parent closes the socket.
    ///
    /// The worker half of the protocol, shipped with the pool so the two ends
    /// cannot drift apart. It is deliberately minimal: its job is to be a
    /// faithful object of confinement tests, not a tool runtime. It reads each
    /// handed-over descriptor, reports which descriptors it held, and answers.
    /// Running the actual tool is somebody else's job.
    pub fn serve_worker(control_fd: i32) -> ! {
        // SAFETY: the pool pinned this descriptor to `CONTROL_FD` and cleared
        // CLOEXEC before exec, so it is open and this process owns it.
        let sock = unsafe { UnixStream::from_raw_fd(control_fd) };
        let fd = sock.as_raw_fd();

        loop {
            let mut head = [0u8; 5];
            if read_exact(fd, &mut head).is_err() {
                // The parent closed the socket, or this worker was replaced.
                std::process::exit(0);
            }
            let op = head[0];
            let n_caps = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
            if n_caps > 1024 {
                std::process::exit(71);
            }

            let mut caps: Vec<OwnedFd> = Vec::with_capacity(n_caps);
            for _ in 0..n_caps {
                match recv_fd(fd) {
                    Ok(c) => caps.push(c),
                    Err(_) => std::process::exit(71),
                }
            }

            let mut lenb = [0u8; 4];
            if read_exact(fd, &mut lenb).is_err() {
                std::process::exit(71);
            }
            let len = u32::from_le_bytes(lenb) as usize;
            if len > 64 * 1024 * 1024 {
                std::process::exit(71);
            }
            let mut _request = vec![0u8; len];
            if len > 0 && read_exact(fd, &mut _request).is_err() {
                std::process::exit(71);
            }

            match op {
                OP_SHUTDOWN => {
                    reply(fd, STATUS_OK, &[]);
                    std::process::exit(0);
                }
                OP_FD_REPORT => {
                    let payload = encode_fds(&open_fds());
                    reply(fd, STATUS_OK, &payload);
                }
                OP_RUN => {
                    let held = open_fds();
                    let mut heads = Vec::with_capacity(caps.len());
                    for c in &caps {
                        heads.push(read_head(c.as_raw_fd(), 64));
                    }
                    let report = super::WorkerReport {
                        held_fds: held,
                        cap_heads: heads,
                    };
                    reply(fd, STATUS_OK, &report.encode());
                    // The capabilities exist only for this request. Dropping them
                    // here is what stops the next request inheriting them, and the
                    // parent asserts it from the outside via `fd_report`.
                    drop(caps);
                }
                _ => {
                    reply(fd, 1, b"unknown opcode");
                    std::process::exit(71);
                }
            }
        }
    }

    fn encode_fds(fds: &[i32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + fds.len() * 4);
        out.extend_from_slice(&(fds.len() as u32).to_le_bytes());
        for f in fds {
            out.extend_from_slice(&f.to_le_bytes());
        }
        out
    }

    /// One reply: opcode, status, payload, and a descriptor count of zero.
    ///
    /// The reference worker returns no descriptors. That is a deliberate limit,
    /// not an omission: there is no safe way for this module to validate an
    /// object a hostile process produced, so it does not offer the capability.
    fn reply(fd: libc::c_int, status: u8, payload: &[u8]) {
        let opcode = if status == STATUS_OK { OP_REPLY } else { OP_ERROR };
        let mut head = [0u8; 6];
        head[0] = opcode;
        head[1] = status;
        head[2..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        if write_all(fd, &head).is_err()
            || write_all(fd, payload).is_err()
            || write_all(fd, &0u32.to_le_bytes()).is_err()
        {
            std::process::exit(72);
        }
    }

    /// Enumerate open descriptors without touching `/proc`.
    ///
    /// Under a deny-by-default Landlock ruleset `/proc` is unreachable, so the
    /// obvious implementation is the wrong one. `fcntl(F_GETFD)` is allowlisted by
    /// every seccomp profile and is unaffected by Landlock, so it works inside
    /// the sandbox.
    fn open_fds() -> Vec<i32> {
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        let ceiling = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
            (lim.rlim_cur as i64).min(FD_CEILING as i64) as i32
        } else {
            FD_CEILING
        };
        let mut out = Vec::new();
        for fd in 0..ceiling {
            // SAFETY: `fcntl(F_GETFD)` takes no pointer and has no side effects.
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                out.push(fd);
            }
        }
        out
    }

    /// Read up to `max` bytes from a descriptor, for evidence that it worked.
    fn read_head(fd: libc::c_int, max: usize) -> Vec<u8> {
        // Seek to the start before reading. This is not cosmetic: SCM_RIGHTS
        // hands the receiver the *same open file description*, and an open file
        // description carries a shared offset. So the first request's read
        // advances the offset that the second request's descriptor starts at,
        // and without this seek the second request sees an empty file. That is
        // the same inode either way - the security property under test is that
        // the worker still sees the original file, not the decoy, and it holds
        // regardless of the offset - but a worker that reads a capability must
        // see its contents on every request.
        // SAFETY: `fd` is an owned descriptor; `lseek` on it takes no pointer
        // and cannot fail in a way that leaves the descriptor unusable.
        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let mut buf = vec![0u8; max];
        let mut got = 0usize;
        while got < max {
            // SAFETY: writing into the tail of `buf`, which is live and zeroed.
            let n = unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr().add(got) as *mut libc::c_void,
                    max - got,
                )
            };
            if n > 0 {
                got += n as usize;
                continue;
            }
            // `n == 0` is end of file. `n < 0` is an error, and the only one
            // worth retrying is `EINTR`: anything else means the descriptor is
            // unreadable, and looping on it would spin. Both cases stop here,
            // which is why they are one arm rather than two identical ones.
            if n == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
        buf.truncate(got);
        buf
    }

    // -----------------------------------------------------------------------
    // fd-table hygiene
    // -----------------------------------------------------------------------

    /// Close every inherited descriptor except the standard streams and the
    /// control socket.
    ///
    /// A failure to enumerate is a failure to scrub, not a no-op: `close_range`
    /// may be unavailable on an old kernel, and `/proc` may not be mounted in a
    /// container. Returning `Ok` because nothing could be walked would leave the
    /// worker holding the daemon's descriptors, which is exactly what I5 forbids.
    fn scrub_inherited_fds() -> std::io::Result<()> {
        let first = CONTROL_FD + 1;
        // `close_range` is one syscall, resolves no paths, and cannot race
        // because the child is single-threaded. Tried first; its absence is not
        // an error, because the walk below is the actual enforcement and the
        // syscall is only an optimisation.
        let rc = unsafe {
            libc::syscall(
                sys_close_range(),
                first as libc::c_long,
                u32::MAX as libc::c_long,
                0 as libc::c_long,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        for_each_open_fd(c"/proc/self/fd", |fd| {
            if fd >= first {
                // SAFETY: `fd` came from the kernel's own enumeration of this
                // process, so it is open here. Nothing in this closure opens a
                // descriptor, so it cannot be closed twice.
                unsafe { libc::close(fd) };
            }
        })
    }

    /// How many descriptors are still open above the control socket.
    ///
    /// Runs before Landlock, because it reads `/proc/self/fd`. An `Err` means the
    /// count is *unknown*, and the caller must treat that as a refusal rather than
    /// as zero.
    fn leaked_fd_count() -> std::io::Result<i32> {
        let mut leaked = 0;
        for_each_open_fd(c"/proc/self/fd", |fd| {
            if fd > CONTROL_FD {
                leaked += 1;
            }
        })?;
        Ok(leaked)
    }

    /// `__NR_close_range`, or a value that always fails on architectures where
    /// it is unknown.
    fn sys_close_range() -> libc::c_long {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            libc::SYS_close_range
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            -1
        }
    }

    /// Walk `/proc/self/fd` with raw syscalls and apply `f` to each descriptor.
    ///
    /// `opendir`/`readdir` are not used because they allocate, and this runs in a
    /// process that just forked out of a possibly multithreaded parent.
    /// `open`, `getdents64` and `close` over a stack buffer allocate nothing.
    ///
    /// Returns `Err` if the directory cannot be opened, if `getdents64` fails, or
    /// if the buffer holds a malformed record. Callers must treat that as a
    /// refusal: a partial walk cannot prove that nothing was inherited, and
    /// saying "zero leaked" when the walk never ran is the fail-open this
    /// function exists to prevent.
    fn for_each_open_fd(
        dir_path: &std::ffi::CStr,
        mut f: impl FnMut(libc::c_int),
    ) -> std::io::Result<()> {
        // SAFETY: opening a NUL-terminated literal with no other pointer
        // arguments.
        let dir = unsafe {
            libc::open(
                dir_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if dir < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = [0u8; 4096];
        let walked = loop {
            // SAFETY: `buf` is 4096 writable bytes and `dir` is an open
            // directory descriptor this function owns.
            let n = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dir,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n == 0 {
                break Ok(());
            }
            if n < 0 {
                break Err(std::io::Error::last_os_error());
            }
            let n = n as usize;
            let mut off = 0usize;
            let mut malformed = false;
            while off < n {
                let base = unsafe { buf.as_ptr().add(off) };
                // struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen;
                //                      u8 d_type; char d_name[]; }
                let reclen =
                    unsafe { std::ptr::read_unaligned(base.add(16) as *const u16) } as usize;
                if reclen == 0 || off + reclen > n {
                    // A record that does not fit the buffer the kernel just
                    // filled is corruption, not an end-of-buffer marker. Stop
                    // with an error rather than silently accepting a partial
                    // view of the fd table.
                    malformed = true;
                    break;
                }
                let name = unsafe { base.add(19) };
                let max_name = reclen.saturating_sub(19);
                let mut value: libc::c_int = 0;
                let mut i = 0usize;
                loop {
                    if i >= max_name {
                        // No NUL inside the record: refuse to read into the next
                        // one looking for it.
                        value = -1;
                        break;
                    }
                    // SAFETY: bounded by the record's own length.
                    let c = unsafe { *name.add(i) };
                    if c == 0 {
                        break;
                    }
                    if !c.is_ascii_digit() || value < 0 {
                        value = -1;
                        break;
                    }
                    // `c_char` is signed, and the digit check above has already
                    // established it is in `b'0'..=b'9'`.
                    value = value
                        .saturating_mul(10)
                        .saturating_add((c - b'0') as i32);
                    i += 1;
                }
                // `dir` is this function's own handle and is closed below.
                if value > 0 && value != dir {
                    f(value);
                }
                off += reclen;
            }
            if malformed {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed /proc/self/fd record",
                ));
            }
        };
        // SAFETY: `dir` is owned by this function and closed exactly once.
        unsafe { libc::close(dir) };
        walked
    }

    // -----------------------------------------------------------------------
    // Kernel-sourced verification
    // -----------------------------------------------------------------------

    /// Confirm from `/proc/<pid>/status` that a worker is confined.
    ///
    /// Deliberately the kernel's view rather than the worker's. A worker that
    /// reports success but has lost its seccomp filter is the case worth
    /// catching, and only `/proc` can tell.
    fn verify_confinement(pid: libc::pid_t) -> Result<(), PoolError> {
        let path = format!("/proc/{pid}/status");
        let status = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                return Err(PoolError::NotConfined {
                    pid,
                    why: format!("cannot read {path}: {e}"),
                })
            }
        };
        let field = |name: &str| -> String {
            status
                .lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| "absent".into())
        };

        let nnp = field("NoNewPrivs");
        if nnp != "1" {
            return Err(PoolError::NotConfined {
                pid,
                why: format!(
                    "NoNewPrivs is {nnp}, expected 1; without it a setuid exec could shed Landlock"
                ),
            });
        }
        // 0 = disabled, 1 = strict, 2 = filter. Only 2 means a filter is loaded.
        let seccomp = field("Seccomp");
        if seccomp != "2" {
            return Err(PoolError::NotConfined {
                pid,
                why: format!("Seccomp is {seccomp}, expected 2 (SECCOMP_MODE_FILTER)"),
            });
        }
        Ok(())
    }

    /// Threads in this process, from `/proc/self/status`.
    fn thread_count() -> Option<u32> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status
            .lines()
            .find(|l| l.starts_with("Threads:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
    }

    // -----------------------------------------------------------------------
    // Small helpers
    // -----------------------------------------------------------------------

    fn cstring(s: &std::ffi::OsStr) -> CString {
        CString::new(s.as_bytes()).unwrap_or_else(|_| {
            // A NUL inside an argument is a programming error, but panicking in
            // the middle of building a child's argv is worse than running with a
            // visibly wrong one, which would fail at exec with a clear errno.
            CString::new("<invalid>").expect("literal without a NUL")
        })
    }

    fn cstrings(items: &[std::ffi::OsString]) -> Vec<CString> {
        items.iter().map(|i| cstring(i)).collect()
    }

    fn raw_pointers(items: &[CString]) -> Vec<*mut libc::c_char> {
        let mut v: Vec<*mut libc::c_char> = Vec::with_capacity(items.len() + 1);
        for c in items {
            v.push(c.as_ptr() as *mut libc::c_char);
        }
        v.push(std::ptr::null_mut());
        v
    }

    fn socketpair() -> io::Result<(libc::c_int, libc::c_int)> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a two-element array and the flags are valid.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    /// Whether the socketpair landed on a standard stream.
    ///
    /// That can only happen when the daemon was started with fd 0, 1 or 2
    /// closed. The child would then inherit the *parent's* end of the control
    /// socket at a number the scrub deliberately keeps, so the check is a
    /// precondition for the scrub's "only stdio and the control socket survive"
    /// claim to be true.
    fn socketpair_used_stdio(host: libc::c_int, ctl: libc::c_int) -> bool {
        host <= 2 || ctl <= 2
    }

    fn write_all(fd: libc::c_int, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            // SAFETY: writing `buf.len()` bytes from `buf`, which is live for the
            // duration of the call.
            let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the worker socket accepted zero bytes",
                ));
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn read_exact(fd: libc::c_int, buf: &mut [u8]) -> io::Result<()> {
        let mut at = 0usize;
        while at < buf.len() {
            // SAFETY: reading into the tail of `buf`, which is live.
            let n = unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr().add(at) as *mut libc::c_void,
                    buf.len() - at,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the worker closed the control socket",
                ));
            }
            at += n as usize;
        }
        Ok(())
    }

    /// Close any descriptors the worker queued that the reply did not account
    /// for, and return how many were closed.
    ///
    /// Four things are enforced here, because the sender is the hostile side:
    ///
    /// * **`cmsg_len` is checked before `CMSG_DATA` is read.** A payload shorter
    ///   than one descriptor would otherwise copy padding; the buffer is zeroed,
    ///   so that reads as fd `0` and this closes the daemon's stdin.
    /// * **Every descriptor in the message is closed**, not just the first. The
    ///   kernel installs all of them in this process, and a leaked one is a
    ///   capability nobody asked for.
    /// * **`MSG_CTRUNC` is an error.** Truncation means the kernel dropped part
    ///   of the message, so the count would be an understatement.
    /// * **The loop is bounded, and EOF ends it.** A worker can send
    ///   descriptors forever, and `recvmsg` returns `0` -- not `EAGAIN` -- once
    ///   it closes the socket, which the unbounded version spun on.
    fn drain_stray_fds(fd: libc::c_int) -> io::Result<usize> {
        const MAX_DRAIN_ROUNDS: usize = 128;
        let mut closed = 0usize;
        for _ in 0..MAX_DRAIN_ROUNDS {
            let mut byte = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr() as *mut libc::c_void,
                iov_len: 1,
            };
            let mut cmsg_buf = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_buf.len() as _;
            // SAFETY: every pointer refers to a live local for the duration of
            // the call, and MSG_DONTWAIT keeps this from blocking on an empty
            // queue.
            let got = unsafe {
                libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC)
            };
            if got < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN) => return Ok(closed),
                    Some(libc::EINTR) => continue,
                    _ => return Err(e),
                }
            }
            if got == 0 {
                // EOF from a worker that closed after replying. There is nothing
                // left to drain, and the next call would return zero forever.
                return Ok(closed);
            }
            // Close everything the message carried before deciding whether the
            // message itself is acceptable.
            close_message_fds(&msg, &mut closed);
            if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stray control message was truncated; some descriptors were dropped",
                ));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker kept sending descriptors after its reply",
        ))
    }

    /// Close every descriptor in an `SCM_RIGHTS` control message.
    ///
    /// Split out so both the normal drain and the truncated path close what they
    /// received instead of returning an error with the descriptors still open.
    fn close_message_fds(msg: &libc::msghdr, closed: &mut usize) {
        // SAFETY: `msg` describes a control buffer that is live for the duration
        // of the call. `cmsg_len` is checked before the payload is read, so a
        // short header cannot make `CMSG_DATA` copy past its message.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET
                    && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                {
                    let header = libc::CMSG_LEN(0) as usize;
                    let len = (*cmsg).cmsg_len as usize;
                    if len >= header {
                        let count =
                            (len - header) / std::mem::size_of::<libc::c_int>();
                        let data = libc::CMSG_DATA(cmsg);
                        for i in 0..count {
                            let mut f: libc::c_int = -1;
                            std::ptr::copy_nonoverlapping(
                                data.add(i * std::mem::size_of::<libc::c_int>()),
                                &mut f as *mut libc::c_int as *mut u8,
                                std::mem::size_of::<libc::c_int>(),
                            );
                            if f >= 0 {
                                libc::close(f);
                                *closed += 1;
                            }
                        }
                    }
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
    }

    /// A worker that stopped talking, with the reason the kernel can still give.
    fn died(pid: libc::pid_t, e: io::Error) -> PoolError {
        PoolError::WorkerDied {
            pid,
            status: format!("{e}; {}", exit_status(pid)),
        }
    }

    /// Whether a worker has exited, reaping it if so.
///
/// `waitpid(WNOHANG)` is the only check that is both non-blocking and not fooled
/// by a recycled pid: it returns the pid when the child has exited (and reaps
/// it), 0 while it is still running, and an error once it has already been
/// reaped. `kill(pid, 0)` is not enough, because a zombie answers it just like
/// a live process does.
fn worker_is_dead(worker: &Worker) -> bool {
    if worker.pid <= 0 {
        return true;
    }
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a live `c_int`; `WNOHANG` means this cannot block.
        let rc = unsafe { libc::waitpid(worker.pid, &mut status, libc::WNOHANG) };
        if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // rc > 0: exited and now reaped. rc == 0: still running. rc < 0: already
        // reaped by someone else, so this pool no longer owns it.
        return rc != 0;
    }
}

fn reap_pid(pid: libc::pid_t) {
        let mut status: libc::c_int = 0;
        loop {
            // SAFETY: `status` is a live `c_int` for the duration of the call.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
    }

    fn exit_status(pid: libc::pid_t) -> String {
        let mut status: libc::c_int = 0;
        // SAFETY: as above; WNOHANG means this cannot block.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == 0 {
            return "still running".into();
        }
        if rc < 0 {
            return "already reaped".into();
        }
        if libc::WIFEXITED(status) {
            return format!("exited with code {}", libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return format!("killed by signal {}", libc::WTERMSIG(status));
        }
        format!("status {status:#x}")
    }

    /// Kill a worker and reap it.
    ///
    /// SIGKILL rather than SIGTERM: the worker exists to run hostile code, and a
    /// worker that installs a `SIGTERM` handler is exactly the worker this pool
    /// must not have to reason about.
    fn terminate(worker: &mut Worker) {
        // SAFETY: `worker.pid` is a child of this process, and -1 is not.
        if worker.pid > 0 {
            unsafe { libc::kill(worker.pid, libc::SIGKILL) };
            // Closing the socket first means the worker's blocked `read` returns
            // and it exits on its own, so the kill is normally redundant and
            // only matters for a worker that stopped reading.
            let _ = worker.sock.shutdown(std::net::Shutdown::Both);
            reap_pid(worker.pid);
        } else {
            let _ = worker.sock.shutdown(std::net::Shutdown::Both);
        }
        worker.pid = -1;
    }

    /// Tell the parent why the child is refusing, then die.
    ///
    /// Takes a `&'static [u8]` on purpose. Formatting an error after a fork
    /// allocates, and the one thing worse than a worker that will not start is a
    /// child that deadlocks in `malloc` while trying to explain itself.
    fn refuse_and_die(msg: &'static [u8]) -> ! {
        refuse_and_die_msg_static(msg)
    }

    fn refuse_and_die_msg_static(msg: &[u8]) -> ! {
        let _ = write_all(CONTROL_FD, &HELLO);
        let _ = write_all(CONTROL_FD, &[1u8]);
        let _ = write_all(CONTROL_FD, &(msg.len() as u32).to_le_bytes());
        let _ = write_all(CONTROL_FD, msg);
        // SAFETY: `_exit` from the forked child, taking no locks and running no
        // atexit handlers.
        unsafe { libc::_exit(EXIT_REFUSED) }
    }

    fn refuse_and_die_msg(msg: String) -> ! {
        // The confinement errors are `Display`, so the message has to be
        // formatted. This happens after `fork` and so does allocate; it is the
        // one place where the module gives that up, because a refusal the
        // operator cannot read is not a useful refusal. The alternative would be
        // a static per-error-class string, which trades the actual reason for a
        // guess.
        let _ = write_all(CONTROL_FD, &HELLO);
        let _ = write_all(CONTROL_FD, &[1u8]);
        let _ = write_all(CONTROL_FD, &(msg.len() as u32).to_le_bytes());
        let _ = write_all(CONTROL_FD, msg.as_bytes());
        // SAFETY: as above.
        unsafe { libc::_exit(EXIT_REFUSED) }
    }

    #[cfg(test)]
    mod fd_table_tests {
        use super::*;
        use std::os::fd::AsRawFd;

        #[test]
        fn an_unreadable_fd_table_is_an_error_not_an_empty_one() {
            // The caller must be able to tell "nothing was inherited" from "I
            // could not look". Returning `Ok(())` with no calls is what would
            // turn a container without `/proc` into a worker holding every one
            // of the daemon's descriptors.
            let err = for_each_open_fd(c"/proc/agentos-no-such-fd-table", |_| {})
                .expect_err("an unreadable table must not read as empty");
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        }

        #[test]
        fn a_socketpair_on_a_standard_stream_is_refused_by_the_spawn_guard() {
            // The guard exists so `spawn_worker` never produces a child that
            // inherits the parent's end of the control socket at 0, 1 or 2.
            assert!(!socketpair_used_stdio(3, 4));
            assert!(!socketpair_used_stdio(4, 3));
            assert!(socketpair_used_stdio(0, 4));
            assert!(socketpair_used_stdio(4, 1));
            assert!(socketpair_used_stdio(4, 2));
        }

        #[test]
        fn the_walk_reports_a_descriptor_that_is_open() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let wanted = file.as_raw_fd();
            let mut seen = Vec::new();
            for_each_open_fd(c"/proc/self/fd", |fd| seen.push(fd)).unwrap();
            assert!(
                seen.contains(&wanted),
                "the walk missed an open descriptor ({wanted}): {seen:?}"
            );
        }
    }

    #[cfg(test)]
    mod stray_fd_tests {
        use super::*;
        use std::os::fd::AsRawFd;

        fn pair() -> (libc::c_int, libc::c_int) {
            let mut fds = [0 as libc::c_int; 2];
            let rc = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
            (fds[0], fds[1])
        }

        fn send_fds(socket: libc::c_int, fds: &[libc::c_int]) {
            let byte = [1u8];
            let mut iov = libc::iovec {
                iov_base: byte.as_ptr() as *mut libc::c_void,
                iov_len: 1,
            };
            let mut cmsg_buf = [0u8; 256];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            let payload = std::mem::size_of_val(fds) as u32;
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(payload) as _ };
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                assert!(!cmsg.is_null());
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(payload) as _;
                let data = libc::CMSG_DATA(cmsg);
                for (i, fd) in fds.iter().enumerate() {
                    std::ptr::copy_nonoverlapping(
                        fd as *const libc::c_int as *const u8,
                        data.add(i * std::mem::size_of::<libc::c_int>()),
                        std::mem::size_of::<libc::c_int>(),
                    );
                }
                let sent = libc::sendmsg(socket, &msg, 0);
                assert_eq!(
                    sent,
                    1,
                    "sendmsg: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        #[test]
        fn a_two_descriptor_stray_message_closes_both() {
            // The kernel installs every descriptor in the message before this
            // function runs. Closing only the first leaves the second open in
            // the daemon, which is a capability nobody asked for.
            let (a, b) = pair();
            let first = std::fs::File::open("/proc/self/status").unwrap();
            let second = std::fs::File::open("/proc/self/maps").unwrap();
            let (f1, f2) = (first.as_raw_fd(), second.as_raw_fd());

            send_fds(a, &[f1, f2]);
            let closed = drain_stray_fds(b).expect("drain");

            assert_eq!(closed, 2, "both stray descriptors must be closed");
            // The originals belong to this test and must still be open.
            assert!(unsafe { libc::fcntl(f1, libc::F_GETFD) } >= 0);
            assert!(unsafe { libc::fcntl(f2, libc::F_GETFD) } >= 0);

            unsafe {
                libc::close(a);
                libc::close(b);
            }
        }

        #[test]
        fn a_closed_sender_ends_the_drain_instead_of_spinning() {
            // `recvmsg` returns 0 at EOF, not EAGAIN. The unbounded loop treated
            // that as "nothing to do, try again" and never returned.
            let (a, b) = pair();
            unsafe {
                libc::close(a);
            }
            let closed = drain_stray_fds(b).expect("drain at EOF");
            assert_eq!(closed, 0);
            unsafe {
                libc::close(b);
            }
        }

        #[test]
        fn a_truncated_stray_message_is_an_error_not_an_undercount() {
            // More descriptors than the 64-byte control buffer can hold. The
            // kernel sets MSG_CTRUNC and drops the excess; reporting the ones
            // that fit as if they were all of them would hide the attempt.
            let (a, b) = pair();
            let files: Vec<std::fs::File> = (0..20)
                .map(|_| std::fs::File::open("/proc/self/status").unwrap())
                .collect();
            let fds: Vec<libc::c_int> = files.iter().map(|f| f.as_raw_fd()).collect();

            send_fds(a, &fds);
            let err = drain_stray_fds(b).expect_err("truncation must be reported");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

            unsafe {
                libc::close(a);
                libc::close(b);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{serve_worker, Lease, Pool};

/// Worker pools exist only where `fork`, Landlock and seccomp do.
///
/// `Confine` and a seccomp profile have no non-Linux form in this crate, so there
/// is nothing honest to construct here. The stub exists so cross-platform code
/// compiles without a `cfg` at every call site, and so a caller who asks for a
/// pool on Windows gets a refusal rather than a value that quietly does nothing.
#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{PoolConfig, PoolError, WorkerImage};

    /// Always refuses to be constructed.
    #[derive(Debug)]
    pub struct Pool {
        _private: (),
    }

    impl Pool {
        /// Always fails: worker pools are Linux-only.
        pub fn spawn(_image: WorkerImage, _config: PoolConfig) -> Result<Pool, PoolError> {
            Err(PoolError::UnsupportedPlatform)
        }

        /// Always fails: a `Pool` on a non-Linux target cannot be constructed.
        pub fn shutdown(&self) {}
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::Pool;