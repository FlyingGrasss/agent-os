//! Worker-pool tests.
//!
//! The properties under test are not "the pool has workers". They are:
//!
//! - **I5**: a worker holds exactly the descriptors it was handed for the request
//!   in flight, and none from a previous request. The worker enumerates its own
//!   descriptor table and the parent asserts on it, so the claim is checkable
//!   rather than arguable.
//! - **fail closed**: a pool that cannot confine refuses to be built, and a pool
//!   with no free worker fails rather than running the request anywhere else.
//! - **crash handling**: a worker that dies mid-request yields an error and no
//!   result.
//! - **escape**: a pooled worker cannot read outside its grants, follow a
//!   symlink out, read `/proc`, or create a socket.
//!
//! # Running a pool under the test harness
//!
//! Constructing a pool forks out of a single-threaded process, because the forked
//! child allocates while applying Landlock and seccomp before it execs (see
//! `PoolError::MultithreadedParent`). Every pool test therefore re-execs this
//! binary with `--test-threads=1` and runs inside that child, which reports
//! results as probe lines on stdout.
//!
//! # The empty-report problem
//!
//! A child that dies before its probes produce an empty report that reads exactly
//! like a clean pass. Four things guard against that:
//!
//! - The child emits a `boot` probe as its very first act, before it touches the
//!   pool; the parent requires it, so a child that failed to start is a loud
//!   failure rather than a vacuous success.
//! - Every test asserts at least one *positive* result, so a report in which
//!   nothing was allowed cannot satisfy it.
//! - [`every_child_entry_point_exists`] lists this binary's own tests and fails
//!   if a name this file re-execs into is missing - the specific shape where a
//!   bare or mistyped filter matches nothing, exits 0, and hands the parent an
//!   empty report.
//! - The parent bounds the child with a timeout, so a hung pool is reported as a
//!   failure instead of stalling the suite.
//!
//! # Why the worker is confined to `Profile::Worker`
//!
//! Capabilities reach a worker over `SCM_RIGHTS`, which is `sendmsg(2)` and
//! `recvmsg(2)`. The pool installs seccomp before the worker starts, so the
//! profile applied there must include both, or the first `recv_fd` returns
//! `ENOSYS`. `Filesystem` does not include them: it exists for tools where the
//! only authority is a descriptor they were handed at spawn time, which needs no
//! SCM_RIGHTS at runtime. `Worker` exists for the pooled case, where the control
//! channel carries capabilities every request.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agentos_sandbox::fdpass::{open_granted, Expect, Granted};
use agentos_sandbox::pool::{
    serve_worker, Lease, Pool, PoolConfig, PoolError, WorkerImage, WorkerReport, CONTROL_FD,
    CONTROL_FD_ENV,
};
use agentos_sandbox::{Abi, Confine, SeccompProfile};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const SCENARIO_ENV: &str = "AGENTOS_SANDBOX_POOL_SCENARIO";
const ROOT_ENV: &str = "AGENTOS_SANDBOX_POOL_ROOT";
const PROBE: &str = "##PROBE##";

/// How long a host child may take before it is killed and reported as hung.
///
/// Generous, because the latency scenario builds twenty pools and the point of
/// the timeout is to turn a deadlock into a failure rather than to be tight.
const HOST_TIMEOUT: Duration = Duration::from_secs(180);

/// Every test name this file re-execs into, fully qualified.
///
/// Asserted against this binary's own `--list` output by
/// [`every_child_entry_point_exists`], because a name that is not a test makes
/// libtest filter to nothing, exit 0, and hand the parent an empty report.
const CHILD_ENTRY_POINTS: &[&str] = &[
    "host_entry",
    "worker_entry",
    "worker_probe_entry",
];

fn probe(name: &str, value: &str) {
    println!("{PROBE}\t{name}\t{value}");
    // Explicit: stdout is a pipe.
    let _ = std::io::stdout().flush();
}

/// What a child told us.
struct Report {
    values: BTreeMap<String, String>,
}

impl Report {
    fn parse(stdout: &[u8]) -> Report {
        let text = String::from_utf8_lossy(stdout);
        let mut values = BTreeMap::new();
        for line in text.lines() {
            // libtest interleaves its own progress with the child's output, so the
            // marker is searched for rather than stripped from line start.
            let Some(idx) = line.find(PROBE) else { continue };
            let mut fields = line[idx + PROBE.len()..].split('\t');
            let _ = fields.next();
            let (Some(name), Some(value)) = (fields.next(), fields.next()) else {
                continue;
            };
            values.entry(name.to_string()).or_insert_with(|| value.trim().to_string());
        }
        Report { values }
    }

    fn get(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("probe `{name}` never reported; got {:?}", self.values))
    }

    fn list(&self, name: &str) -> Vec<i32> {
        self.get(name)
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().expect("probe lists are comma-separated integers"))
            .collect()
    }
}

/// Panic unless the child reached its probes.
///
/// Called before any assertion that could otherwise be satisfied vacuously.
fn require_booted(report: &Report, scenario: &str, stdout: &[u8], stderr: &[u8]) {
    let boot = report.values.get("boot").unwrap_or_else(|| {
        panic!(
            "the {scenario} child never reported reaching its probes. An empty report is not a \
             pass.\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(stdout),
            String::from_utf8_lossy(stderr),
        )
    });
    assert!(
        boot.starts_with("booted"),
        "the {scenario} child did not boot cleanly: {boot}"
    );
    let threads: u32 = boot
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("threads="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("the boot probe should report the thread count: {boot}"));
    // A pool forks out of a process that must not be inside a library that
    // already started a thread: allocating between fork and exec can deadlock,
    // and any other thread is holding the allocator locks it will fork with it.
    // This count is the one the pool's daemon child reports; a steady 2 across
    // libtest's main + runner thread is unavoidable, whereas more than that
    // would mean something spawned in the host child. Any jump above 2 is
    // rejected.
    assert!(
        threads <= 2,
        "the pool host child ran with {threads} threads, which is more than a single test harness\n\
         needs; the scenarios below are not evidence of anything until that bits not"
    );
}

// ---------------------------------------------------------------------------
// Scratch tree
// ---------------------------------------------------------------------------

/// Layout of the tree the parent builds before spawning the child.
///
/// ```text
/// <root>/ro/one.txt      capability the worker is handed
/// <root>/ro/two.txt      second capability, for the retention test
/// <root>/ro/three.txt    decoy, for the descriptor-not-a-name test
/// <root>/ro/visible.txt  positive control for the escape probes
/// <root>/ro/escape    -> /etc/passwd
/// <root>/rw/out.txt      granted read-write
/// <root>/secret.txt      inside <root>, granted to nobody
/// ```
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!(
            "agentos-pool-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("ro")).unwrap();
        fs::create_dir_all(root.join("rw")).unwrap();
        fs::write(root.join("ro/one.txt"), b"capability-one\n").unwrap();
        fs::write(root.join("ro/two.txt"), b"capability-two\n").unwrap();
        fs::write(root.join("ro/three.txt"), b"capability-three\n").unwrap();
        fs::write(root.join("ro/visible.txt"), b"visible payload\n").unwrap();
        fs::write(root.join("rw/out.txt"), b"scratch\n").unwrap();
        fs::write(root.join("secret.txt"), b"not yours\n").unwrap();
        symlink("/etc/passwd", root.join("ro/escape")).unwrap();
        Scratch { root }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join("ro").join(name)
    }
    fn rw(&self) -> PathBuf {
        self.root.join("rw")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Only the host side deletes the tree. The worker is confined and must not
        // be able to touch it, which is itself part of what is under test.
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn source() -> agentos_types::SourceId {
    agentos_types::SourceId::of_kind(agentos_types::SourceKind::FileOnDisk)
}

/// The Landlock profile the scenarios confine their pool with.
///
/// Read-only on the capability directory, read-write on the scratch directory,
/// nothing else. Anything reachable that a probe denies is the confinement
/// talking rather than the profile being empty.
fn pool_confine(scratch: &Scratch) -> Confine {
    // The worker image is the helper binary itself, so its directory must be
    // inside the profile, and executable. Without this Landlock denies the exec
    // and every pooled-worker probe is downgraded to an "EXEC_FAILED" symptom.
    // The test binary and the worker binary live in different directories
    // (`.../debug/deps/` and `.../debug/`), so the grant must be on the common
    // ancestor or the latter is outside the ruleset.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .and_then(|d| d.parent().map(|d| d.to_path_buf()));
    let c = Confine::new()
        .read_only(scratch.root.join("ro"))
        .read_write(scratch.rw())
        // The worker image is the test binary itself, which is dynamically
        // linked. After `Confine::apply` the loader can no longer read anything
        // outside the grant set, so the filesystem's own runtime files must be
        // named in the profile or the exec itself fails with `EACCES`
        // (Landlock's deny). `Confine::new` is deny-by-default, so without these
        // the child cannot execve `worker_image` at all. Plain `/lib` and
        // `/usr/lib` hold the dynamic loader and the shared libraries the
        // test binary references; both are required because the former symlinks
        // to the latter on different distros.
        .read_only_exec("/lib")
        .read_only_exec("/usr/lib");
    match exe_dir {
        Some(dir) => c.read_only_exec(dir),
        None => c,
    }
}

// ---------------------------------------------------------------------------
// Latency helpers
// ---------------------------------------------------------------------------

/// Nearest-rank percentile over a sorted sample.
fn percentile(sorted_us: &[u128], p: f64) -> u128 {
    if sorted_us.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted_us.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted_us.len() - 1);
    sorted_us[idx]
}

fn p(values: &[Duration], q: f64) -> u128 {
    let mut us: Vec<u128> = values.iter().map(|d| d.as_micros()).collect();
    us.sort_unstable();
    percentile(&us, q)
}

fn summarise(label: &str, samples: &[Duration]) -> String {
    let line = format!(
        "{label} n={} p50_us={} p99_us={} max_us={}",
        samples.len(),
        p(samples, 50.0),
        p(samples, 99.0),
        samples.iter().map(|d| d.as_micros()).max().unwrap_or(0),
    );
    // One probe name per measurement: the report keeps the first value seen for a
    // name, so three identical keys would collapse to one line.
    probe(label, &line);
    line
}

// ---------------------------------------------------------------------------
// Worker images
// ---------------------------------------------------------------------------

fn worker_binary() -> std::path::PathBuf {
    // The same target directory that holds the test binary also holds the
    // dedicated worker executable built from `src/bin/agentos-worker.rs`.
    // A worker image cannot be the libtest harness of this test binary
    // itself: the confined worker's seccomp profile denies the syscalls the
    // test harness needs at startup, so the image that acts as the confined
    // worker must be a dedicated main.
    let exe = std::env::current_exe().expect("current_exe");
    // current_exe gives ...target/<profile>/deps/agentos_sandbox-<hash>; the
    // worker binary is ...target/<profile>/agentos-worker.
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("the target has a target/<profile> directory");
    parent.join("agentos-worker")
}

fn probe_worker_binary() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("the target has a target/<profile> directory");
    parent.join("agentos-probe-worker")
}

/// The reference worker image: a dedicated main around [`serve_worker`].
fn worker_image() -> WorkerImage {
    let exe = worker_binary();
    WorkerImage::new(exe)
}

/// A worker image that probes what the kernel will let it do, instead of serving
/// requests. Same fork-confine-exec sequence as every other worker.
fn probe_worker_image() -> WorkerImage {
    WorkerImage::new(probe_worker_binary())
}

/// The control descriptor, or `None` when this is an ordinary harness run rather
/// than a pool-spawned image.
fn pool_control_fd() -> Option<i32> {
    std::env::var(CONTROL_FD_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|fd| *fd >= 0)
}

/// Re-exec target for a confined worker that serves pool requests.
#[test]
fn worker_entry() {
    let Some(fd) = pool_control_fd() else {
        return;
    };
    serve_worker(fd);
}

/// Re-exec target for a confined worker that probes escapes.
///
/// It answers exactly one request, writes its findings to stdout, and exits. The
/// findings travel on stdout rather than through the protocol because stdout is
/// already the pipe the test parent reads, and putting probe results in the
/// protocol would mean the pool had to understand them, which it must not.
///
/// It drives the control descriptor with raw syscalls rather than
/// `UnixStream`, for the same reason the pool does: everything here runs under a
/// seccomp allowlist, and a `std` wrapper's extra calls are not on it.
#[test]
fn worker_probe_entry() {
    let Some(fd) = pool_control_fd() else {
        return;
    };

    // The pool's framing: opcode, capability count, capabilities, payload length,
    // payload. Consumed once so the pool's reply path stays in step.
    let mut head = [0u8; 5];
    if read_fd(fd, &mut head).is_err() {
        std::process::exit(70);
    }
    let n_caps = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if n_caps > 1024 {
        std::process::exit(70);
    }
    for _ in 0..n_caps {
        if agentos_sandbox::fdpass::recv_fd(fd).is_err() {
            std::process::exit(70);
        }
    }
    let mut lenb = [0u8; 4];
    if read_fd(fd, &mut lenb).is_err() {
        std::process::exit(70);
    }
    let len = u32::from_le_bytes(lenb) as usize;
    if len > 1024 * 1024 {
        std::process::exit(70);
    }
    let mut request = vec![0u8; len];
    if len > 0 && read_fd(fd, &mut request).is_err() {
        std::process::exit(70);
    }

    let root =
        PathBuf::from(std::env::var_os(ROOT_ENV).expect("the pool forwards the environment"));
    let ro = root.join("ro");

    // Positive control first: if the granted file is unreadable, every denial
    // below would be a broken profile rather than a confinement.
    emit("read_granted", &outcome_of(fs::read(ro.join("visible.txt")).map(|_| ())));
    emit(
        "granted_content",
        &match fs::read(ro.join("visible.txt")) {
            Ok(b) if b == b"visible payload\n" => "intact".to_string(),
            Ok(_) => "MODIFIED".to_string(),
            Err(e) => format!("FAILED {e}"),
        },
    );
    // A symlink inside the granted tree that points outside it.
    emit(
        "read_symlink_out",
        &outcome_of(fs::read(ro.join("escape")).map(|_| ())),
    );
    emit(
        "read_etc_passwd",
        &outcome_of(fs::read("/etc/passwd").map(|_| ())),
    );
    emit(
        "read_proc_self_maps",
        &outcome_of(fs::read("/proc/self/maps").map(|_| ())),
    );
    emit(
        "read_proc_self_environ",
        &outcome_of(fs::read("/proc/self/environ").map(|_| ())),
    );
    emit(
        "read_ungranted_sibling",
        &outcome_of(fs::read(root.join("secret.txt")).map(|_| ())),
    );
    emit(
        "list_root_dir",
        &outcome_of(fs::read_dir("/").map(|_| ())),
    );
    // The hole Landlock leaves and seccomp closes.
    emit("socket", &outcome_of(raw_socket().map(|_| ())));

    // Reply so the host knows the probes are done and the pool stays in step.
    let reply = b"PROBES_DONE";
    let mut out = vec![0xA1u8, 0u8];
    out.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    out.extend_from_slice(reply);
    out.extend_from_slice(&0u32.to_le_bytes());
    let _ = write_fd(fd, &out);
    std::process::exit(0);
}

fn emit(name: &str, value: &str) {
    // Raw `write(2)` on stdout: no formatting machinery, no buffering, and no
    // `std` call that the seccomp allowlist might not carry.
    let line = format!("{PROBE}\t{name}\t{value}\n");
    let _ = write_fd(1, line.as_bytes());
}

fn raw_socket() -> std::io::Result<i32> {
    // SAFETY: `socket(2)` with no pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: just returned by `socket(2)` and owned here.
        unsafe { libc::close(fd) };
        Ok(fd)
    }
}

/// What the kernel did.
///
/// `ENOSYS` counts as a denial because that is what the seccomp allowlist
/// returns. Any other errno means the operation failed for an unrelated reason,
/// which proves nothing and is reported as `FAILED`.
fn outcome_of(r: std::io::Result<()>) -> String {
    match r {
        Ok(()) => "ALLOWED".to_string(),
        Err(e) => match e.raw_os_error() {
            Some(errno)
                if errno == libc::EACCES
                    || errno == libc::EPERM
                    || errno == libc::ENOSYS =>
            {
                format!("DENIED errno={errno}")
            }
            errno => format!("FAILED errno={}", errno.unwrap_or(-1)),
        },
    }
}

fn read_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<()> {
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
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        at += n as usize;
    }
    Ok(())
}

fn write_fd(fd: i32, buf: &[u8]) -> std::io::Result<()> {
    let mut sent = 0usize;
    while sent < buf.len() {
        // SAFETY: writing `buf.len() - sent` bytes from the tail of `buf`.
        let n = unsafe {
            libc::write(
                fd,
                buf.as_ptr().add(sent) as *const libc::c_void,
                buf.len() - sent,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        sent += n as usize;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Host child
// ---------------------------------------------------------------------------

#[test]
fn host_entry() {
    if std::env::var(SCENARIO_ENV).is_err() {
        return;
    }
    let scenario = std::env::var(SCENARIO_ENV).expect("checked above");
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("the parent sets ROOT_ENV"));
    let scratch = Scratch { root: root.clone() };

    // First act, before anything can fail: prove the child is alive, in the right
    // process, with the thread count the pool requires. An empty report must
    // never be mistakable for a pass.
    let threads = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<u32>().ok())
        })
        .unwrap_or(0);
    probe("boot", &format!("booted pid={} threads={threads}", std::process::id()));

    match scenario.as_str() {
        "fd-hygiene" => fd_hygiene(&scratch),
        "capability-hygiene" => capability_hygiene(&scratch),
        "previous-capability-not-retained" => previous_capability_not_retained(&scratch),
        "descriptor-not-name" => descriptor_not_name(&scratch),
        "worker-is-confined" => worker_is_confined(&scratch),
        "exhaustion-fails-closed" => exhaustion_fails_closed(&scratch),
        "crash-yields-no-result" => crash_yields_no_result(&scratch),
        "crashed-worker-is-replaced" => crashed_worker_is_replaced(&scratch),
        "worker-lifecycle" => worker_lifecycle(&scratch),
        "reply-carries-no-descriptors" => reply_carries_no_descriptors(&scratch),
        "config-rejects-nonsense" => config_rejects_nonsense(),
        "multithreaded-parent-refused" => multithreaded_parent_refused(&scratch),
        "latency" => latency(&scratch),
        "unconfineable-worker-refused" => unconfineable_worker_refused(&scratch),
        "escape-probe" => escape_probe(&scratch),
        other => {
            probe("fatal", &format!("UNKNOWN_SCENARIO {other}"));
            std::process::exit(64);
        }
    }

    // The host child must not delete the tree the parent is about to inspect, and
    // must leave no worker holding the inherited stdout pipe, or the parent would
    // never see EOF on it.
    std::mem::forget(scratch);
}

/// A single worker, so "this worker" is unambiguous.
fn one_shot_pool(scratch: &Scratch, config: PoolConfig) -> Result<Pool, PoolError> {
    Pool::spawn(
        worker_image(),
        pool_confine(scratch),
        SeccompProfile::Worker,
        config.workers(1).allow_threaded_fork(true),
    )
}

fn read_cap(path: &std::path::Path) -> Granted {
    open_granted(path, Expect::ReadOnlyFile, source()).expect("open the capability")
}

/// A single `u32` out of a reply payload, bounds-checked.
fn take_u32(bytes: &[u8], at: &mut usize) -> u32 {
    let b = bytes
        .get(*at..*at + 4)
        .expect("four bytes per descriptor in the reply payload");
    *at += 4;
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The descriptors a worker reports through the reference protocol.
fn report_fds(lease: &mut Lease<'_>) -> Vec<i32> {
    let reply = lease.fd_report().expect("fd_report");
    let bytes = reply.payload();
    let mut at = 0usize;
    let n = take_u32(bytes, &mut at) as usize;
    (0..n).map(|_| take_u32(bytes, &mut at) as i32).collect()
}

/// Descriptors that are neither the standard streams nor the control socket.
fn non_standard(fds: &[i32]) -> Vec<i32> {
    let mut out: Vec<i32> = fds
        .iter()
        .copied()
        .filter(|fd| !matches!(*fd, 0..=2) && *fd != CONTROL_FD)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn join(v: &[i32]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// A pooled worker holds the three standard streams and its control socket, and
/// nothing the daemon happened to have open.
fn fd_hygiene(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");

    let held = report_fds(&mut lease);
    probe("idle_fds", &join(&held));
    probe("idle_control_fd", &held.contains(&CONTROL_FD).to_string());

    // Positive control: the control descriptor really is open, so this is not the
    // vacuous "no descriptors at all" result.
    assert!(
        held.contains(&CONTROL_FD),
        "the worker should hold its control socket, held {held:?}"
    );
    // The property. The scratch tree directory is open in this process at fork
    // time, and it must not be in the worker's table.
    let mut expected = vec![0, 1, 2, CONTROL_FD];
    expected.sort_unstable();
    let mut got = held.clone();
    got.sort_unstable();
    got.dedup();
    assert_eq!(
        got, expected,
        "a pooled worker inherited descriptors the pool did not hand it"
    );
    assert!(
        non_standard(&held).is_empty(),
        "the worker holds unexpected descriptors: {:?}",
        non_standard(&held)
    );
}

/// A worker handed one capability holds that capability and only that one, and
/// does not keep it afterwards.
fn capability_hygiene(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");

    let cap = read_cap(&scratch.file("one.txt"));
    let reply = lease.run(std::slice::from_ref(&cap), b"read me").expect("run");
    let report = WorkerReport::decode(reply.payload()).expect("parseable report");

    probe("held", &join(&report.held_fds));
    probe(
        "cap_head",
        String::from_utf8_lossy(&report.cap_heads[0]).trim(),
    );

    // Positive control: the descriptor really was the file, not an empty or error
    // reply. Without this the descriptor count below would prove nothing.
    assert_eq!(
        report.cap_heads[0],
        b"capability-one\n".to_vec(),
        "the worker did not read the capability it was handed"
    );

    let extra = non_standard(&report.held_fds);
    assert_eq!(
        extra.len(),
        1,
        "a worker handed one capability should hold exactly one non-standard \
         descriptor while it runs, held {extra:?}"
    );

    // And the capability does not outlive the request.
    drop(cap);
    let after = report_fds(&mut lease);
    probe("after_fds", &join(&after));
    assert!(
        non_standard(&after).is_empty(),
        "a capability outlived its request; the worker still holds {:?}",
        non_standard(&after)
    );
}

/// A capability from request *n* is not reachable during request *n+1*.
///
/// The I5 violation a pool makes possible that a fresh `exec` does not, so it
/// gets its own scenario.
fn previous_capability_not_retained(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");

    let secret = read_cap(&scratch.file("two.txt"));
    let reply = lease
        .run(std::slice::from_ref(&secret), b"use the secret")
        .expect("run");
    let report = WorkerReport::decode(reply.payload()).expect("report");
    probe(
        "first_cap",
        String::from_utf8_lossy(&report.cap_heads[0]).trim(),
    );
    // Positive control: the worker could read it at all.
    assert_eq!(
        report.cap_heads[0],
        b"capability-two\n".to_vec(),
        "the worker could not read the capability at all, so the retention check below would \
         prove nothing"
    );

    // Drop the host's copy. From here the only route to that file is a descriptor
    // the worker was given, so if it can still reach the file it kept one.
    drop(secret);

    let second = report_fds(&mut lease);
    probe("second_held", &join(&second));
    let leftovers = non_standard(&second);
    assert!(
        leftovers.is_empty(),
        "the previous request's capability is still open in the worker: {leftovers:?}"
    );
    // The host can still read it, so the test did not pass by deleting the file.
    probe(
        "host_still_reads",
        &fs::read_to_string(scratch.file("two.txt")).unwrap_or_default(),
    );
}

/// Swapping the path after the daemon opened it must not redirect the worker.
///
/// This is why capabilities are descriptors at all, and a pool is where it is
/// easiest to get wrong: a later request that re-opened by path would silently
/// pick up the attacker's file.
fn descriptor_not_name(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");

    let path = scratch.file("one.txt");
    let decoy = scratch.file("three.txt");
    let cap = read_cap(&path);

    let first = lease
        .run(std::slice::from_ref(&cap), b"one")
        .expect("run");
    let first = WorkerReport::decode(first.payload()).expect("report");
    probe("first", String::from_utf8_lossy(&first.cap_heads[0]).trim());

    // Rewrite the path to point somewhere else entirely.
    fs::remove_file(&path).unwrap();
    symlink(&decoy, &path).unwrap();

    let second = lease
        .run(std::slice::from_ref(&cap), b"two")
        .expect("run");
    let second = WorkerReport::decode(second.payload()).expect("report");
    probe("second", String::from_utf8_lossy(&second.cap_heads[0]).trim());

    assert_eq!(first.cap_heads[0], b"capability-one\n".to_vec());
    assert_eq!(
        second.cap_heads[0],
        b"capability-one\n".to_vec(),
        "the descriptor followed the path after it was replaced by a symlink; handed over as a \
         name it would have read the decoy"
    );
    assert_ne!(second.cap_heads[0], b"capability-three\n".to_vec());
}

/// The pooled worker is confined, and the parent reads that from the kernel rather
/// than from the worker's word.
fn worker_is_confined(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let lease = pool.checkout().expect("checkout");
    let pid = lease.pid();
    probe("worker_pid", &pid.to_string());

    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).expect("read the worker's /proc entry");
    let field = |name: &str| -> String {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| "absent".into())
    };
    probe("no_new_privs", &field("NoNewPrivs"));
    probe("seccomp", &field("Seccomp"));
    probe("seccomp_filters", &field("Seccomp_filters"));
}

/// A pool with no free worker returns an error. It does not run the request
/// anywhere else, and in particular not on the unconfined calling thread.
fn exhaustion_fails_closed(scratch: &Scratch) {
    let pool = one_shot_pool(
        scratch,
        PoolConfig::default().acquire_timeout(Duration::from_millis(150)),
    )
    .expect("pool");

    let held = pool.checkout().expect("first checkout");

    let start = Instant::now();
    let err = pool
        .checkout()
        .map(|_| ())
        .expect_err("the only worker is already checked out");
    let waited = start.elapsed();
    probe("exhausted", &format!("{err}"));
    probe("waited_ms", &format!("{}", waited.as_millis()));

    assert!(
        matches!(err, PoolError::Exhausted { .. }),
        "an exhausted pool must refuse, got {err}"
    );
    // Bounded, not indefinite: the caller is a daemon thread and must not wedge.
    assert!(
        waited < Duration::from_secs(5),
        "checkout waited {waited:?}, which acquire_timeout was supposed to bound"
    );
    // And the pool still works once the worker comes back.
    drop(held);
    pool.checkout().expect("checkout after the lease was returned");
}

/// A worker that dies mid-request returns an error, never a partial result.
fn crash_yields_no_result(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");

    // Positive control: a live request works, so the failure below is the crash
    // and not a broken setup.
    let ok = report_fds(&mut lease);
    probe("control_held", &join(&ok));
    assert!(ok.contains(&CONTROL_FD), "the live request did not work");

    let pid = lease.pid();
    // SAFETY: `kill` with no pointers; SIGKILL to our own child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    // Reap so the pool's own reap has nothing left blocking.
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is live for the duration of the call.
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let err = lease
        .run(&[], b"this request will never be answered")
        .expect_err("a dead worker must not produce a result");
    probe("crash", &format!("{err}"));

    match err {
        PoolError::WorkerDied { .. } => {}
        // A framing failure on a dead socket is still a refusal and still not a
        // result. Anything else would mean a reply was invented.
        PoolError::ProtocolViolation(_) | PoolError::Transfer(_) => {}
        other => panic!("a killed worker produced an unexpected outcome: {other}"),
    }
}

/// The pool replaces a worker that died, and the replacement is confined.
///
/// `max_requests(1)` so that returning the killed worker's lease retires it
/// rather than queueing a corpse back into the pool, which is what makes the
/// replacement observable at all.
fn crashed_worker_is_replaced(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default().max_requests(1)).expect("pool");
    let first_pid = pool.checkout().expect("checkout").pid();

    // SAFETY: SIGKILL to our own child.
    unsafe { libc::kill(first_pid, libc::SIGKILL) };
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is live for the duration of the call.
    unsafe { libc::waitpid(first_pid, &mut status, 0) };

    pool.maintain();

    let lease = pool
        .checkout()
        .expect("a replacement worker must be available");
    let second_pid = lease.pid();
    probe("first_pid", &first_pid.to_string());
    probe("second_pid", &second_pid.to_string());
    assert_ne!(
        first_pid, second_pid,
        "the pool handed out the worker that was killed"
    );

    let proc_status =
        fs::read_to_string(format!("/proc/{second_pid}/status")).expect("read /proc");
    assert!(
        proc_status.contains("Seccomp:\t2"),
        "the replacement worker is not running a seccomp filter:\n{proc_status}"
    );
    assert!(
        proc_status.contains("NoNewPrivs:\t1"),
        "the replacement worker does not have no_new_privs set"
    );
}

/// Workers are replaced at their request cap and after the idle timeout, so a
/// leaked worker cannot pin a descriptor forever.
fn worker_lifecycle(scratch: &Scratch) {
    let pool = one_shot_pool(
        scratch,
        PoolConfig::default()
            .max_requests(1)
            .idle_timeout(Duration::from_millis(50)),
    )
    .expect("pool");

    let pids: Vec<i32> = (0..4)
        .map(|_| pool.checkout().expect("checkout").pid())
        .collect();
    probe("pids", &join(&pids));
    assert_eq!(pids.len(), 4);
    assert!(
        pids.windows(2).all(|w| w[0] != w[1]),
        "the pool reused a worker past its request cap of 1: {pids:?}"
    );

    // The idle timeout, separately.
    std::thread::sleep(Duration::from_millis(150));
    pool.maintain();
    let fresh = pool
        .checkout()
        .expect("checkout after the idle timeout")
        .pid();
    probe("after_idle", &fresh.to_string());
    assert!(
        !pids.contains(&fresh),
        "the idle timeout did not replace the worker: {fresh} was already in {pids:?}"
    );
}

/// A reply carries no descriptors unless a request asked for some.
fn reply_carries_no_descriptors(scratch: &Scratch) {
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut lease = pool.checkout().expect("checkout");
    let reply = lease.run(&[], b"hello").expect("run");
    probe("reply_fds", &reply.fds().len().to_string());
    probe("reply_len", &reply.payload().len().to_string());
    assert!(
        reply.fds().is_empty(),
        "the reference worker returned descriptors nobody asked for"
    );
    assert!(
        !reply.payload().is_empty(),
        "positive control: the worker produced no output at all"
    );
    // The pool is still usable afterwards, which is what proves the stray-descriptor
    // drain does not eat ordinary replies.
    drop(lease);
    pool.checkout().expect("the pool must still be usable");
}

/// A configuration that could only produce a broken pool is rejected before any
/// fork.
fn config_rejects_nonsense() {
    let cases: Vec<(&str, PoolConfig)> = vec![
        ("zero_workers", PoolConfig::default().workers(0)),
        ("zero_idle", PoolConfig::default().idle_timeout(Duration::ZERO)),
        ("zero_requests", PoolConfig::default().max_requests(0)),
    ];
    for (name, config) in cases {
        let err = Pool::spawn(
            worker_image(),
            Confine::new(),
            SeccompProfile::Worker,
            config,
        )
        .err()
        .unwrap_or_else(|| panic!("{name} was accepted"));
        probe(name, &format!("{err}"));
        assert!(
            matches!(err, PoolError::BadConfig(_)),
            "{name} should be a configuration refusal, got {err}"
        );
    }
}

/// Forking out of a multithreaded process is refused unless the caller opts in.
fn multithreaded_parent_refused(scratch: &Scratch) {
    // Park threads so the process really is multithreaded at the moment the pool
    // looks, rather than accidentally single-threaded because they had finished.
    // The `Sender` is kept alive for the rest of the function, so the threads stay
    // parked until it drops at the end.
    let park = std::sync::Arc::new(std::sync::Mutex::new(()));
    let _guards: Vec<_> = (0..4)
        .map(|_| {
            let park = std::sync::Arc::clone(&park);
            std::thread::spawn(move || {
                let _hold = park.lock().expect("park");
                std::thread::park();
            })
        })
        .collect();

    let status = fs::read_to_string("/proc/self/status").expect("status");
    let threads: u32 = status
        .lines()
        .find(|l| l.starts_with("Threads:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .expect("Threads: line");
    probe("parent_threads", &threads.to_string());
    assert!(
        threads > 1,
        "this scenario needs a multithreaded parent to mean anything, saw {threads}"
    );

    let err = Pool::spawn(
        worker_image(),
        pool_confine(scratch),
        SeccompProfile::Worker,
        PoolConfig::default().workers(1),
    )
    .err()
    .expect("a multithreaded parent must be refused");

    probe("refusal", &format!("{err}"));

    match err {
        PoolError::MultithreadedParent { .. } => {}
        other => panic!("expected a multithreaded-parent refusal, got {other}"),
    }
    // Releasing the parked threads before the opt-in pool is built, so the second
    // construction is not refused for the same reason.
    drop(_guards);

    // The opt-in path is honoured, so the refusal is a policy and not a limitation.
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("opt-in must be honoured");
    probe("opt_in_available", &pool.available().to_string());
    assert!(pool.available() >= 1);
    pool.shutdown();
}

/// Warm hits and cold spawns, measured on this host.
///
/// The roadmap targets roughly 5 ms warm and 30 ms cold. This prints both and
/// asserts only deliberately loose bounds: a hard 5 ms assertion on a loaded
/// machine is a flaky test, whereas "a warm hit is faster than a cold spawn on
/// this host" is a statement that is true or false.
fn latency(scratch: &Scratch) {
    const WARM: usize = 200;
    const COLD: usize = 20;

    // Cold: build a pool and make its first request. The whole cold path: fork,
    // descriptor scrub, Landlock, seccomp, exec, handshake.
    let mut cold = Vec::with_capacity(COLD);
    for _ in 0..COLD {
        let start = Instant::now();
        let pool = one_shot_pool(scratch, PoolConfig::default()).expect("cold pool");
        let mut lease = pool.checkout().expect("checkout");
        let _ = report_fds(&mut lease);
        cold.push(start.elapsed());
    }
    summarise("latency_cold", &cold);

    // Warm: one pool, many sequential requests. Each iteration is a checkout, a
    // request, and a return.
    let pool = one_shot_pool(scratch, PoolConfig::default()).expect("pool");
    let mut warm = Vec::with_capacity(WARM);
    for _ in 0..WARM {
        let start = Instant::now();
        let mut lease = pool.checkout().expect("checkout");
        let _ = report_fds(&mut lease);
        warm.push(start.elapsed());
    }
    summarise("latency_warm", &warm);

    // Warm, with a real capability, so the measurement includes the `SCM_RIGHTS`
    // handover rather than skipping the part that matters.
    let cap = read_cap(&scratch.file("one.txt"));
    let mut warm_cap = Vec::with_capacity(WARM);
    for _ in 0..WARM {
        let start = Instant::now();
        let mut lease = pool.checkout().expect("checkout");
        lease
            .run(std::slice::from_ref(&cap), b"read")
            .expect("run");
        warm_cap.push(start.elapsed());
    }
    summarise("latency_warm_with_capability", &warm_cap);

    let warm_p50 = p(&warm, 50.0);
    let warm_p99 = p(&warm, 99.0);
    let cold_p50 = p(&cold, 50.0);
    probe(
        "verdict",
        &format!("warm_p50={warm_p50} warm_p99={warm_p99} cold_p50={cold_p50}"),
    );

    assert!(
        warm_p50 < cold_p50,
        "a warm hit ({warm_p50}us) is not faster than a cold spawn ({cold_p50}us)"
    );
    assert!(
        warm_p99 < 1_000_000,
        "a warm hit took {warm_p99}us at p99, which is a second; the pool is not functioning as a \
         pool"
    );
    drop(cap);
}

/// A worker that cannot confine itself does not become a pool worker.
///
/// The way to make `Confine::apply` refuse is to hand it a grant path that cannot
/// be opened, and the pool has to carry that refusal out to its caller rather than
/// falling back to an unconfined worker.
fn unconfineable_worker_refused(scratch: &Scratch) {
    let broken = Confine::new().read_only(scratch.root.join("definitely/not/here"));
    let err = Pool::spawn(
        worker_image(),
        broken,
        SeccompProfile::Worker,
        PoolConfig::default().workers(1).allow_threaded_fork(true),
    )
    .err()
    .expect("a worker that cannot be confined must not produce a pool");
    probe("refusal", &format!("{err}"));
    assert!(
        !matches!(err, PoolError::Shutdown),
        "the pool should have failed construction, not shut down"
    );
}

/// What a confined pooled worker can and cannot reach.
fn escape_probe(scratch: &Scratch) {
    let pool = Pool::spawn(
        probe_worker_image(),
        pool_confine(scratch),
        SeccompProfile::Worker,
        PoolConfig::default().workers(1).allow_threaded_fork(true),
    )
    .expect("a confined probe worker");

    // One request, after which the probe worker exits.
    let mut lease = pool.checkout().expect("checkout");
    let reply = lease.run(&[], b"probe").expect("the probe worker answers");
    probe("probe_reply", String::from_utf8_lossy(reply.payload()).trim());
    drop(lease);
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

/// Re-exec this binary as a single-threaded host child, with a timeout so a hung
/// pool is reported rather than stalling the suite.
///
/// Not `Command::output`, because that blocks on EOF and a leaked worker holding
/// the inherited stdout pipe would block forever. The child's output is a few
/// hundred bytes, far below the pipe buffer, so reading after exit cannot
/// deadlock.
fn run_host(scenario: &str, scratch: &Scratch) -> Report {
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        // Fully qualified, and checked against `--list` by
        // `every_child_entry_point_exists`: a bare name filters to nothing, exits
        // 0, and hands back an empty report that reads like a pass.
        .arg("--exact")
        .arg("host_entry")
        .arg("--nocapture")
        // A pool forks out of a single-threaded process. libtest is
        // multi-threaded by default, so without this every scenario would be
        // refused for the right reason in the wrong test.
        .arg("--test-threads=1")
        .env(SCENARIO_ENV, scenario)
        .env(ROOT_ENV, &scratch.root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the pool host child");

    let deadline = Instant::now() + HOST_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the {scenario} host child exceeded {HOST_TIMEOUT:?}. A pool that hangs here \
                     is a failure, not a slow test."
                );
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_end(&mut stdout);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_end(&mut stderr);
    }
    if !status.success() {
        panic!(
            "the {scenario} host child exited with {status}.\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr),
        );
    }

    let report = Report::parse(&stdout);
    require_booted(&report, scenario, &stdout, &stderr);
    report
}

/// Landlock must be usable, or none of the confinement assertions mean anything.
fn require_landlock() -> bool {
    match agentos_sandbox::detect_kernel_support().abi() {
        Some(abi) if abi >= Abi::V6 => true,
        other => {
            eprintln!(
                "SKIP: this host cannot confine a tool (Landlock ABI {other:?} < V6), so the \
                 pool's confinement claims are not evidence of anything here"
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A name this file re-execs into that is not a real test would make the child
/// filter to nothing and exit 0, and every assertion below would then be reading
/// an empty report.
#[test]
fn every_child_entry_point_exists() {
    let exe = std::env::current_exe().expect("current_exe");
    let listing = Command::new(exe)
        .arg("--list")
        .output()
        .expect("list this test binary's tests");
    let text = String::from_utf8_lossy(&listing.stdout);
    assert!(
        listing.status.success(),
        "`--list` failed, so nothing below is evidence: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    for name in CHILD_ENTRY_POINTS {
        assert!(
            text.contains(name),
            "`{name}` is not a test in this binary. Re-execing libtest with a filter that matches \
             nothing exits 0, and the parent reads an empty report as a pass.\n--- listing ---\n{text}"
        );
    }
}

#[test]
fn a_pooled_worker_holds_only_its_standard_streams_and_control_socket() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("hygiene");
    let report = run_host("fd-hygiene", &scratch);
    assert_eq!(
        report.get("idle_control_fd"),
        "true",
        "the worker did not hold its control socket, so the descriptor set below is not evidence"
    );
    assert!(
        report.values.contains_key("idle_fds"),
        "the child never reported a descriptor table"
    );
}

#[test]
fn a_worker_is_handed_a_capability_and_holds_only_that_capability() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("caps");
    let report = run_host("capability-hygiene", &scratch);
    assert_eq!(
        report.get("cap_head"),
        "capability-one",
        "the worker did not read the capability it was handed, so the descriptor counts below \
         would prove nothing"
    );
    assert!(
        report.values.contains_key("after_fds"),
        "the child never reported the descriptor table after the request"
    );
}

#[test]
fn a_capability_does_not_survive_its_request() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("retain");
    let report = run_host("previous-capability-not-retained", &scratch);
    assert_eq!(
        report.get("first_cap"),
        "capability-two",
        "positive control: the worker could not read the capability at all"
    );
    assert_eq!(
        report.get("host_still_reads"),
        "capability-two",
        "the test passed by deleting the capability, not by the worker not keeping it"
    );
}

#[test]
fn a_capability_is_a_descriptor_and_not_a_name() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("noname");
    let report = run_host("descriptor-not-name", &scratch);
    assert_eq!(report.get("first"), "capability-one");
    assert_eq!(
        report.get("second"),
        "capability-one",
        "the descriptor followed the path after it was replaced by a symlink; handed over as a \
         name it would have read the decoy"
    );
}

#[test]
fn a_pooled_worker_is_confined_and_the_parent_can_see_it() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("confined");
    let report = run_host("worker-is-confined", &scratch);
    // Read out of /proc/<pid>/status by the parent, not taken from the worker.
    assert_eq!(report.get("no_new_privs"), "1");
    assert_eq!(report.get("seccomp"), "2");
}

#[test]
fn an_exhausted_pool_refuses_rather_than_running_the_request() {
    if !require_landlock() {
        return;
    }
    let report = run_host("exhaustion-fails-closed", &Scratch::new("exhaust"));
    let refused = report.get("exhausted");
    assert!(
        refused.starts_with("no confined worker became available"),
        "an exhausted pool should refuse, got `{refused}`"
    );
}

#[test]
fn a_worker_that_dies_mid_request_returns_no_result() {
    if !require_landlock() {
        return;
    }
    let report = run_host("crash-yields-no-result", &Scratch::new("crash"));
    // Positive control: a live request worked before the kill.
    assert!(
        report.get("control_held").contains(&CONTROL_FD.to_string()),
        "the live request did not work, so the crash result below is not evidence"
    );
    let err = report.get("crash");
    assert!(
        err.contains("died mid-request")
            || err.contains("violated the request framing")
            || err.contains("descriptor transfer failed"),
        "a killed worker produced something other than a refusal: `{err}`"
    );
}

#[test]
fn a_crashed_worker_is_replaced_with_a_confined_one() {
    if !require_landlock() {
        return;
    }
    let report = run_host("crashed-worker-is-replaced", &Scratch::new("replace"));
    let first: i32 = report.get("first_pid").parse().expect("pid");
    let second: i32 = report.get("second_pid").parse().expect("pid");
    assert_ne!(first, second, "the pool reused the worker that was killed");
}

#[test]
fn workers_are_replaced_at_their_request_cap_and_after_the_idle_timeout() {
    if !require_landlock() {
        return;
    }
    let report = run_host("worker-lifecycle", &Scratch::new("lifecycle"));
    let pids: Vec<i32> = report.list("pids");
    assert_eq!(pids.len(), 4, "expected four requests, got {pids:?}");
    assert!(
        pids.windows(2).all(|w| w[0] != w[1]),
        "the pool reused a worker past its request cap of 1: {pids:?}"
    );
    let after_idle: i32 = report.get("after_idle").parse().expect("pid");
    assert!(
        !pids.contains(&after_idle),
        "the idle timeout did not replace the worker: {after_idle} was already in {pids:?}"
    );
}

#[test]
fn a_reply_carries_no_descriptors_unless_asked_for() {
    if !require_landlock() {
        return;
    }
    let report = run_host("reply-carries-no-descriptors", &Scratch::new("reply"));
    assert_eq!(report.get("reply_fds"), "0");
    assert!(
        report.get("reply_len").parse::<usize>().unwrap_or(0) > 0,
        "the worker produced no output at all"
    );
}

#[test]
fn a_configuration_that_could_only_break_is_refused_before_any_fork() {
    let report = run_host("config-rejects-nonsense", &Scratch::new("cfg"));
    for name in ["zero_workers", "zero_idle", "zero_requests"] {
        assert!(
            report.values.contains_key(name),
            "the child never checked `{name}`"
        );
    }
}

#[test]
fn forking_from_a_multithreaded_process_is_refused_unless_opted_in() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("threads");
    let report = run_host("multithreaded-parent-refused", &scratch);
    let threads: u32 = report.get("parent_threads").parse().expect("thread count");
    assert!(threads > 1, "the scenario did not run multithreaded");
    assert!(
        report.get("refusal").contains("refusing to fork a confined worker"),
        "a multithreaded parent should be refused, got `{}`",
        report.get("refusal")
    );
    // The opt-in path is exercised too, so the refusal is a policy.
    assert!(
        report
            .get("opt_in_available")
            .parse::<usize>()
            .unwrap_or(0)
            >= 1,
        "the opt-in path did not produce a usable pool"
    );
}

#[test]
fn a_worker_that_cannot_be_confined_does_not_become_a_pool_worker() {
    if !require_landlock() {
        return;
    }
    let report = run_host("unconfineable-worker-refused", &Scratch::new("noconfine"));
    assert!(
        !report.get("refusal").is_empty(),
        "construction should have failed, but no refusal was reported"
    );
}

#[test]
fn warm_and_cold_latency_are_measured() {
    if !require_landlock() {
        return;
    }
    let report = run_host("latency", &Scratch::new("latency"));
    // Printed so the numbers reach the `cargo test` log rather than only the
    // child's, which is discarded unless the test fails.
    for name in [
        "latency_cold",
        "latency_warm",
        "latency_warm_with_capability",
    ] {
        let line = report.get(name);
        println!("{line}");
    }
    let verdict = report.get("verdict");
    println!("latency verdict: {verdict}");
    let field = |name: &str| -> u128 {
        verdict
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix(name))
            .unwrap_or_else(|| panic!("the verdict should carry {name}, got `{verdict}`"))
            .parse()
            .unwrap_or_else(|_| panic!("{name} should be a number, got `{verdict}`"))
    };
    let (warm_p50, warm_p99, cold_p50) = (
        field("warm_p50="),
        field("warm_p99="),
        field("cold_p50="),
    );
    println!("measured: warm p50={warm_p50}us p99={warm_p99}us, cold p50={cold_p50}us");
    assert!(
        warm_p50 < cold_p50,
        "a warm hit ({warm_p50}us) is not faster than a cold spawn ({cold_p50}us)"
    );
}

/// A pooled worker cannot reach outside its grants: no symlink escape, no
/// `/proc`, no ungranted sibling, and no socket.
#[test]
fn a_pooled_worker_cannot_reach_outside_its_grants() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("tricks");
    let report = run_host("escape-probe", &scratch);

    // The positive control first. Without it every denial below could just mean
    // the profile was empty or the path was wrong.
    assert_eq!(
        report.get("read_granted"),
        "ALLOWED",
        "the worker could not read its own grant, so nothing below is evidence"
    );
    assert_eq!(
        report.get("granted_content"),
        "intact",
        "the granted file was modified by a confined worker"
    );

    assert!(
        report.get("read_symlink_out").starts_with("DENIED"),
        "a pooled worker followed a symlink out of its granted tree: {}",
        report.get("read_symlink_out")
    );
    for name in [
        "read_etc_passwd",
        "read_proc_self_maps",
        "read_proc_self_environ",
        "read_ungranted_sibling",
        "list_root_dir",
    ] {
        assert!(
            report.get(name).starts_with("DENIED"),
            "`{name}` should be refused for a pooled worker, got `{}`",
            report.get(name)
        );
    }
    // The hole Landlock leaves and seccomp closes.
    assert!(
        report.get("socket").starts_with("DENIED"),
        "a pooled worker could create a socket, so the seccomp profile is not applied: {}",
        report.get("socket")
    );
}
