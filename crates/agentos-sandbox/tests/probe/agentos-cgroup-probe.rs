//! Worker image used by the cgroup and namespace integration tests.
//!
//! It is deliberately not the libtest harness: the pool confines its image
//! before `exec`, and the `Worker` seccomp profile refuses the thread-spawning
//! syscalls libtest needs to start. A dedicated main is the only image that can
//! run behind the filter.
//!
//! # Modes
//!
//! - `cgroup-report <report-dir>` reads `AGENTOS_SANDBOX_CGROUP` (set by the
//!   pool) and reports the limit files it can see, plus the process's own
//!   cgroup membership. The assertions live in the test; this only reports
//!   facts, including failures, so the test cannot pass on a missing report.
//! - `touch-memory <bytes> <delay-ms>` waits, then allocates and faults in
//!   `bytes` of anonymous memory. If the cgroup does not kill it, it exits 3,
//!   which the test treats as "the limit was not enforced".
//! - `idle <ms>` stays alive so the parent can inspect `/proc/<pid>` and the
//!   cgroup files while the worker is demonstrably running.
//! - `burn-cpu <ms>` spins in userspace, so the parent can read `cpu.stat` and
//!   assert the kernel throttled it rather than taking the quota on trust.
//! - `fork-attempts <attempts> <start-delay-ms> <hold-ms> [cgroup-dir]` waits
//!   for the parent to attach it to a cgroup, then forks repeatedly and reports
//!   how many forks the kernel allowed, the last errno, and the cgroup's
//!   `pids.current` while its child is still alive. Run unconfined, because the
//!   pool's seccomp profile refuses `clone` outright - which is a stronger
//!   guarantee than `pids.max`, and is why this mode bypasses the pool.
//! - `tmpfs-probe <host-marker> <inside-file> [delay-ms]` probes `/tmp` from
//!   inside the namespace: whether a marker the host wrote is visible, and
//!   whether a file can be written there. It reports the errno for the first,
//!   not just "absent", so a Landlock denial (EACCES) cannot be mistaken for a
//!   fresh mount (ENOENT). The findings go to stdout rather than a file: a
//!   user-namespace process writing to WSL's drvfs mount is refused for reasons
//!   that have nothing to do with the sandbox, and the observation must not
//!   depend on that.
//!
//! It never speaks the pool protocol. The pool writes its handshake before
//! `exec`, so every one of these paths is a spawned-and-confined worker from the
//! pool's point of view; the tests then observe the kernel's own records
//! (`/proc/<pid>`, the cgroup files) rather than asking the worker to attest to
//! its own confinement.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Marker shared with the test harness. Kept as a literal here rather than a
/// dependency on the library so the probe binary can be built and inspected on
/// its own.
const PROBE: &str = "##PROBE##";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("");
    let code = match mode {
        "cgroup-report" => cgroup_report(args.get(1)),
        "touch-memory" => touch_memory(args.get(1), args.get(2)),
        "idle" => idle(args.get(1)),
        "burn-cpu" => burn_cpu(args.get(1)),
        #[cfg(unix)]
        "fork-attempts" => fork_attempts(args.get(1), args.get(2), args.get(3), args.get(4)),
        #[cfg(not(unix))]
        "fork-attempts" => {
            eprintln!("agentos-cgroup-probe: fork-attempts requires a Unix host");
            70
        }
        "tmpfs-probe" => tmpfs_probe(args.get(1), args.get(2), args.get(3)),
        other => {
            eprintln!("agentos-cgroup-probe: unknown mode `{other}`");
            64
        }
    };
    // `exit` rather than returning from main so an exit code set by a mode is
    // not overwritten by a normal return.
    std::process::exit(code);
}

/// Report the limits and membership this process can see.
///
/// The report file is the evidence: a mode that cannot write it exits non-zero,
/// so a test waiting for the file fails loudly rather than reading an empty
/// report as a pass.
fn cgroup_report(report_dir: Option<&String>) -> i32 {
    let Some(report_dir) = report_dir else {
        eprintln!("cgroup-report: missing report directory");
        return 64;
    };
    let mut out = String::new();
    match std::env::var("AGENTOS_SANDBOX_CGROUP") {
        Ok(dir) => {
            out.push_str(&format!("cgroup_env={dir}\n"));
            for file in ["memory.max", "memory.swap.max", "pids.max", "cpu.max"] {
                let path = PathBuf::from(&dir).join(file);
                match fs::read_to_string(&path) {
                    Ok(v) => out.push_str(&format!("{file}={}\n", v.trim())),
                    Err(e) => out.push_str(&format!("{file}=ERR {e}\n")),
                }
            }
            // The worker's own view of where it is. This is the membership claim
            // from the worker side; the parent also reads /proc/<pid>/cgroup, so
            // neither side is trusted alone.
            match fs::read_to_string("/proc/self/cgroup") {
                Ok(v) => out.push_str(&format!("self_cgroup={}\n", v.trim())),
                Err(e) => out.push_str(&format!("self_cgroup=ERR {e}\n")),
            }
        }
        Err(e) => out.push_str(&format!("cgroup_env=ERR {e}\n")),
    }
    write_report(report_dir, "cgroup.txt", &out)
}

/// Allocate and fault in anonymous memory, then report that it survived.
fn touch_memory(bytes: Option<&String>, delay_ms: Option<&String>) -> i32 {
    let Some(bytes) = bytes.and_then(|b| b.parse::<usize>().ok()) else {
        eprintln!("touch-memory: missing or invalid byte count");
        return 64;
    };
    let delay = delay_ms
        .and_then(|d| d.parse::<u64>().ok())
        .unwrap_or(0);
    // A short delay so the parent can check out the worker and read the pid
    // before the cgroup kills it. Without it, a 32 MiB ceiling kills the worker
    // within the window between `Pool::spawn` returning and the test looking,
    // and the test would observe a replacement rather than the death.
    if delay > 0 {
        std::thread::sleep(Duration::from_millis(delay));
    }

    // `vec![0; n]` uses calloc, which over-commits. The touch loop is what
    // charges pages to the cgroup and is what the limit acts on. One byte per
    // page is enough to fault the page in; the write is not optimised away
    // because the buffer is handed to `black_box`.
    let mut buf = vec![0u8; bytes];
    let mut at = 0usize;
    while at < buf.len() {
        buf[at] = (at as u8) | 1;
        at += 4096;
    }
    std::hint::black_box(&buf);

    // Reaching here means the cgroup did not enforce the ceiling. Exit non-zero
    // so the test fails on "survived", not on a timeout.
    eprintln!("touch-memory: survived faulting in {bytes} bytes");
    3
}

/// Stay alive for a bounded time so the parent can inspect this process.
fn idle(ms: Option<&String>) -> i32 {
    let Some(ms) = ms.and_then(|m| m.parse::<u64>().ok()) else {
        eprintln!("idle: missing or invalid milliseconds");
        return 64;
    };
    std::thread::sleep(Duration::from_millis(ms));
    0
}

/// Burn userspace CPU for `ms`, then say so.
///
/// A `cpu.max` quota is enforced by the scheduler, so the only honest check is
/// whether it throttled us. The parent reads `cpu.stat` after this exits; this
/// line proves the burn actually happened rather than the worker dying first.
fn burn_cpu(ms: Option<&String>) -> i32 {
    let Some(ms) = ms.and_then(|m| m.parse::<u64>().ok()) else {
        eprintln!("burn-cpu: missing or invalid milliseconds");
        return 64;
    };
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    let mut spin = 0u64;
    while std::time::Instant::now() < deadline {
        for _ in 0..10_000 {
            spin = spin.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
    }
    std::hint::black_box(spin);
    println!("{PROBE}\tcpu_burned\t{ms}");
    let _ = std::io::stdout().flush();
    0
}

/// Fork repeatedly from inside a cgroup and report what the kernel allowed.
///
/// This runs unconfined on purpose: the pool's seccomp profile refuses
/// `clone`/`clone3`, so a pooled worker cannot fork at all, and `pids.max` would
/// never be exercised. The cgroup is the layer under test here, not the filter.
#[cfg(unix)]
fn fork_attempts(
    attempts: Option<&String>,
    start_delay_ms: Option<&String>,
    hold_ms: Option<&String>,
    cgroup_dir: Option<&String>,
) -> i32 {
    let Some(attempts) = attempts.and_then(|v| v.parse::<u32>().ok()) else {
        eprintln!("fork-attempts: missing or invalid attempt count");
        return 64;
    };
    let start_delay = start_delay_ms
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let hold = hold_ms.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    // Give the parent time to migrate this process into the cgroup; a fork
    // before the migration would be charged elsewhere and the test would be
    // measuring the host's limits, not the cgroup's.
    if start_delay > 0 {
        std::thread::sleep(Duration::from_millis(start_delay));
    }

    let mut succeeded = 0u32;
    let mut last_errno = 0i32;
    let mut children: Vec<libc::pid_t> = Vec::new();
    for _ in 0..attempts {
        // SAFETY: `fork` takes no arguments. The child performs only `_exit`,
        // and the parent keeps the only handle that matters (the pid).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            last_errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(-1);
            break;
        }
        if pid == 0 {
            if hold > 0 {
                std::thread::sleep(Duration::from_millis(hold));
            }
            // SAFETY: `_exit` is async-signal-safe and runs no atexit handlers.
            unsafe { libc::_exit(0) };
        }
        succeeded += 1;
        children.push(pid);
    }

    // Read the count while the one allowed child is still alive. After the
    // children are reaped the file correctly says zero, which would prove
    // nothing about the limit being in force.
    if let Some(dir) = cgroup_dir {
        match std::fs::read_to_string(PathBuf::from(dir).join("pids.current")) {
            Ok(v) => println!("{PROBE}\tpids_current\t{}", v.trim()),
            Err(e) => println!("{PROBE}\tpids_current\tERR {e}"),
        }
    }

    for pid in children {
        // SAFETY: `pid` is this process's own child; the result is intentionally
        // ignored because the test only needs it reaped.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    }
    println!("{PROBE}\tpids_forks\t{succeeded}");
    println!("{PROBE}\tpids_errno\t{last_errno}");
    let _ = std::io::stdout().flush();
    0
}

/// Probe `/tmp` from inside the worker's mount namespace.
fn tmpfs_probe(
    marker: Option<&String>,
    inside: Option<&String>,
    delay_ms: Option<&String>,
) -> i32 {
    let (Some(marker), Some(inside)) = (marker, inside) else {
        eprintln!("tmpfs-probe: missing marker or inside-file");
        return 64;
    };
    let delay = delay_ms
        .and_then(|d| d.parse::<u64>().ok())
        .unwrap_or(0);
    // Keep the process alive briefly so the parent can compare namespace inodes
    // in /proc before it exits.
    if delay > 0 {
        std::thread::sleep(Duration::from_millis(delay));
    }

    let host_marker = format!("/tmp/{marker}");
    let (marker_present, marker_errno) = match fs::metadata(&host_marker) {
        Ok(_) => (true, 0),
        Err(e) => (false, e.raw_os_error().unwrap_or(-1)),
    };
    let inside_path = format!("/tmp/{inside}");
    let (write_ok, write_detail) = match fs::write(&inside_path, b"written inside the namespace\n") {
        Ok(()) => (true, String::new()),
        Err(e) => (
            false,
            format!(
                "write failed: {e} (errno {})",
                e.raw_os_error().unwrap_or(-1)
            ),
        ),
    };

    println!("{PROBE}\tmarker_present\t{marker_present}");
    println!("{PROBE}\tmarker_errno\t{marker_errno}");
    println!("{PROBE}\twrite_ok\t{write_ok}");
    if !write_detail.is_empty() {
        println!("{PROBE}\twrite_detail\t{write_detail}");
    }
    println!("{PROBE}\tinside_path\t{inside_path}");
    println!("{PROBE}\tmarker_path\t{host_marker}");

    // Also report the namespace inodes so a failure to isolate is legible
    // rather than a mystery. Landlock may deny this without a `/proc` grant;
    // the authoritative comparison is the parent reading `/proc/<pid>/ns`, so
    // an error here is informational rather than a failure.
    for ns in ["mnt", "user"] {
        let link = format!("/proc/self/ns/{ns}");
        match fs::read_link(&link) {
            Ok(v) => println!("{PROBE}\tself_{ns}_ns\t{}", v.display()),
            Err(e) => println!("{PROBE}\tself_{ns}_ns\tERR {e}"),
        }
    }

    let _ = std::io::stdout().flush();
    0
}

/// Write a report file, returning the process exit code.
fn write_report(report_dir: &str, name: &str, contents: &str) -> i32 {
    let path = PathBuf::from(report_dir).join(name);
    match fs::write(&path, contents) {
        Ok(()) => {
            // A probe line on stdout too, so `cargo test -- --nocapture` shows
            // it and a hung test leaves a trail.
            println!("{PROBE}\tprobe_report\t{}", path.display());
            let _ = std::io::stdout().flush();
            0
        }
        Err(e) => {
            eprintln!(
                "agentos-cgroup-probe: could not write report {}: {e}",
                path.display()
            );
            70
        }
    }
}
