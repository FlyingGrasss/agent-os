//! seccomp enforcement tests.
//!
//! The pattern is the same as the Landlock escape tests: re-exec this binary as a
//! child, apply the profile in the child, have the child make raw syscalls, and
//! read back what actually happened. Applying a filter to the current process
//! would be irreversible and would poison the harness.
//!
//! # Every negative test has a baseline
//!
//! This repo has a recorded incident of a harness that filtered on a bare test
//! name, matched zero tests, exited 0, and handed its parent an empty report
//! that read as a clean run. Three things guard against a repeat here.
//!
//! First, the child is invoked with a fully qualified test name and the parent
//! asserts on the probes it expects to find, so "nothing ran" is a failure
//! rather than a pass. The child prints a `done` line carrying the number of
//! probes it reached, and that number is compared against the table below.
//!
//! Second, [`Scenario::Baseline`] runs **the same probe table with no filter
//! installed**. A denial is only evidence if the probe was capable of
//! succeeding, so the baseline proves each probe actually reaches the kernel and
//! comes back with something other than `ENOSYS`. Without it, a probe built on
//! a wrong syscall number would report `ENOSYS` whether or not a filter existed,
//! and every refusal test below would be a tautology.
//!
//! Third, every probe passes deliberately unusable arguments, so "reached the
//! kernel" means "failed immediately with `EINVAL`/`EFAULT`/`EPERM`" and never
//! means "forked", "attached to the parent" or "opened a socket".
//!
//! # How a refusal is read
//!
//! The filter refuses with `SECCOMP_RET_ERRNO(ENOSYS)` rather than killing, which
//! gives an exact discriminator: `-1` with `errno == ENOSYS` means the filter
//! refused this and nothing else does. A probe is judged *allowed* on anything
//! else, including an outright success, which keeps the rule free of assumptions
//! about what a given syscall does with null arguments.
//!
//! On a non-Linux host there is no filter to install and no syscall to probe, so
//! the whole harness compiles away. It is not skipped: there is nothing here to
//! assert, and a suite that reported "0 tests" while claiming coverage would be
//! the same problem as the silently-non-running escape test.
#![cfg(target_os = "linux")]

use std::process::Command;

const CHILD_ENV: &str = "AGENTOS_SECCOMP_CHILD";
const SCENARIO_ENV: &str = "AGENTOS_SECCOMP_SCENARIO";
const PROBE: &str = "##PROBE##";

/// One raw syscall, made with deliberately unusable arguments.
struct Probe {
    /// `strace`'s name for it, which is also what `FORBIDDEN` uses.
    name: &'static str,
    nr: libc::c_long,
    args: &'static [usize],
}

macro_rules! p {
    ($name:literal, $nr:path) => {
        Probe {
            name: $name,
            nr: $nr as libc::c_long,
            args: &[0; 6],
        }
    };
}

/// A bit no architecture defines as a `clone` flag. `copy_process` validates
/// the flag word against its own mask and returns `EINVAL` before the child is
/// made runnable, so this probe cannot fork, hang, or execute a duplicated
/// address space even if the filter is wrong and lets the call through. That is
/// the whole reason `clone` is probed this way rather than with real flags: the
/// obvious choice of `CLONE_NEWIPC` or `CLONE_NEWUSER` would be a real
/// namespace request that succeeds as a bare unshare under some configurations.
const INVALID_CLONE_FLAGS: usize = 0x8000_0000_0000_0000;

/// `ptrace`'s first argument is the *request*, and the kernel rejects an
/// unrecognised one with `EINVAL` before it looks at the other three.
///
/// The obvious probe, `PTRACE_TRACEME`, is the wrong one for reasons that are
/// not obvious: it succeeds, it marks the child as traced by its parent, and the
/// kernel then stops it at `exit` waiting for a tracer that the test harness
/// never becomes. The child hangs at process exit and takes the whole suite's
/// timing with it, while reporting every probe as passing. The syscall number is
/// the same either way; only the side effects differ.
const INVALID_PTRACE_REQUEST: usize = 0xFFFF_FFFF;

/// The composed probe: `pthread_create` reaches `clone3` first and glibc retries
/// with `clone` when the kernel answers `ENOSYS`. Testing the two raw syscalls
/// is not the same claim as testing what a real tool actually calls, because the
/// fallback is the reason refusing one of them is not enough.
///
/// Returns in the same shape as a raw syscall so the reporting code does not
/// care which kind of probe it is: `-1` with `errno` set to the pthread error.
extern "C" fn probe_thread(_arg: *mut libc::c_void) -> *mut libc::c_void {
    std::ptr::null_mut()
}

fn probe_pthread_create() -> libc::c_long {
    let mut tid: libc::pthread_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::pthread_create(
            &mut tid,
            std::ptr::null(),
            probe_thread,
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        // Only reachable if the filter is broken. Join it rather than leave a
        // stray thread in a process that is about to print a report.
        unsafe { libc::pthread_join(tid, std::ptr::null_mut()) };
        0
    } else {
        // pthread_create returns the error; it does not set errno.
        unsafe { *libc::__errno_location() = rc };
        -1
    }
}

static PROBES: &[Probe] = &[
    // --- the four holes the status document recorded -----------------------
    // `ptrace` with a request the kernel does not implement. See
    // `INVALID_PTRACE_REQUEST` for why this is not `PTRACE_TRACEME`.
    Probe {
        name: "ptrace",
        nr: libc::SYS_ptrace as libc::c_long,
        args: &[INVALID_PTRACE_REQUEST, 0, 0, 0],
    },
    Probe {
        name: "clone",
        nr: libc::SYS_clone as libc::c_long,
        args: &[INVALID_CLONE_FLAGS, 0, 0, 0, 0],
    },
    // `clone3` with a NULL args pointer is EFAULT before it reads anything.
    Probe {
        name: "clone3",
        nr: libc::SYS_clone3 as libc::c_long,
        args: &[0, 0],
    },
    p!("io_uring_setup", libc::SYS_io_uring_setup),
    p!("io_uring_enter", libc::SYS_io_uring_enter),
    p!("io_uring_register", libc::SYS_io_uring_register),
    p!("perf_event_open", libc::SYS_perf_event_open),
    // --- the same class of hole, found while closing those -----------------
    p!("process_vm_readv", libc::SYS_process_vm_readv),
    p!("process_vm_writev", libc::SYS_process_vm_writev),
    p!("bpf", libc::SYS_bpf),
    // `memfd_create(NULL, 0)` is EFAULT, so this stages nothing.
    p!("memfd_create", libc::SYS_memfd_create),
    // Flags are validated before the sysctl is consulted, so this is EINVAL
    // rather than depending on the host's `vm.unprivileged_userfaultfd`.
    Probe {
        name: "userfaultfd",
        nr: libc::SYS_userfaultfd as libc::c_long,
        args: &[0xFFFF_FFFF],
    },
    // The pair that undoes Landlock's path-based model: a handle is minted by
    // name and then consumed by number, with no path for a rule to match.
    p!("open_by_handle_at", libc::SYS_open_by_handle_at),
    p!("name_to_handle_at", libc::SYS_name_to_handle_at),
    p!("keyctl", libc::SYS_keyctl),
    p!("add_key", libc::SYS_add_key),
    Probe {
        name: "pidfd_open",
        nr: libc::SYS_pidfd_open as libc::c_long,
        args: &[0, 0],
    },
    p!("pidfd_send_signal", libc::SYS_pidfd_send_signal),
    p!("kcmp", libc::SYS_kcmp),
    p!("setns", libc::SYS_setns),
    p!("unshare", libc::SYS_unshare),
    p!("mount", libc::SYS_mount),
    p!("umount2", libc::SYS_umount2),
    p!("mount_setattr", libc::SYS_mount_setattr),
    p!("pivot_root", libc::SYS_pivot_root),
    p!("chroot", libc::SYS_chroot),
    p!("init_module", libc::SYS_init_module),
    p!("finit_module", libc::SYS_finit_module),
    p!("delete_module", libc::SYS_delete_module),
    p!("kexec_load", libc::SYS_kexec_load),
    p!("ioperm", libc::SYS_ioperm),
    p!("iopl", libc::SYS_iopl),
    p!("mknod", libc::SYS_mknod),
    p!("mknodat", libc::SYS_mknodat),
    // --- egress, which is the hole Landlock leaves --------------------------
    p!("socket", libc::SYS_socket),
    p!("socketpair", libc::SYS_socketpair),
    p!("bind", libc::SYS_bind),
    p!("connect", libc::SYS_connect),
    p!("listen", libc::SYS_listen),
    p!("accept", libc::SYS_accept),
    p!("accept4", libc::SYS_accept4),
    p!("sendto", libc::SYS_sendto),
    p!("recvfrom", libc::SYS_recvfrom),
    p!("sendmsg", libc::SYS_sendmsg),
    p!("recvmsg", libc::SYS_recvmsg),
    p!("sendmmsg", libc::SYS_sendmmsg),
    p!("recvmmsg", libc::SYS_recvmmsg),
    p!("shutdown", libc::SYS_shutdown),
    p!("setsockopt", libc::SYS_setsockopt),
    p!("getsockopt", libc::SYS_getsockopt),
];

/// What a composed probe reports: its name, and the call that makes it.
type ComposedProbe = (&'static str, fn() -> libc::c_long);

/// Probes that are not a single raw syscall, reported through the same channel so
/// the completeness check counts them too.
static COMPOSED: &[ComposedProbe] = &[("pthread_create", probe_pthread_create)];

fn total_probes() -> usize {
    PROBES.len() + COMPOSED.len()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// No filter. The positive control for every negative assertion below.
    Baseline,
    Filesystem,
    Exec,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Scenario::Baseline => "baseline",
            Scenario::Filesystem => "filesystem",
            Scenario::Exec => "exec",
        }
    }
}

fn main() {
    match std::env::var(CHILD_ENV).ok().as_deref() {
        Some("run") => run_child(),
        _ => eprintln!("this binary is a test harness; run it via `cargo test`"),
    }
}

fn run_child() {
    let scenario = match std::env::var(SCENARIO_ENV).ok().as_deref() {
        Some("baseline") => Scenario::Baseline,
        Some("exec") => Scenario::Exec,
        Some("filesystem") | None => Scenario::Filesystem,
        Some(other) => {
            println!("{PROBE}\tfatal\tunknown scenario {other}");
            return;
        }
    };

    // `no_new_privs` is a precondition for an unprivileged seccomp filter, so set
    // it the way a real confined child would. The baseline sets it too, so the
    // two runs differ only in whether a filter is installed.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    assert_eq!(rc, 0, "could not set no_new_privs");

    if scenario != Scenario::Baseline {
        let profile = match scenario {
            Scenario::Exec => agentos_sandbox::SeccompProfile::Exec,
            _ => agentos_sandbox::SeccompProfile::Filesystem,
        };
        match agentos_sandbox::apply_seccomp(profile) {
            Ok(_) => println!("{PROBE}\tfilter\tAPPLIED"),
            Err(e) => {
                println!("{PROBE}\tfatal\t{e}");
                return;
            }
        }

        // Positive control: an allowlisted syscall still works after the filter
        // is installed. Without this, a child that died early would look
        // identical to a child that was correctly confined.
        if unsafe { libc::getpid() } > 0 {
            println!("{PROBE}\tgetpid\tALLOWED");
        } else {
            println!("{PROBE}\tgetpid\tDENIED errno={}", last_errno());
            return;
        }
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            println!("{PROBE}\topen_dev_null\tALLOWED");
            unsafe { libc::close(fd) };
        } else {
            println!("{PROBE}\topen_dev_null\tDENIED errno={}", last_errno());
            return;
        }
        let msg = b"probe\n";
        let w = unsafe { libc::write(1, msg.as_ptr() as *const libc::c_void, msg.len()) };
        if w > 0 {
            println!("{PROBE}\twrite\tALLOWED");
        } else {
            println!("{PROBE}\twrite\tDENIED errno={}", last_errno());
            return;
        }
    } else {
        println!("{PROBE}\tfilter\tNONE");
    }

    for probe in PROBES {
        let mut args = [0usize; 6];
        for (dst, src) in args.iter_mut().zip(probe.args.iter()) {
            *dst = *src;
        }
        let rc = unsafe {
            libc::syscall(
                probe.nr,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            )
        };
        // A descriptor-returning syscall that was allowed leaves an fd behind.
        if rc >= 0 && probe.name == "pidfd_open" {
            unsafe { libc::close(rc as libc::c_int) };
        }
        report(probe.name, rc);
    }
    for (name, f) in COMPOSED {
        report(name, f());
    }

    // A count, so the parent can tell "reached the end" from "died at probe 12".
    println!("{PROBE}\tdone\t{}", total_probes());
}

fn report(name: &str, rc: libc::c_long) {
    let errno = if rc == -1 { last_errno() } else { 0 };
    let verdict = if rc == -1 && errno == libc::ENOSYS {
        "DENIED"
    } else {
        "ALLOWED"
    };
    println!("{PROBE}\tprobe:{name}\t{verdict} rc={rc} errno={errno}");
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

struct Report {
    outcomes: std::collections::BTreeMap<String, String>,
    fatal: Option<String>,
}

impl Report {
    fn parse(out: &std::process::Output) -> Report {
        let text = String::from_utf8_lossy(&out.stdout);
        let mut r = Report {
            outcomes: std::collections::BTreeMap::new(),
            fatal: None,
        };
        for line in text.lines() {
            let Some(idx) = line.find(PROBE) else { continue };
            let mut fields = line[idx + PROBE.len()..].split('\t');
            let _ = fields.next();
            let Some(name) = fields.next() else { continue };
            let Some(detail) = fields.next() else { continue };
            if name == "fatal" {
                r.fatal = Some(detail.to_string());
            } else {
                r.outcomes.insert(name.to_string(), detail.trim().to_string());
            }
        }
        r
    }

    fn get(&self, name: &str) -> String {
        self.outcomes
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("probe `{name}` never reported; got {:?}", self.outcomes))
    }

    fn allowed(&self, name: &str) {
        let got = self.get(name);
        assert!(
            got.starts_with("ALLOWED"),
            "probe `{name}` should have been allowed, got {got}"
        );
    }

    fn denied(&self, name: &str) {
        let got = self.get(name);
        assert!(
            got.starts_with("DENIED"),
            "probe `{name}` should have been denied, got {got}"
        );
    }

    fn rc(&self, name: &str) -> libc::c_long {
        let got = self.get(name);
        got.split("rc=")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("probe `{name}` reported no rc; got {got}"))
    }

    fn errno(&self, name: &str) -> i32 {
        let got = self.get(name);
        got.rsplit("errno=")
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("probe `{name}` reported no errno; got {got}"))
    }

    /// Whether an unfiltered run of this probe reached the kernel.
    fn reach(&self, name: &str) -> Reach {
        let rc = self.rc(name);
        if rc != -1 {
            Reach::Present
        } else if self.errno(name) == libc::ENOSYS {
            // The kernel has no such syscall. Only meaningful on a baseline run;
            // the caller is responsible for knowing which run it is looking at.
            Reach::Absent
        } else {
            // Reached the kernel and was refused by it for an ordinary reason
            // (bad arguments, no capability). This is the good case: the syscall
            // number is right and the kernel answered.
            Reach::Present
        }
    }
}

fn run_scenario(scenario: Scenario) -> (Report, std::process::Output) {
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        // Fully qualified: the child is a `#[test]` inside a module, and a bare
        // name filters to nothing, exits 0, and leaves the parent with an empty
        // report that looks like a pass.
        .arg("seccomp::child_entry")
        .env(CHILD_ENV, "run")
        .env(SCENARIO_ENV, scenario.name())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run the seccomp child");
    let report = Report::parse(&output);
    if let Some(fatal) = &report.fatal {
        panic!(
            "the {} child could not install the filter: {fatal}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            scenario.name(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // The child reaching `done` with the right count is what makes an absent
    // probe a failure rather than a silent omission.
    assert_eq!(
        report.get("done"),
        total_probes().to_string(),
        "the {} child did not reach every probe; got {:?}",
        scenario.name(),
        report.outcomes
    );
    (report, output)
}

/// The four holes the status document recorded, named so the tests that assert
/// them read as the claim rather than as a loop over a table.
const DOCUMENTED_HOLES: &[&str] = &[
    "ptrace",
    "clone",
    "clone3",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "perf_event_open",
];

/// Probes this kernel answers with `ENOSYS` even unfiltered, so the syscall is
/// not compiled in.
///
/// This is not a hypothetical. On the WSL2 host these tests were written against,
/// `kexec_load`, `ioperm` and `iopl` all return `ENOSYS` from an unfiltered
/// child, because the kernel is built `# CONFIG_KEXEC is not set` with no port
/// I/O support. `ENOSYS` is therefore **not** on its own evidence that a filter
/// refused a call, and a harness that assumes it is will happily assert a refusal
/// that the kernel would have produced anyway.
///
/// The distinction the baseline run buys:
///
/// - **present** - reached the kernel, so `ENOSYS` under the filter is the
///   filter's doing. These are the probes that carry the security claim.
/// - **absent** - not implemented here, so the filtered result proves nothing on
///   this host. They are still required to be refused, because the crate's floor
///   is a refusal and a host without `CONFIG_KEXEC` is not a reason to stop
///   asking; the test asserts both, and says which is which rather than letting
///   a reader assume the stronger claim.
///
/// Everything in here is a host configuration fact, not a portability bug in the
/// crate, so the list is asserted rather than assumed: if a future kernel adds
/// one of these, [`the_baseline_classifies_every_probe`] fails and the entry is
/// moved.
const KERNEL_ABSENT: &[&str] = &["kexec_load", "ioperm", "iopl"];

/// What the unfiltered baseline established about one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Reached the kernel. A refusal under the filter is real.
    Present,
    /// Not implemented on this kernel. The syscall number is right, but this host
    /// cannot demonstrate the filter doing the refusing.
    Absent,
}

fn assert_every_probe_refused(scenario: Scenario) {
    let (report, _) = run_scenario(scenario);
    assert_eq!(report.get("filter"), "APPLIED", "the filter was not installed");
    report.allowed("getpid");
    report.allowed("open_dev_null");
    report.allowed("write");

    let mut wrong: Vec<String> = Vec::new();
    for probe in PROBES {
        let key = format!("probe:{}", probe.name);
        let got = report.get(&key);
        if !(got.starts_with("DENIED") && got.contains("errno=38")) {
            wrong.push(format!("{key} -> {got}"));
        }
    }
    for (name, _) in COMPOSED {
        let key = format!("probe:{name}");
        let got = report.get(&key);
        if !(got.starts_with("DENIED") && got.contains("errno=38")) {
            wrong.push(format!("{key} -> {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} should have refused every probed syscall with ENOSYS; these were not: {wrong:?}",
        scenario.name()
    );
}

#[test]
fn this_kernel_can_filter() {
    // Not a probe. The guard this replaces was
    // `Path::new("/proc/sys/kernel/seccomp/actions_avail").exists()
    //     || cfg!(target_os = "linux")`,
    // which is a tautology on this platform and so checked nothing. If the
    // kernel really cannot filter, every negative test below would be asserting
    // against a child that never installed a filter, so this fails loudly.
    assert!(
        std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists(),
        "this kernel has no CONFIG_SECCOMP_FILTER; every test in this file would be \
         asserting against a child that never installed a filter"
    );
}

#[test]
fn the_baseline_classifies_every_probe() {
    // The positive control for the whole file, and the reason `ENOSYS` is not
    // treated here as proof of a refusal on its own.
    //
    // A probe that is neither a real syscall number nor a syscall this kernel
    // lacks shows up as `DENIED` in the baseline, and would then also show up as
    // `DENIED` under a filter, for the wrong reason. Every probe is therefore
    // classified, and the classification is asserted against `KERNEL_ABSENT` so a
    // change in host configuration is a test failure rather than a silent shift in
    // what the suite is claiming.
    let (report, _) = run_scenario(Scenario::Baseline);
    assert_eq!(report.get("filter"), "NONE");

    let mut present = Vec::new();
    let mut absent = Vec::new();
    for probe in PROBES.iter().map(|p| p.name).chain(COMPOSED.iter().map(|(n, _)| *n)) {
        let key = format!("probe:{probe}");
        match report.reach(&key) {
            Reach::Present => present.push(probe),
            Reach::Absent => absent.push(probe),
        }
    }

    assert_eq!(
        absent, KERNEL_ABSENT,
        "the set of probes this kernel does not implement changed. `ENOSYS` from an \
         unfiltered child means the syscall is absent, so for these probes the \
         filtered result proves nothing on this host. Move the entries between \
         KERNEL_ABSENT and the table and say why."
    );
    assert!(
        present.len() > absent.len(),
        "most probes must actually reach the kernel for the suite to mean anything; \
         present={present:?} absent={absent:?}"
    );

    // The holes the status document called out must all be demonstrable here,
    // otherwise the tests named after them are asserting less than they read as.
    let missing: Vec<&str> = DOCUMENTED_HOLES
        .iter()
        .copied()
        .filter(|h| !present.contains(h))
        .collect();
    assert!(
        missing.is_empty(),
        "these are the holes this file exists to close but this kernel cannot \
         demonstrate them: {missing:?}"
    );
}

#[test]
fn the_baseline_probes_reach_the_kernel_rather_than_short_circuiting() {
    // The other half of the control. If every unfiltered probe came back `EINVAL`
    // from argument validation the baseline would still be satisfied, but it
    // would not be evidence that the syscall numbers are right. At least one
    // must actually succeed when allowed, and most must fail for a reason other
    // than "this kernel has no such syscall".
    let (report, _) = run_scenario(Scenario::Baseline);
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for probe in PROBES.iter().map(|p| p.name).chain(COMPOSED.iter().map(|(n, _)| *n)) {
        let key = format!("probe:{probe}");
        let rc = report.rc(&key);
        if rc >= 0 {
            succeeded.push(probe);
        } else {
            failed.push(probe);
        }
    }
    assert!(
        !succeeded.is_empty(),
        "no probe succeeded when allowed, so the table cannot tell a working \
         syscall from a missing one"
    );
    assert!(
        failed.len() > succeeded.len(),
        "most probes should fail fast on their arguments when allowed; \
         succeeded={succeeded:?} failed={failed:?}"
    );
    println!(
        "baseline: {} succeed when allowed ({succeeded:?}), {} fail fast",
        succeeded.len(),
        failed.len()
    );
}

#[test]
fn the_filesystem_profile_refuses_every_probed_syscall() {
    // The load-bearing test. Landlock constrains none of these - it is a path-
    // and socket-oriented LSM - so the allowlist is the only layer.
    assert_every_probe_refused(Scenario::Filesystem);
}

#[test]
fn the_exec_profile_refuses_every_probed_syscall() {
    // `Exec` is the larger grant, so it is the one most likely to have acquired a
    // hole as syscalls were added for spawning helpers.
    assert_every_probe_refused(Scenario::Exec);
}

#[test]
fn the_documented_holes_are_named_in_the_tests() {
    // Guards the framing rather than the behaviour: a hole fixed here but not
    // named anywhere is a hole someone reopens because nothing referred to it.
    for hole in DOCUMENTED_HOLES {
        assert!(
            PROBES.iter().any(|p| p.name == *hole),
            "`{hole}` is recorded as a fixed hole but nothing probes it"
        );
    }
}

#[test]
fn the_allowlist_agrees_with_the_refusal_table() {
    // `Profile::refused` is derived from the table filtered by the allowlist, so
    // this is the check that it is derived rather than hand-written, that no
    // profile has quietly grown a forbidden number, and that every claim in the
    // table has a probe behind it.
    //
    // `Worker` is the one profile that deliberately grants syscalls the strict
    // ones refuse, and that is a design choice rather than an oversight: it is
    // the only profile whose job includes receiving a descriptor across a
    // process boundary and reaching `main` in a dynamically linked image. So
    // the coverage count is stated as "every probe is accounted for, either by
    // a refusal the strict profiles claim, or by an explicit `Worker` grant".
    // Stating it that way is also what makes `Worker` growing a grant fail: the
    // exception is computed, not assumed.
    let worker = agentos_sandbox::SeccompProfile::Worker
        .allowed()
        .expect("Worker resolves its numbers on x86_64");
    // Only `PROBES` carry a syscall number. A `COMPOSED` entry is a library call
    // whose *result* is probed, not a number, so it cannot be matched against
    // an allowlist and is deliberately not part of the exception count. It is
    // still covered by the per-entry checks below, and by the composed tests.
    let worker_exceptions: Vec<&str> = PROBES
        .iter()
        .filter(|p| worker.contains(&{ p.nr }))
        .map(|p| p.name)
        .collect();

    // Each exception must be a syscall the strict profiles genuinely refuse,
    // otherwise "Worker grants it" is a vacuous excuse for a hole.
    for profile in [
        agentos_sandbox::SeccompProfile::Filesystem,
        agentos_sandbox::SeccompProfile::Exec,
    ] {
        let allowed = profile
            .allowed()
            .expect("the strict profiles resolve their numbers on x86_64");
        for name in &worker_exceptions {
            let nr = PROBES
                .iter()
                .find(|p| p.name == *name)
                .map(|p| p.nr)
                .unwrap_or_else(|| panic!("`{name}` is an exception to no probe"));
            assert!(
                !allowed.contains(&nr),
                "`{name}` is listed as a Worker-only grant but {profile:?} does not \
                 refuse it, so the exception is hiding a grant rather than a refusal"
            );
        }
    }

    for profile in [
        agentos_sandbox::SeccompProfile::Filesystem,
        agentos_sandbox::SeccompProfile::Exec,
    ] {
        let refused = profile.refused();
        let claimed: std::collections::BTreeSet<i64> = refused.iter().map(|f| f.number).collect();

        // The coverage check, stated by name rather than by count. A count can
        // be satisfied by the wrong entries; a set difference cannot. Every
        // probed syscall has to be either something this profile claims to
        // refuse, or one of the explicit `Worker` grants above - nothing in
        // between, because "probed but unmentioned" is how a hole becomes
        // invisible.
        let unaccounted: Vec<&str> = PROBES
            .iter()
            .filter(|p| !claimed.contains(&{ p.nr }) && !worker.contains(&{ p.nr }))
            .map(|p| p.name)
            .collect();
        assert!(
            unaccounted.is_empty(),
            "{profile:?} probes these syscalls but the refusal table names none of them and \
             {worker_exceptions:?} are the Worker-only grants, so they are refused by \
             accident rather than by decision: {unaccounted:?}"
        );

        // And the other direction: a claim nothing probes is a claim nothing
        // tests.
        for f in refused {
            assert!(
                PROBES.iter().any(|p| p.name == f.name)
                    || COMPOSED.iter().any(|(n, _)| *n == f.name),
                "{profile:?} refuses `{}` but nothing probes it, so the claim is untested",
                f.name
            );
            assert!(!f.why.is_empty(), "{} is refused without a reason", f.name);
        }
    }
}

#[test]
fn a_confined_process_cannot_ptrace() {
    // Not a synthetic probe. `PTRACE_ATTACH` against the daemon is the escape:
    // it would let the tool read the prompt and rewrite the policy engine, which
    // makes every other layer irrelevant. `PTRACE_TRACEME` is used here because
    // it exercises the same syscall number without the risk of a filter that is
    // wrong and lets a real attach through to the test runner.
    let (report, _) = run_scenario(Scenario::Filesystem);
    report.denied("probe:ptrace");
    assert!(
        report.get("probe:ptrace").contains("errno=38"),
        "ptrace must be refused with ENOSYS so the failure is legible"
    );
}

#[test]
fn clone_and_clone3_are_both_refused() {
    // The glibc fallback makes these one claim, not two: `clone3` returning
    // ENOSYS is exactly what makes glibc retry with `clone`. Refusing one and
    // allowing the other would refuse nothing.
    let (report, _) = run_scenario(Scenario::Filesystem);
    report.denied("probe:clone");
    report.denied("probe:clone3");
}

#[test]
fn thread_creation_fails_through_glibc_too() {
    // The composed path. `pthread_create` reaches `clone3` first and falls back
    // to `clone` on ENOSYS; if either were allowed this would succeed.
    let (report, _) = run_scenario(Scenario::Filesystem);
    report.denied("probe:pthread_create");
    assert!(
        report.rc("probe:pthread_create") == -1,
        "a confined process must not be able to create a thread"
    );
}

#[test]
fn io_uring_cannot_be_created_at_all() {
    // No ring means no `IORING_SETUP_*` flag and no `IORING_OFFLINE_ASYNC`, and
    // no `IORING_REGISTER` laundering a descriptor into the unrestricted path.
    // Asserting `io_uring_setup` alone is the whole claim; the other two are here
    // so the table cannot rot.
    let (report, _) = run_scenario(Scenario::Filesystem);
    report.denied("probe:io_uring_setup");
    report.denied("probe:io_uring_enter");
    report.denied("probe:io_uring_register");
}

#[test]
fn the_exec_profile_cannot_exfiltrate_over_a_socket() {
    let (report, _) = run_scenario(Scenario::Exec);
    report.denied("probe:socket");
    report.denied("probe:connect");
    report.denied("probe:sendto");
    // `socketpair` is the one that was easy to grant "because it is only local
    // IPC". With `socket` refused it can address nothing the process did not
    // create itself, and `pipe2` covers the need.
    report.denied("probe:socketpair");
}

#[test]
fn denied_syscalls_report_enosys_rather_than_killing_the_process() {
    // ENOSYS so a tool fails visibly and the caller can learn which capability
    // it wanted, rather than the process dying with no explanation.
    // `assert_every_probe_refused` checks `errno=38` for each probe; this keeps
    // the named instance so a change of intent has something to break.
    let (report, _) = run_scenario(Scenario::Filesystem);
    assert!(
        report.get("probe:socket").contains("errno=38"),
        "expected ENOSYS(38) so the failure is legible"
    );
}

#[test]
fn a_filesystem_profile_can_still_read_files() {
    // The filter must not be so tight the tool cannot function.
    let (report, _) = run_scenario(Scenario::Filesystem);
    report.allowed("open_dev_null");
    report.allowed("write");
}

#[test]
fn the_parent_process_is_not_filtered() {
    // Confinement must not leak outward from the child.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(
        fd >= 0,
        "the parent should still be able to open a socket after a child was filtered"
    );
    unsafe { libc::close(fd) };
}

/// The child half. `run_scenario` re-execs this binary with `CHILD_ENV` set and
/// an exactly-matching filter, so this runs as a `#[test]` rather than as the
/// harness's `main`.
mod seccomp {
    use super::*;

    #[test]
    fn child_entry() {
        if std::env::var(CHILD_ENV).ok().as_deref() == Some("run") {
            run_child();
        }
    }
}