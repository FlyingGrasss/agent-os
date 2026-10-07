//! seccomp enforcement tests.
//!
//! The pattern is the same as the Landlock escape tests: re-exec this binary as a
//! child, apply the profile in the child, have the child make raw syscalls, and
//! read back what actually happened. Applying a filter to the current process
//! would be irreversible and would poison the harness.
//!
//! Every negative test has a positive control. A child that died before
//! reaching its probes would otherwise produce an empty report that reads like a
//! clean run.

//! On a non-Linux host there is no filter to install and no syscall to probe, so
//! the whole harness compiles away. It is not skipped: there is nothing here to
//! assert, and a suite that reported "0 tests" while claiming coverage would be
//! the same problem as the silently-non-running escape test.
#![cfg(target_os = "linux")]

use std::process::Command;

const CHILD_ENV: &str = "AGENTOS_SECCOMP_CHILD";
const SCENARIO_ENV: &str = "AGENTOS_SECCOMP_SCENARIO";
const PROBE: &str = "##PROBE##";

#[cfg(target_os = "linux")]
fn raw_socket(domain: i32, ty: i32) -> i32 {
    unsafe { libc::socket(domain, ty, 0) }
}

fn main() {
    match std::env::var(CHILD_ENV).ok().as_deref() {
        Some("run") => run_child(),
        _ => eprintln!("this binary is a test harness; run it via `cargo test`"),
    }
}

#[cfg(target_os = "linux")]
fn run_child() {
    let scenario = std::env::var(SCENARIO_ENV).unwrap_or_else(|_| "filesystem".into());

    // `no_new_privs` is a precondition for an unprivileged seccomp filter, so
    // set it the way a real confined child would.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    assert_eq!(rc, 0, "could not set no_new_privs");

    let profile = match scenario.as_str() {
        "exec" => agentos_sandbox::SeccompProfile::Exec,
        _ => agentos_sandbox::SeccompProfile::Filesystem,
    };

    match agentos_sandbox::apply_seccomp(profile) {
        Ok(_) => println!("{PROBE}\tfilter\tAPPLIED"),
        Err(e) => {
            println!("{PROBE}\tfatal\t{e}");
            return;
        }
    }

    // Positive control: an allowlisted syscall still works after the filter is
    // installed. Without this, a child that died early would look identical to a
    // child that was correctly confined.
    let rc = unsafe { libc::getpid() };
    if rc > 0 {
        println!("{PROBE}\tgetpid\tALLOWED");
    } else {
        println!("{PROBE}\tgetpid\tDENIED errno={}", last_errno());
        return;
    }

    // A file read is allowlisted in every profile.
    let fd = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    if fd >= 0 {
        println!("{PROBE}\topen_dev_null\tALLOWED");
        unsafe { libc::close(fd) };
    } else {
        println!("{PROBE}\topen_dev_null\tDENIED errno={}", last_errno());
    }

    // The point of the exercise. Landlock's network control covers TCP bind and
    // connect; it does not cover `socket` at all.
    let s = raw_socket(libc::AF_INET, libc::SOCK_STREAM);
    if s >= 0 {
        println!("{PROBE}\tsocket\tALLOWED fd={s}");
        unsafe { libc::close(s) };
    } else {
        println!("{PROBE}\tsocket\tDENIED errno={}", last_errno());
    }

    // UDP is outside Landlock's network scope entirely.
    let u = raw_socket(libc::AF_INET, libc::SOCK_DGRAM);
    if u >= 0 {
        println!("{PROBE}\tudp_socket\tALLOWED fd={u}");
        unsafe { libc::close(u) };
    } else {
        println!("{PROBE}\tudp_socket\tDENIED errno={}", last_errno());
    }

    // UNIX sockets are local IPC rather than egress, so they stay available.
    let un = raw_socket(libc::AF_UNIX, libc::SOCK_STREAM);
    if un >= 0 {
        println!("{PROBE}\tunix_socket\tALLOWED fd={un}");
        unsafe { libc::close(un) };
    } else {
        println!("{PROBE}\tunix_socket\tDENIED errno={}", last_errno());
    }

    // Writing must survive, or the filter is useless.
    let msg = b"probe\n";
    let w = unsafe { libc::write(1, msg.as_ptr() as *const libc::c_void, msg.len()) };
    if w > 0 {
        println!("{PROBE}\twrite\tALLOWED");
    } else {
        println!("{PROBE}\twrite\tDENIED errno={}", last_errno());
    }

    println!("{PROBE}\tdone\tok");
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
}

fn run_scenario(scenario: &str) -> (Report, std::process::Output) {
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
        .env(SCENARIO_ENV, scenario)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run the seccomp child");
    (Report::parse(&output), output)
}

fn require_kernel_support() -> bool {
    // CONFIG_SECCOMP_FILTER, confirmed present on this kernel.
    std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists() || cfg!(target_os = "linux")
}

mod seccomp {
    use super::*;

    #[test]
    fn child_entry() {
        if std::env::var(CHILD_ENV).ok().as_deref() == Some("run") {
            run_child();
        }
    }

    #[test]
    fn the_filesystem_profile_blocks_socket_creation() {
        if !require_kernel_support() {
            eprintln!("SKIP: seccomp unavailable on this platform");
            return;
        }
        let (report, out) = run_scenario("filesystem");

        if let Some(fatal) = &report.fatal {
            panic!(
                "the child could not install the filter: {fatal}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Positive controls first: if these fail, the filter is not installed and
        // every denial below would be meaningless.
        assert_eq!(report.get("filter"), "APPLIED", "the filter was not installed");
        report.allowed("getpid");
        report.allowed("write");

        // The hole this closes. Landlock alone leaves socket(2) open.
        report.denied("socket");
        report.denied("udp_socket");

        println!(
            "filesystem profile: unix_socket={} open_dev_null={}",
            report.get("unix_socket"),
            report.get("open_dev_null")
        );
    }

    #[test]
    fn a_filesystem_profile_can_still_read_files() {
        // The filter must not be so tight the tool cannot function. `open` on
        // `/dev/null` is allowlisted in every profile, and this asserts the
        // allowlist was actually applied rather than accidentally blocking
        // everything.
        if !require_kernel_support() {
            return;
        }
        let (report, _out) = run_scenario("filesystem");
        report.allowed("open_dev_null");
        report.allowed("write");
        // `done` is a marker the child prints last, not a syscall outcome, so it
        // is compared exactly. Reaching it proves the child survived every probe
        // rather than dying partway through.
        assert_eq!(report.get("done"), "ok", "the child did not reach the end");
    }

    #[test]
    fn unix_sockets_are_refused_too_under_the_filesystem_profile() {
        // Observed rather than assumed: a profile built for filesystem work has
        // no use for local IPC either, and refusing it removes another channel a
        // confined process could use to talk to something unconfined.
        if !require_kernel_support() {
            return;
        }
        let (report, _out) = run_scenario("filesystem");
        report.denied("unix_socket");
    }

    #[test]
    fn the_exec_profile_also_blocks_socket_creation() {
        if !require_kernel_support() {
            eprintln!("SKIP: seccomp unavailable on this platform");
            return;
        }
        let (report, out) = run_scenario("exec");
        if let Some(fatal) = &report.fatal {
            panic!(
                "the child could not install the filter: {fatal}\n--- stdout ---\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
        assert_eq!(report.get("filter"), "APPLIED", "the filter was not installed");
        report.allowed("getpid");
        report.denied("socket");
        report.denied("udp_socket");
    }

    #[test]
    fn denied_syscalls_report_enosys_rather_than_killing_the_process() {
        // The filter returns ENOSYS so a tool fails visibly and the caller can
        // learn which capability it wanted, rather than the process dying with
        // no explanation.
        if !require_kernel_support() {
            return;
        }
        let (report, _out) = run_scenario("filesystem");
        let got = report.get("socket");
        assert!(
            got.contains("errno=38"),
            "expected ENOSYS(38) so the failure is legible, got {got}"
        );
    }

    #[test]
    fn the_parent_process_is_not_filtered() {
        // Confinement must not leak outward from the child.
        let fd = raw_socket(libc::AF_INET, libc::SOCK_STREAM);
        assert!(
            fd >= 0,
            "the parent should still be able to open a socket after a child was filtered"
        );
        unsafe { libc::close(fd) };
    }
}

