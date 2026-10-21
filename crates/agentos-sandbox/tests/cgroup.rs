//! cgroup and namespace integration tests.
//!
//! These are the tests behind the claims in [`agentos_sandbox::cgroup`] and
//! [`agentos_sandbox::ns`]. They do not assert "the file was written": they
//! spawn a real worker through the real pool and then read the kernel's own
//! records - `/proc/<pid>/cgroup`, `cgroup.procs`, `memory.events`, `cpu.stat`,
//! `/proc/<pid>/ns/*` - rather than asking the worker to attest to its own
//! confinement.
//!
//! # Why a host child
//!
//! Constructing a pool forks, and the forked child allocates while applying
//! Landlock and seccomp. That is only sound from a single-threaded process, so
//! each scenario re-execs this binary with `--test-threads=1`, exactly like
//! `tests/pool.rs`. The empty-report hazard is handled the same way: the child
//! emits a `boot` probe before it touches a pool, and the parent requires it.
//!
//! # What must be true on the host
//!
//! - cgroup tests need a **delegated** cgroup. Configuring limits under a
//!   delegated root is not enough; migrating a child out of the caller's own
//!   cgroup also needs write access to that cgroup's `cgroup.procs`. Under WSL
//!   this is true inside a systemd user scope and false from a plain login
//!   shell, so the suite runs as
//!
//!   ```text
//!   systemd-run --user --scope -- bash -lc 'cargo test -p agentos-sandbox'
//!   ```
//!
//!   and skips, loudly, when delegation is absent. [`delegation_works`] proves
//!   the capability functionally by migrating a throwaway child, not by reading
//!   a file.
//! - namespace tests need unprivileged user namespaces. They are probed the same
//!   way, by actually unmounting a tmpfs in a private namespace.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agentos_sandbox::cgroup::{Attachment, Cgroup, CgroupError, CgroupLimits, CpuMax};
use agentos_sandbox::ns::Namespaces;
use agentos_sandbox::pool::{Pool, PoolConfig, PoolError, WorkerImage};
use agentos_sandbox::{Abi, Confine, SeccompProfile};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const SCENARIO_ENV: &str = "AGENTOS_SANDBOX_RESOURCE_SCENARIO";
const ROOT_ENV: &str = "AGENTOS_SANDBOX_RESOURCE_ROOT";
const MARKER_ENV: &str = "AGENTOS_SANDBOX_RESOURCE_MARKER";
const INSIDE_ENV: &str = "AGENTOS_SANDBOX_RESOURCE_INSIDE";
const PROBE: &str = "##PROBE##";

/// Every test name this file re-execs into.
const CHILD_ENTRY_POINTS: &[&str] = &["host_entry"];

const HOST_TIMEOUT: Duration = Duration::from_secs(180);

fn probe(name: &str, value: &str) {
    println!("{PROBE}\t{name}\t{value}");
    let _ = std::io::stdout().flush();
}

struct Report {
    values: BTreeMap<String, String>,
}

impl Report {
    fn parse(stdout: &[u8]) -> Report {
        let text = String::from_utf8_lossy(stdout);
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let Some(idx) = line.find(PROBE) else { continue };
            let mut fields = line[idx + PROBE.len()..].split('\t');
            let _ = fields.next();
            let (Some(name), Some(value)) = (fields.next(), fields.next()) else {
                continue;
            };
            values
                .entry(name.to_string())
                .or_insert_with(|| value.trim().to_string());
        }
        Report { values }
    }

    fn get(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("probe `{name}` never reported; got {:?}", self.values))
    }
}

fn require_booted(report: &Report, scenario: &str, stdout: &[u8], stderr: &[u8]) {
    let boot = report.values.get("boot").unwrap_or_else(|| {
        panic!(
            "the {scenario} child never reached its probes. An empty report is not a pass.\n\
             --- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(stdout),
            String::from_utf8_lossy(stderr),
        )
    });
    assert!(
        boot.starts_with("booted"),
        "the {scenario} child did not boot cleanly: {boot}"
    );
}

/// Re-exec this binary as a single-threaded host child with a timeout.
fn run_host(scenario: &str, scratch: &Scratch) -> Report {
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("host_entry")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(SCENARIO_ENV, scenario)
        .env(ROOT_ENV, &scratch.root)
        .env(MARKER_ENV, &scratch.marker)
        .env(INSIDE_ENV, &scratch.inside)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the resource host child");

    let deadline = Instant::now() + HOST_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the {scenario} host child exceeded {HOST_TIMEOUT:?}");
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

// ---------------------------------------------------------------------------
// Scratch tree
// ---------------------------------------------------------------------------

struct Scratch {
    root: PathBuf,
    marker: String,
    inside: String,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let unique = format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("agentos-resource-{unique}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Scratch {
            root,
            marker: format!("agentos-ns-marker-{unique}"),
            inside: format!("agentos-ns-inside-{unique}"),
        }
    }

    fn host_marker(&self) -> PathBuf {
        Path::new("/tmp").join(&self.marker)
    }

    fn host_inside(&self) -> PathBuf {
        Path::new("/tmp").join(&self.inside)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_file(self.host_marker());
        let _ = fs::remove_file(self.host_inside());
    }
}

// ---------------------------------------------------------------------------
// Worker image and confinement
// ---------------------------------------------------------------------------

fn probe_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let parent = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("the target has a target/<profile> directory");
    parent.join("agentos-cgroup-probe")
}

fn probe_image(args: &[&str]) -> WorkerImage {
    let mut image = WorkerImage::new(probe_binary());
    for arg in args {
        image = image.arg(*arg);
    }
    image
}

fn base_confine() -> Confine {
    let c = Confine::new()
        .read_only_exec("/lib")
        .read_only_exec("/usr/lib");
    match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .and_then(|d| d.parent().map(|d| d.to_path_buf()))
    {
        Some(dir) => c.read_only_exec(dir),
        None => c,
    }
}

/// The profile for the namespace probe: the private tmpfs is mounted before
/// Landlock, so a rule on `/tmp` describes the tmpfs the worker will use, and
/// the report directory must be writable for the observation to leave the
/// namespace at all.
fn namespace_confine(_scratch: &Scratch) -> Confine {
    base_confine().read_write("/tmp")
}

fn one_worker(config: PoolConfig) -> PoolConfig {
    config.workers(1).allow_threaded_fork(true)
}

fn require_landlock() -> bool {
    match agentos_sandbox::detect_kernel_support().abi() {
        Some(abi) if abi >= Abi::V6 => true,
        other => {
            eprintln!("SKIP: Landlock ABI {other:?} < V6, so no worker can be confined here");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Capability probes
// ---------------------------------------------------------------------------

/// Prove a child can actually be migrated into a limit cgroup.
///
/// A file check is not enough: the destination can be writable while the cgroup
/// the test process is leaving is not, and the migration would fail with `EPERM`
/// on the first real spawn. This does the migration for real and removes every
/// trace of it.
fn delegation_works() -> Result<(), String> {
    let root = agentos_sandbox::cgroup::discover().map_err(|e| e.to_string())?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let name = format!("agentos-delegation-probe-{}-{unique}", std::process::id());
    let cgroup = Cgroup::create_in(&root, &name, CgroupLimits::default())
        .map_err(|e| format!("cannot create a probe cgroup under {}: {e}", root.display()))?;
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .map_err(|e| format!("cannot spawn the delegation probe child: {e}"))?;
    let result = cgroup.attach(child.id() as i32);
    let _ = child.kill();
    let _ = child.wait();
    let removed = cgroup.remove();
    match result {
        Ok(Attachment::Attached) => removed.map_err(|e| e.to_string()),
        Ok(Attachment::ChildGone) => Err("the delegation probe child died before migration".into()),
        Err(e) => Err(format!("cannot migrate a child into {}: {e}", root.display())),
    }
}

fn require_cgroup_delegation() -> bool {
    match delegation_works() {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "SKIP: cgroup v2 limits are not enforceable from this process: {e}\n\
                 Run the suite inside a delegated scope, e.g. \
                 `systemd-run --user --scope -- bash -lc 'cargo test -p agentos-sandbox'`."
            );
            false
        }
    }
}

/// Prove unprivileged user and mount namespaces work, by using them.
fn namespaces_work() -> Result<(), String> {
    let out = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "sh",
            "-c",
            "mount -t tmpfs -o size=1m tmpfs /tmp && echo ns-ok",
        ])
        .output()
        .map_err(|e| format!("cannot run unshare: {e}"))?;
    if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ns-ok") {
        Ok(())
    } else {
        Err(format!(
            "unshare/mount failed: status {} stderr {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn require_namespaces() -> bool {
    match namespaces_work() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("SKIP: user and mount namespaces are not usable here: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Host child
// ---------------------------------------------------------------------------

#[test]
fn host_entry() {
    let Ok(scenario) = std::env::var(SCENARIO_ENV) else {
        return;
    };
    let scratch = Scratch {
        root: std::env::var_os(ROOT_ENV)
            .map(PathBuf::from)
            .expect("the parent sets ROOT_ENV"),
        marker: std::env::var(MARKER_ENV).expect("the parent sets MARKER_ENV"),
        inside: std::env::var(INSIDE_ENV).expect("the parent sets INSIDE_ENV"),
    };

    let threads = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<u32>().ok())
        })
        .unwrap_or(0);
    probe(
        "boot",
        &format!("booted pid={} threads={threads}", std::process::id()),
    );

    match scenario.as_str() {
        "cgroup-installed" => cgroup_installed(&scratch),
        "cgroup-memory" => cgroup_memory(&scratch),
        "cgroup-cpu" => cgroup_cpu(&scratch),
        "cgroup-pids" => cgroup_pids(&scratch),
        "namespaces" => namespaces_tmpfs(&scratch),
        "namespace-fail-closed" => namespace_fail_closed(&scratch),
        "cgroup-fail-closed" => cgroup_fail_closed(&scratch),
        other => {
            probe("fatal", &format!("UNKNOWN_SCENARIO {other}"));
            std::process::exit(64);
        }
    }

    // The host child must not delete the tree the parent may still inspect.
    std::mem::forget(scratch);
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .trim()
        .to_string()
}

fn wait_for_removal(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if !path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    !path.exists()
}

fn process_state(pid: i32) -> Option<char> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field can contain spaces and parentheses; state is the first
    // field after the last `)`.
    let after = text.rsplit_once(')')?.1;
    after.split_whitespace().next()?.chars().next()
}

fn cgroup_membership(pid: i32) -> String {
    read(format!("/proc/{pid}/cgroup"))
}

fn cgroup_installed(_scratch: &Scratch) {
    let limits = CgroupLimits {
        memory_max: 64 * 1024 * 1024,
        memory_swap_max: Some(0),
        pids_max: 8,
        cpu_max: CpuMax::new(50_000, 100_000),
    };
    let pool = Pool::spawn(
        probe_image(&["idle", "8000"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).cgroup_limits(limits),
    )
    .expect("a pool with cgroup limits");

    let lease = pool.checkout().expect("checkout");
    let pid = lease.pid();
    let path = lease
        .cgroup_path()
        .expect("a limited worker has a cgroup")
        .to_path_buf();
    assert!(path.exists(), "the worker's cgroup {} is missing", path.display());

    probe("worker_pid", &pid.to_string());
    probe("cgroup_path", &path.display().to_string());

    // Kernel membership, from the parent's view of the child.
    let membership = cgroup_membership(pid);
    probe("membership", &membership);
    assert!(
        membership.ends_with(&format!("{}", path.file_name().unwrap().to_string_lossy())),
        "the worker is not recorded in the cgroup it was given: {membership}"
    );

    let procs = read(path.join("cgroup.procs"));
    probe("cgroup_procs", &procs);
    assert!(
        procs.split_whitespace().any(|p| p == pid.to_string()),
        "`cgroup.procs` does not contain the worker pid {pid}: {procs}"
    );

    assert_eq!(read(path.join("memory.max")), "67108864");
    assert_eq!(read(path.join("memory.swap.max")), "0");
    assert_eq!(read(path.join("pids.max")), "8");
    assert_eq!(read(path.join("cpu.max")), "50000 100000");
    probe("limits", "memory.max=67108864 pids.max=8 cpu.max=50000 100000 swap.max=0");

    // Nothing has ever been charged against the ceiling yet.
    let events = read(path.join("memory.events"));
    probe("memory_events", &events);
    assert!(
        events
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .map(|v| v.trim() == "0")
            .unwrap_or(false),
        "an idle worker should not have been OOM-killed: {events}"
    );

    // The probe is still alive, so the observations above are of a live worker.
    let state = process_state(pid);
    assert!(
        matches!(state, Some(c) if c != 'Z'),
        "the probe should be alive, not reaped or a zombie: {state:?}"
    );

    lease.shutdown().expect("shutdown the worker");
    assert!(
        wait_for_removal(&path, Duration::from_secs(5)),
        "the worker's cgroup {} outlived the worker; an empty cgroup left behind is a leak",
        path.display()
    );
    probe("cgroup_removed", "true");
    pool.shutdown();
}

fn cgroup_memory(_scratch: &Scratch) {
    let limits = CgroupLimits {
        // Enough for the loader and a Rust binary, far below the 64 MiB the
        // probe will touch.
        memory_max: 32 * 1024 * 1024,
        memory_swap_max: Some(0),
        pids_max: 8,
        cpu_max: CpuMax::default(),
    };
    let pool = Pool::spawn(
        probe_image(&["touch-memory", "67108864", "400"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).cgroup_limits(limits),
    )
    .expect("a pool with a memory ceiling");

    let lease = pool.checkout().expect("checkout");
    let pid = lease.pid();
    let path = lease
        .cgroup_path()
        .expect("a limited worker has a cgroup")
        .to_path_buf();
    assert_eq!(read(path.join("memory.max")), "33554432");
    probe("memory_max", "33554432");

    // Give the probe time to fault the allocation in and the OOM killer time to
    // act. The delay in the probe keeps it alive past `checkout`, so the kill is
    // observed rather than being a race with startup.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = String::new();
    let mut oom_kills = 0u64;
    while Instant::now() < deadline {
        events = read(path.join("memory.events"));
        oom_kills = events
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if oom_kills > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    probe("memory_events", &events);
    probe("oom_kills", &oom_kills.to_string());
    assert!(
        oom_kills > 0,
        "allocating 64 MiB under a 32 MiB ceiling did not charge an OOM kill: {events}"
    );

    // The worker must be dead, not merely reported dead by the cgroup.
    let state = process_state(pid);
    probe("worker_state", &format!("{state:?}"));
    assert!(
        matches!(state, None | Some('Z')),
        "the over-budget worker is still running: {state:?}"
    );

    drop(lease);
    pool.shutdown();
    assert!(
        wait_for_removal(&path, Duration::from_secs(5)),
        "the cgroup outlived an OOM-killed worker"
    );
    probe("cgroup_removed", "true");
}

fn cgroup_cpu(_scratch: &Scratch) {
    let limits = CgroupLimits {
        memory_max: 128 * 1024 * 1024,
        memory_swap_max: Some(0),
        pids_max: 8,
        // 10% of one CPU. A 500 ms burn must be throttled many times.
        cpu_max: CpuMax::new(10_000, 100_000),
    };
    let pool = Pool::spawn(
        probe_image(&["burn-cpu", "500"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).cgroup_limits(limits),
    )
    .expect("a pool with a CPU quota");

    let lease = pool.checkout().expect("checkout");
    let path = lease
        .cgroup_path()
        .expect("a limited worker has a cgroup")
        .to_path_buf();
    assert_eq!(read(path.join("cpu.max")), "10000 100000");
    probe("cpu_max", "10000 100000");

    // Wait for the probe to finish burning and exit. It prints `cpu_burned` to
    // the inherited stdout, which the parent asserts on, so a worker that died
    // before burning cannot make this pass.
    std::thread::sleep(Duration::from_millis(1500));
    let stat = read(path.join("cpu.stat"));
    probe("cpu_stat", &stat);
    let throttled = stat
        .lines()
        .find_map(|l| l.strip_prefix("nr_throttled "))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    probe("nr_throttled", &throttled.to_string());
    assert!(
        throttled > 0,
        "a 500 ms burn under a 10% quota was never throttled: {stat}"
    );

    drop(lease);
    pool.shutdown();
    assert!(wait_for_removal(&path, Duration::from_secs(5)));
}

fn cgroup_pids(_scratch: &Scratch) {
    let limits = CgroupLimits {
        memory_max: 64 * 1024 * 1024,
        memory_swap_max: Some(0),
        pids_max: 2,
        cpu_max: CpuMax::default(),
    };
    let root = agentos_sandbox::cgroup::discover().expect("a delegated root");
    let name = format!("agentos-pids-{}", std::process::id());
    let cgroup = Cgroup::create_in(&root, &name, limits).expect("create the pids cgroup");
    assert_eq!(read(cgroup.path().join("pids.max")), "2");

    // The probe is unconfined so it can fork; the pool's own seccomp profile
    // refuses `clone`, which is why that path cannot exercise `pids.max`.
    // Migration alone does not enforce the limit, so the probe is attached
    // first and only then forks: the second child is the one over budget.
    let child = Command::new(probe_binary())
        .args([
            "fork-attempts",
            "8",
            "400",
            "300",
            cgroup.path().to_str().expect("utf-8 cgroup path"),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the fork probe");
    cgroup
        .attach(child.id() as i32)
        .expect("attach the fork probe");
    let output = child.wait_with_output().expect("wait for the fork probe");

    let report = Report::parse(&output.stdout);
    let forks = report.get("pids_forks");
    let errno = report.get("pids_errno");
    let current = report.get("pids_current");
    probe("pids_forks", forks);
    probe("pids_errno", errno);
    probe("pids_current", current);

    // With `pids.max = 2`, the probe itself is one task, so exactly one child
    // fits and the next fork is refused with EAGAIN.
    assert_eq!(forks, "1", "the pid limit did not stop the second fork: {forks}");
    assert_eq!(errno, "11", "the refusal should be EAGAIN, not an arbitrary error");
    assert_eq!(current, "2");

    cgroup.remove().expect("remove the pids cgroup");
    probe("cgroup_removed", "true");
}

fn namespaces_tmpfs(scratch: &Scratch) {
    // A marker the host writes where the worker's old `/tmp` used to be.
    fs::write(scratch.host_marker(), b"host marker\n").expect("write the host marker");

    let pool = Pool::spawn(
        probe_image(&["tmpfs-probe", &scratch.marker, &scratch.inside, "1500"]),
        namespace_confine(scratch),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).namespaces(Namespaces::UserAndMount {
            tmpfs_bytes: 8 * 1024 * 1024,
        }),
    )
    .expect("a pool with private namespaces");

    let lease = pool.checkout().expect("checkout");
    let pid = lease.pid();

    // Namespace identity from the kernel, for both sides, while the worker is
    // alive. A worker that could not read `/proc` never has to be trusted here.
    let host_mnt = fs::read_link("/proc/self/ns/mnt").expect("host mnt ns");
    let host_user = fs::read_link("/proc/self/ns/user").expect("host user ns");
    let worker_mnt =
        fs::read_link(format!("/proc/{pid}/ns/mnt")).expect("worker mnt ns while alive");
    let worker_user =
        fs::read_link(format!("/proc/{pid}/ns/user")).expect("worker user ns while alive");
    probe("host_mnt_ns", &host_mnt.display().to_string());
    probe("worker_mnt_ns", &worker_mnt.display().to_string());
    probe("host_user_ns", &host_user.display().to_string());
    probe("worker_user_ns", &worker_user.display().to_string());
    assert_ne!(host_mnt, worker_mnt, "the worker shares the host mount namespace");
    assert_ne!(host_user, worker_user, "the worker shares the host user namespace");

    // Let the probe finish its delay, probe /tmp and flush its findings. The
    // parent asserts on those lines; a worker that died first would be caught
    // there because the probes would be absent.
    std::thread::sleep(Duration::from_millis(2500));

    // And the reverse direction: nothing the worker wrote escaped to the host.
    assert!(
        scratch.host_marker().exists(),
        "the host marker disappeared, so the comparison would be vacuous"
    );
    assert!(
        !scratch.host_inside().exists(),
        "a file written inside the worker's /tmp reached the host: {}",
        scratch.host_inside().display()
    );

    drop(lease);
    pool.shutdown();
    let _ = fs::remove_file(scratch.host_marker());
}

fn namespace_fail_closed(_scratch: &Scratch) {
    let result = Pool::spawn(
        probe_image(&["idle", "100"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).namespaces(Namespaces::UserAndMount {
            tmpfs_bytes: 0,
        }),
    );
    match result {
        Err(PoolError::WorkerRefused(message)) => {
            probe("refusal", &message);
            assert!(
                message.contains("NAMESPACES"),
                "the refusal should say the namespaces were the problem: {message}"
            );
        }
        Err(other) => panic!("expected a worker refusal, got {other}"),
        Ok(_) => panic!("a zero-sized tmpfs must refuse to spawn, not run a shared worker"),
    }
}

fn cgroup_fail_closed(scratch: &Scratch) {
    let bad_root = scratch.root.join("not-a-cgroup");
    let result = Pool::spawn(
        probe_image(&["idle", "100"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default())
            .cgroup_limits(CgroupLimits::default())
            .cgroup_root(&bad_root),
    );
    match result {
        Err(PoolError::Cgroup(CgroupError::NoDelegatedRoot { tried, detail })) => {
            probe("detail", &detail);
            assert!(
                tried.iter().any(|p| p == &bad_root),
                "the refusal did not name the configured root: {tried:?}"
            );
            assert!(
                detail.contains(&bad_root.display().to_string()),
                "the refusal should say why the configured root was rejected: {detail}"
            );
        }
        Err(other) => panic!("expected NoDelegatedRoot, got {other}"),
        Ok(_) => panic!("a bad cgroup root must not produce a worker"),
    }

    // A root without limits is a configuration error rather than a silently
    // wasted cgroup.
    let result = Pool::spawn(
        probe_image(&["idle", "100"]),
        base_confine(),
        SeccompProfile::Worker,
        one_worker(PoolConfig::default()).cgroup_root(&bad_root),
    );
    match result {
        Err(PoolError::BadConfig(message)) => probe("bad_config", &message),
        Err(other) => panic!("expected BadConfig for a root without limits, got {other}"),
        Ok(_) => panic!("a root without limits must not produce a worker"),
    }
}

// ---------------------------------------------------------------------------
// Parent tests
// ---------------------------------------------------------------------------

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
        "`--list` failed: {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    for name in CHILD_ENTRY_POINTS {
        assert!(
            text.contains(name),
            "`{name}` is not a test here; a filter that matches nothing exits 0 and hands the \
             parent an empty report that reads like a pass.\n--- listing ---\n{text}"
        );
    }
}

#[test]
fn cgroup_limits_are_installed_and_the_worker_is_inside_them() {
    if !require_landlock() || !require_cgroup_delegation() {
        return;
    }
    let scratch = Scratch::new("cg-install");
    let report = run_host("cgroup-installed", &scratch);
    assert_eq!(report.get("cgroup_removed"), "true");
    assert!(
        report.get("membership").contains("agentos-"),
        "the kernel's /proc/<pid>/cgroup did not name a worker cgroup: {}",
        report.get("membership")
    );
    assert!(report.get("limits").contains("pids.max=8"));
}

#[test]
fn a_worker_that_exceeds_its_memory_ceiling_is_killed() {
    if !require_landlock() || !require_cgroup_delegation() {
        return;
    }
    let scratch = Scratch::new("cg-memory");
    let report = run_host("cgroup-memory", &scratch);
    assert_ne!(report.get("oom_kills"), "0");
    assert_eq!(report.get("cgroup_removed"), "true");
    assert!(
        matches!(report.get("worker_state"), "None" | "Some('Z')"),
        "the over-budget worker was still running: {}",
        report.get("worker_state")
    );
}

#[test]
fn a_cpu_quota_throttles_a_burning_worker() {
    if !require_landlock() || !require_cgroup_delegation() {
        return;
    }
    let scratch = Scratch::new("cg-cpu");
    let report = run_host("cgroup-cpu", &scratch);
    assert_eq!(
        report.get("cpu_burned"),
        "500",
        "the worker never burned CPU, so the throttle count below would be vacuous"
    );
    assert_ne!(report.get("nr_throttled"), "0");
}

#[test]
fn the_pid_limit_refuses_a_task_beyond_it() {
    if !require_cgroup_delegation() {
        return;
    }
    let scratch = Scratch::new("cg-pids");
    let report = run_host("cgroup-pids", &scratch);
    assert_eq!(report.get("pids_forks"), "1");
    assert_eq!(report.get("pids_errno"), "11");
    assert_eq!(report.get("cgroup_removed"), "true");
}

#[test]
fn a_private_tmpfs_hides_the_host_tmp_in_both_directions() {
    if !require_landlock() || !require_namespaces() {
        return;
    }
    let scratch = Scratch::new("ns-tmpfs");
    let report = run_host("namespaces", &scratch);
    assert_ne!(report.get("host_mnt_ns"), report.get("worker_mnt_ns"));
    assert_ne!(report.get("host_user_ns"), report.get("worker_user_ns"));
    assert_eq!(
        report.get("marker_present"),
        "false",
        "the host's /tmp marker is visible inside the worker"
    );
    assert_eq!(
        report.get("marker_errno"),
        "2",
        "the host marker should be ENOENT inside a fresh /tmp, not a denial"
    );
    assert_eq!(
        report.get("write_ok"),
        "true",
        "the worker cannot use its private /tmp"
    );
}

#[test]
fn a_namespace_that_cannot_be_created_refuses_to_spawn() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("ns-refuse");
    let report = run_host("namespace-fail-closed", &scratch);
    assert!(report.get("refusal").contains("NAMESPACES"));
}

#[test]
fn an_unusable_cgroup_root_refuses_to_spawn() {
    if !require_landlock() {
        return;
    }
    let scratch = Scratch::new("cg-refuse");
    let report = run_host("cgroup-fail-closed", &scratch);
    assert!(report.get("detail").contains("not-a-cgroup"));
}
