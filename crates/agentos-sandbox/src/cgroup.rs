//! cgroup v2 CPU, memory and pid limits for worker processes.
//!
//! Landlock and seccomp constrain what a worker may *reach*. They say nothing
//! about what it may *cost*: a confined tool can still allocate the host's
//! memory, spin every CPU, and fork until the pid space is exhausted. cgroup v2
//! is the kernel's answer to that, and this module is the spawn path's use of
//! it.
//!
//! # One cgroup per worker
//!
//! Each worker gets its own directory under a delegated cgroup, created before
//! the fork so a failure to set the limits refuses the spawn rather than
//! producing a worker that is already running unconstrained. The child is moved
//! into it after `fork(2)` and before `execveat(2)` (the latter is enforced with
//! a one-byte barrier in [`crate::pool`]), so the exec'd image starts inside its
//! budget.
//!
//! Moving the *child* rather than putting the daemon in the cgroup is
//! deliberate: the daemon must not be charged to, or throttled by, a worker's
//! budget, and a worker that the pool replaces must not drag the replacement
//! into its own accounting.
//!
//! # Root discovery, without assuming systemd is PID 1
//!
//! A process may only create cgroups under a directory it is allowed to write.
//! Discovery tries, in order:
//!
//! 1. the caller's own cgroup from `/proc/self/cgroup`, if that directory is
//!    writable and its `cgroup.controllers` offers the controllers needed;
//! 2. `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service`, the
//!    systemd user manager's delegated cgroup, with `<uid>` from `geteuid(2)`;
//! 3. nothing. The error names every path that was tried and why each was
//!    rejected.
//!
//! A candidate must also be reachable in the direction that matters: the
//! process's *own* cgroup must have a writable `cgroup.procs`, because migrating
//! a child out of it is checked against the source as well as the destination. A
//! container, or a plain shell outside the systemd user manager, can have a
//! perfectly writable destination it is nevertheless not allowed to populate.
//! Checking that at discovery turns a bare `EPERM` at first spawn into a
//! refusal that says to run the daemon under a delegated cgroup.
//!
//! Step 1 is what makes this work without systemd. Step 2 is what makes it work
//! on a systemd host whose shell sits in an undelegated scope, which is the
//! common case: the shell is in `/user.slice/.../session-N.scope`, and that
//! scope's `cgroup.controllers` is empty because a leaf cgroup cannot offer
//! controllers to children. The user manager's own cgroup is the delegated one.
//!
//! A caller may override discovery with [`crate::pool::PoolConfig::cgroup_root`],
//! which is how the fail-closed path is tested.
//!
//! # Fail closed
//!
//! If limits are requested and any step fails - discovery, controller
//! enablement, `mkdir`, writing a limit, reading it back, or moving the child -
//! the worker is not exec'd and the pool returns [`crate::pool::PoolError`].
//! There is no "spawn it anyway and hope" path, and there is no fallback to the
//! root cgroup.
//!
//! # Cleanup
//!
//! A cgroup with a live process in it cannot be removed. Teardown is therefore
//! ordered: kill, reap, then `rmdir`, retrying briefly because the kernel's
//! release of a task from its cgroup is not always complete at the instant
//! `waitpid` returns. A worker that died between `fork` and the move leaves a
//! cgroup that never had a member; that is removed normally and is not an
//! error.
//!
//! # What is not limited
//!
//! - **I/O.** `io.max` is per-device and needs a device number the pool does
//!   not know. A worker can still saturate a disk.
//! - **Swap, unless `memory_swap_max` is set.** It defaults to `Some(0)`
//!   precisely so that `memory_max` is a ceiling and not a hint: on a host with
//!   swap, a 32 MiB `memory.max` with unlimited swap lets a worker allocate far
//!   more than 32 MiB by paging it out.
//! - **PIDs created outside the cgroup.** The limit counts tasks in the cgroup
//!   hierarchy. Every descendant of the worker inherits the cgroup, so it counts
//!   them; a process the worker talks into leaving the cgroup would not, and
//!   the worker has no authority to move anything.

use std::path::{Path, PathBuf};

use thiserror::Error;

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "linux")]
use std::time::Duration;

/// Environment variable carrying the worker's cgroup path into the worker image.
///
/// Set by the pool on every spawn for which limits are configured, and filtered
/// out of the inherited environment first so a stale value cannot survive. It is
/// a path, not a file descriptor: it confers no authority, because the cgroup
/// controls are only writable by the cgroup's owner and the worker runs under
/// the same uid only until namespaces are enabled.
pub const CGROUP_ENV: &str = "AGENTOS_SANDBOX_CGROUP";

/// Controllers this module knows how to configure.
///
/// Named rather than discovered so that a missing controller is a refusal that
/// names it, instead of a limit file that silently does not exist.
pub const NEEDED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// Default memory ceiling: 512 MiB.
pub const DEFAULT_MEMORY_MAX: u64 = 512 * 1024 * 1024;

/// Default pid ceiling.
pub const DEFAULT_PIDS_MAX: u64 = 64;

/// Default CPU period: 100 ms, the kernel's own default.
pub const DEFAULT_CPU_PERIOD_MICROS: u64 = 100_000;

/// Default CPU quota: 100 ms per 100 ms period, i.e. one full CPU.
pub const DEFAULT_CPU_QUOTA_MICROS: u64 = DEFAULT_CPU_PERIOD_MICROS;

/// How many times teardown retries `rmdir` before reporting.
#[cfg(target_os = "linux")]
const REMOVE_ATTEMPTS: u32 = 20;

/// How long teardown waits between `rmdir` attempts.
#[cfg(target_os = "linux")]
const REMOVE_BACKOFF: Duration = Duration::from_millis(5);

/// A CPU bandwidth limit, as cgroup v2's `cpu.max` expresses it.
///
/// `quota_micros` of CPU time is available per `period_micros` of wall time. A
/// quota equal to the period is one CPU; a quota of twice the period is two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    /// CPU time allowed per period, in microseconds.
    pub quota_micros: u64,
    /// Length of the period, in microseconds.
    pub period_micros: u64,
}

impl CpuMax {
    /// A quota over a period.
    pub const fn new(quota_micros: u64, period_micros: u64) -> Self {
        CpuMax {
            quota_micros,
            period_micros,
        }
    }

    /// The `cpu.max` file contents.
    pub fn to_control_value(self) -> String {
        format!("{} {}", self.quota_micros, self.period_micros)
    }
}

impl Default for CpuMax {
    fn default() -> Self {
        CpuMax::new(DEFAULT_CPU_QUOTA_MICROS, DEFAULT_CPU_PERIOD_MICROS)
    }
}

/// The limits written to a worker's cgroup.
///
/// Every field is explicit. `Default` is a real budget, not zero: a zero
/// `memory.max` would mean "no memory" and a zero `pids.max` would mean "do not
/// even exec", so a caller that forgets to set a field gets a usable default
/// rather than a worker that cannot start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupLimits {
    /// Hard memory ceiling in bytes (`memory.max`).
    pub memory_max: u64,
    /// Hard swap ceiling in bytes (`memory.swap.max`).
    ///
    /// `Some(0)` by default, because `memory.max` on its own is not a ceiling on
    /// a host with swap: pages can be evicted and re-charged. `None` leaves swap
    /// unlimited and is only appropriate on a kernel without swap accounting,
    /// where writing the file would fail.
    pub memory_swap_max: Option<u64>,
    /// Maximum number of tasks in the cgroup (`pids.max`).
    pub pids_max: u64,
    /// CPU bandwidth (`cpu.max`).
    pub cpu_max: CpuMax,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        CgroupLimits {
            memory_max: DEFAULT_MEMORY_MAX,
            memory_swap_max: Some(0),
            pids_max: DEFAULT_PIDS_MAX,
            cpu_max: CpuMax::default(),
        }
    }
}

impl CgroupLimits {
    /// Limits with the default swap ceiling (zero).
    pub const fn new(memory_max: u64, pids_max: u64, cpu_max: CpuMax) -> Self {
        CgroupLimits {
            memory_max,
            memory_swap_max: Some(0),
            pids_max,
            cpu_max,
        }
    }

    /// Set the swap ceiling.
    pub const fn with_swap_max(mut self, bytes: Option<u64>) -> Self {
        self.memory_swap_max = bytes;
        self
    }

    #[cfg(any(target_os = "linux", test))]
    fn validate(self) -> Result<(), CgroupError> {
        if self.memory_max == 0 {
            return Err(CgroupError::InvalidLimits(
                "memory_max of zero would let a worker allocate nothing, including its own stack"
                    .into(),
            ));
        }
        if self.pids_max == 0 {
            return Err(CgroupError::InvalidLimits(
                "pids_max of zero would refuse the exec that starts the worker".into(),
            ));
        }
        if self.cpu_max.period_micros == 0 {
            return Err(CgroupError::InvalidLimits(
                "cpu period of zero is rejected by the kernel".into(),
            ));
        }
        if self.cpu_max.quota_micros == 0 {
            return Err(CgroupError::InvalidLimits(
                "cpu quota of zero would freeze the worker".into(),
            ));
        }
        Ok(())
    }
}

/// Why a cgroup could not be created, joined or removed.
///
/// Every variant is a refusal. The pool never spawns a worker after one of
/// these, except where [`Cgroup::attach`] reports
/// [`Attachment::ChildGone`] - which is not a failure to confine, because the
/// process it would have confined is already dead.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CgroupError {
    /// cgroup v2 is a Linux interface.
    #[error("cgroup v2 limits are only implemented on linux")]
    UnsupportedPlatform,

    /// A limit was zero or otherwise impossible.
    #[error("invalid cgroup limits: {0}")]
    InvalidLimits(String),

    /// No usable delegated cgroup directory was found.
    ///
    /// Both the discovery candidates and an explicitly configured root report
    /// through this variant, because the caller's question is the same in both
    /// cases: "which paths did you try, and why did each one fail?"
    #[error(
        "refusing to spawn: no usable delegated cgroup v2 directory; tried {}: {detail}",
        display_paths(tried)
    )]
    NoDelegatedRoot {
        /// Every path that was considered, in order.
        tried: Vec<PathBuf>,
        /// Why the last candidate, and any earlier ones worth naming, failed.
        detail: String,
    },

    /// Reading or writing a cgroup control file failed.
    #[error("cgroup operation on {path} failed: {op}: {source}")]
    Io {
        /// The control file or directory involved.
        path: PathBuf,
        /// What was being done.
        op: &'static str,
        /// The kernel's error.
        source: std::io::Error,
    },

    /// A controller the limits need is not available or could not be enabled.
    #[error("cgroup {root} cannot provide the `{controller}` controller: {detail}")]
    ControllerUnavailable {
        /// The parent cgroup.
        root: PathBuf,
        /// The controller name.
        controller: &'static str,
        /// What the kernel reported.
        detail: String,
    },

    /// The cgroup is still populated after the worker was killed and reaped.
    #[error("cgroup {path} is still populated after teardown: {source}")]
    StillPopulated {
        /// The cgroup directory.
        path: PathBuf,
        /// The kernel's `rmdir` error.
        source: std::io::Error,
    },
}

/// The result of moving a child into its cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    /// The child is in the cgroup.
    Attached,
    /// The child no longer exists, so there was nothing to move.
    ///
    /// Not a confinement failure: the process that would have been limited is
    /// dead. The caller still removes the now-empty cgroup.
    ChildGone,
}

/// A cgroup directory owned by this process.
///
/// Dropping it attempts removal. [`Cgroup::remove`] does the same but reports
/// why it failed, which is what the pool uses on the paths where an operator
/// can still be told.
#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
    armed: bool,
}

/// A cgroup created with [`Cgroup::create`], removed on drop.
impl Cgroup {
    /// Discover a root, create a cgroup under it, and write `limits`.
    pub fn create(limits: CgroupLimits) -> Result<Cgroup, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            let root = discover()?;
            Cgroup::create_in(&root, &unique_name(), limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = limits;
            Err(CgroupError::UnsupportedPlatform)
        }
    }

    /// Create `name` under an already-discovered `root` and write `limits`.
    ///
    /// Controllers are enabled in `root` if they are not already, and every
    /// limit is read back. A limit that does not read back as written is a
    /// refusal: accepting it would mean announcing a budget the kernel did not
    /// install.
    pub fn create_in(
        root: &Path,
        name: &str,
        limits: CgroupLimits,
    ) -> Result<Cgroup, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            limits.validate()?;
            ensure_controllers(root)?;
            let path = root.join(name);
            std::fs::create_dir(&path).map_err(|source| CgroupError::Io {
                path: path.clone(),
                op: "mkdir",
                source,
            })?;
            let mut cgroup = Cgroup { path, armed: true };
            if let Err(e) = cgroup.write_limits(limits) {
                cgroup.armed = false;
                let _ = cgroup.remove_inner();
                return Err(e);
            }
            Ok(cgroup)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root, name, limits);
            Err(CgroupError::UnsupportedPlatform)
        }
    }

    /// The cgroup directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Move `pid` into this cgroup.
    ///
    /// `ESRCH` and `ENOENT` mean the child died before the move, which leaves an
    /// empty cgroup rather than an unconfined process; those are reported as
    /// [`Attachment::ChildGone`] and not as errors. Every other failure is.
    pub fn attach(&self, pid: i32) -> Result<Attachment, CgroupError> {
        #[cfg(target_os = "linux")]
        {
            let path = self.path.join("cgroup.procs");
            let data = format!("{pid}\n");
            match write_control(&path, &data) {
                Ok(()) => Ok(Attachment::Attached),
                Err(source)
                    if matches!(
                        source.raw_os_error(),
                        Some(libc::ESRCH) | Some(libc::ENOENT)
                    ) =>
                {
                    Ok(Attachment::ChildGone)
                }
                Err(source) => Err(CgroupError::Io {
                    path,
                    op: "write cgroup.procs",
                    source,
                }),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err(CgroupError::UnsupportedPlatform)
        }
    }

    /// Remove the cgroup, retrying briefly if it is still populated.
    ///
    /// Consumes the value so the caller cannot keep using a directory that no
    /// longer exists. The kernel releases a task from its cgroup slightly after
    /// `waitpid(2)` reaps it, so a first `rmdir` racing a just-killed worker can
    /// return `EBUSY`; that is what the retry is for.
    pub fn remove(mut self) -> Result<(), CgroupError> {
        self.armed = false;
        self.remove_inner()
    }

    #[cfg(target_os = "linux")]
    fn write_limits(&self, limits: CgroupLimits) -> Result<(), CgroupError> {
        self.write_limit("memory.max", &limits.memory_max.to_string())?;
        if let Some(swap) = limits.memory_swap_max {
            self.write_limit("memory.swap.max", &swap.to_string())?;
        }
        self.write_limit("pids.max", &limits.pids_max.to_string())?;
        self.write_limit("cpu.max", &limits.cpu_max.to_control_value())?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_limit(&self, file: &str, value: &str) -> Result<(), CgroupError> {
        let path = self.path.join(file);
        write_control(&path, value).map_err(|source| CgroupError::Io {
            path: path.clone(),
            op: "write limit",
            source,
        })?;
        // Read back rather than trusting a successful write. The kernel can
        // clamp a value, and a clamp the caller does not know about is a budget
        // different from the one that was asked for.
        let got = std::fs::read_to_string(&path).map_err(|source| CgroupError::Io {
            path: path.clone(),
            op: "read back limit",
            source,
        })?;
        if got.trim() != value {
            return Err(CgroupError::Io {
                path,
                op: "read back limit",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("wrote `{value}` but the kernel reports `{}`", got.trim()),
                ),
            });
        }
        Ok(())
    }

    fn remove_inner(&self) -> Result<(), CgroupError> {
        #[cfg(target_os = "linux")]
        {
            let mut last = None;
            for attempt in 0..REMOVE_ATTEMPTS {
                match std::fs::remove_dir(&self.path) {
                    Ok(()) => return Ok(()),
                    // Already gone is success: another teardown path, or the
                    // kernel's own cleanup, got there first.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(e) => {
                        let retryable = matches!(
                            e.raw_os_error(),
                            Some(libc::EBUSY) | Some(libc::ENOTEMPTY) | Some(libc::EAGAIN)
                        );
                        last = Some(e);
                        if !retryable || attempt + 1 == REMOVE_ATTEMPTS {
                            break;
                        }
                        std::thread::sleep(REMOVE_BACKOFF);
                    }
                }
            }
            let source = last.unwrap_or_else(|| {
                std::io::Error::other("rmdir failed without an error")
            });
            if source.raw_os_error() == Some(libc::EBUSY) {
                Err(CgroupError::StillPopulated {
                    path: self.path.clone(),
                    source,
                })
            } else {
                Err(CgroupError::Io {
                    path: self.path.clone(),
                    op: "rmdir",
                    source,
                })
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.armed {
            // Nothing can be reported from `Drop`. The pool calls `remove`
            // explicitly on every path where a caller can be told; this is the
            // backstop for the paths where a value is simply dropped.
            let _ = self.remove_inner();
        }
    }
}

/// Discover a usable delegated cgroup v2 root under `/sys/fs/cgroup`.
pub fn discover() -> Result<PathBuf, CgroupError> {
    #[cfg(target_os = "linux")]
    {
        discover_in(Path::new("/sys/fs/cgroup"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(CgroupError::UnsupportedPlatform)
    }
}

/// Discover a delegated cgroup root under a given cgroup v2 mount.
///
/// `sysfs_root` is normally `/sys/fs/cgroup`. It is a parameter so the discovery
/// algorithm can be tested against a directory that is not a cgroup mount, and
/// so a container that mounts cgroup2 elsewhere can be supported without
/// changing the code.
pub fn discover_in(sysfs_root: &Path) -> Result<PathBuf, CgroupError> {
    #[cfg(target_os = "linux")]
    {
        let mut tried: Vec<PathBuf> = Vec::new();
        let mut detail: Vec<String> = Vec::new();

        if let Some(relative) = self_cgroup_relative() {
            let candidate = sysfs_root.join(&relative);
            tried.push(candidate.clone());
            let usable = usable_root(&candidate)
                .and_then(|()| migration_source_writable(sysfs_root));
            match usable {
                Ok(()) => return Ok(candidate),
                Err(why) => detail.push(format!("{}: {why}", candidate.display())),
            }
        } else {
            detail.push(format!(
                "{} has no `0::` cgroup v2 entry",
                "/proc/self/cgroup"
            ));
        }

        let uid = unsafe { libc::geteuid() };
        let candidate = sysfs_root.join(format!(
            "user.slice/user-{uid}.slice/user@{uid}.service"
        ));
        tried.push(candidate.clone());
        let usable =
            usable_root(&candidate).and_then(|()| migration_source_writable(sysfs_root));
        match usable {
            Ok(()) => Ok(candidate),
            Err(why) => {
                detail.push(format!("{}: {why}", candidate.display()));
                Err(CgroupError::NoDelegatedRoot { tried, detail: detail.join("; ") })
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = sysfs_root;
        Err(CgroupError::UnsupportedPlatform)
    }
}

/// Check that an explicitly configured root is usable, without discovering one.
///
/// Used by [`crate::pool::PoolConfig::cgroup_root`]. Fails with the same
/// [`CgroupError::NoDelegatedRoot`] shape as discovery so a caller sees the path
/// it configured and the reason it was rejected.
pub fn validate_root(root: &Path) -> Result<PathBuf, CgroupError> {
    #[cfg(target_os = "linux")]
    {
        let sysfs_root =
            cgroup2_mount_for(root).unwrap_or_else(|| Path::new("/sys/fs/cgroup").to_path_buf());
        match usable_root(root).and_then(|()| migration_source_writable(&sysfs_root)) {
            Ok(()) => Ok(root.to_path_buf()),
            Err(why) => Err(CgroupError::NoDelegatedRoot {
                tried: vec![root.to_path_buf()],
                detail: format!("{}: {why}", root.display()),
            }),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(CgroupError::UnsupportedPlatform)
    }
}

/// The caller's own cgroup, relative to the cgroup mount, from
/// `/proc/self/cgroup`.
///
/// Only the cgroup v2 line (`0::/path`) is relevant. A v1 hierarchy line is
/// ignored rather than guessed at: interpreting it would produce a path that is
/// not a cgroup v2 directory and the first write would fail in a confusing way.
#[cfg(target_os = "linux")]
fn self_cgroup_relative() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("0::") else {
            continue;
        };
        let rest = rest.trim();
        if rest.is_empty() {
            continue;
        }
        return Some(PathBuf::from(rest.trim_start_matches('/')));
    }
    None
}

/// The cgroup2 mount whose tree contains `root`, from `/proc/self/mountinfo`.
///
/// Discovery itself is passed `/sys/fs/cgroup`, but an explicit root can live
/// under any cgroup2 mount. Reading the mount table rather than assuming the
/// conventional path keeps the "can this process migrate a child" check honest
/// inside a container that mounted cgroup2 somewhere else.
#[cfg(target_os = "linux")]
fn cgroup2_mount_for(root: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best: Option<PathBuf> = None;
    for line in text.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        if post.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let Some(mountpoint) = pre.split_whitespace().nth(4) else {
            continue;
        };
        if !root.starts_with(mountpoint) {
            continue;
        }
        let candidate = PathBuf::from(mountpoint);
        if best
            .as_ref()
            .is_none_or(|b| candidate.as_os_str().len() > b.as_os_str().len())
        {
            best = Some(candidate);
        }
    }
    best
}

/// Check that a child could be migrated out of the caller's own cgroup.
///
/// Creating a limit cgroup and writing its files can succeed while moving a
/// process into it is impossible: cgroup v2 migration requires write access to
/// the `cgroup.procs` of the cgroup the process is leaving as well as the one it
/// is entering. A process whose own cgroup is root-owned (a container without
/// delegation, or a shell outside the systemd user manager) can therefore
/// configure a cgroup it can never populate. Catching that at discovery turns a
/// confusing `EPERM` at first spawn into a refusal that names the reason.
#[cfg(target_os = "linux")]
fn migration_source_writable(sysfs_root: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;

    let Some(relative) = self_cgroup_relative() else {
        return Err("/proc/self/cgroup has no cgroup v2 entry, so the cgroup a child would \
                    be migrated out of is unknown"
            .to_string());
    };
    let procs = sysfs_root.join(&relative).join("cgroup.procs");
    let c = std::ffi::CString::new(procs.as_os_str().as_bytes())
        .map_err(|_| "path contains a NUL byte".to_string())?;
    // SAFETY: `c` is a NUL-terminated path and `access(2)` takes no other
    // pointer arguments.
    let rc = unsafe { libc::access(c.as_ptr(), libc::W_OK) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!(
            "this process's own cgroup `{}` is not writable ({e}), so a worker could not be \
             migrated into a limit cgroup; run the daemon under a delegated cgroup such as \
             `systemd-run --user --scope`",
            procs.display()
        ));
    }
    Ok(())
}

/// Why `dir` is or is not a usable parent for worker cgroups.
#[cfg(target_os = "linux")]
fn usable_root(dir: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;

    let controllers_path = dir.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path)
        .map_err(|e| format!("cannot read {}: {e}", controllers_path.display()))?;
    let offered: Vec<&str> = controllers.split_whitespace().collect();
    for needed in NEEDED_CONTROLLERS {
        if !offered.contains(&needed) {
            return Err(format!(
                "cgroup.controllers offers [{}], which does not include `{needed}`",
                offered.join(" ")
            ));
        }
    }

    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| "path contains a NUL byte".to_string())?;
    // SAFETY: `c` is a NUL-terminated path and `access(2)` takes no other
    // pointer arguments.
    let rc = unsafe { libc::access(c.as_ptr(), libc::W_OK) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!("not writable: {e}"));
    }
    Ok(())
}

/// Enable `cpu`, `memory` and `pids` in `root`'s `cgroup.subtree_control`.
///
/// A controller already enabled is left alone rather than rewritten. `EBUSY`
/// from the write is only tolerated if a re-read shows every controller present,
/// because the only benign cause is the "already enabled" race; a cgroup with
/// processes in it returns `EBUSY` and must not be treated as success.
#[cfg(target_os = "linux")]
fn ensure_controllers(root: &Path) -> Result<(), CgroupError> {
    let controllers_path = root.join("cgroup.controllers");
    let controllers = std::fs::read_to_string(&controllers_path).map_err(|source| {
        CgroupError::Io {
            path: controllers_path.clone(),
            op: "read cgroup.controllers",
            source,
        }
    })?;
    let offered: Vec<&str> = controllers.split_whitespace().collect();
    for needed in NEEDED_CONTROLLERS {
        if !offered.contains(&needed) {
            return Err(CgroupError::ControllerUnavailable {
                root: root.to_path_buf(),
                controller: needed,
                detail: format!("cgroup.controllers lists [{}]", offered.join(" ")),
            });
        }
    }

    let subtree_path = root.join("cgroup.subtree_control");
    let current = std::fs::read_to_string(&subtree_path).map_err(|source| CgroupError::Io {
        path: subtree_path.clone(),
        op: "read cgroup.subtree_control",
        source,
    })?;
    let enabled: Vec<&str> = current.split_whitespace().collect();
    let missing: Vec<&str> = NEEDED_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| !enabled.contains(c))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let request = missing
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    if let Err(source) = write_control(&subtree_path, &request) {
        // `EBUSY` is expected when another writer enabled the same controller
        // between the read and the write. Anything else, or an `EBUSY` that
        // did not result in the controllers being enabled, is a refusal.
        let now = std::fs::read_to_string(&subtree_path).unwrap_or_default();
        let now_enabled: Vec<&str> = now.split_whitespace().collect();
        let all_present = NEEDED_CONTROLLERS.iter().all(|c| now_enabled.contains(c));
        if !all_present {
            return Err(CgroupError::Io {
                path: subtree_path,
                op: "write cgroup.subtree_control",
                source,
            });
        }
    }

    let after = std::fs::read_to_string(&subtree_path).map_err(|source| CgroupError::Io {
        path: subtree_path.clone(),
        op: "read back cgroup.subtree_control",
        source,
    })?;
    let after: Vec<&str> = after.split_whitespace().collect();
    for needed in NEEDED_CONTROLLERS {
        if !after.contains(&needed) {
            return Err(CgroupError::ControllerUnavailable {
                root: root.to_path_buf(),
                controller: needed,
                detail: "the controller was requested but does not appear in \
                         cgroup.subtree_control afterwards"
                    .into(),
            });
        }
    }
    Ok(())
}

/// Write to a cgroup control file without `O_CREAT`/`O_TRUNC`.
///
/// `std::fs::write` opens with create and truncate, and cgroup pseudo-files do
/// not want either. `OpenOptions::write` is the shape the kernel documents:
/// open the existing file, write the value, close.
#[cfg(target_os = "linux")]
fn write_control(path: &Path, data: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(data.as_bytes())
}

/// A name unique within this process and unlikely to collide across processes.
#[cfg(target_os = "linux")]
fn unique_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "agentos-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Render a path list for an error message.
fn display_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "nothing (no candidates)".to_string();
    }
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_explicit_and_non_zero() {
        let l = CgroupLimits::default();
        assert!(l.memory_max > 0);
        assert!(l.pids_max > 0);
        assert!(l.cpu_max.quota_micros > 0);
        assert!(l.cpu_max.period_micros > 0);
        // Swap defaults to zero so memory.max is a ceiling, not a hint.
        assert_eq!(l.memory_swap_max, Some(0));
    }

    #[test]
    fn zero_limits_are_refused_before_anything_is_created() {
        assert!(matches!(
            CgroupLimits::new(0, 8, CpuMax::default()).validate(),
            Err(CgroupError::InvalidLimits(_))
        ));
        assert!(matches!(
            CgroupLimits::new(1024, 0, CpuMax::default()).validate(),
            Err(CgroupError::InvalidLimits(_))
        ));
        assert!(matches!(
            CgroupLimits::new(1024, 8, CpuMax::new(0, 1000)).validate(),
            Err(CgroupError::InvalidLimits(_))
        ));
        assert!(matches!(
            CgroupLimits::new(1024, 8, CpuMax::new(1, 0)).validate(),
            Err(CgroupError::InvalidLimits(_))
        ));
        assert!(CgroupLimits::default().validate().is_ok());
    }

    #[test]
    fn cpu_max_renders_the_kernel_format() {
        assert_eq!(
            CpuMax::new(50_000, 100_000).to_control_value(),
            "50000 100000"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_bad_root_error_names_every_path_it_tried() {
        // A path that cannot be a cgroup mount. The error must not be a bare
        // "not supported": an operator needs to know what was consulted.
        let err = discover_in(Path::new("/agentos/not/a/cgroup/mount"))
            .expect_err("a nonexistent root cannot be usable");
        match err {
            CgroupError::NoDelegatedRoot { tried, detail } => {
                assert!(!tried.is_empty(), "no candidate paths were reported");
                assert!(!detail.is_empty(), "no reasons were reported");
                assert!(
                    tried
                        .iter()
                        .all(|p| p.starts_with("/agentos/not/a/cgroup/mount")),
                    "candidates should be under the root that was passed: {tried:?}"
                );
            }
            other => panic!("expected NoDelegatedRoot, got {other}"),
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn discovery_refuses_rather_than_pretending_on_a_non_linux_host() {
        assert!(matches!(
            discover_in(Path::new("/agentos/not/a/cgroup/mount")),
            Err(CgroupError::UnsupportedPlatform)
        ));
        assert!(matches!(
            Cgroup::create(CgroupLimits::default()),
            Err(CgroupError::UnsupportedPlatform)
        ));
    }
}
