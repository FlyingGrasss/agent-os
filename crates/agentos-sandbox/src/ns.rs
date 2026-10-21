//! User and mount namespaces for confined workers.
//!
//! # What this buys, given Landlock and seccomp already exist
//!
//! Landlock is path-based and denies by default, so a worker cannot open a path
//! it was not granted. That leaves three things a shared mount namespace still
//! exposes:
//!
//! - **`/tmp` is shared with the daemon and every other local process.** A
//!   worker granted write access to one scratch directory can still observe the
//!   *names* in a shared `/tmp`, and anything another process leaves there with
//!   permissive modes is reachable if a grant happens to cover it. More
//!   importantly, a tool whose scratch directory is `/tmp` is trusting a
//!   directory that every other process on the host can write.
//! - **Mounts are global state.** A worker that could mount something would
//!   change what every path means for every process. seccomp denies `mount(2)`,
//!   but that is a second layer, not the property.
//! - **The uid is the host uid.** A worker runs as the daemon's user and can
//!   therefore signal, `ptrace`, or open `/proc/<pid>` for any other process of
//!   that user unless seccomp and Landlock happen to close each route.
//!
//! A private user and mount namespace closes all three at once:
//!
//! 1. `unshare(CLONE_NEWUSER)` with a single mapping (`0 <euid> 1`) makes the
//!    worker uid 0 *inside* a namespace that owns nothing on the host. It has
//!    capabilities there and none outside; every host resource it reaches is
//!    still checked against the mapped uid, which is the daemon's uid.
//! 2. `unshare(CLONE_NEWNS)` plus `mount(MS_REC | MS_PRIVATE)` on `/` gives the
//!    worker a private copy of the mount table, so anything it does to mounts is
//!    invisible to every other process.
//! 3. A fresh tmpfs on `/tmp`, bounded and mounted `nosuid,nodev,noexec`, gives
//!    the worker a scratch directory whose contents are its own. A marker the
//!    host wrote to `/tmp` before the spawn does not exist inside; a file the
//!    worker writes inside does not exist outside.
//!
//! # Ordering
//!
//! Namespaces are applied **before** Landlock, and this is load-bearing rather
//! than stylistic. Landlock rules are built from paths, and a mount namespace
//! changes what a path means. Applying Landlock first would install rules
//! against the host's `/tmp` inode and then mount a different filesystem over
//! it, producing a ruleset that grants access to something the worker can no
//! longer see and denies access to the tmpfs the worker is supposed to use.
//! Applying namespaces first means the rules describe the tree the worker will
//! actually run in.
//!
//! seccomp is applied last, after both, because it is the layer that makes the
//! namespace state durable: `mount(2)` and `unshare(2)` are not in any allowlist
//! this crate installs, so once the filter is in place the worker cannot undo or
//! widen what the namespaces established.
//!
//! # No PID namespace
//!
//! `CLONE_NEWPID` is deliberately **not** used. A PID namespace only takes
//! effect for children created after the `unshare`, so the worker would need a
//! second fork after the namespace call, which changes the process the pool
//! tracks, the pid it reports, and the signal target for teardown. Half-doing
//! that - calling `unshare(CLONE_NEWPID)` and leaving the worker in its parent's
//! PID namespace, which is what actually happens without the second fork - is a
//! no-op that looks like isolation. It is absent rather than wrong. The
//! observable consequence is that a worker inside this namespace still sees host
//! pids in `/proc`, which Landlock and seccomp already deny it a path to.
//!
//! # Fail closed
//!
//! Every step returns an error rather than continuing, and the pool refuses to
//! exec the worker when one does. There is no "namespaces were unavailable, so
//! run it shared" path: a caller that asked for isolation and silently did not
//! get it would be the exact failure this crate is written to prevent.

use thiserror::Error;

/// Default size of the private `/tmp`: 64 MiB.
///
/// Bounded because the tmpfs is charged to the worker's cgroup: an unbounded
/// tmpfs would let a tool convert a memory limit into a disk-shaped one, and
/// the cgroup limit would kill the worker before the tmpfs filled.
pub const DEFAULT_TMPFS_BYTES: u64 = 64 * 1024 * 1024;

/// Mode for the private `/tmp` root.
#[cfg(target_os = "linux")]
const TMPFS_MODE: u32 = 0o1777;

/// Which namespaces a worker is placed in.
///
/// Set with [`crate::pool::PoolConfig::namespaces`]. The default is [`Namespaces::None`],
/// not because isolation is optional in principle but because the mount
/// namespace replaces `/tmp`, and a pool whose Landlock grants point *into* the
/// host `/tmp` would find those grants invalid after the mount. That is a real
/// conflict rather than a preference: enabling isolation for such a caller has to
/// be a decision, and a silent default that invalidated the caller's grants
/// would fail closed in a confusing place. A caller with grants outside `/tmp`
/// loses nothing by enabling it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Namespaces {
    /// Share the host's user namespace, mount namespace and `/tmp`.
    #[default]
    None,

    /// A private user namespace, a private mount tree, and a bounded tmpfs on
    /// `/tmp`.
    UserAndMount {
        /// Size of the private tmpfs in bytes.
        tmpfs_bytes: u64,
    },
}

impl Namespaces {
    /// Private user and mount namespaces with the default tmpfs size.
    pub const fn user_and_mount() -> Self {
        Namespaces::UserAndMount {
            tmpfs_bytes: DEFAULT_TMPFS_BYTES,
        }
    }

    /// Set the private tmpfs size, keeping the policy.
    ///
    /// A size of zero is rejected when the namespaces are applied.
    pub const fn with_tmpfs_bytes(self, bytes: u64) -> Self {
        match self {
            Namespaces::UserAndMount { .. } => Namespaces::UserAndMount {
                tmpfs_bytes: bytes,
            },
            Namespaces::None => Namespaces::None,
        }
    }

    /// Whether any namespace work will be done.
    pub const fn is_enabled(self) -> bool {
        matches!(self, Namespaces::UserAndMount { .. })
    }
}

/// Why namespace isolation could not be established.
///
/// Every variant is a refusal. The pool turns one into a worker startup refusal,
/// so a requested namespace that could not be created never produces a running
/// worker.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NamespaceError {
    /// Namespaces are a Linux interface.
    #[error("user and mount namespaces are only implemented on linux")]
    UnsupportedPlatform,

    /// The requested tmpfs size is not usable.
    #[error("invalid namespace configuration: {0}")]
    BadConfig(String),

    /// `unshare(2)` failed.
    #[error("unshare({what}) failed: {source}")]
    Unshare {
        /// The namespace flags, by name.
        what: &'static str,
        /// The kernel's error. `EPERM` here usually means unprivileged user
        /// namespaces are disabled by the host.
        source: std::io::Error,
    },

    /// A `/proc/self/*_map` or `/proc/self/setgroups` write failed.
    #[error("writing {path} failed: {source}")]
    IdMap {
        /// The proc file involved.
        path: &'static str,
        /// The kernel's error.
        source: std::io::Error,
    },

    /// The uid map was written but the process is not uid 0 inside the
    /// namespace, so the mount calls below would fail with an unrelated error.
    #[error("after writing the uid map the process is uid {0} inside the namespace, expected 0")]
    MappingDidNotTake(u32),

    /// Changing the working directory failed.
    #[error("chdir({path}) failed: {source}")]
    Chdir {
        /// The directory.
        path: &'static str,
        /// The kernel's error.
        source: std::io::Error,
    },

    /// A mount call failed.
    #[error("mount({what}) on {target} failed: {source}")]
    Mount {
        /// What was being mounted.
        what: &'static str,
        /// Where it was being mounted.
        target: &'static str,
        /// The kernel's error.
        source: std::io::Error,
    },

    /// The private tmpfs mount point could not be created.
    #[error("could not create the tmpfs mount point {path}: {source}")]
    MountPoint {
        /// The mount point.
        path: &'static str,
        /// The kernel's error.
        source: std::io::Error,
    },
}

/// Apply the requested namespace isolation to the calling process.
///
/// Irreversible, and it changes the process, not just the calling thread. It is
/// called in the forked child between `fork(2)` and `execveat(2)`, where the
/// process is single-threaded and nothing else can observe the change.
///
/// [`Namespaces::None`] is a no-op that returns `Ok(())`.
pub fn apply(namespaces: Namespaces) -> Result<(), NamespaceError> {
    match namespaces {
        Namespaces::None => Ok(()),
        Namespaces::UserAndMount { tmpfs_bytes } => {
            #[cfg(target_os = "linux")]
            {
                apply_user_and_mount(tmpfs_bytes)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = tmpfs_bytes;
                Err(NamespaceError::UnsupportedPlatform)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_user_and_mount(tmpfs_bytes: u64) -> Result<(), NamespaceError> {
    use std::ffi::CString;

    use rustix::mount::{mount, mount_change, MountFlags, MountPropagationFlags};
    use rustix::thread::{unshare_unsafe, UnshareFlags};

    if tmpfs_bytes == 0 {
        return Err(NamespaceError::BadConfig(
            "a zero-sized tmpfs would leave the worker without /tmp".into(),
        ));
    }

    // Captured before the unshare: after it, geteuid() is 0 in the new
    // namespace, and mapping 0 to 0 would map nobody.
    // SAFETY: geteuid and getegid take no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: as above.
    let egid = unsafe { libc::getegid() };

    // 1. A user namespace, so the mappings below are permitted without host
    //    privilege. The worker becomes uid 0 inside a namespace that is mapped
    //    to exactly the one host uid it already had.
    //
    // SAFETY: this runs in the forked child before `execveat`, where the process
    // is single-threaded and no other thread can observe a descriptor table
    // change. The crate never calls this on a live multi-threaded process.
    unsafe { unshare_unsafe(UnshareFlags::NEWUSER) }.map_err(|source| {
        NamespaceError::Unshare {
            what: "CLONE_NEWUSER",
            source: source.into(),
        }
    })?;

    // 2. `setgroups` must be denied before a gid map can be written by an
    //    unprivileged process, or the kernel refuses the gid map with EPERM.
    //    Absent on kernels without the file; not an error there.
    match std::fs::write("/proc/self/setgroups", b"deny") {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(NamespaceError::IdMap {
                path: "/proc/self/setgroups",
                source,
            })
        }
    }

    std::fs::write("/proc/self/uid_map", format!("0 {euid} 1\n")).map_err(|source| {
        NamespaceError::IdMap {
            path: "/proc/self/uid_map",
            source,
        }
    })?;
    std::fs::write("/proc/self/gid_map", format!("0 {egid} 1\n")).map_err(|source| {
        NamespaceError::IdMap {
            path: "/proc/self/gid_map",
            source,
        }
    })?;

    // Check rather than assume: if the map did not take, the mount namespace
    // call below fails with EPERM and the operator would be told the wrong
    // thing.
    // SAFETY: geteuid takes no arguments.
    let inside = unsafe { libc::geteuid() };
    if inside != 0 {
        return Err(NamespaceError::MappingDidNotTake(inside));
    }

    // 3. A private mount tree.
    //
    // SAFETY: as above; it is still the single-threaded forked child.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.map_err(|source| {
        NamespaceError::Unshare {
            what: "CLONE_NEWNS",
            source: source.into(),
        }
    })?;

    // Make every mount private, recursively. Without `MS_REC` the child of a
    // shared mount is still shared, and a mount the worker makes here would
    // propagate to the host.
    mount_change(c"/", MountPropagationFlags::REC | MountPropagationFlags::PRIVATE).map_err(
        |source| NamespaceError::Mount {
            what: "MS_REC|MS_PRIVATE",
            target: "/",
            source: source.into(),
        },
    )?;

    // Leave any working directory that is inside the tree about to be replaced.
    // A process whose cwd is `/tmp` keeps a reference to the *old* mount even
    // after a new filesystem is mounted over it, which would hand the worker a
    // path to the host's `/tmp` that no later `chdir` undoes on its behalf.
    std::env::set_current_dir("/").map_err(|source| NamespaceError::Chdir {
        path: "/",
        source,
    })?;

    // 4. A fresh tmpfs on /tmp. `nosuid,nodev,noexec`: the scratch space holds
    //    data, not programs and not device nodes, and the worker already has a
    //    Landlock profile for anything it does want to execute.
    if let Err(source) = std::fs::create_dir("/tmp") {
        if source.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(NamespaceError::MountPoint {
                path: "/tmp",
                source,
            });
        }
    }
    let data = CString::new(format!(
        "size={tmpfs_bytes},mode={TMPFS_MODE:o}"
    ))
    .expect("a size and mode contain no NUL");
    mount(
        c"tmpfs",
        c"/tmp",
        c"tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        data.as_c_str(),
    )
    .map_err(|source| NamespaceError::Mount {
        what: "tmpfs",
        target: "/tmp",
        source: source.into(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_no_namespace_work() {
        assert_eq!(Namespaces::default(), Namespaces::None);
        assert!(!Namespaces::default().is_enabled());
        // And it is a no-op that succeeds, so a caller that never asked for
        // namespaces is not made to care about them.
        assert!(apply(Namespaces::None).is_ok());
    }

    #[test]
    fn builder_keeps_the_policy_and_sets_the_size() {
        let n = Namespaces::user_and_mount().with_tmpfs_bytes(8 * 1024 * 1024);
        assert!(n.is_enabled());
        assert_eq!(
            n,
            Namespaces::UserAndMount {
                tmpfs_bytes: 8 * 1024 * 1024
            }
        );
        // Setting a size on `None` does not silently enable isolation.
        assert_eq!(
            Namespaces::None.with_tmpfs_bytes(1),
            Namespaces::None
        );
    }
}
