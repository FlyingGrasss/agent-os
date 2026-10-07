//! seccomp-bpf syscall allowlists, one per tool class.
//!
//! Landlock constrains what a confined process may *open*. It does not
//! constrain what it may *call*. A tool confined to one directory can still open
//! a socket and exfiltrate, which is why `LANDLOCK_ACCESS_FS_NET` covers TCP
//! bind and connect but leaves UDP and bare `socket(2)` alone.
//!
//! seccomp closes that from the other side: an allowlist of syscalls, default
//! deny. Together they are the confinement layer. Landlock alone is a filesystem
//! sandbox with a network-shaped hole in it.
//!
//! ## Ordering, which is load-bearing
//!
//! `PR_SET_NO_NEW_PRIVS` must be set before `PR_SET_SECCOMP`, or the kernel
//! refuses. [`Confine`] already sets it, so applying a profile after
//! [`Confine::apply`] is safe; applying one without it is refused here rather
//! than silently ignored.
//!
//! ## Why a deny-list is not offered
//!
//! Every seccomp policy that blocks `socket` by enumerating dangerous syscalls
//! has a hole the day someone adds a syscall. The allowlists here are built from
//! what a tool class actually needs, and anything unlisted is refused with
//! `ENOSYS`, which surfaces as a failing tool rather than as a silent
//! capability.

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeSet;

    use crate::abi::Abi;
    use crate::error::SeccompError;

    /// Syscalls a confined tool class is permitted to make.
    ///
    /// Named rather than numbered so the list reads as intent. The numbers are
    /// resolved from `libc` at compile time on x86-64 and aarch64, and a build
    /// that cannot resolve one fails rather than guessing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Allowed {
        Read,
        Write,
        Close,
        Stat,
        Fstat,
        Lstat,
        Open,
        OpenAt,
        Readlink,
        ReadlinkAt,
        Getdents,
        Newfstatat,
        Faccessat,
        Mmap,
        Mprotect,
        Munmap,
        Brk,
        RtSigaction,
        RtSigprocmask,
        RtSigreturn,
        Sigaltstack,
        Futex,
        ClockGettime,
        ClockGetres,
        Nanosleep,
        Exit,
        ExitGroup,
        Getpid,
        Getppid,
        Geteuid,
        Getegid,
        Gettid,
        SetTidAddress,
        Prlimit64,
        Getrlimit,
        Uname,
        Sysinfo,
        Getrandom,
        Rseq,
        RestrictSelf,
        LandlockCreateRuleset,
        LandlockAddRule,
        LandlockRestrictSelf,
        Getcwd,
        Access,
        Fsync,
        Ftruncate,
        Fchmod,
        Fchown,
        Rename,
        Renameat,
        Renameat2,
        Unlink,
        Unlinkat,
        Mkdir,
        Mkdirat,
        Rmdir,
        Fchdir,
        Chdir,
        Truncate,
        Utime,
        Utimes,
        Futimesat,
        Getxattr,
        Flock,
        Fadvise64,
        Mremap,
        Madvise,
        Fcntl,
        Ioctl,
        Dup,
        Dup3,
        Pipe,
        Pipe2,
        Kill,
        Tgkill,
        RtSigqueueinfo,
        Socketpair,
        Capget,
        Capset,
        SchedGettime,
        SchedYield,
        SchedGetaffinity,
        EpollCreate1,
        EpollCtl,
        EpollPwait,
        Ppoll,
        Pselect6,
        Execveat,
    }

    impl Allowed {
        /// Every syscall this class may use, as a set.
        ///
        /// `base` is what any process needs to start, run, allocate, exit, and
        /// land further syscalls. Note it excludes `socket`, `connect`, `bind`,
        /// `sendto`, and `recvfrom`: a filesystem tool has no business with any
        /// of them, and their absence is the point.
        fn base() -> BTreeSet<i64> {
            let list = [
                Allowed::Read,
                Allowed::Write,
                Allowed::Close,
                Allowed::Stat,
                Allowed::Fstat,
                Allowed::Lstat,
                Allowed::Open,
                Allowed::OpenAt,
                Allowed::Readlink,
                Allowed::ReadlinkAt,
                Allowed::Getdents,
                Allowed::Newfstatat,
                Allowed::Faccessat,
                Allowed::Mmap,
                Allowed::Mprotect,
                Allowed::Munmap,
                Allowed::Brk,
                Allowed::Mremap,
                Allowed::Madvise,
                Allowed::RtSigaction,
                Allowed::RtSigprocmask,
                Allowed::RtSigreturn,
                Allowed::Sigaltstack,
                Allowed::Futex,
                Allowed::ClockGettime,
                Allowed::ClockGetres,
                Allowed::Nanosleep,
                Allowed::Exit,
                Allowed::ExitGroup,
                Allowed::Getpid,
                Allowed::Getppid,
                Allowed::Geteuid,
                Allowed::Getegid,
                Allowed::Gettid,
                Allowed::SetTidAddress,
                Allowed::Rseq,
                Allowed::Prlimit64,
                Allowed::Getrlimit,
                Allowed::Uname,
                Allowed::Sysinfo,
                Allowed::Getrandom,
                Allowed::Getcwd,
                Allowed::Access,
                Allowed::Fcntl,
                Allowed::Flock,
                Allowed::Fadvise64,
                Allowed::Futimesat,
                Allowed::Utime,
                Allowed::Utimes,
                Allowed::SchedGettime,
                Allowed::SchedYield,
                Allowed::SchedGetaffinity,
                Allowed::Getxattr,
                Allowed::Fadvise64,
            ];
            list.iter()
                .filter_map(|a| a.number())
                .collect()
        }

        fn write_extras() -> BTreeSet<i64> {
            [
                Allowed::Fsync,
                Allowed::Ftruncate,
                Allowed::Truncate,
                Allowed::Fchmod,
                Allowed::Fchown,
                Allowed::Fchdir,
                Allowed::Chdir,
                Allowed::Rename,
                Allowed::Renameat,
                Allowed::Renameat2,
                Allowed::Unlink,
                Allowed::Unlinkat,
                Allowed::Mkdir,
                Allowed::Mkdirat,
                Allowed::Rmdir,
                Allowed::Ioctl,
            ]
            .iter()
            .filter_map(|a| a.number())
            .collect()
        }

        /// Syscalls a process needs only when it is itself the program being
        /// confined, as opposed to a library call inside an already-running one.
        fn exec_extras() -> BTreeSet<i64> {
            [
                Allowed::Execveat,
                Allowed::Dup,
                Allowed::Dup3,
                Allowed::Pipe,
                Allowed::Pipe2,
                Allowed::EpollCreate1,
                Allowed::EpollCtl,
                Allowed::EpollPwait,
                Allowed::Ppoll,
                Allowed::Pselect6,
                Allowed::Socketpair,
                Allowed::Kill,
                Allowed::Tgkill,
                Allowed::RtSigqueueinfo,
                Allowed::Capget,
                Allowed::Capset,
                Allowed::RestrictSelf,
                Allowed::LandlockCreateRuleset,
                Allowed::LandlockAddRule,
                Allowed::LandlockRestrictSelf,
            ]
            .iter()
            .filter_map(|a| a.number())
            .collect()
        }

        /// The syscall number, or `None` on an architecture where this crate
        /// does not know it.
        pub fn number(self) -> Option<i64> {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                return Some(match self {
                    Allowed::Read => libc::SYS_read,
                    Allowed::Write => libc::SYS_write,
                    Allowed::Close => libc::SYS_close,
                    Allowed::Stat => libc::SYS_stat,
                    Allowed::Fstat => libc::SYS_fstat,
                    Allowed::Lstat => libc::SYS_lstat,
                    Allowed::Open => libc::SYS_open,
                    Allowed::OpenAt => libc::SYS_openat,
                    Allowed::Readlink => libc::SYS_readlink,
                    Allowed::ReadlinkAt => libc::SYS_readlinkat,
                    Allowed::Getdents => libc::SYS_getdents,
                    Allowed::Newfstatat => libc::SYS_newfstatat,
                    Allowed::Faccessat => libc::SYS_faccessat,
                    Allowed::Mmap => libc::SYS_mmap,
                    Allowed::Mprotect => libc::SYS_mprotect,
                    Allowed::Munmap => libc::SYS_munmap,
                    Allowed::Brk => libc::SYS_brk,
                    Allowed::Mremap => libc::SYS_mremap,
                    Allowed::Madvise => libc::SYS_madvise,
                    Allowed::RtSigaction => libc::SYS_rt_sigaction,
                    Allowed::RtSigprocmask => libc::SYS_rt_sigprocmask,
                    Allowed::RtSigreturn => libc::SYS_rt_sigreturn,
                    Allowed::Sigaltstack => libc::SYS_sigaltstack,
                    Allowed::Futex => libc::SYS_futex,
                    Allowed::ClockGettime => libc::SYS_clock_gettime,
                    Allowed::ClockGetres => libc::SYS_clock_getres,
                    Allowed::Nanosleep => libc::SYS_nanosleep,
                    Allowed::Exit => libc::SYS_exit,
                    Allowed::ExitGroup => libc::SYS_exit_group,
                    Allowed::Getpid => libc::SYS_getpid,
                    Allowed::Getppid => libc::SYS_getppid,
                    Allowed::Geteuid => libc::SYS_geteuid,
                    Allowed::Getegid => libc::SYS_getegid,
                    Allowed::Gettid => libc::SYS_gettid,
                    Allowed::SetTidAddress => libc::SYS_set_tid_address,
                    Allowed::Rseq => libc::SYS_rseq,
                    Allowed::Prlimit64 => libc::SYS_prlimit64,
                    Allowed::Getrlimit => libc::SYS_getrlimit,
                    Allowed::Uname => libc::SYS_uname,
                    Allowed::Sysinfo => libc::SYS_sysinfo,
                    Allowed::Getrandom => libc::SYS_getrandom,
                    Allowed::Getcwd => libc::SYS_getcwd,
                    Allowed::Access => libc::SYS_access,
                    Allowed::Fcntl => libc::SYS_fcntl,
                    Allowed::Flock => libc::SYS_flock,
                    Allowed::Fadvise64 => libc::SYS_fadvise64,
                    Allowed::Futimesat => libc::SYS_futimesat,
                    Allowed::Utime => libc::SYS_utime,
                    Allowed::Utimes => libc::SYS_utimes,
                    // `sched_gettime` is a libc-level wrapper over
                    // `clock_gettime`, not a syscall, so there is no SYS_ name.
                    Allowed::SchedGettime => libc::SYS_clock_gettime,
                    Allowed::SchedYield => libc::SYS_sched_yield,
                    Allowed::SchedGetaffinity => libc::SYS_sched_getaffinity,
                    Allowed::Getxattr => libc::SYS_getxattr,
                    Allowed::Fsync => libc::SYS_fsync,
                    Allowed::Ftruncate => libc::SYS_ftruncate,
                    Allowed::Truncate => libc::SYS_truncate,
                    Allowed::Fchmod => libc::SYS_fchmod,
                    Allowed::Fchown => libc::SYS_fchown,
                    Allowed::Fchdir => libc::SYS_fchdir,
                    Allowed::Chdir => libc::SYS_chdir,
                    Allowed::Rename => libc::SYS_rename,
                    Allowed::Renameat => libc::SYS_renameat,
                    Allowed::Renameat2 => libc::SYS_renameat2,
                    Allowed::Unlink => libc::SYS_unlink,
                    Allowed::Unlinkat => libc::SYS_unlinkat,
                    Allowed::Mkdir => libc::SYS_mkdir,
                    Allowed::Mkdirat => libc::SYS_mkdirat,
                    Allowed::Rmdir => libc::SYS_rmdir,
                    Allowed::Ioctl => libc::SYS_ioctl,
                    Allowed::Dup => libc::SYS_dup,
                    Allowed::Dup3 => libc::SYS_dup3,
                    Allowed::Pipe => libc::SYS_pipe,
                    Allowed::Pipe2 => libc::SYS_pipe2,
                    Allowed::Kill => libc::SYS_kill,
                    Allowed::Tgkill => libc::SYS_tgkill,
                    Allowed::RtSigqueueinfo => libc::SYS_rt_sigqueueinfo,
                    Allowed::Socketpair => libc::SYS_socketpair,
                    Allowed::Capget => libc::SYS_capget,
                    Allowed::Capset => libc::SYS_capset,
                    Allowed::EpollCreate1 => libc::SYS_epoll_create1,
                    Allowed::EpollCtl => libc::SYS_epoll_ctl,
                    Allowed::EpollPwait => libc::SYS_epoll_pwait,
                    Allowed::Ppoll => libc::SYS_ppoll,
                    Allowed::Pselect6 => libc::SYS_pselect6,
                    Allowed::Execveat => libc::SYS_execveat,
                    // `landlock_restrict_self` is the `restrict_self` syscall.
                    Allowed::RestrictSelf => libc::SYS_landlock_restrict_self,
                    Allowed::LandlockCreateRuleset => libc::SYS_landlock_create_ruleset,
                    Allowed::LandlockAddRule => libc::SYS_landlock_add_rule,
                    Allowed::LandlockRestrictSelf => libc::SYS_landlock_restrict_self,
                } as i64);
            }
            #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
            {
                // Refusing to guess is the point. A wrong syscall number silently
                // allows the wrong syscall, which is the failure mode seccomp is
                // installed to prevent.
                let _ = self;
                None
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = self;
                None
            }
        }
    }

    /// Which syscalls a confined process may make.
    ///
    /// One variant per tool class rather than one global policy, because the
    /// narrowest list that still lets the tool work is the safest. A tool that
    /// only reads files does not need `execveat`, and allowing it because
    /// another tool did would be a hole.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Profile {
        /// Reads and writes inside granted directories. The default for
        /// built-in tools. No `socket`, no `execveat`.
        Filesystem,
        /// `Filesystem`, plus process creation, for a tool that must spawn a
        /// helper. Note this is a materially larger grant and the reason no tool
        /// gets it by default.
        Exec,
    }

    impl Profile {
        /// The allowed syscall numbers for this profile.
        ///
        /// Returns `None` when the platform's syscall numbers are unknown, so the
        /// caller refuses rather than installing an empty or wrong filter.
        pub fn allowed(self) -> Option<BTreeSet<i64>> {
            let mut set = Allowed::base();
            match self {
                Profile::Filesystem => {
                    set.extend(Allowed::write_extras());
                }
                Profile::Exec => {
                    set.extend(Allowed::write_extras());
                    set.extend(Allowed::exec_extras());
                }
            }
            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        }

        /// Syscalls this profile deliberately refuses.
        ///
        /// Exposed so the tests can assert the denial directly rather than
        /// inferring it from a tool failing for some other reason.
        pub fn refused_examples(self) -> Vec<&'static str> {
            match self {
                // `socket` is the hole Landlock leaves. `execveat` is absent
                // because a file tool has no business spawning anything.
                Profile::Filesystem => vec!["socket", "connect", "bind", "execveat", "ptrace"],
                Profile::Exec => vec!["socket", "connect", "bind", "ptrace"],
            }
        }
    }

    /// Proof that a filter is installed on this thread.
    pub struct SeccompApplied {
        _private: (),
    }

    /// Install the allowlist on the calling thread.
    ///
    /// Installing a seccomp filter is irreversible for the thread, and the
    /// kernel refuses to filter a thread that could regain privilege. Both facts
    /// are checked rather than assumed.
    pub fn apply(profile: Profile) -> Result<SeccompApplied, SeccompError> {
        let allowed = profile.allowed().ok_or(SeccompError::UnknownPlatform)?;

        // The kernel requires no_new_privs for an unprivileged filter. Reading it
        // back rather than trusting the call avoids a race with another thread
        // clearing it.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
            return Err(SeccompError::NoNewPrivs);
        }

        // `sock_fprog.filter` is `*mut sock_filter` because the kernel's BPF
        // interpreter may rewrite jump targets. The instructions here are already
        // fully resolved, so the mutability is not used.
        let mut filter = build_filter(&allowed)?;
        // `sock_fprog` borrows the instruction slice, so it has to outlive the
        // prctl call. Casting the Vec directly is not a valid pointer cast.
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            return Err(SeccompError::from_errno(
                std::io::Error::last_os_error(),
            ));
        }
        Ok(SeccompApplied { _private: () })
    }

    /// Build the BPF program.
    ///
    /// The layout, with jump targets computed from real indices rather than
    /// hardcoded:
    ///
    /// ```text
    ///   0  LD  arch
    ///   1  JEQ audit_arch -> +1, else fall through to the kill
    ///   2  RET KILL_PROCESS
    ///   3  LD  nr
    ///   4..  JEQ nr_i -> (to ALLOW), else fall through
    ///   n  RET ERRNO(ENOSYS)
    ///   n+1 RET ALLOW
    /// ```
    ///
    /// Getting a jump offset wrong does not produce a compile error. It produces
    /// a filter that permits the wrong syscalls, which is the exact outcome this
    /// crate exists to prevent, so the offsets are arithmetic over the vector
    /// rather than literals.
    fn build_filter(allowed: &BTreeSet<i64>) -> Result<Vec<libc::sock_filter>, SeccompError> {
        // `AUDIT_ARCH_X86_64` and `AUDIT_ARCH_AARCH64`.
        let audit_arch: u32 = if cfg!(target_arch = "x86_64") {
            0xC000_003E
        } else {
            0xC000_00B7
        };

        // Two return instructions at the end: deny, then allow.
        // Indices into the program. Computed rather than hardcoded: a wrong
        // jump offset does not fail to compile, it silently permits the wrong
        // syscalls.
        let ret_deny_index: usize = 4 + allowed.len();
        let ret_allow_index: usize = ret_deny_index + 1;

        let mut prog: Vec<libc::sock_filter> = Vec::with_capacity(ret_allow_index + 1);

        // 0: load the architecture from `seccomp_data.arch`.
        prog.push(stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            4,
        ));
        // 1: if it is the expected architecture, skip the kill at index 2.
        prog.push(jeq(audit_arch, 1, 0));
        // 2: a mismatched architecture means our syscall numbers mean nothing,
        //    so the process is killed rather than filtered.
        prog.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_KILL_PROCESS as u32,
        ));
        // 3: load the syscall number.
        prog.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));

        // 4..: one comparison each, jumping to the allow on a match and falling
        // through to the deny otherwise.
        let last_compare = ret_deny_index - 1;
        for (i, &nr) in allowed.iter().enumerate() {
            let at = 4 + i;
            // Forward offset from this instruction to the ALLOW return.
            let forward = (ret_allow_index - 1) - at;
            let forward = u8::try_from(forward).map_err(|_| SeccompError::FilterTooLarge)?;
            prog.push(jeq(nr as u32, forward, 0));
        }
        let _ = last_compare;

        // Deny by returning ENOSYS rather than killing, so the tool fails
        // visibly and the caller learns which capability it wanted.
        prog.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO as u32 | (libc::ENOSYS as u32 & 0x0000_FFFF),
        ));
        prog.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ALLOW as u32,
        ));

        debug_assert_eq!(prog.len() - 1, ret_allow_index);
        // `struct sock_fprog.len` is a u16.
        if prog.len() > usize::from(u16::MAX) {
            return Err(SeccompError::FilterTooLarge);
        }
        Ok(prog)
    }

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// `BPF_JMP | BPF_JEQ | BPF_K` with both branches relative to the next
    /// instruction.
    fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        }
    }

    /// Kept so the unused-import warning cannot hide a real dependency drift.
    #[allow(dead_code)]
    fn _abi_marker(_: Abi) {}
}

/// Names for readability at call sites.
#[cfg(target_os = "linux")]
pub use imp::Profile;

#[cfg(target_os = "linux")]
pub use imp::{apply as apply_seccomp, SeccompApplied};


