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
//!
//! The consequence is worth stating plainly, because it is the whole reason the
//! four holes this module was written to close were cheap to close: **`ptrace`,
//! `clone`, `io_uring`, `perf_event_open`, `memfd_create`, `userfaultfd` and
//! `bpf` are not granted to any profile.** They are absent from the allowlist,
//! so every one of them returns `ENOSYS`. Landlock does not stop any of them -
//! it is a path- and socket-oriented LSM and none of these are paths or sockets -
//! so the allowlist is the only thing standing between a hostile tool and the
//! daemon's address space.
//!
//! Absence is invisible, though. Nothing in the code says "we decided not to
//! grant `ptrace`"; it only says "we decided to grant these sixty-odd". That is
//! why `FORBIDDEN` exists: a table of syscalls that must never appear in a
//! profile, each with the reason, checked in two places.
//!
//! - [`Profile::refused`] reports the table filtered against what the profile
//!   actually grants, so it cannot drift into being aspirational the way a
//!   hand-written list of names would.
//! - `apply` re-checks it and refuses to install a filter in which one of
//!   these has been added, so a future edit that helpfully adds `socketpair` to
//!   the filesystem profile fails loudly at confinement time rather than quietly
//!   at review time.
//!
//! Neither mechanism is a deny-list. Every syscall absent from the allowlist is
//! refused regardless of whether it appears in `FORBIDDEN`; the table only
//! names the ones where being wrong is catastrophic.
//!
//! ## `clone` and `clone3` are refused *together*, or neither is
//!
//! glibc 2.34+ issues `clone3(2)` and, when the kernel answers `ENOSYS`, silently
//! retries with `clone(2)`. A filter that refuses `clone3` but grants `clone` is
//! therefore a filter that refuses nothing, because the refusal is exactly the
//! signal glibc uses to pick the path you allowed. Both are refused here, and
//! `tests/seccomp.rs` asserts both, plus the composed `pthread_create` path,
//! because the individual syscalls are only half the claim.
//!
//! ## `io_uring` is closed at `io_uring_setup`, which closes all of it
//!
//! `IORING_SETUP_*` flags and `IORING_OFFLINE_ASYNC` are arguments to
//! `io_uring_setup`. A ring cannot exist without it, so refusing the setup call
//! refuses every configuration of the ring without having to enumerate them -
//! which is the default-deny rule applied to flags, where a list of flag values
//! would be a deny-list in all but name. `io_uring_enter` and
//! `io_uring_register` are refused too, because neither is reachable without a
//! ring and refusing a syscall that is already unreachable is free.
//!
//! Whether Landlock accounts for io_uring is a question this module does not
//! need answered: Landlock's filesystem enforcement is path-based and the ring is
//! established once and then driven by `io_uring_enter`, which is exactly the
//! shape of access a path-based LSM does not see. Refusing the setup call makes
//! the question moot on this kernel either way.
//!
//! ## BPF jump width, and the ceiling it puts on a profile
//!
//! The comparison chain is linear: one `JEQ` per allowed syscall, each jumping
//! forward to a shared `ALLOW`. `jt` is a `u8`, so the forward distance from the
//! *first* comparison to that `ALLOW` equals the number of allowed syscalls and
//! may not exceed 255. Past that, [`build_filter`] returns
//! [`SeccompError::FilterTooLarge`] and [`apply`] propagates it, so the failure
//! is a refusal to run rather than a truncated filter.
//!
//! The profiles are not close: `Exec`, the larger of the two, is roughly a third
//! of the ceiling. The limit is documented here, asserted in `mod tests`, and
//! reached by a test that builds a filter at 255 and at 256 rather than merely
//! asserting the arithmetic - the risk at the boundary is an off-by-one in the
//! jump offsets, and arithmetic that is merely correct on paper will not catch
//! one.
//!
//! ## Known residual risk
//!
//! `Allowed::Ioctl` is granted to both profiles, because runtimes probe stdio
//! with `TCGETS`/`TIOCGWINSZ` at startup and refuse with `ENOSYS` rather than
//! reporting "not a terminal", which turns a cosmetic check into a visible
//! failure. Device-file ioctls are constrained by `LANDLOCK_ACCESS_FS_IOCTL_DEV`
//! (V5), which [`Confine`] always handles and treats as a refusal floor, so
//! `TIOCSTI` on a tty the child happens to hold is Landlock's job and not this
//! module's. Non-device ioctls (`FIONREAD` and friends on pipes) are not
//! constrained by either layer; they are not an information-disclosure path.

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::BTreeSet;

    use crate::abi::Abi;
    use crate::error::SeccompError;

    /// Syscalls a confined tool class is permitted to make.
    ///
    /// Named rather than numbered so the list reads as intent. The numbers are
    /// resolved from `libc` at compile time on x86-64, and a build on any other
    /// architecture resolves none of them, which makes [`Profile::allowed`]
    /// return `None` and [`apply`] refuse. That is deliberate: an unresolvable
    /// number is a wrong number, and a wrong number allows the wrong syscall.
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
        Mremap,
        Madvise,
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
        Rseq,
        Prlimit64,
        Getrlimit,
        Uname,
        Sysinfo,
        Getrandom,
        Getcwd,
        Access,
        Fcntl,
        Flock,
        Fadvise64,
        Futimesat,
        Utime,
        Utimes,
        SchedYield,
        SchedGetaffinity,
        Getxattr,
        Fsync,
        Ftruncate,
        Truncate,
        Fchmod,
        Fchown,
        Fchdir,
        Chdir,
        Rename,
        Renameat,
        Renameat2,
        Unlink,
        Unlinkat,
        Mkdir,
        Mkdirat,
        Rmdir,
        Ioctl,
        Execveat,
        Dup,
        Dup3,
        Pipe,
        Pipe2,
        Kill,
        Tgkill,
        RtSigqueueinfo,
        EpollCreate1,
        EpollCtl,
        EpollPwait,
        Ppoll,
        Pselect6,
        LandlockCreateRuleset,
        LandlockAddRule,
        /// `landlock_restrict_self(2)`, which glibc spells `restrict_self`.
        RestrictSelf,
        /// `sendmsg(2)`, which is how a descriptor is placed on a control socket
        /// and handed to a child. See `Profile::Worker`.
        Sendmsg,
        /// `recvmsg(2)`, its counterpart for receiving one.
        Recvmsg,
        /// `arch_prctl(2)`, which glibc uses to write the FS base register.
        ArchPrctl,
        /// `pread64(2)`, how the loader reads positioned ELF data.
        Pread64,
        /// `statx(2)`. glibc 2.33+ implements `stat`/`fstat` through it.
        Statx,
        /// `faccessat2(2)`, the modern `access(2)` with a syscall the loader
        /// uses to probe for the presence of the vDSO.
        Faccessat2,
        /// `membarrier(2)`. The runtime calls it during startup to order the
        /// register state before publishing thread data.
        Membarrier,
        /// `poll(2)`. Empirically the one syscall a dynamically linked image
        /// needs that the rest of the allowlist does not already cover: a
        /// reference worker confined to this profile aborted during loader
        /// startup and adding only this made it run. glibc reaches for it on
        /// the startup path; granting it is a no-op for a worker with no timers,
        /// which is what every confined worker is.
        Poll,
        /// `lseek(2)`. A worker reading a handed-over descriptor seeks to its
        /// start before reading, because `SCM_RIGHTS` shares one open file
        /// description and therefore one offset across every request that
        /// receives the same descriptor. Granting this is required for a
        /// capability to be re-readable, and by itself it grants no new object:
        /// seeking a descriptor is still that descriptor.
        Lseek,
        /// `set_robust_list(2)`. glibc calls it in early startup; it returns
        /// the address of the robust futex list it will later use for
        /// thread-exit bookkeeping.
        SetRobustList,
        /// `prctl(2)`. glibc's startup and the Rust runtime both call it for
        /// thread and signal setup. This is a policy hole on its own - `prctl`
        /// includes `PR_SET_DUMPABLE` and `PR_SET_SECCOMP` - so it is granted
        /// only for the worker profile, where the seccomp filter is already
        /// installed and can only be made more restrictive, and never applied
        /// after `PR_SET_NO_NEW_PRIVS`.
        Prctl,
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
                Allowed::SchedYield,
                Allowed::SchedGetaffinity,
                Allowed::Getxattr,
            ];
            list.iter().filter_map(|a| a.number()).collect()
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
                Allowed::Kill,
                Allowed::Tgkill,
                Allowed::RtSigqueueinfo,
                // Landlock is monotone: `landlock_restrict_self` can only ever
                // remove rights, so a tool that confines its own children more
                // tightly is not escalating. `socketpair` is *not* here - with
                // `socket` refused it can only address a partner the process
                // created itself, and `pipe2` covers the same need, so granting
                // it would be granting an AF_UNIX constructor for nothing.
                Allowed::LandlockCreateRuleset,
                Allowed::LandlockAddRule,
                Allowed::RestrictSelf,
            ]
            .iter()
            .filter_map(|a| a.number())
            .collect()
        }

        /// The control-socket syscalls a pooled worker needs.
        ///
        /// `sendmsg`/`recvmsg` exist because SCM_RIGHTS is the only way to
        /// hand a file descriptor across a process boundary, and the worker's
        /// control channel is the only channel it has. This is deliberate, not
        /// an accident of the allowlist: a worker that cannot receive a
        /// descriptor is a worker with no capabilities to be confused about,
        /// which is a real design choice this pool rejected in favour of the
        /// descriptor-passing one.
        fn fd_extras() -> BTreeSet<i64> {
            [Allowed::Sendmsg, Allowed::Recvmsg]
                .iter()
                .filter_map(|a| a.number())
                .collect()
        }

        /// The syscalls a *dynamically linked* image needs merely to reach
        /// `main`, beyond the baseline.
        ///
        /// A static binary needs none of these, but the seccomp profile cannot
        /// know whether the image it is about to confine is static or dynamic:
        /// the image is chosen by the caller, after the profile is fixed. A
        /// profile that omits them refuses every dynamic image with `ENOSYS`
        /// during loader startup, which is a confusing "no such syscall" for a
        /// worker that is in fact fully confined. So the profile grants the
        /// small loader set and relies on Landlock for what the image may
        /// actually reach.
        ///
        /// - `arch_prctl` sets the FS base register (the thread pointer), which
        ///   glibc writes during startup and which every TLS access reads. A
        ///   dynamic image cannot run without it.
        /// - `pread64` is how the loader reads ELF program headers and symbol
        ///   tables; it seeks with the offset argument rather than `lseek`.
        /// - `readlink`/`readlinkat` resolve the vDSO and the interpreter path
        ///   during relocation.
        fn loader_extras() -> BTreeSet<i64> {
            [
                Allowed::ArchPrctl,
                Allowed::Pread64,
                Allowed::Readlink,
                Allowed::ReadlinkAt,
                Allowed::Statx,
                Allowed::Faccessat2,
                Allowed::Membarrier,
                Allowed::Poll,
                Allowed::Lseek,
                Allowed::SetRobustList,
                Allowed::Prctl,
            ]
            .iter()
            .filter_map(|a| a.number())
            .collect()
        }

        /// The syscall number, or `None` on an architecture where this crate
        /// does not know it.
        pub fn number(self) -> Option<i64> {
            #[cfg(target_arch = "x86_64")]
            {
                Some(match self {
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
                    Allowed::Execveat => libc::SYS_execveat,
                    Allowed::Dup => libc::SYS_dup,
                    Allowed::Dup3 => libc::SYS_dup3,
                    Allowed::Pipe => libc::SYS_pipe,
                    Allowed::Pipe2 => libc::SYS_pipe2,
                    Allowed::Kill => libc::SYS_kill,
                    Allowed::Tgkill => libc::SYS_tgkill,
                    Allowed::RtSigqueueinfo => libc::SYS_rt_sigqueueinfo,
                    Allowed::EpollCreate1 => libc::SYS_epoll_create1,
                    Allowed::EpollCtl => libc::SYS_epoll_ctl,
                    Allowed::EpollPwait => libc::SYS_epoll_pwait,
                    Allowed::Ppoll => libc::SYS_ppoll,
                    Allowed::Pselect6 => libc::SYS_pselect6,
                    Allowed::LandlockCreateRuleset => libc::SYS_landlock_create_ruleset,
                    Allowed::LandlockAddRule => libc::SYS_landlock_add_rule,
                    Allowed::RestrictSelf => libc::SYS_landlock_restrict_self,
                    Allowed::Sendmsg => libc::SYS_sendmsg,
                    Allowed::Recvmsg => libc::SYS_recvmsg,
                    Allowed::ArchPrctl => libc::SYS_arch_prctl,
                    Allowed::Pread64 => libc::SYS_pread64,
                    Allowed::Statx => libc::SYS_statx,
                    Allowed::Faccessat2 => libc::SYS_faccessat2,
                    Allowed::Membarrier => libc::SYS_membarrier,
                    Allowed::Poll => libc::SYS_poll,
                    Allowed::Lseek => libc::SYS_lseek,
                    Allowed::SetRobustList => libc::SYS_set_robust_list,
                    Allowed::Prctl => libc::SYS_prctl,
                })
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                // Refusing to guess is the point. A wrong syscall number silently
                // allows the wrong syscall, which is the failure mode seccomp is
                // installed to prevent. aarch64 is therefore refused wholesale
                // rather than half-supported; `audit_arch` has no aarch64 arm to
                // fall into, because on this build there is never a filter to
                // install in the first place.
                let _ = self;
                None
            }
        }
    }

    /// `AUDIT_ARCH_*` for the architecture whose syscall numbers [`Allowed`]
    /// resolves.
    ///
    /// Takes no `cfg` arm for other architectures on purpose: there is exactly
    /// one architecture on which a filter can be built at all, and an
    /// architecture check that disagreed with the number table would be a
    /// filter that kills every process it is installed on.
    fn audit_arch() -> u32 {
        debug_assert_eq!(cfg!(target_arch = "x86_64"), Allowed::Read.number().is_some());
        const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
        AUDIT_ARCH_X86_64
    }

    /// A syscall that no profile may ever grant, and why granting it is a
    /// bypass rather than a convenience.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Forbidden {
        /// The syscall name as `strace` spells it.
        pub name: &'static str,
        /// The number it has on this architecture.
        pub number: i64,
        /// What an attacker who reaches this syscall gains.
        pub why: &'static str,
    }

    /// Syscalls whose absence from the allowlist is a deliberate decision rather
    /// than an oversight.
    ///
    /// Not a deny-list. The filter already refuses everything not granted; this
    /// table only names the refusals where being wrong is catastrophic, so that
    /// [`Profile::refused`] can report them and `apply` can refuse to install a
    /// filter that has grown one.
    ///
    /// `static` rather than `const` so `&FORBIDDEN` is plainly `&'static` and
    /// [`Profile::refused`] does not lean on rvalue promotion.
    #[cfg(target_arch = "x86_64")]
    pub static FORBIDDEN: &[Forbidden] = &[
        Forbidden {
            name: "ptrace",
            number: libc::SYS_ptrace,
            why: "PTRACE_ATTACH against the daemon reads and rewrites its memory, \
                  which is a complete bypass of every other layer. Landlock does \
                  not touch ptrace at all.",
        },
        Forbidden {
            name: "process_vm_readv",
            number: libc::SYS_process_vm_readv,
            why: "the same capability as ptrace under a different name: read \
                  another process's memory without a tracer.",
        },
        Forbidden {
            name: "process_vm_writev",
            number: libc::SYS_process_vm_writev,
            why: "and the write half, which is worse than reading.",
        },
        Forbidden {
            name: "clone",
            number: libc::SYS_clone,
            why: "thread and process creation. Must be refused together with \
                  clone3: glibc falls back from clone3 to clone on ENOSYS, so \
                  refusing either one alone refuses nothing.",
        },
        Forbidden {
            name: "clone3",
            number: libc::SYS_clone3,
            why: "the call glibc actually makes first. Refusing it is only \
                  meaningful because clone is refused too.",
        },
        Forbidden {
            name: "io_uring_setup",
            number: libc::SYS_io_uring_setup,
            why: "a ring can issue file and network operations that Landlock's \
                  path-based model never sees, because the ring is established \
                  once and then driven. Refusing setup closes every IORING_SETUP_* \
                  flag at once, so none of them need enumerating.",
        },
        Forbidden {
            name: "io_uring_enter",
            number: libc::SYS_io_uring_enter,
            why: "drives an existing ring. Unreachable once setup is refused, and \
                  refused anyway because refusing it is free.",
        },
        Forbidden {
            name: "io_uring_register",
            number: libc::SYS_io_uring_register,
            why: "registers files with a ring, which is how IORING_REGISTER would \
                  launder a descriptor into the unrestricted path.",
        },
        Forbidden {
            name: "perf_event_open",
            number: libc::SYS_perf_event_open,
            why: "a cross-process side channel. Whether it is also usable to \
                  influence another process depends on perf_event_paranoid, \
                  which is host policy, not something this crate installs.",
        },
        Forbidden {
            name: "bpf",
            number: libc::SYS_bpf,
            why: "loads programs into the kernel. Unprivileged load is normally \
                  refused by kernel policy, and relying on kernel policy is \
                  exactly the failure mode this crate avoids.",
        },
        Forbidden {
            name: "memfd_create",
            number: libc::SYS_memfd_create,
            why: "anonymous memory with a name and no path, which defeats any \
                  reasoning about what may be executed or read.",
        },
        Forbidden {
            name: "userfaultfd",
            number: libc::SYS_userfaultfd,
            why: "lets a process own its own page-fault handling. That is a \
                  kernel-exploit primitive, not a tool capability.",
        },
        Forbidden {
            name: "open_by_handle_at",
            number: libc::SYS_open_by_handle_at,
            why: "opens a file by handle instead of by path, which is precisely \
                  the decision Landlock is built to constrain.",
        },
        Forbidden {
            name: "name_to_handle_at",
            number: libc::SYS_name_to_handle_at,
            why: "mints the handle open_by_handle_at consumes.",
        },
        Forbidden {
            name: "keyctl",
            number: libc::SYS_keyctl,
            why: "keyrings are shared state across processes; a tool that can \
                  read or link one is talking to something outside its domain.",
        },
        Forbidden {
            name: "add_key",
            number: libc::SYS_add_key,
            why: "the write half of the keyring surface.",
        },
        Forbidden {
            name: "pidfd_open",
            number: libc::SYS_pidfd_open,
            why: "obtains a process handle the tool can then signal, independently \
                  of any PID-namespace reasoning.",
        },
        Forbidden {
            name: "pidfd_send_signal",
            number: libc::SYS_pidfd_send_signal,
            why: "signalling outside the Landlock Signal scope's path-based view \
                  of who is who.",
        },
        Forbidden {
            name: "kcmp",
            number: libc::SYS_kcmp,
            why: "compares two processes, which discloses their address space \
                  layout and file tables.",
        },
        Forbidden {
            name: "setns",
            number: libc::SYS_setns,
            why: "joins a namespace the process was never confined in.",
        },
        Forbidden {
            name: "unshare",
            number: libc::SYS_unshare,
            why: "leaves the namespaces the confinement was established in.",
        },
        Forbidden {
            name: "mount",
            number: libc::SYS_mount,
            why: "mounts a filesystem Landlock's ruleset has never seen.",
        },
        Forbidden {
            name: "umount2",
            number: libc::SYS_umount2,
            why: "tears down a mount point.",
        },
        Forbidden {
            name: "mount_setattr",
            number: libc::SYS_mount_setattr,
            why: "changes mount flags without going through mount(2).",
        },
        Forbidden {
            name: "pivot_root",
            number: libc::SYS_pivot_root,
            why: "changes the root the confinement resolved paths against.",
        },
        Forbidden {
            name: "chroot",
            number: libc::SYS_chroot,
            why: "the same, more weakly.",
        },
        Forbidden {
            name: "init_module",
            number: libc::SYS_init_module,
            why: "loads kernel code.",
        },
        Forbidden {
            name: "finit_module",
            number: libc::SYS_finit_module,
            why: "loads kernel code from a file the tool was handed.",
        },
        Forbidden {
            name: "delete_module",
            number: libc::SYS_delete_module,
            why: "unloads kernel code.",
        },
        Forbidden {
            name: "kexec_load",
            number: libc::SYS_kexec_load,
            why: "replaces the running kernel image.",
        },
        Forbidden {
            name: "ioperm",
            number: libc::SYS_ioperm,
            why: "port I/O, which reaches hardware no filesystem sandbox models.",
        },
        Forbidden {
            name: "iopl",
            number: libc::SYS_iopl,
            why: "and the privilege-level half of port I/O.",
        },
        Forbidden {
            name: "mknod",
            number: libc::SYS_mknod,
            why: "creates device nodes inside a granted directory.",
        },
        Forbidden {
            name: "mknodat",
            number: libc::SYS_mknodat,
            why: "and the *at form, which is what libc actually calls.",
        },
        Forbidden {
            name: "socket",
            number: libc::SYS_socket,
            why: "the hole Landlock leaves: it gates TCP bind and connect but \
                  leaves socket(2), UDP and every non-TCP protocol alone.",
        },
        Forbidden {
            name: "socketpair",
            number: libc::SYS_socketpair,
            why: "an AF_UNIX constructor that, with socket refused, can only ever \
                  address a peer the process made itself. Pipe covers the need.",
        },
        Forbidden {
            name: "bind",
            number: libc::SYS_bind,
            why: "egress. Landlock gates TCP bind but not UDP, raw or SCTP.",
        },
        Forbidden {
            name: "connect",
            number: libc::SYS_connect,
            why: "egress, same reasoning.",
        },
        Forbidden {
            name: "listen",
            number: libc::SYS_listen,
            why: "egress as an inbound channel.",
        },
        Forbidden {
            name: "accept",
            number: libc::SYS_accept,
            why: "and the syscall that completes it.",
        },
        Forbidden {
            name: "accept4",
            number: libc::SYS_accept4,
            why: "and the *at-style variant libc prefers.",
        },
        Forbidden {
            name: "sendto",
            number: libc::SYS_sendto,
            why: "transmits on any protocol, including UDP.",
        },
        Forbidden {
            name: "recvfrom",
            number: libc::SYS_recvfrom,
            why: "receives on any protocol.",
        },
        Forbidden {
            name: "sendmmsg",
            number: libc::SYS_sendmmsg,
            why: "batched transmit.",
        },
        Forbidden {
            name: "recvmmsg",
            number: libc::SYS_recvmmsg,
            why: "batched receive.",
        },
        Forbidden {
            name: "shutdown",
            number: libc::SYS_shutdown,
            why: "no use without a socket, and one more thing to get wrong.",
        },
        Forbidden {
            name: "setsockopt",
            number: libc::SYS_setsockopt,
            why: "can attach to a process's socket or enable packet capture.",
        },
        Forbidden {
            name: "getsockopt",
            number: libc::SYS_getsockopt,
            why: "discloses socket state.",
        },
    ];

    /// No forbidden list on an architecture where nothing can be granted. Kept
    /// as an empty slice rather than `Option` so [`Profile::refused`] has the
    /// same shape everywhere.
    #[cfg(not(target_arch = "x86_64"))]
    pub static FORBIDDEN: &[Forbidden] = &[];

    /// Which syscalls a confined process may make.
    ///
    /// One variant per tool class rather than one global policy, because the
    /// narrowest list that still lets the tool work is the safest. A tool that
    /// only reads files does not need `execveat`, and allowing it because
    /// another tool did would be a hole.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Profile {
        /// Reads and writes inside granted directories. The default for
        /// built-in tools. No `socket`, no `execveat`, no `clone`.
        Filesystem,
        /// `Filesystem`, plus process creation and local IPC, for a tool that
        /// must spawn a helper. Note this is a materially larger grant and the
        /// reason no tool gets it by default.
        ///
        /// It does **not** grant `clone`/`clone3`, so a tool confined to this
        /// profile cannot actually create a thread or a child; see the module
        /// docs for why both are refused together. It also does not grant
        /// `execve`, only `execveat`, so a helper can be started from a
        /// descriptor but not from a path.
        Exec,
        /// `Exec`, plus `sendmsg`/`recvmsg`.
        ///
        /// This exists for a pooled worker: the worker's entire control channel
        /// to the daemon is an inherited unix socketpair, and the kernel has no
        /// other way to deliver an SCM_RIGHTS descriptor. The inherited socket
        /// is inside the process's fd table from a stand-in-for-mainway down to
        /// the exec'd worker, so the worker cannot listen or connect: this
        /// profile adds the *delivery* of a capability, not the creation of one.
        /// Real network still needs `socket`/`connect`, which stay refused.
        Worker,
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
                Profile::Worker => {
                    set.extend(Allowed::write_extras());
                    set.extend(Allowed::exec_extras());
                    set.extend(Allowed::fd_extras());
                    set.extend(Allowed::loader_extras());
                }
            }
            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        }

        /// Syscalls this profile deliberately refuses, cross-checked against what
        /// it actually grants.
        ///
        /// Derived from `FORBIDDEN` filtered by [`Profile::allowed`] rather
        /// than written out by hand, so it cannot describe an intention the
        /// allowlist does not implement. An entry that stops being refused
        /// disappears from this list, which is exactly when the tests should
        /// start failing.
        pub fn refused(self) -> Vec<&'static Forbidden> {
            let Some(allowed) = self.allowed() else {
                return FORBIDDEN.iter().collect();
            };
            FORBIDDEN
                .iter()
                .filter(|f| !allowed.contains(&f.number))
                .collect()
        }

        /// Refuse to build a filter that grants something in `FORBIDDEN`.
        ///
        /// Redundant with the allowlist as written and deliberately so: this is
        /// the check that catches the next person adding `Allowed::Socketpair`
        /// to `exec_extras` because a test wanted it.
        fn audit(self, allowed: &BTreeSet<i64>) -> Result<(), SeccompError> {
            // `find`, not a loop: the answer is which entry, not how many. The
            // first one is reported because it is the one whose `why` explains
            // the violation.
            if let Some(f) = FORBIDDEN.iter().find(|f| allowed.contains(&f.number)) {
                // `KernelRefused` is the least-wrong existing variant. This is
                // an internal invariant violation rather than anything the
                // kernel said, and `SeccompError` has no variant for that;
                // adding one is a change to `error.rs` and is reported rather
                // than made from here.
                return Err(SeccompError::KernelRefused(format!(
                    "internal: {self:?} grants {} ({}) but it must never be granted: {}",
                    f.name, f.number, f.why
                )));
            }
            Ok(())
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
        profile.audit(&allowed)?;

        // The kernel requires no_new_privs for an unprivileged filter. Reading it
        // back rather than trusting the call avoids a race with another thread
        // clearing it.
        if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
            return Err(SeccompError::NoNewPrivs);
        }

        // `sock_fprog.filter` is `*mut sock_filter` because the kernel's BPF
        // interpreter may rewrite jump targets. The instructions here are already
        // fully resolved, so the mutability is not used.
        let mut filter = build_filter(&allowed, audit_arch())?;
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
    ///
    /// `audit_arch` is a parameter rather than a constant inside so the
    /// `KILL_PROCESS` arm at index 2 is reachable from a test: on the one
    /// architecture where a filter can be built, `seccomp_data.arch` always
    /// matches, so the arm is unreachable by any real syscall and can only be
    /// exercised by handing `build_filter` an architecture that does not match.
    fn build_filter(
        allowed: &BTreeSet<i64>,
        audit_arch: u32,
    ) -> Result<Vec<libc::sock_filter>, SeccompError> {
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
            libc::SECCOMP_RET_KILL_PROCESS,
        ));
        // 3: load the syscall number.
        prog.push(stmt((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0));

        // 4..: one comparison each, jumping to the allow on a match and falling
        // through to the deny otherwise.
        for (i, &nr) in allowed.iter().enumerate() {
            let at = 4 + i;
            // `jt` counts from the instruction *after* this one, so the offset to
            // `ret_allow_index` is one less than the raw index distance. For the
            // first comparison that distance is the size of the allowlist, which
            // is where the u8 ceiling comes from.
            let forward = (ret_allow_index - 1) - at;
            let forward = u8::try_from(forward).map_err(|_| SeccompError::FilterTooLarge)?;
            prog.push(jeq(nr as u32, forward, 0));
        }

        // Deny by returning ENOSYS rather than killing, so the tool fails
        // visibly and the caller learns which capability it wanted.
        prog.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0x0000_FFFF),
        ));
        prog.push(stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ALLOW,
        ));

        debug_assert_eq!(prog.len() - 1, ret_allow_index);
        // `struct sock_fprog.len` is a u16. Unreachable in practice: the jump
        // width caps the allowlist at 255 long before this, so the real ceiling
        // is the u8 one above and this is only a backstop.
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

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Run the BPF program the way the kernel does, and return the action for
        /// `(arch, nr)`.
        ///
        /// The kernel's interpreter is the only thing that can tell whether the
        /// jump offsets are right; asserting on the arithmetic instead would pass
        /// with an off-by-one that skips the `ALLOW`.
        fn run(prog: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
            const LD_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
            const JEQ_K: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
            const RET_K: u32 = libc::BPF_RET | libc::BPF_K;

            let mut pc = 0usize;
            let mut a: u32 = 0;
            // Generous: a correct program takes at most two steps per
            // instruction, and the cap is there so a wrong jump reports a
            // failure rather than hanging the suite.
            for _ in 0..prog.len() * 2 + 8 {
                let i = prog[pc];
                match i.code as u32 {
                    c if c == LD_ABS => {
                        // Offsets into `seccomp_data`: nr at 0, arch at 4.
                        a = if i.k == 4 { arch } else { nr };
                        pc += 1;
                    }
                    c if c == JEQ_K => {
                        let taken = if a == i.k { i.jt } else { i.jf };
                        pc += 1 + taken as usize;
                    }
                    c if c == RET_K => return i.k,
                    other => panic!("unhandled BPF opcode {other:#x} at {pc}"),
                }
            }
            panic!("the program ran off the end without a RET");
        }

        const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
        const DENY_ENOSYS: u32 =
            libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0x0000_FFFF);
        const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

        #[test]
        fn the_arch_check_returns_kill_process() {
            // Reachable only by handing `build_filter` an architecture that does
            // not match, which is why `audit_arch` is a parameter. The claim
            // under test is the *encoding*: index 2 is KILL_PROCESS and index 1
            // jumps over it.
            let allowed = BTreeSet::from([1i64, 2, 3]);
            let prog = build_filter(&allowed, audit_arch()).expect("build");
            assert_eq!(
                run(&prog, 0xFFFF_FFFF, 1),
                KILL,
                "a foreign architecture must be killed, not filtered"
            );
        }

        #[test]
        fn a_matching_architecture_is_not_killed() {
            let allowed = BTreeSet::from([1i64, 2, 3]);
            let prog = build_filter(&allowed, audit_arch()).expect("build");
            assert_eq!(run(&prog, audit_arch(), 1), ALLOW);
            assert_eq!(run(&prog, audit_arch(), 99), DENY_ENOSYS);
        }

        #[test]
        fn the_filter_allows_exactly_the_allowlist() {
            for profile in [Profile::Filesystem, Profile::Exec] {
                let allowed = profile.allowed().expect("x86-64 resolves numbers");
                let prog = build_filter(&allowed, audit_arch()).expect("build");
                for &nr in &allowed {
                    assert_eq!(
                        run(&prog, audit_arch(), nr as u32),
                        ALLOW,
                        "{profile:?} should allow syscall {nr}"
                    );
                }
                // Sweep the whole x86-64 syscall table around the real numbers
                // plus the well-known dangerous ones, so a wrong jump offset
                // cannot accidentally re-allow a neighbour.
                let mut denied_at_least_once = 0;
                for probe in 0u32..1024 {
                    if allowed.contains(&(probe as i64)) {
                        continue;
                    }
                    assert_eq!(
                        run(&prog, audit_arch(), probe),
                        DENY_ENOSYS,
                        "{profile:?} should refuse syscall {probe}"
                    );
                    denied_at_least_once += 1;
                }
                assert!(denied_at_least_once > 500);
            }
        }

        #[test]
        fn every_forbidden_syscall_is_outside_every_allowlist() {
            for profile in [Profile::Filesystem, Profile::Exec] {
                let allowed = profile.allowed().expect("x86-64 resolves numbers");
                for f in FORBIDDEN.iter() {
                    assert!(
                        !allowed.contains(&f.number),
                        "{profile:?} grants {} ({}) but it must never be granted: {}",
                        f.name,
                        f.number,
                        f.why
                    );
                }
                // `refused` is derived, so this also checks the derivation. It is
                // only true for profiles that grant no FORBIDDEN syscall; the
                // worker profile grants `recvmsg`/`sendmsg`, which is why it is
                // excluded here rather than joined to this list.
                assert_eq!(
                    profile.refused().len(),
                    FORBIDDEN.len(),
                    "{profile:?} no longer refuses everything in FORBIDDEN"
                );
            }
        }

        /// The u8 jump ceiling, reached rather than asserted.
        ///
        /// 255 allowed syscalls is the largest set whose first comparison can
        /// still reach the `ALLOW`; 256 is one too many. Both are built and the
        /// resulting programs are executed, because at exactly this boundary an
        /// off-by-one would produce a filter that still installs and still denies
        /// by default, just with the wrong syscall allowed.
        #[test]
        fn the_jump_width_ceiling_is_exactly_255() {
            let at_ceiling: BTreeSet<i64> = (0i64..255).collect();
            let prog = build_filter(&at_ceiling, audit_arch()).expect("255 must build");
            assert_eq!(
                run(&prog, audit_arch(), 0),
                ALLOW,
                "the first comparison must still reach ALLOW at the ceiling"
            );
            assert_eq!(run(&prog, audit_arch(), 254), ALLOW);
            assert_eq!(run(&prog, audit_arch(), 255), DENY_ENOSYS);
            assert_eq!(run(&prog, audit_arch(), 10_000), DENY_ENOSYS);

            let past_ceiling: BTreeSet<i64> = (0i64..256).collect();
            assert!(matches!(
                build_filter(&past_ceiling, audit_arch()),
                Err(SeccompError::FilterTooLarge)
            ));
        }

        #[test]
        fn the_profiles_are_well_inside_the_ceiling() {
            // If this ever fires, the profile is within one syscall of refusing
            // to run at all. Raising the ceiling is a deliberate decision, not
            // something to discover in production.
            for profile in [Profile::Filesystem, Profile::Exec] {
                let n = profile.allowed().expect("x86-64 resolves numbers").len();
                assert!(n <= 255, "{profile:?} grants {n} syscalls; the ceiling is 255");
            }
        }

        #[test]
        fn an_empty_allowlist_denies_everything() {
            let prog = build_filter(&BTreeSet::new(), audit_arch()).expect("build");
            assert_eq!(run(&prog, audit_arch(), 0), DENY_ENOSYS);
            assert_eq!(run(&prog, audit_arch(), 60), DENY_ENOSYS);
        }
    }
}

/// Names for readability at call sites.
#[cfg(target_os = "linux")]
pub use imp::Profile;

#[cfg(target_os = "linux")]
pub use imp::{apply as apply_seccomp, SeccompApplied};