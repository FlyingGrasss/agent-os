//! Landlock feature model and kernel capability detection.
//!
//! This module is deliberately free of any `landlock` crate import so that the
//! [`Abi`] / [`Feature`] vocabulary (and the fallback matrix built on top of it)
//! exists on every platform. Only [`detect`] touches the kernel, and only on
//! Linux.
//!
//! # Why an explicit matrix
//!
//! Landlock grows a new [ABI] version every few kernel releases and each version
//! adds access rights. A sandbox built with `AccessFs::from_all(...)` against an
//! unknown ABI either
//!
//! 1. fails to build, or
//! 2. silently handles *fewer* rights than the caller believes.
//!
//! (2) is the dangerous case: the user believes the tool is confined while the
//! kernel is not enforcing, say, `LANDLOCK_ACCESS_FS_TRUNCATE`. AgentOS treats
//! that as a bug, not a usability problem, so every right this crate can use is
//! named here, mapped to the minimum ABI that defines it, and checked before a
//! ruleset is created. Anything missing is an error, never a downgrade.
//!
//! [ABI]: https://docs.kernel.org/userspace-api/landlock.html#abi

/// A Landlock ABI version.
///
/// This is **not** `landlock::ABI`: it is a closed set limited to the versions
/// this crate has actually been reasoned about and tested against (V1..=V7).
/// Higher kernel versions are reported as [`Abi::V7`] plus a note, because a
/// newer kernel may define rights whose semantics we have not vetted; enabling
/// an unvetted right is itself a (smaller) version of the same bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Abi {
    /// Execute, read file, read dir, write file, remove and make. Linux 5.13.
    V1 = 1,
    /// Adds `REFER` (rename/link between directories). Linux 5.19.
    V2 = 2,
    /// Adds `TRUNCATE`. Linux 6.2.
    V3 = 3,
    /// Adds `LANDLOCK_ACCESS_NET_BIND_TCP` / `_CONNECT_TCP`. Linux 6.7.
    V4 = 4,
    /// Adds `IOCTL_DEV`. Linux 6.10.
    V5 = 5,
    /// Adds scopes (`SIGNAL`, `ABSTRACT_UNIX_SOCKET`). Linux 6.12.
    V6 = 6,
    /// Adds `restrict_self` log flags and `LANDLOCK_RESTRICT_SELF_LOG_*`. Linux 6.15.
    V7 = 7,
}

/// The highest ABI this crate targets. Rights from newer ABIs are never enabled.
pub const TARGET_ABI: Abi = Abi::V7;

impl Abi {
    /// Clamp a raw kernel ABI number onto the versions this crate understands.
    ///
    /// Returns `None` for values below 1, which is not Landlock at all. Values
    /// above [`TARGET_ABI`] are clamped *down*: the kernel may know more than we
    /// do, and acting on rights we have not vetted is exactly what this crate
    /// refuses to do.
    pub fn clamp(raw: i32) -> Option<Abi> {
        match raw {
            i32::MIN..=0 => None,
            1 => Some(Abi::V1),
            2 => Some(Abi::V2),
            3 => Some(Abi::V3),
            4 => Some(Abi::V4),
            5 => Some(Abi::V5),
            6 => Some(Abi::V6),
            _ => Some(Abi::V7),
        }
    }

    /// The maximum of a set of ABI versions.
    pub fn max_of(abilities: impl IntoIterator<Item = Abi>) -> Abi {
        abilities.into_iter().max().unwrap_or(Abi::V1)
    }
}

impl core::fmt::Display for Abi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&(*self as u32), f)
    }
}

/// A single Landlock capability this crate knows how to require.
///
/// Each variant maps to exactly one minimum [`Abi`]. The fallback policy is
/// uniform and stated once in the crate docs: *missing means refuse*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// `LANDLOCK_ACCESS_FS_EXECUTE`.
    Execute,
    /// `LANDLOCK_ACCESS_FS_READ_FILE`.
    ReadFile,
    /// `LANDLOCK_ACCESS_FS_READ_DIR`.
    ReadDir,
    /// `LANDLOCK_ACCESS_FS_WRITE_FILE`.
    WriteFile,
    /// `LANDLOCK_ACCESS_FS_REMOVE_DIR`.
    RemoveDir,
    /// `LANDLOCK_ACCESS_FS_REMOVE_FILE`.
    RemoveFile,
    /// `LANDLOCK_ACCESS_FS_MAKE_CHAR`.
    MakeChar,
    /// `LANDLOCK_ACCESS_FS_MAKE_DIR`.
    MakeDir,
    /// `LANDLOCK_ACCESS_FS_MAKE_REG`.
    MakeReg,
    /// `LANDLOCK_ACCESS_FS_MAKE_SOCK`.
    MakeSock,
    /// `LANDLOCK_ACCESS_FS_MAKE_FIFO`.
    MakeFifo,
    /// `LANDLOCK_ACCESS_FS_MAKE_BLOCK`.
    MakeBlock,
    /// `LANDLOCK_ACCESS_FS_MAKE_SYM`.
    MakeSym,
    /// `LANDLOCK_ACCESS_FS_REFER` - rename/link across directories.
    Refer,
    /// `LANDLOCK_ACCESS_FS_TRUNCATE` - `O_TRUNC`, `ftruncate`.
    Truncate,
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV`.
    IoctlDev,
    /// `LANDLOCK_ACCESS_NET_BIND_TCP`.
    NetBindTcp,
    /// `LANDLOCK_ACCESS_NET_CONNECT_TCP`.
    NetConnectTcp,
    /// `Scope::Signal` - signalling processes outside the domain.
    ScopeSignal,
    /// `Scope::AbstractUnixSocket` - connecting to abstract-namespace UNIX sockets.
    ScopeAbstractUnixSocket,
    /// `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`. ABI V9; **not** implemented here.
    ///
    /// Listed so the matrix is complete. AgentOS refuses to run rather than
    /// silently omitting it, because on a V9 kernel a peer holding a connected
    /// abstract UNIX socket could otherwise reach into the confined child.
    ResolveUnix,
}

impl Feature {
    /// The lowest ABI that defines this right.
    pub const fn min_abi(self) -> Abi {
        match self {
            Feature::Execute
            | Feature::ReadFile
            | Feature::ReadDir
            | Feature::WriteFile
            | Feature::RemoveDir
            | Feature::RemoveFile
            | Feature::MakeChar
            | Feature::MakeDir
            | Feature::MakeReg
            | Feature::MakeSock
            | Feature::MakeFifo
            | Feature::MakeBlock
            | Feature::MakeSym => Abi::V1,
            Feature::Refer => Abi::V2,
            Feature::Truncate => Abi::V3,
            Feature::NetBindTcp | Feature::NetConnectTcp => Abi::V4,
            Feature::IoctlDev => Abi::V5,
            Feature::ScopeSignal | Feature::ScopeAbstractUnixSocket => Abi::V6,
            Feature::ResolveUnix => Abi::V7, // unreachable: never requested, see above
        }
    }

    /// Human-readable name used in error messages.
    pub const fn name(self) -> &'static str {
        match self {
            Feature::Execute => "LANDLOCK_ACCESS_FS_EXECUTE",
            Feature::ReadFile => "LANDLOCK_ACCESS_FS_READ_FILE",
            Feature::ReadDir => "LANDLOCK_ACCESS_FS_READ_DIR",
            Feature::WriteFile => "LANDLOCK_ACCESS_FS_WRITE_FILE",
            Feature::RemoveDir => "LANDLOCK_ACCESS_FS_REMOVE_DIR",
            Feature::RemoveFile => "LANDLOCK_ACCESS_FS_REMOVE_FILE",
            Feature::MakeChar => "LANDLOCK_ACCESS_FS_MAKE_CHAR",
            Feature::MakeDir => "LANDLOCK_ACCESS_FS_MAKE_DIR",
            Feature::MakeReg => "LANDLOCK_ACCESS_FS_MAKE_REG",
            Feature::MakeSock => "LANDLOCK_ACCESS_FS_MAKE_SOCK",
            Feature::MakeFifo => "LANDLOCK_ACCESS_FS_MAKE_FIFO",
            Feature::MakeBlock => "LANDLOCK_ACCESS_FS_MAKE_BLOCK",
            Feature::MakeSym => "LANDLOCK_ACCESS_FS_MAKE_SYM",
            Feature::Refer => "LANDLOCK_ACCESS_FS_REFER",
            Feature::Truncate => "LANDLOCK_ACCESS_FS_TRUNCATE",
            Feature::IoctlDev => "LANDLOCK_ACCESS_FS_IOCTL_DEV",
            Feature::NetBindTcp => "LANDLOCK_ACCESS_NET_BIND_TCP",
            Feature::NetConnectTcp => "LANDLOCK_ACCESS_NET_CONNECT_TCP",
            Feature::ScopeSignal => "Scope::Signal",
            Feature::ScopeAbstractUnixSocket => "Scope::AbstractUnixSocket",
            Feature::ResolveUnix => "LANDLOCK_ACCESS_FS_RESOLVE_UNIX",
        }
    }
}

/// Outcome of asking the kernel what Landlock it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelSupport {
    abi: Option<Abi>,
    detail: &'static str,
}

impl KernelSupport {
    /// Landlock is usable at this ABI.
    // `available`/`disabled`/`missing` are only constructed by the Linux probe;
    // on other targets `detect()` has a single "not Linux" answer, so they are
    // dead there. Keep them rather than cfg-gating so the mapping from a kernel
    // state to a value stays in one place.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const fn available(abi: Abi) -> Self {
        Self {
            abi: Some(abi),
            detail: "available",
        }
    }

    /// Landlock exists in the kernel but is disabled at runtime.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const fn disabled() -> Self {
        Self {
            abi: None,
            detail: "EOPNOTSUPP: compiled in but not enabled at boot",
        }
    }

    /// Landlock is not implemented by this kernel.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const fn missing() -> Self {
        Self {
            abi: None,
            detail: "ENOSYS: kernel was built without CONFIG_SECURITY_LANDLOCK",
        }
    }

    /// The usable ABI, or `None` when Landlock cannot be used at all.
    pub const fn abi(self) -> Option<Abi> {
        self.abi
    }

    /// Whether Landlock is usable.
    pub const fn is_available(self) -> bool {
        self.abi.is_some()
    }

    /// A one-line explanation, for error messages and audit logs.
    pub const fn detail(self) -> &'static str {
        self.detail
    }
}

impl core::fmt::Display for KernelSupport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.abi {
            Some(abi) => write!(f, "landlock ABI {abi} ({})", self.detail),
            None => write!(f, "landlock unusable: {}", self.detail),
        }
    }
}

/// Probe the running kernel for Landlock support. Cached per process.
///
/// This performs `landlock_create_ruleset(NULL, 0, ...)` indirectly via the
/// `landlock` crate's ABI detection. It does **not** set
/// `PR_SET_NO_NEW_PRIVS` and does **not** call `landlock_restrict_self`, so it is
/// safe to call before committing to a profile.
#[cfg(target_os = "linux")]
pub fn detect() -> KernelSupport {
    use std::sync::OnceLock;
    static CACHE: OnceLock<KernelSupport> = OnceLock::new();
    *CACHE.get_or_init(probe_kernel)
}

#[cfg(target_os = "linux")]
fn probe_kernel() -> KernelSupport {
    use landlock::{LandlockStatus, RestrictSelf};

    // `RestrictSelf` with no flags and `no_new_privs(false)` is a pure probe:
    // `apply()` returns before `landlock_restrict_self` because there is no flag
    // to apply, and without `no_new_privs` it does not touch prctl either.
    let status = match RestrictSelf::default().no_new_privs(false).apply() {
        Ok(status) => status,
        Err(_) => return KernelSupport::missing(),
    };
    #[allow(unreachable_patterns)]
    match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => {
            // `kernel_abi` is Some() only when the kernel is newer than anything
            // the crate knows; prefer it so we can report "newer than V7".
            let raw = kernel_abi.unwrap_or(effective_abi as i32);
            match Abi::clamp(raw) {
                Some(abi) => KernelSupport::available(abi),
                None => KernelSupport {
                    abi: None,
                    detail: "kernel reported a non-positive landlock ABI",
                },
            }
        }
        LandlockStatus::NotEnabled => KernelSupport::disabled(),
        LandlockStatus::NotImplemented => KernelSupport::missing(),
        // `LandlockStatus` is `#[non_exhaustive]`. With landlock 0.4.7 it has
        // exactly the three variants above, so this arm is dead code *today* and
        // the compiler says so. It is kept, and the warning suppressed, on
        // purpose: if a future landlock release adds a variant we have not
        // classified, this arm turns it into a refusal instead of letting the
        // kernel's reported state be ignored. Classifying an unrecognised
        // status as usable would be precisely the fail-open bug this crate is
        // written to prevent, so the safe direction is the only one allowed here.
        _ => KernelSupport {
            abi: None,
            detail: "unrecognised landlock status reported by the landlock crate",
        },
    }
}

/// Landlock is a Linux LSM; there is nothing to detect elsewhere.
#[cfg(not(target_os = "linux"))]
pub fn detect() -> KernelSupport {
    KernelSupport {
        abi: None,
        detail: "not a Linux target",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_min_abi_matches_the_upstream_table() {
        assert_eq!(Feature::ReadFile.min_abi(), Abi::V1);
        assert_eq!(Feature::Refer.min_abi(), Abi::V2);
        assert_eq!(Feature::Truncate.min_abi(), Abi::V3);
        assert_eq!(Feature::NetConnectTcp.min_abi(), Abi::V4);
        assert_eq!(Feature::IoctlDev.min_abi(), Abi::V5);
        assert_eq!(Feature::ScopeSignal.min_abi(), Abi::V6);
    }

    #[test]
    fn every_feature_has_a_name() {
        // Guards against a new variant being added without a name, which would
        // make error messages say "Feature(17)".
        for f in [
            Feature::Execute,
            Feature::ReadFile,
            Feature::ReadDir,
            Feature::WriteFile,
            Feature::RemoveDir,
            Feature::RemoveFile,
            Feature::MakeChar,
            Feature::MakeDir,
            Feature::MakeReg,
            Feature::MakeSock,
            Feature::MakeFifo,
            Feature::MakeBlock,
            Feature::MakeSym,
            Feature::Refer,
            Feature::Truncate,
            Feature::IoctlDev,
            Feature::NetBindTcp,
            Feature::NetConnectTcp,
            Feature::ScopeSignal,
            Feature::ScopeAbstractUnixSocket,
            Feature::ResolveUnix,
        ] {
            assert!(!f.name().is_empty());
        }
    }

    #[test]
    fn clamp_never_invents_support() {
        assert_eq!(Abi::clamp(0), None);
        assert_eq!(Abi::clamp(-1), None);
        assert_eq!(Abi::clamp(1), Some(Abi::V1));
        assert_eq!(Abi::clamp(4), Some(Abi::V4));
        // A future kernel is clamped down, never up.
        assert_eq!(Abi::clamp(99), Some(Abi::V7));
    }

    #[test]
    fn max_of_is_the_strictest() {
        assert_eq!(
            Abi::max_of([Abi::V1, Abi::V6, Abi::V3]),
            Abi::V6
        );
        assert_eq!(Abi::max_of([]), Abi::V1);
    }

    #[test]
    fn support_display_is_readable() {
        let s = KernelSupport::available(Abi::V7);
        assert!(s.is_available());
        assert_eq!(s.abi(), Some(Abi::V7));
        assert!(format!("{s}").contains("ABI 7"));

        let s = KernelSupport::missing();
        assert!(!s.is_available());
        assert!(format!("{s}").contains("unusable"));
    }
}