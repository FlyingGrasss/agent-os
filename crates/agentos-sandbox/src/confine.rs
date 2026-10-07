//! [`Confine`]: build a Landlock ruleset from typed grants and apply it to the
//! calling thread.
//!
//! # Shape of a profile
//!
//! Everything is denied by default and every grant is an explicit widening:
//!
//! | Concern | Default | Widened by |
//! |---|---|---|
//! | filesystem | every V7 right handled, no path allowed | [`Confine::read_only`], [`Confine::read_only_exec`], [`Confine::read_write`] |
//! | TCP bind/connect | handled, no port allowed | [`Confine::allow_tcp_bind`], [`Confine::allow_tcp_connect`] |
//! | signalling other processes | `Scope::Signal` on | (nothing; there is no opt-out) |
//! | abstract UNIX sockets | `Scope::AbstractUnixSocket` on | [`Confine::allow_abstract_unix_socket`] |
//!
//! The deny-by-default filesystem stance is what forces the ABI floor to V5: to
//! *deny* a right the ruleset must handle it, and handling all of them means
//! handling `IOCTL_DEV`, which is V5.
//!
//! # What this does not confine
//!
//! Landlock is a filesystem (plus a little TCP) LSM. It is **not** a syscall
//! filter and **not** a resource limiter. Confined processes retain:
//!
//! - every syscall not restricted by the rights above, including `socket(2)`,
//!   `clone`, `ptrace`-adjacent behaviour, `mmap` with arbitrary flags,
//!   `keyctl`, `perf_event_open`, `io_uring`, and `bpf(2)`;
//! - UDP, raw sockets, ICMP and every non-TCP protocol;
//! - access to every file descriptor inherited at exec time, because Landlock
//!   constrains *path-based* access and cannot revoke an fd it did not see
//!   (invariant I5 is therefore enforced by handing the child a small fd set,
//!   not by Landlock alone);
//! - CPU, memory and process counts.
//!
//! Those need seccomp, cgroup v2 and namespaces respectively. On the WSL2 host
//! this was developed against, cgroup v2 and user/mount namespaces are both
//! unavailable to an unprivileged uid, so neither is used; see the crate-level
//! docs.
//!
//! # Threading
//!
//! `landlock_restrict_self(2)` without `LANDLOCK_RESTRICT_SELF_TSYNC` restricts
//! only the **calling thread**. Tapping every thread needs ABI V8's TSYNC flag,
//! which this crate does not use, because AgentOS confines a freshly forked,
//! single-threaded child: the rule "confine after fork, before exec" is simpler
//! to reason about than "confine a running thread pool" and leaves no
//! unconfined window in the child's own address space.

use std::path::PathBuf;

// `TARGET_ABI` is only read from Linux paths, hence the cfg on the import.
#[cfg(target_os = "linux")]
use crate::abi::TARGET_ABI;
use crate::abi::{Abi, Feature};
use crate::error::ConfineError;
use crate::grants::{FsGrant, NetGrant};

#[cfg(target_os = "linux")]
use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

/// The filesystem rights a [`ReadWrite`](crate::grants::ReadWrite) grant carries.
///
/// Kept as data so the required-ABI computation and the ruleset builder cannot
/// drift apart.
pub(crate) const READ_WRITE_FEATURES: &[Feature] = &[
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
];

/// A filesystem profile under construction.
///
/// Build it with [`Confine::new`] and apply it with [`Confine::apply`].
#[derive(Debug, Clone, Default)]
pub struct Confine {
    fs: Vec<FsGrant>,
    net: Vec<NetGrant>,
    allow_abstract_unix_socket: bool,
    abi_floor: Option<Abi>,
}

/// Proof that the ruleset was applied.
///
/// There is no way to obtain one without a successful `landlock_restrict_self`
/// that the kernel reported as fully enforced. Holding an `Enforced` is the
/// signal to spawn the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforced {
    abi: Abi,
    fs_rules: usize,
    net_rules: usize,
}

impl Enforced {
    /// The Landlock ABI the ruleset was built for (never above [`TARGET_ABI`]).
    pub const fn abi(self) -> Abi {
        self.abi
    }

    /// Number of `path_beneath` rules installed.
    pub const fn fs_rules(self) -> usize {
        self.fs_rules
    }

    /// Number of TCP port rules installed.
    ///
    /// Zero with TCP handled means "TCP bind and connect are denied everywhere".
    pub const fn net_rules(self) -> usize {
        self.net_rules
    }
}

impl Confine {
    /// A profile that denies the entire filesystem and all TCP.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow reading (not executing, not writing) everything under `path`.
    pub fn read_only(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs
            .push(FsGrant::ReadOnly(crate::grants::ReadOnly::new(path)));
        self
    }

    /// Allow reading and executing everything under `path`.
    pub fn read_only_exec(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs
            .push(FsGrant::ReadOnlyExec(crate::grants::ReadOnlyExec::new(
                path,
            )));
        self
    }

    /// Allow the full write set under `path`.
    ///
    /// Requires kernel ABI V5.
    pub fn read_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.fs
            .push(FsGrant::ReadWrite(crate::grants::ReadWrite::new(path)));
        self
    }

    /// Allow `bind(2)` on one TCP port. Port `0` allows the whole ephemeral
    /// range from `/proc/sys/net/ipv4/ip_local_port_range`.
    pub fn allow_tcp_bind(mut self, port: u16) -> Self {
        self.net.push(NetGrant::BindTcp(port));
        self
    }

    /// Allow `connect(2)` to one TCP port, on any address.
    pub fn allow_tcp_connect(mut self, port: u16) -> Self {
        self.net.push(NetGrant::ConnectTcp(port));
        self
    }

    /// Permit `connect(2)` to abstract-namespace UNIX sockets.
    ///
    /// Off by default. Only widen this if the tool genuinely talks to a sibling
    /// agent over an abstract socket, and remember that the grant is
    /// all-or-nothing: there is no way to name a single abstract socket.
    pub fn allow_abstract_unix_socket(mut self) -> Self {
        self.allow_abstract_unix_socket = true;
        self
    }

    /// Raise the kernel ABI requirement above what the profile strictly needs.
    ///
    /// Useful to pin a host so that a later kernel upgrade cannot change the
    /// enforcement semantics under a running deployment.
    pub fn require_at_least(mut self, abi: Abi) -> Self {
        self.abi_floor = Some(match self.abi_floor {
            Some(cur) if cur > abi => cur,
            _ => abi,
        });
        self
    }

    /// The Landlock rights this profile depends on, sorted and deduplicated.
    pub fn required_features(&self) -> Vec<Feature> {
        let mut features: Vec<Feature> = Vec::new();

        // Deny-by-default: the ruleset *handles* the whole V7 filesystem set even
        // when no path is granted, otherwise "ungranted" would mean
        // "unrestricted" for every right we did not think to mention.
        features.extend_from_slice(READ_WRITE_FEATURES);

        if !self.allow_abstract_unix_socket {
            features.push(Feature::ScopeAbstractUnixSocket);
        }
        features.push(Feature::ScopeSignal);

        for grant in &self.fs {
            features.extend_from_slice(grant.features());
        }
        // TCP bind/connect are handled unconditionally (see the module docs), so
        // they are always required.
        features.push(Feature::NetBindTcp);
        features.push(Feature::NetConnectTcp);

        features.sort_unstable();
        features.dedup();
        features
    }

    /// The lowest kernel ABI that can enforce this profile.
    pub fn required_abi(&self) -> Abi {
        let from_features = Abi::max_of(self.required_features().iter().map(|f| f.min_abi()));
        Abi::max_of([from_features, self.abi_floor.unwrap_or(Abi::V1)])
    }
}

#[cfg(target_os = "linux")]
impl Confine {
    /// Apply the ruleset to the calling thread.
    ///
    /// On success the calling thread - and every process it subsequently
    /// `fork`s or `exec`s - is confined. The call is irreversible for this
    /// thread.
    ///
    /// Order of operations, and why:
    ///
    /// 1. detect Landlock support and compare ABI levels against the documented
    ///    matrix; refuse before touching anything if the kernel is too old;
    /// 2. `prctl(PR_SET_NO_NEW_PRIVS, 1)`, then read it back;
    /// 3. create the ruleset with `CompatLevel::HardRequirement`, so the
    ///    `landlock` crate itself refuses to drop any right we asked for;
    /// 4. `landlock_restrict_self`;
    /// 5. check the returned status is `FullyEnforced`.
    ///
    /// Step 2 is not optional. `PR_SET_NO_NEW_PRIVS` defaults to 0 in a fresh
    /// process, and without it step 4 fails with `EPERM` and, were it to
    /// succeed via `CAP_SYS_ADMIN`, a setuid exec could lift the ruleset.
    pub fn apply(self) -> Result<Enforced, ConfineError> {
        let support = crate::abi::detect();
        let Some(kernel_abi) = support.abi() else {
            return Err(ConfineError::LandlockUnavailable { support });
        };

        let required = self.required_abi();
        if kernel_abi < required {
            let floor = Abi::max_of([required, self.abi_floor.unwrap_or(Abi::V1)]);
            let missing: Vec<Feature> = self
                .required_features()
                .into_iter()
                .filter(|f| f.min_abi() > kernel_abi)
                .collect();
            return Err(ConfineError::AbiTooOld {
                kernel: kernel_abi,
                required: floor,
                features: missing,
            });
        }

        set_no_new_privs()?;

        let target = landlock::ABI::V7;
        debug_assert_eq!(target as i32, TARGET_ABI as i32);

        // Handle every filesystem right we know about, whether or not a path is
        // granted. `from_all(TARGET_ABI)`, never `AccessFs::all()`: the latter
        // moves with the `landlock` crate's version and could silently enable a
        // right whose semantics we have not vetted.
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(target))?
            .handle_access(AccessNet::from_all(target))?
            .scope(self.scope_flags())?
            .create()?;

        let fs_rule_count = self.fs.len();
        let net_rule_count = self.net.len();

        let ruleset = ruleset.add_rules(self.fs_rules())?;
        let ruleset = ruleset.add_rules(self.net_rules())?;
        let status = ruleset.restrict_self()?;

        check_status(status)?;

        Ok(Enforced {
            abi: TARGET_ABI,
            fs_rules: fs_rule_count,
            net_rules: net_rule_count,
        })
    }

    fn scope_flags(&self) -> landlock::BitFlags<Scope> {
        if self.allow_abstract_unix_socket {
            Scope::Signal.into()
        } else {
            Scope::Signal | Scope::AbstractUnixSocket
        }
    }

    fn fs_rules(&self) -> impl Iterator<Item = Result<PathBeneath<PathFd>, ConfineError>> + '_ {
        self.fs.iter().map(|grant| {
            let path = grant.path();
            // Deliberately not `landlock::path_beneath_rules()`, which silently
            // drops paths it cannot open. A missing grant is a hole, so an
            // unopenable path is an error.
            let fd = PathFd::new(path).map_err(|source| ConfineError::GrantPath {
                path: path.to_path_buf(),
                source: Box::new(source),
            })?;
            let access = access_for(grant);
            Ok(PathBeneath::new(fd, access))
        })
    }

    fn net_rules(&self) -> impl Iterator<Item = Result<NetPort, ConfineError>> + '_ {
        self.net.iter().map(|grant| {
            Ok(match grant {
                NetGrant::BindTcp(port) => NetPort::new(*port, AccessNet::BindTcp),
                NetGrant::ConnectTcp(port) => NetPort::new(*port, AccessNet::ConnectTcp),
            })
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl Confine {
    /// Always fails: Landlock is a Linux LSM.
    ///
    /// Kept so cross-platform callers get a runtime refusal with a clear message
    /// rather than a link error or, worse, an unconfined spawn.
    pub fn apply(self) -> Result<Enforced, ConfineError> {
        Err(ConfineError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn access_for(grant: &FsGrant) -> landlock::BitFlags<AccessFs> {
    match grant {
        // No EXECUTE: ReadOnly is about data, not code.
        FsGrant::ReadOnly(_) => AccessFs::ReadFile | AccessFs::ReadDir,
        FsGrant::ReadOnlyExec(_) => AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute,
        FsGrant::ReadWrite(_) => AccessFs::from_all(landlock::ABI::V7),
    }
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<(), ConfineError> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, ...) takes no pointer arguments.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(ConfineError::NoNewPrivs {
            source: std::io::Error::last_os_error(),
        });
    }
    // Read it back rather than trusting the return value: a ruleset that is not
    // backed by no_new_privs can be shed by a setuid exec.
    // SAFETY: as above; PR_GET_NO_NEW_PRIVS writes nothing.
    let got = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if got != 1 {
        return Err(ConfineError::NoNewPrivsNotSticky);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_status(status: RestrictionStatus) -> Result<(), ConfineError> {
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(ConfineError::PartiallyEnforced {
            status: format!(
                "ruleset={:?} landlock={:?} no_new_privs={}",
                status.ruleset, status.landlock, status.no_new_privs
            ),
        });
    }
    if !status.no_new_privs {
        return Err(ConfineError::NoNewPrivsUnconfirmed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{ReadOnly, ReadOnlyExec, ReadWrite};

    fn abi_of(features: &[Feature]) -> Abi {
        Abi::max_of(features.iter().map(|f| f.min_abi()))
    }

    #[test]
    fn default_profile_denies_everything() {
        let c = Confine::new();
        // Deny-by-default handles the whole V7 filesystem set (so the floor is at
        // least V5, from IOCTL_DEV) and both scopes by default (V6). So the
        // default profile needs V6: Linux 6.12.
        assert_eq!(c.required_abi(), Abi::V6);
        assert!(c.required_features().contains(&Feature::ReadFile));
        assert!(c.required_features().contains(&Feature::WriteFile));
        assert!(c.required_features().contains(&Feature::Truncate));
        assert!(c.required_features().contains(&Feature::Refer));
        assert!(c.required_features().contains(&Feature::IoctlDev));
        assert!(c.required_features().contains(&Feature::ScopeSignal));
        assert!(c.required_features().contains(&Feature::ScopeAbstractUnixSocket));
        // TCP is gated even with no ports granted.
        assert!(c
            .required_features()
            .contains(&Feature::NetBindTcp));
        assert!(c
            .required_features()
            .contains(&Feature::NetConnectTcp));
        // V9's RESOLVE_UNIX is never requested.
        assert!(!c.required_features().contains(&Feature::ResolveUnix));
    }

    #[test]
    fn readonly_grant_alone_does_not_raise_the_floor() {
        let c = Confine::new().read_only("/tmp");
        // The filesystem grant adds nothing to the floor: the whole V7 set is
        // already being denied, so ReadOnly's V1 minimums are subsumed.
        assert_eq!(c.required_abi(), Abi::V6);
    }

    #[test]
    fn abstract_unix_socket_optout_lowers_the_floor_nothing_else_does() {
        let c = Confine::new().allow_abstract_unix_socket();
        // Still V6: Scope::Signal is always on, and it is also V6.
        assert_eq!(c.required_abi(), Abi::V6);
        assert!(!c.required_features().contains(&Feature::ScopeAbstractUnixSocket));
        // The filesystem floor is V5 on its own; the scopes are what push it to
        // V6. Assert that by removing the scopes entirely.
        assert!(Abi::max_of(READ_WRITE_FEATURES.iter().map(|f| f.min_abi())) >= Abi::V5);
    }

    #[test]
    fn explicit_floor_can_be_raised() {
        let c = Confine::new().require_at_least(Abi::V7);
        assert_eq!(c.required_abi(), Abi::V7);
        // Never lowered by a later, lower request.
        assert_eq!(c.require_at_least(Abi::V2).required_abi(), Abi::V7);
    }

    #[test]
    fn required_features_are_sorted_and_deduped() {
        let f = Confine::new()
            .read_only("/a")
            .read_only_exec("/b")
            .read_write("/c")
            .allow_tcp_bind(1)
            .allow_tcp_connect(2)
            .required_features();
        let mut sorted = f.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(f, sorted);
    }

    #[test]
    fn feature_table_covers_the_grants() {
        assert_eq!(
            abi_of(FsGrant::ReadOnly(ReadOnly::new("/a")).features()),
            Abi::V1
        );
        assert_eq!(
            abi_of(FsGrant::ReadOnlyExec(ReadOnlyExec::new("/a")).features()),
            Abi::V1
        );
        assert_eq!(
            abi_of(FsGrant::ReadWrite(ReadWrite::new("/a")).features()),
            Abi::V5
        );
        assert_eq!(abi_of(&[Feature::NetConnectTcp]), Abi::V4);
        assert_eq!(abi_of(&[Feature::Truncate]), Abi::V3);
        assert_eq!(abi_of(&[Feature::Refer]), Abi::V2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unopenable_grant_path_would_be_an_error_not_a_silent_drop() {
        // Cannot call apply() here: it would confine this test thread, which is
        // exactly why every enforcement assertion lives in tests/escape.rs
        // inside a spawned child. This checks the rule-building helper only.
        let conf = Confine::new().read_only("/agentos/definitely/not/here");
        let results: Vec<_> = conf.fs_rules().collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results.into_iter().next().unwrap(),
            Err(ConfineError::GrantPath { .. })
        ));
    }
}