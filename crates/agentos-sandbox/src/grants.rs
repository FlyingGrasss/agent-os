//! Typed filesystem and network grants.
//!
//! Each grant is a distinct Rust type with a private field so that the access
//! rights a caller gets are a property of the type they constructed, not of a
//! bitmask they assembled. `ReadOnly` cannot be widened into `ReadWrite` by
//! accident, and `NetGrant::ConnectTcp` is not reachable from a filesystem
//! grant.
//!
//! The private field also stops `ReadWrite("/tmp/../etc")` from being built by
//! struct literal syntax outside this module; callers go through
//! [`ReadOnly::new`] and friends.

use std::path::{Path, PathBuf};

use crate::abi::Feature;

/// Read-only access to a directory tree.
///
/// Grants exactly `LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR`.
/// **Not** `EXECUTE`: see [`ReadOnlyExec`] if the tree also holds code you
/// intend to run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadOnly(PathBuf);

impl ReadOnly {
    /// Grant read-only access to `path` and everything beneath it.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The granted root.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Read-only *and* executable access to a directory tree.
///
/// Grants `LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
/// LANDLOCK_ACCESS_FS_EXECUTE`. This is the normal grant for a tool's own
/// install directory: the binary has to be mapped from disk to be executed at
/// all.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadOnlyExec(PathBuf);

impl ReadOnlyExec {
    /// Grant read + execute access to `path` and everything beneath it.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The granted root.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Read-write access to a directory tree.
///
/// Grants every filesystem right [`crate::abi::TARGET_ABI`] defines: execute,
/// read, write, truncate, remove, make (all object kinds), refer, and ioctl on
/// device files. That is `AccessFs::from_all(ABI::V7)`, deliberately the whole
/// write set rather than a hand-picked subset: a caller asking for a writable
/// directory and silently not getting `REFER` or `TRUNCATE` would discover the
/// gap at runtime, in a tool, as an unexplained `EPERM`.
///
/// Requires kernel ABI V5 (the minimum for [`Feature::IoctlDev`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadWrite(PathBuf);

impl ReadWrite {
    /// Grant full read-write access to `path` and everything beneath it.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The granted root.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// A filesystem grant, tagged with the rights it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsGrant {
    /// See [`ReadOnly`].
    ReadOnly(ReadOnly),
    /// See [`ReadOnlyExec`].
    ReadOnlyExec(ReadOnlyExec),
    /// See [`ReadWrite`].
    ReadWrite(ReadWrite),
}

impl FsGrant {
    /// The granted root.
    pub fn path(&self) -> &Path {
        match self {
            FsGrant::ReadOnly(g) => g.path(),
            FsGrant::ReadOnlyExec(g) => g.path(),
            FsGrant::ReadWrite(g) => g.path(),
        }
    }

    /// The Landlock rights this grant relies on.
    pub fn features(&self) -> &'static [Feature] {
        match self {
            FsGrant::ReadOnly(_) => &[Feature::ReadFile, Feature::ReadDir],
            FsGrant::ReadOnlyExec(_) => &[Feature::ReadFile, Feature::ReadDir, Feature::Execute],
            FsGrant::ReadWrite(_) => crate::confine::READ_WRITE_FEATURES,
        }
    }
}

/// A TCP permission, scoped to a single port number.
///
/// # What this does and does not cover
///
/// `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP` are
/// **port-scoped only**. They do not filter by address, so a granted port means
/// "any address, that port". They also do not touch anything else at all: UDP,
/// raw sockets, ICMP, Unix sockets (unless the `AbstractUnixSocket` scope is
/// also enabled) and every other protocol remain available to a confined
/// process, and `socket(2)` itself still succeeds. A profile that gates TCP and
/// nothing else has **not** made a tool offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetGrant {
    /// Allow `bind(2)` on this TCP port. Port `0` means "any port in
    /// `/proc/sys/net/ipv4/ip_local_port_range`", per the kernel ABI.
    BindTcp(u16),
    /// Allow `connect(2)` to this TCP port.
    ConnectTcp(u16),
}

impl NetGrant {
    /// The port this grant names.
    pub const fn port(self) -> u16 {
        match self {
            NetGrant::BindTcp(p) | NetGrant::ConnectTcp(p) => p,
        }
    }

    /// The Landlock right this grant relies on.
    pub const fn feature(self) -> Feature {
        match self {
            NetGrant::BindTcp(_) => Feature::NetBindTcp,
            NetGrant::ConnectTcp(_) => Feature::NetConnectTcp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Abi;

    #[test]
    fn read_only_is_not_executable() {
        let g = FsGrant::ReadOnly(ReadOnly::new("/tmp"));
        assert_eq!(g.path(), Path::new("/tmp"));
        assert!(!g.features().contains(&Feature::Execute));
        assert!(!g.features().contains(&Feature::WriteFile));
        assert!(g.features().contains(&Feature::ReadFile));
        assert!(g.features().contains(&Feature::ReadDir));
    }

    #[test]
    fn read_only_exec_adds_execute_but_not_write() {
        let g = FsGrant::ReadOnlyExec(ReadOnlyExec::new("/opt/tool"));
        assert!(g.features().contains(&Feature::Execute));
        assert!(!g.features().contains(&Feature::WriteFile));
    }

    #[test]
    fn read_write_needs_the_full_write_set() {
        let g = FsGrant::ReadWrite(ReadWrite::new("/work"));
        for f in [
            Feature::ReadFile,
            Feature::ReadDir,
            Feature::Execute,
            Feature::WriteFile,
            Feature::RemoveDir,
            Feature::RemoveFile,
            Feature::MakeReg,
            Feature::MakeDir,
            Feature::MakeSock,
            Feature::MakeFifo,
            Feature::MakeChar,
            Feature::MakeBlock,
            Feature::MakeSym,
            Feature::Refer,
            Feature::Truncate,
            Feature::IoctlDev,
        ] {
            assert!(g.features().contains(&f), "missing {f:?}");
        }
        // Not ResolveUnix: that needs ABI V9, past this crate's target.
        assert!(!g.features().contains(&Feature::ResolveUnix));
        assert_eq!(
            Abi::max_of(g.features().iter().map(|f| f.min_abi())),
            Abi::V5
        );
    }

    #[test]
    fn net_grants_map_to_distinct_rights() {
        assert_eq!(NetGrant::BindTcp(8080).feature(), Feature::NetBindTcp);
        assert_eq!(
            NetGrant::ConnectTcp(443).feature(),
            Feature::NetConnectTcp
        );
        assert_eq!(NetGrant::BindTcp(8080).port(), 8080);
        assert_eq!(NetGrant::BindTcp(0).port(), 0);
    }
}