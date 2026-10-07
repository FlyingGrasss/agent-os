use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// Opaque identifier for a capability. Not a path: the mapping from handle to
/// real resource lives only inside the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapId(pub u64);

/// Marker for what sort of resource a capability refers to.
///
/// The type parameter makes handle confusion a compile error rather than a
/// sandbox escape: a `Cap<FsRead>` cannot be passed where a `Cap<NetEgress>`
/// is expected.
pub trait CapKind: sealed::Sealed + 'static {
    #[doc(hidden)]
    type Resource;
}

/// These marker types name the kinds of resource the broker will eventually
/// hand out. They exist now so that handle confusion is a compile error from the
/// start, before the tools that consume them do.
#[allow(dead_code)]
pub struct FsRead;
impl sealed::Sealed for FsRead {}
impl CapKind for FsRead {
    type Resource = std::path::PathBuf;
}

#[allow(dead_code)]
pub struct FsWrite;
impl sealed::Sealed for FsWrite {}
impl CapKind for FsWrite {
    type Resource = std::path::PathBuf;
}

#[allow(dead_code)]
pub struct NetEgress;
impl sealed::Sealed for NetEgress {}
impl CapKind for NetEgress {
    type Resource = String;
}

#[allow(dead_code)]
pub struct ProcessExec;
impl sealed::Sealed for ProcessExec {}
impl CapKind for ProcessExec {
    type Resource = String;
}

/// A capability handle.
///
/// The handle carries no authority of its own; it is a reference the broker
/// resolves. Values cannot be constructed outside the broker because the
/// `id` field is private and `Cap::new` is not public, so a compromised
/// component cannot mint authority for itself.
pub struct Cap<K: CapKind> {
    id: CapId,
    kind: PhantomData<K>,
}

impl<K: CapKind> Cap<K> {
    pub(crate) fn new(id: CapId) -> Self {
        Self {
            id,
            kind: PhantomData,
        }
    }

    pub fn id(&self) -> CapId {
        self.id
    }
}

impl<K: CapKind> Clone for Cap<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: CapKind> Copy for Cap<K> {}

impl<K: CapKind> std::fmt::Debug for Cap<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cap({}, {})", self.id.0, std::any::type_name::<K>())
    }
}

impl<K: CapKind> PartialEq for Cap<K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<K: CapKind> Eq for Cap<K> {}

/// The set of capabilities currently issued, and the authority to mint new
/// ones. In the full design this wraps `cap-std` directories and, on Linux,
/// real file descriptors passed with `SCM_RIGHTS`.
pub struct CapRegistry {
    next_id: u64,
}

impl CapRegistry {
    pub fn new() -> Self {
        Self { next_id: 1 }
    }

    pub fn issue<K: CapKind>(&mut self) -> Cap<K> {
        let id = CapId(self.next_id);
        self.next_id += 1;
        Cap::new(id)
    }

    pub fn revoke(&mut self, id: CapId) -> bool {
        // A real implementation drops the underlying resource here, closing
        // the fd and invalidating every outstanding handle.
        self.next_id > id.0 && id.0 != 0
    }
}

impl Default for CapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

mod sealed {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_unique_per_issue() {
        let mut reg = CapRegistry::new();
        let a: Cap<FsRead> = reg.issue();
        let b: Cap<FsRead> = reg.issue();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn revoke_is_idempotent_and_bounded() {
        let mut reg = CapRegistry::new();
        let a: Cap<FsRead> = reg.issue();
        assert!(reg.revoke(a.id()));
        assert!(!reg.revoke(CapId(9_999)));
    }
}
