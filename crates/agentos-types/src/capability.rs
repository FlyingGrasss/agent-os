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
///
/// ## Why a handle is checked at use, not at issue
///
/// `Cap<K>` is `Copy` and its id is unforgeable, so a handle outlives the
/// registry entry that produced it. If the registry only *recorded* revocation,
/// a tool holding a stale handle would keep working forever, and revocation
/// would be a documentation claim rather than a control. So [`CapRegistry`] is
/// the authority on liveness: every point where a handle is turned into an
/// effect asks it, and a revoked handle is refused. A `Cap<K>` on its own
/// therefore proves nothing - `CapabilityError::Revoked` is what a caller gets.
///
/// Ids are never reused. Reuse would make a stale handle indistinguishable from
/// a fresh one, which is the same class of bug as a reused fd.
pub struct CapRegistry {
    next_id: u64,
    live: std::collections::BTreeSet<CapId>,
    /// Which parent each delegated handle came from, so revoking the parent
    /// revokes the delegation transitively.
    delegated_by: std::collections::BTreeMap<CapId, CapId>,
}

impl CapRegistry {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            live: std::collections::BTreeSet::new(),
            delegated_by: std::collections::BTreeMap::new(),
        }
    }

    /// Mint a capability and record it as live.
    pub fn issue<K: CapKind>(&mut self) -> Cap<K> {
        let id = CapId(self.next_id);
        self.next_id += 1;
        self.live.insert(id);
        Cap::new(id)
    }

    /// Revoke a capability, so every outstanding handle to it stops working.
    ///
    /// Idempotent: revoking an already-revoked id reports `false` rather than
    /// panicking, because a caller reacting to a failed revoke by continuing
    /// anyway is exactly the case where the return value must be trustworthy.
    /// `false` means "was not live", which covers both never-issued and
    /// already-revoked.
    ///
    /// The Linux half - closing the descriptor the handle referred to - happens
    /// in the broker that owns the resource; this type owns liveness only, and
    /// deliberately keeps no resource handles so it stays portable.
    pub fn revoke(&mut self, id: CapId) -> bool {
        let was_live = self.live.remove(&id);
        self.delegated_by.remove(&id);
        // A delegation cannot outlast the authority it came from. Without this
        // cascade, revoking a parent would leave every attenuated child working,
        // which is the shape of bug a capability system is supposed to make
        // impossible.
        let children: Vec<CapId> = self
            .delegated_by
            .iter()
            .filter(|(_, parent)| **parent == id)
            .map(|(child, _)| *child)
            .collect();
        for child in children {
            self.revoke(child);
        }
        was_live
    }

    /// Whether a capability is still live.
    pub fn is_live(&self, id: CapId) -> bool {
        self.live.contains(&id)
    }

    /// Refuse a handle that is no longer live.
    ///
    /// The check every enforcement point makes. `Err` here is what makes
    /// revocation mean something.
    pub fn authorise<K: CapKind>(&self, cap: &Cap<K>) -> Result<(), CapabilityError> {
        if self.live.contains(&cap.id) {
            Ok(())
        } else if cap.id.0 >= self.next_id {
            Err(CapabilityError::NeverIssued { id: cap.id })
        } else {
            Err(CapabilityError::Revoked { id: cap.id })
        }
    }

    /// Mint a capability that is already attenuated to a narrower kind.
    ///
    /// The child is live only while the parent is: revoking the parent revokes
    /// the child, because an attenuated handle is a *delegation* of the parent
    /// and cannot outlast it. Returns `None` if the parent is not live, so a
    /// caller cannot manufacture a live handle from a dead one.
    pub fn attenuate<P: CapKind, C: CapKind>(&mut self, parent: &Cap<P>) -> Option<Cap<C>> {
        if !self.live.contains(&parent.id) {
            return None;
        }
        let id = CapId(self.next_id);
        self.next_id += 1;
        self.live.insert(id);
        self.delegated_by.insert(id, parent.id);
        Some(Cap::new(id))
    }
}

/// Why a capability handle was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    #[error("capability {id:?} was revoked and must no longer be used")]
    Revoked { id: CapId },
    #[error("capability {id:?} was never issued by this registry")]
    NeverIssued { id: CapId },
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
        // Idempotent: the second revoke reports "was not live" rather than
        // panicking, and a caller reacting to a failed revoke by pressing on is
        // precisely the case where that return value has to be honest.
        assert!(!reg.revoke(a.id()));
        assert!(!reg.revoke(CapId(9_999)));
    }

    #[test]
    fn a_revoked_handle_stops_working() {
        // The point of the whole change. Before, `revoke` returned a bool and
        // nothing consulted it, so a stale handle kept its authority forever.
        let mut reg = CapRegistry::new();
        let a: Cap<FsRead> = reg.issue();
        assert!(reg.authorise(&a).is_ok());
        reg.revoke(a.id());
        let err = reg.authorise(&a).expect_err("a revoked handle must be refused");
        assert_eq!(err, CapabilityError::Revoked { id: a.id() });
    }

    #[test]
    fn revoking_the_parent_revokes_every_attenuated_child() {
        let mut reg = CapRegistry::new();
        let parent: Cap<FsRead> = reg.issue();
        let child: Cap<FsWrite> = reg.attenuate(&parent).expect("live parent");
        let grandchild: Cap<FsWrite> = reg.attenuate(&child).expect("live child");

        reg.revoke(parent.id());

        assert_eq!(
            reg.authorise(&child).unwrap_err(),
            CapabilityError::Revoked { id: child.id() },
            "an attenuated child outlived the authority it was delegated from"
        );
        assert_eq!(
            reg.authorise(&grandchild).unwrap_err(),
            CapabilityError::Revoked { id: grandchild.id() },
            "revocation must cascade transitively, not just one level"
        );
        assert!(reg.authorise(&parent).is_err());
    }

    #[test]
    fn an_attenuation_cannot_be_minted_from_a_dead_handle() {
        // Otherwise revocation has a bypass: take a revoked handle, attenuate it,
        // and you are live again.
        let mut reg = CapRegistry::new();
        let parent: Cap<FsRead> = reg.issue();
        reg.revoke(parent.id());
        assert!(
            reg.attenuate::<FsRead, FsWrite>(&parent).is_none(),
            "a dead handle must not delegate"
        );
    }

    #[test]
    fn ids_are_never_reused() {
        // A reused id makes a stale handle indistinguishable from a fresh one,
        // which is the same class of bug as a recycled file descriptor.
        let mut reg = CapRegistry::new();
        let a: Cap<FsRead> = reg.issue();
        reg.revoke(a.id());
        let b: Cap<FsRead> = reg.issue();
        assert_ne!(a.id(), b.id());
        assert!(reg.authorise(&a).is_err());
        assert!(reg.authorise(&b).is_ok());
    }

    #[test]
    fn an_unknown_id_is_reported_as_never_issued() {
        // Distinct from revoked, because the two mean different things to an
        // operator reading the audit log: one is a bug, the other is policy.
        let reg = CapRegistry::new();
        let never: Cap<FsRead> = Cap::new(CapId(4_000));
        assert_eq!(
            reg.authorise(&never).unwrap_err(),
            CapabilityError::NeverIssued { id: CapId(4_000) }
        );
    }
}
