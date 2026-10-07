use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Identifies where a piece of data came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId(pub uuid::Uuid);

impl SourceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl SourceId {
    /// Placeholder origin for values recovered out of an enclosing quarantined
    /// document. Their real provenance is the enclosing document's label, which
    /// is why the interpreter carries that label across extraction.
    pub fn nil() -> Self {
        Self(uuid::Uuid::nil())
    }
}

impl Default for SourceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Broad category of an untrusted source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    WebPage,
    Email,
    ToolOutput,
    FileOnDisk,
    Dependency,
    ModelOutput,
}

/// Provenance label attached to every value.
///
/// `Trusted` means the value originated from the user or from a component the
/// user designated as trusted. `Tainted` means the value may have been
/// influenced by an attacker. A value derived from any tainted input is
/// tainted, and labels accumulate rather than overwrite: combining two tainted
/// values yields a label carrying both sources, so the union of all origins is
/// always recoverable for auditing and confirmation prompts.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Label {
    /// The `Default` is `Trusted`, which is the correct starting point for a
    /// value the planner authored and the worst starting point for an
    /// untrusted one. Code constructing `Label` from untrusted input must call
    /// `Label::tainted` explicitly rather than relying on `default()`.
    #[default]
    Trusted,
    Tainted {
        sources: BTreeSet<SourceId>,
    },
}

impl Label {
    pub fn tainted(source: SourceId) -> Self {
        let mut sources = BTreeSet::new();
        sources.insert(source);
        Label::Tainted { sources }
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, Label::Trusted)
    }

    pub fn is_tainted(&self) -> bool {
        !self.is_trusted()
    }

    /// Combine two labels. Any tainted operand taints the result.
    pub fn join(&self, other: &Label) -> Label {
        match (self, other) {
            (Label::Trusted, Label::Trusted) => Label::Trusted,
            (Label::Trusted, Label::Tainted { sources }) => Label::Tainted {
                sources: sources.clone(),
            },
            (Label::Tainted { sources }, Label::Trusted) => Label::Tainted {
                sources: sources.clone(),
            },
            (Label::Tainted { sources: a }, Label::Tainted { sources: b }) => {
                Label::Tainted {
                    sources: a.union(b).copied().collect(),
                }
            }
        }
    }

    pub fn sources(&self) -> BTreeSet<&SourceId> {
        match self {
            Label::Trusted => BTreeSet::new(),
            Label::Tainted { sources } => sources.iter().collect(),
        }
    }

    pub fn join_all(labels: impl IntoIterator<Item = Label>) -> Label {
        labels
            .into_iter()
            .fold(Label::Trusted, |acc, l| acc.join(&l))
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_join_trusted_is_trusted() {
        assert!(Label::Trusted.join(&Label::Trusted).is_trusted());
    }

    #[test]
    fn tainted_contaminates_either_direction() {
        let s = SourceId::new();
        assert!(Label::Trusted.join(&Label::tainted(s)).is_tainted());
        assert!(Label::tainted(s).join(&Label::Trusted).is_tainted());
    }

    #[test]
    fn joining_two_taints_unions_sources() {
        let a = SourceId::new();
        let b = SourceId::new();
        let joined = Label::tainted(a).join(&Label::tainted(b));
        assert_eq!(joined.sources().len(), 2);
        assert!(joined.sources().contains(&&a));
        assert!(joined.sources().contains(&&b));
    }

    #[test]
    fn idempotent_under_self_join() {
        let a = SourceId::new();
        assert_eq!(Label::tainted(a).join(&Label::tainted(a)), Label::tainted(a));
    }
}
