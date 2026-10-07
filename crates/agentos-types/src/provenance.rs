use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Identifies where a piece of data came from, and what kind of source it was.
///
/// The kind travels with the identifier rather than living in a parallel map,
/// so a [`SourceId`] cannot be carried around, logged, or stored without also
/// carrying the category the user needs to see when asked to confirm a value.
/// A bare UUID tells an audit log *which* origin and nothing about *what* it
/// was, which is exactly the information a user judging a confirmation prompt
/// is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId {
    id: uuid::Uuid,
    kind: SourceKind,
}

impl SourceId {
    /// A fresh identifier whose kind is not yet known.
    ///
    /// Prefer [`SourceId::of_kind`] or [`Label::from_source`] anywhere the
    /// origin is actually known. `new` exists because a UUID is generated
    /// before the caller has classified it, and it degrades to
    /// [`SourceKind::Unattributed`], which renders as untrusted but names no
    /// origin.
    pub fn new() -> Self {
        Self::of_kind(SourceKind::Unattributed)
    }

    /// A fresh identifier for a source of a known kind.
    pub fn of_kind(kind: SourceKind) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            kind,
        }
    }

    /// Re-file an existing identifier under a different kind. The identity is
    /// preserved; only the category is corrected.
    pub fn with_kind(self, kind: SourceKind) -> Self {
        Self { id: self.id, kind }
    }

    /// What kind of untrusted source this identifier names.
    pub fn kind(&self) -> SourceKind {
        self.kind
    }

    /// The raw identity, without the category.
    pub fn uuid(&self) -> uuid::Uuid {
        self.id
    }
}

impl SourceId {
    /// Placeholder origin for values recovered out of an enclosing quarantined
    /// document. Their real provenance is the enclosing document's label, which
    /// is why the interpreter carries that label across extraction. Like
    /// [`SourceId::new`] it is unattributed; the enclosing label is what knows.
    pub fn nil() -> Self {
        Self {
            id: uuid::Uuid::nil(),
            kind: SourceKind::Unattributed,
        }
    }
}

impl Default for SourceId {
    fn default() -> Self {
        Self::new()
    }
}

/// Broad category of an untrusted source.
///
/// Recorded on every [`SourceId`] so that a confirmation prompt and the audit
/// log can say *what* the bytes are, not merely that some unidentified thing
/// produced them. This is load-bearing for invariant I4: a user asked to
/// approve a recipient cannot make a sensible decision from a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    WebPage,
    Email,
    ToolOutput,
    FileOnDisk,
    Dependency,
    ModelOutput,
    /// The value is known to be untrusted but the origin could not be
    /// attributed, either because the source was registered without a kind or
    /// because the bytes arrived from the wire with no provenance attached.
    ///
    /// This is not a safe default that may be rendered as blank or omitted: it
    /// must still render as untrusted, because failing to name a source is not
    /// the same as having no source.
    Unattributed,
}

impl SourceKind {
    /// Human-readable name for confirmation prompts and audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::WebPage => "web page",
            SourceKind::Email => "email message",
            SourceKind::ToolOutput => "tool output",
            SourceKind::FileOnDisk => "file on disk",
            SourceKind::Dependency => "dependency metadata",
            SourceKind::ModelOutput => "model output",
            SourceKind::Unattributed => "unattributed untrusted source",
        }
    }
}

/// Provenance label attached to every value.
///
/// `Trusted` means the value originated from the user or from a component the
/// user designated as trusted. `Tainted` means the value may have been
/// influenced by an attacker. A value derived from any tainted input is
/// tainted, and labels accumulate rather than overwrite: combining two tainted
/// values yields a label carrying both sources, so the union of all origins is
/// always recoverable for auditing and confirmation prompts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Label {
    /// No `Default` derive, deliberately.
    ///
    /// `Label::default() == Trusted` is the right answer for a value the planner
    /// authored and the wrong answer for an untrusted one, and an ingest path that
    /// forgets to label something would have silently produced trust. Removing
    /// the impl makes that a compile error at every call site, so the choice has
    /// to be written down rather than remembered. Construct a label
    /// explicitly: [`Label::Trusted`] for planner output, [`Label::tainted`] or
    /// [`Label::from_source`] for everything else.
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

    /// Label a value as tainted, recording *what kind* of source it came from.
    ///
    /// This is the constructor every untrusted ingest path should use. It is
    /// separate from [`Label::tainted`] because the kind is the part a human
    /// reads before deciding whether to confirm, and a source registered
    /// without one cannot be rendered as anything but "unattributed".
    pub fn from_source(source: SourceId, kind: SourceKind) -> Self {
        Label::tainted(source.with_kind(kind))
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, Label::Trusted)
    }

    pub fn is_tainted(&self) -> bool {
        !self.is_trusted()
    }

    /// Combine two labels. Any tainted operand taints the result.
    ///
    /// Sources accumulate rather than overwrite, and because each source
    /// carries its [`SourceKind`], accumulating ids accumulates kinds with
    /// them: joining a value from a web page with one from an email yields a
    /// label that reports both origins.
    ///
    /// Two sources sharing a uuid but disagreeing about their kind are both
    /// kept. That is a contradictory attribution, and reporting it beats
    /// silently picking one.
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

    /// The distinct kinds of untrusted source that contributed to this value,
    /// for rendering in a confirmation prompt or an audit record.
    ///
    /// Never empty for a tainted label that has at least one source, because
    /// every [`SourceId`] carries a kind and unattributed sources report
    /// [`SourceKind::Unattributed`] rather than nothing.
    pub fn source_kinds(&self) -> BTreeSet<SourceKind> {
        self.sources().into_iter().map(|s| s.kind()).collect()
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

    // --- Source kind is recorded, not inferred from a bare UUID. ---

    #[test]
    fn from_source_records_the_kind() {
        let label = Label::from_source(SourceId::new(), SourceKind::WebPage);
        assert_eq!(label.source_kinds(), [SourceKind::WebPage].into_iter().collect());
    }

    #[test]
    fn from_source_reclassifies_an_id_without_changing_its_identity() {
        let s = SourceId::new();
        let label = Label::from_source(s, SourceKind::Email);
        let source = label.sources().into_iter().next().copied().unwrap();
        assert_eq!(source.uuid(), s.uuid(), "the identity must not change");
        assert_eq!(source.kind(), SourceKind::Email);
    }

    #[test]
    fn joining_two_differently_kinded_taints_reports_both_kinds() {
        let page = Label::from_source(SourceId::new(), SourceKind::WebPage);
        let mail = Label::from_source(SourceId::new(), SourceKind::Email);
        let joined = page.join(&mail);

        assert_eq!(
            joined.source_kinds(),
            [SourceKind::WebPage, SourceKind::Email].into_iter().collect()
        );
        // Both ids are still recoverable for the audit log.
        assert_eq!(joined.sources().len(), 2);
    }

    #[test]
    fn joining_tainted_with_trusted_keeps_the_kinds() {
        let page = Label::from_source(SourceId::new(), SourceKind::WebPage);
        assert_eq!(page.join(&Label::Trusted).source_kinds(), [SourceKind::WebPage].into_iter().collect());
        assert_eq!(Label::Trusted.join(&page).source_kinds(), [SourceKind::WebPage].into_iter().collect());
    }

    #[test]
    fn a_source_with_no_recorded_kind_is_unattributed_not_silent() {
        // `SourceId::new` is what a caller with an origin but no classification
        // reaches for. It must still report as tainted and still name something
        // a user can read.
        let label = Label::tainted(SourceId::new());
        assert!(label.is_tainted());
        assert_eq!(label.source_kinds(), [SourceKind::Unattributed].into_iter().collect());
        assert_ne!(SourceKind::Unattributed.as_str(), "");
    }

    #[test]
    fn trusted_reports_no_sources() {
        assert!(Label::Trusted.sources().is_empty());
        assert!(Label::Trusted.source_kinds().is_empty());
    }

    #[test]
    fn nil_source_is_unattributed() {
        assert_eq!(SourceId::nil().kind(), SourceKind::Unattributed);
        assert_eq!(SourceId::nil().uuid(), uuid::Uuid::nil());
    }
}
