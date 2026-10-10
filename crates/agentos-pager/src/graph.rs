//! The records the pager pages over, and why none of them can carry an
//! untrusted byte.
//!
//! # The whole file exists to make one type unrepresentable
//!
//! Invariant I1 says no untrusted byte enters the Controller's prompt. The
//! enforcement is not a filter in the renderer — filters get forgotten, and a
//! filter that has to recognise hostile prose is a filter that loses. It is the
//! shape of [`StepRecord`]: every field is either an integer, a boolean, or a
//! [`ToolName`], and `ToolName`'s field is private and typed [`Trusted<String>`].
//! There is therefore no expression that builds a `StepRecord` out of document
//! text, and no field the renderer has to inspect before writing.
//!
//! # Why a record names a tool but not its arguments
//!
//! A tool's *name* comes from the plan, which the Controller authored from
//! trusted input only. A tool's *arguments* come from the data, which is exactly
//! where tainted values live — `send_email(to = inv.note)` carries a value lifted
//! out of a hostile document.
//!
//! So [`StepRecord`] deliberately carries no arguments at all. That is a real
//! loss of fidelity and it is the correct trade: a record that could report
//! "called `send_email` with `to = ...`" would be a channel from a web page into
//! the Controller's context, and the pager would be the component that opened
//! it. If the Controller ever needs to see what a call was made with, that has
//! to be a *typed, schema-bounded summary* in the shape of
//! `agentos_types::SummaryField` — an enum-shaped value chosen by the schema,
//! not free text chosen by the document. Until that exists, the pager reports
//! less rather than reporting something it must not.

use std::cmp::Ordering;

use agentos_types::Trusted;

/// A step's ordinal within one session.
///
/// Assigned by [`Pager::ingest`](crate::Pager::ingest) in the order steps were
/// recorded, so the numbering is a function of the event stream alone and never
/// of a clock, a counter reset, or a wall time. Numbering starts at 1 so that `0`
/// can mean "no step" in the arithmetic that turns a run of steps into the
/// contiguous ranges the prompt prints.
///
/// The ordinal is *not* taken from the caller. A caller-supplied id would make
/// the rendered ranges depend on whatever numbering the producer chose, and two
/// runs of the same task could then print different ranges for identical
/// history — which is the same defect as an unordered collection, wearing a
/// number as a disguise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepId(pub u64);

/// The name of a tool, as trusted text.
///
/// Wraps a [`Trusted<String>`] in a type with no public field. `as_str`-style
/// access exists and is deliberately explicit, but there is no `Deref`, no
/// `Display`, and no `From<String>`: every route from a `String` to a
/// `ToolName` goes through a `Trusted`, and that is the whole enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolName(Trusted<String>);

impl ToolName {
    /// Name a tool from text that is already trusted.
    pub fn new(name: Trusted<String>) -> Self {
        Self(name)
    }

    /// The name.
    ///
    /// Named `text` rather than `as_str` so that the call sites read as
    /// "render this trusted name" instead of as a generic string accessor that a
    /// reader might expect to be available on any wrapper type.
    pub fn text(&self) -> &str {
        self.0.get().as_str()
    }
}

impl Ord for ToolName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.get().cmp(other.0.get())
    }
}

impl PartialOrd for ToolName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// How a step ended.
///
/// An enum rather than a status string, for the same reason [`StepKind`] is one:
/// a bounded set of shapes can be rendered into a prompt, counted, and asserted
/// on, whereas a string can be anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepOutcome {
    /// It did what it said.
    Succeeded,
    /// It failed. The code is not carried; the code is a tool's, and tool output
    /// is where tainted bytes live.
    Failed,
    /// Policy refused it, or the user did. Distinguished from [`Self::Failed`]
    /// so the model can tell "the system stopped this" from "this broke", which
    /// are different next actions.
    Refused,
    /// Deliberately not attempted, e.g. a branch not taken.
    Skipped,
}

impl StepOutcome {
    /// Every outcome, in a fixed order. Iteration over an enum is over a
    /// declared list, which is what makes the rendered tally identical on every
    /// run.
    pub const ALL: [StepOutcome; 4] = [
        StepOutcome::Succeeded,
        StepOutcome::Failed,
        StepOutcome::Refused,
        StepOutcome::Skipped,
    ];

    /// One lowercase word, for the prompt.
    pub fn as_str(self) -> &'static str {
        match self {
            StepOutcome::Succeeded => "ok",
            StepOutcome::Failed => "failed",
            StepOutcome::Refused => "refused",
            StepOutcome::Skipped => "skipped",
        }
    }
}

/// What kind of step this was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum StepKind {
    /// A tool was invoked. The name is trusted; see the module docs for why the
    /// arguments are absent.
    Tool {
        /// Which tool.
        name: ToolName,
    },
    /// The user answered a confirmation request.
    Confirmation {
        /// What they said. Recorded because "the user approved this" is one of
        /// the few things the Controller must not re-derive or forget.
        approved: bool,
    },
    /// The Controller marked progress at a point it chose.
    Checkpoint,
    /// The plan reached an end state.
    PlanFinished {
        /// Whether every statement ran.
        ok: bool,
    },
}

impl StepKind {
    /// Render for the prompt. One line, no free text beyond a [`ToolName`].
    pub fn render(&self) -> String {
        match self {
            StepKind::Tool { name } => format!("tool {}", name.text()),
            StepKind::Confirmation { approved } => {
                format!("confirmation {}", if *approved { "approved" } else { "denied" })
            }
            StepKind::Checkpoint => "checkpoint".to_string(),
            StepKind::PlanFinished { ok } => {
                format!("plan {}", if *ok { "finished" } else { "failed" })
            }
        }
    }
}

/// One thing that happened, in a shape the prompt can hold.
///
/// Every field is trusted-by-construction or an integer. That is not a
/// convention a future contributor has to remember; it is the type, and the
/// test `a_record_cannot_carry_document_text` is what holds it there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// What kind of step.
    pub kind: StepKind,
    /// How it ended.
    pub outcome: StepOutcome,
}

impl StepRecord {
    /// A tool call that ended in `outcome`.
    pub fn tool(name: ToolName, outcome: StepOutcome) -> Self {
        Self {
            kind: StepKind::Tool { name },
            outcome,
        }
    }

    /// A user confirmation. `outcome` is normally
    /// [`StepOutcome::Succeeded`] for an approval and
    /// [`StepOutcome::Refused`] for a denial, but the pager does not assume it;
    /// a mismatch is a fact about the session, not an error to paper over.
    pub fn confirmation(approved: bool, outcome: StepOutcome) -> Self {
        Self {
            kind: StepKind::Confirmation { approved },
            outcome,
        }
    }

    /// A progress marker.
    pub fn checkpoint(outcome: StepOutcome) -> Self {
        Self {
            kind: StepKind::Checkpoint,
            outcome,
        }
    }

    /// The plan reached an end state.
    pub fn plan_finished(ok: bool, outcome: StepOutcome) -> Self {
        Self {
            kind: StepKind::PlanFinished { ok },
            outcome,
        }
    }

    /// The tool this record names, if it names one.
    pub fn tool_name(&self) -> Option<&ToolName> {
        match &self.kind {
            StepKind::Tool { name } => Some(name),
            _ => None,
        }
    }

    /// Render for the prompt.
    pub fn render(&self) -> String {
        format!("{} {}", self.kind.render(), self.outcome.as_str())
    }
}