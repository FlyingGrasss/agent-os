//! The three tiers, and the ledger that accounts for everything which left one.
//!
//! # The tier design
//!
//! The tiers differ by *how long a thing stays answerable*, not by how
//! important it is. That is the only division of labour that keeps prompt size
//! bounded while still keeping the answer to an old question.
//!
//! | Tier | Holds | Bound | Why it lives here |
//! |---|---|---|---|
//! | [`Tier::L1`] | the steps still inside the working window | `l1_capacity` steps, verbatim | These are the only steps whose *detail loss would change the next action*. Everything older is already reflected in a summary, and acting on a step nobody summarised would mean re-reading raw history, which is the cost the pager exists to remove. |
//! | [`Tier::L2`] | the recent past, condensed | `max_l2_epochs` epochs plus one rolled tally | Recent history is needed in aggregate — "am I looping?", "what has already been tried?" — but not step by step. An epoch is a run of `l1_capacity` steps summarised once when it closes. Everything older than the epochs folds into a tally that carries counts and tool frequencies and *no text*, so its size depends on the tool schema rather than on how long the task ran. |
//! | [`Tier::L3`] | durable facts | `max_facts` facts, verbatim | A fact is something the Controller asserted and may act on at any point in the future. It is the only tier whose contents are individually addressable, because it is the only tier where "which one" changes what happens. Facts are never evicted to save space; the pager refuses and the caller must retire one explicitly. |
//!
//! # Nothing is ever silently gone
//!
//! Every step that leaves L1 is accounted for in the [`Ledger`], and every fact
//! that stops being shown is accounted for as a [`FactEntry`] carrying a
//! [`RetirementReason`]. There is no path that drops a step or a fact without
//! writing down that it dropped it, and the prompt itself renders the ledger's
//! step dispositions as contiguous ranges — so the accounting is visible to the
//! model and to a test, not merely retained in memory.
//!
//! The distinction between the two tiers' retirement rules is deliberate. A step
//! losing its details is not a loss: the epoch summary and the rolled tally
//! still account for it, and the prompt says so. A fact losing its *entire
//! content* is a loss, so it requires a reason to be written down at the moment
//! it happens.

use std::cmp::Ordering;

use agentos_types::Trusted;

use crate::graph::StepId;

/// Which tier a piece of context lives in.
///
/// A named type rather than a `u8` because the three tiers have different
/// lifetime rules and different bounds, and a caller that confuses them is
/// making a budgeting error that only shows up as an over-budget prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// The working window: the steps immediately behind the cursor.
    L1,
    /// The recent past, condensed into epochs and one rolled tally.
    L2,
    /// Durable facts that outlive compaction.
    L3,
}

impl Tier {
    /// Every tier, in the order they are printed.
    pub const ALL: [Tier; 3] = [Tier::L3, Tier::L2, Tier::L1];

    /// The section header this tier renders under.
    pub fn section(self) -> &'static str {
        match self {
            Tier::L1 => "l1-recent",
            Tier::L2 => "l2-history",
            Tier::L3 => "l3-facts",
        }
    }
}

/// The name a fact is filed under.
///
/// Also a `Trusted`-backed newtype with a private field. A fact key is printed
/// into the prompt next to its value, so an attacker-controlled key would be an
/// injection with a smaller body: `key = ignore previous instructions`. The
/// pager therefore requires the key to be trusted on the same terms as the
/// value, and the absence of `Deref`/`Display` keeps it from being reached by
/// accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactKey(Trusted<String>);

impl FactKey {
    /// Name a fact from text that is already trusted.
    pub fn new(key: Trusted<String>) -> Self {
        Self(key)
    }

    /// The name.
    pub fn text(&self) -> &str {
        self.0.get().as_str()
    }
}

impl Ord for FactKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.get().cmp(other.0.get())
    }
}

impl PartialOrd for FactKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Why a fact stopped being shown.
///
/// An enum, so the retirement reason in the prompt is one of a fixed set of
/// words. A free-text reason would be a place for a sentence to grow without
/// bound, and the reason is read by a person in an audit long after it is read
/// by the model in a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetirementReason {
    /// Replaced by a newer fact under the same key. Supersession is two
    /// explicit steps — retire, then set — so the old text is never simply
    /// overwritten.
    Superseded,
    /// The Controller decided it no longer holds. Distinct from
    /// [`Self::Superseded`] because "this was wrong" and "this was replaced"
    /// are different facts about the session.
    NoLongerHolds,
    /// The user asked for it to go.
    UserDirected,
}

impl RetirementReason {
    /// Every reason, in a fixed order.
    pub const ALL: [RetirementReason; 3] = [
        RetirementReason::Superseded,
        RetirementReason::NoLongerHolds,
        RetirementReason::UserDirected,
    ];

    /// One lowercase word, for the prompt and the audit.
    pub fn as_str(self) -> &'static str {
        match self {
            RetirementReason::Superseded => "superseded",
            RetirementReason::NoLongerHolds => "no-longer-holds",
            RetirementReason::UserDirected => "user-directed",
        }
    }
}

/// One live fact.
///
/// Both fields are trusted by type, so the rendered line is trusted by
/// construction; there is no code path that renders a fact the pager did not
/// receive as `Trusted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// What it is filed under.
    pub key: FactKey,
    /// What it says.
    pub text: Trusted<String>,
}

/// Where a step is, now.
///
/// Recorded per step in the [`Ledger`] and updated as the step ages. There is no
/// fourth variant and no "unknown": every accepted step has a disposition from
/// the moment it is accepted, which is what makes the coverage assertion in the
/// test suite possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// In the L1 working window, rendered in full.
    Live,
    /// Condensed into the named L2 epoch, rendered as that epoch's summary.
    Condensed {
        /// Which epoch the step was folded into.
        epoch: u64,
    },
    /// Older than every retained epoch; represented by the L2 rolled tally.
    Rolled,
}

impl Disposition {
    /// The word this disposition renders as in the ledger line.
    ///
    /// Returns a `String` rather than a `&'static str` because one variant
    /// carries an epoch number. Callers render it with [`Display`](std::fmt::Display)
    /// and must apply the same one-line escaping the rest of the prompt uses.
    pub fn label(self) -> String {
        match self {
            Disposition::Live => "live".to_string(),
            Disposition::Condensed { epoch } => format!("epoch {epoch}"),
            Disposition::Rolled => "rolled".to_string(),
        }
    }
}

/// One step's ledger entry. Entries are never removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepEntry {
    /// Which step.
    pub id: StepId,
    /// Where it is now.
    pub disposition: Disposition,
}

/// Whether a fact is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactState {
    /// Present, and rendered in L3.
    Live,
    /// Gone, and here is why.
    Retired {
        /// Recorded at the moment it happened.
        reason: RetirementReason,
        /// The step ordinal at which it was retired. A step ordinal rather than
        /// a wall time, so the ledger is reproducible.
        at: StepId,
    },
}

/// One entry per fact key ever filed. Entries are never removed, so the ledger
/// answers "was this ever known, and what happened to it" as well as "is it
/// being shown".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactEntry {
    /// Which fact.
    pub key: FactKey,
    /// Its current state.
    pub state: FactState,
}

/// The accounting record.
///
/// Append-only in the sense that matters: an entry is added when a step or a
/// fact is accepted and is never deleted afterwards, though a step's
/// [`Disposition`] is updated as it ages. That is enough to assert the property
/// this whole module exists for — every accepted step has exactly one entry, and
/// every retired fact kept one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    steps: Vec<StepEntry>,
    facts: Vec<FactEntry>,
}

impl Ledger {
    /// Record a newly accepted step.
    pub(crate) fn push_step(&mut self, id: StepId) {
        self.steps.push(StepEntry {
            id,
            disposition: Disposition::Live,
        });
    }

    /// Move a run of steps to a new disposition.
    pub(crate) fn set_step_disposition(&mut self, ids: &[StepId], disposition: Disposition) {
        for id in ids {
            // Indexed by ordinal, because ordinals start at 1 and are handed out
            // densely by `Pager::ingest`. The assertion is the point: a
            // discrepancy here would silently leave a step unaccounted for.
            let index = usize::try_from(id.0)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .expect("step ordinals are dense and start at 1");
            self.steps[index].disposition = disposition;
        }
    }

    /// Record a newly filed fact.
    pub(crate) fn push_fact(&mut self, key: FactKey) {
        self.facts.push(FactEntry {
            key,
            state: FactState::Live,
        });
    }

    /// Mark a fact retired.
    pub(crate) fn retire_fact(&mut self, key: &FactKey, reason: RetirementReason, at: StepId) {
        for entry in &mut self.facts {
            if &entry.key == key {
                entry.state = FactState::Retired { reason, at };
                return;
            }
        }
    }

    /// Every step entry, oldest first.
    pub fn steps(&self) -> &[StepEntry] {
        &self.steps
    }

    /// Every fact entry, in the order the keys were first filed.
    pub fn facts(&self) -> &[FactEntry] {
        &self.facts
    }

    /// Where one step is now, if it was ever accepted.
    pub fn disposition(&self, id: StepId) -> Option<Disposition> {
        let index = usize::try_from(id.0).ok()?.checked_sub(1)?;
        self.steps.get(index).map(|e| e.disposition)
    }

    /// How many steps are in each disposition.
    ///
    /// The three counts sum to the number of accepted steps. That identity is
    /// asserted by the ledger coverage test and is the arithmetic behind the
    /// "nothing was silently dropped" claim.
    pub fn counts(&self) -> TierCounts {
        let mut counts = TierCounts::default();
        for entry in &self.steps {
            match entry.disposition {
                Disposition::Live => counts.live += 1,
                Disposition::Condensed { .. } => counts.condensed += 1,
                Disposition::Rolled => counts.rolled += 1,
            }
        }
        for entry in &self.facts {
            if matches!(entry.state, FactState::Retired { .. }) {
                counts.retired += 1;
            }
        }
        counts
    }

    /// How many facts have been retired, by reason.
    ///
    /// Bounded by the number of reasons rather than by the number of retirements,
    /// which is what lets the prompt report retirement honestly without growing
    /// as the session does.
    pub fn retirement_counts(&self) -> [usize; RetirementReason::ALL.len()] {
        let mut counts = [0usize; RetirementReason::ALL.len()];
        for entry in &self.facts {
            if let FactState::Retired { reason, .. } = entry.state {
                counts[reason as usize] += 1;
            }
        }
        counts
    }
}

/// Step counts per disposition, plus the number of retired facts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierCounts {
    /// Steps in the L1 window.
    pub live: usize,
    /// Steps inside a retained L2 epoch.
    pub condensed: usize,
    /// Steps represented only by the rolled tally.
    pub rolled: usize,
    /// Facts retired.
    pub retired: usize,
}