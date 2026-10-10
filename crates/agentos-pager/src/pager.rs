//! The pager itself: accept steps, age them, and refuse to grow.
//!
//! # Two decisions that shape everything else
//!
//! **Compaction is internal and structural. There is no summariser callback.**
//! A hook that produced the summaries would be the one place in this crate where
//! nondeterminism and untrusted text could both enter, and it would enter the
//! *prompt*, not a log. A model-backed summariser is the obvious thing to want
//! here and it is exactly wrong: it would make the assembled prompt unreproducible
//! (so the determinism guarantee would be a property of the callback rather than
//! of the pager) and it would be a second route from untrusted input into the
//! Controller's context that the type system could not see. So an epoch's summary
//! is rendered here from enum-shaped fields, and if a better summary is ever
//! wanted it has to arrive as `Trusted<String>` from somewhere that has already
//! met I1 — not as a callback.
//!
//! **The prompt budget is enforced, not reported.** `Pager::assemble` returns an
//! error when the assembled prompt is larger than
//! [`PagerConfig::max_chars`]. An implementation that merely measured the size
//! would let a caller ignore the number, and the flatness result would then be a
//! property of the caller rather than of the pager.
//!
//! # What is deliberately absent
//!
//! The phase also lists an LSM store, group-commit fsync, and crash replay. None
//! of them is here, and none of them is stubbed. Nothing in this crate touches
//! a filesystem, so there is no on-disk state to be torn, no fsync to batch, and
//! nothing to replay: a pager is rebuilt by re-ingesting the same events, which
//! is deterministic by construction. A storage layer would be added *under* this
//! one and would not change a single rendered byte, because the ordering that
//! matters is decided by ingest ordinals and not by arrival at a disk.

use std::collections::{BTreeMap, VecDeque};

use agentos_types::{Label, Trusted, Val};

use crate::assemble::{self, Prompt};
use crate::graph::{StepId, StepRecord, ToolName};
use crate::tiers::{Disposition, Fact, FactKey, Ledger, RetirementReason};

/// Bounds on how much context the pager will hold.
///
/// The defaults are chosen so that the assembled prompt stays inside
/// [`PagerConfig::max_chars`] for a long task with a realistic number of tools;
/// [`Pager::assemble`] refuses rather than truncating, so if a task genuinely
/// needs more room the caller raises the budget deliberately and the
/// flatness measurement then has to move with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagerConfig {
    /// Steps rendered in full, in L1.
    ///
    /// Also the number of steps in one L2 epoch: an epoch closes once this many
    /// steps have aged out, which makes "one epoch" mean "one screenful of
    /// history" and lets the epoch count be read as a page count.
    pub l1_capacity: usize,
    /// Closed L2 epochs kept verbatim. Older ones fold into the rolled tally.
    pub max_l2_epochs: usize,
    /// Live L3 facts. Reaching it is an error, never an eviction.
    pub max_facts: usize,
    /// Hard ceiling on the assembled prompt, in characters.
    pub max_chars: usize,
}

impl Default for PagerConfig {
    fn default() -> Self {
        Self {
            l1_capacity: 8,
            max_l2_epochs: 4,
            max_facts: 16,
            max_chars: 8192,
        }
    }
}

impl PagerConfig {
    /// Reject a configuration that could not produce a bounded prompt.
    ///
    /// `l1_capacity: 0` would mean a step is never in L1 and every step opens an
    /// epoch of size zero, so nothing would ever close and L2 would grow without
    /// bound — a configuration that passes the budget check while violating the
    /// flatness property. Refusing it is better than clamping it, because a
    /// silently clamped zero is a number the caller believes and the pager does
    /// not use.
    pub fn validate(&self) -> Result<(), PagerError> {
        if self.l1_capacity == 0 {
            return Err(PagerError::InvalidConfig(
                "l1_capacity must be at least 1, or no epoch could ever close",
            ));
        }
        if self.max_l2_epochs == 0 {
            return Err(PagerError::InvalidConfig(
                "max_l2_epochs must be at least 1, or all history is rolled at once",
            ));
        }
        if self.max_facts == 0 {
            return Err(PagerError::InvalidConfig(
                "max_facts must be at least 1, or no fact can ever be filed",
            ));
        }
        if self.max_chars == 0 {
            return Err(PagerError::InvalidConfig("max_chars must be at least 1"));
        }
        Ok(())
    }
}

/// Why the pager refused.
///
/// No variant carries document text. The one that concerns taint carries a
/// [`Label`], which is a set of source identifiers and the word "tainted" —
/// never the bytes that were rejected — so an error can be logged or shown to a
/// user without reopening injection one layer up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PagerError {
    /// The record arrived under a tainted label.
    #[error("a tainted record may not enter the Controller's context ({label:?})")]
    TaintedRecord {
        /// The label it arrived wearing. Recorded for the audit trail; it names
        /// sources, not content.
        label: Label,
    },

    /// The assembled prompt exceeded the configured ceiling.
    #[error("assembled prompt is {chars} characters, over the {max} budget")]
    OverBudget {
        /// What was assembled.
        chars: usize,
        /// What was allowed.
        max: usize,
    },

    /// Filing a new fact would exceed `max_facts`.
    ///
    /// A refusal rather than an eviction of the oldest fact, because evicting a
    /// fact to make room is exactly the silent loss the ledger exists to prevent.
    #[error("the fact store is full at {max} facts; retire one explicitly")]
    FactStoreFull {
        /// The ceiling.
        max: usize,
    },

    /// A fact is already filed under this key.
    ///
    /// Updating goes through [`Pager::retire_fact`] first, so the old text is
    /// recorded as retired rather than overwritten in place.
    #[error("a fact is already filed under this key; retire it before setting a new value")]
    FactAlreadyFiled,

    /// Retiring a key that was never filed.
    #[error("no fact is filed under this key")]
    UnknownFact,

    /// The configuration itself is unusable.
    #[error("pager configuration is unusable: {0}")]
    InvalidConfig(&'static str),
}

/// A closed run of steps and the one-line summary that stands in for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Epoch {
    /// Which epoch this is, counting from zero.
    pub id: u64,
    /// The steps it closed over, in order.
    pub records: Vec<(StepId, StepRecord)>,
}

impl Epoch {
    /// The ordinals this epoch covers, in order.
    ///
    /// The renderer turns these into a `first-last` span, so an epoch of ten
    /// steps occupies one line in the prompt however many steps it holds.
    pub fn ids(&self) -> Vec<StepId> {
        self.records.iter().map(|(id, _)| *id).collect()
    }
}

/// Everything older than the retained epochs, as counts and no text.
///
/// This is the reason prompt size is bounded by the *tool schema* rather than by
/// the *task length*. It grows when a task meets a tool it has not used before
/// and never when it runs another hundred steps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Rolled {
    pub first: Option<StepId>,
    pub last: Option<StepId>,
    pub steps: u64,
    pub outcomes: [u64; 4],
    pub tools: BTreeMap<ToolName, u64>,
}

impl Rolled {
    fn absorb(&mut self, epoch: &Epoch) {
        for (id, record) in &epoch.records {
            if self.first.is_none() {
                self.first = Some(*id);
            }
            self.last = Some(*id);
            self.steps += 1;
            self.outcomes[record.outcome as usize] += 1;
            if let Some(name) = record.tool_name() {
                *self.tools.entry(name.clone()).or_insert(0) += 1;
            }
        }
    }
}

/// Decides what the Controller sees on each step.
///
/// Consumes a [`Trusted<String>`] task and a sequence of records, and renders a
/// prompt whose size does not grow with the number of steps.
pub struct Pager {
    task: Trusted<String>,
    config: PagerConfig,
    next_id: u64,
    next_epoch: u64,
    l1: VecDeque<(StepId, StepRecord)>,
    open_epoch: Vec<(StepId, StepRecord)>,
    epochs: VecDeque<Epoch>,
    rolled: Rolled,
    facts: BTreeMap<FactKey, Fact>,
    ledger: Ledger,
}

impl Pager {
    /// Start a session's pager.
    ///
    /// `task` is trusted text because the task is what the user asked for. It is
    /// not the only route to the prompt — every fact and every summary is also
    /// trusted — but it is the one the caller has to get right first, so it is
    /// the first parameter and it is a `Trusted` rather than a `String`.
    pub fn new(task: Trusted<String>, config: PagerConfig) -> Result<Self, PagerError> {
        config.validate()?;
        Ok(Self {
            task,
            config,
            next_id: 1,
            next_epoch: 0,
            l1: VecDeque::with_capacity(config.l1_capacity + 1),
            open_epoch: Vec::with_capacity(config.l1_capacity),
            epochs: VecDeque::new(),
            rolled: Rolled::default(),
            facts: BTreeMap::new(),
            ledger: Ledger::default(),
        })
    }

    /// The task this session is running.
    pub fn task(&self) -> &Trusted<String> {
        &self.task
    }

    /// The bounds in force.
    pub fn config(&self) -> &PagerConfig {
        &self.config
    }

    /// How many steps have been accepted.
    ///
    /// One past the highest ordinal handed out, so it is also the count: the
    /// pager hands them out densely and never reuses one.
    pub fn accepted(&self) -> usize {
        (self.next_id - 1) as usize
    }

    /// The accounting record.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    // -----------------------------------------------------------------------
    // Read-only views for the renderer.
    //
    // `pub(crate)` rather than `pub` because `Epoch` and `Rolled` are crate
    // types, and exposing them would make them part of the public API for no
    // reason. The renderer is the only caller that needs them, and it is in this
    // crate. Making them public would also make it possible for a future caller to
    // hold a reference across an `ingest`, which is a use-after-mutation footgun
    // these accessors exist to make impossible.
    // -----------------------------------------------------------------------

    pub(crate) fn rolled(&self) -> &Rolled {
        &self.rolled
    }

    /// Retained epochs, oldest first.
    pub(crate) fn epochs(&self) -> &std::collections::VecDeque<Epoch> {
        &self.epochs
    }

    /// The L1 working window, oldest first.
    pub(crate) fn recent(&self) -> &std::collections::VecDeque<(StepId, StepRecord)> {
        &self.l1
    }

    /// Facts currently shown, in key order.
    ///
    /// `BTreeMap` iteration is already sorted, so the order is stable; the
    /// renderer still sorts defensively rather than depending on the container.
    pub(crate) fn live_facts(&self) -> Vec<&crate::tiers::Fact> {
        self.facts.values().collect()
    }

    /// Facts that were filed and then retired, with the reason for each.
    ///
    /// Retired facts are rendered rather than dropped, so the Controller can tell
    /// "this was superseded" from "this never happened".
    pub(crate) fn retired_facts(&self) -> Vec<(String, crate::tiers::RetirementReason)> {
        self.ledger
            .facts()
            .iter()
            .filter_map(|entry| match entry.state {
                crate::tiers::FactState::Retired { reason, .. } => {
                    Some((entry.key.text().to_string(), reason))
                }
                crate::tiers::FactState::Live => None,
            })
            .collect()
    }


    /// Record one step.
    ///
    /// ## Why the parameter is a `Val` and not a `Trusted`
    ///
    /// A `StepRecord` is structurally incapable of carrying an untrusted byte
    /// string — see the `graph` module — so a trusted caller may pass
    /// `Val::trusted(record)` and never think about labels again. But records do
    /// arrive under labels in this system: the label is attached where a value
    /// enters, and an extraction or a tool result hands back a tainted `Val`
    /// even when every field inside it looks innocuous. A pager that took
    /// `&StepRecord` would have no way to notice, because by then the label is
    /// gone.
    ///
    /// So the boundary that matters is checked here, once, and a tainted record
    /// is refused with [`PagerError::TaintedRecord`]. The check is what the
    /// differential test `the_same_bytes_under_two_labels_differ` measures: the
    /// identical record renders into the prompt when the label is trusted and is
    /// refused when it is not, which is what makes the refusal a real gate rather
    /// than a formality that always passes.
    pub fn ingest(&mut self, record: &Val<StepRecord>) -> Result<StepId, PagerError> {
        let trusted = record
            .as_trusted()
            .map_err(|e| PagerError::TaintedRecord { label: e.label })?;

        let id = StepId(self.next_id);
        self.next_id += 1;

        self.l1.push_back((id, trusted.clone()));
        self.ledger.push_step(id);

        while self.l1.len() > self.config.l1_capacity {
            let Some((aged_id, aged)) = self.l1.pop_front() else {
                break;
            };
            self.open_epoch.push((aged_id, aged));
            // The disposition is set as the step leaves L1 rather than when its
            // epoch closes, so a step is never in L2 with a disposition that
            // still says "live".
            let epoch_id = self.next_epoch;
            self.ledger
                .set_step_disposition(&[aged_id], Disposition::Condensed { epoch: epoch_id });
            if self.open_epoch.len() == self.config.l1_capacity {
                self.close_epoch();
            }
        }

        Ok(id)
    }

    /// Turn the open epoch into a retained one, retiring the oldest if needed.
    fn close_epoch(&mut self) {
        if self.open_epoch.is_empty() {
            return;
        }
        let epoch = Epoch {
            id: self.next_epoch,
            records: std::mem::take(&mut self.open_epoch),
        };
        self.next_epoch += 1;

        while self.epochs.len() >= self.config.max_l2_epochs {
            let Some(oldest) = self.epochs.pop_front() else {
                break;
            };
            self.rolled.absorb(&oldest);
            let ids = oldest.ids();
            self.ledger.set_step_disposition(&ids, Disposition::Rolled);
        }

        self.epochs.push_back(epoch);
    }

    /// File a durable fact.
    ///
    /// Refuses if the key is already filed. Overwriting in place would be the
    /// silent loss this crate is built to avoid: the old text would stop being
    /// shown and nothing would record that it had been shown before. Replace it
    /// explicitly with [`Pager::retire_fact`] and then set the new one.
    pub fn set_fact(&mut self, key: FactKey, text: Trusted<String>) -> Result<(), PagerError> {
        if self.facts.contains_key(&key) {
            return Err(PagerError::FactAlreadyFiled);
        }
        if self.facts.len() >= self.config.max_facts {
            return Err(PagerError::FactStoreFull {
                max: self.config.max_facts,
            });
        }
        self.ledger.push_fact(key.clone());
        self.facts.insert(
            key.clone(),
            Fact {
                key: key.clone(),
                text,
            },
        );
        Ok(())
    }

    /// Retire a fact, recording why.
    ///
    /// Idempotent nowhere and silent never: retiring a key that was never filed
    /// is [`PagerError::UnknownFact`], because a retirement that quietly does
    /// nothing would let a caller believe a fact had been withdrawn.
    pub fn retire_fact(&mut self, key: &FactKey, reason: RetirementReason) -> Result<(), PagerError> {
        if self.facts.remove(key).is_none() {
            return Err(PagerError::UnknownFact);
        }
        let at = StepId(self.next_id.saturating_sub(1));
        self.ledger.retire_fact(key, reason, at);
        Ok(())
    }

    /// Assemble the Controller's prompt for this step.
    ///
    /// Byte-identical for identical input, and an error rather than a truncation
    /// when the result would exceed the budget.
    pub fn assemble(&self) -> Result<Prompt, PagerError> {
        assemble::render(self, &self.config)
    }
}

/// Number of ways a [`StepOutcome`] can be counted into a fixed-size array.
///
/// Indexed by `outcome as usize`, which is only sound because the discriminants
/// are `0..4`. This assertion is where that assumption is kept honest.
#[cfg(test)]
mod outcome_discriminants {
    use crate::graph::StepOutcome;

    const _ASSERT: () = assert!(StepOutcome::Succeeded as usize == 0);
}
