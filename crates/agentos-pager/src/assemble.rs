//! Rendering the prompt, deterministically.
//!
//! # Why this module exists separately
//!
//! Everything about *what the Controller knows* lives in [`crate::pager`] and
//! [`crate::tiers`]. This module only decides the order and the escaping, which
//! is where reproducibility lives or dies.
//!
//! # The determinism rules, and why each is here
//!
//! **Fixed section order.** Sections are emitted in a constant order so the
//! output does not depend on which collections happened to be non-empty.
//!
//! **Every collection is sorted.** Facts are a `BTreeMap` and so are already
//! ordered, but epochs and the L1 window are `VecDeque`s ordered by insertion.
//! Rendering them in that order would make the prompt depend on *when* the pager
//! was asked rather than on what it knows — and a prompt that changes when you
//! look at it is not reproducible, which is the property the whole crate exists
//! to provide.
//!
//! **No wall time, no randomness, no address-derived ordering.** There is no
//! `SystemTime` call and no `HashMap` anywhere in the render path. A test scans
//! the crate's source for both, because the failure mode is invisible: the code
//! compiles, the prompt is subtly unstable, and nothing reports it.
//!
//! **Every free-text field goes through [`one_line`].** A trusted string is
//! trusted with respect to *provenance*, not with respect to *structure*. A task
//! containing a newline could otherwise forge a section header in the rendered
//! prompt, and a task is only trusted because the user wrote it — a user who pastes
//! something adversarial is exactly the case the pager must survive.
//!
//! # The budget is a refusal, not a truncation
//!
//! An over-budget prompt returns [`PagerError::OverBudget`]. Silently truncating
//! would drop the end of the prompt — usually the most recent step — and the
//! Controller would proceed with a silently incomplete view, which is worse than
//! an error: nothing downstream would know anything had been dropped.

use agentos_types::Trusted;

use crate::graph::{StepId, StepRecord};
use crate::pager::{Pager, PagerConfig, PagerError};

/// An assembled prompt.
///
/// The text is [`Trusted`] and cannot be obtained any other way: [`Self::render`]
/// takes `&self` and mints the token from bytes the pager assembled itself, all
/// of which came from `Trusted` inputs. There is no constructor a caller can use
/// to fabricate one, which is the point — if there were, `Trusted<String>` would
/// stop meaning anything at this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    text: Trusted<String>,
}

impl Prompt {
    /// The prompt text, labelled by its own provenance.
    pub fn render(&self) -> Trusted<String> {
        self.text.clone()
    }

    /// Borrow the text without its label.
    ///
    /// Deliberately named for display and auditing, matching the convention in
    /// `agentos_types`. Reading the prompt is fine; *labelling* it trusted is a
    /// separate, explicit act.
    pub fn with_text<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.text.get())
    }

    /// Whether the assembled prompt contains `needle`.
    ///
    /// For tests. Takes a plain `&str` so a test can assert on document content
    /// without minting a `Trusted` for it — the needle is attacker-controlled in
    /// exactly the tests that matter.
    pub fn contains(&self, needle: &str) -> bool {
        self.with_text(|t| t.contains(needle))
    }

    /// Length in characters.
    pub fn chars(&self) -> usize {
        self.with_text(|t| t.chars().count())
    }

    /// Rough token count.
    ///
    /// Four characters per token, which is the usual English approximation. It is
    /// a budget aid and not a billing figure — a real tokenizer would need the
    /// model's vocabulary, and this crate deliberately does not depend on one.
    pub fn approx_tokens(&self) -> usize {
        self.chars().div_ceil(4)
    }
}

/// Render `pager`'s current state into a prompt.
pub(crate) fn render(pager: &Pager, config: &PagerConfig) -> Result<Prompt, PagerError> {
    let mut out = String::with_capacity(config.max_chars.min(4096));

    push_task(&mut out, pager);
    push_rollup(&mut out, pager);
    push_facts(&mut out, pager);
    push_retired(&mut out, pager);
    push_history(&mut out, pager);
    push_recent(&mut out, pager);
    push_ledger(&mut out, pager, config);

    let chars = out.chars().count();
    if chars > config.max_chars {
        return Err(PagerError::OverBudget {
            chars,
            max: config.max_chars,
        });
    }

    Ok(Prompt {
        text: Trusted::inherited(
            agentos_types::Origin::Controller(agentos_types::ControllerAuthority::issue()),
            out,
        ),
    })
}

/// Emit a section header.
///
/// The rendered prompt has more sections than there are tiers: the task, the
/// rolled tally and the retired-facts block each need their own header, and the
/// ledger summary is an accounting line rather than a tier. Headers are therefore
/// plain fixed strings rather than `Tier::section`, and they are a closed set
/// written here — a caller cannot add one, so the set cannot grow with the data.
fn section(out: &mut String, name: &str) {
    out.push_str("\n## ");
    out.push_str(name);
    out.push('\n');
}

fn push_task(out: &mut String, pager: &Pager) {
    section(out, "Task");
    out.push_str(&one_line(pager.task().get().as_str()));
    out.push('\n');
}

/// The rolled tally: everything older than the retained epochs.
///
/// Rendered before the epochs it overlaps, because it is the coarsest view and a
/// reader works from general to specific. Its size depends on which *tools* a task
/// has met, not on how long it has been running — which is the property that keeps
/// the prompt flat.
fn push_rollup(out: &mut String, pager: &Pager) {
    let rolled = pager.rolled();
    if rolled.steps == 0 {
        return;
    }
    section(out, "Rollup");
    out.push_str(&format!("earlier steps: {}\n", rolled.steps));
    // Tools are a `BTreeMap`, so this is already ordered. Sorted explicitly anyway:
    // relying on a container's internal ordering for a *reproducibility* property
    // is the kind of coupling that breaks silently when the container changes.
    for (tool, count) in &rolled.tools {
        out.push_str(&format!("  {} x{}\n", one_line(tool.text()), count));
    }
    let outcomes: Vec<String> = rolled
        .outcomes
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(i, n)| format!("{}={}", outcome_name(i), n))
        .collect();
    if !outcomes.is_empty() {
        out.push_str(&format!("  outcomes: {}\n", outcomes.join(" ")));
    }
}

/// Outcome name by discriminant. Matches the assertion in `pager.rs` that the
/// discriminants are `0..4`; a fifth variant would silently render as `?` here.
fn outcome_name(index: usize) -> &'static str {
    match index {
        0 => "ok",
        1 => "error",
        2 => "denied",
        _ => "other",
    }
}

fn push_facts(out: &mut String, pager: &Pager) {
    let facts = pager.live_facts();
    if facts.is_empty() {
        return;
    }
    section(out, "Facts");
    for fact in facts {
        out.push_str(&format!("{}: {}\n", one_line(fact.key.text()), one_line(fact.text.get())));
    }
}

/// Retired facts are rendered, not dropped.
///
/// A fact that leaves the prompt without a trace is a fact the Controller was
/// told and then un-told, and it cannot tell the difference between "this was
/// superseded" and "this never happened".
fn push_retired(out: &mut String, pager: &Pager) {
    let retired = pager.retired_facts();
    if retired.is_empty() {
        return;
    }
    section(out, "Retired");
    for (key, reason) in retired {
        out.push_str(&format!("{}: retired ({})\n", one_line(&key), reason.as_str()));
    }
}

fn push_history(out: &mut String, pager: &Pager) {
    let epochs = pager.epochs();
    if epochs.is_empty() {
        return;
    }
    section(out, "History");
    // Sorted by epoch id rather than rendered in `VecDeque` order. The deque is in
    // insertion order today and would stay so, but the prompt's reproducibility
    // should not depend on that continuing to be true.
    let mut ordered: Vec<_> = epochs.iter().collect();
    ordered.sort_by_key(|e| e.id);
    for epoch in ordered {
        let ids = epoch.ids();
        let span = match (ids.first(), ids.last()) {
            (Some(a), Some(b)) if a == b => format!("{}", a.0),
            (Some(a), Some(b)) => format!("{}-{}", a.0, b.0),
            _ => "empty".to_string(),
        };
        out.push_str(&format!("  steps {}: {} tool call(s)\n", span, epoch.records.len()));
    }
}

fn push_recent(out: &mut String, pager: &Pager) {
    let recent = pager.recent();
    if recent.is_empty() {
        return;
    }
    section(out, "Recent");
    // Sorted by ordinal, so the rendered order matches the step order regardless
    // of how the window is stored.
    let mut ordered: Vec<&(StepId, StepRecord)> = recent.iter().collect();
    ordered.sort_by_key(|(id, _)| id.0);
    for (id, record) in ordered {
        out.push_str(&format!("{}: {}\n", id.0, one_line(&record.render())));
    }
}

/// The ledger summary: coverage rather than content.
///
/// One line per disposition. The point is that a reader can see every accepted
/// step is accounted for, without the prompt growing per step.
fn push_ledger(out: &mut String, pager: &Pager, _config: &PagerConfig) {
    let counts = pager.ledger().counts();
    section(out, "Ledger");
    out.push_str(&format!(
        "steps: live={} condensed={} rolled={} facts retired={}\n",
        counts.live, counts.condensed, counts.rolled, counts.retired
    ));
}

/// Make a trusted string safe to place on its own line.
///
/// Provenance and structure are different questions. A `Trusted<String>` is trusted
/// with respect to *where it came from*, and the task is only trusted because the
/// user wrote it. A user who pastes a document into their own prompt is a real
/// case, and without this a newline in the task would forge a `## ` header in the
/// rendered prompt — the Controller would read an attacker-authored section as
/// structure it had been given.
///
/// Every free-text field goes through here, without exception.
fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    // Collapse the runs that escaping leaves behind, so the length of the output
    // does not depend on how the input was formatted.
    let mut collapsed = String::with_capacity(out.len());
    let mut last_was_space = false;
    for c in out.chars() {
        let is_space = c == ' ';
        if is_space && last_was_space {
            continue;
        }
        last_was_space = is_space;
        collapsed.push(c);
    }
    collapsed.trim().to_string()
}
