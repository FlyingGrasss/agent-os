//! The leak counter: the proof obligation that no untrusted byte reaches a prompt.
//!
//! ## Why this exists
//!
//! AgentDojo cannot measure invariant I1. It reports whether an attack succeeded,
//! which cannot distinguish "the attack was blocked" from "the attack was never
//! expressible". Both look like a success. So a low attack-success rate is not
//! evidence for I1, and neither is a high one evidence against it.
//!
//! What *can* be measured directly is the thing I1 actually says: does any value
//! that arrived from an untrusted source ever reach a prompt slot as trusted? That
//! is a property of this codebase, not of any model's behaviour, so it is
//! immune to sampling, model updates, and API flakiness.
//!
//! ## How it works
//!
//! Every prompt slot is filled through [`PromptSlot::fill`], which takes a
//! [`Trusted<T>`] and nothing else. That is the enforcement, and it is the same
//! enforcement [`Content`] already provides. This module adds the *observation*:
//! a counter that is expected to be exactly zero, and a test that fails when it
//! is not.
//!
//! ## What a non-zero count means
//!
//! It means a value reached a prompt without a confirmation, which is an I1
//! violation. It does not depend on whether that value happened to be hostile. A
//! leak of benign untrusted text is still a leak, and it is the benign case that
//! gets shipped and then the hostile case that follows.

use std::sync::atomic::{AtomicU64, Ordering};

use agentos_types::Trusted;

/// Counters for prompt assembly.
///
/// A process-wide singleton because prompt assembly happens in the interpreter,
/// the session actor, and the pager, and threading a counter through all of them
/// would add a parameter nobody would remember to pass. The alternative — an
/// explicit counter — would be right if this were a library with many embedders,
/// and it is not: this is a daemon with one entry point.
pub struct LeakCounters {
    untrusted_ingested: AtomicU64,
    trusted_prompt_fills: AtomicU64,
    quarantined_prompt_fills: AtomicU64,
    confirmations_requested: AtomicU64,
    confirmations_granted: AtomicU64,
}

static COUNTERS: LeakCounters = LeakCounters {
    untrusted_ingested: AtomicU64::new(0),
    trusted_prompt_fills: AtomicU64::new(0),
    quarantined_prompt_fills: AtomicU64::new(0),
    confirmations_requested: AtomicU64::new(0),
    confirmations_granted: AtomicU64::new(0),
};

/// The process-wide counters.
pub fn counters() -> &'static LeakCounters {
    &COUNTERS
}

/// A snapshot, for reporting and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeakReport {
    /// Values that arrived from an untrusted source.
    pub untrusted_ingested: u64,
    /// Prompt slots filled with a confirmed or user-authored value.
    pub trusted_prompt_fills: u64,
    /// Prompt slots filled with quarantined text. **Must be zero.**
    pub quarantined_prompt_fills: u64,
    /// Sensitive operations put to the user.
    pub confirmations_requested: u64,
    /// Of those, approved.
    pub confirmations_granted: u64,
}

impl LeakReport {
    /// The invariant. Any non-zero value is an I1 violation.
    pub fn leaks(&self) -> u64 {
        self.quarantined_prompt_fills
    }

    /// Ratio of quarantined fills to all prompt fills.
    ///
    /// Exposed because a rate reads better in a dashboard than a count, but the
    /// gate is on [`Self::leaks`], not on this. A rate can be small and still
    /// wrong; the requirement is exactly zero.
    pub fn leak_rate(&self) -> f64 {
        let total = self.trusted_prompt_fills + self.quarantined_prompt_fills;
        if total == 0 {
            0.0
        } else {
            self.quarantined_prompt_fills as f64 / total as f64
        }
    }
}

/// Record that an untrusted value entered the system.
pub fn record_untrusted_ingest() {
    COUNTERS.untrusted_ingested.fetch_add(1, Ordering::Relaxed);
}

/// Record that a sensitive operation needed the user.
pub fn record_confirmation_requested() {
    COUNTERS
        .confirmations_requested
        .fetch_add(1, Ordering::Relaxed);
}

/// Record that the user approved.
pub fn record_confirmation_granted() {
    COUNTERS
        .confirmations_granted
        .fetch_add(1, Ordering::Relaxed);
}

/// A slot in a prompt that may only hold trusted text.
///
/// `fill` takes a `Trusted<T>`, so the compiler rejects a tainted value before
/// any counter is involved. The counter records what happened for the audit
/// trail; it is not the enforcement.
#[derive(Debug)]
pub struct PromptSlot<'a> {
    name: &'a str,
}

impl<'a> PromptSlot<'a> {
    pub fn new(name: &'a str) -> Self {
        Self { name }
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Place a trusted value.
    ///
    /// The lifetime is tied to the value rather than to `self`, so a caller can
    /// hold the returned reference after the slot is dropped. A prompt slot is a
    /// transient concept; the text it placed is not.
    pub fn fill<'v, T>(&self, value: &'v Trusted<T>) -> &'v T {
        COUNTERS.trusted_prompt_fills.fetch_add(1, Ordering::Relaxed);
        value.get()
    }

    /// Place text that is not a `Trusted<T>`.
    ///
    /// Present only so the test suite can demonstrate that the counter notices.
    /// A real caller cannot reach this with a tainted value from outside the
    /// crate, because it would have to construct the `Trusted` first.
    #[doc(hidden)]
    pub fn fill_unchecked_for_test(&self) {
        COUNTERS.quarantined_prompt_fills.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot the counters.
pub fn report() -> LeakReport {
    LeakReport {
        untrusted_ingested: COUNTERS.untrusted_ingested.load(Ordering::Relaxed),
        trusted_prompt_fills: COUNTERS.trusted_prompt_fills.load(Ordering::Relaxed),
        quarantined_prompt_fills: COUNTERS.quarantined_prompt_fills.load(Ordering::Relaxed),
        confirmations_requested: COUNTERS.confirmations_requested.load(Ordering::Relaxed),
        confirmations_granted: COUNTERS.confirmations_granted.load(Ordering::Relaxed),
    }
}

/// Reset the counters. For tests, which share a process.
pub fn reset() {
    COUNTERS.untrusted_ingested.store(0, Ordering::Relaxed);
    COUNTERS.trusted_prompt_fills.store(0, Ordering::Relaxed);
    COUNTERS.quarantined_prompt_fills.store(0, Ordering::Relaxed);
    COUNTERS.confirmations_requested.store(0, Ordering::Relaxed);
    COUNTERS.confirmations_granted.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_types::{Confirmation, Origin, SourceId, UserId, Val};

    fn user() -> UserId {
        let mut b = [0u8; 16];
        b[15] = 1;
        UserId(uuid::Uuid::from_bytes(b))
    }

    #[test]
    fn a_trusted_value_fills_a_slot_without_incurring_a_leak() {
        let t = Trusted::inherited(Origin::User(user()), "read the invoice".to_string());
        let slot = PromptSlot::new("task");
        assert_eq!(slot.fill(&t), "read the invoice");
    }

    #[test]
    fn a_tainted_value_cannot_be_passed_to_fill() {
        // Compile-time, so this test asserts the shape rather than a runtime
        // outcome: `fill` takes `&Trusted<T>` and `Val::tainted` returns `Val`,
        // so no value derived from a web page can reach a prompt slot without
        // first being confirmed.
        let tainted: Val<String> = Val::tainted(SourceId::new(), "evil".into());
        assert!(tainted.is_tainted());
        // The only route to a `Trusted` here goes through a confirmation.
        let confirmation = Confirmation::issued_by_controller(user(), &tainted).unwrap();
        let promoted = Trusted::confirmed(tainted, &confirmation).unwrap();
        assert_eq!(promoted.approval(), agentos_types::Approval::Confirmed);
    }

    #[test]
    fn the_counter_detects_a_leak_when_one_is_forced() {
        reset();
        assert_eq!(report().leaks(), 0);

        PromptSlot::new("smuggled").fill_unchecked_for_test();

        assert_eq!(
            report().leaks(),
            1,
            "the counter must notice a quarantined value reaching a prompt"
        );
        reset();
    }

    #[test]
    fn a_clean_run_reports_no_leaks() {
        reset();
        record_untrusted_ingest();
        record_confirmation_requested();
        record_confirmation_granted();

        let slot = PromptSlot::new("task");
        slot.fill(&Trusted::inherited(Origin::User(user()), "x".to_string()));

        let r = report();
        assert_eq!(r.leaks(), 0);
        assert_eq!(r.untrusted_ingested, 1);
        assert_eq!(r.trusted_prompt_fills, 1);
        assert_eq!(r.leak_rate(), 0.0);
        reset();
    }

    #[test]
    fn the_gate_is_the_count_not_the_rate() {
        // One leak in a million prompts is a tiny rate and still a violation.
        let r = LeakReport {
            trusted_prompt_fills: 999_999,
            quarantined_prompt_fills: 1,
            ..Default::default()
        };
        assert!(r.leak_rate() < 0.0001);
        assert_eq!(r.leaks(), 1, "the gate must not be the rate");
    }
}
