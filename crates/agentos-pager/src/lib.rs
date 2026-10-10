//! Decides what the privileged model sees on each step.
//!
//! # The problem
//!
//! A naive agent puts its whole history in every prompt. Prompt cost then grows
//! with task length, and — worse for a security system — so does the amount of
//! text the privileged model is exposed to on every single turn. The pager exists
//! to keep that flat: the same tools, the same task, run for a hundred more steps,
//! should produce a prompt of essentially the same size.
//!
//! It does that by tiering, and by counting rather than copying once history gets
//! old. The rolled tally holds *counts*, not text, which is why it grows when a task
//! meets a tool it has not used before and never when it simply runs longer.
//!
//! # The tier table
//!
//! | Tier | Holds | Rendered as |
//! |---|---|---|
//! | L1 | the steps immediately behind the cursor | one line each, in full |
//! | L2 | closed epochs of older steps | a span and a count per epoch |
//! | L3 | durable facts | `key: text`, plus every fact that was retired and why |
//!
//! Nothing is deleted silently. A fact that leaves the prompt leaves a retirement
//! record, because a Controller that was told something and then un-told cannot
//! distinguish "superseded" from "never happened" — and an agent that cannot
//! distinguish them can be told a false thing twice and believe it once.
//!
//! # Determinism
//!
//! The assembled prompt is byte-identical for identical input. No wall clock, no
//! randomness, no hash-iteration order. This is enforced in `assemble` and checked
//! by a test that also scans this crate's source for the three things that would
//! break it — because a reproducibility bug is invisible: the code compiles, the
//! prompt is subtly unstable, and nothing reports it.
//!
//! # I1: no untrusted bytes reach the prompt
//!
//! **The pager is where invariant I1 is actually enforced.** Every string it can
//! render is a [`Trusted<String>`] by type, and it has no constructor that produces
//! a [`Prompt`] from anything else. There is no `Display` or `Deref<str>` on the
//! prompt that drops the label, and no test-only bypass that a production build
//! could reach.
//!
//! Two consequences worth stating, because both are easy to get backwards:
//!
//! - **A `StepRecord` structurally cannot carry document text.** Tool *arguments*
//!   are not recorded, because that is where tainted values live. The pager records
//!   that a tool ran and how it ended, never what it was given.
//! - **Trust is about provenance, not structure.** The task is trusted because the
//!   user wrote it, and a user who pastes a hostile document into their own request
//!   is exactly the case this must survive. Every free-text field therefore goes
//!   through `assemble::one_line`, so a newline in a task cannot forge a `## `
//!   section header in the rendered prompt.
//!
//! # Deliberately absent
//!
//! `fjall` LSM, group-commit fsync and crash replay are listed in the roadmap for a
//! later phase and are **not implemented and not stubbed**. There is no
//! `unimplemented!()` standing in for them, because a stub that reports success is
//! worse than an honest absence. Nothing in this crate claims durability across a
//! process restart; the ledger is an in-memory accounting record.

#![deny(missing_docs)]

mod assemble;
mod graph;
mod pager;
mod tiers;

pub use assemble::Prompt;
pub use graph::{StepId, StepKind, StepOutcome, StepRecord, ToolName};
pub use pager::{Pager, PagerConfig, PagerError};
pub use tiers::{
    Disposition, Fact, FactEntry, FactKey, FactState, Ledger, RetirementReason, StepEntry, Tier,
    TierCounts,
};