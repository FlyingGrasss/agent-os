//! The evaluation harness.
//!
//! # What this measures, and what it deliberately does not
//!
//! `THREAT_MODEL.md` §9 asks for five numbers. This crate produces one of them
//! properly and refuses to pretend at the others.
//!
//! **Measured here:** the policy engine's *decision quality* on a corpus of
//! programs, as a defended-versus-counterfactual pair. The counterfactual arm is
//! the same interpreter, the same tools, and the same programs with every rule
//! forced to `Allow` — which is precisely what an agent with no policy engine
//! does. So the difference between the arms is attributable to the policy engine
//! and to nothing else. This is the metric `THREAT_MODEL.md` §9 calls "the one
//! that does not degenerate to 0 the way ASR does", and it needs no model.
//!
//! **Not measured here, and not pretended:**
//!
//! - *Attack success rate against a real model.* There is no agent loop and no
//!   model backend, so there is no task to attack. An ASR computed without a
//!   model would be a number about a system that does not exist.
//! - *Benign utility.* Same reason.
//! - *Invariant I1.* The leak counter exists and the gate is wired, but nothing
//!   assembles a planner prompt yet, so the counter has never been incremented
//!   by real traffic. Reporting "0 leaks" from a run that assembles no prompts
//!   would be a vacuous pass, and this crate reports it as unmeasured instead.
//!
//! # The positive-control rule
//!
//! Every number here has a control that can make it fail, because the failure
//! mode of a security metric is a good-looking zero that means the measurement
//! did not run:
//!
//! - If the counterfactual arm does not achieve a 100% attack success rate, the
//!   corpus is not attacking anything and the defended arm's number is
//!   meaningless.
//! - If the defended arm blocks benign programs, its low attack rate is
//!   worthless — it would also be achieved by a host that refuses everything.
//!
//! Both are asserted in [`metrics::Measurement::check_controls`], so a corpus
//! that stops being adversarial fails loudly rather than reporting a better
//! score.

#![deny(missing_docs)]

pub mod metrics;
pub mod rig;
pub mod corpus;
pub mod model;

pub use corpus::{Category, Kind, Program, CORPUS};
pub use metrics::{ArmResult, Measurement};
pub use rig::{
    observe_with, AskPolicy,
    counterfactual_engine, defended_engine, observe, user_approves_everything_engine, Executed,
    Observation, Outcome, ToolSpec, HOSTILE_PAGE, INJECTION, TOOLS,
};