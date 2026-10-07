//! Declarative policy over tool arguments, keyed on provenance.

mod engine;
mod rule;

pub use engine::{ConfirmationItem, ConfirmationRequest, Decision, PolicyEngine};
pub use rule::{Rule, RuleExt, RuleSet};
