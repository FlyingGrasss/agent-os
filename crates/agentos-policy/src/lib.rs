//! Declarative policy over tool arguments, keyed on provenance.

mod argview;
mod engine;
mod rule;

pub use argview::{arg_views, ArgView};
pub use engine::{ConfirmationItem, ConfirmationRequest, Decision, PolicyEngine};
pub use rule::{Rule, RuleExt, RuleSet};
