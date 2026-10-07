//! The plan language: parser, interpreter, and taint propagation.
//!
//! The planner (role P) emits programs in this language rather than prose, so
//! the Controller never needs to reason about natural-language intent. The
//! interpreter is the only thing that touches tool arguments, and it moves
//! labeled values rather than strings.

mod ast;
mod data;
mod interp;
#[cfg(test)]
mod tests;
mod parser;

pub use ast::{Arg, Expr, Literal, Plan, PlanError, Stmt, MAX_LOOP_DEPTH};
pub use data::{PlanData, PlanValue};
pub use interp::{
    after_confirmation, run, Extractor, Interp, Limits, Outcome, Report, ToolHost,
};
pub use parser::parse;
