//! The Controller: session state, the disclosure round trip, and the
//! authoritative mint point for user confirmations.

pub mod disclosure;
pub mod extract;
pub mod session;
#[cfg(test)]
mod tests;

pub use disclosure::{request_ops, Disclosure, Disposition, Resolution};
pub use extract::ModelExtractor;
pub use session::{Outcome, Session, DEFAULT_CONFIRMATION_LIMIT};
