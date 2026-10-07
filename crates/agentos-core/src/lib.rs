//! The Controller: session state, the disclosure round trip, and the
//! authoritative mint point for user confirmations.

pub mod disclosure;
#[cfg(test)]
mod tests;

pub use disclosure::{request_ops, Disclosure, Disposition, Resolution};
