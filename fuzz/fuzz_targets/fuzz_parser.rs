//! Fuzz target for the DSL parser.
//!
//! Feeds random byte sequences to the parser and asserts that it either
//! parses successfully or returns a proper error -- never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use agentos_dsl::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse(s);
    }
});