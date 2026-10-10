//! Fuzz target for the schema coercion logic.
//!
//! Feeds random JSON and schema combinations to the coercion function
//! and asserts it never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use agentos_core::extract::coerce_to_schema;
use agentos_dsl::PlanData;
use agentos_types::SourceId;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(schema) = serde_json::from_str::<Value>(s) {
            // Try various PlanData shapes against the schema
            let test_values = vec![
                PlanData::Str("test".to_string()),
                PlanData::Int(42),
                PlanData::Bool(true),
                PlanData::Quoted { text: "test".to_string(), source: SourceId::new() },
                PlanData::Record(vec![("field".to_string(), PlanData::Str("value".to_string()))]),
                PlanData::List(vec![PlanData::Str("item".to_string())]),
            ];
            
            for val in test_values {
                let _ = coerce_to_schema(val, &schema);
            }
        }
    }
});