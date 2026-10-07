use serde::{Deserialize, Serialize};

use crate::capability::CapId;

/// Monotonic id for an event, unique within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventId(pub u64);

/// Typed event emitted by a tool, a sandboxed worker, or the kernel observer.
///
/// Raw stdout, stderr, and kernel tracepoint payloads deliberately have no
/// variant here. The Controller receives these summaries only, which is what
/// keeps untrusted byte streams out of the prompt context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A tool invocation finished.
    ToolCompleted {
        tool: String,
        ok: bool,
        /// Bounded, schema-checked summary. Never raw tool output.
        summary: Option<SummaryField>,
        elapsed_ms: u64,
    },
    /// A sandboxed process exited.
    ProcessExited { code: i32, cap: Option<CapId> },
    /// Bytes changed under a capability.
    FileChanged { cap: CapId, bytes: u64 },
    /// The kernel observer saw an operation outside the declared capability
    /// set. This is a sandbox-integrity signal, not routine noise.
    PolicyViolation { cap: Option<CapId>, operation: String },
    /// The user approved or denied a sensitive operation.
    ConfirmationResolved { approved: bool, target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryField {
    pub key: String,
    /// Enum-shaped. Constrained decoding on the extractor side is what keeps
    /// this field bounded and safe to show.
    pub value: String,
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_through_json() {
        let e = Event::ProcessExited {
            code: 1,
            cap: Some(CapId(3)),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&s).unwrap(), e);
    }
}
