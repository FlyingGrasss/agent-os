//! Errors. Every variant means the extraction did not happen, or happened
//! without the confinement that was promised.
//!
//! Two rules hold across this file:
//!
//! - **No variant is "degraded but running."** There is no `SandboxUnavailable
//!   { .. }` that means "I could not confine the child, so I ran it anyway".
//!   A caller that gets an `Ok` from this crate got a child that the kernel
//!   confirmed was confined.
//! - **No error carries document bytes.** A `Display` impl here is safe to put
//!   in a log line, because every string in it is either a fixed phrase or a
//!   number. That is why [`ProtocolError`] has no `String` payload for
//!   malformed JSON: `serde_json`'s own message can quote the offending value,
//!   and the offending value may be attacker text.

use thiserror::Error;

use crate::protocol::{Attestation, RefusalReason};

/// Why an extraction could not be performed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum QuarantineError {
    /// This build cannot spawn a confined child, because confinement is Linux
    /// only.
    ///
    /// Refused rather than emulated: on a platform with no Landlock there is
    /// nothing to enforce I2 with, and running the extractor in-process would
    /// put the untrusted document inside the Controller's own address space.
    #[error("quarantined extraction requires a Linux host with Landlock and seccomp")]
    UnsupportedPlatform,

    /// The document is larger than the configured limit.
    ///
    /// Reported as a refusal rather than handled by truncating. A truncated
    /// document that the extractor then reads as a whole one is a correctness
    /// bug that looks like a security success: the extraction appears to have
    /// covered the document when it covered a prefix of it.
    #[error("document is {bytes} bytes, over the {limit} byte limit; refusing rather than truncating")]
    DocumentTooLarge {
        /// Size of the document that was offered.
        bytes: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// The child process could not be started.
    #[error("could not start the quarantined extractor `{program}`: {source}")]
    Spawn {
        /// The program that was to be spawned.
        program: String,
        /// Underlying error.
        source: std::io::Error,
    },

    /// The document could not be staged on disk for descriptor passing.
    ///
    /// Staging is an implementation detail of how the document reaches the
    /// child as a descriptor rather than a path; see the crate docs.
    #[error("could not stage the document for handover: {0}")]
    Staging(std::io::Error),

    /// The child did not confine itself, so its result is discarded.
    ///
    /// This is the fail-closed gate. The child reports what the kernel
    /// confirmed; if that report says confinement did not take, the extraction
    /// is dropped rather than returned. A caller cannot obtain an `Extraction`
    /// from an unconfined child.
    #[error("the extractor did not confine itself, so its result is discarded: {0:?}")]
    ConfinementNotEnforced(Attestation),

    /// The host-child protocol was violated.
    #[error("protocol violation between host and extractor: {0}")]
    Protocol(#[from] crate::protocol::ProtocolError),

    /// The child exited without producing a usable result.
    #[error("the extractor exited before answering (code {code:?}, signal {signal:?})")]
    ChildFailed {
        /// Exit code, if it exited normally.
        code: Option<i32>,
        /// Terminating signal, if it was killed.
        signal: Option<i32>,
    },

    /// The child declined to extract.
    ///
    /// A refusal, not a failure: "the document does not contain that field" is
    /// a normal answer. It is an enum so it cannot become free text.
    #[error("the extractor refused: {0}")]
    Refused(RefusalReason),

    /// The child did not answer within the configured timeout and was killed.
    ///
    /// A partial mitigation for the absence of cgroup limits: it bounds wall
    /// clock, not CPU or memory. See the crate docs on what is still
    /// unenforced.
    #[error("the extractor did not answer within {0:?} and was killed")]
    Timeout(std::time::Duration),

    /// No extractor program has been configured.
    ///
    /// Deliberately an error and not a default. A library that silently spawns
    /// *something* when unconfigured, or - much worse - that reads the document
    /// in-process because there was nothing to spawn, is the shape of bug this
    /// crate exists to prevent. The absence of a child program is a refusal.
    #[error("no quarantined extractor program is configured")]
    NoExtractor,

    /// The child returned a field the schema never declared.
    ///
    /// The field name is reported as a length rather than as text. Names come
    /// from the schema in the intended flow, but a child that invents fields is
    /// a child that is not following the protocol, and its names should not be
    /// assumed safe to print.
    #[error("the extractor returned an undeclared field (name length {field_len})")]
    UndeclaredField {
        /// Byte length of the offending name.
        field_len: usize,
    },

    /// The child's values did not satisfy the schema.
    ///
    /// A field that fails its constraint is *quarantined*, not rejected, by
    /// `agentos_infer`'s validator. This variant is therefore only for failures
    /// that stop validation entirely - a result that is not an object, say - and
    /// it carries no field name and no value, both of which could be document
    /// text.
    #[error("the extractor's result does not satisfy its schema")]
    SchemaValidationFailed,

    /// The configured bounds would defeat themselves.
    #[error("invalid limits: {0}")]
    Limits(#[from] crate::limits::LimitsError),
}