//! Built-in tools, the audit log, and the tool boundary.
//!
//! Two things live here because they are the same concern seen from two sides.
//! [`audit`] implements invariant I6: every action is recorded, append-only,
//! before it executes. [`host`] implements invariant I4: sensitive tool
//! arguments reject tainted values unless the user confirms, enforced at the
//! only place a tool can actually be invoked.
//!
//! The redaction policy the audit log enforces is why it lives here rather than
//! in `agentos-core`. A record is going to be read by the Controller, so a
//! record that stored raw untrusted text would be a prompt carrying an
//! attacker's instructions. See the [`audit`] module docs for the exact policy.

pub mod audit;
pub mod chain;
pub mod fswrite;
pub mod http;
pub mod mail;
pub mod host;
#[cfg(test)]
mod tests;

pub use audit::{
    arguments, ArgumentRecord, AuditEntry, AuditError, AuditLog, AuditRecord, AuditSink,
    AttemptToken, BoundedText, Clock, FileSink, Fingerprint, MemoryReader, MemorySink, OutcomeKind,
    PolicySummary, RecordedValue, SystemClock, MAX_ARGS_PER_RECORD, MAX_NAME, MAX_REASON,
    MAX_SOURCES_PER_ARG, MAX_TRUSTED_PREFIX,
};
pub use fswrite::{
    FsWrite, LabelledArgs, WriteArgs, WriteError, WriteGrant, WriteReceipt, ARG_CONTENTS,
    ARG_PATH, TOOL_NAME,
};
// `http::TOOL_NAME` is deliberately not re-exported at the crate root: it would
// collide with `fswrite::TOOL_NAME`, which is already exported there under that
// name. Reach it as `agentos_tools::http::TOOL_NAME`, and `ARG_URL` is unique
// enough to be lifted.
pub use mail::{
    MailError, MailGrant, Message, SendEmail, install_policy_rules as install_mail_policy_rules, validate_address,
    MAX_BODY_BYTES, MAX_HEADER_CHARS, TOOL_NAME as MAIL_TOOL_NAME,
    ARG_TO as MAIL_ARG_TO, ARG_SUBJECT as MAIL_ARG_SUBJECT, ARG_BODY as MAIL_ARG_BODY,
};
pub use http::{
    address_is_routable, install_policy_rules as install_http_policy_rules, FetchError, FetchGrant, FetchRequest,
    FetchUrl, FetchUrlArgs, Fetched, HttpFetch, LabelledFetchArgs, Limits, RawResponse, Resolver,
    SystemResolver, TcpTransport, Transport, ARG_URL, DEFAULT_MAX_BYTES, MAX_URL_LEN,
};
pub mod pins;

pub use pins::IntentPins;

pub use host::{sanitise_for_display, PendingConfirmation, PolicyHost, Tool};
