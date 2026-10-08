//! A real process boundary for the quarantined processor.
//!
//! Invariant **I2**: "The quarantined processor has no tools, no network, and
//! no filesystem access beyond its input."
//!
//! Before this crate, I2 was a claim in a type. [`agentos_infer::Role::may_use_tools`]
//! returned a hardcoded `false`, and `Extractor` was a bare trait with nothing
//! between it and the process. That is documentation, not enforcement: a claim
//! in a type does not survive the first person who adds a field.
//!
//! This crate makes I2 a set of things the kernel or the type system checks:
//!
//! | Half of I2 | Enforced by | Checked by |
//! |---|---|---|
//! | no filesystem beyond its input | a Landlock ruleset that handles every V7 filesystem right and grants **no path at all**, so the document arrives as a descriptor over `SCM_RIGHTS` rather than as a path | [`child::serve`] applies it and refuses to read the document without it; [`tests/escape.rs`](https://docs.rs) observes the kernel refusing real opens |
//! | no network | Landlock denies every TCP bind and connect, and seccomp `Profile::Filesystem` refuses `socket(2)` outright | same |
//! | no tools | [`Request`] has exactly one variant, so there is no message that can name a tool, invoke one, or name a path | a protocol test fails if a second variant appears, and refuses hostile shapes that try to be one |
//! | output is never free text the Controller can read | every value comes back as a [`protocol::Value`](crate::protocol::Outcome) validated against the schema, and a field that fails its constraint is quarantined whole rather than coerced | [`host::SandboxedExtractor::extract`] runs `agentos_infer`'s validator before producing an `Extraction` |
//!
//! # Fail closed, always
//!
//! The rule the whole [`agentos_sandbox`] crate is built on, applied here with no
//! exceptions:
//!
//! - there is no `if available() { ... } else { run anyway }` path. The only
//!   route to reading a document is through a kernel-confirmed [`Enforced`];
//! - a child that reports anything other than the exact promised profile has its
//!   **reply discarded**. Not downgraded, not partially believed - discarded.
//!   Zero filesystem grants, zero TCP grants, `no_new_privs` confirmed, seccomp
//!   installed, or the answer does not exist;
//! - off Linux, [`host::SandboxedExtractor::extract`] returns
//!   [`QuarantineError::UnsupportedPlatform`] rather than extracting in-process;
//! - a spawn failure is an error, never a fallback to in-process extraction;
//! - an oversized document is **refused**, never truncated. Truncating would
//!   produce an extraction that looks complete and covers a prefix.
//!
//! # What is NOT enforced, stated plainly
//!
//! This crate is honest about its limits, because a residual risk that is
//! written down is usable and one that is not is not:
//!
//! - **No CPU, memory, or process-count limit.** Landlock and seccomp are not
//!   resource limiters. A document that makes the engine allocate without bound
//!   or loop forever is bounded only by [`Limits::timeout`], which bounds wall
//!   clock and nothing else. The real fix is cgroup v2, which is **not
//!   delegable to an unprivileged uid on the target host**, so there is nothing
//!   to hand. [`Limits`] is therefore an honest bound on *input size*, not a
//!   claim about resource use.
//! - **No user or mount namespace.** `unshare(CLONE_NEWUSER)` is denied for uid
//!   1000 on the target host, so there is no uid remapping and no pivot_root.
//!   The child keeps the daemon's uid and its view of the filesystem as it was
//!   before Landlock landed.
//! - **The extractor's own binary is trusted.** Between `execve` and
//!   `landlock_restrict_self` the child is unconfined, and a malicious extractor
//!   binary would never confine itself at all. What is confined is the code in
//!   the child *process*; the threat I2 is written against is a hostile document
//!   and a hostile model, both first consulted after confinement is in force. The
//!   attestation the child reports is self-reported and a lying child could lie -
//!   what the host does check is that the *failure* is checked, because
//!   `Confine::apply` and `apply_seccomp` return errors rather than warnings.
//! - **Metadata is not gated.** Landlock gates opening a file, not `stat(2)`. A
//!   confined child can still learn whether a path exists and what kind it is.
//!   The escape tests assert this rather than leaving it assumed.
//! - **The document briefly exists as a file.** Passing a descriptor needs
//!   something to open one from, so the host stages the document in a `0700`
//!   directory, opens it, and unlinks it before the child is spawned. There is a
//!   real window in which attacker-controlled bytes sit on disk in a private
//!   directory. A `memfd` would close it; `SCM_RIGHTS` is the requirement here
//!   and `open_granted` is what hands it over.
//! - **One Linux host, one Landlock ABI floor.** `agentos-sandbox` requires ABI
//!   V6 (Linux 6.12) or newer. This crate inherits that floor rather than
//!   lowering it.
//! - **Metadata about the protocol, not about the document.** A refusal reason is
//!   a fixed phrase ([`RefusalReason`] has no payload), and no error in this
//!   crate carries document bytes. That is deliberate: an error string is a log
//!   line, and a log line is read by the same terminals a prompt-injection would
//!   be aimed at.
//!
//! # Shape of a call
//!
//! ```no_run
//! use agentos_quarantine::{ChildProgram, SandboxedExtractor, SchemaSpec};
//! use agentos_infer::schema::{Constraint, Field, Schema};
//! use agentos_types::{Quarantined, SourceId, SourceKind};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let schema = Schema {
//!     name: "Invoice".into(),
//!     fields: vec![Field {
//!         name: "total".into(),
//!         // A bounded integer, not a string. The schema is the boundary.
//!         constraint: Constraint::Integer { min: 0, max: 1_000_000 },
//!     }],
//! };
//!
//! let extractor = SandboxedExtractor::new()
//!     .with_child(ChildProgram::new("/usr/local/lib/agentos/q-extractor"));
//!
//! // A hostile web page. It arrives as `Quarantined`, and nothing downstream can
//! // make it prompt-eligible except an explicit user confirmation.
//! let document = Quarantined::from_source(
//!     "total = 42".to_string(),
//!     SourceId::of_kind(SourceKind::WebPage),
//! );
//!
//! let spec = SchemaSpec::from_schema(&schema)?;
//! let extraction = extractor.extract(&spec, &document)?;
//!
//! // Tainted in every field, without exception. There is no code path through
//! // `extract` that can produce a `Trusted`.
//! assert!(extraction.data.is_tainted());
//! # Ok(())
//! # }
//! ```
//!
//! # Testing
//!
//! The tests that matter are in `tests/escape.rs`. They re-exec the test binary
//! as a **child**, run the real [`child::serve`] loop inside it, and have the
//! child attempt real escapes against the running kernel and report what the
//! kernel did. A test that asserts "the ruleset was applied" proves almost
//! nothing; a sandbox that grants `/` is applied and useless.
//!
//! Those tests are Linux-only and are `#![cfg(target_os = "linux")]`. On any
//! other target the file compiles to nothing, which means **the escape tests are
//! not evidence of anything there**. The module docs in that file say so at the
//! top rather than letting an empty run read as coverage.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod host;
mod limits;
mod protocol;

pub use error::QuarantineError;
pub use limits::{Limits, LimitsError};
pub use protocol::{
    decode, encode, read_frame, write_frame, Attestation, FieldSpec, Outcome, ProtocolError,
    RefusalReason, Reply, Request, SchemaSpec, MAX_FRAME_BYTES, MAX_NAME_BYTES,
    MAX_SHORT_TEXT_CHARS,
};

// The confined side is Linux-only: it applies Landlock and seccomp. It is gated
// rather than stubbed, because a stub that "succeeds" off Linux would be a second
// path that reads a document with nothing enforcing I2.
#[cfg(target_os = "linux")]
pub mod child;
#[cfg(target_os = "linux")]
pub use child::{
    serve, serve_on_stdin, ExtractionEngine, NoEngine, EXIT_BAD_HANDOVER, EXIT_INTERNAL,
    EXIT_NOT_CONFINED, EXIT_OK, EXIT_WRONG_ROLE, ROLE_ENV, ROLE_VALUE,
};

// The host compiles everywhere so that a cross-platform caller gets a runtime
// refusal with a clear message rather than a link error - but on a non-Linux
// target every `extract` returns `UnsupportedPlatform`, so there is no second
// path that reads a document with nothing enforcing I2.
pub use host::{ChildProgram, SandboxedExtractor};