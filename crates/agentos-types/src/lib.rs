//! Shared types for AgentOS.
//!
//! The central abstraction is [`Val<T>`]: a value paired with a provenance
//! [`Label`]. Labels propagate through every operation, and converting a
//! tainted value into a [`Trusted<T>`] requires an explicit disclosure.

mod capability;
mod digest;
mod event;
mod provenance;
mod value;

pub use capability::{Cap, CapId, CapKind, CapRegistry, CapabilityError};
pub use event::{Event, EventId};
pub use provenance::{Label, SourceId, SourceKind};
pub use value::{
    approval_key, Approval, Confirmation, ConfirmationError, ControllerAuthority, Origin,
    Quarantined, TaintError, Trusted, Val,
};

/// A value produced by the trusted user, never by an untrusted source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct UserId(pub uuid::Uuid);
