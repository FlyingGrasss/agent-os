//! Kernel event bus: observing what a sandboxed tool does.
//!
//! # The problem
//!
//! A sandbox restricts a tool's *authority*. It does not tell you what the tool
//! actually did, and a tool that stays inside its authority can still be
//! misbehaving in ways the sandbox cannot express: reading a file it should not
//! have wanted, writing a lot, talking to a host it should not know about.
//! The kernel observer answers that, and the answers go into the audit log.
//!
//! # The seam this crate is careful about
//!
//! An attacker who controls a web page controls every byte the tool reads and
//! writes, which means they control any path, argument, and hostname the tool
//! touches. If the event wire carried those bytes, the privileged reader would
//! be parsing attacker-controlled text on the way to the audit log and, from
//! there, to the Controller's prompt. That is invariant I1 failing at a new
//! seam, and it is a nastier failure than it looks, because the log would
//! faithfully record what the tool did and nobody would notice.
//!
//! So the wire format carries only closed-vocabulary data: variant tags, `u32`
//! pids and descriptors, counts, booleans, and 32-byte digests standing in for
//! names. See [`event`] for the details.
//!
//! # Layout
//!
//! * [`event`] - the [`Event`] vocabulary and its strict binary codec.
//! * [`audit`] - hash-chained records and [`audit::Verifier`].
//! * [`hash`] - SHA-256, and an honest statement of what a keyless chain hash
//!   does and does not protect against.
//! * [`probe`] - what the host actually offers, reported per requirement.
//!
//! # What is deliberately not here
//!
//! Loading eBPF programs, attaching probes, and ring-buffer plumbing. Those are
//! Linux-specific and belong behind this crate's types; [`probe::probe`] is the
//! portable half, and it exists so a deployment learns *why* observation is
//! unavailable rather than failing later at an opaque `load()`.

pub mod audit;
pub mod event;
pub mod hash;
pub mod probe;

pub use audit::{Chain, ChainError, Record, Verifier};
pub use event::{decode, decode_prefix, encode, DecodeError, Event, NameHash, OpenFlags};
pub use probe::{probe, Report as ProbeReport};