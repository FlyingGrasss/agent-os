//! Provenance: identifying an inbox item without naming it.
//!
//! # The problem
//!
//! Two things went wrong with the first version of the inbox, and both are
//! operational rather than adversarial.
//!
//! **Traceability.** A summary came out and nobody could tell which drop produced
//! it. The log carried a `NameHash` of the filename — which is exactly the wrong
//! direction, since the name is attacker-chosen and must not be readable by the
//! daemon. So the log could show *that* something was processed without showing
//! *what*, which is the one case where showing what is both useful and safe,
//! because the operator is a person, not the model.
//!
//! **Flooding.** A directory with ten thousand files in it produced ten thousand
//! model calls. There was no admission control at all, because a token is only
//! worth minting if something spends it.
//!
//! # The two identifiers, and why there are two
//!
//! [`CorrelationId`] is 128 random bits. It is *random*, not derived. It answers
//! "which log lines belong to this one run" and nothing else, and it cannot be
//! used to confirm a guess about the payload — an attacker who knows the exact
//! bytes they dropped cannot compute the correlation id, because nothing about
//! their bytes feeds it.
//!
//! [`PayloadDigest`] is SHA-256 over the payload, domain-separated. It answers
//! "have I already processed these exact bytes", which is what stops one file
//! dropped ten thousand times from costing ten thousand model calls. It *is*
//! derived from the payload, so it carries one property the correlation id does
//! not: someone who already knows the payload can confirm a match. That is a much
//! smaller thing than it sounds — it tells them what they already knew — and the
//! alternative (hashing nothing) means the flood defence does not work.
//!
//! # What neither of them is allowed to do
//!
//! Reach the Controller's prompt. Both are on the *log* side of the system: they
//! correlate a log line to a drop, for a person reading a log. `Display` and
//! `Debug` are implemented so that can work, and neither has any way to produce
//! the original text.
//!
//! Neither is a `Trusted<T>`, so neither can reach a prompt even by accident.
//! They are plain values, and the task text is still a constant.

use std::collections::VecDeque;

use crate::hash::hash_parts;
use crate::random;

/// Bytes in a [`CorrelationId`].
///
/// 128 bits. Not a tunable: this is the width where an attacker cannot enumerate
/// the space before the process exits.
pub const CORRELATION_ID_BYTES: usize = 16;

/// How many hex characters of a [`CorrelationId`] appear in a log line.
///
/// 12 hex characters is 48 bits. Enough that two runs colliding in one log is
/// not something an operator will see, short enough to read aloud while
/// correlating by hand. The *full* id is compared internally; only the display is
/// truncated, so a collision in the log is cosmetic rather than a correctness
/// problem.
pub const CORRELATION_DISPLAY_CHARS: usize = 12;

/// How many hex characters of a [`PayloadDigest`] appear in a log line.
///
/// 16 hex characters is 64 bits, chosen so that an operator can verify a digest
/// against a file they hold without the value being a practical confirmation
/// oracle for a short payload. It is a *display* width; comparisons use all 256.
pub const DIGEST_DISPLAY_CHARS: usize = 16;

/// A random identifier for one processing run.
///
/// Carries no information about the payload. Its only job is to be quoted in a
/// log line so a person can find the rest of that run's lines.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorrelationId([u8; CORRELATION_ID_BYTES]);

impl CorrelationId {
    /// Draw a fresh id.
    ///
    /// Fails rather than falling back, for the reason in [`crate::random`]: a
    /// guessable correlation id would let someone forge log lines that look like
    /// they belong to a real run.
    pub fn generate() -> Result<Self, String> {
        let bytes = random::fill16().map_err(|e| format!("could not draw a correlation id: {e}"))?;
        Ok(CorrelationId(bytes))
    }

    /// The full 32-character hex form.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// The first [`CORRELATION_DISPLAY_CHARS`] hex characters, for log lines.
    pub fn short(&self) -> String {
        self.to_hex().chars().take(CORRELATION_DISPLAY_CHARS).collect()
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

impl std::fmt::Debug for CorrelationId {
    /// Prints the full value rather than redacting.
    ///
    /// The opposite of `NameHash`, and deliberately. `NameHash` stands in for an
    /// attacker-chosen *name*, and a `Debug` that printed its preimage would be an
    /// exfiltration channel for bytes that must not leave. A `CorrelationId` is
    /// random: it discloses nothing, and an operator reading a log in a debugger
    /// needs to be able to quote it. The value is safe to print because it is not
    /// derived from anything.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CorrelationId({})", self.to_hex())
    }
}

/// SHA-256 over an inbox payload, domain-separated.
///
/// Domain separation matters: an audit-chain digest and a payload digest are both
/// SHA-256 over something, and sharing a construction between them would let a
/// value cross from one domain to the other. The label makes that impossible by
/// construction rather than by convention.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadDigest([u8; 32]);

impl PayloadDigest {
    /// Hash a payload's bytes.
    pub fn of(bytes: &[u8]) -> Self {
        PayloadDigest(hash_parts(b"agentos/inbox-payload/v1", &[bytes]))
    }

    /// The full 64-character hex form.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// The first [`DIGEST_DISPLAY_CHARS`] hex characters, for log lines.
    pub fn short(&self) -> String {
        self.to_hex().chars().take(DIGEST_DISPLAY_CHARS).collect()
    }

    /// Constant-time equality.
    ///
    /// The same reason `agentos_types::digest::digests_equal` does it: a digest
    /// comparison that exits early is a comparison whose timing says how much
    /// matched. Cheap here, but there is no reason to make it free.
    fn matches(&self, other: &PayloadDigest) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl std::fmt::Display for PayloadDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.short())
    }
}

impl std::fmt::Debug for PayloadDigest {
    /// Truncated, unlike `CorrelationId`.
    ///
    /// A digest is derived from the payload, so printing all 64 characters is
    /// printing as much of a confirmation oracle as the value supports. The
    /// short form is enough for an operator to match a log line to a file they
    /// hold and no more.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PayloadDigest({})", self.short())
    }
}

/// A bounded, insertion-ordered set of recently seen payload digests.
///
/// This is the flood defence. Ten thousand copies of one file have one digest, so
/// the second through ten-thousandth are recognised and skipped without spending
/// a model call.
///
/// # Why it is bounded
///
/// A set of everything ever seen is a set an attacker grows without limit: keep
/// dropping distinct files and the memory goes up forever. Bounded, the oldest
/// digests fall out and the protection covers the recent window, which is the
/// window a flood actually occupies. Re-dropping a file after it has aged out
/// costs one model call, which is the right trade — the alternative is a limit
/// that can be pushed rather than a window that expires.
///
/// The bound is on *entries*, not on bytes, so memory is predictable
/// independently of payload size.
#[derive(Debug, Clone)]
pub struct DigestWindow {
    seen: VecDeque<PayloadDigest>,
    capacity: usize,
}

impl DigestWindow {
    /// A window holding the most recent `capacity` digests.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Whether this payload has been seen recently.
    pub fn contains(&self, digest: &PayloadDigest) -> bool {
        self.seen.iter().any(|d| d.matches(digest))
    }

    /// Record a payload, evicting the oldest if full.
    ///
    /// Returns `true` if the digest was already present, which the caller reads as
    /// "this is a repeat, do not process it".
    pub fn record(&mut self, digest: PayloadDigest) -> bool {
        if self.contains(&digest) {
            return true;
        }
        if self.capacity == 0 {
            return false;
        }
        if self.seen.len() >= self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(digest);
        false
    }

    /// How many digests are currently held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for DigestWindow {
    /// 1024 entries. Chosen so a flood of identical drops is caught in full
    /// (the limit will not admit 1024 of them) while the set stays small.
    fn default() -> Self {
        Self::new(1024)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[(byte >> 4) as usize]));
        out.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    out
}

const DIGITS: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests;