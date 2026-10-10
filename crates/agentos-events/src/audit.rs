//! Hash-chained audit records and the verifier that walks them.
//!
//! # What the chain is for
//!
//! Invariant I6 says every action is recorded before it executes. A chain
//! turns "there is a log" into "the log is the one that was written": each
//! record commits to its predecessor, so an edit anywhere invalidates every
//! link after it and a splice-out is visible as a gap.
//!
//! # What the chain is not for
//!
//! See the [`crate::hash`] module docs: the link hash is keyless, so anyone who
//! can read the log can recompute every digest. This detects corruption,
//! reordering, truncation against a known length, and a naive
//! edit-without-recomputing. It does not resist an adversary who re-derives
//! the chain, and no claim here should be read as claiming it does.
//!
//! # Truncation, and the honest limitation
//!
//! A chain alone **cannot** detect a truncated tail. Drop the last ten records
//! and every remaining link still verifies; there is nothing left that
//! disagrees. Detecting it requires a length or a terminal marker that the
//! truncator cannot reach.
//!
//! [`Verifier::verify`] therefore takes the expected record count as a
//! separate input. The count must come from somewhere the log cannot rewrite:
//! the length is returned by [`Chain::append`] to be persisted out of band, or
//! published as a terminal record whose own digest is checked. If an attacker
//! controls both the log and the expected count, truncation is undetectable by
//! construction, and no arrangement of the chain changes that.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::event::{decode, encode, DecodeError, Event};
use crate::hash::{digests_equal, Digest};

/// The `prev` field of the first record. A chain that does not start here is
/// a suffix of some longer chain, which is itself a reason to look.
pub const GENESIS: Digest = Digest([0u8; 32]);

/// One link in the audit chain.
///
/// `digest = H(label || prev || seq || event_bytes)`. The event is carried in
/// its encoded form so that the digest is over exactly the bytes a verifier
/// will re-read; hashing a struct instead would let two encodings of the same
/// event disagree about what was committed to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub prev: Digest,
    pub event: Event,
    pub digest: Digest,
}

impl Record {
    /// Recompute this record's digest from its own contents.
    pub fn expected_digest(&self) -> Digest {
        let ev_bytes = encode(&self.event);
        let seq = self.seq.to_be_bytes();
        let prev = self.prev.0;
        crate::event::digest_of(&[&prev, &seq, &ev_bytes])
    }

    /// True when this record's digest matches its contents and its stated
    /// predecessor.
    ///
    /// Alone this checks nothing about the chain, since `prev` is inside the
    /// record and therefore under the same control. It is exposed so a caller
    /// that reconstructs records from raw bytes can check each one before
    /// deciding what to do with it.
    pub fn is_self_consistent(&self) -> bool {
        digests_equal(&self.expected_digest().0, &self.digest.0)
    }
}

/// Rendered without the event payload.
///
/// A record is audit material, so it gets a readable form. The event is
/// summarised rather than dumped because a dump would be the path back to
/// whatever the caller chose to put in it.
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("seq", &self.seq)
            .field("prev", &format_args!("{:02x}{:02x}..", self.prev.0[0], self.prev.0[1]))
            .field("digest", &format_args!("{:02x}{:02x}..", self.digest.0[0], self.digest.0[1]))
            .field("event", &self.event)
            .finish()
    }
}

/// Append-only builder that maintains the running chain head.
#[derive(Debug, Clone)]
pub struct Chain {
    head: Digest,
    next_seq: u64,
    len: u64,
}

impl Chain {
    /// A fresh chain, starting at genesis.
    pub fn new() -> Self {
        Self { head: GENESIS, next_seq: 0, len: 0 }
    }

    /// Seal an event into a record and advance the head.
    ///
    /// Returns the record *and* the chain length after appending. The length is
    /// the value a caller must persist out of band; see the module docs on why
    /// the chain cannot supply it.
    pub fn append(&mut self, event: Event) -> (Record, u64) {
        let prev = self.head;
        let seq = self.next_seq;
        let ev_bytes = encode(&event);
        let seq_be = seq.to_be_bytes();
        let digest = crate::event::digest_of(&[&prev.0, &seq_be, &ev_bytes]);
        self.head = digest;
        self.next_seq += 1;
        self.len += 1;
        (Record { seq, prev, event, digest }, self.len)
    }

    /// The current head digest, for publishing alongside the log.
    pub fn head(&self) -> Digest {
        self.head
    }

    /// Number of records appended so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Default is a fresh chain at genesis, which is the same as [`Chain::new`].
///
/// Provided because a default-constructed value must not be a usable chain
/// with an arbitrary head; here the default and the explicit constructor agree
/// on genesis, so there is no way to accidentally start an unattested chain.
impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// A way the chain failed to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The record at this index does not commit to the digest of the one
    /// before it.
    #[error("record {index} does not follow record {index}: prev link mismatch")]
    BrokenLink { index: usize },
    /// The record's own digest does not match its contents: the record was
    /// altered after it was sealed.
    #[error("record {index} contents do not match its digest")]
    AlteredRecord { index: usize },
    /// Sequence numbers are not consecutive from zero. Either a record was
    /// removed or one was inserted; the chain alone cannot say which, and the
    /// error deliberately does not guess.
    #[error("record {index} has seq {found}, expected {expected}")]
    SequenceGap { index: usize, expected: u64, found: u64 },
    /// Fewer records than the expected count. See the module docs: this is only
    /// detectable because the caller supplied the count out of band.
    #[error("log has {found} records, expected {expected}")]
    Truncated { expected: u64, found: u64 },
    /// More records than the expected count. An append after the count was
    /// published, which is either a bug or an extra record nobody attested to.
    #[error("log has {found} records, expected {expected}")]
    LengthMismatch { expected: u64, found: u64 },
    /// The first record does not start at genesis, so this is a suffix of a
    /// longer chain with its head removed.
    #[error("first record does not start at genesis")]
    NotGenesis,
}

/// What a verification pass found.
///
/// `ok` alone is the answer most callers want; the error carries the index so
/// an operator can go and look at the offending record instead of re-deriving
/// everything.
pub type ChainResult = Result<u64, ChainError>;

/// Verifies a chain of records against an expected length.
///
/// The expected length is not optional and is not read from the log. An empty
/// log with an expected length of zero is the one case that cannot distinguish
/// "nothing happened" from "everything was removed", and it is reported as
/// valid because the count says so.
#[derive(Debug, Clone, Copy)]
pub struct Verifier {
    expected_len: u64,
}

impl Verifier {
    /// Build a verifier for a log known to hold `expected_len` records.
    ///
    /// If this fails, either an action was executed with no record, or a record
    /// was destroyed. Both break I6 and neither is visible from the remaining
    /// chain.
    pub fn new(expected_len: u64) -> Self {
        Self { expected_len }
    }

    /// Walk the records in order.
    ///
    /// Checks, in order of earliest possible detection: sequence numbers are
    /// consecutive, each record commits to its predecessor, and each record's
    /// digest matches its own contents. Length is checked last so that a
    /// truncated log reports the structural break it caused where it occurred,
    /// rather than only reporting a smaller count.
    pub fn verify(&self, records: &[Record]) -> ChainResult {
        let mut prev = GENESIS;

        for (index, r) in records.iter().enumerate() {
            let expected_seq = index as u64;
            if r.seq != expected_seq {
                return Err(ChainError::SequenceGap {
                    index,
                    expected: expected_seq,
                    found: r.seq,
                });
            }
            if !digests_equal(&prev.0, &r.prev.0) {
                return Err(ChainError::BrokenLink { index });
            }
            if !r.is_self_consistent() {
                return Err(ChainError::AlteredRecord { index });
            }
            prev = r.digest;
        }

        // An empty log that claims to be non-empty is caught here, and so is a
        // missing genesis link when the caller expected records.
        if records.is_empty() && self.expected_len > 0 {
            return Err(ChainError::Truncated { expected: self.expected_len, found: 0 });
        }
        if records.is_empty() {
            return Ok(0);
        }

        let found = records.len() as u64;
        if found != self.expected_len {
            return Err(if found < self.expected_len {
                ChainError::Truncated { expected: self.expected_len, found }
            } else {
                ChainError::LengthMismatch { expected: self.expected_len, found }
            });
        }

        Ok(found)
    }

    /// The head digest of a verified chain, for comparing against a value
    /// published out of band.
    pub fn head(records: &[Record]) -> Option<Digest> {
        records.last().map(|r| r.digest)
    }
}

/// Build a chain from bare event frames.
///
/// # This authenticates nothing
///
/// Despite the name, this does **not** verify anything. It recomputes the chain
/// over whatever events it is handed, so an event edited before it arrives
/// produces a perfectly valid chain. It is a *builder*, not a *verifier*.
///
/// The distinction is not pedantic. An earlier version of this function's doc
/// said only "re-derive records from their encoded bytes, checking each one",
/// which reads as though the output could be trusted -- and a caller who believed
/// that would be treating attacker-editable bytes as evidence.
///
/// **To check a log that was stored, use [`Verifier::verify`] on the stored
/// [`Record`]s**, each of which carries the `prev` and `digest` it was written
/// with. That is the path that detects editing, because the digest is compared
/// against a recomputation rather than being produced by it.
///
/// Use this function to rebuild a chain from events the caller produced itself,
/// or in tests. `tests/tamper.rs` pins both halves of that statement so the
/// distinction cannot quietly change.
///
/// What it does still enforce: every frame goes through the strict decoder, so
/// trailing garbage or an unknown kind fails here rather than becoming a record.
pub fn records_from_wire(frames: &[&[u8]]) -> Result<Vec<Record>, WireError> {
    let mut out = Vec::with_capacity(frames.len());
    let mut prev = GENESIS;
    for (index, frame) in frames.iter().enumerate() {
        let event = decode(frame).map_err(|source| WireError::Decode { index, source })?;
        let seq = index as u64;
        let seq_be = seq.to_be_bytes();
        let digest = crate::event::digest_of(&[&prev.0, &seq_be, frame]);
        // `prev` must go into the record before the cursor advances. Assigning
        // first would make each record claim itself as its own predecessor,
        // which is self-consistent and therefore verifies for a chain that was
        // never actually linked.
        out.push(Record { seq, prev, event, digest });
        prev = digest;
    }
    Ok(out)
}

/// Failure rebuilding records from wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("frame {index} failed to decode: {source}")]
    Decode { index: usize, source: DecodeError },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::hash_name;

    fn events(n: u32) -> Vec<Event> {
        (0..n)
            .map(|i| Event::FileWrite {
                pid: i,
                fd: 1,
                bytes: u64::from(i) * 10,
            })
            .collect()
    }

    fn chain_of(n: u32) -> Vec<Record> {
        let mut c = Chain::new();
        events(n).into_iter().map(|e| c.append(e).0).collect()
    }

    #[test]
    fn a_valid_chain_verifies() {
        let recs = chain_of(5);
        assert_eq!(Verifier::new(5).verify(&recs), Ok(5));
    }

    #[test]
    fn an_empty_chain_verifies_only_when_empty_is_expected() {
        assert_eq!(Verifier::new(0).verify(&[]), Ok(0));
        assert!(matches!(
            Verifier::new(3).verify(&[]),
            Err(ChainError::Truncated { expected: 3, found: 0 })
        ));
    }

    #[test]
    fn flipping_one_byte_in_the_middle_is_detected() {
        let mut recs = chain_of(6);
        // Recompute the digest for the edited record so the chain still looks
        // locally consistent; only the link to the *next* record gives it away.
        // This is the interesting case: the naive "did the digest match" check
        // would pass here.
        recs[3].event = Event::FileWrite { pid: 9999, fd: 1, bytes: 0 };
        recs[3].digest = recs[3].expected_digest();

        assert!(matches!(
            Verifier::new(6).verify(&recs),
            Err(ChainError::BrokenLink { index: 4 })
        ));
    }

    #[test]
    fn a_digest_left_unrecomputed_is_caught_directly() {
        let mut recs = chain_of(6);
        recs[3].event = Event::FileWrite { pid: 9999, fd: 1, bytes: 0 };
        assert!(matches!(
            Verifier::new(6).verify(&recs),
            Err(ChainError::AlteredRecord { index: 3 })
        ));
    }

    #[test]
    fn swapping_two_adjacent_records_is_detected() {
        let mut recs = chain_of(6);
        recs.swap(2, 3);
        // seq fields moved with the records, so the first thing to fail is the
        // sequence check rather than the link. Both are detections.
        assert!(Verifier::new(6).verify(&recs).is_err());
    }

    #[test]
    fn swapping_and_resequencing_is_still_caught_by_the_link() {
        // The stronger version of the swap: an editor who also fixes up the seq
        // numbers to look tidy. The chain still catches it, because each record
        // still commits to the previous digest.
        let mut recs = chain_of(6);
        recs.swap(2, 3);
        recs[2].seq = 2;
        recs[3].seq = 3;
        let assert_broken = matches!(
            Verifier::new(6).verify(&recs),
            Err(ChainError::BrokenLink { .. }) | Err(ChainError::AlteredRecord { .. })
        );
        assert!(assert_broken, "resequenced swap slipped through");
    }

    #[test]
    fn truncation_is_detected_given_the_expected_length() {
        let recs = chain_of(10);
        let truncated = &recs[..6];
        assert!(matches!(
            Verifier::new(10).verify(truncated),
            Err(ChainError::Truncated { expected: 10, found: 6 })
        ));
    }

    #[test]
    fn truncation_from_the_end_that_is_structurally_invisible_is_still_caught() {
        // Dropping a whole-record-aligned suffix leaves every remaining link
        // valid. Only the out-of-band count catches it. This test exists to
        // document that dependence rather than to claim the chain does it.
        let recs = chain_of(10);
        let truncated = &recs[..6];
        let head = Verifier::head(truncated).unwrap();
        let mut recomputed = Vec::new();
        let mut c = Chain::new();
        for r in truncated {
            recomputed.push(c.append(r.event).0);
        }
        assert_eq!(head, recomputed.last().unwrap().digest);
        assert!(Verifier::new(6).verify(truncated).is_ok());
        assert!(Verifier::new(10).verify(truncated).is_err());
    }

    #[test]
    fn extra_records_are_rejected() {
        let recs = chain_of(4);
        assert!(matches!(
            Verifier::new(3).verify(&recs),
            Err(ChainError::LengthMismatch { expected: 3, found: 4 })
        ));
    }

    #[test]
    fn a_chain_whose_genesis_is_missing_is_rejected() {
        let mut recs = chain_of(4);
        recs.remove(0);
        assert!(Verifier::new(3).verify(&recs).is_err());
    }

    #[test]
    fn removing_a_record_from_the_middle_is_detected() {
        let mut recs = chain_of(6);
        recs.remove(2);
        // Resequence so only the link check can catch it.
        for (i, r) in recs.iter_mut().enumerate() {
            r.seq = i as u64;
        }
        assert!(Verifier::new(5).verify(&recs).is_err());
    }

    #[test]
    fn the_first_record_points_at_genesis() {
        // A builder that advanced its cursor before building the record would
        // give every record itself as its own predecessor. That is internally
        // consistent, so a self-consistency check alone would not notice.
        let recs = chain_of(1);
        assert_eq!(recs[0].prev, GENESIS);
        assert!(recs[0].is_self_consistent());
    }

    #[test]
    fn wire_rebuild_agrees_with_the_builder() {
        let built = chain_of(4);
        let frames: Vec<Vec<u8>> = built.iter().map(|r| encode(&r.event)).collect();
        let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        let rebuilt = records_from_wire(&refs).expect("valid frames should rebuild");
        assert_eq!(rebuilt, built);
    }

    #[test]
    fn wire_rebuild_refuses_a_frame_with_appended_bytes() {
        let built = chain_of(2);
        let mut frame = encode(&built[0].event);
        frame.push(0xFF);
        assert!(matches!(
            records_from_wire(&[&frame]),
            Err(WireError::Decode { index: 0, .. })
        ));
    }

    #[test]
    fn two_chains_of_identical_events_have_identical_digests() {
        // Determinism matters for auditability: a second auditor replaying the
        // same events must derive the same chain.
        assert_eq!(chain_of(7), chain_of(7));
    }

    #[test]
    fn chain_length_is_reported_for_out_of_band_storage() {
        let mut c = Chain::new();
        let mut last = 0;
        for e in events(4) {
            let (_, len) = c.append(e);
            last = len;
        }
        assert_eq!(last, 4);
        assert_eq!(c.len(), 4);
    }

    #[test]
    fn a_different_event_yields_a_different_head() {
        // Guards against a digest that ignores the event, which would make the
        // chain blind to exactly the content it exists to attest.
        let mut a = Chain::new();
        let _ = a.append(Event::NetConnect {
            pid: 1,
            fd: 2,
            addr: hash_name(b"10.0.0.1"),
            port: 443,
        });
        let mut b = Chain::new();
        let _ = b.append(Event::NetConnect {
            pid: 1,
            fd: 2,
            addr: hash_name(b"10.0.0.2"),
            port: 443,
        });
        assert_ne!(a.head(), b.head());
    }

    #[test]
    fn a_different_sequence_number_yields_a_different_digest() {
        // The seq is inside the digest input, so a record cannot be renumbered
        // and re-linked at a different position without detection.
        let ev = Event::ProcessExec { pid: 1, ppid: 0 };
        let mut c = Chain::new();
        let (r0, _) = c.append(ev);
        let mut shifted = r0.clone();
        shifted.seq = 7;
        assert_ne!(shifted.expected_digest(), r0.digest);
    }

    #[test]
    fn a_different_prev_yields_a_different_digest() {
        let ev = Event::ProcessExec { pid: 1, ppid: 0 };
        let mut c = Chain::new();
        let (r0, _) = c.append(ev);
        let mut moved = r0.clone();
        moved.prev = Digest([0xAB; 32]);
        assert_ne!(moved.expected_digest(), r0.digest);
    }
}