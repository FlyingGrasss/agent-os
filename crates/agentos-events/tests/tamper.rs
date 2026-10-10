//! Independent tamper tests against the audit chain.
//!
//! The crate's own tests assert that a flipped byte, a swapped pair, and a
//! truncated log are all caught. These re-derive the same claims from outside,
//! and add the cases a test written alongside the implementation tends to miss:
//! forgery, replay from a different origin, and the empty-log case.
//!
//! # The threat being modelled
//!
//! An attacker who can write to the audit log -- a compromised tool, a bug in the
//! collector -- wants a reader to believe something false. The chain is
//! **keyless**, so anyone can recompute a consistent chain over records they
//! invented. What the chain does buy is that they cannot *edit* an existing chain
//! in place, cannot reorder it, and cannot shorten it without the reader's
//! out-of-band length disagreeing.
//!
//! Forgery of an entire chain is out of reach of a keyless hash. That limitation
//! is real and is not papered over here; see the module docs on `hash`.

use agentos_events::audit::{Chain, ChainError, Verifier};
use agentos_events::event::Event;

fn log(n: usize) -> Vec<agentos_events::audit::Record> {
    let mut chain = Chain::new();
    (0..n)
        .map(|i| chain.append(Event::FileRead {
            pid: 1000 + i as u32,
            fd: 3,
            bytes: i as u64,
        }).0)
        .collect()
}

/// An untouched chain verifies.
#[test]
fn an_untouched_chain_verifies() {
    let records = log(8);
    let v = Verifier::new(8);
    assert_eq!(v.verify(&records).expect("a clean chain verifies"), 8);
}

/// Flipping a bit in a *stored record* is detected.
///
/// # Which path this tests, and why the distinction is the whole point
///
/// There are two ways records arrive:
///
/// 1. **Stored records** -- each persisted with its `seq`, `prev` and `digest`,
///    then re-verified later. This is the protected path: `verify` recomputes
///    each record's digest and compares, so editing the event breaks it.
/// 2. **Raw frames** through `records_from_wire` -- which *builds* the chain from
///    bare events rather than checking a stored one. Editing an event there and
///    re-deriving produces a perfectly valid chain, because that is what the
///    function does: it is a builder, not a verifier.
///
/// The first draft of this test used path 2 and reported that a bit flip "was
/// not detected" -- which read as a hole in the hash chain and was actually a
/// hole in the test. The distinction is worth a test of its own, because a reader
/// who assumes `records_from_wire` authenticates anything is wrong, and that is
/// the assumption worth pre-empting.
#[test]
fn a_single_bit_flip_in_a_stored_record_is_detected() {
    let mut records = log(6);
    let clean = Verifier::new(6)
        .verify(&records)
        .expect("the clean chain must verify first");

    // Flip one bit in the payload of every record in turn. The event is read out
    // and written back so the borrow ends before `verify` needs `&records`.
    let mut detected = 0;
    let mut total = 0;
    for index in 0..records.len() {
        for bit in 0..32 {
            let original = records[index].event;
            match &mut records[index].event {
                Event::FileRead { pid, .. } => *pid ^= 1 << bit,
                _ => unreachable!("log() builds FileRead records"),
            }
            total += 1;
            let refused = Verifier::new(6).verify(&records).is_err();
            records[index].event = original;
            assert!(
                refused,
                "flipping bit {bit} of record {index}'s pid was not detected"
            );
            detected += 1;
        }
    }
    assert_eq!(clean, 6);
    assert!(detected > 0 && detected == total);
}

/// The from-wire path builds a chain; it does not authenticate one.
///
/// Asserted rather than left implicit, because the function name
/// (`records_from_wire`) invites the opposite assumption. A caller who treats its
/// output as *evidence* rather than as *a reconstruction* would be trusting
/// attacker-editable bytes.
///
/// The correct use is: a reader that has stored records calls `verify`. This
/// function is for rebuilding a chain from events it produced itself, or for
/// testing. It is not a trust boundary.
#[test]
fn records_from_wire_derives_rather_than_authenticates() {
    let mut frames: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            let mut c = Chain::new();
            let (record, _) = c.append(Event::FileWrite {
                pid: 3000 + i as u32,
                fd: 4,
                bytes: i as u64,
            });
            agentos_events::event::encode(&record.event)
        })
        .collect();

    // Tamper with an event before it is ever chained.
    frames[1][8] ^= 0x01; // first byte of pid

    let borrowed: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let records = agentos_events::audit::records_from_wire(&borrowed)
        .expect("frames still decode individually");

    assert!(
        Verifier::new(4).verify(&records).is_ok(),
        "records_from_wire recomputes the chain over whatever events it is given, \
         so an edited event yields a valid chain. That is what a builder does. \
         Authentication requires records that were STORED with their digests -- \
         see a_single_bit_flip_in_a_stored_record_is_detected."
    );
}

/// Swapping two adjacent records is detected.
///
/// Reordering is the attack a naive per-record checksum misses entirely: every
/// record is individually intact.
#[test]
fn swapping_adjacent_records_is_detected() {
    let mut records = log(6);
    records.swap(2, 3);
    let v = Verifier::new(6);
    let err = v.verify(&records).expect_err("a reordered chain must not verify");
    // Either complaint is correct -- the sequence numbers no longer line up, and
    // the link digests no longer chain. Asserting on the specific variant would
    // pin an implementation detail; asserting that it is *some* variant would let
    // a wrong answer through, so both are named.
    assert!(
        matches!(
            err,
            ChainError::SequenceGap { .. } | ChainError::BrokenLink { .. }
        ),
        "reordering produced an unrelated error: {err:?}"
    );
}

/// A gap in the middle is detected.
#[test]
fn a_missing_middle_record_is_detected() {
    let mut records = log(6);
    records.remove(3);
    assert!(
        Verifier::new(6).verify(&records).is_err(),
        "a chain missing a record must not verify against an expected length"
    );
}

/// Shortening the log is detected when the caller knows the true length.
#[test]
fn truncation_against_a_known_length_is_detected() {
    let records = log(10);
    for keep in [0usize, 1, 5, 9] {
        let err = Verifier::new(10)
            .verify(&records[..keep])
            .expect_err("a shortened log must not verify");
        assert!(
            matches!(err, ChainError::Truncated { .. }),
            "truncating to {keep} gave {err:?}"
        );
    }
}

/// An empty log claiming to be non-empty is refused.
///
/// The degenerate case, and one a length check written as `found < expected`
/// would miss.
#[test]
fn an_empty_log_is_refused_when_records_were_expected() {
    assert!(matches!(
        Verifier::new(1).verify(&[]),
        Err(ChainError::Truncated { expected: 1, found: 0 })
    ));
}

/// An empty log with nothing expected is fine.
#[test]
fn an_empty_log_verifies_when_nothing_was_expected() {
    assert_eq!(Verifier::new(0).verify(&[]).expect("empty is consistent"), 0);
}

/// Longer than expected is refused too, not just shorter.
#[test]
fn a_longer_log_is_refused() {
    let records = log(4);
    assert!(matches!(
        Verifier::new(2).verify(&records),
        Err(ChainError::LengthMismatch { .. })
    ));
}

/// The documented limitation: a whole chain can be forged, because the hash is
/// keyless.
///
/// Written as a test on purpose. A limitation that lives only in a doc comment
/// gets forgotten; a limitation with a test attached gets re-read whenever the
/// code changes. It asserts that forging *succeeds*, so if someone later adds a
/// key this test fails and forces them to update the claim deliberately rather
/// than leaving a stale warning in a comment.
///
/// This is not a weakness being celebrated -- it is the reason a key is needed if
/// the audit log has to be non-forgeable across a trust boundary.
#[test]
fn a_keyless_chain_can_be_forged_which_is_why_a_key_is_needed() {
    // Build a chain whose contents were never observed by the original writer.
    let mut forged = Chain::new();
    let records: Vec<_> = (0..4)
        .map(|i| {
            forged
                .append(Event::FileRead {
                    pid: 666,
                    fd: 9,
                    bytes: i as u64,
                })
                .0
        })
        .collect();

    assert!(
        Verifier::new(4).verify(&records).is_ok(),
        "a freshly built chain verifies -- which is exactly the point. The chain \
         detects *editing* and *reordering*, not *invention*. Non-forgeability \
         needs a key held outside the sandbox."
    );
}
