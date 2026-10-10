//! Codec round-trip and the "no text on the wire" property, asserted through
//! the public API rather than through internals.
//!
//! The hostile-input tests live in `decoder_robustness.rs`. This file covers
//! the ordinary path and the invariants that hold regardless of input.

use agentos_events::audit::{records_from_wire, Chain, Verifier};
use agentos_events::event::{hash_name, OpenFlags};
use agentos_events::{decode, encode, Event};

fn corpus() -> Vec<Event> {
    vec![
        Event::ProcessExec { pid: 0, ppid: 0 },
        Event::ProcessExec { pid: u32::MAX, ppid: u32::MAX },
        Event::ProcessExit { pid: 1, code: 0 },
        Event::ProcessExit { pid: 1, code: -1 },
        Event::ProcessExit { pid: 1, code: i32::MIN },
        Event::ProcessExit { pid: 1, code: i32::MAX },
        Event::FileOpen {
            pid: 1,
            fd: 0,
            path: hash_name(b""),
            flags: OpenFlags::NONE,
        },
        Event::FileOpen {
            pid: 1,
            fd: 3,
            path: hash_name(&[0xFF; 4096]),
            flags: OpenFlags::READ | OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::TRUNCATE,
        },
        Event::FileRead { pid: 1, fd: 3, bytes: 0 },
        Event::FileRead { pid: 1, fd: 3, bytes: u64::MAX },
        Event::FileWrite { pid: 1, fd: 3, bytes: u64::MAX },
        Event::NetConnect { pid: 1, fd: 5, addr: hash_name(b"\x00"), port: 0 },
        Event::NetConnect {
            pid: 1,
            fd: 5,
            addr: hash_name(b"host"),
            port: u16::MAX,
        },
        Event::CapCheck { pid: 1, cap: 0, granted: false },
        Event::CapCheck { pid: u32::MAX, cap: u32::MAX, granted: true },
        Event::PolicyViolation { pid: 1, cap: None },
        Event::PolicyViolation { pid: 1, cap: Some(0) },
        Event::PolicyViolation { pid: u32::MAX, cap: Some(u32::MAX) },
    ]
}

#[test]
fn every_event_round_trips() {
    for ev in corpus() {
        let bytes = encode(&ev);
        assert_eq!(decode(&bytes), Ok(ev), "round trip failed for {ev:?}");
    }
}

#[test]
fn encoding_is_deterministic() {
    // Determinism is what makes the audit digest verifiable by a second
    // auditor replaying the same events.
    for ev in corpus() {
        assert_eq!(encode(&ev), encode(&ev));
    }
}

#[test]
fn distinct_events_encode_to_distinct_frames() {
    let frames: Vec<Vec<u8>> = corpus().iter().map(encode).collect();
    for i in 0..frames.len() {
        for j in (i + 1)..frames.len() {
            assert_ne!(frames[i], frames[j], "frames {i} and {j} collided");
        }
    }
}

#[test]
fn a_name_hash_does_not_contain_its_input() {
    // An attacker-chosen path must not be recoverable from the frame. Searching
    // the encoded bytes for the path is the crude version of that test, but it
    // is the property that actually matters at the seam: nothing on the wire
    // spells out the name.
    let secret = b"/home/victim/.ssh/id_ed25519";
    let ev = Event::FileOpen {
        pid: 1,
        fd: 3,
        path: hash_name(secret),
        flags: OpenFlags::READ,
    };
    let bytes = encode(&ev);
    let needle_len = 8.min(secret.len());
    assert!(
        !bytes
            .windows(needle_len)
            .any(|w| w == &secret[..needle_len]),
        "encoded frame contains the start of the path"
    );
}

#[test]
fn the_coded_size_of_every_variant_is_fixed() {
    // The decoder sizes records from the tag, so a varying length would let a
    // hostile frame drive an allocation.
    let per_tag: Vec<usize> = corpus().iter().map(|e| encode(e).len()).collect();
    // Corpus mixes variants of different sizes; group by the tag byte.
    let mut by_tag: std::collections::BTreeMap<u8, Vec<usize>> = std::collections::BTreeMap::new();
    for (ev, len) in corpus().iter().zip(per_tag) {
        by_tag.entry(encode(ev)[5]).or_default().push(len);
    }
    for (tag, lens) in by_tag {
        assert!(
            lens.windows(2).all(|w| w[0] == w[1]),
            "tag {tag:#04x} produced frames of differing lengths: {lens:?}"
        );
    }
}

#[test]
fn a_chain_built_from_encoded_events_verifies_after_a_wire_round_trip() {
    // The path an auditor takes: bytes on disk back to a verified chain.
    let mut chain = Chain::new();
    let mut frames = Vec::new();
    for ev in corpus() {
        let (record, len) = chain.append(ev);
        assert_eq!(len as usize, frames.len() + 1);
        frames.push(encode(&record.event));
    }
    let expected_len = chain.len();

    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
    let rebuilt = records_from_wire(&refs).expect("valid frames should rebuild");

    assert_eq!(rebuilt.len() as u64, expected_len);
    assert_eq!(Verifier::new(expected_len).verify(&rebuilt), Ok(expected_len));
    assert_eq!(Verifier::head(&rebuilt), Some(chain.head()));
}

#[test]
fn the_chain_digest_covers_every_byte_of_the_frame() {
    // Walk the flip point across the whole frame rather than sampling, so a
    // field accidentally left out of the digest input cannot hide in a byte the
    // test never touched.
    //
    // What is being checked is coverage: tampering with any byte changes the
    // link digest, so it changes the chain head and no longer matches a head
    // published out of band. A single-record chain cannot show the *link*
    // break, which is why this asserts on the digest rather than on a verify.
    let mut chain = Chain::new();
    let (record, _) = chain.append(Event::FileOpen {
        pid: 1234,
        fd: 56,
        path: hash_name(b"/etc/passwd"),
        flags: OpenFlags::READ,
    });
    let frame = encode(&record.event);

    // Bytes 0..4 are the magic, 4 is the version, 5 is the kind tag. Below the
// header the frame must still decode, and its digest must change.
const HEADER_LEN: usize = 6;

for idx in 0..frame.len() {
        let mut tampered = frame.clone();
        tampered[idx] ^= 0x01;

        if idx < HEADER_LEN {
            // Header bytes may be rejected outright by the decoder. If one
            // happens to remain decodable, it must still not reproduce the
            // original digest.
            if let Ok(rebuilt) = records_from_wire(&[&tampered]) {
                assert_ne!(
                    rebuilt[0].digest, record.digest,
                    "header byte {idx} is not covered by the chain digest"
                );
            }
            continue;
        }

        let rebuilt = records_from_wire(&[&tampered])
            .expect("a payload-byte flip must leave the frame structurally valid");
        assert_ne!(
            rebuilt[0].digest, record.digest,
            "byte {idx} is not covered by the chain digest"
        );
        assert_ne!(rebuilt[0].event, record.event, "byte {idx} changed nothing");
    }
}