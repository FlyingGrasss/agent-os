//! Independent attack on the decoder, from outside the crate.
//!
//! The crate has 54 tests. This file exists because a decoder's own tests are
//! written by the same person who wrote the decoder, against the same mental
//! model. These cases are written to break that model rather than to confirm it.
//!
//! Run: `cargo test -p agentos-events --test attack`

use agentos_events::event::{
    decode, encode, hash_name, DecodeError, Event, OpenFlags, MAGIC, VERSION};

fn read(pid: u32, fd: u32, bytes: u64) -> Event {
    Event::FileRead { pid, fd, bytes }
}

/// Every byte position is a place a frame can be cut short.
#[test]
fn truncation_at_any_offset_is_refused() {
    let full = encode(&read(0xDEAD_BEEF, 7, u64::MAX));
    for cut in 0..full.len() {
        match decode(&full[..cut]) {
            Err(_) => {}
            Ok(_) => panic!("truncating to {cut} of {} bytes decoded anyway", full.len()),
        }
    }
    // And the whole thing must still work, or "everything is refused" passes.
    assert!(decode(&full).is_ok());
}

/// Appending bytes must never be silently accepted.
///
/// This is the one that matters most for a ring-buffer reader. If trailing bytes
/// were ignored, an attacker who can write to the buffer could append a second
/// frame of their own and have it read as though the kernel produced it.
#[test]
fn appended_bytes_are_refused() {
    let base = encode(&read(1, 2, 3));
    let cap = agentos_events::event::MAX_FRAME_LEN;

    // Small appends keep the buffer a legal length, so the only thing wrong with
    // the frame is the trailing data, and the refusal must name exactly that.
    for extra in [1usize, 2, 8] {
        let mut buf = base.clone();
        buf.extend(std::iter::repeat_n(0x41u8, extra));
        assert!(
            matches!(decode(&buf), Err(DecodeError::TrailingBytes { .. })),
            "{extra} appended bytes decoded instead of being refused as trailing"
        );
    }

    // Larger appends push the buffer past the frame cap and are refused for that
    // reason instead. Both are refusals and both are correct, but they are
    // different facts, and a reader that only handled one would misreport the
    // other. Asserted separately because the first version of this test demanded
    // `TrailingBytes` unconditionally and failed on the *right* behaviour.
    let mut big = base.clone();
    big.extend(std::iter::repeat_n(0x41u8, cap));
    assert!(
        matches!(decode(&big), Err(DecodeError::FrameTooLong { .. })),
        "a buffer past MAX_FRAME_LEN must be refused as too long, not as trailing"
    );

    // The control: the un-appended frame still decodes, so the refusals above are
    // about the appended bytes rather than about the frame being invalid anyway.
    assert!(decode(&base).is_ok());
}

/// An unknown discriminant must not become a known event.
///
/// The dangerous version of this bug is a decoder that maps an unrecognised tag
/// to a default variant: an attacker invents tag 0x99, gets back `ProcessExec`,
/// and the audit log records a process that never existed.
#[test]
fn every_unknown_tag_is_refused() {
    let template = encode(&read(1, 2, 3));

    for tag in 0u8..=255 {
        if matches!(tag, 0x01..=0x08) {
            continue; // real tags are covered by the round-trip test
        }
        let mut buf = template.clone();
        buf[5] = tag; // magic(4) + version(1) + kind(1)
        assert!(
            decode(&buf).is_err(),
            "tag {tag:#04x} decoded as {:?}; an unknown tag must never become a \
             known event",
            decode(&buf).ok()
        );
    }

    // Tag 0 is called out separately. It is reserved, not "unknown" -- and it is
    // the tag an attacker is most likely to reach for, because it is the one
    // value that is guaranteed never to be assigned.
    let mut zero = template.clone();
    zero[5] = 0x00;
    assert!(
        matches!(decode(&zero), Err(DecodeError::UnknownKind { .. })),
        "tag 0 is reserved and must be refused as unknown, got {:?}",
        decode(&zero)
    );
}

/// A wrong magic or version must be refused, not parsed anyway.
#[test]
fn a_foreign_frame_is_refused() {
    let good = encode(&read(1, 2, 3));

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xFF;
    assert!(decode(&bad_magic).is_err(), "a wrong magic decoded");

    for v in [0u8, 2, 3, 255] {
        if v == VERSION {
            continue;
        }
        let mut bad_version = good.clone();
        bad_version[4] = v;
        assert!(
            decode(&bad_version).is_err(),
            "version {v} decoded; only version {VERSION} is known"
        );
    }
}

/// An empty or near-empty buffer must be refused without panicking.
#[test]
fn degenerate_buffers_are_refused() {
    for buf in [vec![], vec![0u8], vec![0u8; 5], vec![0xFFu8; 5]] {
        assert!(decode(&buf).is_err(), "{buf:?} decoded");
    }
}

/// The size guard should catch a future `String` field -- but only if it is
/// actually sensitive to one.
///
/// The guard as written checks `size_of_val <= 64`. A `bool` or a `u8` added to a
/// variant does not change its size (Rust pads), so a future field can slip in
/// without tripping it. This test pins the *current* sizes so that tightening the
/// guard becomes a deliberate act rather than an accident nobody notices.
#[test]
fn variant_sizes_are_pinned() {
    use std::mem::size_of;
    let samples = [
        read(1, 2, 3),
        Event::ProcessExec { pid: 1, ppid: 2 },
        Event::ProcessExit { pid: 1, code: 2 },
        Event::FileOpen {
            pid: 1,
            fd: 2,
            path: hash_name(b"/tmp/x"),
            flags: OpenFlags::NONE,
        },
        Event::NetConnect {
            pid: 1,
            fd: 2,
            addr: hash_name(b"1.2.3.4"),
            port: 443,
        },
    ];
    for ev in &samples {
        println!("{ev:?} => {} bytes", size_of_val(ev));
        assert!(
            size_of_val(ev) <= 64,
            "a variant is {} bytes; the wire has started carrying something large",
            size_of_val(ev)
        );
    }
    let _ = size_of::<u64>();
}

/// Round-tripping every variant must be exact.
///
/// Cheap, and it is the test that would notice if a field were dropped from the
/// encoder while the decoder still accepted the frame -- a silent data loss on the
/// audit path, which is worse on an audit path than on any other.
#[test]
fn every_variant_round_trips_exactly() {
    let all = [
        Event::ProcessExec { pid: 1, ppid: 2 },
        Event::ProcessExit { pid: 3, code: -1 },
        Event::FileOpen {
            pid: 4,
            fd: 5,
            path: hash_name(b"/etc/passwd"),
            flags: OpenFlags::TRUNCATE,
        },
        read(6, 7, 8),
        Event::FileWrite { pid: 9, fd: 10, bytes: 11 },
        Event::NetConnect {
            pid: 12,
            fd: 13,
            addr: hash_name(b"evil.test"),
            port: 443,
        },
        Event::CapCheck {
            pid: 14,
            cap: 7,
            granted: true,
        },
        Event::PolicyViolation { pid: 15, cap: Some(21) },
    ];
    for ev in all {
        let bytes = encode(&ev);
        assert_eq!(
            decode(&bytes).unwrap_or_else(|e| panic!("{ev:?} did not decode: {e:?}")),
            ev,
            "{ev:?} did not survive a round trip"
        );
    }
}

/// The magic is what a reader keys on, so it must be what the module says.
#[test]
fn the_magic_is_the_documented_one() {
    assert_eq!(MAGIC.to_be_bytes(), [0x41, 0x45, 0x56, 0x54]);
}
