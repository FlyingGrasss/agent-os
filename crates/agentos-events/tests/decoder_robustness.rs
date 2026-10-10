//! Decoder robustness against hostile input.
//!
//! The decoder runs in the privileged process. A panic there is a denial of
//! service, and a permissive parse is an integrity failure, so both are tested
//! with a deterministic PRNG rather than by inspection.
//!
//! The PRNG is xorshift64*, written out here rather than pulled from a crate:
//! the workspace takes on no new dependencies, and a fixed seed makes every
//! failure in this file exactly reproducible.

use agentos_events::event::{decode, decode_prefix, encode, MAX_FRAME_LEN};
use agentos_events::Event;

/// Deterministic PRNG. Seeded explicitly so a failing case is reproducible
/// from the seed printed in the failure message.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point of xorshift, so a zero seed is remapped.
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
}

/// The header prefix a valid frame always starts with.
fn valid_header() -> [u8; 6] {
    let e = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
    let mut h = [0u8; 6];
    h.copy_from_slice(&e[..6]);
    h
}

#[test]
fn random_bytes_never_panic() {
    // The point of this test is the absence of a panic, so it asserts only
    // that the call returns. Any Ok or Err is acceptable; a panic is not.
    let mut rng = Rng::new(0x5EED_1234_ABCD_0001);
    for _ in 0..20_000 {
        let len = rng.below(MAX_FRAME_LEN + 8);
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let _ = decode(&buf);
    }
}

#[test]
fn mutated_valid_frames_never_panic() {
    // Uniformly random bytes almost never reach the field decoders. Starting
    // from a real frame and flipping bytes exercises the paths past the header,
    // which is where an unchecked read would actually live.
    let seeds = [
        Event::ProcessExec { pid: 7, ppid: 1 },
        Event::ProcessExit { pid: 7, code: -13 },
        Event::FileRead { pid: 7, fd: 3, bytes: u64::MAX },
        Event::FileWrite { pid: 7, fd: 1, bytes: 0 },
        Event::NetConnect { pid: 7, fd: 5, addr: agentos_events::event::hash_name(b"h"), port: 1 },
        Event::CapCheck { pid: 7, cap: 0, granted: false },
        Event::PolicyViolation { pid: 7, cap: None },
        Event::PolicyViolation { pid: 7, cap: Some(9) },
    ];
    let header = valid_header();

    let mut rng = Rng::new(0x5EED_1234_ABCD_0002);
    for ev in seeds {
        let base = encode(&ev);
        for _ in 0..2_500 {
            let mut buf = base.clone();
            let mutations = 1 + rng.below(4);
            for _ in 0..mutations {
                let idx = rng.below(buf.len());
                buf[idx] = rng.byte();
            }
            let _ = decode(&buf);
        }
    }

    // Also mutate the header itself, which must fail every time.
    for _ in 0..5_000 {
        let mut buf = header.to_vec();
        buf.extend((0..rng.below(40)).map(|_| rng.byte()));
        let idx = rng.below(buf.len());
        buf[idx] = rng.byte();
        let _ = decode(&buf);
    }
}

#[test]
fn truncating_a_valid_frame_at_every_offset_is_an_error() {
    let ev = Event::FileOpen {
        pid: 42,
        fd: 9,
        path: agentos_events::event::hash_name(b"/etc/shadow"),
        flags: agentos_events::OpenFlags::WRITE,
    };
    let full = encode(&ev);
    for cut in 0..full.len() {
        let r = decode(&full[..cut]);
        assert!(r.is_err(), "prefix of length {cut} decoded as {r:?}");
    }
    assert!(decode(&full).is_ok());
}

#[test]
fn appending_bytes_to_a_valid_frame_is_an_error() {
    // This is the specific attack: someone who can append to the frame buffer
    // appends bytes, hoping the reader treats them as another event.
    let ev = Event::FileOpen {
        pid: 42,
        fd: 9,
        path: agentos_events::event::hash_name(b"/etc/shadow"),
        flags: agentos_events::OpenFlags::READ,
    };
    let base = encode(&ev);
    let attacker_frame = encode(&Event::PolicyViolation { pid: 42, cap: Some(1) });

    for extra in 1..=attacker_frame.len() {
        let mut buf = base.clone();
        buf.extend_from_slice(&attacker_frame[..extra]);
        let r = decode(&buf);
        assert!(
            r.is_err(),
            "frame with {extra} appended bytes decoded as {r:?}; a writer could inject events"
        );
    }

    // Padding that is not a frame at all is also refused.
    for pad in [1usize, 4, 8, 32] {
        let mut buf = base.clone();
        buf.extend(std::iter::repeat_n(0xFFu8, pad));
        assert!(decode(&buf).is_err(), "{pad} padding bytes were accepted");
    }
}

/// One representative event per defined tag, so a frame can be retagged to
/// that variant and still be structurally valid.
fn frame_for_tag(tag: u8) -> Option<Vec<u8>> {
    let ev = match tag {
        0x01 => Event::ProcessExec { pid: 1, ppid: 2 },
        0x02 => Event::ProcessExit { pid: 1, code: 0 },
        0x03 => Event::FileOpen {
            pid: 1,
            fd: 3,
            path: agentos_events::event::hash_name(b"/x"),
            flags: agentos_events::OpenFlags::READ,
        },
        0x04 => Event::FileRead { pid: 1, fd: 3, bytes: 0 },
        0x05 => Event::FileWrite { pid: 1, fd: 3, bytes: 0 },
        0x06 => Event::NetConnect {
            pid: 1,
            fd: 3,
            addr: agentos_events::event::hash_name(b"h"),
            port: 1,
        },
        0x07 => Event::CapCheck { pid: 1, cap: 2, granted: true },
        0x08 => Event::PolicyViolation { pid: 1, cap: Some(3) },
        _ => return None,
    };
    Some(encode(&ev))
}

#[test]
fn an_unknown_kind_tag_is_refused_not_defaulted() {
    // Every tag outside the defined set must be refused, including tag 0, which
    // is permanently reserved. Retagging a frame built for that exact variant
    // isolates the tag: a variant that refuses due to a length mismatch would
    // pass this test for the wrong reason.
    for tag in 0u8..=255 {
        match frame_for_tag(tag) {
            Some(base) => {
                let decoded = decode(&base);
                assert!(decoded.is_ok(), "frame for known tag {tag:#04x} did not decode");
                let ev = decoded.expect("checked above");
                // A known tag must decode to the variant it names, not another.
                match (tag, ev) {
                    (0x01, Event::ProcessExec { .. })
                    | (0x02, Event::ProcessExit { .. })
                    | (0x03, Event::FileOpen { .. })
                    | (0x04, Event::FileRead { .. })
                    | (0x05, Event::FileWrite { .. })
                    | (0x06, Event::NetConnect { .. })
                    | (0x07, Event::CapCheck { .. })
                    | (0x08, Event::PolicyViolation { .. }) => {}
                    (t, other) => panic!("tag {t:#04x} decoded to the wrong variant {other:?}"),
                }
            }
            None => {
                // No event produces this tag, so put it on a frame that is
                // otherwise well formed and confirm it is refused on the tag
                // alone.
                let mut buf = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
                buf[5] = tag;
                assert!(
                    matches!(decode(&buf), Err(agentos_events::DecodeError::UnknownKind { .. })),
                    "undefined tag {tag:#04x} was not refused as unknown"
                );
            }
        }
    }
}

#[test]
fn a_known_tag_on_the_wrong_payload_length_is_refused() {
    // The counterpart to the test above: retagging a frame to a variant whose
    // layout is longer must fail on truncation rather than half-parsing.
    let base = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
    let mut buf = base.clone();
    buf[5] = 0x03; // FileOpen, which needs far more bytes
    assert!(decode(&buf).is_err());
}

#[test]
fn a_reserved_flag_bit_is_refused() {
    let base = encode(&Event::FileOpen {
        pid: 1,
        fd: 1,
        path: agentos_events::event::hash_name(b"/x"),
        flags: agentos_events::OpenFlags::READ,
    });
    let flags_offset = base.len() - 1;
    for bit in 4u8..8 {
        let mut buf = base.clone();
        buf[flags_offset] |= 1 << bit;
        assert!(
            matches!(
                decode(&buf),
                Err(agentos_events::DecodeError::ReservedBits { .. })
            ),
            "reserved flag bit {bit} was accepted"
        );
    }
}

#[test]
fn a_non_boolean_byte_in_a_bool_field_is_refused() {
    let base = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
    for raw in [2u8, 3, 0x7F, 0x80, 0xFF] {
        let last = base.len() - 1;
        let mut buf = base.clone();
        buf[last] = raw;
        assert!(
            matches!(decode(&buf), Err(agentos_events::DecodeError::InvalidBool { .. })),
            "bool byte {raw:#04x} was accepted"
        );
    }
}

#[test]
fn an_invalid_option_tag_is_refused() {
    let base = encode(&Event::PolicyViolation { pid: 1, cap: Some(7) });
    // prev(4) + version(1) + kind(1) + pid(4) = 10, then the option tag.
    let tag_offset = 10;
    for raw in [2u8, 3, 0x10, 0xFF] {
        let mut buf = base.clone();
        buf[tag_offset] = raw;
        assert!(
            matches!(
                decode(&buf),
                Err(agentos_events::DecodeError::InvalidOptionTag { .. })
            ),
            "option tag {raw:#04x} was accepted"
        );
    }
}

#[test]
fn a_wrong_version_is_refused_rather_than_guessed() {
    let mut base = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
    for version in [0u8, 2, 3, 0xFF] {
        base[4] = version;
        assert!(
            matches!(
                decode(&base),
                Err(agentos_events::DecodeError::UnsupportedVersion { .. })
            ),
            "version {version} was accepted"
        );
    }
}

#[test]
fn a_frame_longer_than_the_limit_is_refused() {
    let mut buf = encode(&Event::CapCheck { pid: 1, cap: 2, granted: true });
    buf.extend_from_slice(&[0u8; MAX_FRAME_LEN]);
    assert!(matches!(
        decode(&buf),
        Err(agentos_events::DecodeError::FrameTooLong { .. })
    ));
}

#[test]
fn decode_prefix_returns_the_consumed_length_for_a_stream_reader() {
    let a = encode(&Event::ProcessExec { pid: 1, ppid: 0 });
    let b = encode(&Event::ProcessExit { pid: 1, code: 0 });
    let mut buf = a.clone();
    buf.extend_from_slice(&b);

    let (first, used) = decode_prefix(&buf).expect("first frame should parse");
    assert_eq!(first, Event::ProcessExec { pid: 1, ppid: 0 });
    assert_eq!(used, a.len());

    let (second, used2) = decode_prefix(&buf[used..]).expect("second frame should parse");
    assert_eq!(second, Event::ProcessExit { pid: 1, code: 0 });
    assert_eq!(used + used2, buf.len());
}

#[test]
fn decode_prefix_does_not_consume_trailing_bytes() {
    // A ring-buffer reader needs to be told where the frame ended. If
    // decode_prefix swallowed trailing bytes, an attacker could hide a
    // boundary inside a frame.
    let a = encode(&Event::ProcessExec { pid: 1, ppid: 0 });
    let mut buf = a.clone();
    buf.push(0xAA);
    buf.push(0xBB);
    let (_, used) = decode_prefix(&buf).expect("frame itself is valid");
    assert_eq!(used, a.len());
}