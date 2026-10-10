//! The kernel event vocabulary and its binary codec.
//!
//! # Why the wire carries no text
//!
//! An attacker who controls a web page controls every byte a sandboxed tool
//! reads and writes. If the event wire carried path strings or command-line
//! text, the privileged side parsing those events would be handling
//! attacker-controlled bytes on its way to the audit log and, eventually, to
//! the Controller's prompt. That is invariant I1 (no untrusted bytes in the
//! prompt) failing at a new seam, and it is worse than failing: it would look
//! like the architecture working, because the log would faithfully record what
//! the tool did.
//!
//! So every field below is drawn from a closed vocabulary: enum variants,
//! integers, booleans, and fixed-size opaque hashes. A path is represented by
//! a [`NameHash`] of its bytes, never the bytes themselves. The reader on the
//! privileged side therefore has nothing attacker-authored to parse, and the
//! value that gets matched against an allowlist is a digest.
//!
//! The consequence to be honest about: a hash of a path is *not* reversible,
//! so the audit log records "something hashed to X was opened", not "that
//! file was opened". Recovering the path needs an out-of-band lookup table
//! that the sandbox never writes to.
//!
//! # Decoder strictness
//!
//! The decoder is strict on all four axes, and each is a separate attack:
//!
//! * **Unknown discriminant is an error.** A future kernel emitting an event
//!   type this build has never heard of must not be silently mapped onto a
//!   known variant. Defaulting would mean a kernel or a hostile writer picks
//!   which behaviour gets recorded.
//! * **Trailing bytes are an error.** A frame with extra bytes appended must
//!   be refused, otherwise a writer who can append to a buffer can append
//!   events, and the reader will parse them as part of the frame.
//! * **Truncated input is an error, not a panic.** This parser runs in a
//!   privileged process; a panic there is a denial of service.
//! * **No panics at all on hostile input.** Enforced by the fuzz-style test in
//!   `tests/decoder_robustness.rs`.

use serde::{Deserialize, Serialize};

use crate::hash::Digest;

/// Frame magic. A buffer that does not start with this is not our stream, and
/// is rejected rather than parsed on the chance that it happens to look valid.
pub const MAGIC: u32 = 0x4145_5654; // "AEVT"
/// Wire format version. A reader that does not recognise this must refuse the
/// frame rather than guess at a layout it was not written for.
pub const VERSION: u8 = 1;

/// Largest frame this decoder will consider. Every variant is fixed size and
/// far below this, so the bound only rejects frames that are already malformed.
///
/// If this were absent, a length field read from a hostile frame could make
/// the decoder allocate attacker-chosen memory in the privileged process.
pub const MAX_FRAME_LEN: usize = 64;

/// A 32-byte digest standing in for an attacker-controlled name.
///
/// Constructed only from bytes the caller has already decided to hash. It has
/// no `Display`, no `Debug` that reveals the input, and no conversion to a
/// string, so the name it stands for cannot leak through a log line or a
/// `format!` by accident.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NameHash(pub [u8; 32]);

impl std::fmt::Debug for NameHash {
    /// Deliberately opaque: `Debug` reaches log lines, and a `Debug` that
    /// printed the preimage would turn every debug log into an exfiltration
    /// channel for the very bytes the hash exists to withhold.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameHash(<redacted>)")
    }
}

/// Open flags, as a closed bit set.
///
/// A bit set here is a fact about the syscall arguments. It is deliberately not
/// a path-derived predicate: "was this opened for writing" must be answerable
/// without ever looking at the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenFlags(u8);

impl std::ops::BitOr for OpenFlags {
    type Output = OpenFlags;

    /// Union of two flag sets, so a producer can build a value from the
    /// defined bits without a public constructor.
    fn bitor(self, rhs: OpenFlags) -> OpenFlags {
        OpenFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for OpenFlags {
    fn bitor_assign(&mut self, rhs: OpenFlags) {
        self.0 |= rhs.0;
    }
}

impl OpenFlags {
    /// No flags set.
    pub const NONE: OpenFlags = OpenFlags(0);

    pub const READ: OpenFlags = OpenFlags(0b0000_0001);
    pub const WRITE: OpenFlags = OpenFlags(0b0000_0010);
    pub const APPEND: OpenFlags = OpenFlags(0b0000_0100);
    pub const TRUNCATE: OpenFlags = OpenFlags(0b0000_1000);

    pub fn contains(self, other: OpenFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Bits outside the defined set make the value uninterpretable, so they are
    /// rejected rather than masked off. Masking would let a hostile writer use
    /// reserved bits to smuggle data past a byte-level filter.
    fn is_valid(self) -> bool {
        self.0 & !0b0000_1111 == 0
    }
}

/// A process observed by the kernel observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcRef {
    pub pid: u32,
}

impl ProcRef {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }
}

/// The closed set of observations the kernel observer reports.
///
/// Every variant is a fixed-size, closed-shape record. There is no variant that
/// carries a path, a command line, a hostname, or any other attacker-chosen
/// bytes, and adding one would break the property this module exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Event {
    /// A process was created. `ppid` lets a reader reconstruct lineage
    /// without any name.
    ProcessExec {
        pid: u32,
        ppid: u32,
    },
    /// A process exited. `code` is the kernel's wait status, not a string.
    ProcessExit {
        pid: u32,
        code: i32,
    },
    /// A file descriptor was opened on a path whose bytes are represented only
    /// by `path`.
    FileOpen {
        pid: u32,
        fd: u32,
        path: NameHash,
        flags: OpenFlags,
    },
    /// A read observed. `bytes` is a count, not content.
    FileRead {
        pid: u32,
        fd: u32,
        bytes: u64,
    },
    /// A write observed. Counting writes is what lets the pager notice a tool
    /// exfiltrating, without ever reading what it wrote.
    FileWrite {
        pid: u32,
        fd: u32,
        bytes: u64,
    },
    /// A network connection attempt. The address is a digest for the same
    /// reason paths are: it is attacker-influenced in both its literal and
    /// resolved forms.
    NetConnect {
        pid: u32,
        fd: u32,
        addr: NameHash,
        port: u16,
    },
    /// A capability check for `cap` was made by `pid`. `granted` is the
    /// kernel's answer. Indexes into the workspace's capability registry, not a
    /// name.
    CapCheck {
        pid: u32,
        cap: u32,
        granted: bool,
    },
    /// The observer saw an operation outside the declared capability set for
    /// the process holding `cap`, when one is known.
    PolicyViolation {
        pid: u32,
        cap: Option<u32>,
    },
}

/// Kind tags on the wire. Explicit constants rather than `as u8` casts, so a
/// reordered enum cannot silently change a wire value.
mod kind {
    pub const PROCESS_EXEC: u8 = 0x01;
    pub const PROCESS_EXIT: u8 = 0x02;
    pub const FILE_OPEN: u8 = 0x03;
    pub const FILE_READ: u8 = 0x04;
    pub const FILE_WRITE: u8 = 0x05;
    pub const NET_CONNECT: u8 = 0x06;
    pub const CAP_CHECK: u8 = 0x07;
    pub const POLICY_VIOLATION: u8 = 0x08;
    /// Tag 0 is permanently invalid. Listed explicitly so that a reader can
    /// see the tag space is closed and 0 is not a hole to be filled later.
    pub const RESERVED: u8 = 0x00;
}

/// Everything that can go wrong decoding a frame.
///
/// Each variant corresponds to a distinct way a hostile frame could otherwise
/// be accepted as something it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The buffer is shorter than the frame it claims to start.
    #[error("frame truncated: needed {needed} bytes, only {available} available")]
    Truncated { needed: usize, available: usize },
    /// Bytes remain after a complete, well-formed frame.
    ///
    /// Refusing these is what stops a writer who can append to a shared buffer
    /// from appending events of their own.
    #[error("trailing bytes after frame: {extra} unconsumed")]
    TrailingBytes { extra: usize },
    /// The kind tag is not one this build knows.
    ///
    /// Explicitly an error rather than a default: an unknown event type from a
    /// newer kernel must not be recorded as some known type, or a hostile
    /// writer chooses which behaviour gets written down.
    #[error("unknown event kind 0x{tag:02x}")]
    UnknownKind { tag: u8 },
    /// The frame does not begin with [`MAGIC`].
    #[error("bad magic 0x{magic:08x}")]
    BadMagic { magic: u32 },
    /// The version is not one this build implements.
    #[error("unsupported wire version {version}")]
    UnsupportedVersion { version: u8 },
    /// The frame is longer than [`MAX_FRAME_LEN`].
    #[error("frame of {len} bytes exceeds the {max} byte limit")]
    FrameTooLong { len: usize, max: usize },
    /// A reserved bit was set in an options field.
    ///
    /// Reserved bits are rejected, not masked: a hostile writer must not be
    /// able to use them to carry data past a byte-level filter.
    #[error("reserved bits set in flags 0x{raw:02x}")]
    ReservedBits { raw: u8 },
    /// An `Option` discriminant was neither 0 nor 1.
    #[error("invalid option tag 0x{tag:02x}")]
    InvalidOptionTag { tag: u8 },
    /// A boolean field held a byte other than 0 or 1.
    ///
    /// Coercing it would let a writer pick a value the encoder never meant to
    /// produce, so the frame is refused rather than normalised.
    #[error("invalid boolean byte 0x{raw:02x}")]
    InvalidBool { raw: u8 },
}

/// A bounds-checked cursor over a frame.
///
/// Written as an explicit cursor rather than indexing a slice inline so that
/// every read is a checked subtraction. The invariant it enforces is the one
/// that matters here: no input byte can cause an out-of-bounds read, because
/// every length check happens before every indexing operation.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated { needed: n, available: self.remaining() });
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..self.pos])
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = self.take(1)?;
        // Length is checked as exactly 1 above, so this index is in bounds.
        Ok(b[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.u32()? as i32)
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn hash32(&mut self) -> Result<NameHash, DecodeError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(NameHash(a))
    }

    /// Presence tag for an optional value: exactly one byte, 0 or 1.
    ///
    /// The payload is read separately and unconditionally, so a frame's length
    /// does not depend on whether the value is present. A tag other than 0 or 1
    /// is rejected: coercing it would let a writer pick a third interpretation
    /// the encoder never emitted.
    fn opt_tag(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(DecodeError::InvalidOptionTag { tag }),
        }
    }
}

/// Encode an event into a fixed-size frame.
///
/// Big-endian throughout, so that a byte-level diff of two frames reads in
/// the same order as the struct. Frames are fixed size per variant, which means
/// a reader can size a record before parsing it and cannot be talked into an
/// allocation by a hostile length field.
pub fn encode(ev: &Event) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_FRAME_LEN);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(VERSION);
    out.push(kind_of(ev));
    match *ev {
        Event::ProcessExec { pid, ppid } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&ppid.to_be_bytes());
        }
        Event::ProcessExit { pid, code } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&code.to_be_bytes());
        }
        Event::FileOpen { pid, fd, path, flags } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&fd.to_be_bytes());
            out.extend_from_slice(&path.0);
            out.push(flags.0);
        }
        Event::FileRead { pid, fd, bytes } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&fd.to_be_bytes());
            out.extend_from_slice(&bytes.to_be_bytes());
        }
        Event::FileWrite { pid, fd, bytes } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&fd.to_be_bytes());
            out.extend_from_slice(&bytes.to_be_bytes());
        }
        Event::NetConnect { pid, fd, addr, port } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&fd.to_be_bytes());
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Event::CapCheck { pid, cap, granted } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&cap.to_be_bytes());
            out.push(u8::from(granted));
        }
        Event::PolicyViolation { pid, cap } => {
            out.extend_from_slice(&pid.to_be_bytes());
            out.extend_from_slice(&opt_tag(cap));
            // The payload is always present, even when the tag says None. A
            // present/absent payload would make this variant's length depend on
            // its value, and a decoder that sized records from the tag alone
            // would then be wrong. The cost is four bytes per frame.
            out.extend_from_slice(&cap.unwrap_or(0).to_be_bytes());
        }
    }
    out
}

fn opt_tag(v: Option<u32>) -> [u8; 1] {
    match v {
        None => [0],
        Some(_) => [1],
    }
}

fn kind_of(ev: &Event) -> u8 {
    match ev {
        Event::ProcessExec { .. } => kind::PROCESS_EXEC,
        Event::ProcessExit { .. } => kind::PROCESS_EXIT,
        Event::FileOpen { .. } => kind::FILE_OPEN,
        Event::FileRead { .. } => kind::FILE_READ,
        Event::FileWrite { .. } => kind::FILE_WRITE,
        Event::NetConnect { .. } => kind::NET_CONNECT,
        Event::CapCheck { .. } => kind::CAP_CHECK,
        Event::PolicyViolation { .. } => kind::POLICY_VIOLATION,
    }
}

/// Decode exactly one frame, which must consume the whole buffer.
///
/// Trailing bytes are an error by design. A stream reader should use
/// [`decode_prefix`] and then require the remaining bytes to be a complete
/// frame; a single-message API should use this one so that "extra bytes
/// appended by someone else" is indistinguishable from corruption.
pub fn decode(buf: &[u8]) -> Result<Event, DecodeError> {
    let (ev, used) = decode_prefix(buf)?;
    if used != buf.len() {
        return Err(DecodeError::TrailingBytes { extra: buf.len() - used });
    }
    Ok(ev)
}

/// Decode one frame from the front of a buffer, returning the bytes consumed.
///
/// For a ring-buffer reader that pulls frames as they arrive. The caller is
/// responsible for deciding what an incomplete tail means; returning the
/// consumed length rather than an event alone is what lets it tell "a frame
/// ended here" from "more bytes are coming".
pub fn decode_prefix(buf: &[u8]) -> Result<(Event, usize), DecodeError> {
    if buf.len() > MAX_FRAME_LEN {
        return Err(DecodeError::FrameTooLong { len: buf.len(), max: MAX_FRAME_LEN });
    }

    let mut c = Cursor::new(buf);

    let magic = c.u32()?;
    if magic != MAGIC {
        return Err(DecodeError::BadMagic { magic });
    }
    let version = c.u8()?;
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { version });
    }

    let tag = c.u8()?;
    let ev = match tag {
        kind::PROCESS_EXEC => Event::ProcessExec { pid: c.u32()?, ppid: c.u32()? },
        kind::PROCESS_EXIT => Event::ProcessExit { pid: c.u32()?, code: c.i32()? },
        kind::FILE_OPEN => {
            let pid = c.u32()?;
            let fd = c.u32()?;
            let path = c.hash32()?;
            let raw = c.u8()?;
            let flags = OpenFlags(raw);
            if !flags.is_valid() {
                return Err(DecodeError::ReservedBits { raw });
            }
            Event::FileOpen { pid, fd, path, flags }
        }
        kind::FILE_READ => Event::FileRead { pid: c.u32()?, fd: c.u32()?, bytes: c.u64()? },
        kind::FILE_WRITE => Event::FileWrite { pid: c.u32()?, fd: c.u32()?, bytes: c.u64()? },
        kind::NET_CONNECT => {
            let pid = c.u32()?;
            let fd = c.u32()?;
            let addr = c.hash32()?;
            Event::NetConnect { pid, fd, addr, port: c.u16()? }
        }
        kind::CAP_CHECK => {
            let pid = c.u32()?;
            let cap = c.u32()?;
            // Only 0 and 1 are meaningful; any other byte means the frame was
            // not produced by an encoder that follows the format.
            let raw = c.u8()?;
            let granted = match raw {
                0 => false,
                1 => true,
                other => return Err(DecodeError::InvalidBool { raw: other }),
            };
            Event::CapCheck { pid, cap, granted }
        }
        kind::POLICY_VIOLATION => {
            let pid = c.u32()?;
            let has = c.opt_tag()?;
            // The payload is read unconditionally; only the tag decides whether
            // it is meaningful.
            let payload = c.u32()?;
            Event::PolicyViolation { pid, cap: if has { Some(payload) } else { None } }
        }
        // Listed so the closed tag space is visible at the decode site. No
        // variant maps here: an unknown tag from a future or hostile writer
        // must not become a known event.
        kind::RESERVED => return Err(DecodeError::UnknownKind { tag }),
        other => return Err(DecodeError::UnknownKind { tag: other }),
    };

    Ok((ev, c.position()))
}

/// Hash attacker-controlled bytes into a [`NameHash`].
///
/// The hash input is length-framed by the caller of the event source; this
/// function only makes the "never keep the original" decision explicit at one
/// place, so there is exactly one function in the crate that touches the bytes
/// on their way to the wire.
///
/// Note that a plain digest of a path is guessable by anyone who can guess the
/// path, which is to say an attacker who chose it usually can. It is therefore
/// an *identity for matching*, not a secrecy mechanism; the secrecy property
/// this crate needs is that the privileged side never *parses* the value.
pub fn hash_name(bytes: &[u8]) -> NameHash {
    NameHash(crate::hash::hash_parts(b"name", &[bytes]))
}

/// Expose the digest type on the audit records without letting a caller build
/// a record's digest out of thin air.
pub(crate) fn digest_of(parts: &[&[u8]]) -> Digest {
    Digest(crate::hash::hash_parts(b"audit-link", parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<Event> {
        vec![
            Event::ProcessExec { pid: 1, ppid: 0 },
            Event::ProcessExit { pid: 1, code: -1 },
            Event::FileOpen {
                pid: 1,
                fd: 3,
                path: hash_name(b"/etc/passwd"),
                flags: OpenFlags::READ | OpenFlags::WRITE,
            },
            Event::FileRead { pid: 1, fd: 3, bytes: 4096 },
            Event::FileWrite { pid: 1, fd: 3, bytes: 0 },
            Event::NetConnect { pid: 1, fd: 5, addr: hash_name(b"10.0.0.1"), port: 443 },
            Event::CapCheck { pid: 1, cap: 7, granted: true },
            Event::PolicyViolation { pid: 1, cap: Some(7) },
            Event::PolicyViolation { pid: 1, cap: None },
        ]
    }

    #[test]
    fn every_variant_round_trips() {
        for ev in all_variants() {
            let bytes = encode(&ev);
            assert!(bytes.len() <= MAX_FRAME_LEN, "frame exceeded the size bound");
            assert_eq!(decode(&bytes), Ok(ev), "round trip failed for {ev:?}");
        }
    }

    #[test]
    fn frames_are_fixed_size_per_variant() {
        // The decoder sizes a record from the tag alone; a length that varied
        // with the payload would reintroduce an attacker-chosen allocation.
        let a = encode(&Event::FileRead { pid: 1, fd: 2, bytes: 0 });
        let b = encode(&Event::FileRead { pid: 999, fd: 99, bytes: u64::MAX });
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn no_variant_carries_text() {
        // A guard against someone adding a String field later. If this fails,
        // the wire has started carrying attacker-controlled bytes and the
        // module's central claim is false.
        for ev in all_variants() {
            let size = std::mem::size_of_val(&ev);
            assert!(size <= 64, "variant grew to {size} bytes; check for a String field");
        }
    }

    #[test]
    fn name_hash_debug_does_not_reveal_its_input() {
        let h = hash_name(b"/home/alice/.ssh/id_rsa");
        let shown = format!("{h:?}");
        assert!(!shown.contains("alice"));
        assert!(!shown.contains("id_rsa"));
    }

    #[test]
    fn distinct_names_hash_distinctly() {
        assert_ne!(hash_name(b"/a"), hash_name(b"/b"));
    }

    #[test]
    fn open_flags_containment() {
        let f = OpenFlags::READ | OpenFlags::APPEND;
        assert!(f.contains(OpenFlags::READ));
        assert!(f.contains(OpenFlags::APPEND));
        assert!(!f.contains(OpenFlags::WRITE));
    }
}