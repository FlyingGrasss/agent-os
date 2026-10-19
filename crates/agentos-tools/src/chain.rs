//! Hash-chaining for the audit log, so I6 is tamper-*evident* and not merely
//! append-only.
//!
//! # What append-only does not buy
//!
//! The [`AuditSink`](crate::audit::AuditSink) contract says an implementation
//! never rewrites what it already appended, and [`FileSink`](crate::audit::FileSink)
//! honours that. That is
//! a promise about this process's behaviour, and it is exactly as strong as the
//! discretion of whoever can open the file with an editor afterwards. "Append-only"
//! describes an API, not a filesystem. Anyone with write access to the log can
//! delete the line recording a tool call, or change `denied` to `allowed`, and the
//! remaining log still looks like a well-formed append-only log: the sequence
//! numbers still ascend, nothing is out of order, and there is no residue.
//!
//! A hash chain turns "the log looks fine" into a checkable claim. Each line
//! commits to its predecessor, so an edit, a deletion, or a reordering breaks
//! every link after it and [`verify`] names the first broken line.
//!
//! # What this does and does not prove
//!
//! **The chain is keyless.** The digest is `SHA-256(label || prev || line_bytes)`,
//! and everything needed to recompute it is in the log. So this detects accidental
//! corruption, truncated or spliced lines, out-of-order insertion, and an editor
//! that changed a byte and did not think to recompute the rest. It does **not**
//! resist an attacker who rewrites the whole file and recomputes the entire chain
//! from the genesis record, because nothing they need is secret. Detect that and
//! you need an anchor the attacker cannot reach: a signed head, a head published
//! somewhere they cannot write, or a witness. [`verify`] returns the chain head so
//! it can be pinned; pinning it is the caller's job.
//!
//! Stating this plainly matters. A ledger described as "tamper-proof" that is only
//! tamper-*evident* is worse than one that never claimed the property, because the
//! first thing anyone does with an unbacked integrity claim is assume the attacker
//! is stupid.
//!
//! # Why the chain wraps the line instead of living inside it
//!
//! [`AuditRecord`](crate::audit::AuditRecord) derives `Serialize` and deliberately
//! does not derive `Deserialize`: a [`BoundedText`](crate::audit::BoundedText)
//! read back off disk could claim a length its constructor would have refused, and
//! an audit record must not be rehydratable into a state the writer would have
//! rejected. Adding chain fields *inside* the record would mean the verifier has
//! to deserialize the record to recompute the digest, which reopens exactly that
//! hole for the one component whose whole job is reading a file an attacker
//! controls.
//!
//! So the line is `<prev_hex> <hash_hex>\t<json>`. The verifier splits on the tab
//! and hashes the remainder as opaque bytes. It never parses, never allocates a
//! typed record, and cannot be tricked by a payload that happens to be valid JSON.
//! A side benefit: binding the literal bytes also catches reformatting that a
//! field-by-field comparison would miss.

use std::fmt;

use agentos_types::{Sha256, digests_equal};

/// Domain separator for every chain digest.
///
/// Prefixed to each hash so a chain digest can never collide with the audit
/// `Fingerprint` or with an event digest over the same bytes.
pub const CHAIN_LABEL: &[u8] = b"agentos/audit/chain/v1\0";

/// Length of a hex-encoded digest.
const HEX_LEN: usize = 64;

/// The chain head before any record exists.
///
/// A fixed root nonce rather than 32 zero bytes, so a forged line claiming
/// `prev = 0...0` is distinguishable from a genuine first record. It is a
/// constant, not a secret; see the module docs on what that does and does not buy.
pub fn genesis() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_LABEL);
    h.update(b"genesis");
    h.finish()
}

/// The digest linking one line to its predecessor.
pub fn link(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_LABEL);
    h.update(prev);
    h.update(body);
    h.finish()
}

fn hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(HEX_LEN);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble is a hex digit"));
        s.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble is a hex digit"));
    }
    s
}

/// Parse 64 hex characters into a digest.
///
/// Strictly lowercase. Uppercase would be accepted by `char::to_digit`, but then
/// `'a'` and `'A'` decode alike and differ only in bit 5, so flipping that one bit
/// of a digest would leave the log verifying while its bytes had changed. Rejecting
/// uppercase keeps the encoding canonical, which is what makes "any modification is
/// detected" true at the byte level rather than only for edits that survive a
/// decode.
fn unhex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != HEX_LEN {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

/// The writing half of the chain: remembers the head and stamps each line.
///
/// One of these lives inside each sink, because the sink is the only place that
/// holds the serialized bytes. Both sinks call the same `seal`, so a line is
/// byte-identical whichever sink produced it.
#[derive(Debug, Clone)]
pub struct Chain {
    prev: [u8; 32],
}

impl Chain {
    /// A chain positioned at the genesis record.
    pub fn new() -> Self {
        Self { prev: genesis() }
    }

    /// A chain resuming after `head`, for reopening a log that already has records.
    pub fn resume(head: [u8; 32]) -> Self {
        Self { prev: head }
    }

    /// The digest the next line will claim as its `prev`.
    pub fn head(&self) -> [u8; 32] {
        self.prev
    }

    /// Wrap `body` in a chain link and advance the head.
    pub fn seal(&mut self, body: &str) -> String {
        let hash = link(&self.prev, body.as_bytes());
        let mut line = hex(&self.prev);
        line.push(' ');
        line.push_str(&hex(&hash));
        line.push('\t');
        line.push_str(body);
        self.prev = hash;
        line
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a line failed to chain.
///
/// The point of naming the fault is that "verification failed" is not actionable;
/// "line 412's bytes were altered" and "line 412 does not follow line 411" point at
/// different accidents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainFault {
    /// The line is not `<prev> <hash>\t<body>` at all.
    Malformed { line_no: usize, detail: &'static str },
    /// The line chains from something other than the previous line's digest.
    ///
    /// A deleted, reordered, or duplicated line lands here.
    BrokenLink { line_no: usize },
    /// The line chains correctly but its body does not hash to the digest it claims.
    ///
    /// A body was edited in place without updating the link.
    Tampered { line_no: usize },
    /// A bare JSON record carrying no chain link at all.
    ///
    /// Almost always a log written before the chain existed, rather than an attack,
    /// and worth distinguishing: an operator seeing "COMPROMISED" on a log they know
    /// they have not touched needs to be told to rotate it, not to go hunting.
    Unchained { line_no: usize },
    /// The final line has no terminating newline, so it may be a partial write.
    ///
    /// Distinct from the above because the record may still be intact in a buffer
    /// that was never flushed; treat it as suspect rather than proven altered.
    TruncatedTail { line_no: usize },
}

impl fmt::Display for ChainFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainFault::Malformed { line_no, detail } => {
                write!(f, "line {line_no} is not a chained audit line: {detail}")
            }
            ChainFault::BrokenLink { line_no } => write!(
                f,
                "line {line_no} does not follow the previous record: a record was \
                 deleted, reordered, or duplicated"
            ),
            ChainFault::Tampered { line_no } => write!(
                f,
                "line {line_no} was altered: its bytes do not match the digest it carries"
            ),
            ChainFault::Unchained { line_no } => write!(
                f,
                "line {line_no} carries no chain link: this log predates hash chaining, \
                 or it was stripped. It cannot be verified; archive it and start a new one"
            ),
            ChainFault::TruncatedTail { line_no } => write!(
                f,
                "line {line_no} has no terminating newline: the log ends in a partial write"
            ),
        }
    }
}

impl std::error::Error for ChainFault {}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// How many records chained cleanly.
    pub records: u64,
    /// The final chain head, for pinning against a later check.
    pub head: [u8; 32],
}

impl Verification {
    pub fn head_hex(&self) -> String {
        hex(&self.head)
    }
}

/// The reading half of the chain: walks lines and refuses a broken link.
#[derive(Debug, Clone)]
pub struct Verifier {
    prev: [u8; 32],
    records: u64,
}

impl Verifier {
    /// A verifier expecting the genesis record first.
    pub fn new() -> Self {
        Self {
            prev: genesis(),
            records: 0,
        }
    }

    /// The head so far, so a caller can anchor a partial log.
    pub fn head(&self) -> [u8; 32] {
        self.prev
    }

    /// Records accepted so far.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Check one line, with no trailing newline, and advance if it holds.
    ///
    /// `line_no` is 1-based and only used to name the fault.
    pub fn check(&mut self, line: &str, line_no: usize) -> Result<(), ChainFault> {
        // A bare JSON object is a record from before the chain existed, or one whose
        // link was stripped. Distinguish it so the operator gets told to rotate the
        // log rather than told their log was attacked.
        if line.starts_with('{') {
            return Err(ChainFault::Unchained { line_no });
        }
        let space = line.find(' ').ok_or(ChainFault::Malformed {
            line_no,
            detail: "no digest separator",
        })?;
        let (claimed_prev, rest) = line.split_at(space);
        let rest = &rest[1..];

        let tab = rest.find('\t').ok_or(ChainFault::Malformed {
            line_no,
            detail: "no body separator",
        })?;
        let (claimed_hash, body) = rest.split_at(tab);
        let body = &body[1..];

        let claimed_prev =
            unhex(claimed_prev).ok_or(ChainFault::Malformed {
                line_no,
                detail: "previous digest is not 64 hex characters",
            })?;
        let claimed_hash =
            unhex(claimed_hash).ok_or(ChainFault::Malformed {
                line_no,
                detail: "record digest is not 64 hex characters",
            })?;

        if !digests_equal(&claimed_prev, &self.prev) {
            return Err(ChainFault::BrokenLink { line_no });
        }
        if !digests_equal(&claimed_hash, &link(&self.prev, body.as_bytes())) {
            return Err(ChainFault::Tampered { line_no });
        }

        self.prev = claimed_hash;
        self.records += 1;
        Ok(())
    }

    /// Seal off a successful run.
    pub fn finish(self) -> Verification {
        Verification {
            records: self.records,
            head: self.prev,
        }
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Walk every line of a newline-delimited chained log.
///
/// `text` is the whole file. The final newline is optional; a missing one is
/// reported as [`ChainFault::TruncatedTail`] rather than silently accepted,
/// because a log that stops mid-record is a log whose last line cannot be trusted.
///
/// Returns the first fault, so the caller learns *where* the chain broke rather
/// than only that it did.
pub fn verify(text: &str) -> Result<Verification, ChainFault> {
    let mut verifier = Verifier::new();
    // `split_inclusive` keeps the terminator, so an unterminated final line is
    // distinguishable from a terminated one.
    for (i, raw) in text.split_inclusive('\n').enumerate() {
        let line_no = i + 1;
        let terminated = raw.ends_with('\n');
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        if line.is_empty() {
            if terminated {
                continue; // a blank line between records carries no chain link
            }
            return Err(ChainFault::TruncatedTail { line_no });
        }
        verifier.check(line, line_no)?;
        if !terminated {
            return Err(ChainFault::TruncatedTail { line_no });
        }
    }
    Ok(verifier.finish())
}

/// Recompute the chain head of an existing log, for a sink reopening it.
///
/// Returns the head to resume from, or the genesis value if the log is empty.
/// Used by [`FileSink`](crate::audit::FileSink) on open. Errors if the existing
/// log does not verify: appending to a log whose history is already broken would
/// launder the break, because every new line would chain from it.
pub fn head_of_existing(text: &str) -> Result<[u8; 32], ChainFault> {
    Ok(resume_of_existing(text)?.1)
}

/// The head to resume from *and* the number of records already chained.
///
/// The two come from the same verification pass on purpose. A sink reopening a
/// log has to resume its sequence counter past the records already on disk, and
/// deriving that count from the pass that computes the head means the two can
/// never disagree. Returned as `(records, head)` because the count is the primary
/// quantity here; [`head_of_existing`] is the accessor for callers that want only
/// the head.
///
/// Relies on one record per line and one sequence number per record, which is
/// what `append` guarantees.
pub fn resume_of_existing(text: &str) -> Result<(u64, [u8; 32]), ChainFault> {
    let v = verify(text)?;
    Ok((v.records, v.head))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal_all(bodies: &[&str]) -> String {
        let mut chain = Chain::new();
        let mut out = String::new();
        for b in bodies {
            out.push_str(&chain.seal(b));
            out.push('\n');
        }
        out
    }

    #[test]
    fn a_sealed_line_verifies_and_advances_the_head() {
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#]);
        let v = verify(&text).expect("clean chain");
        assert_eq!(v.records, 2);
        assert_ne!(v.head, genesis());
    }

    #[test]
    fn the_first_line_commits_to_genesis() {
        let mut chain = Chain::new();
        let line = chain.seal("{}");
        assert!(line.starts_with(&format!("{} ", hex(&genesis()))));
    }

    #[test]
    fn editing_any_byte_of_any_line_is_detected() {
        // The claim is "a single tampered byte in a historical entry is detected",
        // so exercise every byte offset rather than a convenient one.
        let original = seal_all(&[
            r#"{"entry":"attempt","tool":"fs.write","args":[]}"#,
            r#"{"entry":"outcome","attempt":1,"result":"succeeded"}"#,
            r#"{"entry":"attempt","tool":"mail.send","args":[{"name":"to"}]}"#,
        ]);

        let mut checked = 0;
        for byte_index in 0..original.len() {
            let mut mutated = original.clone().into_bytes();
            mutated[byte_index] ^= 0x01;
            let Ok(text) = String::from_utf8(mutated) else {
                continue;
            };
            assert!(
                verify(&text).is_err(),
                "flipping bit 0 of byte {byte_index} went undetected"
            );
            checked += 1;
        }
        assert!(checked > 200, "expected to exercise many offsets, got {checked}");
    }

    #[test]
    fn a_deleted_middle_record_breaks_the_link_after_it() {
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#, r#"{"seq":3}"#]);
        let lines: Vec<&str> = text.lines().collect();
        let spliced = format!("{}\n{}\n", lines[0], lines[2]);
        assert_eq!(verify(&spliced), Err(ChainFault::BrokenLink { line_no: 2 }));
    }

    #[test]
    fn reordered_records_break_the_link() {
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#, r#"{"seq":3}"#]);
        let lines: Vec<&str> = text.lines().collect();
        let swapped = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
        assert_eq!(verify(&swapped), Err(ChainFault::BrokenLink { line_no: 1 }));
    }

    #[test]
    fn a_duplicated_record_breaks_the_link() {
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#]);
        let lines: Vec<&str> = text.lines().collect();
        let doubled = format!("{}\n{}\n{}\n", lines[0], lines[0], lines[1]);
        assert_eq!(verify(&doubled), Err(ChainFault::BrokenLink { line_no: 2 }));
    }

    #[test]
    fn a_line_missing_its_newline_is_reported_as_a_partial_write() {
        // What a crash between `write_all` and the next append actually leaves: a
        // complete, correctly-chained final line with no terminator. The record may
        // or may not have been fully synced, so it is suspect rather than proven
        // altered, and `TruncatedTail` says so instead of quietly accepting it.
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#]);
        let unterminated = text.strip_suffix('\n').expect("ends with a newline");
        assert_eq!(
            verify(unterminated),
            Err(ChainFault::TruncatedTail { line_no: 2 })
        );
    }

    #[test]
    fn a_body_truncated_mid_json_is_detected_as_tampering() {
        // Distinct from the partial write above: here the line is still terminated
        // but its contents no longer hash to the digest the line claims.
        let text = seal_all(&[r#"{"seq":1}"#, r#"{"seq":2}"#]);
        let cut = &text[..text.len() - 4];
        assert!(matches!(verify(cut), Err(ChainFault::Tampered { .. })));
    }

    #[test]
    fn an_empty_log_verifies_as_empty() {
        let v = verify("").expect("no records");
        assert_eq!(v.records, 0);
        assert_eq!(v.head, genesis());
    }

    #[test]
    fn malformed_lines_are_rejected_rather_than_skipped() {
        for bad in [
            "no separators at all",
            "deadbeef\t{}",
            &format!("{} nothex\t{{}}", hex(&genesis())),
            &format!("{} \t{{}}", hex(&genesis())),
            &format!("{}\t{{}}", hex(&genesis())),
        ] {
            assert!(
                matches!(verify(&format!("{bad}\n")), Err(ChainFault::Malformed { .. })),
                "should have been malformed: {bad}"
            );
        }
    }

    #[test]
    fn a_pre_chain_record_is_reported_as_unchained_not_malformed() {
        // An operator who knows they have not touched the log needs to be told to
        // rotate it, not told it was attacked.
        let legacy = r#"{"seq":1,"atUnixMs":0,"entry":{"entry":"attempt"}}"#;
        assert_eq!(
            verify(&format!("{legacy}\n")),
            Err(ChainFault::Unchained { line_no: 1 })
        );
    }

    #[test]
    fn the_chain_label_cannot_collide_with_an_unlabelled_digest() {
        // Domain separation: hashing the same bytes without the label must give a
        // different digest, or an event digest could be replayed as a chain link.
        let mut bare = Sha256::new();
        bare.update(&genesis());
        bare.update(b"{}");
        assert_ne!(link(&genesis(), b"{}"), bare.finish());
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        let d = link(&genesis(), b"x");
        assert_eq!(unhex(&hex(&d)), Some(d));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex(&"z".repeat(64)), None);
        assert_eq!(unhex(&format!("{}0", hex(&d))), None);
    }

    #[test]
    fn uppercase_hex_is_rejected_so_the_encoding_is_canonical() {
        // Regression: `char::to_digit(16)` accepts 'A'..'F', and 'a' differs from 'A'
        // only in bit 5. Accepting both made a single bit-flip of a digest invisible
        // to verification, which would have made "every byte flip is detected" a lie.
        let d = link(&genesis(), b"x");
        let lower = hex(&d);
        assert!(lower.contains(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()));

        let upper = lower.to_ascii_uppercase();
        assert_ne!(upper, lower);
        assert_eq!(unhex(&upper), None, "uppercase must not decode");

        // And flipping bit 5 of a lowercase letter yields its uppercase twin, which
        // is now a malformed line rather than a silently equivalent one.
        let mutated: String = String::from_utf8(
            lower
                .bytes()
                .map(|b| if (b'a'..=b'f').contains(&b) { b ^ 0x20 } else { b })
                .collect(),
        )
        .expect("flipping ascii letter case stays valid UTF-8");
        assert_eq!(unhex(&mutated), None);
    }
}