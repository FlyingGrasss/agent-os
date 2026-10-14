//! End-to-end tamper detection against a real `FileSink` on a real disk file.
//!
//! The unit tests in `chain.rs` prove the arithmetic. These prove the property
//! that actually matters: that what the daemon writes to disk, read back by a
//! separate process, fails verification when any historical byte changes.
//!
//! The tests here deliberately include the cases the chain *cannot* catch, so
//! the limit is written down in executable form rather than only in prose.

use std::fs;
use std::path::{Path, PathBuf};

use agentos_tools::audit::{AuditLog, FileSink, OutcomeKind, PolicySummary, SystemClock};
use agentos_tools::chain::{self, ChainFault, Verification};

/// A scratch directory unique to this process, following the convention used by
/// the other file-based tests in this workspace.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agentos-chain-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Write `attempts` attempt/outcome pairs to a fresh file-backed log.
fn write_log(path: &Path, attempts: usize) {
    let sink = FileSink::open(path).expect("open sink");
    let mut log = AuditLog::new(Box::new(sink), Box::new(SystemClock));
    for i in 0..attempts {
        let tool = format!("tool-{i}");
        let token = log
            .record_intent(&tool, &[], PolicySummary::Allowed)
            .expect("record intent");
        log
            .record_outcome(&token, OutcomeKind::Succeeded { elapsed_ms: i as u64 })
            .expect("record outcome");
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).expect("read log")
}

/// A log written by a normal run verifies, and reports one record per intent and
/// per outcome.
#[test]
fn a_pristine_file_backed_log_verifies() {
    let dir = scratch("pristine");
    let path = dir.join("audit.log");
    write_log(&path, 3);

    let v = chain::verify(&read(&path)).expect("pristine log verifies");
    assert_eq!(v.records, 6, "3 attempts + 3 outcomes");
    assert_ne!(v.head, chain::genesis());
}

/// The headline claim: one flipped bit, anywhere in any historical record, is
/// caught. Every byte offset is exercised, not a representative sample, because
/// "we tested one edit" has hidden a great deal of untested hashing code.
#[test]
fn a_single_flipped_bit_in_any_record_is_detected() {
    let dir = scratch("bitflip");
    let path = dir.join("audit.log");
    write_log(&path, 3);

    let original = read(&path);
    let mut exercised = 0usize;

    for index in 0..original.len() {
        for bit in 0..8u8 {
            let mut mutated = original.clone().into_bytes();
            mutated[index] ^= 1 << bit;
            let Ok(text) = String::from_utf8(mutated) else {
                continue;
            };
            assert!(
                chain::verify(&text).is_err(),
                "flipping bit {bit} of byte {index} went undetected"
            );
            exercised += 1;
        }
    }

    assert!(
        exercised > 8_000,
        "expected to exercise every bit of every byte, only did {exercised}"
    );
}

/// An attacker editing a record to say something different — the case that
/// matters most — is caught even though the edit keeps the line well-formed.
#[test]
fn rewriting_a_denied_outcome_as_succeeded_is_detected() {
    let dir = scratch("rewrite");
    let path = dir.join("audit.log");

    let sink = FileSink::open(&path).expect("open sink");
    let mut log = AuditLog::new(Box::new(sink), Box::new(SystemClock));
    let token = log
        .record_intent("fs.write", &[], PolicySummary::Denied)
        .expect("record intent");
    log.record_outcome(&token, OutcomeKind::denied("policy refused"))
        .expect("record outcome");
    drop(log);

    let tampered = read(&path).replace("denied", "allowed");
    assert_ne!(tampered, read(&path), "the fixture must actually differ");
    assert!(
        matches!(chain::verify(&tampered), Err(ChainFault::Tampered { .. })),
        "a denied outcome rewritten to allowed must not verify"
    );
}

/// Removing a record from the middle leaves the rest looking like a perfectly
/// ordinary append-only log — which is exactly why the chain is needed.
#[test]
fn deleting_a_middle_record_is_detected() {
    let dir = scratch("delete");
    let path = dir.join("audit.log");
    write_log(&path, 4);

    let text = read(&path);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 8);

    // Drop the outcome for the first attempt: the next attempt no longer follows it.
    let spliced: String = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| format!("{l}\n"))
        .collect();

    assert_eq!(chain::verify(&spliced), Err(ChainFault::BrokenLink { line_no: 2 }));
}

/// Reordering two records is caught for the same reason deletion is.
#[test]
fn reordering_records_is_detected() {
    let dir = scratch("reorder");
    let path = dir.join("audit.log");
    write_log(&path, 3);

    let text = read(&path);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(2, 3);
    let swapped: String = lines.iter().map(|l| format!("{l}\n")).collect();

    assert_eq!(chain::verify(&swapped), Err(ChainFault::BrokenLink { line_no: 3 }));
}

/// A log that stops mid-record is suspect, not silently accepted.
#[test]
fn a_log_ending_mid_record_is_reported() {
    let dir = scratch("partial");
    let path = dir.join("audit.log");
    write_log(&path, 2);

    let text = read(&path);
    let cut = &text[..text.len() - 12];
    assert!(
        chain::verify(cut).is_err(),
        "a log ending mid-record must not verify"
    );
}

/// Reopening an existing log must continue the chain, not restart it.
///
/// A restart at genesis would make every log that survives a daemon restart fail
/// verification, and silently re-chaining from scratch would launder a tampered
/// tail.
#[test]
fn reopening_continues_the_chain_instead_of_restarting_it() {
    let dir = scratch("resume");
    let path = dir.join("audit.log");

    write_log(&path, 2);
    let before = chain::verify(&read(&path)).expect("first run verifies");

    write_log(&path, 2);
    let after = chain::verify(&read(&path)).expect("second run verifies");

    assert_eq!(after.records, 8, "both runs' records are present");
    assert_ne!(after.head, before.head, "the chain moved forward");

    // The first run's records must still be intact, not re-chained.
    let text = read(&path);
    let first_run: String = text.lines().take(4).map(|l| format!("{l}\n")).collect();
    let replayed = chain::verify(&first_run).expect("prefix still verifies");
    assert_eq!(replayed.records, 4);
    assert_eq!(replayed.head, before.head, "the head advanced, it was not rewritten");
}

/// Appending to a log whose history is already broken would launder the break,
/// because every new record inherits it. Opening must fail instead.
#[test]
fn a_sink_refuses_to_append_to_a_tampered_log() {
    let dir = scratch("refuse");
    let path = dir.join("audit.log");
    write_log(&path, 3);

    let text = read(&path);
    let tampered = text.replacen("tool-1", "tool-9", 1);
    fs::write(&path, tampered).expect("write tampered log");

    let err = FileSink::open(&path).expect_err("must refuse to open a broken log");
    assert!(
        err.to_string().contains("broken audit log"),
        "unhelpful error: {err}"
    );
}

/// The limit of a keyless chain, asserted rather than glossed over.
///
/// Truncating the *end* of a log yields a shorter prefix that is entirely
/// self-consistent, because every surviving link still holds. No keyless chain can
/// catch this on its own. What catches it is the head: if a reader recorded the
/// head when the log was last known-good, the truncated head will not match.
///
/// If this test ever starts failing because the chain *does* detect truncation,
/// the chain has gained a property worth keeping — update the module docs.
#[test]
fn tail_truncation_defeats_the_chain_but_changes_the_head() {
    let dir = scratch("truncate");
    let path = dir.join("audit.log");
    write_log(&path, 5);

    let full = read(&path);
    let lines: Vec<&str> = full.lines().collect();

    // Drop the last two records entirely. What remains is a valid prefix.
    let truncated: String = lines[..lines.len() - 2]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect();

    let honest: Verification = chain::verify(&truncated).expect("a prefix is self-consistent");
    assert_eq!(honest.records, 8, "2 of 5 pairs removed");

    // This is the whole reason the head is reported: the prefix is indistinguishable
    // from a log that simply never grew, unless something outside the file remembers
    // what the head used to be.
    let pinned = chain::verify(&full).expect("full log verifies");
    assert_ne!(honest.head, pinned.head, "an anchored reader detects the truncation");
}

/// Two logs with identical bodies but different history must have different
/// heads, or an attacker could reorder whole blocks between logs undetected.
#[test]
fn the_head_binds_position_not_just_content() {
    let single = {
        let mut c = chain::Chain::new();
        format!("{}\n", c.seal(r#"{"seq":1}"#))
    };
    let with_prefix = {
        let mut c = chain::Chain::new();
        let first = c.seal(r#"{"seq":9}"#);
        let second = c.seal(r#"{"seq":1}"#);
        format!("{first}\n{second}\n")
    };

    let a = chain::verify(&single).expect("verifies");
    let b = chain::verify(&with_prefix).expect("verifies");
    assert_eq!(a.records, 1);
    assert_eq!(b.records, 2);
    assert_ne!(
        a.head, b.head,
        "the same trailing record must chain to a different head"
    );
}