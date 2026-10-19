//! The sequence counter is ledger-wide, not per-`AuditLog`.
//!
//! # The defect these cover
//!
//! `AuditRecord::seq` was documented as "monotonic, 1-based, never reused",
//! but the counter lived in `AuditLog` and the daemon builds one `AuditLog` per
//! task. Fifty concurrent tasks therefore produced fifty records numbered
//! `1`, `2`, ... The chain was unaffected -- it commits to the literal line
//! bytes, not to `seq` -- but a forensic reader opening the log saw a column of
//! numbers that repeated, and the documentation promised otherwise.
//!
//! The fix moves the counter into the sink, which is the object every task
//! genuinely shares. These tests hold that property in place.
//!
//! The concurrency-level version of this is
//! `agentos-cli/tests/concurrency_stress.rs`, which drives it through fifty real
//! connections. The tests here hold the mechanism still so a failure points at
//! the counter rather than at the daemon.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentos_tools::audit::{
    AuditEntry, AuditError, AuditLog, AuditRecord, AuditSink, BoundedText, FileSink, PolicySummary,
    SystemClock,
};

/// Mirrors the daemon's `LockedSink`: one sink behind a mutex, shared by every
/// `AuditLog` that talks to it. This is the shape that makes `seq` ledger-wide,
/// so the test has to reproduce it rather than approximate it.
#[derive(Clone)]
struct Shared(Arc<Mutex<FileSink>>);

impl AuditSink for Shared {
    fn append(&mut self, record: &mut AuditRecord) -> Result<(), AuditError> {
        self.0.lock().expect("sink not poisoned").append(record)
    }

    fn peek_next_seq(&self) -> u64 {
        self.0.lock().expect("sink not poisoned").peek_next_seq()
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agentos-seq-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        Self(dir)
    }

    fn log(&self) -> PathBuf {
        self.0.join("audit.log")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A record with no meaningful sequence number: the sink assigns it.
fn record() -> AuditRecord {
    AuditRecord {
        seq: 0,
        at_unix_ms: 1_700_000_000_000,
        entry: AuditEntry::Attempt {
            tool: BoundedText::new("fs.write", 64),
            args: Vec::new(),
            omitted_args: 0,
            policy: PolicySummary::Allowed,
        },
    }
}

fn seqs_in(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .expect("read ledger")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let body = l.split_once('\t').expect("chain prefix").1;
            serde_json::from_str::<serde_json::Value>(body).expect("record json")["seq"]
                .as_u64()
                .expect("seq is a number")
        })
        .collect()
}

/// The load-bearing test: two logs, one sink, no repeated numbers.
#[test]
fn one_sink_hands_every_log_a_unique_sequence_number() {
    let s = Scratch::new("shared");
    let path = s.log();
    let shared = Shared(Arc::new(Mutex::new(FileSink::open(&path).expect("open"))));

    // Two `AuditLog`s, standing in for two tasks. Each owns its own log; both
    // append to the one shared sink.
    let mut a = AuditLog::new(Box::new(shared.clone()), Box::new(SystemClock));
    let mut b = AuditLog::new(Box::new(shared.clone()), Box::new(SystemClock));

    let mut seen = Vec::new();
    for i in 0..20 {
        let token = if i % 2 == 0 {
            a.record_intent("fs.write", &[], PolicySummary::Allowed)
        } else {
            b.record_intent("fs.write", &[], PolicySummary::Allowed)
        }
        .expect("append");
        seen.push(token.seq());
    }

    assert_eq!(
        seen,
        (1..=20).collect::<Vec<u64>>(),
        "sequence numbers must be ledger-wide; a per-log counter repeats here"
    );
    assert_eq!(
        seqs_in(&path),
        (1..=20).collect::<Vec<u64>>(),
        "and the numbers written must match the ones handed out"
    );

    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        agentos_tools::chain::verify(&text).expect("chain intact").records,
        20
    );
}

/// Restarting the daemon must not restart the counter: the same defect, moved
/// from "between tasks" to "between runs".
#[test]
fn reopening_a_log_resumes_the_sequence_counter() {
    let s = Scratch::new("resume");
    let path = s.log();

    {
        let mut sink = FileSink::open(&path).expect("open");
        for _ in 0..3 {
            sink.append(&mut record()).expect("append");
        }
        assert_eq!(sink.peek_next_seq(), 4);
    }

    let mut sink = FileSink::open(&path).expect("reopen");
    assert_eq!(
        sink.peek_next_seq(),
        4,
        "a reopened log must resume past the records on disk, not restart at 1"
    );
    sink.append(&mut record()).expect("append after reopen");

    assert_eq!(
        seqs_in(&path),
        vec![1, 2, 3, 4],
        "the fourth record carries the fourth number, not a repeated 1"
    );
    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        agentos_tools::chain::verify(&text).expect("chain intact").records,
        4
    );
}

/// A refusal must not spend a number, or the first retry after a rotation would
/// reuse the number the refused record would have had.
#[test]
fn a_refused_append_does_not_consume_a_sequence_number() {
    let s = Scratch::new("refuse");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    sink.append(&mut record()).expect("append");
    assert_eq!(sink.peek_next_seq(), 2);

    std::fs::remove_file(&path).expect("unlink");
    assert!(
        sink.append(&mut record()).is_err(),
        "a removed path must be refused"
    );
    assert_eq!(
        sink.peek_next_seq(),
        2,
        "a refused append must not consume a sequence number"
    );
}
