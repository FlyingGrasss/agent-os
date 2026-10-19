//! Rotation detection: the log must not follow a path that stopped being its log.
//!
//! # The defect this covers
//!
//! A long-running daemon holds one open descriptor to the audit log. `logrotate`'s
//! default strategy is rename-then-create: it renames the old file out of the way
//! and writes a fresh empty one at the original path. The daemon's descriptor
//! follows the *renamed* file, which now has no name. It keeps accepting writes
//! happily, and every reader that opens the path sees the new file instead.
//!
//! Observed live, not theorised: six records went into an unlinked inode while
//! `agentos audit verify` on the path reported `ok 2 records chained`. The audit
//! trail and the audited file had quietly become two different files.
//!
//! These tests assert the sink refuses rather than diverging.

use std::fs;
use std::path::{Path, PathBuf};

use agentos_tools::audit::{
    AuditEntry, AuditError, AuditRecord, AuditSink, BoundedText, FileIdentity, FileSink,
    PolicySummary,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agentos-rot-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        Self(dir)
    }

    fn log(&self) -> PathBuf {
        self.0.join("audit.log")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Append one record straight through the sink.
///
/// Built by hand rather than through `AuditLog` because this file is about the
/// *sink*: `AuditLog` takes ownership of its sink, which makes it impossible to
/// hold one open, rotate the file, and keep appending -- which is the entire
/// scenario.
///
/// The record is an `Attempt`, which carries no sequence number, because the sink
/// assigns `seq` itself. A hand-tracked number here would only be overwritten.
fn append_one(sink: &mut FileSink) -> Result<(), AuditError> {
    sink.append(&mut AuditRecord {
        seq: 0,
        at_unix_ms: 1_700_000_000_000,
        entry: AuditEntry::Attempt {
            tool: BoundedText::new("fs.write", 64),
            args: Vec::new(),
            omitted_args: 0,
            policy: PolicySummary::Allowed,
        },
    })
}

fn size_of(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The core case: rename-and-create, which is what logrotate does
// ---------------------------------------------------------------------------

#[test]
fn a_sink_refuses_to_append_after_the_log_is_renamed_away() {
    let s = Scratch::new("rename");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    append_one(&mut sink).expect("first append works");
    let before = size_of(&path);
    assert!(before > 0, "nothing was written");

    // logrotate: rename the live log aside, create a fresh empty one at the path.
    fs::rename(&path, s.0.join("audit.log.1")).expect("rotate");
    fs::write(&path, "").expect("create replacement");

    // The descriptor is still perfectly valid. That is the whole problem.
    let err = append_one(&mut sink).expect_err("must refuse after rotation");
    assert!(
        matches!(err, AuditError::LogRotatedOrReplaced(_)),
        "expected a rotation fault, got {err:?}"
    );
    let text = err.to_string();
    assert!(text.contains("rotated"), "{text}");

    // And critically: nothing was written to either file. The tool that asked for
    // this record is not going to run, so nothing may have leaked.
    assert_eq!(size_of(&path), 0, "wrote into the replacement file");
    assert_eq!(
        size_of(&s.0.join("audit.log.1")),
        before,
        "wrote into the orphaned file"
    );
}

#[test]
fn the_faithful_case_does_not_divert_the_audit_trail() {
    // The consequence, stated as its own test: the path and the descriptor must
    // never again hold different amounts of audit history.
    let s = Scratch::new("divert");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    append_one(&mut sink).expect("append");
    let recorded_before = size_of(&path);

    fs::rename(&path, s.0.join("audit.log.1")).expect("rotate");
    fs::write(&path, "").expect("replace");

    let _ = append_one(&mut sink); // expected to fail
    let _ = append_one(&mut sink); // and to keep failing

    assert_eq!(size_of(&path), 0, "the path must not grow");
    assert_eq!(
        size_of(&s.0.join("audit.log.1")),
        recorded_before,
        "the orphan must not grow either"
    );
}

// ---------------------------------------------------------------------------
// The other ways a path stops being the file
// ---------------------------------------------------------------------------

#[test]
fn a_sink_refuses_after_the_log_is_deleted_outright() {
    let s = Scratch::new("delete");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    append_one(&mut sink).expect("append");

    fs::remove_file(&path).expect("unlink");

    let err = append_one(&mut sink).expect_err("must refuse after unlink");
    assert!(
        matches!(err, AuditError::LogRotatedOrReplaced(_)),
        "a deleted path is the same class of fault, got {err:?}"
    );
    assert_eq!(size_of(&path), 0, "the path must not reappear");
}

#[test]
fn a_sink_refuses_after_the_log_is_truncated_in_place() {
    // `copytruncate` is the other logrotate strategy: same inode, empty file. The
    // identity is unchanged, so only the size check can catch this.
    let s = Scratch::new("truncate");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    append_one(&mut sink).expect("append");
    let before = size_of(&path);

    fs::write(&path, "").expect("copytruncate");

    let err = append_one(&mut sink).expect_err("must refuse after truncate");
    assert!(
        matches!(err, AuditError::LogRotatedOrReplaced(_)),
        "expected a rotation fault, got {err:?}"
    );
    assert_eq!(size_of(&path), 0, "history was already lost before the check");
    let _ = before;
}

#[test]
fn a_sink_keeps_working_when_nothing_moved() {
    // The negative case. A check that cannot tell rotation from normal operation
    // is not a check, it is a coin flip that happens to say yes.
    let s = Scratch::new("stable");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    for i in 1..=25u64 {
        append_one(&mut sink).unwrap_or_else(|e| panic!("append {i} refused: {e}"));
    }

    assert!(size_of(&path) > 0, "nothing was written");
    let text = fs::read_to_string(&path).expect("read");
    assert_eq!(text.lines().count(), 25, "one record per append");
    // And the chain is intact, which is the property the sink exists to protect.
    let v = agentos_tools::chain::verify(&text).expect("chain intact");
    assert_eq!(v.records, 25);
}

#[test]
fn reopening_after_rotation_adopts_the_new_file_and_its_chain() {
    // Refusing is only half the job. The recovery path has to work, or operators
    // will restart with a rotated log and find it unusable.
    let s = Scratch::new("reopen");
    let path = s.log();

    let mut sink = FileSink::open(&path).expect("open");
    append_one(&mut sink).expect("append");
    let before = size_of(&path);

    fs::rename(&path, s.0.join("audit.log.1")).expect("rotate");
    fs::write(&path, "").expect("replace");

    let mut sink = FileSink::open(&path).expect("reopen on the replacement");
    assert_eq!(
        sink.identity(),
        FileIdentity::of_path(&path).expect("identity"),
        "the reopened sink must describe the file at the path"
    );
    append_one(&mut sink).expect("append to the new file");

    let text = fs::read_to_string(&path).expect("read");
    let v = agentos_tools::chain::verify(&text).expect("new file is a valid chain");
    assert_eq!(v.records, 1, "the replacement starts its own chain, from genesis");
    // The rotated-aside file still holds exactly what it had, untouched.
    assert_eq!(size_of(&s.0.join("audit.log.1")), before, "the old file was not rewritten");
}