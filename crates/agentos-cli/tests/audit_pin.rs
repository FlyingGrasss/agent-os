//! Integration tests for `agentos audit verify --pin`.
//!
//! These drive the built binary rather than the library, because the thing under
//! test is a *command*: its exit codes and what it prints. A pin check that works
//! in a unit test and returns 0 in a shell script is not a working pin check.
//!
//! The bug this closes is specific and silent. `verify` alone cannot see a
//! truncated log -- a truncated log is a shorter but entirely valid prefix, every
//! surviving link still holds. An operator who believed otherwise would watch
//! `exit 0` from a nightly job while an attacker quietly removed the records they
//! cared about.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use agentos_tools::chain::{Chain, verify};

/// The `agentos` binary under test.
///
/// `CARGO_BIN_EXE_agentos` is set by cargo for integration tests and points at
/// the binary built from this same package, so this cannot silently drift onto a
/// stale executable the way a hardcoded path would.
fn agentos() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentos"))
}

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agentos-pin-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        Self(dir)
    }

    fn ledger(&self) -> PathBuf {
        self.0.join("audit.log")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write `count` chained records and return the head.
fn write_ledger(path: &Path, count: usize) -> String {
    let mut chain = Chain::new();
    let mut text = String::new();
    for i in 0..count {
        let body = format!(r#"{{"seq":{i},"entry":"attempt","tool":"fs.write"}}"#);
        text.push_str(&chain.seal(&body));
        text.push('\n');
    }
    std::fs::write(path, &text).expect("write ledger");
    verify(&text).expect("fresh ledger verifies").head_hex()
}

fn run(path: &Path, pin: Option<&str>) -> (i32, String) {
    let mut cmd = agentos();
    cmd.arg("audit").arg("verify").arg("--path").arg(path);
    if let Some(p) = pin {
        cmd.arg("--pin").arg(p);
    }
    let out = cmd.output().expect("run agentos");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

// ---------------------------------------------------------------------------
// The headline case: tail truncation
// ---------------------------------------------------------------------------

#[test]
fn an_intact_chain_is_not_enough_a_pinned_truncation_is_caught() {
    let s = Scratch::new("truncate");
    let path = s.ledger();

    let head = write_ledger(&path, 5);

    // Pin the head we just recorded, the way a scheduled job would.
    let (code, text) = run(&path, Some(&head));
    assert_eq!(code, 0, "a matching pin must pass: {text}");
    assert!(text.contains("matches pin"), "{text}");

    // Now truncate the tail -- exactly what the pin exists to catch. The remaining
    // prefix is a *valid* chain.
    let full = std::fs::read_to_string(&path).expect("read");
    let truncated: String = full
        .lines()
        .take(2)
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&path, &truncated).expect("write truncated");

    // The chain alone says everything is fine. This is the whole reason --pin exists.
    let (code, _) = run(&path, None);
    assert_eq!(
        code, 0,
        "this assertion documents the LIMIT: a truncated log must still pass an \
         unpinned check, or --pin would be solving a problem that does not exist"
    );
    assert!(verify(&truncated).is_ok(), "the prefix is a valid chain");

    // With the pin, it is caught, and the exit code says which kind of problem it is.
    let (code, text) = run(&path, Some(&head));
    assert_eq!(code, 2, "a pin mismatch must exit 2: {text}");
    assert!(text.contains("PIN MISMATCH"), "{text}");
    assert!(text.contains("expected head"), "{text}");
    assert!(text.contains(&head), "the pin it was compared against: {text}");
    assert!(text.contains("truncated or the log was rolled over"), "{text}");
}

// ---------------------------------------------------------------------------
// Exit codes are the interface
// ---------------------------------------------------------------------------

#[test]
fn the_four_outcomes_get_four_distinct_exit_codes() {
    let s = Scratch::new("codes");
    let path = s.ledger();
    let head = write_ledger(&path, 3);

    // 0: intact, pin matches.
    assert_eq!(run(&path, Some(&head)).0, 0);
    // 0: intact, no pin asked for.
    assert_eq!(run(&path, None).0, 0);

    // 2: intact chain, wrong head. The truncation case.
    let full = std::fs::read_to_string(&path).expect("read");
    let shortened: String = full.lines().take(1).map(|l| format!("{l}\n")).collect();
    std::fs::write(&path, &shortened).expect("write");
    let (code, text) = run(&path, Some(&head));
    assert_eq!(code, 2, "a pinned head that moved must exit 2: {text}");

    // 1: the chain itself is broken. An edit, not a truncation.
    std::fs::write(&path, &full).expect("restore");
    let mut edited = full.clone();
    let at = edited.find("fs.write").expect("body");
    edited.replace_range(at..at + 2, "zz");
    std::fs::write(&path, &edited).expect("write");
    let (code, text) = run(&path, Some(&head));
    assert_eq!(code, 1, "a broken chain must exit 1, not 2: {text}");
    assert!(text.contains("COMPROMISED"), "{text}");
    // A broken chain has no head, so it must not pretend to a pin comparison.
    assert!(
        text.contains("not established"),
        "a broken chain must say the head is unknown, not report a mismatch: {text}"
    );

    // 3: usage error, checked before the ledger is even read.
    assert_eq!(run(&path, Some("not-a-hash")).0, 3);
}

#[test]
fn a_malformed_pin_is_a_usage_error_not_a_verdict_on_the_ledger() {
    let s = Scratch::new("badpin");
    let path = s.ledger();
    let head = write_ledger(&path, 2);

    for bad in ["", "abc", &"z".repeat(64), &"0".repeat(63), &"0".repeat(65)] {
        let (code, text) = run(&path, Some(bad));
        assert_eq!(code, 3, "`{bad}` should be a usage error: {text}");
        assert!(
            text.contains("is not a ledger head"),
            "a typo must not be reported as tampering: {text}"
        );
        assert!(
            !text.contains("COMPROMISED") && !text.contains("PIN MISMATCH"),
            "a malformed pin must not accuse the ledger: {text}"
        );
    }

    // And the real pin still works afterwards.
    assert_eq!(run(&path, Some(&head)).0, 0);
}

#[test]
fn a_pin_comparison_ignores_case_because_it_is_typed_by_hand() {
    let s = Scratch::new("case");
    let path = s.ledger();
    let head = write_ledger(&path, 2);

    let (code, text) = run(&path, Some(&head.to_ascii_uppercase()));
    assert_eq!(
        code, 0,
        "a pin copied in upper case must still match: {text}"
    );
}

// ---------------------------------------------------------------------------
// The pin must not weaken what it does not replace
// ---------------------------------------------------------------------------

#[test]
fn a_pin_cannot_launder_a_broken_chain() {
    // Someone could hope a matching pin turns exit 1 into exit 0. It must not: the
    // pin is an *additional* requirement, never a substitute for the chain.
    let s = Scratch::new("launder");
    let path = s.ledger();
    let head = write_ledger(&path, 3);

    // Delete the middle record, then pin the head of the BROKEN file.
    let full = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = full.lines().collect();
    let broken: String = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    std::fs::write(&path, &broken).expect("write");

    // Pin the head the broken file itself reports, so the pin can never match.
    let broken_head = match verify(&broken) {
        Ok(_) => panic!("the spliced file must not verify"),
        Err(_) => {
            // Derive the head the broken file *would* claim is irrelevant; pinning
            // the correct original head is the realistic attack.
            head.clone()
        }
    };

    let (code, text) = run(&path, Some(&broken_head));
    assert_eq!(
        code, 1,
        "a broken chain stays broken no matter what is pinned: {text}"
    );
}

#[test]
fn pinning_an_empty_ledger_still_detects_later_records() {
    // The pin is meaningful from the first moment: a brand new log has the genesis
    // head, and as soon as anything is written the pin stops matching.
    let s = Scratch::new("empty");
    let path = s.ledger();

    std::fs::write(&path, "").expect("write empty");
    let genesis = agentos_tools::chain::genesis();
    let genesis_hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();

    let (code, text) = run(&path, Some(&genesis_hex));
    assert_eq!(code, 0, "an empty ledger has the genesis head: {text}");

    write_ledger(&path, 1);
    let (code, text) = run(&path, Some(&genesis_hex));
    assert_eq!(
        code, 2,
        "once anything is written the genesis pin must stop matching: {text}"
    );
}

#[test]
fn a_missing_ledger_is_an_error_not_a_pass() {
    // The failure that matters most in cron: a deleted log must not look healthy.
    let s = Scratch::new("missing");
    let path = s.ledger();
    let head = write_ledger(&path, 2);
    std::fs::remove_file(&path).expect("remove");

    let out = agentos()
        .args(["audit", "verify", "--path"])
        .arg(&path)
        .arg("--pin")
        .arg(&head)
        .output()
        .expect("run");
    assert_ne!(
        out.status.code(),
        Some(0),
        "a missing ledger must never exit 0"
    );
}