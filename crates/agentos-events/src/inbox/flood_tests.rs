//! Flood tests for the inbox.
//!
//! # What is being tested
//!
//! The claim in the module docs is that "a flood of files costs bounded model
//! calls rather than one call per file". These tests attack that claim from the
//! two directions an attacker would actually use:
//!
//! 1. **Many distinct files.** The rate limiter has to hold. This is the plain
//!    case and the one a burst limit is for.
//! 2. **The same file, many times.** The digest window has to hold, because the
//!    rate limiter alone would still let an attacker spend every token on copies
//!    of one file — bounded, but expensive, and pointless work.
//!
//! # Why these count model calls rather than files
//!
//! The property that matters is not "how many files were noticed" but "how many
//! would reach the model". A watcher that queued all ten thousand faithfully is
//! still a denial of service if each one becomes an inference call. So the tests
//! assert on the size of `Poll::ready`, which is the set that becomes work.

use std::fs;
use std::path::PathBuf;

use crate::inbox::{SkipReason, DEFERRED_DIR, PROCESSED_DIR};
use crate::ratelimit::Limits;
use crate::{Inbox, PayloadDigest};

use super::*;

/// A directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agentos-flood-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) {
        fs::write(self.0.join(name), contents).expect("write payload");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A limiter tight enough that a handful of files already exhausts it.
fn tight() -> Limits {
    // 1 per minute, burst 5. Five files pass, the sixth does not, and credit takes
    // a minute to come back -- so a test cannot accidentally pass because time
    // moved.
    Limits::per_minute(1, 5)
}

/// Poll until something is ready, or give up.
///
/// The settle rule means a new file takes two polls to appear, so "write N files
/// then poll" needs a couple of rounds before anything is ready.
fn poll_settled(inbox: &mut Inbox, rounds: usize) -> Vec<Poll> {
    let mut polls = Vec::new();
    for _ in 0..rounds {
        polls.push(inbox.poll().expect("poll"));
    }
    polls
}

fn ready_across(polls: &[Poll]) -> usize {
    polls.iter().map(|p| p.ready.len()).sum()
}

#[test]
fn a_flood_of_distinct_files_admits_only_the_burst() {
    // The primary claim. Five admitted against a burst of five, no matter how many
    // were dropped.
    let scratch = Scratch::new("distinct");
    for i in 0..500 {
        scratch.write(&format!("payload-{i}.txt"), &format!("distinct content {i}"));
    }

    let mut inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    let polls = poll_settled(&mut inbox, 4);

    let admitted = ready_across(&polls);
    assert_eq!(
        admitted, 5,
        "a burst of 5 must admit exactly 5, not 500"
    );
}

#[test]
fn the_flood_is_deferred_not_dropped() {
    // The other half of the claim, and the one that matters to the user: a
    // flood costs latency, not data. Every payload must still be on disk.
    let scratch = Scratch::new("notdropped");
    for i in 0..50 {
        scratch.write(&format!("payload-{i}.txt"), &format!("content {i}"));
    }

    let mut inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    poll_settled(&mut inbox, 4);

    let deferred_dir = scratch.0.join(DEFERRED_DIR);
    let deferred_count = fs::read_dir(&deferred_dir)
        .map(|d| d.count())
        .unwrap_or(0);

    // Whatever was admitted is no longer in the root; everything else must be in
    // deferred/. Nothing may have been deleted.
    let root_remaining = fs::read_dir(&scratch.0)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    !e.file_name().to_string_lossy().contains(DEFERRED_DIR)
                        && !e.file_name().to_string_lossy().contains(PROCESSED_DIR)
                })
                .count()
        })
        .unwrap_or(0);

    assert_eq!(
        deferred_count + root_remaining,
        50,
        "every payload must be accounted for: on disk, deferred, or not lost"
    );
    assert!(
        deferred_count >= 45,
        "most of the flood should be deferred, got {deferred_count}"
    );
}

#[test]
fn a_deferred_payload_is_never_lost_even_if_the_daemon_restarts() {
    // Deferral has to survive a crash, or "not dropped" is only true while the
    // process lives. A fresh watcher over the same directory must see the
    // backlog.
    let scratch = Scratch::new("survives");
    for i in 0..20 {
        scratch.write(&format!("payload-{i}.txt"), &format!("content {i}"));
    }

    let mut first = Inbox::with_limits(&scratch.0, tight()).unwrap();
    poll_settled(&mut first, 4);
    drop(first);

    // A brand new watcher, as if the daemon had been restarted.
    let mut second = Inbox::with_limits(&scratch.0, tight()).unwrap();
    let polls = poll_settled(&mut second, 4);

    assert!(
        ready_across(&polls) > 0,
        "a restarted daemon must pick up the deferred backlog"
    );
}

#[test]
fn the_same_file_dropped_many_times_costs_nothing_after_the_first() {
    // The digest window. Ten thousand copies of one file have one digest, so the
    // copies cost no model calls at all — the rate limiter does not even have to
    // absorb them.
    let scratch = Scratch::new("duplicate");
    for i in 0..200 {
        scratch.write(&format!("copy-{i}.txt"), "the same bytes every time");
    }

    let mut inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    let polls = poll_settled(&mut inbox, 4);

    let admitted = ready_across(&polls);
    assert_eq!(
        admitted, 1,
        "identical payloads must cost one model call, not one per copy"
    );

    let duplicates: usize = polls
        .iter()
        .flat_map(|p| p.skipped.iter())
        .filter(|s| s.reason == SkipReason::DuplicatePayload)
        .count();
    assert!(duplicates > 0, "the repeats must be reported as duplicates");
}

#[test]
fn distinct_content_is_not_mistaken_for_a_duplicate() {
    // The converse, and the one that matters for not losing the user's work: two
    // files that differ by one byte are two payloads and both get through.
    let scratch = Scratch::new("nearidentical");
    scratch.write("a.txt", "the report says 41 units");
    scratch.write("b.txt", "the report says 42 units");

    let mut inbox = Inbox::with_limits(&scratch.0, Limits::per_minute(60, 10)).unwrap();
    let polls = poll_settled(&mut inbox, 4);

    assert_eq!(
        ready_across(&polls),
        2,
        "one differing byte must make these distinct payloads"
    );
    assert_ne!(PayloadDigest::of(b"the report says 41 units"),
               PayloadDigest::of(b"the report says 42 units"));
}

#[test]
fn a_flood_does_not_stop_the_deferred_queue_draining() {
    // Rate limiting is not the same as refusing. Given time, the backlog must
    // drain, or the limiter has silently become a loss.
    let scratch = Scratch::new("drains");
    for i in 0..10 {
        scratch.write(&format!("payload-{i}.txt"), &format!("content {i}"));
    }

    let mut inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    let first = poll_settled(&mut inbox, 4);
    let admitted_first = ready_across(&first);
    assert_eq!(admitted_first, 5);

    // The bucket needs a minute per credit at this rate. Rather than sleep, this
    // asserts the *mechanism*: the deferred directory still holds the rest, and
    // `deferred/` entries are still files on disk that a later pass would move.
    let deferred = fs::read_dir(scratch.0.join(DEFERRED_DIR))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(deferred, 5, "the remaining five must be waiting, not dropped");

    // And they are readable payloads, not placeholders.
    let contents: Vec<String> = fs::read_dir(scratch.0.join(DEFERRED_DIR))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter_map(|e| fs::read_to_string(e.path()).ok())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(contents.len(), 5);
    assert!(contents.iter().all(|c| c.starts_with("content ")));
}

#[test]
fn a_default_limiter_admits_a_persons_ordinary_drop() {
    // The limiter must not be so tight that the feature is unusable. The default
    // allows a burst of eight, so a person dropping a morning's files is not
    // throttled into frustration.
    let scratch = Scratch::new("default");
    for i in 0..6 {
        scratch.write(&format!("payload-{i}.txt"), &format!("content {i}"));
    }

    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let polls = poll_settled(&mut inbox, 4);
    assert_eq!(ready_across(&polls), 6, "six files must pass the default limit");
}

#[test]
fn the_limiter_can_be_told_it_is_weak() {
    // A limit above one per second is not plausible for a model-backed pipeline,
    // so it almost certainly means misconfiguration. The daemon should be able to
    // say so rather than silently running unprotected.
    let scratch = Scratch::new("weak");

    let tight_inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    assert!(!tight_inbox.flood_defence_is_weak());

    let fast = Inbox::with_limits(&scratch.0, Limits::per_minute(600, 60)).unwrap();
    assert!(
        fast.flood_defence_is_weak(),
        "ten per second must be reported as a weak configuration"
    );
}

#[test]
fn a_flood_does_not_exhaust_memory_or_disk_in_the_watcher() {
    // The window is bounded, so a long flood of *distinct* files cannot grow the
    // watcher without limit. Files themselves are on disk (the user's problem),
    // but the watcher's own state must stay small.
    let scratch = Scratch::new("bounded");
    for i in 0..300 {
        scratch.write(&format!("payload-{i}.txt"), &format!("content {i}"));
    }

    let mut inbox = Inbox::with_limits(&scratch.0, tight()).unwrap();
    poll_settled(&mut inbox, 4);

    // The watcher tracks one `u64` per live file for the settle check, which is
    // bounded by what is on disk, plus a digest window capped at 1024 entries.
    // What must not happen is unbounded growth of anything the watcher owns
    // independently of the directory contents.
    let tracked = inbox.seen_len();
    assert!(tracked <= 300, "the watcher tracks at most the files present");
    assert!(
        inbox.digest_window_len() <= 1024,
        "the digest window must stay bounded regardless of how many files arrive"
    );
}

#[test]
fn a_duplicate_still_counts_as_accounted_for_on_disk() {
    // Skipping a duplicate must not mean deleting it. The payload is the user's.
    let scratch = Scratch::new("dupdisk");
    for i in 0..5 {
        scratch.write(&format!("copy-{i}.txt"), "identical");
    }

    let mut inbox = Inbox::with_limits(&scratch.0, Limits::per_minute(60, 10)).unwrap();
    poll_settled(&mut inbox, 4);

    let on_disk: usize = fs::read_dir(&scratch.0)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n != DEFERRED_DIR && n != PROCESSED_DIR
                })
                .count()
        })
        .unwrap_or(0);
    let deferred = fs::read_dir(scratch.0.join(DEFERRED_DIR))
        .map(|d| d.count())
        .unwrap_or(0);

    assert_eq!(
        on_disk + deferred,
        5,
        "skipping a duplicate must not delete the user's file"
    );
}