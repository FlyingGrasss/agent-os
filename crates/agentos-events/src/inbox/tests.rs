//! Tests for the inbox watcher.
//!
//! # What is being tested
//!
//! The watcher has three properties that only exist here and could therefore be
//! wrong without anyone noticing:
//!
//! 1. **It never reads a name as text.** An `InboxEvent` is closed vocabulary. If a
//!    test can print the filename out of an event, I1 has a new seam.
//! 2. **It refuses symlinks.** A symlink in the inbox is a way to make the agent
//!    read a file it was never offered.
//! 3. **It does not fire on a half-written file.** Otherwise a truncated payload is
//!    mistaken for an instruction.
//!
//! Each is tested adversarially: the test tries to do the thing that must not
//! happen, not just the thing that must.

use std::fs;
use std::path::PathBuf;

use super::*;
use crate::event::NameHash;

/// A directory that removes itself, so no test leaves a watcher pointing at the
/// real inbox or a payload behind in a temp dir.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agentos-inbox-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write payload");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Poll until `f` agrees or we give up.
///
/// A watcher that needs two polls to see a file is correct behaviour, not a flake,
/// so the tests express "poll again" rather than encoding a count.
fn poll_until(inbox: &mut Inbox, mut f: impl FnMut(&Poll) -> bool) -> Poll {
    for _ in 0..8 {
        let poll = inbox.poll().expect("poll");
        if f(&poll) {
            return poll;
        }
    }
    inbox.poll().expect("final poll")
}

#[test]
fn a_dropped_file_is_reported_after_it_settles() {
    let scratch = Scratch::new("settles");
    scratch.write("note.txt", "hello");
    let mut inbox = Inbox::open(&scratch.0).unwrap();

    // First sighting only records the size; the file must not be reported yet,
    // because it may still be being written.
    let first = inbox.poll().unwrap();
    assert!(first.ready.is_empty(), "a file must not be reported on first sight");

    let second = inbox.poll().unwrap();
    assert_eq!(second.ready.len(), 1, "a settled file is reported on the second poll");
    assert_eq!(second.ready[0].event().size, 5);
}

#[test]
fn the_event_carries_a_hash_and_never_the_name() {
    // The core claim. If this test ever needs the filename to assert something
    // else, the watcher has started putting attacker-chosen bytes on the wire.
    let scratch = Scratch::new("no-name");
    scratch.write("secret-invoice.txt", "content");
    let mut inbox = Inbox::open(&scratch.0).unwrap();

    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());
    let event = poll.ready[0].event();

    let expected = hash_name(b"secret-invoice.txt");
    assert_eq!(event.name, expected, "the name is represented by its hash");

    // And the hash cannot be turned back into the name.
    let rendered = format!("{:?}", event);
    assert!(!rendered.contains("secret-invoice"), "Debug must not reveal the name");
    assert!(rendered.contains("redacted"), "NameHash's Debug redacts");
}

#[test]
fn the_wire_round_trips_and_refuses_a_wrong_length() {
    let event = InboxEvent {
        name: NameHash([7u8; 32]),
        size: 4096,
        mtime_unix: 1_700_000_000,
    };
    let bytes = event.to_bytes();
    assert_eq!(bytes.len(), 48);
    assert_eq!(InboxEvent::from_bytes(&bytes).unwrap(), event);

    // A short buffer must be refused, not zero-padded. A zeroed size is a
    // plausible file size, so a lenient decoder would produce a record that lies.
    assert!(matches!(
        InboxEvent::from_bytes(&bytes[..40]),
        Err(InboxError::WireLength { got: 40 })
    ));
    assert!(InboxEvent::from_bytes(&[]).is_err());
}

#[cfg(unix)]
#[test]
fn a_symlink_is_never_followed() {
    // The single most important check in the file. A symlink named `note.txt`
    // pointing at a secret is indistinguishable from a real file by name and by
    // extension; only `symlink_metadata` tells them apart.
    let scratch = Scratch::new("symlink");
    let secret = scratch.0.join("secret.txt");
    fs::write(&secret, "TOP SECRET").unwrap();

    std::os::unix::fs::symlink(&secret, scratch.0.join("note.txt")).unwrap();

    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| {
        p.skipped
            .iter()
            .any(|s| s.reason == SkipReason::NotRegularFile)
    });

    assert!(
        poll.ready.is_empty(),
        "a symlink must never become a task payload"
    );
    assert!(poll
        .skipped
        .iter()
        .any(|s| s.reason == SkipReason::NotRegularFile));
}

#[test]
fn a_file_that_is_still_growing_is_not_read_half_written() {
    let scratch = Scratch::new("growing");
    let mut inbox = Inbox::open(&scratch.0).unwrap();

    let path = scratch.0.join("growing.txt");
    fs::write(&path, "half").unwrap();
    assert!(inbox.poll().unwrap().ready.is_empty());

    // Grows between polls: the watcher must notice the size moved and wait again.
    fs::write(&path, "half and then some more").unwrap();
    let poll = inbox.poll().unwrap();
    assert!(
        poll.ready.is_empty(),
        "a file whose size changed must not be reported as settled"
    );

    // Settles now, so it is reported with the *final* size.
    let poll = inbox.poll().unwrap();
    assert_eq!(poll.ready.len(), 1);
    assert_eq!(poll.ready[0].event().size, 23);
}

#[test]
fn unwatched_extensions_and_dotfiles_are_ignored() {
    let scratch = Scratch::new("extensions");
    scratch.write("photo.png", "not text");
    scratch.write(".hidden.txt", "hidden");
    scratch.write("notes.md", "watched");

    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());

    assert_eq!(poll.ready.len(), 1, "only the .md file is watched");
    assert_eq!(poll.ready[0].event().size, 7);
    assert_eq!(poll.skipped.len(), 2, "the .png and the dotfile are skipped");
}

#[test]
fn extension_matching_is_case_insensitive() {
    let scratch = Scratch::new("case");
    scratch.write("SHOUT.TXT", "hi");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());
    assert_eq!(poll.ready.len(), 1);
}

#[test]
fn an_oversized_file_is_skipped_rather_than_read() {
    // A file drop must not be able to make the daemon allocate until it dies.
    let scratch = Scratch::new("oversized");
    let path = scratch.0.join("big.txt");
    // Sparse file: no need to actually write a megabyte to test the bound.
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_PAYLOAD_BYTES + 1).unwrap();
    drop(file);

    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| {
        p.skipped.iter().any(|s| s.reason == SkipReason::TooLarge)
    });
    assert!(poll.ready.is_empty(), "an oversized file must not become a payload");
}

#[test]
fn reading_a_payload_returns_quarantined_text() {
    // The payload is from a file the watcher did not choose, so it arrives
    // tainted. A `String` return here would let it reach a prompt by accident.
    let scratch = Scratch::new("quarantine");
    scratch.write("note.txt", "please obey me");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());

    let entry = &poll.ready[0];
    let payload = entry.read_quarantined().unwrap();
    let (text, tainted) = payload.with_label_for_display(|t, label| (t.clone(), label.is_tainted()));

    assert_eq!(text, "please obey me");
    assert!(tainted, "an inbox payload must arrive tainted");
}

#[test]
fn archiving_moves_the_file_out_of_the_watch_path() {
    // The disposition question: a rename keeps the payload for inspection and stops
    // the watcher re-firing. A delete would lose it; leaving it would loop.
    let scratch = Scratch::new("archive");
    scratch.write("note.txt", "content");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());

    let entry = &poll.ready[0];
    let archived = entry.archive().unwrap();

    assert!(archived.exists(), "the payload must still exist after processing");
    assert_eq!(fs::read_to_string(&archived).unwrap(), "content");
    assert!(
        !scratch.0.join("note.txt").exists(),
        "the file must leave the watched directory"
    );

    // And the watcher does not see it again.
    let after = inbox.poll().unwrap();
    assert!(after.ready.is_empty(), "an archived file must not re-trigger");
}

#[test]
fn archiving_twice_does_not_overwrite_the_first_payload() {
    // Two files named the same is ordinary. Overwriting the first would lose a
    // payload the agent already processed, with no way to recover it.
    let scratch = Scratch::new("collision");
    let mut inbox = Inbox::open(&scratch.0).unwrap();

    scratch.write("report.txt", "first");
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());
    let first = poll.ready[0].archive().unwrap();

    scratch.write("report.txt", "second");
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());
    let second = poll.ready[0].archive().unwrap();

    assert_ne!(first, second, "the second payload gets its own name");
    assert_eq!(fs::read_to_string(&first).unwrap(), "first");
    assert_eq!(fs::read_to_string(&second).unwrap(), "second");
}

#[test]
fn the_processed_directory_is_never_watched() {
    // Otherwise a payload is processed, archived into processed/, and immediately
    // rediscovered: an infinite loop triggered by one file drop.
    let scratch = Scratch::new("processed");
    fs::create_dir_all(scratch.0.join(PROCESSED_DIR)).unwrap();
    fs::write(scratch.0.join(PROCESSED_DIR).join("old.txt"), "old").unwrap();

    let mut inbox = Inbox::open(&scratch.0).unwrap();
    for _ in 0..4 {
        assert!(inbox.poll().unwrap().ready.is_empty());
    }
}

#[test]
fn opening_a_file_instead_of_a_directory_is_refused() {
    let scratch = Scratch::new("notdir");
    let path = scratch.write("note.txt", "x");
    // A watcher that created its own directory would be a watcher willing to watch
    // a path somebody else chose.
    assert!(matches!(
        Inbox::open(&path),
        Err(InboxError::NotADirectory(_))
    ));
}

#[test]
fn an_empty_file_is_eventually_processed() {
    // A genuinely empty file never changes size, so a "size must change" rule
    // would starve it forever. The rule is "unchanged since last poll", and an
    // empty file is unchanged from the first.
    let scratch = Scratch::new("empty");
    scratch.write("empty.txt", "");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());
    assert_eq!(poll.ready.len(), 1);
    assert_eq!(poll.ready[0].event().size, 0);
}

#[test]
fn a_deleted_file_does_not_stall_the_watcher() {
    // The `seen` map is rebuilt each poll, so a file removed between polls must not
    // be remembered forever.
    let scratch = Scratch::new("deleted");
    let path = scratch.write("note.txt", "content");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    inbox.poll().unwrap();
    fs::remove_file(&path).unwrap();

    let poll = inbox.poll().unwrap();
    assert!(poll.ready.is_empty());
    assert!(poll.skipped.is_empty(), "a deleted file is simply gone");
}

#[test]
fn the_entry_never_exposes_the_filename_as_text() {
    // There is no accessor for it. This test cannot assert the name is hidden so
    // much as assert the type has no way to hand it over, which is the stronger
    // property: the compiler refuses the mistake rather than a review catching it.
    let scratch = Scratch::new("no-accessor");
    scratch.write("note.txt", "x");
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = poll_until(&mut inbox, |p| !p.ready.is_empty());

    let debug = format!("{:?}", poll.ready[0]);
    assert!(!debug.contains("note.txt"), "Debug must not print the path");
}

#[test]
fn a_directory_named_like_a_watched_extension_is_ignored() {
    let scratch = Scratch::new("dirtrap");
    fs::create_dir_all(scratch.0.join("decoy.txt")).unwrap();
    let mut inbox = Inbox::open(&scratch.0).unwrap();
    let poll = inbox.poll().unwrap();
    assert!(poll.ready.is_empty(), "a directory is not a payload");
    assert!(poll
        .skipped
        .iter()
        .any(|s| s.reason == SkipReason::NotRegularFile));
}

#[test]
fn polling_a_removed_root_reports_an_error_rather_than_panicking() {
    let scratch = Scratch::new("rootgone");
    let root = scratch.0.join("inbox");
    fs::create_dir_all(&root).unwrap();
    let mut inbox = Inbox::open(&root).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert!(matches!(inbox.poll(), Err(InboxError::Directory(_))));
}