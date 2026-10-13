//! Ambient inbox watching: notice when a file is dropped, without ever reading
//! the file's name as text.
//!
//! # What this is
//!
//! A zero-dependency polling watcher over one directory. When a regular file
//! appears there, it produces an [`InboxEntry`] the daemon can act on. It is the
//! "something happened in the world" half of an agent that does not have to be
//! poked by hand every time.
//!
//! # Why polling, and not inotify
//!
//! inotify needs a `libc` binding, so it is not available under the zero-dependency
//! rule this workspace follows. Beyond that, polling is *more honest* here: inotify
//! reports events for the directory entry, so an editor that saves by
//! write-temp-then-rename produces an event for a name the daemon has never seen
//! resolve, and the classic race is that the watcher reads the name between the
//! create and the rename and gets the wrong file. Polling reads the directory and
//! looks at what is actually there now, so there is no window between "we were
//! told" and "it exists".
//!
//! The cost is real and worth stating: a poll interval bounds latency, and the
//! watcher will not notice a file within that interval. [`Watcher::poll`] takes the
//! interval as a parameter rather than a constant so a caller can choose it rather
//! than discover it.
//!
//! # Why an event carries no filename
//!
//! This crate's whole reason for existing is that the event wire carries only
//! closed-vocabulary data — tags, counts, booleans, and 32-byte digests — because
//! an attacker who controls a web page controls every path the agent touches. See
//! the crate docs.
//!
//! A file dropped in an inbox is under exactly as little control as a web page: it
//! arrives from a mail client, a download, an editor, or whatever else the user
//! pointed at the directory. **A filename is therefore attacker-chosen bytes, and it
//! does not go on the wire.** It goes through [`hash_name`], the same treatment a
//! kernel-observed path gets.
//!
//! This is not only a tidiness rule. A filename interpolated into a task string
//! would reach the Controller's prompt, which is invariant I1 failing at a new
//! seam. The name exists on disk and the daemon needs it to open the file, so it
//! lives in [`InboxEntry`] behind a private field and is reachable only through an
//! accessor that returns [`Quarantined`] text.
//!
//! # Symlinks
//!
//! A symlink dropped in the inbox is a way to make the agent read a file it was
//! never offered — `/etc/shadow` is one `ln -s` away, and the name would look
//! perfectly ordinary. Every entry is therefore checked with `symlink_metadata`,
//! which does *not* follow links, and anything that is not a regular file is
//! ignored. This is the cheapest and most important check in the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use agentos_types::{Quarantined, SourceId};

use crate::event::hash_name;
use crate::event::NameHash;

/// Subdirectory that processed files are moved into.
///
/// The watcher never descends into it, so a processed file cannot be re-discovered
/// and processed again on the next poll.
pub const PROCESSED_DIR: &str = "processed";

/// Extensions the watcher will act on.
///
/// A closed list rather than "everything": a `.swp` file, a partial download, or a
/// lock file left by another program is not an instruction to the agent, and
/// treating it as one means the agent wakes up for noise. An unlisted extension is
/// ignored rather than refused, because the inbox is the user's directory and
/// silently deleting or moving files the watcher does not understand would be
/// worse than ignoring them.
pub const WATCHED_EXTENSIONS: &[&str] = &["txt", "html", "json", "md"];

/// Largest file the watcher will read, in bytes.
///
/// A bound because the daemon reads the payload into memory. An unbounded read
/// turned "someone dropped a large file in a watched directory" into "the daemon
/// allocated until it died", which is a denial of service delivered by a file
/// drop rather than by a credential.
pub const MAX_PAYLOAD_BYTES: u64 = 1 << 20; // 1 MiB

/// Why an inbox file was not acted on.
///
/// Distinct from an error. A refusal is the watcher working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A dotfile. Usually a partial write or an editor's swap file.
    Hidden,
    /// An extension the watcher does not act on.
    ExtensionNotWatched,
    /// Not a regular file. Covers directories, symlinks, sockets, and devices.
    NotRegularFile,
    /// Already being written: the size changed between polls.
    StillBeingWritten,
    /// Larger than [`MAX_PAYLOAD_BYTES`].
    TooLarge,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            SkipReason::Hidden => "hidden file",
            SkipReason::ExtensionNotWatched => "extension is not watched",
            SkipReason::NotRegularFile => "not a regular file",
            SkipReason::StillBeingWritten => "still being written",
            SkipReason::TooLarge => "larger than the payload limit",
        };
        f.write_str(text)
    }
}

/// What the watcher observed, in closed vocabulary.
///
/// Mirrors [`crate::Event`]: no variant carries a name, a path, or any other
/// attacker-chosen bytes. The filename appears only as a [`NameHash`], which has no
/// `Display` and a redacting `Debug`.
///
/// This is the type that belongs in a log, an audit record, or an event bus. It is
/// not what the daemon uses to open the file; that is [`InboxEntry`], which keeps
/// the path private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct InboxEvent {
    /// Hash of the file's name, standing in for the name itself.
    pub name: NameHash,
    /// Size in bytes at the moment it was observed.
    pub size: u64,
    /// Seconds since the Unix epoch of the file's modification time, or 0 if the
    /// platform did not report one.
    pub mtime_unix: u64,
}

impl InboxEvent {
    /// The wire encoding, for an event bus.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&self.name.0);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.mtime_unix.to_be_bytes());
        out
    }

    /// Decode what [`Self::to_bytes`] wrote.
    ///
    /// A length that is not exactly 48 is refused rather than padded or
    /// truncated. A decoder that accepted a short buffer would silently produce a
    /// record with zeroed fields, and a zeroed size is a real file size.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, InboxError> {
        if buf.len() != 48 {
            return Err(InboxError::WireLength { got: buf.len() });
        }
        let mut name = [0u8; 32];
        name.copy_from_slice(&buf[..32]);
        let mut size = [0u8; 8];
        size.copy_from_slice(&buf[32..40]);
        let mut mtime = [0u8; 8];
        mtime.copy_from_slice(&buf[40..48]);
        Ok(InboxEvent {
            name: NameHash(name),
            size: u64::from_be_bytes(size),
            mtime_unix: u64::from_be_bytes(mtime),
        })
    }
}

/// Why inbox watching failed.
///
/// Every variant is a fact about the filesystem rather than about a file's
/// contents, so none of them can be attacker-chosen text.
#[derive(Debug, thiserror::Error)]
pub enum InboxError {
    #[error("cannot read the inbox directory: {0}")]
    Directory(std::io::Error),

    #[error("the inbox path is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("inbox event wire length {got}, expected 48")]
    WireLength { got: usize },

    #[error("cannot read the inbox payload: {0}")]
    Payload(std::io::Error),

    #[error("the inbox payload is {size} bytes, over the {limit} byte limit")]
    PayloadTooLarge { size: u64, limit: u64 },

    #[error("cannot move the processed payload: {0}")]
    Archive(std::io::Error),
}

/// One file the watcher decided to act on.
///
/// # Why the path is private
///
/// The path contains the filename, which is attacker-chosen. Keeping it private
/// means there is no way to reach it by `Debug`, by accident, or by a `format!` in
/// a log line. The two ways out are deliberate:
///
/// - [`Self::event`] gives the closed-vocabulary [`InboxEvent`], safe for a log.
/// - [`Self::read_quarantined`] gives the *contents* as [`Quarantined`], so the text
///   cannot be read without its provenance label travelling with it.
///
/// There is deliberately **no** accessor returning the filename as a `String`. If a
/// caller needs to show a person which file this was, that is a decision to be made
/// at a point where the text is about to reach a human's terminal, not something
/// this type should enable by default.
#[derive(Clone)]
pub struct InboxEntry {
    path: PathBuf,
    event: InboxEvent,
}

impl std::fmt::Debug for InboxEntry {
    /// Shows the path, but not through the private field — and the path is a
    /// *filesystem* path this process already chose, so naming it in a local debug
    /// line is acceptable. What is never shown is the file's *contents*.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxEntry")
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

impl InboxEntry {
    /// The closed-vocabulary observation.
    pub fn event(&self) -> InboxEvent {
        self.event
    }

    /// Read the payload as quarantined text.
    ///
    /// The return type is [`Quarantined`] rather than `String` because the bytes are
    /// from a file the watcher did not choose. Quarantining here means a caller
    /// cannot reach the contents without the label that says where they came from —
    /// which is what stops a payload from reaching a prompt by accident.
    pub fn read_quarantined(&self) -> Result<Quarantined<String>, InboxError> {
        // Re-check the size rather than trusting `observed_size`. A file that grew
        // since the poll is a different file from the one the watcher approved.
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(InboxError::Payload)?
            .len();
        if current > MAX_PAYLOAD_BYTES {
            return Err(InboxError::PayloadTooLarge {
                size: current,
                limit: MAX_PAYLOAD_BYTES,
            });
        }

        let bytes = std::fs::read(&self.path).map_err(InboxError::Payload)?;
        // Truncate rather than refuse if the read came back under the limit but
        // the file was still larger — the alternative is rejecting a payload
        // because of a race the watcher cannot see.
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_PAYLOAD_BYTES as usize)])
            .into_owned();
        Ok(Quarantined::from_source(text, SourceId::new()))
    }

    /// Move the file into `processed/` beside it, so the watcher does not re-fire.
    ///
    /// A rename rather than a delete, for two reasons. The user keeps the payload
    /// and can see what the agent actually saw, which is the difference between
    /// debugging a bad summary and guessing at it. And a delete that fails halfway
    /// loses the only copy of something that may have been the user's only copy of
    /// anything.
    ///
    /// The destination is derived from this file's own parent, so a caller needs no
    /// separate handle on the inbox — which in turn means there is no way to archive
    /// a payload into an arbitrary directory by passing the wrong one.
    pub fn archive(&self) -> Result<PathBuf, InboxError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| InboxError::Archive(std::io::Error::other("path has no parent")))?;
        archive_into(parent, &self.path)
    }
}

/// Move `path` into `root/processed/`, disambiguating a name collision.
fn archive_into(root: &Path, path: &Path) -> Result<PathBuf, InboxError> {
    let processed = root.join(PROCESSED_DIR);
    std::fs::create_dir_all(&processed).map_err(InboxError::Archive)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| InboxError::Archive(std::io::Error::other("path has no file name")))?;

    // A collision means two payloads arrived with the same name, which is
    // ordinary: `report.txt` twice. Rather than overwrite the first — losing a
    // payload the agent already processed — disambiguate with a counter.
    let mut candidate = processed.join(file_name);
    let mut counter = 1u32;
    while candidate.exists() {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("payload");
        let ext = path.extension().and_then(|e| e.to_str());
        let stamped = match ext {
            Some(e) => format!("{stem}.{counter}.{e}"),
            None => format!("{stem}.{counter}"),
        };
        candidate = processed.join(stamped);
        counter += 1;
    }

    std::fs::rename(path, &candidate).map_err(InboxError::Archive)?;
    Ok(candidate)
}

/// One file the watcher looked at and decided not to act on.
#[derive(Debug)]
pub struct Skipped {
    /// Hash of the name, so a log line can say what was skipped without printing
    /// the name.
    pub name: NameHash,
    pub reason: SkipReason,
}

/// A watched inbox directory.
///
/// Owns the path and the "what have I already seen" state. Constructing one
/// requires naming a directory, so a test cannot accidentally watch the real one.
#[derive(Debug)]
pub struct Inbox {
    root: PathBuf,
    /// Last observed `(name hash, size)` per file, used to detect a file that is
    /// still being written.
    ///
    /// Keyed by the *file name*, not the hash: two files whose names hash
    /// identically are a collision this module cannot act on, and keying by hash
    /// would silently merge them. The map holds names internally and only exposes
    /// hashes.
    seen: BTreeMap<PathBuf, u64>,
}

impl Inbox {
    /// Watch `root`, which must already exist.
    ///
    /// Refuses a path that is not a directory rather than creating it. A watcher
    /// that made its own directory would be a watcher that would happily watch a
    /// path an attacker had chosen.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, InboxError> {
        let root = root.into();
        let metadata = std::fs::metadata(&root).map_err(InboxError::Directory)?;
        if !metadata.is_dir() {
            return Err(InboxError::NotADirectory(root));
        }
        Ok(Self {
            root,
            seen: BTreeMap::new(),
        })
    }

    /// The watched directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Look once, and report what is new.
    ///
    /// # The still-being-written rule
    ///
    /// A file is reported only when its size is **unchanged** since the previous
    /// poll. The first sighting records the size and returns nothing, so a file
    /// being written by `cp` is picked up one poll later, once it has settled.
    ///
    /// This costs one poll interval of latency on every file and is worth it: a
    /// half-written file read as a task payload is a truncated instruction, and the
    /// failure would look like the model misunderstanding rather than like a race.
    /// A zero-byte file is reported on its second sighting, since a genuinely empty
    /// file never changes size and would otherwise never be processed.
    pub fn poll(&mut self) -> Result<Poll, InboxError> {
        let mut ready = Vec::new();
        let mut skipped = Vec::new();
        let mut live: BTreeMap<PathBuf, u64> = BTreeMap::new();

        let entries =
            std::fs::read_dir(&self.root).map_err(InboxError::Directory)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                // One unreadable directory entry must not stop the poll. The rest
                // of the inbox is still worth watching.
                Err(_) => continue,
            };

            let path = entry.path();

            // Never descend. `processed/` holds files this watcher already acted
            // on, and re-processing them would loop.
            if path.file_name().and_then(|n| n.to_str()) == Some(PROCESSED_DIR) {
                continue;
            }

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let hash = hash_name(name.as_bytes());

            if name.starts_with('.') {
                skipped.push(Skipped { name: hash, reason: SkipReason::Hidden });
                continue;
            }

            let ext_ok = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| WATCHED_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
            if !ext_ok {
                skipped.push(Skipped {
                    name: hash,
                    reason: SkipReason::ExtensionNotWatched,
                });
                continue;
            }

            // `symlink_metadata` does not follow links. This is the check that
            // stops a symlink to `/etc/shadow` being read as though the user had
            // put `/etc/shadow` in their inbox.
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !metadata.is_file() {
                skipped.push(Skipped {
                    name: hash,
                    reason: SkipReason::NotRegularFile,
                });
                continue;
            }

            let size = metadata.len();
            live.insert(path.clone(), size);

            if size > MAX_PAYLOAD_BYTES {
                skipped.push(Skipped {
                    name: hash,
                    reason: SkipReason::TooLarge,
                });
                continue;
            }

            match self.seen.get(&path) {
                Some(previous) if *previous == size => {
                    // Settled across two polls.
                    let mtime = metadata
                        .modified()
                        .ok()
                        .and_then(system_time_to_unix)
                        .unwrap_or(0);
                    ready.push(InboxEntry {
                        path: path.clone(),
                        event: InboxEvent { name: hash, size, mtime_unix: mtime },
                    });
                }
                _ => {
                    // First sighting, or the size moved. Record and wait.
                    skipped.push(Skipped {
                        name: hash,
                        reason: SkipReason::StillBeingWritten,
                    });
                }
            }
        }

        self.seen = live;
        Ok(Poll { ready, skipped })
    }
}

/// The result of one poll.
#[derive(Debug)]
pub struct Poll {
    /// Files that settled and are ready to act on.
    pub ready: Vec<InboxEntry>,
    /// Files that were looked at and not acted on.
    pub skipped: Vec<Skipped>,
}

/// Seconds since the Unix epoch, saturating rather than wrapping.
///
/// A `SystemTime` before the epoch is nonsense but representable, and `unwrap_or(0)`
/// on a subtraction would panic. Saturating keeps a nonsense mtime as a nonsense
/// number rather than turning it into a plausible-looking one.
fn system_time_to_unix(time: SystemTime) -> Option<u64> {
    let duration = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    Some(duration.as_secs())
}

#[cfg(test)]
mod tests;