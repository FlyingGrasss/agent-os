//! `fs.write`: a filesystem write tool that cannot be talked out of its directory.
//!
//! Two controls guard this tool and they are not the same control.
//!
//! **Policy** (`agentos-policy`) asks where a value came from. A path lifted off
//! a web page is refused before the tool is ever dispatched, because the user
//! did not author it.
//!
//! **Confinement** (this module) asks what the tool may touch. It answers that
//! from a [`WriteGrant`] handed in at construction, never from the arguments. The
//! argument `path` is attacker-influenced text; the grant is agent-authored
//! configuration. If the grant could be named in an argument, an attacker who
//! controlled `path` would control the grant too, and confinement would reduce to
//! "do what the arguments say", which is the tool being written here in the first
//! place.
//!
//! # What containment actually means
//!
//! Three separate ways out of a directory, each defeated separately:
//!
//! 1. **`..` and absolute paths and drive prefixes.** Rejected lexically, by
//!    requiring every component of the requested path to be an ordinary name. No
//!    arithmetic on the string, so there is nothing to get wrong.
//! 2. **A sibling directory sharing a name prefix.** `/tmp/data-evil` is not
//!    inside `/tmp/data`. This is the bug a `starts_with` check has, so the
//!    check here is [`WriteGrant::contains`], which uses component-wise
//!    [`Path::strip_prefix`] and additionally refuses the empty remainder (the
//!    root itself is not a writable file).
//! 3. **Symlinks.** A lexical check says nothing about what a path *resolves* to,
//!    so every component between the grant and the target is examined with
//!    `symlink_metadata`, which does not follow. The write itself is then
//!    arranged so the final component is never followed either: a new file is
//!    created with `O_CREAT|O_EXCL`, and an existing file is replaced by
//!    renaming a fresh temporary over it, which replaces a symlink instead of
//!    writing through it.
//!
//! # What this does not defend against
//!
//! A process that can rename or replace directories *inside* the grant while a
//! write is in flight can still confuse the parent-directory walk, between one
//! `symlink_metadata` and the next. Closing that needs `openat(2)` with
//! `O_NOFOLLOW` on every component, which means an `libc` dependency this crate
//! does not have. The intended deployment is inside `agentos-sandbox`'s Landlock
//! profile, where the grant is also enforced by the kernel against the resolved
//! path; the checks here are the layer that works when the tool runs unconfined,
//! which is how these tests run it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use agentos_dsl::{PlanData, PlanError, PlanValue};
use agentos_types::{Label, Val};
use schemars::JsonSchema;
use serde::Serialize;

use crate::host::Tool;

/// Tool name, which is also the `(tool, argument)` key prefix the policy rules
/// are written against: `fs.write.path` and `fs.write.contents`.
pub const TOOL_NAME: &str = "fs.write";
/// Destination argument, relative to the granted directory.
pub const ARG_PATH: &str = "path";
/// Bytes argument.
pub const ARG_CONTENTS: &str = "contents";

/// The declared argument shape, and the source of the JSON schema the planner
/// is shown.
///
/// Generated rather than hand-written, because a hand-written schema drifts from
/// the struct it describes and the drift shows up as a plan that validates and
/// then gets rejected, or worse, one that is rejected for a field that was never
/// read.
///
/// `deny_unknown_fields` is load-bearing rather than decorative: an argument the
/// schema does not name is an argument no policy rule was ever written for, and
/// [`LabelledArgs::from_call`] refuses it for the same reason.
///
/// Deliberately `Serialize` and not `Deserialize`. These fields carry no
/// provenance label, so there is nothing to restore when decoding one, and a
/// `Deserialize` impl would hand out unlabelled argument values that look like
/// the input to a tool call but are not. The type the tool reads is
/// [`LabelledArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteArgs {
    /// Destination, relative to the granted directory. Traversal, absolute
    /// paths and symlinks are refused, not sanitised.
    pub path: String,
    /// Bytes to write, replacing any existing file.
    pub contents: String,
}

impl WriteArgs {
    /// The JSON schema for this tool's arguments.
    pub fn schema() -> schemars::schema::RootSchema {
        schemars::schema_for!(WriteArgs)
    }
}

/// A parsed call, with every value still carrying its provenance.
///
/// [`WriteArgs`] exists to describe the call to a planner and carries bare
/// `String`s, because a JSON schema has nowhere to put a label. This is the form
/// the tool actually reads: the only way to build one is from a
/// `BTreeMap<String, PlanValue>`, and [`LabelledArgs::from_call`] copies the
/// label off each value it takes. There is no constructor from plain strings, so
/// there is no line where a value arrives here unlabelled.
#[derive(Debug, Clone)]
pub struct LabelledArgs {
    path: Val<String>,
    contents: Val<String>,
}

impl LabelledArgs {
    /// Read and validate a call's arguments.
    ///
    /// Refuses a missing argument, an argument the schema does not declare, and
    /// a value with no text form. The text form deliberately excludes
    /// [`PlanData::Quoted`], for the same reason policy evaluation excludes it:
    /// quarantined text exists to be unreadable by the Controller, and a tool
    /// that accepted it would be a way to read it.
    pub fn from_call(args: &BTreeMap<String, PlanValue>) -> Result<Self, WriteError> {
        for name in args.keys() {
            if name != ARG_PATH && name != ARG_CONTENTS {
                return Err(WriteError::UnexpectedArg(name.clone()));
            }
        }
        Ok(Self {
            path: text_arg(args, ARG_PATH)?,
            contents: text_arg(args, ARG_CONTENTS)?,
        })
    }

    /// The destination, still labeled.
    pub fn path(&self) -> &Val<String> {
        &self.path
    }

    /// The bytes, still labeled.
    pub fn contents(&self) -> &Val<String> {
        &self.contents
    }

    /// The label the result of this call carries.
    ///
    /// The result echoes the destination, so it inherits the destination's
    /// provenance. Reading a trusted `path` and a tainted `contents` must not
    /// produce a trusted record naming a tainted path, so the two labels join
    /// rather than one winning.
    pub fn result_label(&self) -> Label {
        self.path.label().join(self.contents.label())
    }
}

fn text_arg(
    args: &BTreeMap<String, PlanValue>,
    name: &'static str,
) -> Result<Val<String>, WriteError> {
    let value = args.get(name).ok_or(WriteError::MissingArg(name))?;
    let (text, type_name, label) =
        value.with_label_for_display(|data, label| (scalar_text(data), data.type_name(), label.clone()));
    match text {
        Some(t) => Ok(Val::labeled(t, label)),
        None => Err(WriteError::NotText {
            arg: name,
            type_name,
        }),
    }
}

fn scalar_text(data: &PlanData) -> Option<String> {
    match data {
        PlanData::Str(s) | PlanData::Enum(s) => Some(s.clone()),
        PlanData::Int(i) => Some(i.to_string()),
        PlanData::Bool(b) => Some(b.to_string()),
        // `Quoted` is quarantined on purpose and `Unit`/`Record`/`List` have no
        // single text form. Treating either as an empty string would turn a
        // refusal into a write to the wrong place.
        _ => None,
    }
}

/// Why a write did not happen.
///
/// Nothing in here formats the requested path or the contents. The host records
/// a failed tool call by stringifying its error into the audit log, and the
/// audit log is a Controller input: a reason containing attacker-chosen bytes
/// would put those bytes in a prompt with the session's authority behind them.
/// Argument *names* are echoed because the planner writes those, which is the
/// assumption [`crate::audit::OutcomeKind`] already documents.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum WriteError {
    #[error("`fs.write` requires a `{0}` argument")]
    MissingArg(&'static str),
    #[error("`fs.write` takes only `path` and `contents`; `{0}` is not a declared argument")]
    UnexpectedArg(String),
    #[error("`{arg}` is a {type_name}, which has no text form to write")]
    NotText {
        arg: &'static str,
        type_name: &'static str,
    },
    #[error("the write path must be relative to the granted directory")]
    NotRelative,
    #[error("the write path names no file")]
    NoFileNamed,
    #[error("the write path ends in a separator, so it names a directory rather than a file")]
    TrailingSeparator,
    #[error("the write path does not resolve inside the granted directory")]
    OutsideGrant,
    #[error("the write path crosses a symbolic link, which could leave the granted directory")]
    SymlinkInPath,
    #[error("the write path crosses a file that is not a directory")]
    NotADirectory,
    #[error("the write target is a symbolic link; the tool replaces files rather than writing through them")]
    SymlinkTarget,
    #[error("the write target is not a regular file")]
    NotAFile,
    #[error("the filesystem refused the write: {0}")]
    Io(String),
}

impl WriteError {
    fn io(e: std::io::Error) -> WriteError {
        WriteError::Io(e.to_string())
    }
}

/// The write authority this tool holds: one directory it may write inside.
///
/// Held as a value with a private field and a validating constructor, never
/// taken from an argument. Canonicalised once, here, so that every later
/// comparison is against the real on-disk location and not against a spelling
/// that `..` could move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteGrant {
    root: PathBuf,
}

impl WriteGrant {
    /// Take write authority over `root`, which must exist and be a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, WriteError> {
        let root = fs::canonicalize(root.as_ref()).map_err(WriteError::io)?;
        if !root.is_dir() {
            return Err(WriteError::NotADirectory);
        }
        Ok(Self { root })
    }

    /// The granted directory, canonical.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether `candidate` is a file *strictly inside* the granted directory.
    ///
    /// Component-wise, via [`Path::strip_prefix`], which is the whole reason
    /// this is not `candidate.starts_with(self.root)`: string prefixes accept
    /// `/tmp/data-evil/x` for the grant `/tmp/data`, because
    /// `"/tmp/data-evil/x".starts_with("/tmp/data")` is true. `strip_prefix`
    /// compares whole components, so it is not.
    ///
    /// The remainder must also be non-empty. The granted root is a directory, and
    /// a tool that reports "the root itself is a writable file" has stopped
    /// reasoning about the filesystem.
    pub fn contains(&self, candidate: &Path) -> bool {
        match candidate.strip_prefix(self.root.as_path()) {
            Ok(rest) => !rest.as_os_str().is_empty(),
            Err(_) => false,
        }
    }

    /// Write `contents` to `requested`, relative to the granted directory.
    ///
    /// The returned path is relative, so a result handed back to the Controller
    /// does not disclose the host's directory layout.
    pub fn write(&self, requested: &str, contents: &[u8]) -> Result<WriteReceipt, WriteError> {
        let relative = relative_parts(requested)?;
        let target = self.root.join(&relative);
        // Belt and braces. The lexical rules already make this unreachable for
        // any input accepted by `relative_parts`; it is here so that a future
        // change to those rules cannot silently remove the containment check,
        // and so `contains` is on the write path rather than only in tests.
        if !self.contains(&target) {
            return Err(WriteError::OutsideGrant);
        }
        self.check_and_make_parents(&target)?;

        let mut replaced = false;
        match fs::symlink_metadata(&target) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(WriteError::SymlinkTarget);
                }
                if !meta.is_file() {
                    return Err(WriteError::NotAFile);
                }
                self.replace_file(&target, contents)?;
                replaced = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // `create_new` is `O_CREAT | O_EXCL`, so a file that appeared
                // between the check above and this open - including a symlink -
                // makes this fail rather than being written through.
                use std::io::Write as _;
                let mut f = fs::File::create_new(&target).map_err(WriteError::io)?;
                f.write_all(contents).map_err(WriteError::io)?;
                f.sync_all().map_err(WriteError::io)?;
            }
            Err(e) => return Err(WriteError::io(e)),
        }

        Ok(WriteReceipt {
            path: relative,
            bytes_written: contents.len(),
            replaced,
        })
    }

    /// Create the target's parent directories, refusing to walk through a symlink
    /// to get there.
    fn check_and_make_parents(&self, target: &Path) -> Result<(), WriteError> {
        let parent = target.parent().ok_or(WriteError::OutsideGrant)?;
        let relative_parent = parent
            .strip_prefix(self.root.as_path())
            .map_err(|_| WriteError::OutsideGrant)?;

        let mut walk = self.root.clone();
        for component in relative_parent.components() {
            let name = component.as_os_str();
            if name.is_empty() {
                continue;
            }
            walk.push(name);
            match fs::symlink_metadata(&walk) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(WriteError::SymlinkInPath);
                    }
                    if !meta.is_dir() {
                        return Err(WriteError::NotADirectory);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&walk).map_err(WriteError::io)?;
                    // `create_dir` does not follow a final symlink, but it also
                    // fails if something else created the path first, so the
                    // type is confirmed rather than assumed.
                    let meta = fs::symlink_metadata(&walk).map_err(WriteError::io)?;
                    if meta.file_type().is_symlink() {
                        return Err(WriteError::SymlinkInPath);
                    }
                    if !meta.is_dir() {
                        return Err(WriteError::NotADirectory);
                    }
                }
                Err(e) => return Err(WriteError::io(e)),
            }
        }
        Ok(())
    }

    /// Replace an existing file without ever following its final component.
    ///
    /// Writing in place with `O_TRUNC` would follow a symlink that appeared
    /// after the check in `write`. `rename` over the destination does not: it
    /// replaces whatever is at that name. The cost is a fresh inode, so hard
    /// links to the old file are not updated, which is the safe direction.
    fn replace_file(&self, target: &Path, contents: &[u8]) -> Result<(), WriteError> {
        use std::io::Write as _;
        let parent = target.parent().ok_or(WriteError::OutsideGrant)?;
        let staging = parent.join(staging_name());
        // The staging file is created exclusively and then renamed, so a failed
        // write leaves a partial file to clean up rather than a truncated
        // target.
        let write_result = (|| -> Result<(), WriteError> {
            let mut f = fs::File::create_new(&staging).map_err(WriteError::io)?;
            f.write_all(contents).map_err(WriteError::io)?;
            f.sync_all().map_err(WriteError::io)?;
            Ok(())
        })();
        if let Err(e) = write_result {
            let _ = fs::remove_file(&staging);
            return Err(e);
        }
        if let Err(e) = fs::rename(&staging, target) {
            let _ = fs::remove_file(&staging);
            return Err(WriteError::io(e));
        }
        Ok(())
    }
}

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

fn staging_name() -> String {
    // Unpredictability is not a goal here: the name only has to be unique among
    // concurrent writers inside one granted directory. `O_EXCL` does the rest.
    let n = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".agentos-write-{}-{n}.tmp", std::process::id())
}

/// Reduce a requested path to ordinary names, refusing everything else.
///
/// `Component::Normal` is the only accepted component. That single match rejects
/// `..` ([`Component::ParentDir`]), `/etc/passwd` and `C:\Windows`
/// ([`Component::RootDir`] and [`Component::Prefix`]) and a UNC path, without
/// any string arithmetic that could be got wrong. `CurDir` is dropped, so
/// `./notes.txt` and `notes.txt` are the same request.
///
/// This check is what actually prevents traversal. It does not rely on
/// `Path::join` to normalise the result, because that is platform behaviour
/// rather than a guarantee: joining `..` onto a verbatim (`\\?\`) root on Windows
/// silently drops the component, so a `..` would turn into a write *inside* the
/// grant instead of a refusal. Safe direction, wrong semantics, and not something
/// to build on.
fn relative_parts(requested: &str) -> Result<PathBuf, WriteError> {
    if requested.is_empty() {
        return Err(WriteError::NoFileNamed);
    }
    if requested.ends_with('/') || requested.ends_with('\\') {
        return Err(WriteError::TrailingSeparator);
    }
    let mut out = PathBuf::new();
    for component in Path::new(requested).components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(WriteError::NotRelative)
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(WriteError::NoFileNamed);
    }
    Ok(out)
}

/// What a successful write did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReceipt {
    /// Path written, relative to the granted directory.
    pub path: PathBuf,
    pub bytes_written: usize,
    /// Kept as a property rather than assumed, so a caller can tell a create
    /// from an overwrite when auditing.
    pub replaced: bool,
}

/// The `fs.write` tool.
pub struct FsWrite {
    grant: WriteGrant,
}

impl FsWrite {
    /// Build the tool with its write authority already in hand.
    pub fn new(grant: WriteGrant) -> Self {
        Self { grant }
    }

    /// The authority this tool holds. Exposed so a caller can report it to the
    /// user; there is no setter, so it cannot be widened after construction.
    pub fn grant(&self) -> &WriteGrant {
        &self.grant
    }
}

impl Tool for FsWrite {
    fn name(&self) -> &str {
        TOOL_NAME
    }

    fn invoke(&mut self, args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError> {
        let parsed = LabelledArgs::from_call(args).map_err(reject)?;
        // Read through the label-aware accessor even though the bytes are
        // consumed unconditionally: there is no label-free read of a `Val`, so
        // the label stays attached at the point the effect is chosen.
        let requested = parsed.path.with_label_for_display(|p, _| p.clone());
        let bytes = parsed
            .contents
            .with_label_for_display(|s, _| s.as_bytes().to_vec());
        let receipt = self.grant.write(&requested, bytes.as_slice()).map_err(reject)?;

        // Labelled with the union of the input labels: the result names the
        // destination, so a tainted destination makes the result tainted rather
        // than handing the Controller a trusted string it did not author.
        Ok(Val::labeled(
            PlanData::Record(vec![
                (ARG_PATH.to_string(), PlanData::Str(path_text(&receipt.path))),
                (
                    "bytes_written".to_string(),
                    PlanData::Int(receipt.bytes_written as i64),
                ),
            ]),
            parsed.result_label(),
        ))
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn reject(e: WriteError) -> PlanError {
    PlanError::ToolRejected {
        tool: TOOL_NAME.to_string(),
        reason: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_types::{SourceId, SourceKind};
    use std::collections::BTreeSet;

    struct Scratch {
        root: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let base = std::env::temp_dir().join(format!(
                "agentos-fswrite-unit-{tag}-{}-{}",
                std::process::id(),
                unique()
            ));
            fs::create_dir_all(base.join("data")).expect("create grant");
            fs::create_dir_all(base.join("data-evil")).expect("create sibling");
            fs::write(base.join("data-evil").join("target.txt"), b"outside\n").expect("seed outside");
            // Canonicalised for the same reason `WriteGrant::new` canonicalises:
            // the fixture has to speak the same spelling as the grant, or every
            // containment comparison fails for reasons that have nothing to do
            // with containment.
            let root = fs::canonicalize(base).expect("canonicalize scratch");
            Scratch { root }
        }

        fn grant(&self) -> PathBuf {
            self.root.join("data")
        }
        /// A directory whose name starts with the grant's name, and which is
        /// therefore accepted by a string-prefix containment check.
        fn sibling(&self) -> PathBuf {
            self.root.join("data-evil")
        }
        fn outside(&self) -> PathBuf {
            self.sibling().join("target.txt")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn unique() -> u64 {
        UNIQUE.fetch_add(1, Ordering::Relaxed)
    }

    fn grant_of(scratch: &Scratch) -> WriteGrant {
        WriteGrant::new(scratch.grant()).expect("grant")
    }

    fn trusted_str(text: &str) -> PlanValue {
        Val::trusted(PlanData::Str(text.to_string()))
    }

    fn tainted_str(text: &str) -> PlanValue {
        Val::tainted(
            SourceId::of_kind(SourceKind::WebPage),
            PlanData::Str(text.to_string()),
        )
    }

    fn call(pairs: &[(&str, PlanValue)]) -> BTreeMap<String, PlanValue> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    // --- lexical rules ---

    #[test]
    fn traversal_absolute_and_prefix_components_are_all_refused() {
        for bad in [
            "../escape.txt",
            "../../etc/passwd",
            "sub/../../escape.txt",
            "./../escape.txt",
            "/etc/passwd",
            "..",
            "a/../..",
        ] {
            assert_eq!(
                relative_parts(bad),
                Err(WriteError::NotRelative),
                "{bad:?} was not refused as a non-relative path"
            );
        }
        // Drive prefixes and UNC authorities are `Component::Prefix`, which the
        // same match rejects; on a platform without prefixes these are ordinary
        // file names, and asserting otherwise would be asserting something false.
        #[cfg(windows)]
        for bad in [r"C:\Windows\win.ini", r"\\server\share\x", r"C:relative"] {
            assert_eq!(relative_parts(bad), Err(WriteError::NotRelative), "{bad:?}");
        }
        // Empty and separator-terminated are refused too, for different reasons.
        for (bad, why) in [
            ("", WriteError::NoFileNamed),
            (".", WriteError::NoFileNamed),
            ("sub/", WriteError::TrailingSeparator),
            (r"sub\", WriteError::TrailingSeparator),
        ] {
            assert_eq!(relative_parts(bad), Err(why), "{bad:?} was not refused");
        }
    }

    #[test]
    fn ordinary_relative_paths_survive() {
        assert_eq!(relative_parts("a.txt").unwrap(), PathBuf::from("a.txt"));
        assert_eq!(relative_parts("./a.txt").unwrap(), PathBuf::from("a.txt"));
        assert_eq!(
            relative_parts("sub/dir/a.txt").unwrap(),
            PathBuf::from("sub").join("dir").join("a.txt")
        );
    }

    // --- the containment predicate ---

    #[test]
    fn a_sibling_sharing_the_grant_name_prefix_is_not_contained() {
        // This is the assertion a `starts_with` implementation fails. It is
        // written against the predicate directly because the lexical rules
        // refuse every path that could reach the sibling through the tool, so
        // testing only through the tool would prove nothing about `contains`.
        let s = Scratch::new("prefix");
        let grant = grant_of(&s);
        assert!(grant.contains(&s.grant().join("ok.txt")));
        assert!(!grant.contains(&s.sibling().join("x.txt")));
        assert!(
            s.sibling()
                .to_string_lossy()
                .starts_with(s.grant().to_string_lossy().as_ref()),
            "the fixture must actually be a string-prefix trap, or this test proves nothing"
        );
        assert!(!grant.contains(&s.grant()), "the root itself is not a file");
    }

    // --- writing ---

    #[test]
    fn writes_inside_the_grant_and_creates_missing_parents() {
        let s = Scratch::new("inside");
        let grant = grant_of(&s);
        let receipt = grant.write("sub/dir/note.txt", b"hello").expect("write");
        assert_eq!(receipt.path, PathBuf::from("sub/dir/note.txt"));
        assert_eq!(receipt.bytes_written, 5);
        assert_eq!(
            fs::read(s.grant().join("sub/dir/note.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn writing_over_an_existing_file_replaces_it_wholesale() {
        let s = Scratch::new("replace");
        let grant = grant_of(&s);
        fs::write(s.grant().join("note.txt"), b"a much longer original").unwrap();
        grant.write("note.txt", b"new").expect("write");
        assert_eq!(fs::read(s.grant().join("note.txt")).unwrap(), b"new");
        // The staging file must not be left behind.
        let leftovers: Vec<_> = fs::read_dir(s.grant())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "staging file left behind");
    }

    #[test]
    fn traversal_never_creates_a_file_outside_the_grant() {
        let s = Scratch::new("traversal");
        let grant = grant_of(&s);
        for bad in ["../target.txt", "sub/../../target.txt", "a/../target.txt"] {
            assert!(grant.write(bad, b"pwned").is_err(), "{bad} was accepted");
        }
        assert_eq!(fs::read(s.outside()).unwrap(), b"outside\n");
    }

    #[test]
    fn an_absolute_path_is_refused_even_when_it_points_inside_the_grant() {
        // Refused rather than accepted-as-relative, so there is no spelling of
        // "absolute path" that means anything different to this tool.
        let s = Scratch::new("absolute");
        let grant = grant_of(&s);
        let inside_absolute = s.grant().join("note.txt");
        let spelling = inside_absolute.to_string_lossy().into_owned();
        assert!(grant.write(&spelling, b"x").is_err());
        assert!(!inside_absolute.exists());
    }

    #[test]
    fn writing_through_a_file_named_like_a_directory_is_refused() {
        let s = Scratch::new("notdir");
        let grant = grant_of(&s);
        fs::write(s.grant().join("blocker"), b"x").unwrap();
        assert_eq!(
            grant.write("blocker/child.txt", b"x"),
            Err(WriteError::NotADirectory)
        );
    }

    #[test]
    fn a_directory_is_not_a_write_target() {
        let s = Scratch::new("isdir");
        let grant = grant_of(&s);
        fs::create_dir(s.grant().join("adir")).unwrap();
        assert_eq!(grant.write("adir", b"x"), Err(WriteError::NotAFile));
    }

    // --- arguments ---

    #[test]
    fn arguments_are_read_with_their_labels_intact() {
        let args = call(&[("path", tainted_str("notes.txt")), ("contents", trusted_str("hi"))]);
        let parsed = LabelledArgs::from_call(&args).expect("parse");
        assert!(parsed.path().is_tainted(), "the path lost its label");
        assert!(!parsed.contents().is_tainted());
        assert!(
            parsed.result_label().is_tainted(),
            "a result naming a tainted path must itself be tainted"
        );
    }

    #[test]
    fn quarantined_text_is_refused_rather_than_written() {
        let quoted = Val::tainted(
            SourceId::of_kind(SourceKind::WebPage),
            PlanData::quoted("notes.txt".to_string(), SourceId::nil()),
        );
        let args = call(&[(ARG_PATH, quoted), (ARG_CONTENTS, trusted_str("x"))]);
        assert!(matches!(
            LabelledArgs::from_call(&args),
            Err(WriteError::NotText { type_name: "quoted", .. })
        ));
    }

    #[test]
    fn an_undeclared_argument_is_refused() {
        // An argument no policy rule covers is an argument nobody classified.
        let args = call(&[
            (ARG_PATH, trusted_str("a.txt")),
            (ARG_CONTENTS, trusted_str("x")),
            ("root", trusted_str("/")),
        ]);
        assert!(matches!(
            LabelledArgs::from_call(&args),
            Err(WriteError::UnexpectedArg(a)) if a == "root"
        ));
    }

    #[test]
    fn a_missing_argument_is_refused() {
        let args = call(&[(ARG_PATH, trusted_str("a.txt"))]);
        assert!(matches!(
            LabelledArgs::from_call(&args),
            Err(WriteError::MissingArg(ARG_CONTENTS))
        ));
    }

    // --- schema ---

    #[test]
    fn the_schema_is_generated_from_the_argument_struct() {
        let schema = WriteArgs::schema();
        let json = serde_json::to_value(&schema).expect("schema serializes");
        let props = &json["properties"];
        assert_eq!(props[ARG_PATH]["type"], serde_json::json!("string"));
        assert_eq!(props[ARG_CONTENTS]["type"], serde_json::json!("string"));
        let mut required: Vec<&str> = json["required"]
            .as_array()
            .expect("required is a list")
            .iter()
            .map(|v| v.as_str().expect("required entries are strings"))
            .collect();
        required.sort_unstable();
        assert_eq!(required, vec![ARG_CONTENTS, ARG_PATH]);
        assert_eq!(json["additionalProperties"], serde_json::json!(false));
    }

    #[test]
    fn the_serialized_form_agrees_with_the_generated_schema() {
        // A schema that disagrees with the struct it describes is the drift this
        // test exists to catch: the planner would be shown a contract the tool
        // does not honour.
        let schema = serde_json::to_value(WriteArgs::schema()).expect("schema");
        let wire = serde_json::to_value(WriteArgs {
            path: "a.txt".into(),
            contents: "hi".into(),
        })
        .expect("args serialize");
        let declared = schema["properties"]
            .as_object()
            .expect("schema declares properties");
        for (name, value) in wire.as_object().expect("object") {
            let property = declared
                .get(name)
                .unwrap_or_else(|| panic!("{name} is serialized but absent from the schema"));
            assert_eq!(
                property["type"], serde_json::json!("string"),
                "{name} is a different type in the schema than in the struct"
            );
            assert!(
                value.is_string(),
                "{name} is not a string in the struct's own encoding"
            );
        }
        assert_eq!(
            declared.len(),
            wire.as_object().expect("object").len(),
            "the schema declares fields the struct does not have"
        );
    }

    // --- the tool through its own boundary ---

    #[test]
    fn the_tool_writes_and_reports_a_labelled_result() {
        let s = Scratch::new("tool");
        let mut tool = FsWrite::new(grant_of(&s));
        let args = call(&[
            (ARG_PATH, trusted_str("note.txt")),
            (ARG_CONTENTS, trusted_str("hi")),
        ]);
        let result = tool.invoke(&args).expect("write");
        assert!(result.label().is_trusted());
        assert_eq!(fs::read(s.grant().join("note.txt")).unwrap(), b"hi");
    }

    #[test]
    fn a_tainted_path_reaches_the_tool_and_is_still_contained() {
        // Policy normally stops a tainted path before dispatch. This asserts the
        // second layer independently: even if a rule set were changed to allow
        // it, the write still lands only inside the grant.
        let s = Scratch::new("tainted");
        let mut tool = FsWrite::new(grant_of(&s));
        let args = call(&[
            (ARG_PATH, tainted_str("notes.txt")),
            (ARG_CONTENTS, tainted_str("hi")),
        ]);
        let result = tool.invoke(&args).expect("write");
        assert!(result.label().is_tainted());
        assert_eq!(fs::read(s.grant().join("notes.txt")).unwrap(), b"hi");
    }

    #[test]
    fn a_refusal_never_echoes_the_bytes_that_were_refused() {
        // The audit log stringifies tool errors and is a Controller input.
        let s = Scratch::new("quiet");
        let grant = grant_of(&s);
        let payload = "ZQXJ-ATTACKER/../../etc/passwd";
        let err = grant.write(payload, b"").expect_err("refused");
        let rendered = err.to_string();
        assert!(
            !rendered.contains("ZQXJ") && !rendered.contains("passwd"),
            "the refusal leaked the path it refused: {rendered}"
        );
    }

    #[test]
    fn a_refusal_leaves_the_outside_file_untouched() {
        let s = Scratch::new("untouched");
        let grant = grant_of(&s);
        let _ = grant.write("../target.txt", b"pwned");
        assert_eq!(fs::read(s.outside()).unwrap(), b"outside\n");
    }

    #[test]
    fn a_label_with_no_sources_still_reads_as_tainted() {
        // Mirrors the audit log's rule: provenance that could not be classified
        // must not be reported as trusted.
        let val: Val<String> = Val::from_wire("x".into(), BTreeSet::new());
        assert!(val.is_tainted());
    }
}
