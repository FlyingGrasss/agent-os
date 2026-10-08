//! Escape tests for `fs.write`.
//!
//! The pattern is borrowed from `crates/agentos-sandbox/tests/escape.rs`: a
//! feature test that asserts "the grant was applied" proves nothing, so these
//! tests build a real directory tree, aim real writes at it, and then check the
//! filesystem to see whether anything outside the grant changed. The Linux
//! section goes further and re-execs this binary as a **child**, confines that
//! child under Landlock, and has the child attempt escapes so the kernel's own
//! verdict, not the tool's, can be observed.
//!
//! Every escape test carries a positive control in the same test body. Without
//! one, a build in which `WriteGrant::write` returned `Err` unconditionally would
//! pass all of them.
//!
//! Each test builds and removes its own tree. Nothing is shared, so a failure
//! cannot cascade into an unrelated test passing for the wrong reason.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use agentos_dsl::{PlanData, PlanError, PlanValue, ToolHost};
use agentos_policy::PolicyEngine;
use agentos_tools::audit::{AuditLog, MemorySink, SystemClock};
use agentos_tools::{FsWrite, PolicyHost, Tool, WriteGrant, ARG_CONTENTS, ARG_PATH};

/// Bytes seeded in every out-of-grant target, so a refusal that was cosmetic
/// is visible in the file's contents.
const OUTSIDE_CONTENT: &[u8] = b"do-not-touch\n";

// ---------------------------------------------------------------------------
// Scratch tree
// ---------------------------------------------------------------------------

/// ```text
/// <root>/data/            <- the grant
/// <root>/data-evil/       <- shares the grant's name prefix
/// <root>/data-evil/target.txt
/// <root>/escape.txt       <- what `../escape.txt` would hit
/// <root>/data/link        -> ../data-evil/target.txt   (unix only)
/// <root>/data/dirlink     -> ../data-evil              (unix only)
/// ```
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "agentos-fswrite-escape-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(base.join("data")).expect("create grant");
        fs::create_dir_all(base.join("data-evil")).expect("create sibling");
        fs::write(base.join("data").join("keep.txt"), b"inside\n").expect("seed inside");
        fs::write(base.join("data-evil").join("target.txt"), OUTSIDE_CONTENT)
            .expect("seed sibling target");
        fs::write(base.join("escape.txt"), OUTSIDE_CONTENT).expect("seed escape target");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink("../data-evil/target.txt", base.join("data").join("link"))
                .expect("symlink to a file outside");
            symlink("../data-evil", base.join("data").join("dirlink"))
                .expect("symlink to a directory outside");
        }

        // Canonicalised, because `WriteGrant` canonicalises and the containment
        // comparisons below have to speak the same spelling as the grant.
        let root = fs::canonicalize(base).expect("canonicalize scratch");
        Scratch { root }
    }

    fn grant(&self) -> WriteGrant {
        WriteGrant::new(self.grant_dir()).expect("grant over an existing directory")
    }

    fn grant_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    /// The directory a `starts_with` containment check would wrongly accept.
    fn sibling_dir(&self) -> PathBuf {
        self.root.join("data-evil")
    }

    fn sibling_target(&self) -> PathBuf {
        self.sibling_dir().join("target.txt")
    }

    fn escape_target(&self) -> PathBuf {
        self.root.join("escape.txt")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trusted(text: &str) -> PlanValue {
    agentos_types::Val::trusted(PlanData::Str(text.to_string()))
}

fn write_args(path: &str, contents: &str) -> BTreeMap<String, PlanValue> {
    let mut args = BTreeMap::new();
    args.insert(ARG_PATH.to_string(), trusted(path));
    args.insert(ARG_CONTENTS.to_string(), trusted(contents));
    args
}

/// Invoke the tool directly, bypassing policy, so a failure can only come from
/// containment. The policy boundary is covered separately, in `src/tests.rs`.
fn try_write(grant: &WriteGrant, path: &str, contents: &str) -> Result<(), PlanError> {
    FsWrite::new(grant.clone()).invoke(&write_args(path, contents)).map(|_| ())
}

fn host_with(grant: WriteGrant, sink: &MemorySink) -> PolicyHost {
    let mut host = PolicyHost::new(
        PolicyEngine::new(PolicyEngine::default_rules()),
        AuditLog::new(Box::new(sink.clone()), Box::new(SystemClock)),
    );
    host.register(Box::new(FsWrite::new(grant)));
    host
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("reading {} failed: {e}", path.display()))
}

/// Sorted entry names of a directory, so a test can assert that a refused
/// attempt left nothing behind without hard-coding an order.
fn read_dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("listing {} failed: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Tests: the grant, and the positive control every other test relies on
// ---------------------------------------------------------------------------

#[test]
fn writing_inside_the_granted_directory_succeeds() {
    let s = Scratch::new("allowed");
    let grant = s.grant();

    try_write(&grant, "notes/todo.txt", "buy milk\n").expect("write inside the grant");

    assert_eq!(
        read(&s.grant_dir().join("notes").join("todo.txt")),
        b"buy milk\n",
        "the write did not land where it said it did"
    );
    assert_eq!(read(&s.grant_dir().join("keep.txt")), b"inside\n");
}

#[test]
fn overwriting_a_file_inside_the_grant_works() {
    let s = Scratch::new("overwrite");
    let grant = s.grant();
    fs::write(s.grant_dir().join("keep.txt"), b"a much longer original\n").unwrap();
    try_write(&grant, "keep.txt", "new\n").expect("overwrite");
    assert_eq!(read(&s.grant_dir().join("keep.txt")), b"new\n");
}

// ---------------------------------------------------------------------------
// Tests: traversal
// ---------------------------------------------------------------------------

#[test]
fn dotdot_traversal_out_of_the_grant_is_refused() {
    let s = Scratch::new("traversal");
    let grant = s.grant();

    // Positive control first: the very same tool and grant can write.
    try_write(&grant, "control.txt", "control\n").expect("positive control");
    assert_eq!(read(&s.grant_dir().join("control.txt")), b"control\n");

    for attempt in ["../escape.txt", "../../escape.txt", "sub/../../escape.txt"] {
        assert!(
            try_write(&grant, attempt, "pwned\n").is_err(),
            "{attempt} was accepted"
        );
        assert_eq!(
            read(&s.escape_target()),
            OUTSIDE_CONTENT,
            "{attempt} modified a file outside the grant"
        );
        assert_eq!(
            read(&s.sibling_target()),
            OUTSIDE_CONTENT,
            "{attempt} modified the prefix-sharing sibling"
        );
    }
    // Nothing was created inside the grant either: the refusal happens before
    // any parent directory is made, so a refused attempt leaves no trace.
    //
    // Compare against a snapshot rather than a literal list, because on Unix the
    // fixture seeds symlinks into the grant for other tests to attack. A
    // hardcoded expectation had to be platform-conditional and was wrong twice.
    let before = read_dir_names(&s.grant_dir());
    for attempt in ["../fresh1.txt", "sub/../../fresh2.txt"] {
        assert!(try_write(&grant, attempt, "pwned\n").is_err(), "{attempt} accepted");
    }
    assert_eq!(
        read_dir_names(&s.grant_dir()),
        before,
        "a refused attempt left a new entry in the grant"
    );
    assert!(
        !s.grant_dir().join("sub").exists(),
        "a refused traversal still created a directory inside the grant"
    );
}

#[test]
fn an_absolute_path_outside_the_grant_is_refused() {
    let s = Scratch::new("absolute");
    let grant = s.grant();
    try_write(&grant, "control.txt", "control\n").expect("positive control");

    let outside = s.escape_target().to_string_lossy().into_owned();
    assert!(
        try_write(&grant, &outside, "pwned\n").is_err(),
        "an absolute path was accepted"
    );
    assert_eq!(read(&s.escape_target()), OUTSIDE_CONTENT);

    // Even an absolute path that points *inside* the grant is refused, so the
    // tool has one spelling of "destination" rather than two.
    let inside = s.grant_dir().join("absolute.txt").to_string_lossy().into_owned();
    assert!(
        try_write(&grant, &inside, "x").is_err(),
        "an absolute path inside the grant was accepted"
    );
    assert!(!s.grant_dir().join("absolute.txt").exists());
}

// ---------------------------------------------------------------------------
// Tests: the `starts_with` prefix bug
// ---------------------------------------------------------------------------

#[test]
fn a_sibling_directory_sharing_the_grant_prefix_is_not_contained() {
    let s = Scratch::new("prefix");
    let grant = s.grant();

    // The fixture must actually be the trap this test claims to be testing, or
    // a `starts_with` implementation would not fail it.
    assert!(
        s.sibling_dir()
            .to_string_lossy()
            .starts_with(grant.root().to_string_lossy().as_ref()),
        "the sibling does not share the grant's string prefix, so this test \
         proves nothing about the bug it is named for"
    );

    // The containment predicate itself, directly. Asserted on its own because
    // the lexical rules refuse every path that could reach the sibling *through
    // the tool*, so testing only through the tool would leave `contains`
    // unverified.
    assert!(
        grant.contains(&s.grant_dir().join("ok.txt")),
        "a file inside the grant must be recognised as inside"
    );
    assert!(
        !grant.contains(&s.sibling_dir().join("x.txt")),
        "a file in a prefix-sharing sibling was accepted: this is the \
         starts_with bug"
    );
    assert!(
        !grant.contains(&s.escape_target()),
        "a file above the grant was accepted"
    );
    assert!(
        !grant.contains(grant.root()),
        "the granted root is a directory, not a writable file"
    );

    // And through the tool, for completeness: a `..`-prefixed path into the
    // sibling is refused, and the sibling's file is untouched.
    try_write(&grant, "control.txt", "control\n").expect("positive control");
    assert!(
        try_write(&grant, "../data-evil/target.txt", "pwned\n").is_err(),
        "traversal into the prefix-sharing sibling was accepted"
    );
    assert_eq!(read(&s.sibling_target()), OUTSIDE_CONTENT);
}

// ---------------------------------------------------------------------------
// Tests: symlinks
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlink_inside_the_grant_pointing_outside_is_refused_and_its_target_is_untouched() {
    // `symlink_metadata` is the free function in `std::fs`, not a member of
    // `std::os::unix::fs`. It is what does not follow the link, which is the
    // entire reason it is used here rather than `metadata`.
    use std::fs::symlink_metadata;

    let s = Scratch::new("symlink");
    let grant = s.grant();

    // Positive control: the tool works, and a real file next to the symlink is
    // written normally. Without this, "everything is refused" would pass.
    try_write(&grant, "control.txt", "control\n").expect("positive control");
    assert_eq!(read(&s.grant_dir().join("control.txt")), b"control\n");

    // A symlink whose *target* is outside.
    assert!(
        try_write(&grant, "link", "pwned\n").is_err(),
        "writing through a symlink to an outside file was accepted"
    );
    // The point of this assertion. A write that returns an error but has already
    // followed the link is not a refused write.
    assert_eq!(
        read(&s.sibling_target()),
        OUTSIDE_CONTENT,
        "the symlink target outside the grant was modified by a write that \
         reported failure"
    );

    // A symlink whose *parent* is a directory outside the grant.
    assert!(
        try_write(&grant, "dirlink/planted.txt", "pwned\n").is_err(),
        "writing through a symlinked directory was accepted"
    );
    assert!(
        !s.sibling_dir().join("planted.txt").exists(),
        "a file was created outside the grant through a symlinked directory"
    );
    assert_eq!(read(&s.sibling_target()), OUTSIDE_CONTENT);

    // The symlinks themselves are inside the grant, so they are still there: the
    // tool refused the write, it did not clean up after itself.
    assert!(
        symlink_metadata(s.grant_dir().join("link")).is_ok(),
        "the symlink inside the grant was removed"
    );
    assert!(symlink_metadata(s.grant_dir().join("dirlink")).is_ok());

    // Control on the control: the file the symlink points *from* still exists and
    // is still the file the symlink names, so the target assertion above is
    // about the right file.
    assert!(symlink_metadata(s.sibling_target()).is_ok());
}

// ---------------------------------------------------------------------------
// Tests: the tool under the policy host
// ---------------------------------------------------------------------------

#[test]
fn the_host_writes_a_trusted_path_inside_the_grant() {
    let sink = MemorySink::new();
    let s = Scratch::new("host-allowed");
    let mut host = host_with(s.grant(), &sink);
    host.call("fs.write", &write_args("via-host.txt", "ok\n"))
        .expect("trusted write inside the grant");
    assert_eq!(read(&s.grant_dir().join("via-host.txt")), b"ok\n");
}

#[test]
fn the_host_refuses_a_trusted_path_that_escapes_and_the_outside_file_is_untouched() {
    let sink = MemorySink::new();
    let s = Scratch::new("host-escape");
    let mut host = host_with(s.grant(), &sink);

    // Control inside the same host: a legitimate call works, so the refusal
    // below is about the path and not about a host that refuses everything.
    host.call("fs.write", &write_args("control.txt", "control\n"))
        .expect("positive control");
    assert_eq!(read(&s.grant_dir().join("control.txt")), b"control\n");

    let err = host
        .call("fs.write", &write_args("../escape.txt", "pwned\n"))
        .expect_err("the escape must be refused");
    assert!(
        matches!(err, PlanError::ToolRejected { .. }),
        "the refusal must come from the tool's containment, not from policy: {err:?}"
    );
    assert_eq!(
        read(&s.escape_target()),
        OUTSIDE_CONTENT,
        "a file outside the grant was modified"
    );
    assert_eq!(read(&s.sibling_target()), OUTSIDE_CONTENT);
}

// ---------------------------------------------------------------------------
// Landlock: the same tool under kernel confinement, in a child process
// ---------------------------------------------------------------------------
//
// The module is not `#[cfg(target_os = "linux")]` so that the whole thing is
// type-checked on every platform; `agentos-sandbox` exposes `Confine`,
// `detect_kernel_support` and `Abi` everywhere, with `apply` failing closed off
// Linux. The two tests that need a real ruleset skip loudly when the kernel has
// no Landlock, which is the same trade `agentos-sandbox` makes.

mod landlock {
    use super::*;
    use agentos_sandbox::{detect_kernel_support, Abi, Confine};
    use std::io::Write as _;
    use std::process::{Command, Output, Stdio};

    const SCENARIO_ENV: &str = "AGENTOS_FSWRITE_ESCAPE_SCENARIO";
    const ROOT_ENV: &str = "AGENTOS_FSWRITE_ESCAPE_ROOT";
    const PROBE_PREFIX: &str = "##PROBE##";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Probe {
        Allowed,
        Denied(String),
    }

    impl Probe {
        fn of(what: &str, r: std::io::Result<()>) -> Probe {
            match r {
                Ok(()) => Probe::Allowed,
                Err(e) => match e.kind() {
                    // Landlock answers EACCES for filesystem rights and EPERM for
                    // scopes. Anything else - ENOENT from a typo'd path, say -
                    // proves nothing and is reported as such.
                    std::io::ErrorKind::PermissionDenied => {
                        Probe::Denied(format!("{what}: {e}"))
                    }
                    _ => Probe::Denied(format!("{what}: UNEXPECTED {e}")),
                },
            }
        }
        fn render(&self) -> String {
            match self {
                Probe::Allowed => "ALLOWED".to_string(),
                Probe::Denied(d) => format!("DENIED {d}"),
            }
        }
    }

    #[test]
    fn report_kernel_landlock_support() {
        println!(
            "landlock: {}",
            detect_kernel_support()
        );
    }

    /// The single entry point the parent re-execs into. A no-op when the
    /// environment does not name a scenario, so it never disturbs the parent run.
    #[test]
    fn child_entry() {
        let Some(raw) = std::env::var_os(SCENARIO_ENV) else {
            return;
        };
        if raw != "confined-write" {
            println!("{PROBE_PREFIX}\tfatal\tUNKNOWN_SCENARIO");
            std::process::exit(3);
        }
        let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("ROOT_ENV must be set"));
        let grant_dir = root.join("data");

        match Confine::new().read_write(&grant_dir).apply() {
            Ok(enforced) => println!(
                "{PROBE_PREFIX}\tconfine\tENFORCED abi={} fs_rules={} no_new_privs=1",
                enforced.abi(),
                enforced.fs_rules()
            ),
            Err(e) => {
                println!("{PROBE_PREFIX}\tfatal\tCONFINE_FAILED {e}");
                std::process::exit(4);
            }
        }

        // Everything below runs inside the sandbox.
        let grant = WriteGrant::new(&grant_dir).expect("grant");
        let mut tool = FsWrite::new(grant);

        // 1. The tool still does its job under confinement.
        println!(
            "{PROBE_PREFIX}\ttool_write_inside\t{}",
            match tool.invoke(&write_args("confined.txt", "ok\n")) {
                Ok(_) => "ALLOWED".to_string(),
                Err(e) => format!("DENIED {e}"),
            }
        );

        // 2. The tool refuses an escaping path itself.
        println!(
            "{PROBE_PREFIX}\ttool_write_escape\t{}",
            match tool.invoke(&write_args("../escape.txt", "pwned\n")) {
                Ok(_) => "ALLOWED".to_string(),
                Err(_) => "DENIED tool".to_string(),
            }
        );

        // 3. The kernel refuses the same write with the tool entirely out of the
        //    way. This is the layer that would catch a containment bug: it does
        //    not use `FsWrite` on purpose, so it measures Landlock and nothing
        //    else. Without this probe, probe 2 alone would be consistent with
        //    confinement working and with the tool simply refusing everything.
        let raw_write = || -> std::io::Result<()> {
            fs::write(root.join("escape.txt"), b"pwned\n")
        };
        println!(
            "{PROBE_PREFIX}\tkernel_write_outside\t{}",
            Probe::of("raw write outside the grant", raw_write()).render()
        );

        // Control on the control: a raw write inside the grant is allowed, so
        // probe 3's denial is about the path and not about a dead filesystem.
        let raw_inside = || -> std::io::Result<()> { fs::write(grant_dir.join("raw.txt"), b"ok\n") };
        println!(
            "{PROBE_PREFIX}\tkernel_write_inside\t{}",
            Probe::of("raw write inside the grant", raw_inside()).render()
        );

        let _ = std::io::stdout().flush();
        // The child must not delete the tree the parent is about to inspect.
        std::mem::forget(Scratch { root });
    }

    #[derive(Debug, Default)]
    struct Report {
        outcomes: BTreeMap<String, String>,
        confine: Option<String>,
        fatal: Option<String>,
    }

    impl Report {
        fn parse(output: &Output) -> Report {
            let mut r = Report::default();
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // libtest prints its own progress on the same line as the child's
                // first probe output, so the marker is searched for.
                let Some(idx) = line.find(PROBE_PREFIX) else {
                    continue;
                };
                let mut fields = line[idx..].split('\t');
                let _ = fields.next();
                let Some(name) = fields.next() else { continue };
                let Some(detail) = fields.next() else { continue };
                match name {
                    "confine" => r.confine = Some(detail.to_string()),
                    "fatal" => r.fatal = Some(detail.to_string()),
                    other => {
                        r.outcomes
                            .insert(other.to_string(), detail.trim().to_string());
                    }
                }
            }
            r
        }

        fn require_confinement(&self, output: &Output) {
            if let Some(fatal) = &self.fatal {
                panic!(
                    "the child could not be confined: {fatal}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let confine = self
                .confine
                .clone()
                .unwrap_or_else(|| panic!("the child never reported confinement status"));
            assert!(
                confine.starts_with("ENFORCED"),
                "the child was not fully enforced: {confine}"
            );
        }

        fn allowed(&self, name: &str) {
            assert_eq!(
                self.outcomes.get(name).map(String::as_str),
                Some("ALLOWED"),
                "probe `{name}` should have succeeded, got {:?}",
                self.outcomes.get(name)
            );
        }

        fn denied(&self, name: &str) {
            let got = self
                .outcomes
                .get(name)
                .unwrap_or_else(|| panic!("probe `{name}` was never reported"));
            assert!(
                got.starts_with("DENIED"),
                "probe `{name}` should have been denied, got {got}"
            );
        }
    }

    fn run_confined(scratch: &Scratch) -> (Report, Output) {
        let exe = std::env::current_exe().expect("current_exe");
        let output = Command::new(exe)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            // Fully qualified, because the child test lives in a module. A bare
            // name filters to nothing, the harness reports zero tests and exits
            // 0, and the parent sees an empty report rather than a failure.
            .arg("landlock::child_entry")
            .env(SCENARIO_ENV, "confined-write")
            .env(ROOT_ENV, &scratch.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run the confined child");
        (Report::parse(&output), output)
    }

    /// Loud when Landlock is missing, for the same reason
    /// `agentos-sandbox`'s escape tests are loud: on the WSL2 host this targets
    /// Landlock is present, so a silent skip here means the confinement claims
    /// have stopped being verified by anything.
    /// The Landlock ABI this host can enforce, or `None` if it cannot.
    ///
    /// Returning `None` rather than a fake high ABI matters: a previous version
    /// substituted `Abi::V7` on an unsupported host, so the child tried to
    /// confine itself, could not, and the test failed for the wrong reason.
    /// Callers must skip explicitly on `None`.
    fn require_landlock() -> Option<Abi> {
        let support = detect_kernel_support();
        match support.abi() {
            Some(abi) => Some(abi),
            None => {
                eprintln!(
                    "SKIPPING the confined fs.write test: {support}. Landlock cannot be \
                     verified here, so this test is not evidence of anything."
                );
                None
            }
        }
    }

    /// Whether a ruleset can actually be installed on this platform at all.
    ///
    /// `agentos-sandbox` refuses off Linux, and `detect` reports no ABI there,
    /// so the two agree; the check exists so the skip is explicit rather than
    /// inferred from an ABI comparison that happens to also be false.
    fn landlock_enforceable() -> bool {
        cfg!(target_os = "linux") && detect_kernel_support().is_available()
    }

    #[test]
    fn a_confined_tool_writes_inside_its_grant_and_the_kernel_refuses_outside_it() {
        let Some(abi) = require_landlock() else { return };
        if !landlock_enforceable() {
            return;
        }
        if abi < Abi::V5 {
            eprintln!("SKIP: kernel ABI {abi} < V5; every profile is refused by design");
            return;
        }
        let scratch = Scratch::new("confined");
        let (report, output) = run_confined(&scratch);
        report.require_confinement(&output);

        // The tool under confinement: the legitimate write works.
        report.allowed("tool_write_inside");
        // The tool under confinement: the escaping path is refused.
        report.denied("tool_write_escape");

        // The kernel under confinement, measured without the tool in the way.
        report.allowed("kernel_write_inside");
        report.denied("kernel_write_outside");

        // And nothing outside the grant moved, checked by a parent that was
        // never confined.
        assert_eq!(
            read(&scratch.escape_target()),
            OUTSIDE_CONTENT,
            "the file outside the grant was modified by the confined child"
        );
        assert_eq!(read(&scratch.sibling_target()), OUTSIDE_CONTENT);
        assert_eq!(
            read(&scratch.grant_dir().join("confined.txt")),
            b"ok\n",
            "the confined write did not land inside the grant"
        );
    }

    #[test]
    fn the_parent_of_a_confined_child_is_not_confined() {
        let Some(abi) = require_landlock() else { return };
        if abi < Abi::V5 {
            eprintln!("SKIP: kernel ABI {abi} < V5");
            return;
        }
        let scratch = Scratch::new("leak");
        let (report, output) = run_confined(&scratch);
        report.require_confinement(&output);

        // Exactly the operations the child was refused.
        read(&scratch.escape_target());
        read(&scratch.sibling_target());
        fs::read_dir(scratch.sibling_dir()).expect("parent must still list the sibling");
        fs::write(scratch.escape_target(), b"parent was here\n").expect("parent may still write");
        assert_eq!(read(&scratch.escape_target()), b"parent was here\n");
    }
}
