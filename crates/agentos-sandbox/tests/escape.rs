//! Escape tests.
//!
//! A test that asserts "the ruleset was applied" proves almost nothing: a
//! sandbox that grants `/` is applied and useless. These tests instead re-exec
//! this test binary as a **child**, confine that child, and then have the child
//! attempt real escapes and report what the kernel did.
//!
//! Every `assert_allowed` / `assert_denied` below corresponds to a probe the
//! child actually performed against the running kernel, and the child refuses
//! to report a probe it did not run.
//!
//! Running the payload in a child rather than in a `#[test]` thread is
//! deliberate: `landlock_restrict_self` is irreversible and thread-local, so
//! confining a test thread would poison the harness, and the parent needs to
//! stay unconfined so it can create and delete the scratch tree.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use agentos_sandbox::{detect_kernel_support, Abi, Confine, ConfineError};

const SCENARIO_ENV: &str = "AGENTOS_SANDBOX_ESCAPE_SCENARIO";
const ROOT_ENV: &str = "AGENTOS_SANDBOX_ESCAPE_ROOT";
const PORT_ENV: &str = "AGENTOS_SANDBOX_ESCAPE_PORT";
const PARENT_PID_ENV: &str = "AGENTOS_SANDBOX_ESCAPE_PARENT_PID";
const PROBE_PREFIX: &str = "##PROBE##";

// ---------------------------------------------------------------------------
// Scratch tree
// ---------------------------------------------------------------------------

/// Layout of the tree the parent builds before spawning the child.
///
/// ```text
/// <root>/ro/visible.txt        <- granted ReadOnly
/// <root>/ro/existing.txt       <- granted ReadOnly, used for write-denial probes
/// <root>/ro/rename-src.txt     <- granted ReadOnly
/// <root>/ro/link-abs  -> /etc/passwd
/// <root>/ro/link-rel  -> ../../..(etc/passwd)   (depth-correct relative escape)
/// <root>/ro/link-self -> visible.txt
/// <root>/rw/scratch.txt        <- granted ReadWrite in some scenarios
/// <root>/rw/rename-src.txt
/// <root>/secrets.txt           <- inside <root>, granted to nobody
/// ```
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!(
            "agentos-escape-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let s = Scratch { root };
        fs::create_dir_all(s.ro()).unwrap();
        fs::create_dir_all(s.rw()).unwrap();
        fs::write(s.ro().join("visible.txt"), b"visible payload\n").unwrap();
        fs::write(s.ro().join("existing.txt"), b"must not be clobbered\n").unwrap();
        fs::write(s.ro().join("rename-src.txt"), b"rename me\n").unwrap();
        fs::write(s.rw().join("scratch.txt"), b"scratch\n").unwrap();
        fs::write(s.rw().join("rename-src.txt"), b"rename me\n").unwrap();
        fs::write(s.root.join("secrets.txt"), b"top secret\n").unwrap();

        symlink("/etc/passwd", s.ro().join("link-abs")).unwrap();
        // Relative escape: walk from <root>/ro back to "/" then into /etc.
        let up = "../".repeat(s.root.components().count());
        symlink(format!("{up}etc/passwd"), s.ro().join("link-rel")).unwrap();
        symlink("visible.txt", s.ro().join("link-self")).unwrap();
        s
    }

    fn root(&self) -> PathBuf {
        self.root.clone()
    }
    fn ro(&self) -> PathBuf {
        self.root.join("ro")
    }
    fn rw(&self) -> PathBuf {
        self.root.join("rw")
    }
    fn secrets(&self) -> PathBuf {
        self.root.join("secrets.txt")
    }
    /// `../` repeated just enough to climb from `<root>/ro` back to `/`.
    fn up_from_ro(&self) -> String {
        "../".repeat(self.root.components().count())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The parent is never confined, so this always works.
        let _ = fs::remove_dir_all(&self.root);
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// ReadOnly on `<root>/ro` only.
    ReadOnlyTree,
    /// ReadWrite on `<root>/rw` and ReadOnly on `<root>/ro`.
    ReadWriteTree,
    /// ReadOnly on `<root>/ro`, which contains symlinks pointing outside it.
    SymlinkEscape,
    /// ReadOnly on `<root>/ro`, probed via `..` and absolute paths.
    TraversalEscape,
    /// No filesystem grant at all.
    NoFilesystem,
    /// Default TCP handling: no port granted.
    TcpDenied,
    /// One TCP port granted for connect.
    TcpConnectAllowed,
    /// Default scopes: Signal and AbstractUnixSocket.
    Scopes,
}

impl Scenario {
    fn as_str(self) -> &'static str {
        match self {
            Scenario::ReadOnlyTree => "read-only-tree",
            Scenario::ReadWriteTree => "read-write-tree",
            Scenario::SymlinkEscape => "symlink-escape",
            Scenario::TraversalEscape => "traversal-escape",
            Scenario::NoFilesystem => "no-filesystem",
            Scenario::TcpDenied => "tcp-denied",
            Scenario::TcpConnectAllowed => "tcp-connect-allowed",
            Scenario::Scopes => "scopes",
        }
    }

    fn parse(s: &str) -> Option<Scenario> {
        Some(match s {
            "read-only-tree" => Scenario::ReadOnlyTree,
            "read-write-tree" => Scenario::ReadWriteTree,
            "symlink-escape" => Scenario::SymlinkEscape,
            "traversal-escape" => Scenario::TraversalEscape,
            "no-filesystem" => Scenario::NoFilesystem,
            "tcp-denied" => Scenario::TcpDenied,
            "tcp-connect-allowed" => Scenario::TcpConnectAllowed,
            "scopes" => Scenario::Scopes,
            _ => return None,
        })
    }

    /// The exact profile under test. Nothing is granted implicitly.
    fn confine(self, scratch: &Scratch, port: u16) -> Confine {
        let c = Confine::new();
        match self {
            Scenario::ReadOnlyTree | Scenario::SymlinkEscape | Scenario::TraversalEscape => {
                c.read_only(scratch.ro())
            }
            Scenario::ReadWriteTree => c
                .read_only(scratch.ro())
                .read_write(scratch.rw()),
            // Nothing at all: the deny-by-default filesystem.
            Scenario::NoFilesystem => c,
            Scenario::TcpDenied => c.read_only(scratch.ro()),
            Scenario::TcpConnectAllowed => {
                c.read_only(scratch.ro()).allow_tcp_connect(port)
            }
            Scenario::Scopes => c.read_only(scratch.ro()),
        }
    }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// What the kernel did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// The operation succeeded. For an escape probe that is a failure.
    Allowed,
    /// The kernel refused with a policy errno (EACCES / EPERM).
    Denied { errno: i32 },
    /// Some other failure. Never treated as a denial: a test that wanted a
    /// denial and got ENOENT has not proved anything.
    Failed { errno: i32, what: String },
}

impl Outcome {
    fn of<T>(what: &str, r: std::io::Result<T>) -> Outcome {
        match r {
            Ok(_) => Outcome::Allowed,
            Err(e) => match e.raw_os_error() {
                Some(errno) if errno == libc::EACCES || errno == libc::EPERM => {
                    Outcome::Denied { errno }
                }
                errno => Outcome::Failed {
                    errno: errno.unwrap_or(-1),
                    what: format!("{what}: {e}"),
                },
            },
        }
    }

    fn render(&self) -> String {
        match self {
            Outcome::Allowed => "ALLOWED".to_string(),
            Outcome::Denied { errno } => format!("DENIED errno={errno}"),
            Outcome::Failed { errno, what } => format!("FAILED errno={errno} {what}"),
        }
    }

    fn parse(s: &str) -> Outcome {
        if s == "ALLOWED" {
            return Outcome::Allowed;
        }
        if let Some(rest) = s.strip_prefix("DENIED errno=") {
            return Outcome::Denied {
                errno: rest.parse().unwrap_or(-1),
            };
        }
        let errno = s
            .strip_prefix("FAILED errno=")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(-1);
        Outcome::Failed {
            errno,
            what: s.to_string(),
        }
    }
}

fn read_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_existing(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(data)
}

fn write_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(data)
}

/// `socket(2)` alone. Landlock does **not** gate this; the probe exists to pin
/// that fact down rather than let someone assume it is covered.
fn raw_socket() -> std::io::Result<i32> {
    // SAFETY: plain socket(2) with no pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just returned by socket(2) and is owned here.
        unsafe { libc::close(fd) };
        Ok(fd)
    }
}

fn connect_tcp(port: u16) -> std::io::Result<TcpStream> {
    TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn bind_tcp(port: u16) -> std::io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn bind_udp(port: u16) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn kill(pid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: kill(2) with no pointers. Signal 0 performs an existence check and
    // has no side effect, which keeps the "signal myself" probe harmless.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn no_new_privs() -> i32 {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no arguments and writes nothing.
    unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }
}

/// Standalone kernel probe so a failing test can say what the kernel actually
/// reports instead of guessing. Run with `cargo test -p agentos-sandbox -- --nocapture`.
#[test]
fn report_kernel_landlock_support() {
    let support = detect_kernel_support();
    let floor = Confine::new().required_abi();
    println!(
        "landlock: {support}; minimum ABI any AgentOS profile needs: {floor}"
    );
    assert_eq!(
        support.is_available(),
        support.abi().map(|a| a >= floor).unwrap_or(false),
        "probe and ABI floor disagree: {support}"
    );
}

// ---------------------------------------------------------------------------
// Child
// ---------------------------------------------------------------------------

/// The single entry point the parent re-execs into.
///
/// When run as part of the ordinary suite (no scenario in the environment) this
/// is a no-op, so it never disturbs the other tests.
#[test]
fn child_entry() {
    let Some(raw) = std::env::var_os(SCENARIO_ENV) else {
        return;
    };
    let scenario = Scenario::parse(&raw.to_string_lossy()).unwrap_or_else(|| {
        emit_raw("fatal", "UNKNOWN_SCENARIO");
        std::process::exit(3);
    });
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("ROOT_ENV must be set"));
    let port: u16 = std::env::var(PORT_ENV)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let parent_pid: i32 = std::env::var(PARENT_PID_ENV)
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);

    // Rebuild the view of the tree from `root` alone; the child must not depend
    // on anything the parent held open.
    let scratch = Scratch {
        root: root.clone(),
    };

// The only way past this point is a ruleset the kernel confirmed as fully
    // enforced. Everything below is therefore operating inside the sandbox.
    match scenario.confine(&scratch, port).apply() {
        Ok(enforced) => {
            emit_raw(
                "confine",
                &format!(
                    "ENFORCED abi={} fs_rules={} net_rules={} no_new_privs={}",
                    enforced.abi(),
                    enforced.fs_rules(),
                    enforced.net_rules(),
                    no_new_privs()
                ),
            );
        }
        Err(ConfineError::AbiTooOld {
            kernel,
            required,
            features,
        }) => {
            emit_raw(
                "fatal",
                &format!(
                    "ABI_TOO_OLD kernel={kernel} required={required} missing={features:?}"
                ),
            );
            std::process::exit(4);
        }
        Err(e) => {
            emit_raw("fatal", &format!("CONFINE_FAILED {e}"));
            std::process::exit(4);
        }
    };
    

    let mut probes: Vec<(&'static str, Outcome)> = Vec::new();
    let ro = scratch.ro();
    let rw = scratch.rw();

    match scenario {
        Scenario::ReadOnlyTree => {
            probes.push((
                "read_granted_file",
                Outcome::of("read", read_file(&ro.join("visible.txt"))),
            ));
            probes.push((
                "list_granted_dir",
                Outcome::of("read_dir", fs::read_dir(&ro)),
            ));
            probes.push((
                "read_etc_passwd",
                Outcome::of("read", read_file(Path::new("/etc/passwd"))),
            ));
            probes.push((
                "read_etc_shadow",
                Outcome::of("read", read_file(Path::new("/etc/shadow"))),
            ));
            probes.push((
                "read_proc_self_maps",
                Outcome::of("read", read_file(Path::new("/proc/self/maps"))),
            ));
            probes.push((
                "read_proc_self_mem",
                Outcome::of("read", read_file(Path::new("/proc/self/mem"))),
            ));
            probes.push((
                "read_proc_self_environ",
                Outcome::of("read", read_file(Path::new("/proc/self/environ"))),
            ));
            probes.push((
                "read_ungranted_sibling",
                Outcome::of("read", read_file(&scratch.secrets())),
            ));
            // Even though it sits right next to the granted tree, writing to the
            // read-only grant must fail.
            probes.push((
                "write_granted_ro_file",
                Outcome::of(
                    "write",
                    write_existing(&ro.join("existing.txt"), b"clobbered\n"),
                ),
            ));
            probes.push((
                "create_in_granted_ro_dir",
                Outcome::of("create", write_new(&ro.join("brand-new"), b"x")),
            ));
            probes.push((
                "unlink_in_granted_ro_dir",
                Outcome::of("unlink", fs::remove_file(ro.join("existing.txt"))),
            ));
            // The child verified the content it was allowed to read, not just
            // that the open() returned 0.
            probes.push((
                "granted_content_is_intact",
                Outcome::of(
                    "content",
                    match read_file(&ro.join("existing.txt")) {
                        Ok(b) if b == b"must not be clobbered\n" => Ok(()),
                        Ok(_) => Err(std::io::Error::other(
                            "granted read-only file was modified",
                        )),
                        Err(e) => Err(e),
                    },
                ),
            ));
        }
        Scenario::ReadWriteTree => {
            probes.push((
                "write_existing_in_rw",
                Outcome::of("write", write_existing(&rw.join("scratch.txt"), b"written\n")),
            ));
            probes.push((
                "create_new_in_rw",
                Outcome::of("create", write_new(&rw.join("fresh"), b"fresh\n")),
            ));
            probes.push((
                "truncate_in_rw",
                Outcome::of(
                    "truncate",
                    write_existing(&rw.join("scratch.txt"), b""),
                ),
            ));
            probes.push((
                "make_dir_in_rw",
                Outcome::of("mkdir", fs::create_dir(rw.join("sub"))),
            ));
            probes.push((
                "rename_within_rw",
                Outcome::of(
                    "rename",
                    fs::rename(rw.join("rename-src.txt"), rw.join("renamed.txt")),
                ),
            ));
            probes.push((
                "unlink_in_rw",
                Outcome::of("unlink", fs::remove_file(rw.join("renamed.txt"))),
            ));
            probes.push((
                "write_existing_in_ro",
                Outcome::of("write", write_existing(&ro.join("existing.txt"), b"clobbered\n")),
            ));
            probes.push((
                "create_new_in_ro",
                Outcome::of("create", write_new(&ro.join("brand-new"), b"x")),
            ));
            probes.push((
                "truncate_in_ro",
                Outcome::of("truncate", write_existing(&ro.join("existing.txt"), b"")),
            ));
            probes.push((
                "make_dir_in_ro",
                Outcome::of("mkdir", fs::create_dir(ro.join("sub"))),
            ));
            probes.push((
                "unlink_in_ro",
                Outcome::of("unlink", fs::remove_file(ro.join("existing.txt"))),
            ));
            // REFER is a distinct right: renaming *out* of the granted tree must
            // fail even though both endpoints are readable.
            probes.push((
                "rename_out_of_rw_into_ro",
                Outcome::of(
                    "rename",
                    fs::rename(rw.join("scratch.txt"), ro.join("stolen.txt")),
                ),
            ));
            probes.push((
                "read_file_ro_still_intact",
                Outcome::of(
                    "content",
                    match read_file(&ro.join("existing.txt")) {
                        Ok(b) if b == b"must not be clobbered\n" => Ok(()),
                        Ok(_) => Err(std::io::Error::other(
                            "read-only file was modified through the rw grant",
                        )),
                        Err(e) => Err(e),
                    },
                ),
            ));
        }
        Scenario::SymlinkEscape => {
            probes.push((
                "read_symlink_absolute_out",
                Outcome::of("read", read_file(&ro.join("link-abs"))),
            ));
            probes.push((
                "read_symlink_relative_out",
                Outcome::of("read", read_file(&ro.join("link-rel"))),
            ));
            probes.push((
                "write_through_symlink_out",
                Outcome::of("write", write_existing(&ro.join("link-abs"), b"pwned\n")),
            ));
            probes.push((
                "unlink_symlink_out",
                Outcome::of("unlink", fs::remove_file(ro.join("link-abs"))),
            ));
            // A symlink that stays inside the grant must still work, otherwise
            // the two results above would prove nothing.
            probes.push((
                "read_symlink_inside_grant",
                Outcome::of("read", read_file(&ro.join("link-self"))),
            ));
            probes.push((
                "read_etc_passwd_directly",
                Outcome::of("read", read_file(Path::new("/etc/passwd"))),
            ));
        }
        Scenario::TraversalEscape => {
            let up = scratch.up_from_ro();
            probes.push((
                "read_dotdot_escape",
                Outcome::of(
                    "read",
                    read_file(&PathBuf::from(format!("{}/{}etc/passwd", ro.display(), up))),
                ),
            ));
            probes.push((
                "read_absolute_outside_grant",
                Outcome::of("read", read_file(Path::new("/etc/passwd"))),
            ));
            probes.push((
                "read_dotdot_escape_root_etc",
                Outcome::of("read", read_file(Path::new("/etc"))),
            ));
            probes.push((
                "read_dotdot_escape_sibling_file",
                Outcome::of("read", read_file(&scratch.secrets())),
            ));
            probes.push((
                "create_through_dotdot",
                Outcome::of(
                    "create",
                    write_new(
                        &PathBuf::from(format!("{}/{}etc/agentos-pwned", ro.display(), up)),
                        b"x",
                    ),
                ),
            ));
            probes.push((
                "read_root_dir_listing",
                Outcome::of("read_dir", fs::read_dir(Path::new("/"))),
            ));
            probes.push((
                "read_granted_file_still_works",
                Outcome::of("read", read_file(&ro.join("visible.txt"))),
            ));
        }
        Scenario::NoFilesystem => {
            probes.push((
                "read_granted_path_but_not_granted",
                Outcome::of("read", read_file(&ro.join("visible.txt"))),
            ));
            probes.push((
                "read_etc_passwd",
                Outcome::of("read", read_file(Path::new("/etc/passwd"))),
            ));
            probes.push((
                "list_working_directory",
                Outcome::of("read_dir", fs::read_dir(".")),
            ));
            probes.push((
                "read_proc_self_exe",
                Outcome::of("read", read_file(Path::new("/proc/self/exe"))),
            ));
            probes.push((
                "read_proc_self_maps",
                Outcome::of("read", read_file(Path::new("/proc/self/maps"))),
            ));
            probes.push((
                "stat_tmp_is_not_gated",
                Outcome::of("stat", fs::metadata(Path::new("/tmp"))),
            ));
        }
        Scenario::TcpDenied => {
            probes.push(("tcp_connect_denied", Outcome::of("connect", connect_tcp(port))));
            probes.push(("tcp_bind_denied", Outcome::of("bind", bind_tcp(0))));
            // The gap Landlock does not close: socket(2) still works.
            probes.push(("socket_creation_is_not_gated", Outcome::of("socket", raw_socket())));
            // ...and neither is UDP.
            probes.push((
                "udp_bind_is_not_gated",
                Outcome::of("udp_bind", bind_udp(0)),
            ));
        }
        Scenario::TcpConnectAllowed => {
            probes.push(("tcp_connect_allowed", Outcome::of("connect", connect_tcp(port))));
            // Prove bind and connect are separately gated: allowing one port for
            // connect must not silently allow binding anything.
            probes.push(("tcp_bind_still_denied", Outcome::of("bind", bind_tcp(0))));
        }
        Scenario::Scopes => {
            probes.push((
                "signal_parent_denied",
                Outcome::of("kill", kill(parent_pid, 0)),
            ));
            probes.push((
                "signal_self_allowed",
                Outcome::of("kill", kill(std::process::id() as i32, 0)),
            ));
        }
    }

    for (name, outcome) in probes {
        emit(name, &outcome);
    }
    // Flush explicitly: stdout may be a pipe and we are about to be confined to
    // whatever we can already write.
    let _ = std::io::stdout().flush();
    // The child must not delete the tree the parent is about to inspect.
    std::mem::forget(scratch);
}

fn emit_raw(name: &str, detail: &str) {
    println!("{PROBE_PREFIX}\t{name}\t{detail}");
}
fn emit(name: &str, outcome: &Outcome) {
    println!("{PROBE_PREFIX}\t{name}\t{}", outcome.render());
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

/// Everything the child told us.
#[derive(Debug, Default)]
struct Report {
    outcomes: BTreeMap<String, Outcome>,
    confine: Option<String>,
    fatal: Option<String>,
}

impl Report {
    fn parse(output: &Output) -> Report {
        let mut r = Report::default();
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // libtest prints its own progress on the same line as the child's
            // first output ("test child_entry ... ##PROBE##..."), even with
            // --nocapture, so the marker is searched for rather than stripped
            // from the start of the line.
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
                _ => {
                    r.outcomes
                        .insert(name.to_string(), Outcome::parse(detail.trim()));
                }
            }
        }
        r
    }

    /// Panics with the child's own output if confinement did not happen: every
    /// probe after this point would be meaningless.
    fn require_confinement(&self, scenario: Scenario, output: &Output) {
        if let Some(fatal) = &self.fatal {
            panic!(
                "scenario {} could not be confined: {fatal}\n--- child stdout ---\n{}\n--- child stderr ---\n{}",
                scenario.as_str(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        let confine = self
            .confine
            .as_ref()
            .unwrap_or_else(|| panic!("child never reported confinement status"));
        assert!(
            confine.starts_with("ENFORCED"),
            "scenario {} was not fully enforced: {confine}",
            scenario.as_str()
        );
        assert!(
            confine.contains("no_new_privs=1"),
            "PR_SET_NO_NEW_PRIVS was not confirmed in the child: {confine}"
        );
    }

    fn allowed(&self, name: &str) {
        assert_eq!(
            self.outcomes.get(name).map(Outcome::render),
            Some("ALLOWED".to_string()),
            "probe `{name}` should have succeeded",
        );
    }

    /// The probe must have been refused by the kernel with a policy errno.
    ///
    /// Landlock returns `EACCES` for filesystem and TCP denials and `EPERM` for
    /// scope denials, so both count. Any other errno means the operation failed
    /// for an unrelated reason (a typo'd path giving `ENOENT`, say), which proves
    /// nothing about confinement and is treated as a test failure.
    fn denied(&self, name: &str) {
        match self.outcomes.get(name) {
            Some(Outcome::Denied { errno }) => assert!(
                *errno == libc::EACCES || *errno == libc::EPERM,
                "probe `{name}` was denied with errno {errno}, which is not a Landlock \
                 policy errno (EACCES={} EPERM={})",
                libc::EACCES,
                libc::EPERM,
            ),
            other => panic!(
                "probe `{name}` should have been denied by Landlock, got {}",
                other.map(Outcome::render).unwrap_or_else(|| "<missing>".into())
            ),
        }
    }
}

/// Spawns the confined child and collects what it reported.
fn run_confined(
    scenario: Scenario,
    scratch: &Scratch,
    port: u16,
    parent_pid: i32,
) -> (Report, Output) {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .arg("child_entry")
        .env(SCENARIO_ENV, scenario.as_str())
        .env(ROOT_ENV, scratch.root())
        .env(PORT_ENV, port.to_string())
        .env(PARENT_PID_ENV, parent_pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().expect("spawn confined child");
    let output = child.wait_with_output().expect("wait for confined child");
    (Report::parse(&output), output)
}

/// Skips the whole module's real tests when the kernel genuinely has no Landlock.
///
/// Loud on purpose: on the WSL2 host this crate targets, Landlock is present and
/// has been observed working, so a skip here means the host changed and the
/// confinement claims above are no longer being verified by anything.
fn require_landlock() -> Abi {
    let support = detect_kernel_support();
    match support.abi() {
        Some(abi) => abi,
        None => {
            eprintln!(
                "SKIPPING agentos-sandbox escape tests: {support}. Landlock confinement cannot be \
                 verified here, so these tests are not evidence of anything."
            );
            Abi::V7
        }
    }
}

fn abi_too_old_for(support_abi: Abi) -> bool {
    support_abi < Abi::V5
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn granted_file_readable_etc_passwd_not() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5, every profile is refused by design");
        return;
    }
    let scratch = Scratch::new("ro");
    let (r, out) = run_confined(Scenario::ReadOnlyTree, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::ReadOnlyTree, &out);

    // The tool can do its job...
    r.allowed("read_granted_file");
    r.allowed("list_granted_dir");
    // ...and cannot read the host.
    r.denied("read_etc_passwd");
    r.denied("read_etc_shadow");
    r.denied("read_proc_self_maps");
    r.denied("read_proc_self_mem");
    r.denied("read_proc_self_environ");
    r.denied("read_ungranted_sibling");
    // A ReadOnly grant is not a ReadWrite grant.
    r.denied("write_granted_ro_file");
    r.denied("create_in_granted_ro_dir");
    r.denied("unlink_in_granted_ro_dir");
    // And the denied writes really did not happen.
    r.allowed("granted_content_is_intact");
}

#[test]
fn read_write_grant_writable_read_only_grant_not() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5, ReadWrite is refused by design");
        return;
    }
    let scratch = Scratch::new("rw");
    let (r, out) = run_confined(
        Scenario::ReadWriteTree,
        &scratch,
        0,
        std::process::id() as i32,
    );
    r.require_confinement(Scenario::ReadWriteTree, &out);

    r.allowed("write_existing_in_rw");
    r.allowed("create_new_in_rw");
    r.allowed("truncate_in_rw");
    r.allowed("make_dir_in_rw");
    r.allowed("rename_within_rw");
    r.allowed("unlink_in_rw");

    r.denied("write_existing_in_ro");
    r.denied("create_new_in_ro");
    r.denied("truncate_in_ro");
    r.denied("make_dir_in_ro");
    r.denied("unlink_in_ro");
    // REFER is a separate right from WRITE_FILE.
    r.denied("rename_out_of_rw_into_ro");

    r.allowed("read_file_ro_still_intact");
}

#[test]
fn symlink_out_of_granted_directory_is_refused() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("symlink");
    let (r, out) = run_confined(Scenario::SymlinkEscape, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::SymlinkEscape, &out);

    r.denied("read_symlink_absolute_out");
    r.denied("read_symlink_relative_out");
    r.denied("write_through_symlink_out");
    r.denied("unlink_symlink_out");
    // Control: a symlink that stays inside the grant still resolves, so the
    // denials above are about the destination, not about symlinks.
    r.allowed("read_symlink_inside_grant");
    // Control: /etc/passwd is unreachable directly too, so the symlink result is
    // not an artefact of a broken profile.
    r.denied("read_etc_passwd_directly");
    // And the write through the symlink really did not modify the target. The
    // parent is unconfined, so it can read /etc/passwd to check.
    let passwd = read_file(Path::new("/etc/passwd")).expect("parent reads /etc/passwd");
    assert!(
        !passwd.windows(5).any(|w| w == b"pwned\n"),
        "/etc/passwd was modified through a symlink from inside the sandbox"
    );
    assert!(
        passwd.starts_with(b"root:") || passwd.windows(3).any(|w| w == b":x:"),
        "/etc/passwd no longer looks like a passwd file"
    );
    // The symlink itself is inside the granted tree, so removing it is a
    // modification of granted content: denied, and it is still there.
    assert!(
        scratch.ro().join("link-abs").symlink_metadata().is_ok(),
        "the symlink inside the granted tree was removed"
    );
}

#[test]
fn dotdot_traversal_out_of_granted_directory_is_refused() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("traversal");
    let (r, out) = run_confined(
        Scenario::TraversalEscape,
        &scratch,
        0,
        std::process::id() as i32,
    );
    r.require_confinement(Scenario::TraversalEscape, &out);

    r.denied("read_dotdot_escape");
    r.denied("read_absolute_outside_grant");
    r.denied("read_dotdot_escape_root_etc");
    r.denied("read_dotdot_escape_sibling_file");
    r.denied("create_through_dotdot");
    r.denied("read_root_dir_listing");
    // Control: the granted path is still reachable, so the denials are the
    // traversal and not a broken profile.
    r.allowed("read_granted_file_still_works");
}

#[test]
fn a_profile_with_no_filesystem_grant_reads_nothing() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("nofs");
    let (r, out) = run_confined(Scenario::NoFilesystem, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::NoFilesystem, &out);

    r.denied("read_granted_path_but_not_granted");
    r.denied("read_etc_passwd");
    r.denied("list_working_directory");
    r.denied("read_proc_self_exe");
    r.denied("read_proc_self_maps");
    // Metadata-only access is NOT covered: Landlock gates opening a file, not
    // stat(2). Asserting the observed behaviour so a future change that starts
    // or stops gating it is noticed, rather than leaving it assumed either way.
    r.allowed("stat_tmp_is_not_gated");
}

#[test]
fn tcp_bind_and_connect_denied_by_default() {
    let abi = require_landlock();
    if abi < Abi::V4 {
        eprintln!("SKIP: kernel ABI {abi} < V4, TCP gating unavailable");
        return;
    }
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    // A real listening socket, so a successful connect would be unambiguous.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind parent listener");
    let port = listener.local_addr().expect("local addr").port();
    let scratch = Scratch::new("tcpdeny");
    let (r, out) = run_confined(Scenario::TcpDenied, &scratch, port, std::process::id() as i32);
    r.require_confinement(Scenario::TcpDenied, &out);

    r.denied("tcp_connect_denied");
    r.denied("tcp_bind_denied");
    // Honest about the hole: Landlock's TCP rights do not stop socket(2), and do
    // not stop UDP. These two assertions are what keep the docs honest.
    r.allowed("socket_creation_is_not_gated");
    r.allowed("udp_bind_is_not_gated");
    drop(listener);
}

#[test]
fn granting_one_tcp_port_allows_connect_and_nothing_else() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind parent listener");
    let port = listener.local_addr().expect("local addr").port();
    let scratch = Scratch::new("tcpallow");
    let (r, out) = run_confined(
        Scenario::TcpConnectAllowed,
        &scratch,
        port,
        std::process::id() as i32,
    );
    r.require_confinement(Scenario::TcpConnectAllowed, &out);

    r.allowed("tcp_connect_allowed");
    r.denied("tcp_bind_still_denied");
    drop(listener);
}

#[test]
fn scope_blocks_signalling_processes_outside_the_domain() {
    let abi = require_landlock();
    if abi < Abi::V6 {
        eprintln!("SKIP: kernel ABI {abi} < V6, Scope::Signal unavailable");
        return;
    }
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("scopes");
    let (r, out) = run_confined(Scenario::Scopes, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::Scopes, &out);

    r.denied("signal_parent_denied");
    // Control: the child may still signal itself.
    r.allowed("signal_self_allowed");
}

/// Confined children must inherit `PR_SET_NO_NEW_PRIVS`, otherwise a setuid exec
/// could shed the ruleset. Asserted on every run via `require_confinement`, and
/// called out here so it is a named claim.
#[test]
fn no_new_privs_is_set_and_read_back() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("nnp");
    let (r, out) = run_confined(Scenario::ReadOnlyTree, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::ReadOnlyTree, &out);
    let confine = r.confine.clone().expect("confine line");
    assert!(confine.contains("no_new_privs=1"), "{confine}");
}

/// The unconfined parent must be unaffected: confinement is per-child, so a bug
/// that leaked a ruleset into the parent would show up here.
#[test]
fn parent_process_is_not_confined() {
    let abi = require_landlock();
    if abi_too_old_for(abi) {
        eprintln!("SKIP: kernel ABI {abi} < V5");
        return;
    }
    let scratch = Scratch::new("leak");
    let (r, out) = run_confined(Scenario::NoFilesystem, &scratch, 0, std::process::id() as i32);
    r.require_confinement(Scenario::NoFilesystem, &out);
    // These are the exact operations the child was denied.
    read_file(&scratch.secrets()).expect("parent must still read its own tree");
    read_file(Path::new("/etc/passwd")).expect("parent must still read /etc/passwd");
    fs::read_dir(Path::new("/")).expect("parent must still list /");
}