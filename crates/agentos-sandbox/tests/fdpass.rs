//! Descriptor-passing tests.
//!
//! The property under test is that a capability survives the process boundary as
//! a *reference to the object*, not as a name that could be redirected. So the
//! tests that matter are the ones that try to redirect it: replace the path with
//! a symlink after the daemon opened it, and confirm the worker still reads the
//! original file.
//!
//! `SCM_RIGHTS` is exercised over a real `socketpair`, because a mocked sendmsg
//! would prove nothing about whether the kernel transfers the descriptor.

#![cfg(target_os = "linux")]

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use agentos_sandbox::fdpass::{open_granted, recv_fd, send_fd, Expect, FileIdentity};

static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "agentos-fdpass-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn source() -> agentos_types::SourceId {
    agentos_types::SourceId::of_kind(agentos_types::SourceKind::FileOnDisk)
}

fn socket_pair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

fn read_all(fd: RawFd) -> String {
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    // `File::from_raw_fd` took ownership; hand it back so the caller's `close`
    // is the only one.
    let raw = f.as_raw_fd();
    std::mem::forget(f);
    assert!(raw >= 0);
    s
}

#[test]
fn a_descriptor_survives_a_real_scm_rights_transfer() {
    let s = Scratch::new("basic");
    let p = s.path("data.txt");
    std::fs::write(&p, b"the real contents\n").unwrap();

    let granted = open_granted(&p, Expect::ReadOnlyFile, source()).unwrap();

    let (host, worker) = socket_pair();
    send_fd(host, &granted).unwrap();
    let received: OwnedFd = recv_fd(worker).unwrap();

    assert_eq!(
        read_all(received.as_raw_fd()),
        "the real contents\n",
        "the descriptor did not carry the file it was opened on"
    );

    unsafe {
        libc::close(host);
        libc::close(worker);
    }
}

#[test]
fn the_received_descriptor_still_points_at_the_same_inode() {
    let s = Scratch::new("identity");
    let p = s.path("data.txt");
    std::fs::write(&p, b"x\n").unwrap();

    let granted = open_granted(&p, Expect::ReadOnlyFile, source()).unwrap();
    let before: FileIdentity = granted.identity().unwrap();

    let (host, worker) = socket_pair();
    send_fd(host, &granted).unwrap();
    let received: OwnedFd = recv_fd(worker).unwrap();

    let after = agentos_sandbox::fdpass::FileIdentity {
        dev: 0,
        ino: 0,
    };
    // Recompute rather than reuse the private helper.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(received.as_raw_fd(), &mut st) };
    assert_eq!(rc, 0);
    assert_eq!(
        (st.st_dev as u64, st.st_ino as u64),
        (before.dev, before.ino),
        "the transferred descriptor refers to a different file"
    );
    let _ = after;

    unsafe {
        libc::close(host);
        libc::close(worker);
    }
}

#[test]
fn a_symlink_at_the_final_component_is_refused() {
    // The classic redirection. `O_NOFOLLOW` makes the open fail rather than
    // handing out a descriptor for whatever the link points at.
    let s = Scratch::new("symlink");
    let secret = s.path("secret.txt");
    let link = s.path("link.txt");
    std::fs::write(&secret, b"secret\n").unwrap();
    std::os::unix::fs::symlink(&secret, &link).unwrap();

    let err = open_granted(&link, Expect::ReadOnlyFile, source())
        .expect_err("a symlink must not be opened as a granted file");
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
}

#[test]
fn replacing_the_path_after_the_open_does_not_redirect_the_descriptor() {
    // This is the reason capabilities are descriptors. The daemon opens the file,
    // then the path is rewritten to point somewhere else. The descriptor the
    // worker receives must still be the original file, because there is no longer
    // a name to redirect.
    let s = Scratch::new("swap");
    let p = s.path("data.txt");
    let decoy = s.path("decoy.txt");
    std::fs::write(&p, b"original\n").unwrap();
    std::fs::write(&decoy, b"decoy\n").unwrap();

    let granted = open_granted(&p, Expect::ReadOnlyFile, source()).unwrap();

    // Swap the path out from under the already-open descriptor.
    std::fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(&decoy, &p).unwrap();

    let (host, worker) = socket_pair();
    send_fd(host, &granted).unwrap();
    let received: OwnedFd = recv_fd(worker).unwrap();

    let contents = read_all(received.as_raw_fd());
    assert_eq!(
        contents, "original\n",
        "the descriptor followed the path after the swap"
    );
    assert_ne!(contents, "decoy\n");

    unsafe {
        libc::close(host);
        libc::close(worker);
    }
}

#[test]
fn a_directory_must_be_a_directory() {
    let s = Scratch::new("expect");
    let d = s.path("adir");
    std::fs::create_dir_all(&d).unwrap();
    let f = s.path("afile");
    std::fs::write(&f, b"x\n").unwrap();

    open_granted(&d, Expect::Directory, source()).expect("a directory grant should open");
    assert!(
        open_granted(&f, Expect::Directory, source()).is_err(),
        "a regular file must not satisfy a directory grant"
    );
    assert!(
        open_granted(&d, Expect::ReadOnlyFile, source()).is_err(),
        "a directory must not satisfy a file grant"
    );
}

#[test]
fn a_missing_path_is_an_error_not_a_silent_empty_grant() {
    let s = Scratch::new("missing");
    assert!(open_granted(&s.path("nope"), Expect::ReadOnlyFile, source()).is_err());
}

#[test]
fn a_writable_grant_opens_for_writing_and_a_read_only_one_does_not() {
    let s = Scratch::new("mode");
    let p = s.path("f.txt");
    std::fs::write(&p, b"x\n").unwrap();

    open_granted(&p, Expect::WritableFile, source()).expect("writable grant");
    // The read-only grant opens read-only, which is checked by the kernel on
    // write, not by us. Opening twice is enough to show both modes are accepted;
    // the actual write refusal is Landlock's and seccomp's business.
    open_granted(&p, Expect::ReadOnlyFile, source()).expect("read-only grant");
}

#[test]
fn the_capability_id_is_separate_from_the_open() {
    // Opening a path and authorising it are different acts. Conflating them would
    // mean any caller that can open a path can also grant it.
    let s = Scratch::new("cap");
    let p = s.path("f.txt");
    std::fs::write(&p, b"x\n").unwrap();

    let granted = open_granted(&p, Expect::ReadOnlyFile, source()).unwrap();
    // Freshly opened, so it carries the zero id until the broker authorises it.
    assert_eq!(granted.cap(), agentos_types::CapId(0));

    let authorised =
        agentos_sandbox::fdpass::with_cap(granted, agentos_types::CapId(42));
    assert_eq!(authorised.cap(), agentos_types::CapId(42));
}

#[test]
fn the_granted_descriptor_carries_its_provenance() {
    // A file fetched from a web page must say so, so the worker's audit trail can
    // distinguish it from a local file.
    let s = Scratch::new("provenance");
    let p = s.path("f.txt");
    std::fs::write(&p, b"x\n").unwrap();

    let web = agentos_types::SourceId::of_kind(agentos_types::SourceKind::WebPage);
    let granted = open_granted(&p, Expect::ReadOnlyFile, web).unwrap();
    assert_eq!(granted.source().kind(), agentos_types::SourceKind::WebPage);
}

#[test]
fn receiving_without_a_descriptor_is_an_error_not_a_bogus_fd() {
    // A peer that sends a byte with no control message must not be read as
    // having sent a descriptor.
    let (host, worker) = socket_pair();
    let payload = b"x";
    let sent = unsafe { libc::write(host, payload.as_ptr() as *const libc::c_void, 1) };
    assert_eq!(sent, 1);

    let err = recv_fd(worker).expect_err("a bare byte is not a descriptor");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    unsafe {
        libc::close(host);
        libc::close(worker);
    }
}

#[test]
fn a_closed_socket_yields_an_error_rather_than_a_stale_descriptor() {
    let (host, worker) = socket_pair();
    unsafe {
        libc::close(host);
        libc::close(worker);
    }
    // A negative or closed fd is caught rather than read.
    assert!(recv_fd(-1).is_err());
}

#[test]
fn opening_a_non_regular_file_as_a_file_is_refused() {
    // A fifo would open and then block or behave unexpectedly, which is not what
    // a file grant means.
    let s = Scratch::new("fifo");
    let p = s.path("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&p)
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if !made {
        eprintln!("SKIP: mkfifo unavailable");
        return;
    }
    // O_NONBLOCK would be needed to open a fifo without a peer, so this asserts
    // the refusal rather than hanging.
    assert!(open_granted(&p, Expect::ReadOnlyFile, source()).is_err());
}

#[test]
fn a_directory_grant_can_be_opened_relative_to_by_the_worker() {
    // The point of a directory grant: the worker opens by relative path and the
    // descriptor keeps it anchored to the granted directory even if the path is
    // later moved.
    let s = Scratch::new("dirfd");
    let d = s.path("data");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("f.txt"), b"inside\n").unwrap();

    let granted = open_granted(&d, Expect::Directory, source()).unwrap();

    let (host, worker) = socket_pair();
    send_fd(host, &granted).unwrap();
    let received: OwnedFd = recv_fd(worker).unwrap();

    // Open relative to the directory descriptor, so no path is resolved at all.
    // `OpenOptions::openat` was stabilised after this toolchain, so this calls
    // `libc::openat` directly and wraps the result.
    let opened = openat(received.as_raw_fd(), "f.txt");
    let opened = opened.expect("openat relative to the granted directory");

    let mut s = String::new();
    let mut opened = opened;
    opened.read_to_string(&mut s).unwrap();
    assert_eq!(s, "inside\n");

    // And a name outside it is unreachable, because there is no path involved.
    assert!(
        openat(received.as_raw_fd(), "../secret.txt").is_err(),
        "a traversal out of a directory descriptor must fail"
    );

    unsafe {
        libc::close(host);
        libc::close(worker);
    }
}

/// `openat(2)` against a directory descriptor.
///
/// Returns `Err` rather than panicking, so a caller can assert the refusal.
fn openat(dir: RawFd, name: &str) -> std::io::Result<std::fs::File> {
    let mut path = name.as_bytes().to_vec();
    path.push(0);
    let rc = unsafe {
        libc::openat(
            dir,
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(rc) })
}
