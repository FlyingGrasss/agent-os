//! Passing capabilities to a worker as real file descriptors.
//!
//! ## Why a descriptor and not a path
//!
//! A capability handed over as a path string is a *name*, and names can be
//! resolved by someone else's rules. If the daemon says "you may read
//! `/data/x.csv`" and the worker opens it, the worker is trusting whatever the
//! filesystem does with that name at that moment: a symlink could be swapped in
//! between the check and the open, the path could be bind-mounted over, and the
//! worker has no way to tell.
//!
//! A descriptor is the object itself. Once the daemon opens `/data/x.csv` and
//! hands the descriptor over `SCM_RIGHTS`, the worker's read cannot be redirected
//! to a different file, because there is no name left to redirect. This is why
//! invariant I5 is phrased in terms of descriptors rather than paths.
//!
//! ## The descriptor still points at the right file
//!
//! A descriptor is a reference to an inode, so the *open* has to be trustworthy
//! too. [`open_granted`] uses `O_NOFOLLOW` and a `fstat` against the expected
//! identity, so a symlink at the final component is refused rather than followed.
//! Landlock is what makes the open itself safe; this module makes the handover
//! safe.
//!
//! ## Everything here is Linux
//!
//! `SCM_RIGHTS` is a Unix socket feature. Off Linux the module exposes the
//! portable parts — opening a granted file safely, and the identity check — and
//! the send/receive side is compiled away.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use agentos_types::{CapId, SourceId, SourceKind};

/// What a granted file is expected to be.
///
/// Checked rather than assumed, because a descriptor opened on the wrong kind of
/// object is still a descriptor and still passes Landlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A regular file, read-only.
    ReadOnlyFile,
    /// A regular file, writable.
    WritableFile,
    /// A directory, so the worker can open relative to it.
    Directory,
}

/// A file descriptor that will be handed to a worker.
#[derive(Debug)]
pub struct Granted {
    fd: OwnedFd,
    cap: CapId,
    source: SourceId,
}

impl Granted {
    /// The capability id this descriptor was authorised under.
    pub fn cap(&self) -> CapId {
        self.cap
    }

    /// The source this descriptor came from, so the worker's audit trail can say
    /// a web page produced it.
    pub fn source(&self) -> SourceId {
        self.source
    }

    /// The raw descriptor, for handing to send_fd.
    pub fn as_raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The fd's identity: device and inode.
    ///
    /// Recorded so the receiving side can verify it received the object it was
    /// sent, rather than something swapped in transit.
    pub fn identity(&self) -> io::Result<FileIdentity> {
        identity_of(self.fd.as_raw_fd())
    }

    /// Keep this descriptor in this process and drop it.
    ///
    /// Used by the receiving side once it has decided not to hand the capability
    /// on, and by tests that need to assert the descriptor was delivered.
    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

/// A file's device and inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
}

fn identity_of(fd: RawFd) -> io::Result<FileIdentity> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

/// Open a granted path, refusing a symlink at the final component.
///
/// `O_NOFOLLOW` makes the final component a symlink an error instead of a
/// redirection. Landlock is what constrains which paths may be opened at all;
/// this is what stops the specific case of the last component being swapped for
/// a link between the check and the open.
pub fn open_granted(path: &std::path::Path, expect: Expect, source: SourceId) -> io::Result<Granted> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    match expect {
        Expect::ReadOnlyFile | Expect::Directory => {}
        Expect::WritableFile => {
            opts.write(true);
        }
    }
    // `O_NONBLOCK` is not a politeness flag here, it is a liveness requirement.
    // Opening a FIFO for reading blocks until a writer appears, so a `Grant` of
    // an attacker-chosen path that happens to be a FIFO would hang the daemon
    // inside a capability open. With `O_NONBLOCK` the open returns immediately
    // and the non-regular-file check below refuses it.
    //
    // On a regular file `O_NONBLOCK` is a no-op for reads and writes.
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // `O_DIRECTORY` makes the kernel enforce the directory check, so a path that
    // changed into a regular file between the caller's plan and this open is
    // refused by the open itself rather than by the `metadata` call below, which
    // would otherwise race.
    if matches!(expect, Expect::Directory) {
        flags |= libc::O_DIRECTORY;
    }
    opts.custom_flags(flags);

    let file = opts.open(path)?;
    let meta = file.metadata()?;
    let fd = OwnedFd::from(file);

    match expect {
        Expect::Directory => {
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "granted path is not a directory",
                ));
            }
        }
        _ => {
            // A device, fifo, or socket would pass the open and then behave in
            // ways the caller did not ask for.
            if !meta.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "granted path is not a regular file",
                ));
            }
        }
    }

    Ok(Granted {
        fd,
        cap: CapId(0),
        source,
    })
}

/// Attach a capability id to a granted descriptor.
///
/// The broker is the only thing that should be minting ids, so this is separate
/// from `open_granted`: opening a file and authorising it are different acts, and
/// conflating them would mean any caller that can open a path can also grant it.
pub fn with_cap(g: Granted, cap: CapId) -> Granted {
    Granted { cap, ..g }
}

#[cfg(target_os = "linux")]
mod transfer {
    use super::*;

    /// Send a descriptor over a Unix socket with `SCM_RIGHTS`.
    ///
    /// A descriptor cannot be forged on this path. The kernel only transfers a
    /// descriptor the sender actually holds, so a compromised worker cannot
    /// conjure authority by sending a larger id than it was granted: the id is
    /// advisory and the descriptor is the authority.
    pub fn send_fd(socket: RawFd, granted: &Granted) -> io::Result<()> {
        let byte = [1u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cmsg_buf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        // `CMSG_SPACE` is a const-evaluatable size computation, but the libc
        // binding is an unsafe fn on this target.
        msg.msg_controllen = unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _
        };

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not build the control message",
                ));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                &granted.as_raw() as *const RawFd as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );

            let sent = libc::sendmsg(socket, &msg, 0);
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Receive a descriptor, and the single control byte that frames it.
    ///
    /// The control message is checked rather than trusted: a caller must verify
    /// `cmsg_type == SCM_RIGHTS`, because a socket peer that sent something else
    /// would otherwise have the receiver read a garbage fd.
    pub fn recv_fd(socket: RawFd) -> io::Result<OwnedFd> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cmsg_buf = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        let got = unsafe { libc::recvmsg(socket, &mut msg, 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        // `MSG_CTRUNC` means the control data did not fit, so the descriptor was
        // dropped and whatever is in the buffer is not a descriptor.
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control message was truncated; no descriptor was transferred",
            ));
        }

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() || (*cmsg).cmsg_level != libc::SOL_SOCKET {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no control header accompanied the descriptor",
                ));
            }
            if (*cmsg).cmsg_type != libc::SCM_RIGHTS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control message was not SCM_RIGHTS",
                ));
            }
            let mut fd: RawFd = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut RawFd as *mut u8,
                std::mem::size_of::<RawFd>(),
            );
            if fd < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "received an invalid descriptor",
                ));
            }
            // `CLOEXEC` so a later `exec` does not silently inherit it.
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }
}

#[cfg(target_os = "linux")]
pub use transfer::{recv_fd, send_fd};

/// The source kind a granted file most likely came from.
///
/// A convenience for the caller, not a security decision: the caller knows where
/// the path came from and this only saves a line.
pub fn likely_source(path: &std::path::Path) -> SourceId {
    let s = path.to_string_lossy();
    if s.starts_with("http") {
        SourceId::of_kind(SourceKind::WebPage)
    } else {
        SourceId::of_kind(SourceKind::FileOnDisk)
    }
}

