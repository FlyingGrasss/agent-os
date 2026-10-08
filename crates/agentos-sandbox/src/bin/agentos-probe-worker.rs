//! Confined probe worker for the pool tests.
//!
//! It receives one request on the control socket, probes what the kernel lets
//! it do, writes the findings to stdout, and exits. The findings travel on
//! stdout rather than through the protocol because stdout is already the pipe
//! the test parent reads, and putting probe results in the protocol would
//! mean the pool had to understand them, which it must not.
//!
//! # Why this file still builds on Windows
//!
//! The probes are Unix-only: a probe is a raw syscall against the kernel, and the
//! control socket that carries the request is a Unix socket. The binary is still
//! compiled everywhere so a Windows workspace build needs no cfg in every
//! dependent manifest, and so the refusal is a visible runtime exit rather than a
//! link error somebody works around by removing the dependency. Same reasoning,
//! and same exit-code convention, as `agentos-q-extractor`.

#[cfg(unix)]
const CONTROL_FD_ENV: &str = "AGENTOS_SANDBOX_POOL_CTL_FD";
#[cfg(unix)]
const ROOT_ENV: &str = "AGENTOS_SANDBOX_POOL_ROOT";
#[cfg(unix)]
const PROBE: &str = "##PROBE##";

/// `EX_SOFTWARE`. Distinct from every code the Unix path returns, so a caller
/// that somehow reached this binary on the wrong platform cannot mistake it for a
/// probe report.
#[cfg(not(unix))]
fn run() -> i32 {
    eprintln!(
        "agentos-probe-worker requires a Unix host: it probes the kernel with raw syscalls and \
         receives the request over a Unix control socket, and neither exists on this target. \
         Refusing rather than reporting nothing as though nothing were refused."
    );
    70
}

#[cfg(unix)]
fn run() -> i32 {
    use std::fs;
    
    use std::path::PathBuf;

    let fd = std::env::var(CONTROL_FD_ENV)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or_else(|| std::process::exit(70));

    let mut head = [0u8; 5];
    if read_fd(fd, &mut head).is_err() {
        std::process::exit(70);
    }
    let n_caps = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if n_caps > 1024 {
        std::process::exit(70);
    }
    for _ in 0..n_caps {
        if agentos_sandbox::fdpass::recv_fd(fd).is_err() {
            std::process::exit(70);
        }
    }
    let mut lenb = [0u8; 4];
    if read_fd(fd, &mut lenb).is_err() {
        std::process::exit(70);
    }
    let len = u32::from_le_bytes(lenb) as usize;
    if len > 1024 * 1024 {
        std::process::exit(70);
    }
    let mut request = vec![0u8; len];
    if len > 0 && read_fd(fd, &mut request).is_err() {
        std::process::exit(70);
    }

    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("the pool forwards the environment"));
    let ro = root.join("ro");

    emit("read_granted", &outcome_of(fs::read(ro.join("visible.txt")).map(|_| ())));
    emit(
        "granted_content",
        &match fs::read(ro.join("visible.txt")) {
            Ok(b) if b == b"visible payload\n" => "intact".to_string(),
            Ok(_) => "MODIFIED".to_string(),
            Err(e) => format!("FAILED {e}"),
        },
    );
    emit(
        "read_symlink_out",
        &outcome_of(fs::read(ro.join("escape")).map(|_| ())),
    );
    emit("read_etc_passwd", &outcome_of(fs::read("/etc/passwd").map(|_| ())));
    emit(
        "read_proc_self_maps",
        &outcome_of(fs::read("/proc/self/maps").map(|_| ())),
    );
    emit(
        "read_proc_self_environ",
        &outcome_of(fs::read("/proc/self/environ").map(|_| ())),
    );
    emit(
        "read_ungranted_sibling",
        &outcome_of(fs::read(root.join("secret.txt")).map(|_| ())),
    );
    emit("list_root_dir", &outcome_of(fs::read_dir("/").map(|_| ())));
    emit("socket", &outcome_of(raw_socket().map(|_| ())));

    let reply = b"PROBES_DONE";
    let mut out = vec![0xA1u8, 0u8];
    out.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    out.extend_from_slice(reply);
    out.extend_from_slice(&0u32.to_le_bytes());
    write_fd(fd, &out);
    0
}

#[cfg(unix)]
fn write_fd(fd: i32, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(at) as *const libc::c_void,
                bytes.len() - at,
            )
        };
        if n < 0 {
            std::process::exit(71);
        }
        at += n as usize;
    }
}

#[cfg(unix)]
fn read_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(at) as *mut libc::c_void,
                buf.len() - at,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        at += n as usize;
    }
    Ok(())
}

#[cfg(unix)]
fn outcome_of(r: std::io::Result<()>) -> String {
    match r {
        Ok(()) => "ALLOWED".to_string(),
        Err(e) => match e.raw_os_error() {
            Some(errno)
                if errno == libc::EACCES
                    || errno == libc::EPERM
                    || errno == libc::ENOSYS =>
            {
                format!("DENIED errno={errno}")
            }
            errno => format!("FAILED errno={}", errno.unwrap_or(-1)),
        },
    }
}

#[cfg(unix)]
fn emit(name: &str, value: &str) {
    use std::io::Write;
    let line = format!("{PROBE}\t{name}\t{value}\n");
    let _ = writeln!(std::io::stdout(), "{line}");
}

#[cfg(unix)]
fn raw_socket() -> std::io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        unsafe {
            libc::close(fd);
        }
        Ok(fd)
    }
}

fn main() -> std::process::ExitCode {
    // One exit path. Nothing runs after the probes: continuing would mean
    // running code in the process whose confinement the probes were testing.
    std::process::ExitCode::from(run().clamp(0, 255) as u8)
}