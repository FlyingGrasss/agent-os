//! The AgentOS daemon (`agentosd`).
//!
//! # What this is
//!
//! The long-running process that holds the machine's authority. It accepts task
//! intents over IPC, plans them with the privileged model, runs them through the
//! real policy engine, and returns what happened.
//!
//! It is deliberately thin in the way `agentos-cli` is: it holds no policy, no
//! taint rules, and no authority of its own. Everything it decides is decided in
//! the crates below it. Removing this file would not weaken the system, which is
//! the test of whether a daemon is a control or a claim.
//!
//! # What it refuses to do
//!
//! **It never approves anything.** See [`executor`] for why, in full. The short
//! version: a daemon has no stdin, so it can never satisfy the project's own rule
//! that approval requires a person, and adding an IPC approval path would make
//! every local process that can open a socket a principal in the authority model.
//! A headless daemon therefore cannot execute a plan that needs approval. It says
//! so, with the rendered request attached, and nothing was sent or written.
//!
//! # Invariants, and where they are enforced here
//!
//! The daemon adds no new enforcement. It preserves what the crates below
//! enforce, and the two places where it could plausibly have broken them are worth
//! naming:
//!
//! - **I1.** The task text arrives off a socket and is [`Quarantined`] at the
//!   boundary (`ExecuteParams::into_quarantined`). The only promotion to `Trusted`
//!   is [`executor::run_task`], and it carries `Origin::User`, so the audit log
//!   shows tasks attributed to the daemon's configured user rather than to
//!   whoever sent the frame.
//! - **I4.** Policy is consulted for every tool argument. The daemon adds no rule
//!   and relaxes none.
//!
//! # A note on the transport
//!
//! Unix socket on Unix; on other platforms a TCP socket bound to loopback. The
//! TCP bind address is checked and refused rather than warned about, because a
//! daemon started with a warning is a daemon someone deploys with the warning
//! scrolled past. See [`listener`].
//!
//! # Running it
//!
//! ```text
//! AGENTOSD_MODEL=llama3.2:3b \
//! AGENTOSD_WRITE_ROOTS=/var/agentos/outbox \
//! AGENTOSD_ALLOWED_HOSTS=invoices.example.com \
//! agentosd
//! ```
//!
//! Every capability is opt-in from the environment. Started with none, the daemon
//! still plans and still runs plans that need no authority; it cannot write a file,
//! reach a host, or send mail. A mistyped variable produces an inert daemon rather
//! than an unrestricted one.

pub mod executor;
pub mod grants;
pub mod listener;
pub mod protocol;
pub mod state;

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentos_tools::audit::{FileSink, SystemClock};

use grants::{split_list, split_paths, Ceiling};
use state::{default_audit_path, DaemonState};

/// Default TCP port when no socket path is given.
const DEFAULT_TCP_PORT: u16 = 54321;

/// Default number of in-flight tasks.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// How the daemon was configured to listen.
enum Listen {
    #[cfg(unix)]
    Unix(PathBuf),
    Tcp(std::net::SocketAddr),
}

/// Entry point for the `agentosd` binary.
/// Run the daemon until it is asked to stop.
///
/// # Why a single-threaded runtime
///
/// All real work is handed to `spawn_blocking`, and the async side only moves bytes
/// between sockets. A multi-threaded runtime would buy nothing here and would make
/// the blocking-pool reasoning harder to follow. The blocking pool is sized
/// independently, so a burst of tasks still runs concurrently up to
/// `max_concurrent_tasks`.
pub fn entry_point() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agentosd: cannot start the async runtime: {e}");
            return std::process::ExitCode::from(70);
        }
    };

    match runtime.block_on(serve()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agentosd: {e}");
            std::process::ExitCode::from(70)
        }
    }
}

/// Read configuration, probe the model, bind, and serve until interrupted.
async fn serve() -> Result<(), String> {
    let model = env_or("AGENTOSD_MODEL", "llama3.2:3b");
    let max_concurrent: usize = env_or("AGENTOSD_MAX_CONCURRENT", &DEFAULT_MAX_CONCURRENT.to_string())
        .parse()
        .unwrap_or(DEFAULT_MAX_CONCURRENT)
        .max(1);
    let audit_path = env_or("AGENTOSD_AUDIT_LOG", &default_audit_path().display().to_string());

    let ceiling = ceiling_from_env();
    let listen = listen_from_env()?;

    // The audit log is opened before anything can run. Invariant I6 says every
    // action is recorded before it executes, and a daemon that started and then
    // failed to open its log would have a window where it acts without recording.
    let sink: executor::SharedSink = Arc::new(Mutex::new(
        FileSink::open(&audit_path).map_err(|e| {
            format!(
                "cannot open the audit log at {audit_path}: {e}\n\
                 (invariant I6 requires it to exist before anything runs, so this refuses \
                 rather than starting a daemon that acts without recording)"
            )
        })?,
    ));
    let clock: executor::SharedClock = Arc::new(Mutex::new(SystemClock));

    let backend = executor::build_backend(&model);

    // Probe before binding. A daemon that cannot plan is not degraded, it is
    // broken, and finding that out at startup is better than finding it out when
    // someone sends it a task.
    match backend.probe() {
        Ok(models) => {
            if models.iter().any(|m| m.starts_with(&model)) {
                eprintln!("agentosd: model {model} available");
            } else {
                eprintln!("agentosd: model {model} is NOT PULLED; available: {models:?}");
                eprintln!("         run `ollama pull {model}`; the daemon will not plan until then");
                return Err("the configured model is not available".into());
            }
        }
        Err(e) => {
            return Err(format!(
                "cannot reach the model server: {e}\n\
                 (start one with `ollama serve`)"
            ));
        }
    }

    let state = Arc::new(DaemonState::new(
        ceiling,
        Box::new(backend),
        sink,
        clock,
        model,
        max_concurrent,
    ));

    report_configuration(&state);

    match listen {
        #[cfg(unix)]
        Listen::Unix(path) => {
            let handle = listener::serve_unix(&path, state.clone())
                .await
                .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
            eprintln!("agentosd: listening on {}", path.display());
            wait_for_signal().await;
            handle.abort();
            Ok(())
        }
        Listen::Tcp(addr) => {
            // Bind first, announce second. Announcing before the bind would put a
            // "listening on 0.0.0.0" line in the log of a process that never
            // listened on it -- and a log line like that is exactly what someone
            // would later read to conclude the daemon was exposed.
            let listener = listener::bind_tcp(addr).await.map_err(|e| match e.kind() {
                io::ErrorKind::PermissionDenied => format!("{e}"),
                _ => format!("cannot listen on {addr}: {e}"),
            })?;
            eprintln!("agentosd: listening on {addr}");
            tokio::select! {
                result = listener::accept_tcp(listener, state) => {
                    result.map_err(|e| format!("accept loop failed on {addr}: {e}"))
                }
                _ = wait_for_signal() => Ok(()),
            }
        }
    }
}

/// Build the operator's ceiling from the environment.
///
/// Every list defaults to empty, which means "nothing is permitted". The default
/// is not a convenience; it is the fail-closed direction, and it is what makes a
/// mistyped `AGENTOSD_ALLOWED_HOSTS` produce an inert daemon rather than one that
/// trusts everything.
fn ceiling_from_env() -> Ceiling {
    let write_roots = match std::env::var("AGENTOSD_WRITE_ROOTS") {
        Ok(raw) => split_paths(&raw),
        Err(_) => Vec::new(),
    };
    let allowed_hosts = match std::env::var("AGENTOSD_ALLOWED_HOSTS") {
        Ok(raw) => split_list(&raw),
        Err(_) => Vec::new(),
    };
    let mail_outbox = std::env::var("AGENTOSD_MAIL_OUTBOX")
        .ok()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty());

    Ceiling {
        write_roots,
        allowed_hosts,
        mail_outbox,
    }
}

/// Decide where to listen.
///
/// The environment may set `AGENTOSD_SOCKET` (Unix only) or `AGENTOSD_TCP_ADDR`.
/// Neither set means loopback TCP on the default port.
fn listen_from_env() -> Result<Listen, String> {
    #[cfg(unix)]
    if let Ok(path) = std::env::var("AGENTOSD_SOCKET") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(Listen::Unix(PathBuf::from(trimmed)));
        }
    }

    let addr = match std::env::var("AGENTOSD_TCP_ADDR") {
        Ok(raw) => raw
            .trim()
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("AGENTOSD_TCP_ADDR is not a socket address: {e}"))?,
        Err(_) => std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_TCP_PORT)),
    };
    Ok(Listen::Tcp(addr))
}

/// Print what this daemon is and, more importantly, what it cannot do.
///
/// The limitations are the point of the exercise. A caller that believes tools are
/// confined when they are not is the most expensive kind of wrong available here,
/// and the only defence is to say so before it matters.
fn report_configuration(state: &Arc<DaemonState>) {
    let info = state.info();
    eprintln!("agentosd: protocol {}", info.protocol);
    eprintln!("agentosd: max concurrent tasks: {}", info.max_concurrent_tasks);
    eprintln!(
        "agentosd: can ask a human: {}",
        if info.can_ask_human { "yes" } else { "NO -- tasks needing approval are refused" }
    );
    if info.write_roots.is_empty() {
        eprintln!("agentosd: write roots: none (fs.write unavailable)");
    } else {
        eprintln!("agentosd: write roots: {}", info.write_roots.join(", "));
    }
    if info.allowed_hosts.is_empty() {
        eprintln!("agentosd: allowed hosts: none (http.fetch unavailable)");
    } else {
        eprintln!("agentosd: allowed hosts: {}", info.allowed_hosts.join(", "));
    }
    if info.send_email_enabled {
        eprintln!("agentosd: send_email: enabled (outbox configured)");
    } else {
        eprintln!("agentosd: send_email: unavailable (no AGENTOSD_MAIL_OUTBOX)");
    }
    for limitation in &info.limitations {
        eprintln!("agentosd: limitation: {limitation}");
    }
}

/// Resolve when the process is asked to stop.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => fallback.to_string(),
    }
}

#[cfg(test)]
mod tests;