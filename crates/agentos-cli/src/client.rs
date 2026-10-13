//! Client for the `agentosd` daemon.
//!
//! # What this is
//!
//! A lightweight JSON-RPC client that discovers the running daemon, authenticates
//! with its startup token, and dispatches tasks. It is intentionally thin: all
//! policy, taint tracking, and authority live in the daemon; this just moves
//! bytes and renders what comes back.
//!
//! # Discovery
//!
//! The client looks for the daemon in this order:
//!
//! 1. **Environment override** — `AGENTOS_SOCKET` (Unix socket path) or
//!    `AGENTOS_TCP_ADDR` (e.g. `127.0.0.1:54321`).
//! 2. **Unix socket** — `$XDG_RUNTIME_DIR/agentosd/agentosd.sock` or
//!    `/tmp/agentosd-<uid>/agentosd.sock` (the daemon writes its socket here).
//! 3. **TCP** — `127.0.0.1:54321` (the daemon's default port).
//!
//! The token file is always `$XDG_STATE_HOME/agentosd/auth.token` or
//! `~/.local/state/agentosd/auth.token`. The daemon writes it on startup.
//!
//! # Transport
//!
//! Both transports use the same length-prefixed JSON-RPC 2.0 framing as the
//! daemon: 4-byte big-endian length, then the JSON payload. The TCP transport
//! requires an `auth` frame first; the Unix transport does not (the kernel
//! enforces the socket's `0600` mode at connect time).
//!
//! # Errors
//!
//! Errors are returned as structured strings, never panicked. A connection
//! failure is distinct from an auth failure which is distinct from a task
//! refusal, so a script can distinguish them.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::daemon::protocol::{
    ExecuteParams as ProtoExecuteParams, Info, Request, Response, TaskOutcome, MAX_FRAME_BYTES,
};

use crate::daemon::auth::AuthParams;

/// Re-export the protocol types for CLI use.
pub use crate::daemon::protocol::{ExecuteParams, Grants};

/// Where to find the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEndpoint {
    /// Unix domain socket.
    Unix(PathBuf),
    /// TCP loopback.
    Tcp(SocketAddr),
}

/// The authentication token, read from the daemon's token file.
#[derive(Debug, Clone)]
pub struct AuthToken(String);

impl AuthToken {
    /// Read the token from the standard location.
    ///
    /// `$XDG_STATE_HOME/agentosd/auth.token` → `~/.local/state/agentosd/auth.token`
    /// Falls back to `~/.agentosd/auth.token`.
    pub fn read() -> Result<Self, String> {
        let path = Self::default_path()?;
        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "cannot read token file at {}: {}\n\
                 (the daemon writes this file on startup; is it running?)",
                path.display(), e
            )
        })?;
        let token = content.trim().to_string();
        if token.is_empty() {
            return Err(format!(
                "token file at {} is empty",
                path.display()
            ));
        }
        if token.len() != 64 {
            return Err(format!(
                "token file at {} has invalid length (expected 64 hex chars, got {})",
                path.display(),
                token.len()
            ));
        }
        if !token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "token file at {} contains non-hex characters",
                path.display()
            ));
        }
        Ok(AuthToken(token))
    }

    /// The default token file path.
    pub fn default_path() -> Result<PathBuf, String> {
        if let Ok(explicit) = std::env::var("AGENTOS_TOKEN_FILE") {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }

        let base = std::env::var("XDG_STATE_HOME")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".local").join("state"))
            })
            .unwrap_or_else(|| PathBuf::from(".agentosd"));

        Ok(base.join("agentosd").join("auth.token"))
    }

    /// The raw token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Discover the daemon's endpoint.
///
/// Order:
/// 1. `AGENTOS_SOCKET` → Unix socket
/// 2. `AGENTOS_TCP_ADDR` → TCP
/// 3. Unix socket at `$XDG_RUNTIME_DIR/agentosd/agentosd.sock` or `/tmp/agentosd-<pid>/agentosd.sock`
/// 4. TCP at `127.0.0.1:54321`
pub fn discover_endpoint() -> DaemonEndpoint {
    // 1. Explicit environment override
    if let Ok(path) = std::env::var("AGENTOS_SOCKET") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            eprintln!("agentos: discovered Unix socket via AGENTOS_SOCKET: {}", trimmed);
            return DaemonEndpoint::Unix(PathBuf::from(trimmed));
        }
    }
    if let Ok(addr) = std::env::var("AGENTOS_TCP_ADDR") {
        if let Ok(parsed) = addr.trim().parse::<SocketAddr>() {
            eprintln!("agentos: discovered TCP address via AGENTOS_TCP_ADDR: {}", parsed);
            return DaemonEndpoint::Tcp(parsed);
        }
    }

    // 2. Unix socket in standard locations
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/agentosd-{}", std::process::id())));

    let sock_path = runtime_dir.join("agentosd.sock");
    if sock_path.exists() {
        eprintln!("agentos: discovered Unix socket at {}", sock_path.display());
        return DaemonEndpoint::Unix(sock_path);
    }

    // 3. Default TCP
    eprintln!("agentos: using default TCP address 127.0.0.1:54321");
    DaemonEndpoint::Tcp("127.0.0.1:54321".parse().unwrap())
}

/// A connected client session.
pub struct Client {
    stream: ClientStream,
    endpoint: DaemonEndpoint,
    needs_auth: bool,
}

#[cfg(unix)]
enum ClientStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

#[cfg(not(unix))]
enum ClientStream {
    Tcp(TcpStream),
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            ClientStream::Unix(s) => s.read(buf),
            ClientStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            ClientStream::Unix(s) => s.write(buf),
            ClientStream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            ClientStream::Unix(s) => s.flush(),
            ClientStream::Tcp(s) => s.flush(),
        }
    }
}

impl Client {
    /// Connect to the daemon and authenticate if needed.
    pub fn connect(endpoint: DaemonEndpoint, token: Option<AuthToken>) -> Result<Self, String> {
        let needs_auth = matches!(endpoint, DaemonEndpoint::Tcp(_));

        if needs_auth && token.is_none() {
            return Err(
                "the daemon requires authentication on TCP, but no token was provided\n\
                 (run the daemon with a Unix socket to avoid this, or provide the token)"
                    .to_string(),
            );
        }

        eprintln!("agentos: connecting to {}", match &endpoint {
            DaemonEndpoint::Unix(p) => format!("Unix socket {}", p.display()),
            DaemonEndpoint::Tcp(a) => format!("TCP {}", a),
        });

        let stream = match &endpoint {
            #[cfg(unix)]
            DaemonEndpoint::Unix(path) => {
                let stream = UnixStream::connect(path).map_err(|e| {
                    format!(
                        "could not connect to daemon at {}: {}",
                        path.display(),
                        e
                    )
                })?;
                ClientStream::Unix(stream)
            }
            #[cfg(not(unix))]
            DaemonEndpoint::Unix(_) => {
                return Err("Unix sockets are not supported on this platform".to_string());
            }
            DaemonEndpoint::Tcp(addr) => {
                let stream = TcpStream::connect_timeout(addr, Duration::from_secs(5)).map_err(|e| {
                    format!(
                        "could not connect to daemon at {}: {}",
                        addr,
                        e
                    )
                })?;
                stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
                ClientStream::Tcp(stream)
            }
        };

        eprintln!("agentos: connected, authenticating={}", needs_auth);

        let mut client = Self {
            stream,
            endpoint,
            needs_auth,
        };

        // Authenticate on TCP
        if needs_auth {
            client.authenticate(token.unwrap())?;
        }

        Ok(client)
    }

    /// Return a human-readable description of the endpoint.
    pub fn endpoint_str(&self) -> Option<String> {
        match &self.endpoint {
            DaemonEndpoint::Unix(p) => Some(format!("Unix socket {}", p.display())),
            DaemonEndpoint::Tcp(a) => Some(format!("TCP {}", a)),
        }
    }

    /// Send the `auth` frame and verify the response.
    fn authenticate(&mut self, token: AuthToken) -> Result<(), String> {
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(0),
            method: "auth".to_string(),
            params: serde_json::to_value(AuthParams {
                token: token.0,
            })
            .unwrap(),
        };
        eprintln!("agentos: sending auth frame");
        self.send_frame(&req).map_err(|e| format!("failed to send auth: {e}"))?;

        eprintln!("agentos: waiting for auth response");
        let resp = self.recv_frame().map_err(|e| format!("failed to read auth response: {e}"))?;

        eprintln!("agentos: auth response received: error={:?}", resp.error);

        if let Some(error) = resp.error {
            return Err(format!(
                "authentication failed: {} (code {})",
                error.message, error.code
            ));
        }

        eprintln!("agentos: authentication successful");
        Ok(())
    }

    /// Dispatch a task and return the outcome.
    ///
    /// The task text comes from `params.task` rather than a separate argument. An
    /// earlier version took both, which meant two copies of the task text that a
    /// caller could disagree about -- and disagreeing copies are how a client ends
    /// up showing the user one task and sending another.
    pub fn execute(&mut self, params: ProtoExecuteParams) -> Result<TaskOutcome, String> {
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: "execute".to_string(),
            params: serde_json::to_value(params).unwrap(),
        };
        self.send_frame(&req).map_err(|e| format!("failed to send execute: {e}"))?;

        let resp = self.recv_frame().map_err(|e| format!("failed to read execute response: {e}"))?;

        if let Some(error) = resp.error {
            return Err(format!(
                "task failed: {} (code {})",
                error.message, error.code
            ));
        }

        let result: TaskOutcome = serde_json::from_value(resp.result.unwrap())
            .map_err(|e| format!("failed to parse task result: {e}"))?;
        Ok(result)
    }

    /// Query daemon info.
    pub fn info(&mut self) -> Result<Info, String> {
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(2),
            method: "info".to_string(),
            params: serde_json::json!({}),
        };
        self.send_frame(&req).map_err(|e| format!("failed to send info: {e}"))?;

        let resp = self.recv_frame().map_err(|e| format!("failed to read info response: {e}"))?;

        if let Some(error) = resp.error {
            return Err(format!(
                "info failed: {} (code {})",
                error.message, error.code
            ));
        }

        let info: Info = serde_json::from_value(resp.result.unwrap())
            .map_err(|e| format!("failed to parse info: {e}"))?;
        Ok(info)
    }

    /// Send a single JSON-RPC frame.
    fn send_frame(&mut self, req: &Request) -> io::Result<()> {
        let body = serde_json::to_vec(req)?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("request exceeds {} bytes", MAX_FRAME_BYTES),
            ));
        }
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        self.stream.write_all(&framed)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive a single JSON-RPC frame.
    fn recv_frame(&mut self) -> io::Result<Response> {
        let mut head = [0u8; 4];
        self.stream.read_exact(&mut head)?;
        let len = u32::from_be_bytes(head) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response exceeds {} bytes", MAX_FRAME_BYTES),
            ));
        }
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body)?;
        let resp: Response = serde_json::from_slice(&body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(resp)
    }
}

/// Render a task outcome for human consumption.
pub fn render_outcome(result: TaskOutcome) -> String {
    use crate::daemon::protocol::TaskOutcome::*;
    match result {
        Completed { reports } => {
            let mut out = "done.\n".to_string();
            for r in reports {
                out.push_str(&format!("  {}\n", r));
            }
            out
        }
        Refused { op } => {
            format!("refused: {}\nnothing was sent or written.\n", op)
        }
        NeedsHuman { op, rendered } => {
            format!(
                "needs human approval: {}\n{}\n(run interactively to approve)\n",
                op.join(", "),
                rendered
            )
        }
        ConfirmationLimit { asked } => {
            format!(
                "stopped after {} confirmation(s); the loop gave up.\nthis is NOT a refusal -- no decision was made.\n",
                asked
            )
        }
        Failed { message, policy_denied } => {
            let mut out = format!("stopped: {}\n", message);
            if policy_denied {
                out.push_str("  refused by policy, with no human involved.\n");
            }
            out
        }
    }
}

/// Send a request over the wire and print the outcome.
///
/// Returns the exit code the CLI should use.
pub fn dispatch(params: ProtoExecuteParams) -> Result<std::process::ExitCode, String> {
    let endpoint = discover_endpoint();
    let token = if matches!(endpoint, DaemonEndpoint::Tcp(_)) {
        Some(AuthToken::read()?)
    } else {
        None
    };

    let mut client = Client::connect(endpoint, token)?;

    // Print the endpoint we're using
    match &client.endpoint {
        DaemonEndpoint::Unix(p) => eprintln!("agentos: connected via Unix socket {}", p.display()),
        DaemonEndpoint::Tcp(a) => eprintln!("agentos: connected via TCP {}", a),
    }

    let result = client.execute(params)?;
    let exit_code = match &result {
        TaskOutcome::Completed { .. } => std::process::ExitCode::SUCCESS,
        TaskOutcome::Refused { .. } => std::process::ExitCode::from(3),
        TaskOutcome::NeedsHuman { .. } => std::process::ExitCode::from(4),
        TaskOutcome::ConfirmationLimit { asked: _ } => std::process::ExitCode::from(5),
        TaskOutcome::Failed { policy_denied, .. } => {
            if *policy_denied {
                std::process::ExitCode::from(1)
            } else {
                std::process::ExitCode::from(2)
            }
        }
    };
    print!("{}", render_outcome(result));
    Ok(exit_code)
}

/// Check if the daemon is reachable and report its status.
pub fn check() -> Result<std::process::ExitCode, String> {
    let endpoint = discover_endpoint();
    let token = if matches!(endpoint, DaemonEndpoint::Tcp(_)) {
        Some(AuthToken::read()?)
    } else {
        None
    };

    let mut client = Client::connect(endpoint, token)?;

    eprint!("AgentOS daemon status\n\n");
    match &client.endpoint {
        DaemonEndpoint::Unix(p) => eprintln!("endpoint: Unix socket {}", p.display()),
        DaemonEndpoint::Tcp(a) => eprintln!("endpoint: TCP {}", a),
    }

    let info = client.info()?;
    eprintln!("model: {}", info.model);
    eprintln!("protocol: {}", info.protocol);
    eprintln!("max concurrent tasks: {}", info.max_concurrent_tasks);
    eprintln!("requires auth: {}", if info.requires_auth { "yes" } else { "no" });
    eprintln!("send_email enabled: {}", if info.send_email_enabled { "yes" } else { "no" });
    let write_roots = if info.write_roots.is_empty() { "none".to_string() } else { info.write_roots.join(", ") };
    let allowed_hosts = if info.allowed_hosts.is_empty() { "none".to_string() } else { info.allowed_hosts.join(", ") };
    eprintln!("write roots: {}", write_roots);
    eprintln!("allowed hosts: {}", allowed_hosts);
    eprintln!("\nlimitations:");
    for lim in &info.limitations {
        eprintln!("  - {}", lim);
    }

    Ok(std::process::ExitCode::SUCCESS)
}

/// Implement the REPL's transport trait for the real client.
///
/// This is the only place the REPL talks to the daemon, so the trait
/// implementation is the contract between the interactive loop and the
/// wire protocol.
impl crate::repl::Transport for Client {
    fn execute(
        &mut self,
        params: crate::repl::ExecuteParams,
    ) -> Result<crate::daemon::protocol::TaskOutcome, crate::repl::TransportError> {
        // Convert the REPL's params to the wire protocol's params
        let wire_params = ProtoExecuteParams {
            task: params.task,
            grants: params.grants,
            timeout_secs: params.timeout_secs,
        };
        self.execute(wire_params)
            .map_err(crate::repl::TransportError::Refused)
    }

    fn info(&mut self) -> Result<crate::daemon::protocol::Info, crate::repl::TransportError> {
        self.info().map_err(crate::repl::TransportError::Refused)
    }

    fn reconnect(&mut self) -> Result<(), crate::repl::TransportError> {
        // Rebuild the connection from scratch. A new socket has no memory of
        // the old handshake, so we must re-authenticate on TCP.
        let token = if matches!(self.endpoint, DaemonEndpoint::Tcp(_)) {
            Some(crate::client::AuthToken::read().map_err(|e| {
                crate::repl::TransportError::Refused(format!("could not read token: {e}"))
            })?)
        } else {
            None
        };
        *self = Client::connect(self.endpoint.clone(), token)
            .map_err(crate::repl::TransportError::Disconnected)?;
        Ok(())
    }
}