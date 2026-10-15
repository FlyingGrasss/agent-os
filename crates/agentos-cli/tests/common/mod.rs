//! Shared fixtures for the benchmarks and the concurrency stress test.
//!
//! Not a test target itself. Every helper here exists because two callers would
//! otherwise each write a slightly different one, and a stress test whose
//! fixture differs from the benchmark's measures a different system than the one
//! the benchmark reported.

// Each integration target and each bench is compiled as its own crate and
// `include`s this module, so every target sees the whole surface while using a
// subset of it. `ipc_throughput` never writes a file and never computes
// percentiles; `concurrent_dispatch` never measures framing. That is the point of
// sharing, so the unused-in-this-target warnings are noise rather than signal.
#![allow(dead_code)]
//!
//! # The model is replayed, not mocked around
//!
//! `daemon::entry_point` builds a real Ollama backend and refuses to start unless
//! the model is pulled, so it cannot run on a machine that is not a developer's
//! laptop — and a benchmark that needs a 2 GB model download is not a benchmark,
//! it is a slow test with worse error messages. [`Replay`] returns a fixed plan
//! instead, which keeps the real path under measurement: framing, auth, grants,
//! the interpreter, policy, the audit sink and its `sync_data`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use agentos_cli::daemon::auth;
use agentos_cli::daemon::executor::{SharedClock, SharedSink};
use agentos_cli::daemon::grants::Ceiling;
use agentos_cli::daemon::protocol::ExecuteParams;
use agentos_cli::daemon::{listener, protocol, state};
use agentos_infer::{Backend, Completion, Conversation, InferError, Output, Role, Usage};
use agentos_tools::audit::{Clock, FileSink, SystemClock};
use agentos_types::{ControllerAuthority, Origin, Trusted};

/// A backend that replays a fixed plan.
pub struct Replay {
    plan: String,
    calls: Arc<Mutex<usize>>,
}

impl Replay {
    /// A plan that only reports. Fastest path through the daemon: no tool, no
    /// policy decision, no audit record. Useful for isolating IPC cost.
    pub fn reporting() -> Self {
        Self {
            plan: r#"{"program":[{"op":"let","name":"w","value":"\"hi\""},{"op":"report","value":"w"}]}"#
                .to_string(),
            calls: Arc::new(Mutex::new(0)),
        }
    }

    /// A plan that invokes `fs.write` with planner-authored literals.
    ///
    /// Both arguments are `Trusted`, and `PolicyEngine::evaluate` skips untainted
    /// arguments outright, so this runs without the untrusted document that
    /// `extract` would require — which is unreachable without a network fetch.
    /// Each execution therefore produces one attempt and one outcome record,
    /// which is what makes the audit ledger a useful thing to stress.
    ///
    /// The result is deliberately not reported: a tool's return value is tainted
    /// and the pager rightly refuses to put it in a prompt. The write has already
    /// happened by the time the `let` binds.
    pub fn writing(file: &str) -> Self {
        Self {
            plan: format!(
                r#"{{"program":[
                     {{"op":"let","name":"p","value":"\"{file}\""}},
                     {{"op":"let","name":"c","value":"\"bench\""}},
                     {{"op":"let","name":"r","value":"fs.write(path = p, contents = c)"}}]}}"#
            ),
            calls: Arc::new(Mutex::new(0)),
        }
    }

    /// How many times the planner was asked for a plan.
    pub fn calls(&self) -> usize {
        *self.calls.lock().expect("counter")
    }
}

impl Backend for Replay {
    fn complete(&mut self, role: Role, _c: &Conversation) -> Result<Completion, InferError> {
        *self.calls.lock().expect("counter") += 1;
        let _ = role;
        Ok(Completion {
            output: Output::PlannerText(Trusted::inherited(
                Origin::Controller(ControllerAuthority::issue()),
                self.plan.clone(),
            )),
            usage: Usage::default(),
        })
    }

    fn supports_constrained_decoding(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        "replay"
    }
}

/// A clock that never advances, so records are byte-identical across runs.
///
/// Two reasons. Latency numbers are meaningless if every run writes different
/// bytes, and a `FileSink` under stress should be doing identical work each time
/// rather than varying with how long the run has been going.
pub struct Frozen(u64);

impl Clock for Frozen {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

/// A running daemon plus everything needed to talk to it.
pub struct Harness {
    pub addr: std::net::SocketAddr,
    pub token_hex: String,
    pub audit_log: PathBuf,
    pub dir: PathBuf,
    /// The one directory tasks may write to. Derived from `dir` so it cannot
    /// drift from the ceiling the daemon was built with.
    write_root: PathBuf,
    accept: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Start on an ephemeral loopback port with authentication required, which is
    /// what every TCP deployment does and therefore what has to be measured.
    ///
    /// Takes the directory rather than making one. An earlier version called
    /// `scratch_dir` internally and separately built a ceiling from another call,
    /// and because `scratch_dir` allocates a fresh numbered directory each time,
    /// the ceiling permitted one path while the tasks requested another -- every
    /// task came back `GRANT_DENIED`. The harness owns one directory and derives
    /// everything from it.
    pub async fn start(
        dir: PathBuf,
        backend: Box<dyn Backend + Send>,
        max_concurrent: usize,
    ) -> Self {
        let write_root = dir.join("out");
        let ceiling = write_ceiling(&write_root);

        let token = auth::Token::generate().expect("token");
        let token_hex = token.to_hex();

        // A real file, so the audit sink's locking and `sync_data` are genuinely
        // in the measured path. An in-memory sink would measure everything except
        // the thing this test exists to stress.
        let audit_log = dir.join("audit.log");
        let sink: SharedSink = Arc::new(Mutex::new(FileSink::open(&audit_log).expect("sink")));
        let clock: SharedClock = Arc::new(Mutex::new(Frozen(1_700_000_000_000)));

        let l = listener::bind_tcp("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("bind loopback");
        let addr = l.local_addr().expect("local addr");

        let st = Arc::new(state::DaemonState::new(
            ceiling,
            backend,
            sink,
            clock,
            "replay-model".to_string(),
            max_concurrent,
            token,
            true,
        ));
        let accept = tokio::spawn(async move {
            let _ = listener::accept_tcp(l, st).await;
        });

        Self {
            addr,
            token_hex,
            audit_log,
            write_root,
            dir,
            accept,
        }
    }

    /// The only directory tasks may write to.
    pub fn write_root(&self) -> &std::path::Path {
        &self.write_root
    }

    /// The raw bytes currently in the ledger.
    pub fn ledger(&self) -> String {
        std::fs::read_to_string(&self.audit_log).unwrap_or_default()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.accept.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A scratch directory unique to this process and this call site.
pub fn scratch_dir(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentos-bench-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A permissive ceiling that permits exactly one write root and no network.
pub fn write_ceiling(root: &std::path::Path) -> Ceiling {
    let _ = std::fs::create_dir_all(root);
    Ceiling {
        write_roots: vec![root.to_path_buf()],
        allowed_hosts: Vec::new(),
        mail_outbox: None,
    }
}

/// An `execute` request as raw JSON, for the hand-rolled load generator.
pub fn execute_params(task: &str, write_root: &std::path::Path) -> ExecuteParams {
    ExecuteParams {
        task: task.to_string(),
        grants: protocol::Grants {
            hosts: Vec::new(),
            write_roots: vec![write_root.to_string_lossy().into_owned()],
            send_email: false,
        },
        timeout_secs: 30,
    }
}

/// Percentiles from a latency sample, sorted ascending.
///
/// `nearest-rank`, so the answer is always a measurement that actually happened
/// rather than an interpolation between two that did not. At the sizes these
/// tests run at, the difference does not matter; reporting a number nobody
/// observed would matter more.
pub fn percentiles(mut samples_us: Vec<u128>) -> Percentiles {
    samples_us.sort_unstable();
    let pick = |q: f64| -> u128 {
        if samples_us.is_empty() {
            return 0;
        }
        let rank = (q * samples_us.len() as f64).ceil() as usize;
        samples_us[rank.clamp(1, samples_us.len()) - 1]
    };
    Percentiles {
        count: samples_us.len(),
        p50: pick(0.50),
        p95: pick(0.95),
        p99: pick(0.99),
        max: samples_us.last().copied().unwrap_or(0),
    }
}

/// Latency distribution, in microseconds.
#[derive(Debug, Clone, Copy)]
pub struct Percentiles {
    pub count: usize,
    pub p50: u128,
    pub p95: u128,
    pub p99: u128,
    pub max: u128,
}

impl std::fmt::Display for Percentiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n={} p50={}us p95={}us p99={}us max={}us",
            self.count, self.p50, self.p95, self.p99, self.max
        )
    }
}

/// Frame a payload the way the daemon does, using the daemon's own encoder.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    listener::encode_frame(payload).expect("frame").to_vec()
}

/// The `auth` frame a client sends first.
pub fn auth_frame(token_hex: &str) -> Vec<u8> {
    frame(
        &serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": auth::AUTH_METHOD,
            "params": { "token": token_hex }
        }))
        .expect("serialise auth"),
    )
}

/// A framed JSON-RPC request.
pub fn request_frame(method: &str, params: serde_json::Value, id: u64) -> Vec<u8> {
    frame(
        &serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .expect("serialise request"),
    )
}

/// Read exactly one frame from a blocking stream.
///
/// Blocking rather than async because the load generator drives many OS threads
/// on purpose: this measures what the daemon does when 50 processes really do
/// connect at once, which is not the same shape as 50 tasks on one runtime.
pub fn read_frame(stream: &mut std::net::TcpStream) -> Option<serde_json::Value> {
    use std::io::Read;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes(head) as usize;
    assert!(
        len <= protocol::MAX_FRAME_BYTES,
        "daemon announced an oversized frame: {len}"
    );
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

/// Complete the handshake over a fresh blocking connection.
pub fn connect_authenticated(addr: std::net::SocketAddr, token_hex: &str) -> std::net::TcpStream {
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();
    use std::io::Write;
    stream.write_all(&auth_frame(token_hex)).expect("send auth");
    let reply = read_frame(&mut stream).expect("auth reply");
    assert!(
        reply.get("error").is_none(),
        "handshake refused: {reply}"
    );
    stream
}

/// The `SystemClock`, so callers that do not want determinism can have it.
pub fn system_clock() -> SharedClock {
    Arc::new(Mutex::new(SystemClock))
}