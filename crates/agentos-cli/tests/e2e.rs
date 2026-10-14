//! End-to-end integration tests: a real daemon, a real socket, a real inbox.
//!
//! # Why this file exists and why it is shaped this way
//!
//! The unit tests elsewhere pin individual pieces. This file starts the actual
//! daemon state on an ephemeral loopback port, speaks the actual wire protocol
//! over an actual socket, drops actual files into an actual inbox directory, and
//! then verifies the ledger those runs wrote. A regression that only shows up
//! when those are connected -- the auth gate living in the wrong layer, the
//! chain head not surviving a reopen, an inbox payload archived without ever
//! reaching the sink -- is invisible to every other test in the workspace.
//!
//! # The one thing this file deliberately does not do
//!
//! It does **not** reach `TaskOutcome::NeedsHuman` through the socket, because
//! that path is not reachable on this machine and pretending otherwise would
//! mean asserting something weaker than it looks.
//!
//! Reaching it needs a tainted value in a sensitive argument, and inside
//! `run_task` the only source of taint is `extract`, which
//! [`ModelExtractor`](agentos_core::extract::ModelExtractor) accepts only from an
//! *untrusted* document. The sole producer of an untrusted document is
//! `http.get`. And `http.get` cannot be aimed at a test server here:
//!
//! * `address_is_routable` rejects loopback, and `agentos-tools/src/http.rs`
//!   says so explicitly -- listing `127.0.0.1` in a grant does **not** make it
//!   fetchable, which is correct SSRF defence and not a gap to route around.
//! * `TcpTransport` refuses `https` outright, because there is no TLS here.
//!
//! So a live fetch would need the public internet plus a model. A test that
//! depended on either would be slow, flaky, and would stop testing this code if
//! either moved. Instead the confirmation gate is covered where it is actually
//! load-bearing, and the claim is asserted directly:
//!
//! * **Over the real socket:** an `approve` method does not exist, so authority
//!   cannot cross the wire at all. This is the stronger statement, and it is
//!   checked behaviourally rather than by reading the protocol module.
//! * **Over a real REPL:** a halt renders as an approval request, and answering
//!   `y` re-submits the *person's own words* as a new task instead of granting
//!   anything.
//!
//! If the daemon ever grows an unauthenticated-document source (a pipe, a
//! plugin, a loopback exemption), the socket test should grow a `NeedsHuman`
//! case. The comment belongs here so nobody adds one that quietly no-ops.

// ---------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A private directory that removes itself, however the test ends.
///
/// `Drop` rather than an explicit teardown call, because a test that fails an
/// assertion panics before reaching its cleanup line, and a harness that leaks a
/// socket directory or an inbox full of stale payloads on failure turns one
/// broken run into a permanently flaky suite.
///
/// Keyed on the process id *and* a per-instance counter: two harnesses alive at
/// once in one process (cargo runs test binaries in parallel threads) would
/// otherwise share a directory and silently cross-contaminate each other's
/// inboxes.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "agentos-e2e-{name}-{}-{n}",
            std::process::id()
        ));
        // Start from a clean slate: a leftover directory from a killed previous
        // run would make the inbox settle-rule tests observe stale files.
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch dir");
        Self { root }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, contents: &str) {
        let path = self.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dir");
        }
        std::fs::write(&path, contents).expect("write file");
    }

    fn entries_in(&self, rel: &str) -> Vec<String> {
        let dir = self.join(rel);
        let mut names: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// Names in a directory, ignoring the inbox's own bookkeeping subdirectories.
    ///
    /// `processed/` and `deferred/` live *inside* the watched root, so a naive
    /// listing of "what is left" always finds them and would make this assertion
    /// about the wrong thing.
    fn entries_except_inbox_dirs(&self, rel: &str) -> Vec<String> {
        self.entries_in(rel)
            .into_iter()
            .filter(|n| n != "processed" && n != "deferred")
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Serialises the tests that read the process environment.
///
/// `std::env::set_var` is process-global, so two tests doing it concurrently can
/// read each other's values -- which is precisely how an env test ends up
/// asserting on a variable the *other* test set. One lock, held for the whole
/// read-modify-restore.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `body` with `pairs` set, restoring the previous state exactly -- including
/// the difference between "unset" and "set to empty".
fn with_env<T>(pairs: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let saved: Vec<(String, Option<String>)> = pairs
        .iter()
        .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
        .collect();
    for (key, value) in pairs {
        std::env::set_var(key, value);
    }
    let outcome = body();
    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(&key, v),
            None => std::env::remove_var(&key),
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

use agentos_infer::{Backend, Completion, Conversation, InferError, Output, Role, Usage};
use agentos_types::{ControllerAuthority, Origin, Trusted};

/// A backend that replays a fixed planner answer.
///
/// `entry_point` builds a real Ollama backend and refuses to start unless the
/// model is pulled, which makes it unusable in a test on any machine that is not
/// a developer's laptop. Replaying the planner's response keeps the whole
/// pipeline from `Session` through policy and out to the audit log under test,
/// and removes the one dependency that cannot be made hermetic here.
///
/// Two roles, not one: the planner asks for a plan, the extractor asks for
/// structure out of a document. Answering both keeps a future plan that uses
/// `extract` from failing for a reason that has nothing to do with the test.
struct Replay {
    plan: String,
    extraction: String,
}

impl Replay {
    fn planning(plan: &str) -> Self {
        Self {
            plan: plan.to_string(),
            extraction: r#"{"text":"replayed"}"#.to_string(),
        }
    }

    /// A plan that reports a literal and touches nothing. Needs no grant, so it
    /// runs to completion without a model, a network, or a filesystem write.
    fn harmless() -> Self {
        Self::planning(
            r#"{"program":[
                 {"op":"let","name":"w","value":"\"hello\""},
                 {"op":"report","value":"w"}]}"#,
        )
    }

    /// A plan that writes a real file through the real `fs.write` tool.
    ///
    /// Needed by the audit test because *audit records are written per tool
    /// call*. A plan that only `report`s registers no tool, invokes no tool, and
    /// therefore writes nothing to the ledger -- so an audit test built on
    /// `harmless()` would be asserting that an empty file verifies, which says
    /// nothing about the chain.
    ///
    /// Both arguments are planner-authored literals, so they are `Trusted` and
    /// policy never halts on them (`PolicyEngine::evaluate` skips untainted
    /// arguments outright). That is what keeps the write reachable without the
    /// tainted document `extract` would need.
    ///
    /// The result is deliberately *not* reported: a tool's return value carries a
    /// label, and reporting one puts it in a Controller prompt, which the pager
    /// rightly refuses. The write has already happened by the time the `let`
    /// binds, so the omission costs the test nothing.
    fn writing(contents: &str) -> Self {
        Self::planning(&format!(
            r#"{{"program":[
                 {{"op":"let","name":"p","value":"\"e2e-outcome.txt\""}},
                 {{"op":"let","name":"c","value":"\"{contents}\""}},
                 {{"op":"let","name":"r","value":"fs.write(path = p, contents = c)"}}]}}"#
        ))
    }
}

impl Backend for Replay {
    fn complete(&mut self, role: Role, _c: &Conversation) -> Result<Completion, InferError> {
        let text = match role {
            Role::Planner => self.plan.clone(),
            _ => self.extraction.clone(),
        };
        Ok(Completion {
            output: Output::PlannerText(Trusted::inherited(
                Origin::Controller(ControllerAuthority::issue()),
                text,
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

// ---------------------------------------------------------------------------
// The daemon
// ---------------------------------------------------------------------------

use agentos_cli::daemon::executor::{SharedClock, SharedSink};
use agentos_cli::daemon::grants::Ceiling;
use agentos_cli::daemon::{auth, listener, protocol, state};
use agentos_tools::audit::{FileSink, SystemClock};

/// A running daemon: its address, its token, its audit path, and the accept task.
///
/// Dropping this aborts the accept loop and removes the scratch directory, so a
/// failed assertion cannot leave a listener running or a token on disk.
struct Daemon {
    addr: std::net::SocketAddr,
    token_hex: String,
    audit_log: PathBuf,
    token_file: PathBuf,
    _scratch: Scratch,
    accept: tokio::task::JoinHandle<()>,
}

impl Daemon {
    /// Start a daemon on an ephemeral loopback port.
    ///
    /// Port 0 rather than a fixed port so parallel test binaries cannot collide,
    /// and `127.0.0.1` rather than `0.0.0.0` so nothing leaves the machine --
    /// `bind_tcp` refuses anything else anyway, which is the point of checking
    /// that it does.
    async fn start(name: &str, ceiling: Ceiling, backend: Box<dyn Backend + Send>) -> Self {
        let scratch = Scratch::new(name);

        // The token is generated, written where a client would find it, and read
        // back -- so the file round-trip is exercised rather than bypassed.
        // `TokenFile::write` uses `create_new`, so the path must not exist.
        let token_file = scratch.join("agentosd/auth.token");
        let token = auth::Token::generate().expect("generate token");
        let tf = auth::TokenFile::new(&token_file);
        tf.write(&token).expect("write token file");
        let read_back = tf.read().expect("read token file");
        assert!(
            token.matches(&read_back),
            "the token did not survive its own file round-trip"
        );

        // A real file sink, so the audit chain is written to a real path and can be
        // verified the way an operator would verify it.
        let audit_log = scratch.join("audit.log");
        let sink: SharedSink = Arc::new(Mutex::new(FileSink::open(&audit_log).expect("audit sink")));
        let clock: SharedClock = Arc::new(Mutex::new(SystemClock));

        let listener = listener::bind_tcp("127.0.0.1:0".parse().expect("loopback addr"))
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        assert!(addr.ip().is_loopback(), "the daemon must not be reachable off-host");

        let daemon_state = Arc::new(state::DaemonState::new(
            ceiling,
            backend,
            sink,
            clock,
            "replay-model".to_string(),
            2,
            token.clone(),
            true, // require auth, as every TCP deployment does
        ));

        let accept = tokio::spawn(async move {
            let _ = listener::accept_tcp(listener, daemon_state).await;
        });

        Self {
            addr,
            token_hex: token.to_hex(),
            audit_log,
            token_file,
            _scratch: scratch,
            accept,
        }
    }

    /// The token exactly as it sits on disk, for the client to read.
    fn token_on_disk(&self) -> String {
        std::fs::read_to_string(&self.token_file)
            .expect("token file")
            .trim()
            .to_string()
    }

    /// Verify the ledger this daemon wrote, through the same routine the CLI uses.
    fn verify_ledger(&self) -> Result<agentos_tools::chain::Verification, String> {
        let text = std::fs::read_to_string(&self.audit_log).map_err(|e| e.to_string())?;
        agentos_tools::chain::verify(&text).map_err(|f| f.to_string())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.accept.abort();
        // `_scratch` drops after this body and removes the directory, so ordering
        // is: stop listening, then delete the socket/token/log underneath it.
    }
}

// ---------------------------------------------------------------------------
// A hand-rolled client
// ---------------------------------------------------------------------------

/// Why not `agentos_cli::client::Client`?
///
/// Two reasons, and the second is the important one. `Client` is the right tool
/// for proving the *client* works, and one test below uses it for exactly that.
/// But `Client` resolves its endpoint and token through process environment
/// variables, so every assertion made through it would be serialised behind
/// `ENV_LOCK` and would be testing discovery rather than the daemon. Speaking
/// the protocol directly keeps the daemon under test and keeps the tests
/// parallel.
struct Raw {
    stream: tokio::net::TcpStream,
}

impl Raw {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        Self { stream }
    }

    async fn send(&mut self, payload: serde_json::Value) {
        use tokio::io::AsyncWriteExt;
        let body = serde_json::to_vec(&payload).expect("serialise");
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        self.stream.write_all(&framed).await.expect("write frame");
        self.stream.flush().await.expect("flush");
    }

    /// Read one response frame, or `None` if the peer closed without sending one.
    ///
    /// A daemon that hangs up instead of answering is itself an answer, so this
    /// must be able to say "nothing came back" rather than blocking forever.
    async fn recv(&mut self) -> Option<serde_json::Value> {
        use tokio::io::AsyncReadExt;
        let mut head = [0u8; 4];
        self.stream.read_exact(&mut head).await.ok()?;
        let len = u32::from_be_bytes(head) as usize;
        assert!(
            len <= protocol::MAX_FRAME_BYTES,
            "daemon announced an oversized frame: {len}"
        );
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await.ok()?;
        serde_json::from_slice(&body).ok()
    }

    /// Complete the handshake, then hand back a ready client.
    async fn authenticate(addr: std::net::SocketAddr, token_hex: &str) -> Self {
        let mut c = Self::connect(addr).await;
        c.send(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": auth::AUTH_METHOD,
            "params": { "token": token_hex }
        }))
        .await;
        let reply = c.recv().await.expect("auth reply");
        assert!(
            reply.get("error").is_none(),
            "handshake was refused: {reply}"
        );
        c
    }

    /// Send one request and return the response frame.
    async fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": method,
            "params": params
        }))
        .await;
        self.recv()
            .await
            .expect("daemon closed without answering")
    }
}

/// A grants object for a task that asks for nothing.
fn no_grants() -> protocol::Grants {
    protocol::Grants::default()
}

// ---------------------------------------------------------------------------
// 1. A daemon answers over a real, authenticated socket
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_daemon_answers_ping_and_info_over_authenticated_ipc() {
    let d = Daemon::start("auth-ok", Ceiling::deny_all(), Box::new(Replay::harmless())).await;

    let mut c = Raw::authenticate(d.addr, &d.token_hex).await;

    let pong = c.call(protocol::method::PING, serde_json::json!({})).await;
    assert_eq!(pong["result"]["pong"], serde_json::json!(true));

    let info = c.call(protocol::method::INFO, serde_json::json!({})).await;
    assert_eq!(info["result"]["protocol"], serde_json::json!(protocol::PROTOCOL_VERSION));
    assert_eq!(info["result"]["model"], serde_json::json!("replay-model"));
    // The gate the auth handshake exists to protect is reported honestly, and the
    // daemon's own inability to ask a human is stated rather than implied.
    // `Info` carries no `rename_all`, so these keys are snake_case on the wire.
    assert_eq!(info["result"]["requires_auth"], serde_json::json!(true));
    assert_eq!(info["result"]["can_ask_human"], serde_json::json!(false));
    let limits = info["result"]["limitations"]
        .as_array()
        .expect("limitations is an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<String>();
    assert!(limits.contains("cannot ask a person"), "{limits}");
}

#[tokio::test]
async fn the_audit_ledger_a_real_run_wrote_verifies() {
    let scratch = Scratch::new("audit-write");
    let write_root = scratch.join("out");
    std::fs::create_dir_all(&write_root).expect("write root");
    let root_str = write_root.to_string_lossy().into_owned();

    let ceiling = Ceiling {
        write_roots: vec![write_root.clone()],
        allowed_hosts: Vec::new(),
        mail_outbox: None,
    };
    let d = Daemon::start(
        "audit",
        ceiling,
        Box::new(Replay::writing("recorded")),
    )
    .await;

    let mut c = Raw::authenticate(d.addr, &d.token_hex).await;
    let reply = c
        .call(
            protocol::method::EXECUTE,
            serde_json::to_value(protocol::ExecuteParams {
                // The task text is what the intent pins are built from, so it has
                // to actually describe the write. Pinning from a request that did
                // not ask for the effect would refuse it, correctly.
                task: "write the file e2e-outcome.txt".into(),
                grants: protocol::Grants {
                    write_roots: vec![root_str.clone()],
                    ..protocol::Grants::default()
                },
                timeout_secs: 5,
            })
            .unwrap(),
        )
        .await;

    assert_eq!(
        reply["result"]["kind"],
        serde_json::json!("completed"),
        "the run should have completed: {reply}"
    );
    // The tool really ran, in the real directory. Asserting only the outcome kind
    // would pass even if `fs.write` had been skipped and the plan misreported.
    assert_eq!(
        std::fs::read_to_string(write_root.join("e2e-outcome.txt")).ok(),
        Some("recorded".to_string()),
        "the write did not happen"
    );

    // Drop the client and the daemon's accept loop before reading, so nothing can
    // append a record halfway through verification and make a good log look broken.
    drop(c);
    d.accept.abort();

    let verified = d
        .verify_ledger()
        .expect("the ledger a real run wrote must verify");
    assert!(
        verified.records > 0,
        "a run that invoked a tool wrote no audit records"
    );
    assert_ne!(verified.head, agentos_tools::chain::genesis());

    // And the tamper check is real, on this exact ledger: editing one byte of one
    // historical record must break it. Without this, "verified" only proves the
    // file is self-consistent, which a verifier that always returned Ok would too.
    let text = std::fs::read_to_string(&d.audit_log).unwrap();
    let mut tampered = text.clone().into_bytes();
    let at = text.find("e2e-outcome.txt").expect("the tool name is in the record");
    tampered[at] ^= 0x01;
    let tampered = String::from_utf8(tampered).expect("still utf-8");
    assert!(
        agentos_tools::chain::verify(&tampered).is_err(),
        "editing one byte of a real ledger went undetected"
    );
}

// ---------------------------------------------------------------------------
// 2. The auth gate refuses before any routing happens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_ipc_is_refused_before_any_routing() {
    let d = Daemon::start("auth-bad", Ceiling::deny_all(), Box::new(Replay::harmless())).await;

    // No handshake at all: go straight for `info`, which is the cheapest method.
    // If the gate were enforced in the dispatcher rather than the connection
    // handler, this would answer.
    let mut c = Raw::connect(d.addr).await;
    let reply = c.call(protocol::method::INFO, serde_json::json!({})).await;
    assert_eq!(
        reply["error"]["code"],
        serde_json::json!(protocol::codes::UNAUTHORIZED),
        "an unauthenticated call must be refused: {reply}"
    );
    // The connection is closed afterwards rather than left open for a retry.
    assert!(
        c.recv().await.is_none(),
        "the daemon must hang up after refusing, not keep the socket open"
    );

    // A wrong token is refused too, and indistinguishably from a malformed one:
    // a distinguishable failure would tell an attacker which half was wrong.
    let mut c = Raw::connect(d.addr).await;
    c.send(serde_json::json!({
        "jsonrpc": "2.0", "id": 0, "method": auth::AUTH_METHOD,
        "params": { "token": "0".repeat(64) }
    }))
    .await;
    let wrong = c.recv().await.expect("a reply to the bad token");
    assert_eq!(wrong["error"]["code"], serde_json::json!(protocol::codes::UNAUTHORIZED));

    let mut c = Raw::connect(d.addr).await;
    c.send(serde_json::json!({
        "jsonrpc": "2.0", "id": 0, "method": auth::AUTH_METHOD,
        "params": { "token": "not hex at all" }
    }))
    .await;
    let malformed = c.recv().await.expect("a reply to the malformed token");
    assert_eq!(
        malformed["error"]["message"], wrong["error"]["message"],
        "a wrong token and a malformed one must be reported identically"
    );

    // The real token still works afterwards, so the refusals above did not
    // somehow poison the daemon's token.
    let mut ok = Raw::authenticate(d.addr, &d.token_hex).await;
    let pong = ok.call(protocol::method::PING, serde_json::json!({})).await;
    assert_eq!(pong["result"]["pong"], serde_json::json!(true));
}

// ---------------------------------------------------------------------------
// 3. Policy: grants are enforced over the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_task_asking_for_authority_outside_the_ceiling_is_refused() {
    // A ceiling that permits exactly one write root.
    let allowed = std::env::temp_dir().join("agentos-e2e-allowed");
    std::fs::create_dir_all(&allowed).expect("allowed root");
    let ceiling = Ceiling {
        write_roots: vec![allowed.clone()],
        allowed_hosts: Vec::new(),
        mail_outbox: None,
    };
    let d = Daemon::start("grants", ceiling, Box::new(Replay::harmless())).await;

    let mut c = Raw::authenticate(d.addr, &d.token_hex).await;

    // Inside the ceiling: allowed, and the task runs.
    let inside = c
        .call(
            protocol::method::EXECUTE,
            serde_json::to_value(protocol::ExecuteParams {
                task: "report the word hello".into(),
                grants: protocol::Grants {
                    write_roots: vec![allowed.to_string_lossy().into_owned()],
                    ..protocol::Grants::default()
                },
                timeout_secs: 5,
            })
            .unwrap(),
        )
        .await;
    assert!(
        inside.get("error").is_none(),
        "a root inside the ceiling must be granted: {inside}"
    );

    // Outside it: refused before the model is ever consulted.
    let outside = c
        .call(
            protocol::method::EXECUTE,
            serde_json::to_value(protocol::ExecuteParams {
                task: "report the word hello".into(),
                grants: protocol::Grants {
                    write_roots: vec!["/etc".to_string()],
                    ..protocol::Grants::default()
                },
                timeout_secs: 5,
            })
            .unwrap(),
        )
        .await;
    assert_eq!(
        outside["error"]["code"],
        serde_json::json!(protocol::codes::GRANT_DENIED),
        "a root outside the ceiling must be denied: {outside}"
    );
    // The *reason* matters as much as the code, and this is why. Asserting only
    // the code is a check that passes for the wrong reason: deleting the
    // containment test entirely still yields `GRANT_DENIED`, because constructing
    // a grant for a path that does not exist fails as a *configuration* error.
    // Both paths return the same code, so only the message distinguishes "you
    // asked for too much" from "this daemon is misconfigured".
    let message = outside["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("/etc") && message.contains("outside"),
        "the refusal must name the offending root and say it was outside the ceiling, \
         got: {message}"
    );
    assert!(
        !message.contains("grant configuration is invalid"),
        "the request was refused as out-of-policy, not as a broken configuration: {message}"
    );

    // Mail is refused when no outbox is configured at all.
    let mail = c
        .call(
            protocol::method::EXECUTE,
            serde_json::to_value(protocol::ExecuteParams {
                task: "report the word hello".into(),
                grants: protocol::Grants {
                    send_email: true,
                    ..protocol::Grants::default()
                },
                timeout_secs: 5,
            })
            .unwrap(),
        )
        .await;
    assert_eq!(
        mail["error"]["code"],
        serde_json::json!(protocol::codes::GRANT_DENIED),
        "mail with no outbox must be denied: {mail}"
    );
    assert!(
        !mail["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("grant configuration is invalid"),
        "mail without an outbox is a missing capability, not a broken one: {mail}"
    );

    let _ = std::fs::remove_dir_all(&allowed);
}

#[tokio::test]
async fn an_approval_cannot_be_expressed_over_the_wire() {
    // This is the confirmation gate's load-bearing property, checked
    // behaviourally on a real socket rather than by reading the protocol module.
    //
    // The REPL asks a person to approve, and the answer is deliberately *not*
    // forwarded: agreeing re-authorises the task in the person's own words
    // instead. That design only holds if there is no way to say "approved" to the
    // daemon. If someone ever adds an `approve` method or a field on
    // `ExecuteParams`, every process holding the token becomes an approver -- the
    // token proves a process reached the socket, not that a person is at it.
    let d = Daemon::start("approve", Ceiling::deny_all(), Box::new(Replay::harmless())).await;

    let mut c = Raw::authenticate(d.addr, &d.token_hex).await;

    for method in ["approve", "confirm", "authorize", "grant"] {
        let reply = c
            .call(method, serde_json::json!({ "op": "send_email.to", "approved": true }))
            .await;
        assert_eq!(
            reply["error"]["code"],
            serde_json::json!(protocol::codes::METHOD_NOT_FOUND),
            "the daemon must not implement `{method}`: {reply}"
        );
    }

    // The same must hold at the type level: `ExecuteParams` denies unknown fields,
    // so approval cannot ride along inside an ordinary execute either.
    let smuggled = c
        .call(
            protocol::method::EXECUTE,
            serde_json::json!({
                "task": "report the word hello",
                "grants": {},
                "timeout_secs": 5,
                "approved": true,
            }),
        )
        .await;
    assert_eq!(
        smuggled["error"]["code"],
        serde_json::json!(protocol::codes::INVALID_PARAMS),
        "an execute carrying an `approved` field must be rejected: {smuggled}"
    );

    // The daemon reports itself unable to ask anyone, which is the reason the
    // REPL has to resolve a halt locally rather than forwarding it.
    let info = c.call(protocol::method::INFO, serde_json::json!({})).await;
    assert_eq!(info["result"]["can_ask_human"], serde_json::json!(false));
}

// ---------------------------------------------------------------------------
// 4. The inbox: a real drop, really watched, really rate limited
// ---------------------------------------------------------------------------

use agentos_cli::daemon::inbox_loop;
use agentos_events::{Inbox, InboxEntry, Limits, SkipReason};

/// Poll until `ready` yields an entry, or give up.
///
/// The settle rule means a file dropped in the root takes two polls to be
/// reported, so a single poll is never enough. Eight rounds is the convention the
/// rest of this workspace uses and is still microseconds -- no sleeping anywhere.
fn poll_until_ready(inbox: &mut Inbox) -> InboxEntry {
    for _ in 0..8 {
        let poll = inbox.poll().expect("poll inbox");
        if let Some(entry) = poll.ready.into_iter().next() {
            return entry;
        }
    }
    panic!("the payload never became ready");
}

#[test]
fn a_dropped_payload_is_processed_archived_and_recorded_in_the_ledger() {
    let scratch = Scratch::new("inbox-ok");
    let inbox_dir = scratch.join("inbox");
    std::fs::create_dir_all(&inbox_dir).expect("inbox dir");
    scratch.write("inbox/note.txt", "please summarise this");

    // A real inbox, with the real default flood limits.
    let mut inbox = Inbox::open(&inbox_dir).expect("open inbox");
    let entry = poll_until_ready(&mut inbox);

    // The payload reaches the quarantine boundary tainted. If it arrived trusted,
    // every downstream provenance guarantee would be void, and this is the only
    // place that can prove it.
    let payload = inbox_loop::payload_of(&entry).expect("payload reads");
    assert!(
        !payload.label().is_trusted(),
        "an inbox payload must arrive quarantined"
    );

    // The file is still in the root until it is handled.
    assert!(inbox_dir.join("note.txt").exists());

    let audit_log = scratch.join("audit.log");
    let sink: SharedSink = Arc::new(Mutex::new(FileSink::open(&audit_log).expect("sink")));
    let clock: SharedClock = Arc::new(Mutex::new(SystemClock));

    let mut backend = Replay::harmless();
    let handled = inbox_loop::handle_entry(
        &entry,
        &mut backend,
        &Ceiling::deny_all(),
        sink,
        clock,
    );

    // The handler archived it, so a daemon restarted after every run would not
    // loop forever on the same file.
    assert!(!inbox_dir.join("note.txt").exists(), "the payload was not archived");
    assert_eq!(scratch.entries_in("inbox/processed"), vec!["note.txt"]);
    // Nothing left to re-fire on the next poll.
    assert!(
        scratch.entries_except_inbox_dirs("inbox").is_empty(),
        "the inbox root still has unprocessed payloads: {:?}",
        scratch.entries_except_inbox_dirs("inbox")
    );

    // The log line carries no untrusted byte.
    let line = handled.log_line();
    assert!(line.contains(&handled.size.to_string()), "{line}");
    assert!(!line.contains("summarise"), "payload text leaked into the log line");

    // The run wrote a ledger that verifies. The record count is zero and that is
    // correct, not a gap: `params_for` grants nothing, so no tool is registered,
    // and records are written per tool call. A report-only plan therefore writes
    // nothing -- which is precisely the invariant worth pinning, since a change
    // that made every task write records regardless would show up here.
    let text = std::fs::read_to_string(&audit_log).expect("ledger");
    agentos_tools::chain::verify(&text).expect("ledger verifies");
}

#[test]
fn a_flood_is_deferred_rather_than_dropped() {
    let scratch = Scratch::new("inbox-flood");
    let inbox_dir = scratch.join("inbox");
    std::fs::create_dir_all(&inbox_dir).expect("inbox dir");

    // Limits tight enough that real elapsed time cannot refill the bucket during
    // the test, so this cannot pass by accident because the clock moved.
    let limits = Limits::per_minute(1, 5);
    let mut inbox = Inbox::with_limits(&inbox_dir, limits).expect("open inbox");

    // Six distinct payloads: five fit the burst, the sixth has nowhere to go.
    for i in 0..6 {
        scratch.write(&format!("inbox/payload-{i}.txt"), &format!("distinct payload {i}"));
    }

    // Poll 1 settles them all; poll 2 admits five and defers the sixth.
    let mut ready = 0usize;
    let mut deferred_on_disk = 0usize;
    for _ in 0..4 {
        let poll = inbox.poll().expect("poll inbox");
        ready += poll.ready.len();
        deferred_on_disk = scratch.entries_in("inbox/deferred").len();
        if deferred_on_disk > 0 {
            break;
        }
    }

    assert_eq!(
        ready, 5,
        "exactly the burst should have been admitted, got {ready}"
    );
    assert_eq!(
        deferred_on_disk, 1,
        "the overflow must be deferred, not dropped"
    );

    // Deferred means *still on disk, under its own name*, not deleted and not
    // executed. `defer` is a rename into `deferred/`, so the payload has left the
    // root -- which is the whole point of the directory: a root file is retried on
    // every poll, and a deferred one waits for a token. Deleting it would be an
    // attacker's win.
    assert_eq!(scratch.entries_in("inbox/deferred"), vec!["payload-5.txt"]);
    assert!(
        !inbox_dir.join("payload-5.txt").exists(),
        "the deferred payload was never moved out of the root"
    );
    assert_eq!(
        std::fs::read_to_string(inbox_dir.join("deferred/payload-5.txt")).ok(),
        Some("distinct payload 5".to_string()),
        "the deferred payload's bytes did not survive the deferral"
    );
}

#[test]
fn a_repeated_drop_is_recognised_as_a_duplicate_not_processed_twice() {
    let scratch = Scratch::new("inbox-dedup");
    let inbox_dir = scratch.join("inbox");
    std::fs::create_dir_all(&inbox_dir).expect("inbox dir");

    let mut inbox = Inbox::open(&inbox_dir).expect("open inbox");
    scratch.write("inbox/first.txt", "identical bytes");
    let first = poll_until_ready(&mut inbox);

    // Same bytes, different name. The dedup window is keyed on the payload digest,
    // so the rate limiter does not spend a token and no second run happens.
    scratch.write("inbox/second.txt", "identical bytes");
    let mut saw_duplicate = false;
    for _ in 0..4 {
        let poll = inbox.poll().expect("poll inbox");
        assert!(
            poll.ready.is_empty(),
            "an identical payload must not be handled a second time"
        );
        if poll
            .skipped
            .iter()
            .any(|s| s.reason == SkipReason::DuplicatePayload)
        {
            saw_duplicate = true;
            break;
        }
    }
    assert!(saw_duplicate, "the duplicate was never reported as one");
    assert_eq!(first.digest().expect("digest"), agentos_events::PayloadDigest::of(b"identical bytes"));
}

#[test]
fn an_unwatched_extension_is_ignored_rather_than_executed() {
    let scratch = Scratch::new("inbox-ext");
    let inbox_dir = scratch.join("inbox");
    std::fs::create_dir_all(&inbox_dir).expect("inbox dir");

    let mut inbox = Inbox::open(&inbox_dir).expect("open inbox");
    scratch.write("inbox/payload.exe", "MZ not a task");
    scratch.write("inbox/payload", "no extension at all");

    let mut saw = false;
    for _ in 0..4 {
        let poll = inbox.poll().expect("poll inbox");
        assert!(poll.ready.is_empty(), "an unwatched file must never be handled");
        if poll
            .skipped
            .iter()
            .any(|s| s.reason == SkipReason::ExtensionNotWatched)
        {
            saw = true;
            break;
        }
    }
    assert!(saw, "the extension filter never reported a skip");
    // Ignored, not consumed: still sitting there for an operator to look at.
    assert!(inbox_dir.join("payload.exe").exists());
}

// ---------------------------------------------------------------------------
// 5. The REPL, driving a real daemon over the real transport
// ---------------------------------------------------------------------------

use agentos_cli::client::{AuthToken, Client, DaemonEndpoint};

#[tokio::test]
async fn the_repl_dispatches_a_task_over_the_real_transport() {
    // Here the real `Client` is the thing under test, so its endpoint discovery
    // and token reading are exercised too -- which is why this one test takes
    // `ENV_LOCK` rather than speaking the protocol directly.
    let d = Daemon::start("repl", Ceiling::deny_all(), Box::new(Replay::harmless())).await;

    let addr = d.addr.to_string();
    let token_path = d.token_file.to_string_lossy().into_owned();
    let token_on_disk = d.token_on_disk();
    let socket = d.addr;

    // `Client` is synchronous: it does a blocking connect and then blocks
    // on `read` with a 30s socket timeout. The daemon's accept loop is
    // `tokio::spawn`ed onto the *same* current-thread runtime this test
    // runs on, so calling it inline would park the only thread that could
    // accept the connection. The result is a 30-second stall followed by a
    // timeout error that reads like a daemon bug.
    //
    // `spawn_blocking` is the fix, and it is the same reason the daemon
    // hands its own blocking work off in `daemon::serve`. It also happens to be
    // the right place for the env guard, since `with_env` is synchronous and
    // cannot `.await`.
    let out = tokio::task::spawn_blocking(move || {
        with_env(
            &[("AGENTOS_TCP_ADDR", &addr), ("AGENTOS_TOKEN_FILE", &token_path)],
            || {
                let token = AuthToken::read().expect("read token");
                assert_eq!(
                    token.as_str(),
                    token_on_disk,
                    "the client read a different token than the daemon wrote"
                );
                let client = Client::connect(DaemonEndpoint::Tcp(socket), Some(token))
                    .expect("connect to the daemon");

                // Drive one real turn and quit.
                let script = "report the word hello\n/exit\n";
                let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
                let mut sink: Vec<u8> = Vec::new();

                let mut repl = agentos_cli::repl::Repl::new(client, no_grants(), true);
                let exit = repl.run(&mut input, &mut sink).expect("the REPL ran");

                assert!(matches!(exit, agentos_cli::repl::ReplExit::Normal));

                // And the turn is remembered, so the session is a session.
                let history = repl.history();
                assert!(!history.is_empty(), "the REPL forgot the turn it just ran");
                assert_eq!(history[0].user_text(), "report the word hello");

                String::from_utf8(sink).expect("utf-8 output")
            },
        )
    })
    .await
    .expect("the blocking client thread did not panic");

    // The banner states the constraint the whole design rests on.
    assert!(
        out.contains("the daemon cannot approve anything"),
        "banner did not state the approval constraint: {out}"
    );
    // The task really was submitted and really did complete.
    assert!(out.contains("submitted"), "{out}");
    assert!(out.contains("done."), "{out}");

    d.accept.abort();
    // The turn ran over the real socket and completed, and the ledger it shares
    // with every other run still verifies. The record count is not asserted to be
    // non-zero: this task only `report`s, so no tool was invoked and a record
    // would not have been written. That a report-only task writes *nothing* is
    // itself the I6 property -- records are written per tool call, not per task.
    d.verify_ledger()
        .expect("the ledger verifies after a REPL turn");
}

// ---------------------------------------------------------------------------
// 6. The confirmation gate, at the layer that resolves it
// ---------------------------------------------------------------------------

use agentos_cli::repl::{Transport, TransportError};

/// A transport that answers with a scripted sequence, to drive the REPL into a
/// halt the daemon cannot reach on this machine.
///
/// This is a substitute for a network, not a substitute for the daemon: the REPL
/// under test is the real one, the rendering and the approval arithmetic are the
/// real ones, and only the bytes on the socket are canned.
struct Scripted {
    replies: Vec<Result<protocol::TaskOutcome, TransportError>>,
    /// Shared, because `Repl` *owns* its transport and never hands it back.
    /// Without a handle out here the test could only see what the REPL printed,
    /// which is exactly the value under suspicion: the whole claim is about what
    /// crossed the wire, so it has to be counted on the wire's side of the call.
    sent: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

impl Scripted {
    fn new(replies: Vec<Result<protocol::TaskOutcome, TransportError>>) -> Self {
        Self {
            replies,
            sent: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        }
    }

    fn sent(&self) -> std::rc::Rc<std::cell::RefCell<Vec<String>>> {
        std::rc::Rc::clone(&self.sent)
    }
}

impl Transport for Scripted {
    fn execute(&mut self, params: agentos_cli::repl::ExecuteParams) -> Result<protocol::TaskOutcome, TransportError> {
        self.sent.borrow_mut().push(params.task.clone());
        if self.replies.is_empty() {
            return Err(TransportError::Disconnected("script exhausted".into()));
        }
        self.replies.remove(0)
    }

    fn info(&mut self) -> Result<protocol::Info, TransportError> {
        Ok(agentos_cli::daemon::executor::describe(
            "replay-model",
            &Ceiling::deny_all(),
            2,
            true,
        ))
    }

    fn reconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

fn needs_human() -> protocol::TaskOutcome {
    protocol::TaskOutcome::NeedsHuman {
        op: vec!["send_email.to".to_string()],
        rendered: "send_email to: attacker@evil.test".to_string(),
    }
}

#[test]
fn approving_in_the_repl_re_authorises_the_task_and_grants_nothing() {
    let transport = Scripted::new(vec![
        Ok(needs_human()),
        // The daemon halts again. It always does: the person re-authorised the
        // task in their own words, but the value is still tainted, so policy
        // still stops it. That second halt is the point.
        Ok(needs_human()),
    ]);
    let sent = transport.sent();

    let script = "mail the invoice\ny\nmail the invoice from my own account\n/exit\n";
    let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
    let mut sink: Vec<u8> = Vec::new();
    let mut repl = agentos_cli::repl::Repl::new(transport, no_grants(), true);
    repl.run(&mut input, &mut sink).expect("repl ran");
    let text = String::from_utf8(sink).expect("utf-8");

    // The halt is shown, and the constraint is stated at the prompt rather than
    // letting a "yes" look like it unlocked anything.
    assert!(text.contains("needs your approval"), "{text}");
    assert!(text.contains("send_email.to"), "{text}");
    assert!(
        text.contains("agreeing here does NOT give the daemon authority"),
        "{text}"
    );
    assert!(text.contains("noted."), "{text}");

    // Two tasks went over the wire, and the second is the person's own sentence --
    // not the rendered request, which carries a value the agent chose.
    let sent = sent.borrow();
    assert_eq!(sent.len(), 2, "sent: {sent:?}");
    assert_eq!(sent[0], "mail the invoice");
    assert_eq!(
        sent[1], "mail the invoice from my own account",
        "the re-authorised task must be the person's own words"
    );
    assert!(
        !sent[1].contains("attacker@evil.test"),
        "the agent's rendered request must never become the task text"
    );
}

#[test]
fn declining_in_the_repl_sends_nothing() {
    let transport = Scripted::new(vec![Ok(needs_human())]);
    let sent = transport.sent();

    let script = "mail the invoice\nn\n/exit\n";
    let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
    let mut sink: Vec<u8> = Vec::new();
    let mut repl = agentos_cli::repl::Repl::new(transport, no_grants(), true);
    repl.run(&mut input, &mut sink).expect("repl ran");
    let text = String::from_utf8(sink).expect("utf-8");

    assert!(text.contains("declined. nothing was sent or written."), "{text}");
    assert!(
        !text.contains("noted."),
        "a decline must not look like an approval: {text}"
    );
    // Exactly one task: the original. A decline adds nothing to the wire.
    assert_eq!(*sent.borrow(), vec!["mail the invoice".to_string()]);
}

#[test]
fn a_non_interactive_repl_asks_nobody_and_sends_nothing_extra() {
    // A piped stdin has no person. The answer is therefore no-human, and the
    // second task is never read, so nothing extra reaches the daemon.
    let transport = Scripted::new(vec![Ok(needs_human())]);
    let sent = transport.sent();

    let script = "mail the invoice\ny\nsomething the agent never sees\n/exit\n";
    let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
    let mut sink: Vec<u8> = Vec::new();
    let mut repl = agentos_cli::repl::Repl::new(transport, no_grants(), false);
    repl.run(&mut input, &mut sink).expect("repl ran");
    let text = String::from_utf8(sink).expect("utf-8");

    assert!(text.contains("no interactive terminal"), "{text}");
    assert!(
        text.contains("nothing was sent or written"),
        "{text}"
    );

    // The load-bearing property: the `y` was consumed as the *answer to the gate*
    // and never became a task. If it had, a piped script containing "y" anywhere
    // would be one line closer to an approval than a person ever gave.
    assert!(
        !sent.borrow().iter().any(|t| t.trim() == "y"),
        "the approval answer was submitted as a task: {:?}",
        sent.borrow()
    );
    // The line after the halt is an ordinary new task, which is correct REPL
    // behaviour and is *not* a re-authorisation of the halted one.
    assert_eq!(
        *sent.borrow(),
        vec![
            "mail the invoice".to_string(),
            "something the agent never sees".to_string()
        ],
        "unexpected tasks submitted by a non-interactive run"
    );
}

// ---------------------------------------------------------------------------
// 7. Cleanup is not optional
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failing_assertion_still_leaves_nothing_behind() {
    // The harness's cleanup story is only worth anything if it holds when a test
    // blows up, and the only honest way to show that is to drop the daemon as if
    // an assertion had just panicked, then look at what survived.
    //
    // Note there is deliberately no `Scratch` alive in this test's body: one would
    // keep its own directory alive and make the assertions below pass or fail for
    // the wrong reason.
    let (audit_log, token_file, root) = {
        let d = Daemon::start(
            "cleanup-inner",
            Ceiling::deny_all(),
            Box::new(Replay::harmless()),
        )
        .await;
        // Everything the daemon created exists while it is alive.
        assert!(d.audit_log.exists(), "no ledger was written at all");
        assert!(d.token_file.exists(), "no startup token was written");
        (d.audit_log.clone(), d.token_file.clone(), d._scratch.root.clone())
        // `d` drops here, as a panicking test's frame would drop it.
    };

    // The token file and the ledger went with the scratch directory. A leaked token
    // file is a live credential for whatever runs next on this machine, which is
    // the reason this is asserted rather than assumed.
    assert!(!audit_log.exists(), "the audit ledger outlived its scratch dir");
    assert!(
        !token_file.exists(),
        "the startup token outlived its scratch dir"
    );
    assert!(!root.exists(), "the scratch dir outlived the daemon");
}

/// A guard against the suite quietly outgrowing its own budget.
///
/// Cheap to assert and impossible to notice otherwise: an e2e harness that
/// starts sleeping, or starts shelling out, or starts talking to the network,
/// will pass every functional test above while becoming useless to run.
#[test]
fn the_harness_needs_no_network_and_no_sleeping() {
    let source = include_str!("e2e.rs");

    // Scan only the part of the file *before* this guard. A guard that greps its
    // own source for a literal it contains always fails, and the usual workaround
    // -- splitting the needle so it does not appear literally -- is fragile in a
    // different way: it silently stops matching if someone reformats the literal.
    let body = source
        .split_once("fn the_harness_needs_no_network_and_no_sleeping")
        .map_or(source, |(head, _)| head);

    // Deliberately *not* a check for an HTTP client: this harness does use
    // `TcpStream`, to reach the daemon it just started, and pretending otherwise
    // would make the guard cry wolf.
    for needle in [
        "std::process::Command",
        "thread::sleep",
        "tokio::time::sleep",
        "Duration::from_millis",
        "Duration::from_secs",
        "Instant::now",
    ] {
        assert!(
            !body.contains(needle),
            "the e2e harness must not contain `{needle}`: an e2e suite that sleeps or \
             shells out is a suite nobody can run in CI"
        );
    }

    // Loopback-only is asserted *behaviourally* rather than by grepping this file
    // for an address: `Daemon::start` checks `addr.ip().is_loopback()` on every
    // socket it binds, which is a fact about the run rather than about the text.
    // A grep for `0.0.0.0` would only have caught the string, and this file
    // mentions it in a comment explaining why it is avoided.

    // Every scratch directory is namespaced, so a leak is greppable and two
    // harnesses cannot collide.
    assert!(body.contains("agentos-e2e-"), "scratch dirs must be namespaced");
    assert!(body.contains("is_loopback"), "the bound address must be checked");
}