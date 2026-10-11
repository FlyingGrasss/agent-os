//! The daemon's wire protocol.
//!
//! # What this is
//!
//! A closed vocabulary of request and response shapes, in the same spirit as the
//! plan language: the set of things a client may ask for is enumerated here, and
//! an unrecognised field is an error rather than something carried forward. That
//! matters more than it looks. The IPC request is the one place where a value the
//! daemon did not produce enters the system, and a permissive `serde_json::Value`
//! parameter type would let a client smuggle fields that no rule was written
//! against.
//!
//! # Why JSON-RPC, and where it stops
//!
//! The envelope is JSON-RPC 2.0 shaped because it is a known convention and the
//! error codes are standard. Everything below the envelope is not: the `params`
//! for each method is a typed struct with `deny_unknown_fields`, and the
//! `result` is a typed struct rather than a tagged union. A tagged union would
//! need the client to guess which variant it got; named fields with a `kind`
//! discriminator are cheaper to read and equally easy to validate.
//!
//! # The direction trust runs
//!
//! **Nothing in a request is trusted.** A `task` string arriving over IPC is
//! attacker-controlled text as far as the type system is concerned, and the daemon
//! marks it `Quarantined` until a person or a signed configuration makes it
//! `Trusted`. `TaskRequest::task` is a `Quarantined<String>` for exactly this
//! reason; see `executor::run_task`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use agentos_types::{Quarantined, SourceId};

/// Protocol version string, sent in the `info` response.
///
/// Bumped when a request or response shape changes incompatibly. A client that
/// does not recognise the version should refuse rather than guess, because the
/// failure mode of guessing is a client believing it approved something it did
/// not.
pub const PROTOCOL_VERSION: &str = "agentosd/1";

/// Largest frame accepted, in bytes.
///
/// This is a refusal, not a truncation: a client that sends a larger frame gets a
/// connection error and no partial parse. Bounding the frame is what stops a
/// client from making the daemon allocate without limit.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// A request from a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Always `"2.0"`. Rejected otherwise, so a client speaking some other
    /// dialect cannot be silently accepted.
    pub jsonrpc: String,
    /// Correlation id, echoed in the response. Never interpreted.
    pub id: Value,
    /// One of [`method::EXECUTE`], [`method::INFO`], [`method::PING`].
    pub method: String,
    /// Method parameters. Required even when empty, so that "no params" and
    /// "params I forgot to send" are the same thing on the wire.
    #[serde(default)]
    pub params: Value,
}

/// The methods this daemon answers.
pub mod method {
    /// Run a task to completion.
    pub const EXECUTE: &str = "execute";
    /// Report daemon configuration and what this build can actually do.
    pub const INFO: &str = "info";
    /// Liveness check.
    pub const PING: &str = "ping";
}

/// Parameters for [`method::EXECUTE`].
///
/// ## Why the task arrives untrusted
///
/// `task` is a `String` on the wire and a [`Quarantined<String>`] the moment it
/// lands. The daemon's job is to plan and execute on a user's behalf, and the text
/// describing that job comes from whoever can reach the socket. Treating it as
/// trusted on arrival would mean any local process that can open a TCP port could
/// write to the Controller's prompt through `Session::with_pager`, which is
/// precisely the path invariant I1 closes.
///
/// The split is deliberate rather than incidental: `Quarantined<T>` has no serde
/// implementation, so a quarantined value cannot be deserialised out of a request
/// or serialised into a response by accident. The wrapping is a decision made in
/// code ([`ExecuteParams::into_quarantined`]) rather than something the type
/// system infers from having been read off a socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteParams {
    /// What to do, in plain words. Untrusted on arrival, per above.
    pub task: String,

    /// Capability grants for this one task. Each is a *narrowing* of the
    /// daemon's configured ceiling, never a widening: an unknown host or a path
    /// outside the configured roots is an error, not a silent grant.
    #[serde(default)]
    pub grants: Grants,

    /// Seconds to allow before the task is abandoned.
    ///
    /// Bounded above by [`MAX_TASK_SECONDS`] however large the client asks. A
    /// client that can set an unbounded timeout can pin a worker thread
    /// indefinitely, which is a denial of service against the one process that
    /// holds the machine's authority.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    300
}

impl ExecuteParams {
    /// Wrap the wire task text as quarantined, labelled to this request.
    ///
    /// `source` is the request id rendered as a `SourceId`. It exists so the
    /// provenance in an audit record or a rendered confirmation names the request
    /// that carried the text, which is what makes a refusal investigable after
    /// the fact.
    pub fn into_quarantined(self, source: SourceId) -> Quarantined<String> {
        Quarantined::from_source(self.task, source)
    }

    /// The timeout, clamped to [`MAX_TASK_SECONDS`].
    ///
    /// A clamp rather than an error, because a client asking for a long timeout is
    /// asking for patience, not for authority. Refusing the whole task over it
    /// would make a misconfiguration look like a security event.
    pub fn clamped_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.min(MAX_TASK_SECONDS))
    }
}

/// Hard ceiling on `timeout_secs`, regardless of what a client asks for.
pub const MAX_TASK_SECONDS: u64 = 3600;

/// Capability grants requested for one task.
///
/// Every field is a subset request. `grants.rs` intersects each of them with the
/// daemon's configured ceiling, so a client cannot widen authority by asking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    /// Hosts `http.fetch` may reach. Narrowing only.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Directory `fs.write` may write inside. Narrowing only.
    #[serde(default)]
    pub write_roots: Vec<String>,
    /// Whether `send_email` is registered at all for this task.
    ///
    /// A `bool` rather than a recipient list on purpose. The recipient list is
    /// policy's business and lives in the rule set; letting the wire choose
    /// recipients would mean the sender of an IPC frame picks who receives mail.
    #[serde(default)]
    pub send_email: bool,
}

/// A response to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The `id` from the request this answers.
    pub id: Value,
    /// Present on success, absent on error. Mutually exclusive with `error` by
    /// construction, so a client never has to check which one won.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present on failure, absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    /// A successful response carrying `result`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// A failed response carrying `error`.
    pub fn err(id: Value, error: ErrorBody) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Serialise this response, falling back to a protocol-level error if even
    /// that fails.
    ///
    /// The fallback matters: a response that cannot be encoded would otherwise
    /// leave the client waiting forever for a reply that is never coming, and a
    /// silent hang is a worse failure than an error about the error.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|e| {
            let fallback = Response::err(
                Value::Null,
                ErrorBody::internal(format!("response could not be serialised: {e}")),
            );
            serde_json::to_vec(&fallback).unwrap_or_else(|_| {
                br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response encoding failed"}}"#.to_vec()
            })
        })
    }
}

/// The body of a JSON-RPC error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: i32,
    pub message: String,
    /// Machine-readable detail. Never contains untrusted document text; see
    /// [`ErrorBody::internal`], which is the only constructor that takes a free
    /// string, and it is fed by this crate's own errors rather than by a tool's
    /// output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorBody {
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self { code: codes::PARSE_ERROR, message: message.into(), data: None }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self { code: codes::INVALID_REQUEST, message: message.into(), data: None }
    }

    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self { code: codes::METHOD_NOT_FOUND, message: message.into(), data: None }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self { code: codes::INVALID_PARAMS, message: message.into(), data: None }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self { code: codes::INTERNAL, message: message.into(), data: None }
    }

    /// The task was refused before it ran.
    pub fn refused(message: impl Into<String>) -> Self {
        Self { code: codes::REFUSED, message: message.into(), data: None }
    }

    /// The task needed a person and there was none.
    pub fn needs_human(message: impl Into<String>) -> Self {
        Self { code: codes::NEEDS_HUMAN, message: message.into(), data: None }
    }

    /// The requested grant is outside the daemon's configured ceiling.
    pub fn grant_denied(message: impl Into<String>) -> Self {
        Self { code: codes::GRANT_DENIED, message: message.into(), data: None }
    }
}

/// Standard and AgentOS-specific error codes.
pub mod codes {
    /// The frame was not valid JSON.
    pub const PARSE_ERROR: i32 = -32700;
    /// Valid JSON, but not a request this daemon accepts.
    pub const INVALID_REQUEST: i32 = -32600;
    /// No such method.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// The method exists and the parameters are wrong.
    pub const INVALID_PARAMS: i32 = -32602;
    /// The daemon failed in a way the client cannot fix.
    pub const INTERNAL: i32 = -32603;

    /// The task was refused. Nothing ran.
    pub const REFUSED: i32 = -32001;
    /// The task halted because policy required approval and no person was
    /// reachable.
    pub const NEEDS_HUMAN: i32 = -32002;
    /// The requested capability exceeds the daemon's configured ceiling.
    pub const GRANT_DENIED: i32 = -32003;
}

/// What the daemon reports about itself and the host it runs on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub protocol: String,
    pub model: String,
    /// Write roots the daemon will grant from, after narrowing.
    pub write_roots: Vec<String>,
    /// Hosts `http.fetch` will grant from, after narrowing.
    pub allowed_hosts: Vec<String>,
    /// Whether `send_email` is registered for tasks.
    pub send_email_enabled: bool,
    /// Tasks that may run at once.
    pub max_concurrent_tasks: usize,
    /// Always `false` in this build.
    ///
    /// Reported rather than assumed, because a caller planning around "the daemon
    /// can ask someone" would otherwise silently get a system that refuses. See
    /// `executor::NEEDS_HUMAN`.
    pub can_ask_human: bool,
    /// What this build cannot do, in the caller's terms.
    pub limitations: Vec<String>,
}

/// The result of an `execute` call.
///
/// `kind` discriminates so a client can switch on a string rather than guess at
/// the shape. The variants are distinct outcomes, not degrees of the same one:
/// `Completed` ran everything, `Refused` ran nothing because a person said no,
/// `NeedsHuman` ran nothing because no person could be asked, and `Failed` ran
/// part of the way and stopped on an error. Collapsing the middle two would make
/// "the system refused" indistinguishable from "the loop gave up", which is the
/// same conflation `Outcome::ConfirmationLimit` was added to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskOutcome {
    /// Every statement ran.
    Completed {
        reports: Vec<String>,
    },
    /// A person said no. Nothing was sent or written.
    Refused {
        op: String,
    },
    /// Policy halted the plan on a value that needed approval, and the daemon
    /// has no way to ask.
    NeedsHuman {
        op: Vec<String>,
        /// Rendered for a person to read if one ever reads it.
        ///
        /// Carried back so an interactive front-end can show it and re-submit,
        /// without this daemon having to pretend it asked anyone.
        rendered: String,
    },
    /// The loop asked more times than its limit allowed.
    ConfirmationLimit {
        asked: usize,
    },
    /// The plan stopped on an error.
    Failed {
        message: String,
        /// True when policy refused, with no human involved.
        ///
        /// Typed rather than inferred from the message: a policy denial and a
        /// budget stop are different claims and a string cannot be trusted to
        /// carry that distinction.
        policy_denied: bool,
    },
}