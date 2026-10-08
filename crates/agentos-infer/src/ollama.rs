//! An Ollama-backed [`Backend`].
//!
//! Local models, no API key, no egress. That is the whole reason this backend
//! exists in a project whose threat model is about untrusted input: a hosted
//! provider would put a third party between the Controller's prompt and the
//! model, and §7.6 of the threat model already says a model provider we do not
//! control is out of scope. Running locally removes that party rather than
//! reasoning about it.
//!
//! # Constrained decoding is claimed, not assumed
//!
//! [`Backend::supports_constrained_decoding`] returns `true` because Ollama's
//! `/api/chat` accepts a `format` field carrying a JSON Schema and applies it as
//! a sampler-side grammar. That is a claim about a *different process*, so this
//! module does not treat it as enforcement:
//!
//! - Role Q's output is re-validated against the schema host-side by
//!   `agentos-quarantine` regardless of what Ollama claims to have enforced. The
//!   grammar is the first wall; validation is the second. A backend that lied
//!   about constraining decoding would produce output that fails validation, not
//!   output that reaches the Controller.
//! - [`Ollama::complete`] refuses to serve role Q at all if the caller did not
//!   supply a schema, so "constrained decoding" is never vacuously true.
//!
//! # What a caller must still do
//!
//! This backend moves bytes. It does not decide what may be asked, and it holds
//! no authority: a `Trusted` value cannot be produced here, and the trait has no
//! tool-calling method by design. Policy lives in `agentos-policy`, confinement
//! lives in `agentos-sandbox`, and both are downstream of this file.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use agentos_types::{ControllerAuthority, Origin, Trusted, Val};

use crate::{
    Backend, Completion, Content, Conversation, InferError, Message, MessageRole, Output, Role,
    Usage,
};

/// Default endpoint. Loopback on purpose: this backend talks to a process on this
/// machine, and a reachable HTTP listener on a routable address would be a way to
/// redirect the Controller's prompt at something we do not control.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434";

/// How long to wait for the whole exchange.
///
/// Generous, because a cold small model on CPU can take tens of seconds for the
/// first token and this is a local process, not a network peer. It is still a
/// bound: an agent loop that hangs forever is not a failure mode worth having.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// A model served by Ollama, per role.
///
/// Splitting the two is the point of the whole design, so it is a type-level
/// decision rather than a runtime option: there is no constructor that builds
/// one `Ollama` serving both roles, so nothing can accidentally point the
/// quarantined reader at the same model that writes plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleModels {
    /// The privileged planner. Writes DSL. Trusted by construction because it
    /// never sees untrusted bytes.
    Separate {
        /// Model name for role P.
        planner: String,
        /// Model name for role Q.
        extractor: String,
    },
    /// One model serving both. Convenient, and honest about being weaker: the
    /// role separation in the *interface* is all that remains, since the weights
    /// are shared.
    Shared {
        /// The single model name.
        model: String,
    },
}

impl RoleModels {
    /// The model name for `role`.
    pub fn model_for(&self, role: Role) -> &str {
        match (self, role) {
            (RoleModels::Separate { planner, .. }, Role::Planner) => planner,
            (RoleModels::Separate { extractor, .. }, Role::Extractor) => extractor,
            (RoleModels::Shared { model }, _) => model,
        }
    }
}

/// An Ollama client.
#[derive(Debug, Clone)]
pub struct Ollama {
    endpoint: String,
    models: RoleModels,
    timeout: Duration,
    /// Schema for role Q's output. Required whenever this backend serves the
    /// extractor; see [`Ollama::with_extraction_schema`].
    extraction_schema: Option<Value>,
}

impl Ollama {
    /// A client against the default loopback endpoint.
    pub fn new(models: RoleModels) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            models,
            timeout: DEFAULT_TIMEOUT,
            extraction_schema: None,
        }
    }

    /// Point at a different endpoint. The value must be loopback.
    ///
    /// Refuses a routable address rather than warning about one. A backend whose
    /// endpoint can be redirected is a backend whose prompt can be redirected,
    /// and this is not a knob worth having.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, InferError> {
        let endpoint = endpoint.into();
        if !Self::is_loopback(&endpoint) {
            return Err(InferError::Backend(format!(
                "ollama endpoint `{endpoint}` is not loopback; this backend refuses to send a \
                 Controller prompt anywhere a third party could read it"
            )));
        }
        self.endpoint = endpoint;
        Ok(self)
    }

    /// Supply the schema role Q must satisfy.
    pub fn with_extraction_schema(mut self, schema: Value) -> Self {
        self.extraction_schema = Some(schema);
        self
    }

    /// Bound each exchange.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn models(&self) -> &RoleModels {
        &self.models
    }

    fn is_loopback(endpoint: &str) -> bool {
        let rest = endpoint
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        // A bracketed IPv6 literal must be taken whole. Splitting on `:` first
        // turns `[::1]:11434` into `[`, ``, `1]`, ... — and the leading `[`
        // matches nothing, so a legitimate loopback endpoint gets refused. That
        // is a fail-closed bug, which is the safe direction, but it would push
        // someone toward a routable address to work around it.
        let host = match rest.find('[') {
            Some(open) => match rest[open..].find(']') {
                Some(close) => &rest[open..=open + close],
                None => return false,
            },
            None => rest.split(['/', ':']).next().unwrap_or_default(),
        };
        matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
            // The whole 127/8 range, not just 127.0.0.1, so an operator using a
            // different loopback address is not pushed toward a routable one.
            || host.starts_with("127.")
    }

    /// Flatten a conversation into the `messages` array Ollama expects.
    ///
    /// For role Q this reads quarantined text, which is why it is allowed to here
    /// and only here: this is the process that is supposed to see hostile bytes.
    /// A planner conversation cannot contain untrusted content at all, because
    /// `Conversation::push` refuses it before this is reached.
    fn wire_messages(c: &Conversation) -> Vec<Value> {
        c.messages()
            .iter()
            .map(|m: &Message| {
                let role = match m.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                };
                let content = match &m.content {
                    Content::Trusted(t) => t.get().clone(),
                    // `Quarantined` hides its content from `Debug` but
                    // `with_label_for_display` is the intended way to read it,
                    // and this is the one component allowed to: it is the
                    // quarantined role's own prompt.
                    Content::Untrusted(q) => {
                        q.with_label_for_display(|text: &String, _| text.clone())
                    }
                };
                json!({ "role": role, "content": content })
            })
            .collect()
    }

    /// One HTTP exchange with the Ollama endpoint.
    ///
    /// Hand-rolled rather than pulling in an HTTP client: the requests are simple
    /// JSON to a known loopback port, and adding a dependency with its own TLS
    /// stack and redirect policy would be more attack surface than the thing
    /// being protected. It also keeps `agentos-infer` free of async, which the
    /// `Backend` trait requires anyway.
    fn post_json(&self, path: &str, body: &Value) -> Result<Value, InferError> {
        self.exchange("POST", path, Some(body))
    }

    /// A GET. Ollama's `/api/tags` is GET-only, and POSTing it answers `405`.
    fn get_json(&self, path: &str) -> Result<Value, InferError> {
        self.exchange("GET", path, None)
    }

    fn exchange(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, InferError> {
        let (host_port, request_path) = self.split_endpoint(path)?;
        let mut stream = TcpStream::connect(&host_port).map_err(|e| {
            InferError::Backend(format!(
                "cannot reach ollama at {host_port}: {e}; is it running? \
                 (`ollama serve`, or see the install notes)"
            ))
        })?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let (head, payload) = match body {
            Some(body) => {
                let payload = serde_json::to_vec(body)
                    .map_err(|e| InferError::Backend(format!("cannot encode request: {e}")))?;
                (
                    format!(
                        "{method} {request_path} HTTP/1.1\r\nHost: {host_port}\r\n\
                         Content-Type: application/json\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        payload.len()
                    ),
                    payload,
                )
            }
            None => (
                format!(
                    "{method} {request_path} HTTP/1.1\r\nHost: {host_port}\r\n\
                     Connection: close\r\n\r\n"
                ),
                Vec::new(),
            ),
        };

        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(&payload))
            .and_then(|_| stream.flush())
            .map_err(|e| InferError::Backend(format!("sending request failed: {e}")))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| InferError::Backend(format!("reading response failed: {e}")))?;
        let text = String::from_utf8_lossy(&raw);
        // Split headers from body. Status line first, so a 404 with a JSON error
        // body reports the server's message rather than a parse failure.
        let (headers, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| InferError::Backend("response had no header/body split".into()))?;
        let status: u16 = headers
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        // Status is checked BEFORE the body is parsed.
        //
        // This ordering is the fix for a bug the live test found: a wrong method
        // against a GET-only endpoint returns 405 with a body that is not JSON, so
        // parsing first reported `trailing characters at line 1 column 5` and
        // buried the only useful fact, which was the status. A parse failure on a
        // non-2xx response is a symptom; the status is the cause.
        //
        // Chunked bodies are still not decoded. Ollama sends `Content-Length` for
        // `/api/chat`; a chunked reply fails to parse and says so, rather than
        // being silently truncated into a wrong answer.
        if !(200..300).contains(&status) {
            // Best-effort extraction of the server's own message. Never a hard
            // failure: an error body can be anything, including an HTML page from
            // something that is not Ollama at all.
            let detail = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| {
                    let trimmed = body.trim();
                    if trimmed.is_empty() {
                        "no response body".to_string()
                    } else {
                        // Bounded, and with the body not necessarily ours: this
                        // string reaches an operator's terminal.
                        trimmed.chars().take(200).collect()
                    }
                });
            return Err(InferError::Backend(format!(
                "ollama returned {status} for {method} {request_path}: {detail}"
            )));
        }
        let value: Value = serde_json::from_str(body).map_err(|e| {
            InferError::Backend(format!(
                "cannot parse a {status} response from {method} {request_path}: {e}"
            ))
        })?;
        Ok(value)
    }

    fn split_endpoint(&self, path: &str) -> Result<(String, String), InferError> {
        let rest = self
            .endpoint
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let (host_port, base_path) = match rest.split_once('/') {
            Some((h, b)) => (h.to_string(), format!("/{b}")),
            None => (rest.to_string(), String::new()),
        };
        if host_port.is_empty() {
            return Err(InferError::Backend("endpoint has no host".into()));
        }
        Ok((host_port, format!("{base_path}{path}")))
    }

    /// Whether Ollama is up and which models it has.
    ///
    /// Separate from the constructor on purpose: a build that constructs a
    /// backend at startup should not fail because a model has not been pulled
    /// yet, and a test should be able to ask without issuing an inference call.
    ///
    /// GET, not POST. `/api/tags` is read-only and answers `405` to a POST. The
    /// live test found this, and it was invisible until then because the client
    /// parsed the body before checking the status, so the only symptom was a
    /// confusing JSON parse failure.
    pub fn probe(&self) -> Result<Vec<String>, InferError> {
        let value = self.get_json("/api/tags")?;
        let names = value
            .get("models")
            .and_then(Value::as_array)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|m| m.get("name").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }

    /// Pull a model. Blocking, and slow; this is a setup operation, not something
    /// to call from a request path.
    pub fn pull(&self, model: &str) -> Result<(), InferError> {
        // `/api/pull` streams progress for minutes on a cold cache, so it is
        // issued but its body is not awaited: the caller's job is to start it and
        // then poll `probe` for the model to appear.
        self.post_json("/api/pull", &json!({ "model": model, "stream": false }))?;
        Ok(())
    }
}

/// Ollama's chat reply. Only the fields we use.
#[derive(Debug, Deserialize)]
struct ChatReply {
    message: Option<ChatMessage>,
    #[serde(default)]
    prompt_eval_count: u64,
    #[serde(default)]
    eval_count: u64,
    #[serde(default)]
    done_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    content: String,
}

impl Backend for Ollama {
    fn complete(&mut self, role: Role, conversation: &Conversation) -> Result<Completion, InferError> {
        // Role Q's shape is a security boundary, so a schema is required rather
        // than optional. "Constrained decoding" that constrains nothing would be
        // the worst possible outcome: it would satisfy the check while removing
        // the boundary.
        if role == Role::Extractor && self.extraction_schema.is_none() {
            return Err(InferError::Backend(
                "refusing to serve role Q without an extraction schema: constrained decoding \
                 with nothing to constrain is not a boundary"
                    .into(),
            ));
        }

        let mut body = json!({
            "model": self.models.model_for(role),
            "messages": Self::wire_messages(conversation),
            "stream": false,
        });

        // The planner's output is a restricted DSL, not prose. Ollama can enforce
        // a JSON Schema, so the planner is asked for a plan object rather than
        // free text; the caller parses it. A model that answers with anything else
        // fails here rather than reaching the parser.
        if role == Role::Planner {
            body["format"] = planner_schema();
        } else if let Some(schema) = &self.extraction_schema {
            body["format"] = schema.clone();
        }

        let reply: ChatReply = serde_json::from_value(self.post_json("/api/chat", &body)?)
            .map_err(|e| InferError::Backend(format!("unexpected reply shape: {e}")))?;
        let content = reply
            .message
            .map(|m| m.content)
            .ok_or_else(|| InferError::Backend("reply carried no message".into()))?;

        let usage = Usage {
            prompt_tokens: reply.prompt_eval_count,
            completion_tokens: reply.eval_count,
        };

        // The one output this backend is allowed to mark trusted.
        //
        // `Trusted::inherited(Origin::Controller(..))` is only sound here because
        // of what the caller cannot do: `Conversation::push` refuses untrusted
        // content for `Role::Planner`, so a planner conversation contains only
        // `Trusted` values, so the model's answer derives only from trusted input.
        // That argument is about the conversation, not about this function, which
        // is why it is written down here rather than left implicit.
        let output = match role {
            Role::Planner => {
                // `done_reason` is surfaced rather than swallowed: "length" means
                // the plan was cut off mid-statement and the caller must not
                // parse it as complete.
                if reply.done_reason.as_deref() == Some("length") {
                    return Err(InferError::Backend(
                        "planner output was truncated at the length limit; a partial plan is not \
                         a plan"
                            .into(),
                    ));
                }
                Output::PlannerText(Trusted::inherited(
                    Origin::Controller(ControllerAuthority::issue()),
                    content,
                ))
            }
            Role::Extractor => {
                let value: Value = serde_json::from_str(&content).map_err(|e| {
                    InferError::SchemaViolation(format!(
                        "extractor output is not JSON despite a schema being enforced: {e}"
                    ))
                })?;
                // Tainted regardless of what Ollama claimed to enforce. The
                // document was hostile, so anything derived from it is; the
                // schema constrains shape and cannot launder provenance.
                Output::Extracted(Val::tainted(
                    agentos_types::SourceId::of_kind(agentos_types::SourceKind::WebPage),
                    value,
                ))
            }
        };

        Ok(Completion { output, usage })
    }

    fn supports_constrained_decoding(&self) -> bool {
        // Ollama's `/api/chat` takes a `format` JSON Schema and applies it as a
        // sampler-side grammar. Claimed, and independently re-checked host-side by
        // the quarantine validator, so a false claim degrades to a validation
        // failure rather than to a leak.
        true
    }

    fn name(&self) -> &str {
        "ollama"
    }
}

/// The shape the planner must answer in.
///
/// A deliberately small object rather than the DSL's own grammar, because
/// Ollama enforces JSON Schema and not a bespoke grammar. The `program` field is
/// a list of statements, each already restricted to the operation kinds the
/// interpreter accepts, so a model cannot express something the parser would
/// reject — it can only produce a list the interpreter then still validates.
fn planner_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["program"],
        "properties": {
            "program": {
                "type": "array",
                "maxItems": 32,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["op"],
                    "properties": {
                        "op": { "type": "string", "enum": ["let", "report", "for"] },
                        "name": { "type": "string", "maxLength": 64,
                                  "pattern": "^[A-Za-z_][A-Za-z0-9_]*$" },
                        "value": { "type": "string", "maxLength": 4096 },
                        "body": {
                            "type": "array", "maxItems": 16,
                            "items": { "type": "object" }
                        }
                    }
                }
            }
        }
    })
}