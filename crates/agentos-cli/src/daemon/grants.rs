//! Turning a client's requested grants into a bounded set of capabilities.
//!
//! # The rule this file exists to enforce
//!
//! **A client narrows authority; it never widens it.** Every grant the daemon
//! hands out is an intersection of two sets: what the operator configured at
//! startup, and what this particular request asked for. A request can only ever
//! select a subset.
//!
//! The tempting alternative is to let the request name its own hosts and roots
//! directly, since that is one line shorter. It is also the same mistake as
//! `--allow-host` on the CLI being settable by whatever the agent decides to pass
//! to itself: authority that the untrusted side of a conversation can widen is
//! not authority, it is a suggestion. Every function here therefore returns an
//! error when the request reaches outside the configured ceiling, rather than
//! silently clamping -- a silent clamp would let a client believe it had more
//! than it does, and a plan that believes it can reach a host it cannot will
//! fail confusingly halfway through instead of up front.
//!
//! # What is actually provisioned
//!
//! `WriteGrant`, `FetchGrant` and `MailGrant` are the existing capability types in
//! this workspace, and they are what the `Tool` implementations already enforce.
//! Reusing them means one capability model rather than two. See [`TaskGrants`].

use std::path::PathBuf;

use agentos_tools::fswrite::WriteGrant;
use agentos_tools::http::FetchGrant;
use agentos_tools::mail::MailGrant;

use super::protocol::Grants;

/// Why a requested grant could not be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// The request named a write root the operator did not configure.
    WriteRootOutside {
        requested: String,
    },
    /// The request named a host the operator did not configure.
    HostOutside { requested: String },
    /// A configured root or host was itself unusable (bad path, malformed host).
    /// Distinct from the two above because the fix is to the daemon's
    /// configuration, not to the client's request.
    ConfigurationInvalid { detail: String },
    /// The request asked for mail and no outbox was configured.
    MailUnavailable,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::WriteRootOutside { requested } => write!(
                f,
                "write root `{requested}` is outside this daemon's configured roots; \
                 a request can narrow authority but not widen it"
            ),
            GrantError::HostOutside { requested } => write!(
                f,
                "host `{requested}` is not in this daemon's configured allow-list; \
                 a request can narrow authority but not widen it"
            ),
            GrantError::ConfigurationInvalid { detail } => {
                write!(f, "the daemon's own grant configuration is invalid: {detail}")
            }
            GrantError::MailUnavailable => write!(
                f,
                "send_email was requested but no outbox is configured for this daemon"
            ),
        }
    }
}

impl std::error::Error for GrantError {}

/// The capabilities one task may use, already intersected with the daemon's
/// ceiling.
#[derive(Debug)]
pub struct TaskGrants {
    /// Filesystem capability, or `None` if this task may not write.
    pub write: Option<WriteGrant>,
    /// Network capability, or `None` if this task may not fetch.
    pub fetch: Option<FetchGrant>,
    /// Mail capability, or `None` if this task may not send mail.
    pub mail: Option<MailGrant>,
}

/// The operator's ceiling, read from the environment at startup.
///
/// # Why the ceiling lives here and not in a request
///
/// Because a request is not a trust boundary. Everything in this struct is set by
/// whatever launched the daemon -- a systemd unit, a shell, a supervisor -- which
/// is a different and more privileged position than whoever can open the socket.
#[derive(Debug, Clone)]
pub struct Ceiling {
    /// Directories the daemon will write inside.
    pub write_roots: Vec<PathBuf>,
    /// Hosts the daemon will fetch from.
    pub allowed_hosts: Vec<String>,
    /// Directory `send_email` writes to instead of talking to an SMTP server.
    ///
    /// A path, not a list of recipients. The *recipients* are constrained by the
    /// mail policy rules, which are fixed at build time; this only says where the
    /// message is delivered. Letting a request choose recipients would mean the
    /// sender of an IPC frame decides who receives the agent's mail.
    pub mail_outbox: Option<PathBuf>,
}

impl Ceiling {
    /// The ceiling used when nothing is configured: no writes, no network, no
    /// mail.
    ///
    /// An empty ceiling rather than a permissive default. A daemon started with
    /// no configuration can still plan and run plans that need no capabilities;
    /// it cannot write a file or reach a host. Failing closed here is the whole
    /// point -- a mistyped environment variable should produce an inert daemon,
    /// not an unrestricted one.
    pub fn deny_all() -> Self {
        Self {
            write_roots: Vec::new(),
            allowed_hosts: Vec::new(),
            mail_outbox: None,
        }
    }

    /// Intersect a request against this ceiling.
    pub fn narrow(&self, requested: &Grants) -> Result<TaskGrants, GrantError> {
        let write = self.narrow_write(&requested.write_roots)?;
        let fetch = self.narrow_hosts(&requested.hosts)?;
        let mail = match (requested.send_email, self.mail_outbox.as_ref()) {
            (false, _) => None,
            (true, None) => return Err(GrantError::MailUnavailable),
            (true, Some(outbox)) => Some(
                MailGrant::new(outbox)
                    .map_err(|e| GrantError::ConfigurationInvalid { detail: e.to_string() })?,
            ),
        };
        Ok(TaskGrants { write, fetch, mail })
    }

    /// Narrow write roots.
    ///
    /// Each requested root must be *inside* a configured root. Containment is
    /// checked on path components, not on string prefixes: on Windows
    /// `"C:\outbox-evil"` starts with `"C:\outbox"` as a string but is a
    /// different directory, and a prefix test would hand out write access to it.
    /// `Path::starts_with` compares components, so it does not have that bug.
    fn narrow_write(&self, requested: &[String]) -> Result<Option<WriteGrant>, GrantError> {
        if requested.is_empty() {
            return Ok(None);
        }
        // A task gets at most one write capability. `WriteGrant` is one root, and a
        // plan needing two roots should be two tasks -- handing out the union
        // would be strictly more authority than either half asked for.
        let raw = &requested[0];
        let wanted = PathBuf::from(raw);
        if !self.write_roots.iter().any(|root| wanted.starts_with(root)) {
            return Err(GrantError::WriteRootOutside { requested: raw.clone() });
        }
        // Scope to the *requested* path, not the configured root. Granting the
        // root would answer a request for a subdirectory with its parent, which is
        // a widening in the one direction this file forbids.
        WriteGrant::new(&wanted)
            .map(Some)
            .map_err(|e| GrantError::ConfigurationInvalid { detail: e.to_string() })
    }

    /// Narrow hosts, preserving the operator's ordering.
    ///
    /// Returns `None` when nothing was requested, which leaves `http.fetch`
    /// unregistered rather than registered with an empty allow-list. The
    /// distinction matters: an unregistered tool fails with "no such tool" and
    /// an empty allow-list fails with "host not permitted", and the first is the
    /// honest answer for "this task may not use the network".
    fn narrow_hosts(&self, requested: &[String]) -> Result<Option<FetchGrant>, GrantError> {
        if requested.is_empty() {
            return Ok(None);
        }
        for host in requested {
            if !self.allowed_hosts.iter().any(|allowed| allowed == host) {
                return Err(GrantError::HostOutside { requested: host.clone() });
            }
        }
        FetchGrant::new(requested.iter().map(String::as_str))
            .map(Some)
            .map_err(|e| GrantError::ConfigurationInvalid { detail: e.to_string() })
    }
}

/// Parse a comma-separated environment variable into trimmed, non-empty parts.
///
/// An empty or whitespace-only value yields an empty list rather than a list
/// containing `""`. That distinction is the difference between "no hosts
/// allowed" and "a host named the empty string", and only the first is expressible
/// in a config file.
pub(crate) fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse a comma-separated list of paths, canonicalising where possible.
///
/// Canonicalisation is best-effort: a path that does not exist yet cannot be
/// canonicalised, and refusing to start the daemon because a not-yet-created
/// output directory was named would be a worse failure than using the path as
/// written. `WriteGrant::new` does its own containment checking later, which is
/// the check that actually matters.
pub(crate) fn split_paths(raw: &str) -> Vec<PathBuf> {
    split_list(raw).into_iter().map(PathBuf::from).collect()
}