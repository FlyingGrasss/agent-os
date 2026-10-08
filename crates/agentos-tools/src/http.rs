//! `http.fetch`: read a URL the operator decided this tool may read.
//!
//! This is the ingress side of invariant I1. Its whole purpose is to produce
//! attacker-controlled bytes and hand them to the quarantined extractor with the
//! provenance still attached, so the single most important thing in this module
//! is that **the result is always labelled `Tainted` with a
//! [`SourceKind::WebPage`] source**, whatever the arguments said. A trusted
//! result here is not a bug, it is a direct break of I1: the Controller would
//! read a web page as though the user had typed it.
//!
//! # Policy and confinement are two different controls
//!
//! As in [`crate::fswrite`], the argument is attacker-influenced text and the
//! authority is agent-authored configuration:
//!
//! * **Policy** ([`agentos_policy`]) asks where the `url` came from. A URL off a
//!   web page is refused before dispatch unless the user confirmed the domain.
//! * **Confinement** (this module) asks what this tool may reach. It answers
//!   that from a [`FetchGrant`] handed in at construction. There is no argument
//!   that can name a host, widen the allowlist, change a port, or raise the byte
//!   ceiling; [`LabelledFetchArgs::from_call`] refuses an undeclared argument
//!   before anything else happens.
//!
//! # Why a URL allowlist is a security boundary and not a convenience
//!
//! This repository has already been bitten twice here, and both bugs are in
//! `agentos-policy`'s host parser, which the tool deliberately does not reuse:
//!
//! 1. `file://good.test/etc/passwd` satisfied a host allowlist, because the
//!    check was on the authority and `file` is a scheme whose handling this
//!    runtime never reasoned about. Here the scheme allowlist is consulted
//!    *before* the host, and defaults to `https` only.
//! 2. `https://evil.test\@good.test/` bypassed an allowlist entirely, because
//!    userinfo was stripped before the backslash was looked at and a browser
//!    reads the backslash as a separator. Here a backslash anywhere in the URL
//!    is refused outright, and userinfo is refused too, so there is no
//!    "strip it and carry on" step to get wrong.
//!
//! Everything after that is the same class of bug, so it is refused rather than
//! parsed: percent escapes are never decoded, fragments are refused, a trailing
//! dot is refused, a host must have at least two labels, and only the scheme's
//! default port is accepted. A parser that rejects the ambiguous spelling has
//! no second opinion to disagree with.
//!
//! # Redirects are re-validated from scratch, never followed
//!
//! Every hop goes through the same [`FetchUrl`] construction and the same
//! address check as the first request. A redirect off the allowlist, to a
//! non-default port, or to an address that resolves privately is a refusal. The
//! transport is given the redirect as data and returns it; following it is this
//! module's job precisely so that there is one implementation of the checks.
//!
//! # Server-side request forgery
//!
//! An allowlist of host *names* does not stop a fetch of `169.254.169.254` or of
//! `internal.corp` if that name is listed, and a name that resolves to
//! `127.0.0.1` turns an allowed fetch into a request to the daemon's own
//! loopback interface. So every address the host resolves to is checked against
//! [`address_is_routable`], and **all** of them must pass: choosing the public
//! one from a mixed answer is an attacker-controlled choice among the attacker's
//! own records, and it is how DNS rebinding is turned back into a private fetch.
//! A literal address in the URL is vetted the same way, so listing `127.0.0.1`
//! in the grant does not make it fetchable.
//!
//! # What this does *not* protect against
//!
//! * **There is no network confinement here.** [`TcpTransport`] opens the socket
//!   in the daemon process, so the fetch is not inside a Landlock profile and
//!   the `socket(2)` refusal in the `Filesystem` sandbox profile does not apply
//!   to it. Every control in this module is a check in userspace code, and a
//!   bug in the URL parser is a bug in the daemon. Running this in a confined
//!   worker with a descriptor-passed socket is the intended deployment and is
//!   not implemented; [`Transport`] exists so that worker can be dropped in.
//! * **There is no TLS.** [`TcpTransport`] refuses `https`, and the default
//!   grant allows `https` and nothing else, so a default-configured fetch
//!   fails with [`FetchError::TlsUnsupported`] rather than silently downgrading
//!   to plaintext. Closing this needs a TLS dependency, which changes the
//!   posture of the whole workspace and is not this module's decision.
//! * **The address check is advisory against a hostile resolver.** The tool
//!   hands the vetted addresses to the transport and the transport must connect
//!   to one of them, but a transport that re-resolves the name has reintroduced
//!   DNS rebinding. [`FetchRequest`] documents the requirement.
//! * **The deadline is only as good as the transport.** A transport that ignores
//!   [`Limits::total_timeout`] can hang the daemon. [`Transport::send`] is
//!   synchronous; enforcing the bound against a transport that ignores it needs
//!   a worker process with a hard kill.
//! * **Bodies are carried as text.** `PlanData` has no byte-string, so a binary
//!   body is `from_utf8_lossy`'d. That corrupts binary documents; it does not
//!   make them safe to read.

#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use agentos_dsl::{PlanData, PlanError, PlanValue};
use agentos_policy::RuleSet;
use agentos_types::{Label, SourceId, SourceKind, Val};
use schemars::JsonSchema;
use serde::Serialize;

use crate::host::Tool;

/// Tool name, and the `(tool, argument)` prefix the policy rules are keyed on:
/// `http.fetch.url`.
pub const TOOL_NAME: &str = "http.fetch";
/// The only argument: an absolute `http`/`https` URL.
pub const ARG_URL: &str = "url";

/// Longest URL accepted, in bytes.
///
/// A bound, not a validation: a megabyte of URL is not a fetch anyone intended,
/// and it is also megabytes of attacker-chosen text flowing into DNS and into
/// refusal messages that do not print it.
pub const MAX_URL_LEN: usize = 2048;
/// Longest header block accepted from a server, in bytes.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Longest `Location` value accepted from a server, in bytes.
pub const MAX_LOCATION_LEN: usize = 2048;
/// Longest `Content-Type` value echoed back into a result, in bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 128;
/// Default ceiling on the response body, in bytes.
pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
/// Default ceiling on the connect phase.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default ceiling on the whole exchange, connect included.
pub const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Default number of redirects followed before the fetch is refused.
pub const DEFAULT_MAX_REDIRECTS: usize = 3;

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// The declared argument shape, and the source of the schema the planner sees.
///
/// One field. Every other input to this tool - which hosts, which schemes, which
/// port, how many bytes, how long - is in [`FetchGrant`], held at construction,
/// because an argument is text the attacker may have written.
///
/// `deny_unknown_fields` is load-bearing: an argument the schema does not name
/// is an argument no policy rule was ever written for, and
/// [`LabelledFetchArgs::from_call`] refuses it for the same reason.
///
/// `Serialize` and not `Deserialize`, for the reason [`crate::fswrite`] gives:
/// these fields carry no provenance label, so a `Deserialize` impl would hand
/// out unlabelled values that look like tool input. The type the tool reads is
/// [`LabelledFetchArgs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchUrlArgs {
    /// Absolute URL to read. The host must be on the tool's grant, the scheme
    /// must be one the grant enables, and the host must not resolve to a
    /// private address.
    pub url: String,
}

impl FetchUrlArgs {
    /// The JSON schema for this tool's arguments.
    pub fn schema() -> schemars::schema::RootSchema {
        schemars::schema_for!(FetchUrlArgs)
    }
}

/// A parsed call, with the URL still carrying its provenance.
///
/// There is no constructor from a plain `String`. The only way to build one is
/// from a `BTreeMap<String, PlanValue>`, and `from_call` copies the label off
/// the value it takes, so there is no line on which a URL arrives unlabelled
/// and is then compared against the allowlist as though it were trusted.
///
/// The label is *not* consulted when the fetch is authorised. It has already
/// been, by the policy engine, before dispatch. This tool must not re-derive a
/// permission from the label: the allowlist, not the label, decides what may be
/// reached, and a `Trusted` URL is still an untrusted server's response.
#[derive(Debug, Clone)]
pub struct LabelledFetchArgs {
    url: Val<String>,
}

impl LabelledFetchArgs {
    /// Read a call's arguments.
    ///
    /// Refuses a missing argument, an argument the schema does not declare, and
    /// a value with no text form. `Quoted` is excluded from the text form on
    /// purpose: quarantined text exists to be unreadable by the Controller, and
    /// a tool that accepted it here would be a way to read it.
    pub fn from_call(args: &BTreeMap<String, PlanValue>) -> Result<Self, FetchError> {
        for name in args.keys() {
            if name != ARG_URL {
                return Err(FetchError::UnexpectedArg(name.clone()));
            }
        }
        let url = args.get(ARG_URL).ok_or(FetchError::MissingArg(ARG_URL))?;
        let (text, type_name, label) = url
            .with_label_for_display(|data, label| (scalar_text(data), data.type_name(), label.clone()));
        match text {
            Some(t) => Ok(Self {
                url: Val::labeled(t, label),
            }),
            None => Err(FetchError::NotText {
                arg: ARG_URL,
                type_name,
            }),
        }
    }

    /// The requested URL, still labelled.
    pub fn url(&self) -> &Val<String> {
        &self.url
    }
}

fn scalar_text(data: &PlanData) -> Option<String> {
    match data {
        PlanData::Str(s) | PlanData::Enum(s) => Some(s.clone()),
        PlanData::Int(i) => Some(i.to_string()),
        PlanData::Bool(b) => Some(b.to_string()),
        // `Quoted` is quarantined on purpose and `Unit`/`Record`/`List` have no
        // single text form. Treating either as an empty string would turn a
        // refusal into a fetch of `/`.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a fetch did not happen.
///
/// Nothing in here formats the URL, the host, or the body. The host stringifies
/// a failed tool call into the audit log, and the audit log is a Controller
/// input: a refusal that echoed `https://evil.test/ignore-previous...` would put
/// attacker-chosen bytes into a prompt with the session's authority behind them.
/// Argument *names* are echoed, because the planner writes those, which is the
/// assumption [`crate::audit::OutcomeKind`] already documents.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// A declared argument was absent.
    #[error("`http.fetch` requires a `{0}` argument")]
    MissingArg(&'static str),
    /// An argument the schema does not declare was present. Refused rather than
    /// ignored, because an ignored argument is authority nobody classified.
    #[error("`http.fetch` takes only `url`; `{0}` is not a declared argument")]
    UnexpectedArg(String),
    /// The argument has no text form, so there is nothing to parse as a URL.
    #[error("`{arg}` is a {type_name}, which has no text form to fetch")]
    NotText {
        /// The argument that had no text form.
        arg: &'static str,
        /// Its plan type, so the planner can be told what it passed.
        type_name: &'static str,
    },

    /// Over [`MAX_URL_LEN`].
    #[error("the URL is longer than this tool will look at")]
    UrlTooLong,
    /// Contains a backslash. Browsers read it as a separator, which is how
    /// `https://evil.test\@good.test/` once slipped past an allowlist.
    #[error("the URL contains a backslash, which browsers read as a path separator")]
    UrlHasBackslash,
    /// Contains a control character or non-ASCII text, so header injection and
    /// IDN homograph spellings are both out of reach.
    #[error("the URL contains a control character or non-ASCII text")]
    UrlHasControlChar,
    /// Carries a fragment, which is never sent to a server.
    #[error("the URL carries a fragment, which is never sent to a server")]
    UrlHasFragment,
    /// No scheme, so no fetch this tool knows how to make.
    #[error("the URL has no scheme, so it names no fetch this tool can make")]
    NoScheme,
    /// The grant does not enable this scheme. This is the `file://` bug's
    /// control, and it is consulted before the host.
    #[error("the URL's scheme is not one this tool's grant enables")]
    SchemeNotAllowed,
    /// The authority carries userinfo. Refused rather than stripped, because
    /// stripping it is the step that made a host comparison disagree with the
    /// browser.
    #[error("the URL's authority carries userinfo, which is refused rather than stripped")]
    AuthorityHasUserinfo,
    /// The authority does not parse as host and optional port.
    #[error("the URL's authority is malformed")]
    BadAuthority,
    /// The path could not go on a request line safely, because it contains a
    /// character that would end the target and start a header or a second
    /// request. Refused rather than escaped.
    #[error("the URL's path contains a character that cannot be sent on a request line")]
    UnsafeRequestTarget,
    /// No host in the authority.
    #[error("the URL names no host")]
    NoHost,
    /// The host is neither a well-formed name nor an address literal.
    #[error("the host is not a well-formed name or address literal")]
    MalformedHost,
    /// The host ends in a dot: a second spelling of a name the allowlist may not
    /// contain, and DNS treats it as the same host.
    #[error("the host ends in a dot, which is a second spelling of a name the allowlist may not contain")]
    HostTrailingDot,
    /// One label, which the resolver would complete from a local search domain.
    #[error("the host has a single label, which the resolver would complete from a local search domain")]
    HostSingleLabel,
    /// A port other than the scheme's default, so the grant would be naming a
    /// service rather than a host.
    #[error("the port is not the scheme's default, so the allowlist entry names a host rather than a service")]
    NonDefaultPort,
    /// Not on the grant.
    #[error("the host is not on this tool's grant")]
    HostNotAllowed,
    /// The grant itself names something that is not a well-formed host, so it
    /// was refused at construction rather than stored as authority that looks
    /// valid.
    #[error("the grant names a host that is not a well-formed name or address")]
    MalformedGrant,
    /// Resolution failed.
    #[error("the host could not be resolved")]
    ResolutionFailed,
    /// Resolution succeeded but produced nothing to connect to.
    #[error("the host resolved to no addresses")]
    NoAddresses,
    /// At least one resolved address is loopback, private, link-local,
    /// multicast, broadcast or reserved. This is the server-side request forgery
    /// control, and one bad address refuses the whole fetch: picking the good one
    /// out of a mixed answer hands the choice to whoever controls the name.
    #[error("the host resolves to an address that is not routable on the public internet, which is a server-side request forgery")]
    AddressNotRoutable,
    /// The redirect target is neither an absolute URL nor an absolute path.
    #[error("the redirect target could not be understood; only an absolute URL or an absolute path is followed")]
    RedirectUnparseable,
    /// A 3xx with no `Location`.
    #[error("the server asked for a redirect without naming a target")]
    RedirectWithoutLocation,
    /// More redirects than [`FetchGrant::with_max_redirects`] permits.
    #[error("the fetch was redirected more times than this tool will follow")]
    TooManyRedirects,
    /// More body bytes than [`Limits::max_bytes`]. Refused, never truncated.
    #[error("the response body is larger than this tool will read")]
    ResponseTooLarge,
    /// More header bytes than [`MAX_HEADER_BYTES`].
    #[error("the response headers are larger than this tool will read")]
    HeadersTooLarge,
    /// Chunked or otherwise encoded transfer. Refused rather than decoded
    /// partially: a body this tool did not decode is not a body to reason about.
    #[error("the response used a transfer encoding this tool does not decode")]
    UnsupportedTransferEncoding,
    /// The response was not an HTTP/1.x response this tool could read.
    #[error("the server's response did not parse as an HTTP status line")]
    MalformedResponse,
    /// The connect or total budget ran out.
    #[error("the fetch exceeded its time budget")]
    TimedOut,
    /// The socket could not be opened.
    #[error("the connection failed")]
    ConnectFailed,
    /// The exchange failed. The message is bounded by [`crate::audit::MAX_REASON`].
    #[error("the transport failed: {0}")]
    TransportFailed(String),
    /// The URL was `https` and no TLS transport is installed.
    #[error("this tool has no TLS transport, so an `https` fetch cannot be made; install one rather than downgrading to plaintext")]
    TlsUnsupported,
    /// Not a 2xx and not a followed 3xx, so there is no body to read.
    #[error("the server answered with a status this tool will not treat as a body")]
    UnexpectedStatus(u16),
}

impl FetchError {
    /// Report a transport failure, with the message bounded.
    ///
    /// The cap is here because this is the one error a [`Transport`] outside this
    /// crate will reach for, and a refusal that grows to whatever a misbehaving
    /// transport passed in becomes an unbounded string in the audit log.
    pub fn transport(message: impl fmt::Display) -> FetchError {
        let mut text = message.to_string();
        if text.len() > crate::audit::MAX_REASON {
            text.truncate(crate::audit::MAX_REASON);
            while !text.is_char_boundary(text.len()) {
                text.pop();
            }
        }
        FetchError::TransportFailed(text)
    }
}

// ---------------------------------------------------------------------------
// The grant: agent-authored authority
// ---------------------------------------------------------------------------

/// Time and size bounds handed to every fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Ceiling on the connect phase.
    pub connect_timeout: Duration,
    /// Ceiling on the whole exchange, connect included.
    pub total_timeout: Duration,
    /// Ceiling on the response body. A body over this is refused, never
    /// truncated: a silent truncation turns a refusal into a plan that reasons
    /// about half a document.
    pub max_bytes: usize,
}

impl Default for Limits {
    /// Finite by default. A tool with no timeout is a denial-of-service
    /// primitive handed to whoever can influence an argument, so "unbounded" has
    /// to be written down explicitly rather than reached by omitting a field.
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// What this tool is allowed to reach.
///
/// Held as a value with private fields and validating constructors, never taken
/// from an argument. If the host allowlist could be named in a call, an attacker
/// who controlled `url` would control the allowlist, and the allowlist would
/// reduce to "do what the arguments say".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchGrant {
    hosts: BTreeSet<String>,
    schemes: BTreeSet<String>,
    limits: Limits,
    max_redirects: usize,
}

impl FetchGrant {
    /// A grant that may fetch exactly these hosts, over `https` only.
    ///
    /// `https` and nothing else, because a plaintext default would make the
    /// common mistake the safe one. Enabling `http` is a separate, explicit act.
    pub fn new<I, S>(hosts: I) -> Result<Self, FetchError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = BTreeSet::new();
        for host in hosts {
            set.insert(normalise_grant_host(host.as_ref())?);
        }
        Ok(Self {
            hosts: set,
            schemes: BTreeSet::from(["https".to_string()]),
            limits: Limits::default(),
            max_redirects: DEFAULT_MAX_REDIRECTS,
        })
    }

    /// Permit another host.
    pub fn allowing(mut self, host: &str) -> Result<Self, FetchError> {
        self.hosts.insert(normalise_grant_host(host)?);
        Ok(self)
    }

    /// Permit a scheme. `http` here means plaintext; the grant does not pretend
    /// otherwise and [`TcpTransport`] will serve it.
    pub fn with_scheme(mut self, scheme: &str) -> Result<Self, FetchError> {
        let scheme = scheme.to_ascii_lowercase();
        if !is_well_formed_scheme(&scheme) {
            return Err(FetchError::MalformedGrant);
        }
        // Only the two schemes this module can actually speak. `is_well_formed`
        // alone would let a grant name `foo://`, and `default_port` would then
        // have no answer for it - which is the right way for that to fail, at
        // configuration time where an operator will read the message, rather
        // than at fetch time as an unexplained refusal.
        if default_port(&scheme).is_none() {
            return Err(FetchError::MalformedGrant);
        }
        self.schemes.insert(scheme);
        Ok(self)
    }

    /// Replace the time and size bounds.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set how many redirects may be followed.
    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// The hosts this grant names, lowercased.
    pub fn hosts(&self) -> &BTreeSet<String> {
        &self.hosts
    }

    /// The schemes this grant enables.
    pub fn schemes(&self) -> &BTreeSet<String> {
        &self.schemes
    }

    /// The bounds every fetch runs under.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// How many redirects may be followed.
    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }
}

/// Validate and lowercase a host named in configuration.
///
/// Checked at construction so that a grant cannot contain a spelling this
/// parser would later refuse, which would leave an entry that looks like
/// authority and is not.
fn normalise_grant_host(host: &str) -> Result<String, FetchError> {
    let lower = host.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Err(FetchError::MalformedGrant);
    }
    if lower.parse::<IpAddr>().is_ok() {
        return Ok(lower);
    }
    if is_well_formed_host(&lower) {
        Ok(lower)
    } else {
        Err(FetchError::MalformedGrant)
    }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// A URL that has passed every syntactic rule and is on the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchUrl {
    scheme: String,
    host: String,
    port: u16,
    target: String,
    literal: Option<IpAddr>,
}

impl FetchUrl {
    /// Parse and authorise a requested URL.
    ///
    /// The order of the checks is the point. Scheme, then the characters that
    /// two parsers could disagree about, then the authority, then the host's
    /// shape, then the allowlist. Nothing is compared against the allowlist
    /// before the spelling has been reduced to a single host.
    pub fn parse(raw: &str, grant: &FetchGrant) -> Result<Self, FetchError> {
        if raw.len() > MAX_URL_LEN {
            return Err(FetchError::UrlTooLong);
        }
        if raw.contains('\\') {
            return Err(FetchError::UrlHasBackslash);
        }
        if raw.contains('#') {
            return Err(FetchError::UrlHasFragment);
        }
        if !raw.is_ascii() || raw.chars().any(|c| c.is_ascii_control()) {
            return Err(FetchError::UrlHasControlChar);
        }

        let (scheme, rest) = raw.split_once("://").ok_or(FetchError::NoScheme)?;
        if !is_well_formed_scheme(scheme) {
            return Err(FetchError::NoScheme);
        }
        let scheme = scheme.to_ascii_lowercase();

        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        if authority.is_empty() {
            return Err(FetchError::NoHost);
        }
        if authority.contains('@') {
            return Err(FetchError::AuthorityHasUserinfo);
        }

        let url = Self::build(&scheme, authority, tail)?;
        url.authorise(grant)?;
        Ok(url)
    }

    /// Build from parts, applying every syntactic rule that does not depend on
    /// configuration. Shared with redirect handling so there is one parser.
    fn build(scheme: &str, authority: &str, tail: &str) -> Result<Self, FetchError> {
        let (host_text, port) = split_authority(authority)?;
        let host = host_text.to_ascii_lowercase();
        if host.is_empty() {
            return Err(FetchError::NoHost);
        }
        let literal = literal_of(&host, authority.starts_with('['));

        if let Some(addr) = literal {
            // An address literal bypasses the name rules on purpose; it is
            // checked for routability later, which is the control that matters.
            let _ = addr;
        } else {
            if host.ends_with('.') {
                return Err(FetchError::HostTrailingDot);
            }
            if !is_well_formed_host(&host) {
                return Err(FetchError::MalformedHost);
            }
            if !host.contains('.') {
                return Err(FetchError::HostSingleLabel);
            }
        }

        Ok(Self {
            scheme: scheme.to_string(),
            // A URL that omits its port means the scheme's default, and saying so
            // here rather than in `authorise` keeps `port()` meaningful to the
            // transport, which has to pass a real port to `connect`.
            port: if port == 0 {
                default_port(scheme).ok_or(FetchError::SchemeNotAllowed)?
            } else {
                port
            },
            host,
            target: normalise_target(tail),
            literal,
        })
    }

    /// Apply the configuration-dependent checks: scheme allowlist, host
    /// allowlist, and the port.
    fn authorise(&self, grant: &FetchGrant) -> Result<(), FetchError> {
        // Scheme first. `file://good.test/etc/passwd` is the recorded bug in
        // this repository, and it is only reachable by asking the host question
        // before asking whether the scheme is one this tool does at all.
        if !grant.schemes.contains(&self.scheme) {
            return Err(FetchError::SchemeNotAllowed);
        }
        match default_port(&self.scheme) {
            Some(default) if self.port == default => {}
            Some(_) => return Err(FetchError::NonDefaultPort),
            // Reachable only via a redirect: `follow` on a path keeps the scheme,
            // so this is here to make the invariant total rather than because a
            // path-absolute redirect can change it.
            None => return Err(FetchError::SchemeNotAllowed),
        }
        // Whole-host equality, never `starts_with`. `good.test.evil.test` has
        // `good.test` as a string prefix and is a different machine.
        if !grant.hosts.contains(&self.host) {
            return Err(FetchError::HostNotAllowed);
        }
        if !is_safe_request_target(&self.target) {
            return Err(FetchError::UnsafeRequestTarget);
        }
        Ok(())
    }

    /// The scheme, lowercased.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased and without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, always the scheme's default.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The origin-form request target: always starts with `/`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The address literal this URL names, if it names one.
    pub fn literal(&self) -> Option<IpAddr> {
        self.literal
    }

    /// The host as it belongs in an authority, bracketed if it is IPv6.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// Resolve a `Location` value against this URL, then authorise the result.
    ///
    /// Only two spellings are followed: an absolute URL, which goes through
    /// [`FetchUrl::parse`] like anything else, and an absolute path, which stays
    /// on this URL's host. A network-path reference (`//other.test/x`) is
    /// deliberately read as a *path* on the current host rather than as a host
    /// change. That is not what a browser does, and the deviation is in the safe
    /// direction: it cannot leave the allowlist.
    pub fn follow(&self, location: &str, grant: &FetchGrant) -> Result<Self, FetchError> {
        if location.len() > MAX_LOCATION_LEN {
            return Err(FetchError::UrlTooLong);
        }
        if location.contains('\\') {
            return Err(FetchError::UrlHasBackslash);
        }
        if location.contains('#') {
            return Err(FetchError::UrlHasFragment);
        }
        if !location.is_ascii() || location.chars().any(|c| c.is_ascii_control()) {
            return Err(FetchError::UrlHasControlChar);
        }
        // Path-absolute is tested first, not second. A reference that begins with
        // `/` is a path by RFC 3986 and cannot be an absolute URL, and a query
        // string on one may well contain `://` — testing for that first would
        // refuse an ordinary redirect to `/next?from=https://example.test`.
        if !location.starts_with('/') {
            if location.contains("://") {
                return FetchUrl::parse(location, grant);
            }
            return Err(FetchError::RedirectUnparseable);
        }
        let next = FetchUrl::build(&self.scheme, &self.authority(), location)?;
        next.authorise(grant)?;
        Ok(next)
    }
}

impl fmt::Display for FetchUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}{}", self.scheme, self.authority(), self.port, self.target)
    }
}

/// RFC 3986's scheme grammar: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
///
/// The full grammar rather than alphanumerics only, because a scheme like
/// `https+evil` is a *parseable* scheme, and reporting it as "not a URL" would be
/// wrong in a way that matters: it would put the refusal in the wrong place, and
/// the test for it should be the allowlist's refusal rather than the parser's.
/// Nothing here decides what a scheme means. That is `FetchGrant`'s job.
fn is_well_formed_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// The port a scheme means when the URL omits one.
///
/// Only `http` and `https` have an answer. Every other scheme returns `None`,
/// which is the same argument `agentos-policy`'s `host_of` makes: a scheme whose
/// handling this module cannot reason about is a scheme whose semantics are
/// somebody else's decision, and returning a plausible-looking port would let an
/// operator enable `foo://` on the grant and have it silently fetched as
/// plaintext HTTP to port 80.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

/// Split an authority into its host text and port, refusing anything ambiguous.
///
/// Bracketed IPv6 is handled because `[::1]` is the only unambiguous spelling;
/// a bare `::1` has no way to say where the port stops, so it is refused rather
/// than guessed at. Multiple colons outside brackets land here too.
fn split_authority(authority: &str) -> Result<(&str, u16), FetchError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(FetchError::BadAuthority);
        };
        let host = &rest[..close];
        let after = &rest[close + 1..];
        return Ok((host, parse_port_suffix(after)?));
    }
    match authority.matches(':').count() {
        0 => Ok((authority, 0)),
        1 => {
            let (host, port) = authority.split_once(':').expect("counted one colon");
            let port = parse_port(port)?;
            Ok((host, port))
        }
        _ => Err(FetchError::BadAuthority),
    }
}

fn parse_port_suffix(after: &str) -> Result<u16, FetchError> {
    // Absent port: zero, which `build` reads as "the scheme's default".
    if after.is_empty() {
        return Ok(0);
    }
    let Some(port) = after.strip_prefix(':') else {
        return Err(FetchError::BadAuthority);
    };
    parse_port(port)
}

fn parse_port(text: &str) -> Result<u16, FetchError> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return Err(FetchError::BadAuthority);
    }
    let port: u32 = text.parse().map_err(|_| FetchError::BadAuthority)?;
    if port == 0 || port > 65535 {
        return Err(FetchError::BadAuthority);
    }
    Ok(port as u16)
}

/// The address literal a host text names, if it names one.
///
/// `bracketed` says whether the text came from inside `[...]`, which is what
/// distinguishes an IPv6 literal from a name that happens to contain colons.
fn literal_of(host: &str, bracketed: bool) -> Option<IpAddr> {
    if bracketed {
        return host.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

fn normalise_target(tail: &str) -> String {
    if tail.is_empty() {
        "/".to_string()
    } else {
        tail.to_string()
    }
}

/// Whether `target` is safe to put on a request line.
///
/// The request is built by string formatting, so a target holding a space, a
/// control character or a CR would let a crafted URL inject a second request or a
/// header. This is checked on the way *in*, once, at the point the string is
/// about to be interpolated.
///
/// Percent escapes are deliberately **not** decoded. Decoding is where a `%0d%0a`
/// becomes a header break and `%2f` becomes a path separator that the host
/// comparison never saw. Nothing here needs a decoded form: the allowlist is
/// checked against the host, which is parsed before any escaping is relevant.
fn is_safe_request_target(target: &str) -> bool {
    if target.is_empty() || !target.starts_with('/') {
        return false;
    }
    target
        .chars()
        .all(|c| c.is_ascii_graphic() && c != ' ' && c != '"' && c != '\\')
}

/// Whether `host` is a well-formed DNS name.
///
/// Labels of ASCII alphanumerics and hyphens, no empty labels, no label longer
/// than 63, and no leading or trailing dot. Underscores are allowed because
/// internal names use them; they are not legal in a hostname but refusing them
/// would make the grant unusable for real deployments, and this check is about
/// removing ambiguity rather than about proving a name exists.
fn is_well_formed_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

// ---------------------------------------------------------------------------
// Address vetting: the SSRF control
// ---------------------------------------------------------------------------

/// Whether an address may be fetched.
///
/// The question is "would a packet to this address leave the machine on the
/// public internet", and the safe direction is to say no unless it obviously
/// says yes. Everything refused here is either a loopback, a private, a
/// link-local (which is where cloud instance metadata lives), a multicast or
/// broadcast destination, or a range reserved for documentation or benchmarks.
///
/// IPv6 is where this is usually got wrong. An IPv4 address smuggled into an
/// IPv6 literal reaches the same host by another name, so mapped and compatible
/// forms are unwrapped and re-checked, and a 6to4 address is unwrapped too.
pub fn address_is_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_routable(v4),
        IpAddr::V6(v6) => v6_is_routable(v6),
    }
}

fn v4_is_routable(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    match (a, b) {
        // 0.0.0.0/8 "this network". Connecting to 0.0.0.0 reaches localhost on
        // Linux, which is the whole reason it is refused rather than treated as
        // merely unspecified.
        (0, _) => false,
        (10, _) => false,
        // 100.64.0.0/10 carrier-grade NAT: internal space, not the internet.
        (100, 64..=127) => false,
        (127, _) => false,
        (169, 254) => false,
        (172, 16..=31) => false,
        // 192.0.0.0/24 IETF protocol assignments and 192.0.2.0/24 documentation.
        (192, 0) if c == 0 || c == 2 => false,
        (192, 168) => false,
        // 198.18.0.0/15 benchmarking, 198.51.100.0/24 documentation.
        (198, 18 | 19) => false,
        (198, 51) if c == 100 => false,
        (203, 0) if c == 113 => false,
        // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255.
        (224..=255, _) => false,
        _ => true,
    }
}

fn v6_is_routable(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    // `to_ipv4` covers both `::ffff:a.b.c.d` and the older `::a.b.c.d`. Either
    // one is an IPv4 address wearing a hat, and vetting it as IPv6 would pass
    // `::ffff:127.0.0.1`.
    if let Some(v4) = ip.to_ipv4() {
        return v4_is_routable(&v4);
    }
    if let Some(v4) = six_to_four(seg) {
        return v4_is_routable(&v4);
    }
    let first = seg[0];
    // fc00::/7 unique local, fe80::/10 link-local, ff00::/8 multicast.
    if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 || first & 0xff00 == 0xff00 {
        return false;
    }
    // 2001:db8::/32 documentation.
    if first == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    true
}

/// The IPv4 address a 6to4 (`2002::/16`) address embeds, if it is one.
fn six_to_four(seg: [u16; 8]) -> Option<Ipv4Addr> {
    if seg[0] != 0x2002 {
        return None;
    }
    Some(Ipv4Addr::new(
        (seg[1] >> 8) as u8,
        seg[1] as u8,
        (seg[2] >> 8) as u8,
        seg[2] as u8,
    ))
}

// ---------------------------------------------------------------------------
// Transport seam
// ---------------------------------------------------------------------------

/// One fetch, already validated and already vetted.
///
/// Everything the transport needs is here and nothing else: there is no argument
/// for a host, because the host was decided by the grant, and no way for a
/// caller to hand the transport a different one.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// The validated URL.
    pub url: FetchUrl,
    /// Addresses the host resolved to, every one of which has been checked by
    /// [`address_is_routable`].
    ///
    /// A transport **must** connect to one of these and must not resolve the
    /// name again. Re-resolving re-opens the window between the check and the
    /// connect, which is exactly the window DNS rebinding uses.
    pub addrs: Vec<IpAddr>,
    /// The port to connect to.
    pub port: u16,
    /// The bounds this fetch runs under.
    pub limits: Limits,
}

/// What a server said, with no interpretation applied.
///
/// The redirect loop and every check live in this module, not in the transport,
/// so there is one implementation of "is this URL allowed" rather than one per
/// transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Location`, verbatim and unvalidated, if the server sent one.
    pub location: Option<String>,
    /// `Content-Type`, verbatim and unvalidated.
    pub content_type: Option<String>,
    /// The body, already bounded by `max_bytes`.
    pub body: Vec<u8>,
    /// Body bytes the transport saw on the wire. Headers are **not** counted, so
    /// this is comparable with [`Limits::max_bytes`] and with `body.len()`.
    ///
    /// Reported separately because a transport that stopped early would otherwise
    /// make an over-long response look like a short one, and the tool must
    /// refuse rather than reason about a prefix.
    pub bytes_seen: u64,
}

/// Turning a hostname into addresses.
///
/// A trait so the SSRF control is testable without a resolver, and so the
/// address a fetch actually connects to is decided in one place.
pub trait Resolver {
    /// Resolve `host` to the addresses a connection could use.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, FetchError>;
}

/// Moving bytes.
///
/// A trait so the tool's logic is testable without a network and so a
/// Landlock-confined worker can be dropped in behind it later.
pub trait Transport {
    /// Perform one request. The caller has already authorised the URL and vetted
    /// the addresses.
    fn send(&mut self, req: &FetchRequest) -> Result<RawResponse, FetchError>;
}

/// Resolves with the platform resolver.
///
/// This is the one place in the tool that talks to the operating system's DNS.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, FetchError> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<IpAddr> = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|_| FetchError::ResolutionFailed)?
            .map(|a| a.ip())
            .collect();
        if addrs.is_empty() {
            return Err(FetchError::NoAddresses);
        }
        Ok(addrs)
    }
}

// ---------------------------------------------------------------------------
// The tool
// ---------------------------------------------------------------------------

/// Write the policy rules for `http.fetch` into a [`RuleSet`].
///
/// The URL is the sensitive argument. [`agentos_policy::Rule::Allowlist`] is
/// the rule that matches what this tool actually enforces: a tainted URL is
/// permitted only when the user has confirmed its domain for this session, and
/// refused otherwise. Confirmation cannot override a deny, and an allowlisted
/// host still has to survive this module's own checks.
///
/// # Why this is a function and not part of `default_rules`
///
/// [`agentos_policy::PolicyEngine::default_rules`] lives in another crate and
/// carries an entry for `http.get`, a tool that does not exist. This function
/// is the declaration for `http.fetch`, kept next to the code that depends on
/// it. A host that never calls it gets `Confirm` for a tainted `url`, because
/// an absent rule defaults to `Confirm` - fail-closed, and useless, which is the
/// correct direction for a mistake.
pub fn install_policy_rules(rules: &mut RuleSet) {
    rules.allowlist_tainted(TOOL_NAME, ARG_URL);
}

/// What a successful fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The URL actually fetched, after any redirects.
    pub url: FetchUrl,
    /// Status code.
    pub status: u16,
    /// `Content-Type`, bounded.
    pub content_type: Option<String>,
    /// The body.
    pub body: Vec<u8>,
    /// How many redirects were followed.
    pub redirects: usize,
}

/// The `http.fetch` tool.
pub struct HttpFetch<T: Transport, R: Resolver> {
    grant: FetchGrant,
    resolver: R,
    transport: T,
}

impl HttpFetch<TcpTransport, SystemResolver> {
    /// Build the tool with the platform resolver and the std-only transport.
    pub fn new(grant: FetchGrant) -> Self {
        Self::with_parts(grant, SystemResolver, TcpTransport)
    }
}

impl<T: Transport, R: Resolver> HttpFetch<T, R> {
    /// Build the tool with a chosen resolver and transport.
    pub fn with_parts(grant: FetchGrant, resolver: R, transport: T) -> Self {
        Self {
            grant,
            resolver,
            transport,
        }
    }

    /// The authority this tool holds, for reporting to the user. There is no
    /// setter, so it cannot be widened after construction.
    pub fn grant(&self) -> &FetchGrant {
        &self.grant
    }

    /// Resolve a URL's addresses and check every one of them.
    ///
    /// All must pass, not some. Choosing the routable address out of a mixed
    /// answer hands the choice to whoever controls the name's records, and that
    /// is how a rebound name reaches a private address despite this check.
    fn vetted_addrs(&self, url: &FetchUrl) -> Result<Vec<IpAddr>, FetchError> {
        let addrs = match url.literal() {
            Some(ip) => vec![ip],
            None => self.resolver.resolve(url.host(), url.port())?,
        };
        if addrs.is_empty() {
            return Err(FetchError::NoAddresses);
        }
        for addr in &addrs {
            if !address_is_routable(addr) {
                return Err(FetchError::AddressNotRoutable);
            }
        }
        Ok(addrs)
    }

    /// Fetch one URL, following redirects under the same rules as the first hop.
    fn run(&mut self, raw_url: &str) -> Result<Fetched, FetchError> {
        let mut url = FetchUrl::parse(raw_url, &self.grant)?;
        let mut redirects = 0usize;

        loop {
            let addrs = self.vetted_addrs(&url)?;
            let req = FetchRequest {
                url: url.clone(),
                addrs,
                port: url.port(),
                limits: self.grant.limits(),
            };
            let resp = self.transport.send(&req)?;

            // Checked against the bytes seen, not the bytes kept. A transport
            // that truncated to fit would otherwise pass a check it just
            // defeated, and the plan downstream would reason about half a
            // document believing it read all of it.
            if resp.bytes_seen > self.grant.limits().max_bytes as u64
                || resp.body.len() > self.grant.limits().max_bytes
            {
                return Err(FetchError::ResponseTooLarge);
            }

            if (300..400).contains(&resp.status) {
                redirects += 1;
                if redirects > self.grant.max_redirects() {
                    return Err(FetchError::TooManyRedirects);
                }
                let location = resp
                    .location
                    .as_deref()
                    .ok_or(FetchError::RedirectWithoutLocation)?;
                url = url.follow(location, &self.grant)?;
                continue;
            }

            if !(200..300).contains(&resp.status) {
                return Err(FetchError::UnexpectedStatus(resp.status));
            }

            let content_type = resp.content_type.map(|ct| bound_text(ct, MAX_CONTENT_TYPE_LEN));
            return Ok(Fetched {
                url,
                status: resp.status,
                content_type,
                body: resp.body,
                redirects,
            });
        }
    }

    /// The label every result of this tool carries.
    ///
    /// Unconditional, and not derived from the arguments. The response body is
    /// written by a server that may be the attacker, and a user typing a URL
    /// says nothing about what comes back. `Label::Trusted` here would hand the
    /// Controller a web page as though the user had authored it, which is I1.
    ///
    /// The source is named `WebPage` because that is what the bytes are, and a
    /// confirmation prompt or audit record that says "unattributed" would
    /// understate what it is.
    pub fn result_label() -> Label {
        Label::from_source(
            SourceId::of_kind(SourceKind::WebPage),
            SourceKind::WebPage,
        )
    }
}

impl<T: Transport, R: Resolver> Tool for HttpFetch<T, R> {
    fn name(&self) -> &str {
        TOOL_NAME
    }

    fn invoke(&mut self, args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError> {
        let parsed = LabelledFetchArgs::from_call(args).map_err(reject)?;
        // Read through the label-aware accessor so the label stays attached at
        // the point the request is chosen, even though the label plays no part
        // in the decision: the grant does, and only the grant.
        let requested = parsed.url.with_label_for_display(|u, _| u.clone());
        let fetched = self.run(&requested).map_err(reject)?;

        let body = String::from_utf8_lossy(&fetched.body).into_owned();
        let source = SourceId::of_kind(SourceKind::WebPage);
        let mut fields = vec![
            ("url".to_string(), PlanData::Str(fetched.url.to_string())),
            ("status".to_string(), PlanData::Int(i64::from(fetched.status))),
            (
                "bytes".to_string(),
                PlanData::Int(fetched.body.len() as i64),
            ),
            (
                "redirects".to_string(),
                PlanData::Int(fetched.redirects as i64),
            ),
        ];
        if let Some(ct) = fetched.content_type {
            fields.push(("contentType".to_string(), PlanData::Str(ct)));
        }
        fields.push(("body".to_string(), PlanData::quoted(body, source)));

        Ok(Val::labeled(
            PlanData::Record(fields),
            Self::result_label(),
        ))
    }
}

fn bound_text(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    text.truncate(max);
    while !text.is_char_boundary(text.len()) {
        text.pop();
    }
    text
}

fn reject(e: FetchError) -> PlanError {
    PlanError::ToolRejected {
        tool: TOOL_NAME.to_string(),
        reason: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The std-only transport
// ---------------------------------------------------------------------------

/// A blocking HTTP/1.1 client built on `std::net` only.
///
/// # This is not confined
///
/// The socket is opened in the daemon's own process. No Landlock profile
/// applies to it, so the `socket(2)` refusal in the `Filesystem` sandbox profile
/// is irrelevant to this code, and there is no descriptor to pass to a worker.
/// Every control that stops this fetch is a check in this process. That is an
/// honest gap, not a design: the intended deployment puts this behind
/// [`Transport`] in a confined worker, and [`FetchRequest`] is shaped for it.
///
/// # There is no TLS
///
/// `https` is refused with [`FetchError::TlsUnsupported`] rather than served in
/// plaintext. TLS needs a dependency this crate does not have and the workspace
/// owner did not ask for, and quietly downgrading would be worse than refusing.
///
/// # Redirects are not followed here
///
/// A 3xx comes back as a [`RawResponse`] and the tool validates the target. A
/// transport that followed it would be a second implementation of the allowlist.
pub struct TcpTransport;

impl Transport for TcpTransport {
    fn send(&mut self, req: &FetchRequest) -> Result<RawResponse, FetchError> {
        if req.url.scheme() == "https" {
            return Err(FetchError::TlsUnsupported);
        }
        // The tool vetted these addresses; connecting to one of them rather
        // than re-resolving is what makes the check mean anything.
        let addr = req
            .addrs
            .first()
            .copied()
            .ok_or(FetchError::NoAddresses)?;
        exchange(
            SocketAddr::new(addr, req.port),
            &req.url.authority(),
            req.url.target(),
            &req.limits,
        )
    }
}

/// One request/response exchange against an address the caller has vetted.
///
/// Public because the time and size bounds are worth testing against a real
/// socket, and a silent local listener is the only way to test a read timeout
/// without a network. The caller is responsible for having vetted `addr`;
/// [`Transport::send`] is the path that does.
pub fn exchange(
    addr: SocketAddr,
    host: &str,
    target: &str,
    limits: &Limits,
) -> Result<RawResponse, FetchError> {
    // Re-checked here even though `authorise` already checked it, because this
    // function is public and takes a bare `&str`. The whole reason the function
    // takes strings rather than a `FetchUrl` is so the socket tests can reach it;
    // the whole reason it must not trust them is the same.
    if !is_safe_request_target(target) {
        return Err(FetchError::UnsafeRequestTarget);
    }
    let deadline = Instant::now() + limits.total_timeout;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, limits.connect_timeout)
        .map_err(|e| io_error(e, Some(FetchError::ConnectFailed)))?;
    stream.set_nodelay(true).ok();

    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: agentos-http-fetch/1\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    // `host` goes on a `Host:` line, so it gets the same treatment as the
    // target. `FetchUrl::host()` already guarantees this, but `exchange` is
    // public and takes the string directly.
    if !is_safe_request_target(&format!("/{host}")) {
        return Err(FetchError::BadAuthority);
    }
    stream
        .write_all(request.as_bytes())
        .map_err(|e| io_error(e, None))?;
    stream.flush().map_err(|e| io_error(e, None))?;

    let (head, body_start) = read_head(&mut stream, deadline, MAX_HEADER_BYTES)?;
    let (status, headers) = parse_head(&head)?;

    if let Some(te) = header(&headers, "transfer-encoding") {
        if !te.eq_ignore_ascii_case("identity") {
            return Err(FetchError::UnsupportedTransferEncoding);
        }
    }

    let declared = header(&headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    if let Some(len) = declared {
        if len > limits.max_bytes as u64 {
            // Refused from the header alone: the body is never read, so an
            // over-long response costs one header's worth of bytes rather than
            // however much the server felt like sending.
            return Err(FetchError::ResponseTooLarge);
        }
    }

    // A redirect's body is discarded. It cannot be needed, and reading it would
    // spend the byte budget on a document nobody will read.
    let is_redirect = (300..400).contains(&status);
    // `bytes_seen` counts *body* bytes only, so it means the same thing here as
    // it does to the tool's own check in `run`. Counting headers would make the
    // two disagree by the header size, and a server could then pass the tool's
    // check with a body the transport had already refused, or fail the tool's
    // check with a body that fitted.
    let (body, bytes_seen) = if is_redirect || status == 204 || status == 304 {
        (Vec::new(), 0)
    } else {
        read_body(&mut stream, deadline, limits.max_bytes, body_start)?
    };

    Ok(RawResponse {
        status,
        location: header(&headers, "location").map(str::to_string),
        content_type: header(&headers, "content-type").map(str::to_string),
        body,
        bytes_seen,
    })
}

/// Map an I/O failure onto a refusal.
///
/// A timeout is its own variant because it is the answer to a different
/// question: not "could not reach the host" but "would have taken too long".
/// Everything else keeps its message, bounded, because an operator reading a
/// failure needs to know a connection was refused rather than a name was
/// rejected.
fn io_error(e: std::io::Error, keep: Option<FetchError>) -> FetchError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => FetchError::TimedOut,
        _ => match keep {
            Some(other) => other,
            None => FetchError::transport(e),
        },
    }
}

fn set_deadline(
    stream: &std::net::TcpStream,
    deadline: Instant,
) -> Result<(), FetchError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(FetchError::TimedOut);
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|_| stream.set_write_timeout(Some(remaining)))
        .map_err(|e| io_error(e, None))
}

/// Read up to and including the header terminator.
///
/// Returns the header block *and* whatever was already read past it, because
/// the read that completes the headers will usually have carried the first
/// chunk of the body with it. Dropping that remainder truncates every response
/// that arrives in one segment, silently, which is the worst way for this to
/// be wrong: the caller gets a short body and no indication.
fn read_head(
    stream: &mut std::net::TcpStream,
    deadline: Instant,
    max: usize,
) -> Result<(Vec<u8>, Vec<u8>), FetchError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        set_deadline(stream, deadline)?;
        let n = stream.read(&mut chunk).map_err(|e| io_error(e, None))?;
        if n == 0 {
            // The server closed before finishing its headers, so there is no
            // response to bound. Refused rather than treated as an empty body.
            return Err(FetchError::MalformedResponse);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if at + 4 > max {
                return Err(FetchError::HeadersTooLarge);
            }
            let rest = buf.split_off(at + 4);
            return Ok((buf, rest));
        }
        if buf.len() > max {
            return Err(FetchError::HeadersTooLarge);
        }
    }
}

/// Read the body to EOF, starting from whatever the header read already brought
/// in.
///
/// `already` is the header block's length, so the ceiling applies to the body
/// alone and is not consumed by the headers. The whole thing is refused on
/// overflow rather than truncated.
fn read_body(
    stream: &mut std::net::TcpStream,
    deadline: Instant,
    max: usize,
    mut buf: Vec<u8>,
) -> Result<(Vec<u8>, u64), FetchError> {
    let mut chunk = [0u8; 8192];
    // The tail of the header read counts toward the ceiling: those bytes are body
    // bytes, and a body that has already arrived over the ceiling is still an
    // over-long body.
    if buf.len() > max {
        return Err(FetchError::ResponseTooLarge);
    }
    let mut seen = buf.len() as u64;
    loop {
        set_deadline(stream, deadline)?;
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_error(e, None)),
        };
        if n == 0 {
            return Ok((buf, seen));
        }
        seen += n as u64;
        // Refused, never truncated. Truncating would hand the extractor half a
        // document labelled as the document.
        if seen > max as u64 {
            return Err(FetchError::ResponseTooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_head(raw: &[u8]) -> Result<(u16, Vec<(String, String)>), FetchError> {
    let text = std::str::from_utf8(raw).map_err(|_| FetchError::MalformedResponse)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(FetchError::MalformedResponse)?;
    let mut parts = status_line.split(' ');
    let version = parts.next().ok_or(FetchError::MalformedResponse)?;
    if !version.starts_with("HTTP/1.") {
        return Err(FetchError::MalformedResponse);
    }
    let status: u16 = parts
        .next()
        .ok_or(FetchError::MalformedResponse)?
        .parse()
        .map_err(|_| FetchError::MalformedResponse)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Obsolete line folding is refused rather than joined: a folded header
        // is a header two spellings can disagree about.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(FetchError::MalformedResponse);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(FetchError::MalformedResponse);
        };
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic()) {
            return Err(FetchError::MalformedResponse);
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((status, headers))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

// ---------------------------------------------------------------------------
// Tests: the pure logic, with no transport and no network
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(hosts: &[&str]) -> FetchGrant {
        FetchGrant::new(hosts.iter().copied()).expect("grant")
    }

    fn ok_url(raw: &str) -> FetchUrl {
        FetchUrl::parse(raw, &grant(&["good.test"])).unwrap_or_else(|e| panic!("{raw}: {e}"))
    }

    // --- the allowlist is a whole-host comparison ---

    #[test]
    fn a_prefix_sharing_host_is_not_on_the_allowlist() {
        // The string-prefix trap, in this domain. `good.test.evil.test` starts
        // with `good.test` and is a different machine an attacker owns.
        let g = grant(&["good.test"]);
        assert!(FetchUrl::parse("https://good.test.evil.test/x", &g).is_err());
        assert!("good.test.evil.test".starts_with("good.test"));
        assert!(FetchUrl::parse("https://evil-good.test/x", &g).is_err());
    }

    #[test]
    fn the_host_comparison_is_case_insensitive_on_both_sides() {
        let g = grant(&["Good.TEST"]);
        assert_eq!(FetchUrl::parse("https://good.test/x", &g).unwrap().host(), "good.test");
        assert_eq!(FetchUrl::parse("https://GOOD.TEST/x", &g).unwrap().host(), "good.test");
    }

    // --- schemes ---

    #[test]
    fn a_non_http_scheme_never_reaches_the_host_allowlist() {
        // `file://good.test/...` is the recorded bug in this repository.
        let g = grant(&["good.test"]);
        for attack in [
            "file://good.test/etc/passwd",
            "ftp://good.test/",
            "gopher://good.test/",
            "data://good.test/",
            "javascript://good.test/",
            "ws://good.test/",
            "wss://good.test/",
            "HTTP2://good.test/",
            "https+evil://good.test/",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::SchemeNotAllowed),
                "{attack} was not refused on its scheme"
            );
        }
    }

    #[test]
    fn the_grant_refuses_a_scheme_this_module_cannot_speak() {
        // `foo://` is a parseable scheme. Admitting it to the grant would leave
        // `default_port` with no answer at fetch time, and the operator reading
        // `MalformedGrant` here is in a position to fix it.
        for scheme in ["foo", "gopher", "file", "data", "ws", "https+evil"] {
            assert_eq!(
                FetchGrant::new(["good.test"]).expect("grant").with_scheme(scheme),
                Err(FetchError::MalformedGrant),
                "{scheme}:// was admitted to a grant"
            );
        }
        assert!(FetchGrant::new(["good.test"])
            .expect("grant")
            .with_scheme("http")
            .is_ok());
    }

    #[test]
    fn plaintext_http_needs_to_be_enabled_explicitly() {
        let g = grant(&["good.test"]);
        assert_eq!(
            FetchUrl::parse("http://good.test/x", &g),
            Err(FetchError::SchemeNotAllowed)
        );
        let g = grant(&["good.test"]).with_scheme("http").expect("scheme");
        assert_eq!(FetchUrl::parse("http://good.test/x", &g).unwrap().port(), 80);
        // `with_scheme` widens, it does not replace: asking for plaintext is not
        // a request to lose TLS.
        assert!(FetchUrl::parse("https://good.test/x", &g).is_ok());
        // And it is still the only two.
        assert!(FetchUrl::parse("ftp://good.test/x", &g).is_err());
    }

    // --- the recorded backslash and userinfo bypasses ---

    #[test]
    fn a_backslash_anywhere_is_refused() {
        let g = grant(&["good.test"]);
        for attack in [
            "https://evil.test\\@good.test/",
            "https://good.test\\@evil.test/",
            "https://good.test\\evil.test/",
            "https://good.test/\\evil.test",
            "https:\\\\good.test/x",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::UrlHasBackslash),
                "{attack} was not refused"
            );
        }
    }

    #[test]
    fn userinfo_is_refused_rather_than_stripped() {
        // Stripping userinfo is the step that made the recorded bypass work, so
        // there is no strip step here at all.
        let g = grant(&["good.test"]);
        for attack in [
            "https://good.test@evil.test/x",
            "https://evil.test@good.test/x",
            "https://user:pass@good.test/x",
            "https://good.test@good.test@evil.test/x",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::AuthorityHasUserinfo),
                "{attack} was not refused"
            );
        }
    }

    // --- ambiguous spellings are refused, not guessed at ---

    #[test]
    fn a_trailing_dot_is_refused() {
        let g = grant(&["good.test"]);
        assert_eq!(
            FetchUrl::parse("https://good.test./x", &g),
            Err(FetchError::HostTrailingDot)
        );
    }

    #[test]
    fn a_single_label_host_is_refused() {
        // A resolver completes `intranet` from a local search domain, so the
        // name that was allowlisted is not the host that would be reached.
        let g = grant(&["intranet"]);
        assert_eq!(
            FetchUrl::parse("https://intranet/x", &g),
            Err(FetchError::HostSingleLabel)
        );
    }

    #[test]
    fn only_the_schemes_default_port_is_accepted() {
        let g = grant(&["good.test"]);
        assert_eq!(
            FetchUrl::parse("https://good.test:8443/x", &g),
            Err(FetchError::NonDefaultPort)
        );
        assert_eq!(ok_url("https://good.test/x").port(), 443);
        assert_eq!(ok_url("https://good.test:443/x").port(), 443);
    }

    #[test]
    fn an_off_allowlist_host_is_refused() {
        let g = grant(&["good.test"]);
        assert_eq!(
            FetchUrl::parse("https://evil.test/x", &g),
            Err(FetchError::HostNotAllowed)
        );
    }

    #[test]
    fn non_url_text_is_refused() {
        let g = grant(&["good.test"]);
        for attack in ["", "not a url", "good.test/x", "://good.test", "https://", "https:///x"] {
            assert!(FetchUrl::parse(attack, &g).is_err(), "{attack} was accepted");
        }
        assert_eq!(FetchUrl::parse("://good.test", &g), Err(FetchError::NoScheme));
        assert_eq!(FetchUrl::parse("https://", &g), Err(FetchError::NoHost));
    }

    #[test]
    fn control_characters_and_non_ascii_are_refused() {
        let g = grant(&["good.test"]);
        for attack in [
            "https://good.test/\r\nHost: evil.test",
            "https://good.test/\n",
            "https://good.test/\u{0}",
            "https://good.test/\u{7f}",
            "https://g\u{fc}od.test/x",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::UrlHasControlChar),
                "{attack:?} was not refused"
            );
        }
    }

    #[test]
    fn a_fragment_is_refused() {
        let g = grant(&["good.test"]);
        assert_eq!(
            FetchUrl::parse("https://good.test/x#frag", &g),
            Err(FetchError::UrlHasFragment)
        );
    }

    #[test]
    fn a_path_that_would_end_the_request_target_is_refused() {
        // The request is formatted as a string, so a path holding a space, a
        // quote or a CR would end the target and start a header or a second
        // request. The whole URL is already refused for control characters, so
        // these are the printable ones that survive that check.
        let g = grant(&["good.test"]);
        // A CR or LF is already refused by the control-character rule, so these
        // are the printable characters that get past it and would still end the
        // target. A literal CR is asserted separately below, as refused rather
        // than accepted.
        for attack in [
            "https://good.test/a HTTP/1.1",
            "https://good.test/a\"b",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::UnsafeRequestTarget),
                "{attack:?} would have been sent on the request line"
            );
        }
        for attack in [
            "https://good.test/a\r\nHost: evil.test",
            "https://good.test/a\nX",
        ] {
            assert_eq!(
                FetchUrl::parse(attack, &g),
                Err(FetchError::UrlHasControlChar),
                "{attack:?} was accepted"
            );
        }
        // Percent escapes are not decoded, so an encoded CR stays encoded and
        // cannot become a line break.
        assert!(FetchUrl::parse("https://good.test/a%0d%0aX:%20y", &g).is_ok());
    }

    #[test]
    fn an_ordinary_path_with_a_query_is_accepted() {
        // The control for the test above: refusing everything with a space would
        // also refuse every legitimate percent-encoded URL.
        let g = grant(&["good.test"]);
        let url = FetchUrl::parse("https://good.test/search?q=hello%20world&n=2", &g)
            .expect("an ordinary path");
        assert_eq!(url.target(), "/search?q=hello%20world&n=2");
    }

    #[test]
    fn an_over_long_url_is_refused_before_anything_parses_it() {
        let g = grant(&["good.test"]);
        let long = format!("https://good.test/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(FetchUrl::parse(&long, &g), Err(FetchError::UrlTooLong));
    }

    #[test]
    fn an_ipv6_literal_is_bracketed_and_only_its_default_port_is_accepted() {
        let g = FetchGrant::new(["2001:db8::1"]).expect("grant");
        let url = FetchUrl::parse("https://[2001:db8::1]/x", &g).expect("v6 literal");
        assert_eq!(url.host(), "2001:db8::1");
        assert_eq!(url.authority(), "[2001:db8::1]");
        assert_eq!(url.port(), 443);
        assert_eq!(
            FetchUrl::parse("https://[2001:db8::1]:8443/x", &g),
            Err(FetchError::NonDefaultPort)
        );
    }

    #[test]
    fn a_bare_ipv6_literal_is_refused_as_ambiguous() {
        let g = FetchGrant::new(["2001:db8::1"]).expect("grant");
        assert_eq!(
            FetchUrl::parse("https://2001:db8::1/x", &g),
            Err(FetchError::BadAuthority)
        );
    }

    #[test]
    fn a_malformed_grant_is_refused_rather_than_stored() {
        for bad in ["", "  ", "good.test.", "good..test", "-bad.test", "bad-.test", "a b"] {
            assert_eq!(
                FetchGrant::new([bad]),
                Err(FetchError::MalformedGrant),
                "{bad:?} was accepted into a grant"
            );
        }
    }

    // --- SSRF: which addresses may be fetched ---

    #[test]
    fn private_and_reserved_addresses_are_not_routable() {
        let refused = [
            // loopback
            "127.0.0.1", "127.1.2.3",
            // private
            "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            // link-local, which is where cloud instance metadata lives
            "169.254.169.254",
            // "this network": connecting to 0.0.0.0 reaches localhost on Linux
            "0.0.0.0", "0.1.2.3",
            // carrier-grade NAT, benchmarking, documentation, broadcast
            "100.64.0.1", "198.18.0.1", "198.19.255.255", "192.0.2.1",
            "198.51.100.1", "203.0.113.1", "192.0.0.1",
            // multicast and reserved
            "224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255",
            // IPv6
            "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
            "2001:db8::1",
            // an IPv4 address wearing an IPv6 hat
            "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1",
            // 6to4 with a loopback payload
            "2002:7f00:0001::",
        ];
        for ip in refused {
            let addr: IpAddr = ip.parse().expect("test address");
            assert!(
                !address_is_routable(&addr),
                "{ip} was treated as routable; a fetch of it is an SSRF"
            );
        }
    }

    #[test]
    fn ordinary_public_addresses_are_routable() {
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            let addr: IpAddr = ip.parse().expect("test address");
            assert!(address_is_routable(&addr), "{ip} was refused");
        }
    }

    // --- bounds ---

    #[test]
    fn the_default_bounds_are_finite_and_small() {
        let limits = Limits::default();
        assert!(limits.total_timeout <= Duration::from_secs(60));
        assert!(limits.connect_timeout <= Duration::from_secs(30));
        assert!(limits.max_bytes > 0 && limits.max_bytes <= 16 * 1024 * 1024);
    }

    // --- refusals do not echo ---

    #[test]
    fn no_refusal_renders_the_url() {
        let g = grant(&["good.test"]);
        for attack in [
            "file://good.test/etc/passwd",
            "https://evil.test\\@good.test/",
            "https://good.test@evil.test/x",
            "https://good.test./x",
            "https://good.test:8443/x",
            "https://evil.test/x",
        ] {
            let e = FetchUrl::parse(attack, &g).expect_err("must be refused");
            let rendered = e.to_string();
            for marker in ["good.test", "evil.test", "passwd", "file:"] {
                assert!(
                    !rendered.contains(marker),
                    "the refusal `{rendered}` echoed part of the URL"
                );
            }
        }
    }

    // --- the schema ---

    #[test]
    fn the_schema_names_only_the_url_and_forbids_the_rest() {
        let json = serde_json::to_value(FetchUrlArgs::schema()).expect("schema");
        assert_eq!(json["properties"][ARG_URL]["type"], serde_json::json!("string"));
        assert_eq!(json["required"], serde_json::json!([ARG_URL]));
        assert_eq!(json["additionalProperties"], serde_json::json!(false));
        assert_eq!(
            json["properties"].as_object().expect("properties").len(),
            1,
            "the schema declares an argument this tool does not read"
        );
    }
}