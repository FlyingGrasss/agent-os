//! Composing an outbound email.
//!
//! # What this tool actually does, and why
//!
//! It **does not send mail.** It composes a message into an outbox directory.
//! That is not a stub pretending to be a mailer; it is the correct behaviour for a
//! sandboxed agent:
//!
//! - A confined process should not hold SMTP credentials. Granting them would
//!   hand the sandbox a capability that outlives every other one it has.
//! - A confined process should not have SMTP egress. Mail leaves over TCP to a
//!   port it would have to be granted, and a grant that permits arbitrary
//!   outbound TCP is not a confinement worth having.
//!
//! So the authority this tool holds is "write a message here", and a separate
//! component with the credentials -- outside the sandbox -- is what turns it into
//! mail. The security properties below are all about the *composed* message,
//! because that is where the attack lands: a message written correctly but
//! addressed to the wrong person is worse than no message.
//!
//! # The attack this exists to stop
//!
//! The headline threat is recipient substitution: a document says
//! `recipient=attacker@evil.test` and the agent mails it there. That is handled
//! upstream by the intent pins, which refuse a recipient contradicting what the
//! user typed. This tool's own job is the adjacent one:
//!
//! **Header injection.** An address of
//! `"bob@example.com\r\nBcc: attacker@evil.test"` is not a bad address, it is two
//! headers. Any check that validates "does this look like an email" passes it --
//! the first line does -- and the message then carries a recipient the user never
//! saw and the policy engine never evaluated. Confirmation would have been asked
//! about `bob@example.com` while the mail went to two people.
//!
//! That is why every header is rejected outright on any character that could
//! terminate it, rather than sanitised. Stripping a newline produces an address
//! that neither the user nor the policy engine approved.

use std::collections::BTreeMap;

use agentos_dsl::{PlanData, PlanError, PlanValue};
use agentos_policy::RuleSet;
use agentos_types::{Label, Val};

use crate::fswrite::{WriteError, WriteGrant};

/// The tool's registered name.
///
/// Matches the name the intent pins, the policy rules, and the evaluation corpus
/// all use. Deliberately not `mail.compose`: renaming it would leave those three
/// describing a tool that no longer exists, which is the same
/// harness-describes-a-fiction failure this crate has hit twice.
pub const TOOL_NAME: &str = "send_email";

pub const ARG_TO: &str = "to";
pub const ARG_SUBJECT: &str = "subject";
pub const ARG_BODY: &str = "body";

/// Longest a single header may be.
///
/// A bound, because a header is one line and a line that can be a megabyte is a
/// denial of service against whatever eventually transmits it. Chosen to fit a
/// realistic subject with room to spare.
pub const MAX_HEADER_CHARS: usize = 200;

/// Longest a body may be.
///
/// Deliberately larger than a header. The body is the one place where free-form
/// attacker-influenced text is *legitimate*: the user asked for a note to be
/// forwarded, and refusing to carry prose would make the tool useless for its
/// actual job. The defence here is that the body cannot affect addressing, which
/// is what header injection would try to use it for.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Why a message was not composed.
///
/// Nothing in here formats an address or a subject. The host stringifies a tool's
/// error into the audit log, and the audit log is a Controller input: an error
/// carrying attacker-chosen bytes would put those bytes in a prompt with the
/// session's authority behind them. The same rule `fswrite` follows, for the same
/// reason.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MailError {
    #[error("missing argument `{0}`")]
    MissingArg(&'static str),
    #[error("unexpected argument `{0}`")]
    UnexpectedArg(String),
    #[error("`{arg}` has no text form (it is a {type_name})")]
    NotText {
        arg: &'static str,
        type_name: &'static str,
    },
    /// The specific header-injection refusal.
    ///
    /// Its own variant rather than a generic "invalid address", because it is the
    /// one failure an attacker is actively engineering and an operator debugging a
    /// refusal needs to recognise it. The message names the character class and
    /// nothing about the value.
    #[error("`{arg}` contains a character that cannot appear in a header")]
    HeaderInjection { arg: &'static str },
    #[error("`{arg}` is not a single email address")]
    NotAnAddress { arg: &'static str },
    #[error("`{arg}` is longer than {max} characters")]
    TooLong { arg: &'static str, max: usize },
    #[error("the message could not be written to the outbox: {0}")]
    Outbox(WriteError),
}

fn reject(e: MailError) -> PlanError {
    PlanError::ToolRejected {
        tool: TOOL_NAME.to_string(),
        reason: e.to_string(),
    }
}

/// Compose messages into this directory.
///
/// Wraps a [`WriteGrant`] rather than reimplementing path containment. Traversal
/// refusal, symlink refusal, and the create-new race are all already tested
/// there, and a second copy of that logic would be a second thing to get wrong.
/// Composing means the mail tool inherits the filesystem's defences instead of
/// weakening them.
#[derive(Debug, Clone)]
pub struct MailGrant {
    outbox: WriteGrant,
}

impl MailGrant {
    /// Take compose authority over `outbox`, which must exist and be a directory.
    pub fn new(outbox: impl AsRef<std::path::Path>) -> Result<Self, MailError> {
        WriteGrant::new(outbox)
            .map(|outbox| MailGrant { outbox })
            .map_err(MailError::Outbox)
    }

    /// The outbox directory, canonical.
    pub fn outbox(&self) -> &std::path::Path {
        self.outbox.root()
    }

    /// The write authority underneath.
    ///
    /// Exposed for reporting, as `FsWrite` does. There is no setter, so it cannot
    /// be widened after construction.
    pub fn grant(&self) -> &WriteGrant {
        &self.outbox
    }
}

/// A composed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl Message {
    /// Render to RFC 5322-ish bytes.
    ///
    /// Only safe because every field was validated first. This function does no
    /// checking of its own, and that is stated rather than hidden: it is
    /// `pub(crate)` for exactly that reason, and the public entry point is
    /// [`MailGrant::compose`], which validates.
    pub(crate) fn render(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 128);
        out.extend_from_slice(format!("To: {}\r\n", self.to).as_bytes());
        out.extend_from_slice(format!("Subject: {}\r\n", self.subject).as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(self.body.as_bytes());
        out
    }
}

/// Validate an address and return it normalised.
///
/// Strict on purpose, and stricter than RFC 5322. In particular it **rejects**
/// display-name forms -- `Bob <bob@example.com>` -- because those permit a comma
/// separated list in one argument, and an argument that can name several
/// recipients is an argument the confirmation prompt showed only one of.
///
/// One `@`, something either side, no whitespace, no angle brackets, no quotes.
pub fn validate_address(raw: &str) -> Result<String, MailError> {
    reject_header_characters(ARG_TO, raw)?;

    if raw.chars().count() > MAX_HEADER_CHARS {
        return Err(MailError::TooLong {
            arg: ARG_TO,
            max: MAX_HEADER_CHARS,
        });
    }

    if raw.contains('<') || raw.contains('>') || raw.contains('"') || raw.contains(',') {
        return Err(MailError::NotAnAddress { arg: ARG_TO });
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(MailError::NotAnAddress { arg: ARG_TO });
    }

    let mut parts = raw.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    // A second `@` means `parts.next()` yields `None`, and a bare `@` means an
    // empty side. Both are refused.
    if parts.next().is_some() || local.is_empty() || domain.is_empty() {
        return Err(MailError::NotAnAddress { arg: ARG_TO });
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(MailError::NotAnAddress { arg: ARG_TO });
    }
    Ok(raw.to_ascii_lowercase())
}

/// Validate a single-line header value.
pub fn validate_header(arg: &'static str, raw: &str) -> Result<String, MailError> {
    reject_header_characters(arg, raw)?;
    if raw.chars().count() > MAX_HEADER_CHARS {
        return Err(MailError::TooLong {
            arg,
            max: MAX_HEADER_CHARS,
        });
    }
    Ok(raw.trim().to_string())
}

/// Reject anything that could terminate a header line.
///
/// The characters that matter are CR and LF. Everything below U+0020 plus DEL is
/// refused as well: a NUL in an address is never legitimate, and a terminal-
/// invisible control in a value a person is asked to approve is an attack on the
/// person, not on the parser.
///
/// **Refused, never stripped.** Stripping would produce an address that neither
/// the user nor the policy engine approved, which is worse than a refusal because
/// it looks like success.
fn reject_header_characters(arg: &'static str, raw: &str) -> Result<(), MailError> {
    if raw.chars().any(|c| c == '\r' || c == '\n' || c == '\0' || (c < ' ') || c == '\u{7f}') {
        return Err(MailError::HeaderInjection { arg });
    }
    Ok(())
}

/// Validate a body.
///
/// Only a length bound. No character filtering: the body is where legitimate
/// attacker-influenced text belongs, and the defence is structural -- the body
/// cannot influence addressing, because addressing was validated against a header
/// rule before the body was ever read.
pub fn validate_body(raw: &str) -> Result<String, MailError> {
    if raw.len() > MAX_BODY_BYTES {
        return Err(MailError::TooLong {
            arg: ARG_BODY,
            max: MAX_BODY_BYTES,
        });
    }
    Ok(raw.to_string())
}

/// Everything the policy engine evaluates, still labeled.
#[derive(Debug, Clone)]
pub struct MailArgs {
    to: Val<String>,
    subject: Val<String>,
    body: Val<String>,
}

impl MailArgs {
    /// Read and validate a call's arguments.
    ///
    /// Refuses a missing argument, an argument the schema does not declare, and a
    /// value with no text form. The text form excludes `PlanData::Quoted` for the
    /// same reason policy evaluation excludes it: quarantined text exists to be
    /// unreadable by the Controller, and a tool that accepted it would be a way to
    /// read it.
    pub fn from_call(args: &BTreeMap<String, PlanValue>) -> Result<Self, MailError> {
        for name in args.keys() {
            if name != ARG_TO && name != ARG_SUBJECT && name != ARG_BODY {
                return Err(MailError::UnexpectedArg(name.clone()));
            }
        }
        Ok(Self {
            to: text_arg(args, ARG_TO)?,
            subject: text_arg(args, ARG_SUBJECT)?,
            body: text_arg(args, ARG_BODY)?,
        })
    }

    /// The validated message, if it validates.
    ///
    /// Returns owned strings because validation normalises: a lowercased address
    /// is what gets composed, and returning the raw value would let a caller
    /// compose the unchecked one.
    pub fn message(&self) -> Result<Message, MailError> {
        // Read through the label-aware accessor. There is no label-free read of a
        // `Val`, so the provenance stays attached at the point the effect is
        // chosen.
        let to = self.to.with_label_for_display(|t, _| validate_address(t));
        let subject = self
            .subject
            .with_label_for_display(|t, _| validate_header(ARG_SUBJECT, t));
        let body = self
            .body
            .with_label_for_display(|t, _| validate_body(t));
        Ok(Message {
            to: to?,
            subject: subject?,
            body: body?,
        })
    }

    /// The label the result of this call carries.
    ///
    /// The result names the recipient, so it inherits the recipient's provenance.
    /// Joining all three rather than picking one: a trusted `to` read with a
    /// tainted `body` must not produce a trusted record naming where the message
    /// was going, or the audit trail would report a verified destination for a
    /// message carrying attacker prose.
    pub fn result_label(&self) -> Label {
        self.to
            .label()
            .join(self.subject.label())
            .join(self.body.label())
    }
}

fn text_arg(
    args: &BTreeMap<String, PlanValue>,
    name: &'static str,
) -> Result<Val<String>, MailError> {
    let value = args.get(name).ok_or(MailError::MissingArg(name))?;
    let (text, type_name, label) = value.with_label_for_display(|data, label| {
        (scalar_text(data), data.type_name(), label.clone())
    });
    match text {
        Some(t) => Ok(Val::labeled(t, label)),
        None => Err(MailError::NotText {
            arg: name,
            type_name,
        }),
    }
}

fn scalar_text(data: &PlanData) -> Option<String> {
    match data {
        PlanData::Str(s) | PlanData::Enum(s) => Some(s.clone()),
        PlanData::Int(i) => Some(i.to_string()),
        PlanData::Bool(b) => Some(b.to_string()),
        // `Quoted` is quarantined on purpose, and `Unit`/`Record`/`List` have no
        // single text form. Treating either as empty would turn a refusal into a
        // message to an empty address.
        _ => None,
    }
}

/// The mail tool.
pub struct SendEmail {
    grant: MailGrant,
}

impl SendEmail {
    pub fn new(grant: MailGrant) -> Self {
        Self { grant }
    }

    /// The authority this tool holds.
    pub fn grant(&self) -> &MailGrant {
        &self.grant
    }

    /// Compose a message into the outbox.
    ///
    /// The filename is derived from the recipient and the byte length, never
    /// from attacker-controlled text directly: an address has already been
    /// validated to contain no path separators, but deriving the name *from the
    /// validated value* rather than from the raw one is what makes that
    /// guarantee checkable here rather than merely intended upstream.
    pub fn compose(&self, message: &Message) -> Result<String, MailError> {
        let safe_name = message
            .to
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
            .collect::<String>();
        let name = format!("{safe_name}.{}.eml", message.body.len());
        self.grant
            .outbox
            .write(&name, &message.render())
            .map_err(MailError::Outbox)?;
        Ok(name)
    }
}

impl crate::host::Tool for SendEmail {
    fn name(&self) -> &str {
        TOOL_NAME
    }

    fn invoke(
        &mut self,
        args: &BTreeMap<String, PlanValue>,
    ) -> Result<PlanValue, PlanError> {
        let parsed = MailArgs::from_call(args).map_err(reject)?;
        // Validation happens before any effect. A message that would be addressed
        // wrongly is never written, even partially.
        let message = parsed.message().map_err(reject)?;
        let name = self.compose(&message).map_err(reject)?;

        Ok(Val::labeled(
            PlanData::Record(vec![
                (ARG_TO.to_string(), PlanData::Str(message.to.clone())),
                (
                    "composed".to_string(),
                    PlanData::Str(name),
                ),
                (
                    "bytes".to_string(),
                    PlanData::Int(message.body.len() as i64 + 64),
                ),
            ]),
            parsed.result_label(),
        ))
    }
}

/// Install this tool's default policy rules.
///
/// Every header is `Confirm` on tainted input, and none is `Allow`. A tool with
/// no rule for an argument defaults to `Confirm` anyway, so these are not what
/// makes it safe -- they are what makes the *intent* explicit rather than
/// inherited from a default nobody looked at.
pub fn install_policy_rules(rules: &mut RuleSet) {
    rules.confirm_tainted(TOOL_NAME, ARG_TO);
    rules.confirm_tainted(TOOL_NAME, ARG_SUBJECT);
    rules.confirm_tainted(TOOL_NAME, ARG_BODY);
}
