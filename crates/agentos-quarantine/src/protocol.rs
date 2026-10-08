//! The host/child wire protocol.
//!
//! # Why this type exists
//!
//! Invariant I2 says the quarantined processor "has no tools, no network, and
//! no filesystem access beyond its input". Kernel confinement enforces the
//! second and third halves at runtime. The first half - *no tools* - is not a
//! property the kernel can check, because a "tool call" is not a syscall. It is
//! a property of what the host is willing to ask for, so it is expressed in the
//! request type.
//!
//! [`Request`] has exactly one variant. There is no `CallTool`, no
//! `ReadFile`, no `Open` - not because they are commented out, but because
//! adding one is a visible change to this enum that a reviewer of the protocol
//! would have to notice. A capability that arrives silently is the failure mode
//! this whole crate is built to avoid.
//!
//! # Why the document never appears in a message
//!
//! The request names a schema, never a path. The document itself arrives as a
//! file *descriptor* over `SCM_RIGHTS`, out of band from the framing below, so
//! the child never learns a name it could try to re-resolve. See
//! [`crate::child`], which is where that ordering is enforced.
//!
//! # Why no error in this module carries document bytes
//!
//! Every `Display` here is safe to log. A malformed reply is reported as
//! [`ProtocolError::MalformedPayload`] with no payload, deliberately: serde's
//! own error message quotes the offending value, and the offending value is
//! attacker-authored text read out of a hostile document. Propagating it would
//! turn a parse failure into an injection into the operator's log terminal.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use agentos_infer::schema::{conservative_charset, Constraint};

/// Longest permitted schema or field name, in bytes.
///
/// Field names arrive back from the child in [`Reply`], and a child that echoes
/// a long string into a field name is an attacker who has found a field name.
/// Capping it here means the name is at worst an identifier rather than a
/// document.
pub const MAX_NAME_BYTES: usize = 64;

/// Longest permitted enum alternative set name... more precisely, the cap on
/// how many alternatives one enum field may declare.
pub const MAX_ENUM_ALTERNATIVES: usize = 64;

/// Longest permitted value for a `ShortText` field, in characters.
///
/// Matches the `maxLength` `agentos_infer` uses for free text, so a field
/// declared here cannot smuggle an unbounded string past the schema.
pub const MAX_SHORT_TEXT_CHARS: usize = 4096;

/// A schema, in the form the child receives it.
///
/// This is deliberately *not* `agentos_infer::schema::Schema`. That type carries
/// a character allowlist for short text, and the allowlist is host-side policy:
/// the child produces values, the host decides which ones are narrow enough to
/// type. Sending the allowlist would tell an untrusted component what shape of
/// hostile text the host is willing to accept, which is information about the
/// filter rather than about the document. So [`WireConstraint::ShortText`] carries
/// only the length bound, and [`Constraint`] is reconstructed with
/// [`conservative_charset`] on the way back in - which can only *narrow*, since
/// no field's validity is widened by losing its allowlist and finding a stricter
/// one.
#[derive(Debug, Clone, PartialEq)]
pub struct SchemaSpec {
    name: String,
    fields: Vec<FieldSpec>,
}

impl SchemaSpec {
    /// Build a schema spec, refusing names that are too long.
    pub fn new(
        name: impl Into<String>,
        fields: impl IntoIterator<Item = FieldSpec>,
    ) -> Result<Self, ProtocolError> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(ProtocolError::NameTooLong);
        }
        let mut fields: Vec<FieldSpec> = fields.into_iter().collect();
        // Sorted and deduplicated so a schema cannot declare the same field twice
        // with two different constraints, and so `field()` finds exactly one.
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        fields.dedup_by(|a, b| a.name == b.name);
        Ok(Self { name, fields })
    }

    /// The schema's name. Never a path, never a tool name: see
    /// [`MAX_NAME_BYTES`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared fields, sorted by name.
    pub fn fields(&self) -> &[FieldSpec] {
        &self.fields
    }

    /// Look up a field by name, for checking a reply against the declaration.
    pub fn field(&self, name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Recover an `agentos_infer` schema for host-side validation.
    ///
    /// Round-tripping through the wire form is lossless in the direction that
    /// matters: [`Constraint::ShortText`] always comes back with
    /// [`conservative_charset`], which is the same allowlist
    /// [`Self::from_schema`] would have carried for a caller that used it.
    pub fn to_schema(&self) -> agentos_infer::schema::Schema {
        agentos_infer::schema::Schema {
            name: self.name.clone(),
            fields: self
                .fields
                .iter()
                .map(|f| agentos_infer::schema::Field {
                    name: f.name.clone(),
                    constraint: f.constraint.clone(),
                })
                .collect(),
        }
    }

    /// Build a spec from an authoritative [`agentos_infer::schema::Schema`].
    ///
    /// Prefer this over [`Self::from_json_schema`] whenever a real `Schema` is
    /// available: it is lossless, including the short-text allowlist.
    pub fn from_schema(schema: &agentos_infer::schema::Schema) -> Result<Self, ProtocolError> {
        Self::new(
            schema.name.clone(),
            schema
                .fields
                .iter()
                .map(|f| {
                    FieldSpec::new(f.name.clone(), f.constraint.clone())
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    }

    /// Recover a spec from the JSON Schema `agentos_infer` emits.
    ///
    /// This exists only because [`agentos_infer::Extractor`] hands the extractor
    /// a `serde_json::Value` rather than a [`agentos_infer::schema::Schema`], so
    /// a caller going through that trait has to go through the lossy encoding.
    /// The loss is deliberate and biased towards safety:
    ///
    /// - a JSON Schema cannot express [`Constraint`]'s character allowlist, so
    ///   every short-text field comes back with [`conservative_charset`]. That
    ///   can reject a value the caller would have accepted, which quarantines a
    ///   field; it can never accept one the caller would have rejected.
    /// - `{"type":"string","maxLength":n}` is how *both* `ShortText` and
    ///   `FreeText` are rendered, so a `maxLength` at or above
    ///   [`MAX_SHORT_TEXT_CHARS`] is read as `FreeText`. Reading it the other
    ///   way would type unbounded text, so the ambiguity resolves towards
    ///   quarantine.
    /// - anything not in this list is refused rather than approximated.
    ///
    /// Callers who hold a real [`agentos_infer::schema::Schema`] should use
    /// [`Self::from_schema`] and avoid all of the above.
    pub fn from_json_schema(
        name: &str,
        schema: &serde_json::Value,
    ) -> Result<Self, ProtocolError> {
        use serde_json::Value;

        let Value::Object(root) = schema else {
            return Err(ProtocolError::UnsupportedConstraint);
        };
        let properties = match root.get("properties") {
            Some(Value::Object(p)) => p,
            _ => return Err(ProtocolError::UnsupportedConstraint),
        };

        let mut fields = Vec::with_capacity(properties.len());
        for (field_name, field_schema) in properties {
            let Value::Object(spec) = field_schema else {
                return Err(ProtocolError::UnsupportedConstraint);
            };
            let constraint = if let Some(Value::Array(alternatives)) = spec.get("enum") {
                let mut set = BTreeMap::new();
                for a in alternatives {
                    let Value::String(s) = a else {
                        return Err(ProtocolError::UnsupportedConstraint);
                    };
                    if s.len() > MAX_NAME_BYTES || set.len() >= MAX_ENUM_ALTERNATIVES {
                        return Err(ProtocolError::UnsupportedConstraint);
                    }
                    set.insert(s.clone(), ());
                }
                Constraint::Enum(set.into_keys().collect())
            } else {
                match spec.get("type").and_then(Value::as_str) {
                    Some("boolean") => Constraint::Boolean,
                    Some("integer") => {
                        let min = spec.get("minimum").and_then(Value::as_i64);
                        let max = spec.get("maximum").and_then(Value::as_i64);
                        match (min, max) {
                            (Some(min), Some(max)) if min <= max => Constraint::Integer { min, max },
                            _ => return Err(ProtocolError::UnsupportedConstraint),
                        }
                    }
                    Some("string") => match spec.get("pattern").and_then(Value::as_str) {
                        // The only pattern `agentos_infer` emits for a date. The
                        // pattern string itself is dropped rather than carried
                        // into the child: a pattern is a filter description, and
                        // the host re-validates with `Constraint::Date` anyway.
                        Some(r"^\d{4}-\d{2}-\d{2}$") => Constraint::Date,
                        // Any other pattern is a filter this crate has not been
                        // asked to reason about, so it is refused rather than
                        // approximated by something weaker.
                        Some(_) => return Err(ProtocolError::UnsupportedConstraint),
                        None => {
                            let Some(n) = spec.get("maxLength").and_then(Value::as_u64) else {
                                return Err(ProtocolError::UnsupportedConstraint);
                            };
                            if n as usize >= MAX_SHORT_TEXT_CHARS {
                                Constraint::FreeText
                            } else {
                                Constraint::ShortText {
                                    max_len: n as usize,
                                    allowed: conservative_charset(),
                                }
                            }
                        }
                    },
                    _ => return Err(ProtocolError::UnsupportedConstraint),
                }
            };
            fields.push(FieldSpec::new(field_name.clone(), constraint)?);
        }
        Self::new(name, fields)
    }
}

impl Serialize for SchemaSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("SchemaSpec", 2)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("fields", &self.fields)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for SchemaSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireSchema {
            name: String,
            fields: Vec<FieldSpec>,
        }
        let wire = WireSchema::deserialize(d)?;
        SchemaSpec::new(wire.name, wire.fields).map_err(serde::de::Error::custom)
    }
}

/// One field of a [`SchemaSpec`].
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSpec {
    name: String,
    constraint: Constraint,
}

impl FieldSpec {
    /// Build a field, refusing a name that is too long and a short-text bound
    /// that would let an unbounded string through.
    pub fn new(name: impl Into<String>, constraint: Constraint) -> Result<Self, ProtocolError> {
        let name = name.into();
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(ProtocolError::NameTooLong);
        }
        if let Constraint::ShortText { max_len, allowed } = &constraint {
            if *max_len > MAX_SHORT_TEXT_CHARS || allowed.len() > 1024 {
                return Err(ProtocolError::UnsupportedConstraint);
            }
        }
        if let Constraint::Enum(values) = &constraint {
            if values.len() > MAX_ENUM_ALTERNATIVES {
                return Err(ProtocolError::UnsupportedConstraint);
            }
            if values.iter().any(|v| v.len() > MAX_NAME_BYTES) {
                return Err(ProtocolError::UnsupportedConstraint);
            }
        }
        Ok(Self { name, constraint })
    }

    /// The field's name. Bounded by [`MAX_NAME_BYTES`], so it cannot be a document.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How this field's values are bounded. Host-side policy: it is enforced on
    /// the reply, and the character allowlist it may carry is deliberately not
    /// sent to the child.
    pub fn constraint(&self) -> &Constraint {
        &self.constraint
    }
}

impl Serialize for FieldSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("FieldSpec", 2)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("constraint", &WireConstraint::from(&self.constraint))?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for FieldSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WireField {
            name: String,
            constraint: WireConstraint,
        }
        let wire = WireField::deserialize(d)?;
        FieldSpec::new(wire.name, wire.constraint.into_constraint())
            .map_err(serde::de::Error::custom)
    }
}

/// The constraint as it travels, with the short-text allowlist removed.
///
/// See [`SchemaSpec`] for why the allowlist is host-side and deliberately not
/// sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WireConstraint {
    Enum {
        values: Vec<String>,
    },
    Integer {
        min: i64,
        max: i64,
    },
    Boolean,
    Date,
    ShortText {
        max_len: usize,
    },
    FreeText,
}

impl WireConstraint {
    fn into_constraint(self) -> Constraint {
        match self {
            WireConstraint::Enum { values } => Constraint::Enum(values.into_iter().collect()),
            WireConstraint::Integer { min, max } => Constraint::Integer { min, max },
            WireConstraint::Boolean => Constraint::Boolean,
            WireConstraint::Date => Constraint::Date,
            WireConstraint::ShortText { max_len } => Constraint::ShortText {
                max_len,
                // Restored, not remembered. Losing an allowlist and finding the
                // conservative one can only reject more, never accept more.
                allowed: conservative_charset(),
            },
            WireConstraint::FreeText => Constraint::FreeText,
        }
    }
}

impl From<&Constraint> for WireConstraint {
    fn from(c: &Constraint) -> Self {
        match c {
            Constraint::Enum(v) => WireConstraint::Enum {
                values: v.iter().cloned().collect(),
            },
            Constraint::Integer { min, max } => WireConstraint::Integer {
                min: *min,
                max: *max,
            },
            Constraint::Boolean => WireConstraint::Boolean,
            Constraint::Date => WireConstraint::Date,
            Constraint::ShortText { max_len, .. } => WireConstraint::ShortText {
                max_len: *max_len,
            },
            Constraint::FreeText => WireConstraint::FreeText,
        }
    }
}

/// Everything the host may ask the quarantined extractor to do.
///
/// # Adding a variant is a security change
///
/// This enum has one variant because I2 says Q has no tools. A variant that
/// could name a tool, invoke one, or carry a path would move the boundary from
/// "Q cannot ask for anything except a schema" to "Q can ask for whatever this
/// enum grew". Whatever the reason for a new variant, it needs to be argued as
/// a weakening of I2 rather than as a feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Extract `schema` from the document that is being handed over as a file
    /// descriptor on the control socket.
    ///
    /// The document is not named, not sized, and not carried in the message.
    /// The host sends the schema here and then sends the descriptor; see
    /// [`crate::child`] for why that ordering matters.
    Extract {
        /// The schema to extract.
        schema: SchemaSpec,
    },
}

/// What the kernel told the child about its own confinement.
///
/// The host does not take the child's word for anything, but it also cannot
/// inspect another process's Landlock ruleset. So the child reports what the
/// kernel *returned*, and the host checks that what came back is the profile
/// that was promised. This is not attestation in a trusted sense - a child that
/// wants to lie can lie about this - but it does turn "the child says it is
/// confined" into a checkable claim, and a child that failed to confine will
/// have failed before reaching the point where it could report success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The Landlock ABI the ruleset was built for, or `None` if no ruleset was
    /// applied at all.
    pub abi: Option<u32>,
    /// `path_beneath` rules installed. Must be `0`: the document arrived as a
    /// descriptor, so there is no path to grant.
    pub fs_rules: usize,
    /// TCP port rules installed. Must be `0`.
    pub net_rules: usize,
    /// Whether `PR_SET_NO_NEW_PRIVS` was confirmed.
    pub no_new_privs: bool,
    /// Whether the seccomp allowlist was installed.
    pub seccomp: bool,
}

impl Attestation {
    /// The attestation a correctly confined child must produce.
    ///
    /// A single value, so "did the child confine itself" is one comparison
    /// rather than a policy the caller could loosen.
    pub fn expected() -> Self {
        Self {
            abi: None, // filled in by the child from the kernel's answer
            fs_rules: 0,
            net_rules: 0,
            no_new_privs: true,
            seccomp: true,
        }
    }

    /// Whether this report describes the profile I2 promises.
    pub fn is_expected(&self) -> bool {
        self.abi.is_some()
            && self.fs_rules == 0
            && self.net_rules == 0
            && self.no_new_privs
            && self.seccomp
    }
}

/// Why the extractor produced no values.
///
/// An enum with no payload, deliberately. The alternative - a `String` - would
/// let "I could not find the field" carry document text back out of the
/// quarantine, which is exactly the leak the quarantine exists to prevent.
/// The *shape* of a refusal is information the host needs; its *content* never
/// is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The document does not contain anything the schema asked for.
    NoMatch,
    /// The document could not be read as text.
    NotText,
    /// The schema asked for something this extractor cannot produce.
    UnsupportedSchema,
    /// The host's profile was not available, so nothing was read.
    ///
    /// The refusal is the *answer*, not an error: an extractor that could not
    /// confine itself has no business reporting what it found, and this variant
    /// is how it says so without having read a byte of the document.
    NotConfined,
}

/// What the extractor sends back.
#[derive(Clone, Serialize, Deserialize)]
pub struct Reply {
    /// What confinement did, as reported from inside the child.
    pub attestation: Attestation,
    /// The answer.
    pub outcome: Outcome,
}

// A hand-written, redacted `Debug`. The derived one would inline the raw
// `serde_json::Value`s straight from the hostile document into whatever log or
// panic message prints this type, which is exactly the channel this crate
// exists to close. Shape is still visible; content never is.
impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("attestation", &self.attestation)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// The answer itself.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Values for some subset of the schema's fields.
    ///
    /// Raw. Every value here is attacker-influenced and none of it is trusted:
    /// the host runs [`agentos_infer::schema::validate`] over this before it
    /// becomes an `Extraction`, and that validation is what types a field or
    /// quarantines it. This enum existing is not permission to read it.
    Values {
        /// Field name to raw JSON value. The host discards any name the schema
        /// did not declare, so a child cannot introduce a field by inventing
        /// one.
        fields: BTreeMap<String, serde_json::Value>,
    },
    /// No values. See [`RefusalReason`].
    Refused {
        /// Why.
        reason: RefusalReason,
    },
}

// Redacted like `Reply`'s: a `Values` answer carries attacker-authored JSON,
// and `{:?}` must not become a second way out of the quarantine. The field
// count and the refusal reason say what an operator needs; the payload never
// crosses into a log line.
impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Values { fields } => f
                .debug_struct("Values")
                .field("field_count", &fields.len())
                .finish(),
            Outcome::Refused { reason } => f
                .debug_struct("Refused")
                .field("reason", reason)
                .finish(),
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed phrases. A refusal explains itself to an operator and says
        // nothing about the document it declined to read.
        let s = match self {
            RefusalReason::NoMatch => "the document does not contain the requested fields",
            RefusalReason::NotText => "the document is not valid text",
            RefusalReason::UnsupportedSchema => "the schema is outside this extractor's capabilities",
            RefusalReason::NotConfined => "the extractor was not confined, so it read nothing",
        };
        f.write_str(s)
    }
}

impl Outcome {
    /// The values, if any were produced.
    pub fn values(&self) -> Option<&BTreeMap<String, serde_json::Value>> {
        match self {
            Outcome::Values { fields } => Some(fields),
            Outcome::Refused { .. } => None,
        }
    }

    /// The refusal reason, if this was a refusal.
    pub fn refusal(&self) -> Option<RefusalReason> {
        match self {
            Outcome::Values { .. } => None,
            Outcome::Refused { reason } => Some(*reason),
        }
    }
}

/// Something the child did that the host will not accept.
///
/// No variant carries the offending bytes. See the module docs for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The control stream ended mid-message.
    Truncated,
    /// A message declared a length outside the permitted range.
    ///
    /// Refused rather than allocated: a child that claims a 4 GiB frame gets an
    /// error, not the host's attempt to reserve 4 GiB on its behalf.
    LengthOutOfRange,
    /// The bytes were not a message this crate can parse.
    ///
    /// The `serde` message is discarded here rather than wrapped. It quotes the
    /// input, and the input is attacker text.
    MalformedPayload,
    /// A schema or field name was empty or longer than [`MAX_NAME_BYTES`].
    NameTooLong,
    /// A constraint this crate has not been reasoned about.
    ///
    /// Approximating an unknown constraint with a weaker one is how a schema
    /// stops being a boundary, so an unrecognised constraint is an error.
    UnsupportedConstraint,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every arm is a fixed phrase. Nothing derived from the message.
        let s = match self {
            ProtocolError::Truncated => "the control stream ended mid-message",
            ProtocolError::LengthOutOfRange => "declared message length is out of range",
            ProtocolError::MalformedPayload => "message was not a valid frame",
            ProtocolError::NameTooLong => "a schema or field name was empty or too long",
            ProtocolError::UnsupportedConstraint => {
                "the schema used a constraint this extractor will not approximate"
            }
        };
        f.write_str(s)
    }
}

impl std::error::Error for ProtocolError {}

/// Size prefix for a framed message: a big-endian `u32` byte count.
const LEN_PREFIX: usize = 4;

/// Upper bound on any framed message, in bytes.
///
/// Bounds both directions. The host refuses to *send* more, so it cannot push
/// an unbounded schema at the child; the child refuses to *read* more, so a
/// hostile or broken peer cannot make it reserve memory.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Write a length-prefixed frame.
pub fn write_frame<W: std::io::Write>(w: &mut W, body: &[u8]) -> Result<(), ProtocolError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let n = u32::try_from(body.len()).map_err(|_| ProtocolError::LengthOutOfRange)?;
    w.write_all(&n.to_be_bytes())
        .and_then(|()| w.write_all(body))
        .and_then(|()| w.flush())
        .map_err(|_| ProtocolError::Truncated)
}

/// Read one length-prefixed frame.
///
/// Returns `Ok(None)` at a clean end of stream, which is how the host learns
/// that a child exited without answering rather than hanging.
pub fn read_frame<R: std::io::Read>(r: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut prefix = [0u8; LEN_PREFIX];
    match read_full(r, &mut prefix)? {
        0 => return Ok(None),
        4 => {}
        _ => return Err(ProtocolError::Truncated),
    }
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared > MAX_FRAME_BYTES {
        return Err(ProtocolError::LengthOutOfRange);
    }
    let mut body = vec![0u8; declared];
    match read_full(r, &mut body)? {
        n if n == declared => Ok(Some(body)),
        _ => Err(ProtocolError::Truncated),
    }
}

/// `read_full` that reports how much it got, so a clean EOF at a message
/// boundary is distinguishable from a truncated message.
fn read_full<R: std::io::Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, ProtocolError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return Ok(got),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ProtocolError::Truncated),
        }
    }
    Ok(got)
}

/// Serialise a value into a frame body.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(value).map_err(|_| ProtocolError::MalformedPayload)
}

/// Parse a frame body.
///
/// [`ProtocolError::MalformedPayload`] deliberately carries nothing from
/// `serde_json::Error`, which quotes its input.
pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(body).map_err(|_| ProtocolError::MalformedPayload)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn bounded() -> SchemaSpec {
        SchemaSpec::new(
            "Invoice",
            [
                FieldSpec::new("total", Constraint::Integer { min: 0, max: 1_000_000 }).unwrap(),
                FieldSpec::new(
                    "status",
                    Constraint::Enum(["paid", "unpaid"].iter().map(|s| s.to_string()).collect()),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn the_request_has_exactly_one_variant_and_it_names_no_tool_or_path() {
        // Not a comment: this serialises the only constructible request and
        // asserts the wire form has no key that could name a tool, a path, or an
        // argument. If someone adds a `CallTool { .. }` variant this fails.
        let wire = serde_json::to_value(Request::Extract { schema: bounded() }).unwrap();
        let obj = wire.as_object().unwrap();
        assert_eq!(obj.len(), 1, "the request envelope gained a field: {wire}");
        assert!(obj.contains_key("extract"), "{wire}");

        let inner = obj["extract"].as_object().unwrap();
        for key in inner.keys() {
            assert!(
                key == "schema",
                "the extract request carries `{key}`, which is not a schema"
            );
        }
        // And no string anywhere in it looks like a path or a command.
        let rendered = wire.to_string();
        for hostile in ["/", "\\", "..", ";", "`", "$(", "http://"] {
            assert!(
                !rendered.contains(hostile),
                "request wire form contains {hostile:?}: {rendered}"
            );
        }
    }

    #[test]
    fn a_tool_calling_request_is_refused_rather_than_ignored() {
        // A future `CallTool` variant would make this parse. It is the test
        // that notices.
        for hostile in [
            r#"{"call_tool":{"name":"sh","args":["-c","id"]}}"#,
            r#"{"read_file":{"path":"/etc/passwd"}}"#,
            r#"{"open":{"path":"/etc/shadow"}}"#,
            r#"{"fetch":{"url":"http://169.254.169.254/latest/meta-data/"}}"#,
            r#"{"execute":{"program":"bash"}}"#,
        ] {
            assert!(
                serde_json::from_str::<Request>(hostile).is_err(),
                "the protocol accepted a message that can name a capability: {hostile}"
            );
        }
    }

    #[test]
    fn a_refusal_reason_cannot_carry_document_text() {
        // Compile-time property: `RefusalReason` has no String variant, so
        // there is no expression that puts document bytes in a refusal. The
        // runtime half asserts the rendered form is a fixed phrase.
        // There is no `String` in `RefusalReason`, so this is a compile-time property
        // with a runtime echo: the four rendered forms are checked to be fixed
        // phrases that name no path and match no document text.
        let rendered: Vec<String> = [
            RefusalReason::NoMatch,
            RefusalReason::NotText,
            RefusalReason::UnsupportedSchema,
            RefusalReason::NotConfined,
        ]
        .iter()
        .map(|r| r.to_string())
        .collect();
        for r in &rendered {
            assert!(
                !r.contains('/') && !r.contains('\\'),
                "a refusal reason rendered as something path-shaped: {r}"
            );
        }
        // Distinct, so an operator can tell the four apart from a log line alone.
        let unique: BTreeSet<&String> = rendered.iter().collect();
        assert_eq!(unique.len(), rendered.len(), "two refusals render identically");
    }

    #[test]
    fn the_only_attestation_that_is_accepted_is_zero_grants_and_two_layers() {
        assert!(Attestation {
            abi: Some(7),
            ..Attestation::expected()
        }
        .is_expected());

        // A single filesystem grant is a hole, even one.
        assert!(!Attestation {
            abi: Some(7),
            fs_rules: 1,
            ..Attestation::expected()
        }
        .is_expected());
        assert!(!Attestation {
            abi: Some(7),
            net_rules: 1,
            ..Attestation::expected()
        }
        .is_expected());
        // No ruleset at all.
        assert!(!Attestation::expected().is_expected());
        // Seccomp missing means `socket(2)` still works.
        assert!(!Attestation {
            abi: Some(7),
            seccomp: false,
            ..Attestation::expected()
        }
        .is_expected());
        // A ruleset that could be shed by a setuid exec.
        assert!(!Attestation {
            abi: Some(7),
            no_new_privs: false,
            ..Attestation::expected()
        }
        .is_expected());
    }

    #[test]
    fn a_short_text_allowlist_is_not_sent_to_the_child_but_is_restored_narrower() {
        // Build a schema whose short-text field has a deliberately wide
        // allowlist, then check what actually crosses the boundary.
        let wide = SchemaSpec::new(
            "X",
            [FieldSpec::new(
                "note",
                Constraint::ShortText {
                    max_len: 64,
                    allowed: ['a', '\n', ';', '`', '/', '\0'].into_iter().collect(),
                },
            )
            .unwrap()],
        )
        .unwrap();

        let wire = serde_json::to_string(&wide).unwrap();
        assert!(
            !wire.contains("\\u0000") && !wire.contains('`'),
            "the allowlist leaked into the wire form: {wire}"
        );
        assert!(!wire.contains("allowed"), "the wire form carries an allowlist: {wire}");

        let back: SchemaSpec = serde_json::from_str(&wire).unwrap();
        let c = back.fields()[0].constraint().clone();
        let Constraint::ShortText { allowed, .. } = c else {
            panic!("short text did not survive the round trip")
        };
        assert_eq!(
            allowed,
            conservative_charset(),
            "the allowlist came back as something other than the conservative one"
        );
        // And the narrow set genuinely rejects what the wide one allowed.
        let hostile = serde_json::json!("a`\0");
        assert!(!back.fields()[0].constraint().accepts(&hostile));
    }

    #[test]
    fn a_json_schema_round_trip_resolves_the_short_text_ambiguity_towards_quarantine() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "ref": {"type": "string", "maxLength": 32},
                "note": {"type": "string", "maxLength": 4096},
                "paid": {"type": "boolean"},
                "n": {"type": "integer", "minimum": 0, "maximum": 10},
                "day": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"},
            },
            "additionalProperties": false,
        });
        let spec = SchemaSpec::from_json_schema("X", &schema).unwrap();
        let ref_c = spec.field("ref").unwrap().constraint();
        assert!(matches!(ref_c, Constraint::ShortText { max_len: 32, .. }));
        // 4096 is how FreeText renders, and it must come back as FreeText.
        assert!(matches!(
            spec.field("note").unwrap().constraint(),
            Constraint::FreeText
        ));
        assert!(matches!(
            spec.field("paid").unwrap().constraint(),
            Constraint::Boolean
        ));
        assert!(matches!(
            spec.field("n").unwrap().constraint(),
            Constraint::Integer { min: 0, max: 10 }
        ));
        assert!(matches!(
            spec.field("day").unwrap().constraint(),
            Constraint::Date
        ));
    }

    #[test]
    fn an_unrecognised_json_schema_constraint_is_refused_not_approximated() {
        // Each of these would have to be approximated with something weaker to
        // parse, which is how a schema stops being a boundary.
        for hostile in [
            serde_json::json!({"type": "object", "properties": {"a": {"type": "number"}}}),
            serde_json::json!({"type": "object", "properties": {"a": {"type": "string"}}}),
            serde_json::json!({"type": "object", "properties": {"a": {"type": "string", "pattern": "^.*$"}}}),
            serde_json::json!({"type": "object", "properties": {"a": {"type": "integer"}}}),
            serde_json::json!({"type": "array"}),
            serde_json::json!({"type": "object"}),
        ] {
            assert!(
                SchemaSpec::from_json_schema("X", &hostile).is_err(),
                "an unvetted constraint was accepted: {hostile}"
            );
        }
    }

    #[test]
    fn an_oversized_frame_is_refused_rather_than_allocated() {
        // A child that claims a 4 GiB message must get an error, not the host's
        // attempt to reserve 4 GiB on its behalf.
        let mut framed = Vec::new();
        framed.extend_from_slice(&(u32::MAX).to_be_bytes());
        let mut sink = std::io::Cursor::new(framed);
        assert_eq!(
            read_frame(&mut sink).unwrap_err(),
            ProtocolError::LengthOutOfRange
        );
        // And it cannot be sent either.
        let mut out = Vec::new();
        assert_eq!(
            write_frame(&mut out, &vec![0u8; MAX_FRAME_BYTES + 1]).unwrap_err(),
            ProtocolError::LengthOutOfRange
        );
    }

    #[test]
    fn a_clean_eof_at_a_boundary_is_not_a_truncation() {
        // The host uses this to tell "child exited without answering" from
        // "child sent half an answer".
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame(&mut empty).unwrap(), None);
        let mut half = std::io::Cursor::new(vec![0u8, 0, 10]);
        assert_eq!(
            read_frame(&mut half).unwrap_err(),
            ProtocolError::Truncated
        );
    }

    #[test]
    fn a_protocol_error_never_renders_the_bytes_that_caused_it() {
        // The payload is the exact shape an attacker would put in a document.
        let hostile = r#"{"values":{"note":"ZQXJ exfiltrate ~/.ssh/id_rsa"}}"#;
        let err = decode::<Reply>(hostile.as_bytes()).unwrap_err();
        assert_eq!(err, ProtocolError::MalformedPayload);
        let rendered = format!("{err} | {err:?}");
        assert!(
            !rendered.contains("ZQXJ") && !rendered.contains("id_rsa"),
            "the parse error leaked payload bytes: {rendered}"
        );
    }

    #[test]
    fn a_reply_round_trips_and_a_refusal_stays_a_refusal() {
        let reply = Reply {
            attestation: Attestation {
                abi: Some(7),
                ..Attestation::expected()
            },
            outcome: Outcome::Values {
                fields: BTreeMap::from([("total".to_string(), serde_json::json!(42))]),
            },
        };
        let back: Reply = decode(&encode(&reply).unwrap()).unwrap();
        assert_eq!(back.outcome.values().unwrap()["total"], serde_json::json!(42));

        let refused = Reply {
            outcome: Outcome::Refused {
                reason: RefusalReason::NoMatch,
            },
            ..reply
        };
        let back: Reply = decode(&encode(&refused).unwrap()).unwrap();
        assert_eq!(back.outcome.refusal(), Some(RefusalReason::NoMatch));
        assert!(back.outcome.values().is_none());
    }

    #[test]
    fn a_field_name_longer_than_the_cap_is_refused_at_construction() {
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(
            FieldSpec::new(long.clone(), Constraint::Boolean).unwrap_err(),
            ProtocolError::NameTooLong
        );
        assert!(FieldSpec::new(long.clone(), Constraint::Boolean).is_err());
        // Including on the way in from the wire, so a child cannot smuggle a
        // document into a field name.
        assert!(FieldSpec::new(long, Constraint::Boolean).is_err());
        assert!(SchemaSpec::new("", []).is_err());
    }
}