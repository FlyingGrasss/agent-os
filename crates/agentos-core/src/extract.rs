//! Bridging the inference extractor to the plan language.
//!
//! # The gap this fills
//!
//! Two extractors exist and they do not meet. `agentos_infer::Extractor` is the
//! quarantined processor: it takes a [`Quarantined`] document and a JSON Schema,
//! and returns JSON. `agentos_dsl::Extractor` is what the interpreter calls: it
//! takes a [`PlanData`] document and a schema *name*, and returns [`PlanData`].
//!
//! Every plan that reads a web page needs both, so something has to convert. That
//! conversion is where a string lifted out of an untrusted document becomes a
//! value the rest of the system can hold, and it is the single most security-
//! sensitive line of code in this file.
//!
//! # The rule
//!
//! **Every string in an extraction becomes [`PlanData::Quoted`], and the result
//! carries the document's label — regardless of what the extractor said.**
//!
//! `PlanData::Str` is what a planner-authored literal looks like, and `report`
//! will happily print a trusted `Str`. So a conversion that turned an extracted
//! string into `Str` would hand attacker text to the Controller as
//! planner-authored prose, which is precisely the injection I1 exists to prevent
//! — reached through a JSON deserialiser rather than through a prompt.
//!
//! The label is forced rather than carried for the same reason. An extractor that
//! returned a `Trusted` label would be a bug in the extractor, and the wrong
//! response to a bug in a trust boundary is to fail closed, not to propagate it.
//! The document was untrusted by construction; nothing downstream can make that
//! not so.
//!
//! # What is preserved
//!
//! Structure. The extractor's job is to bound *shape*, and the shape is real
//! information: a `bool` that came back as a bool is still a bool, and an integer
//! is still an integer. Only text is restricted, because only text can carry an
//! instruction. That is the same rule the interpreter applies at `report`, and
//! having it in both places means the restriction does not depend on which path a
//! value took to get there.

use std::collections::BTreeMap;

use agentos_dsl::{PlanData, PlanError};
use agentos_infer::Extractor as InferExtractor;
use agentos_types::{Quarantined, SourceId};

/// Adapts a quarantined [`InferExtractor`] into the plan language's.
///
/// Holds the schema table rather than taking one per call: the interpreter names
/// a schema by string, and resolving that name to a JSON Schema is a Controller
/// decision made once, at construction, from schemas the Controller chose. A
/// schema arriving from the plan would let the plan choose the shape of what it is
/// allowed to learn.
pub struct ModelExtractor<'a> {
    inner: &'a mut dyn InferExtractor,
    schemas: BTreeMap<String, serde_json::Value>,
}

impl<'a> ModelExtractor<'a> {
    pub fn new(
        inner: &'a mut dyn InferExtractor,
        schemas: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self { inner, schemas }
    }

    /// Register a schema the plans may name.
    pub fn with_schema(mut self, name: impl Into<String>, schema: serde_json::Value) -> Self {
        self.schemas.insert(name.into(), schema);
        self
    }
}

impl agentos_dsl::Extractor for ModelExtractor<'_> {
    fn extract(&mut self, schema: &str, document: &PlanData) -> Result<PlanData, PlanError> {
        let spec = self.schemas.get(schema).ok_or_else(|| PlanError::UnknownSchema {
            schema: schema.to_string(),
        })?;

        // The document must be text the quarantined processor can actually be
        // given. Anything else is refused rather than rendered: turning an
        // arbitrary value into a string here would be inventing an input the
        // quarantine boundary never inspected.
        let (text, source) = match document {
            PlanData::Quoted { text, source } => (text.clone(), *source),
            other => {
                return Err(PlanError::ToolRejected {
                    tool: "extract".into(),
                    reason: format!(
                        "extraction needs an untrusted document, got {}",
                        other.type_name()
                    ),
                })
            }
        };

        let quarantined = Quarantined::from_source(text, source);
        let extraction = self.inner.extract(spec, &quarantined).map_err(|e| {
            PlanError::ToolRejected {
                tool: "extract".into(),
                reason: e.to_string(),
            }
        })?;

        // No label is set on the way out, and that is deliberate. The interpreter
        // applies the document's own label to whatever this returns, so an
        // extraction inherits the taint of the document it was lifted out of.
        // Setting one here would either duplicate that or, worse, provide a place
        // where a trusted label could be attached to attacker-controlled structure.
        //
        // Read through the deliberately awkward accessor, because that is the only
        // way to see inside a `Val` whose label has not been vouched for. It also
        // hands over the extractor's own claim, which is checked rather than
        // believed: an extractor that reports a *trusted* result for an untrusted
        // document is broken, and the right response to a broken trust boundary is
        // to refuse the run, not to launder the label through.
        let data = extraction.data.with_label_for_display(|json, label| {
            if label.is_trusted() {
                return Err(PlanError::ToolRejected {
                    tool: "extract".into(),
                    reason: "extractor returned a trusted result for an untrusted document"
                        .into(),
                });
            }
            Ok(from_json(json))
        })?;

        let bound = bounds_from_schema(spec);
        enforce_bound(&data, bound.as_ref())?;
        coerce_to_schema(data, spec)
    }
}

/// Narrow every field to the type the schema declared.
///
/// # Why this exists and why it is not the same as `enforce_bound`
///
/// A length bound **shrinks** the forwarding surface. It does not remove it. A
/// 96-character injection still fits in 96 characters, which is why the bounded
/// arm of the measurement still forwarded 56 bytes and only stopped one task.
///
/// A closed type **removes** it. A schema declaring `status: {enum: ["paid",
/// "unpaid", "overdue"]}` admits exactly three values, and the value that comes
/// out is one of the three strings the Controller wrote in the schema. Whatever
/// the document said, it cannot be forwarded, because it is not one of the
/// allowed values -- it fails to match and the extraction is refused.
///
/// That is the structural answer to forwarding, and it is the reason the earlier
/// measurement's modest result is not the end of the story.
///
/// # Two things this deliberately does not do
///
/// **It does not clear taint.** A field coerced to `paid` is still tainted: the
/// *choice* of that member was influenced by the document even though the
/// *content* came from the schema. Clearing the label would let a short value
/// skip confirmation entirely, which is the exact accident the bound's tests
/// guard against. Taint is about provenance; a closed type is about content.
/// Conflating them would trade one hole for another.
///
/// **It does not truncate or guess.** A value that does not fit its declared type
/// is refused, naming the field and the type. Substituting a default would mean
/// the plan proceeds on data the extractor never produced.
fn coerce_to_schema(data: PlanData, spec: &serde_json::Value) -> Result<PlanData, PlanError> {
    let Some(props) = spec.get("properties").and_then(|p| p.as_object()) else {
        return Ok(data);
    };
    let PlanData::Record(fields) = data else {
        // A non-record cannot be checked field by field. Refusing would break the
        // common case of a schema whose root is a scalar, so it passes through and
        // the length bound above is what constrains it.
        return Ok(data);
    };

    let mut out = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        match props.get(&name) {
            Some(field_spec) => {
                let coerced = coerce_field(&name, value, field_spec)?;
                out.push((name, coerced));
            }
            // A field the schema does not declare is left alone. It is still
            // bounded by `enforce_bound` above, so this is not an unbounded escape
            // -- but it is not typed either, and a caller who wants every field
            // checked should declare every field.
            None => out.push((name, value)),
        }
    }
    Ok(PlanData::Record(out))
}

fn coerce_field(
    name: &str,
    value: PlanData,
    spec: &serde_json::Value,
) -> Result<PlanData, PlanError> {
    let kind = spec.get("type").and_then(serde_json::Value::as_str);

    // Only string-shaped values are coerced. A JSON number or boolean that
    // arrived already typed needs no work, and coercing it would be a chance to
    // lose information for nothing.
    let (text, source) = match value {
        PlanData::Quoted { text, source } => (text, Some(source)),
        PlanData::Str(text) => (text, None),
        other => return Ok(other),
    };

    match kind {
        // --- enum -----------------------------------------------------------
        // The load-bearing case. The output is drawn from the schema's own list,
        // never from the document.
        Some("string") => {
            let Some(allowed) = spec.get("enum").and_then(|e| e.as_array()) else {
                return Ok(rebuild(text, source));
            };
            let normalised = normalise(&text);
            let chosen = allowed
                .iter()
                .filter_map(serde_json::Value::as_str)
                .find(|candidate| normalise(candidate) == normalised)
                .ok_or_else(|| PlanError::ToolRejected {
                    tool: "extract".into(),
                    reason: format!(
                        "field `{name}` is not one of the values this schema allows; \
                         a value outside a closed set has no forwarding surface, \
                         which is the point of declaring one"
                    ),
                })?;
            // Re-wrapped as the schema's own spelling, so the output is
            // byte-identical to one of the declared values and nothing else --
            // and rebuilt in the value's original *shape*, so a `Quoted` stays a
            // `Quoted`. Turning a lifted value into planner-authored `Str` text
            // would launder a label, which is the one thing this function must
            // never do.
            Ok(rebuild(chosen.to_string(), source))
        }

        // --- integer --------------------------------------------------------
        Some("integer") => {
            // Digits with optional separators and a leading sign. Deliberately
            // not `parse::<i64>()` on the raw text: that accepts forms the schema
            // author did not write down.
            let cleaned: String = text
                .trim()
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '_' && *c != ',')
                .collect();
            match cleaned.parse::<i64>() {
                Ok(n) => Ok(PlanData::Int(n)),
                Err(_) => Err(PlanError::ToolRejected {
                    tool: "extract".into(),
                    reason: format!(
                        "field `{name}` is declared an integer and its value is not \
                         one; an integer field has no forwarding surface, which is \
                         the point of declaring it"
                    ),
                }),
            }
        }

        // --- boolean --------------------------------------------------------
        Some("boolean") => {
            let t = text.trim().to_ascii_lowercase();
            match t.as_str() {
                "true" | "yes" | "1" => Ok(PlanData::Bool(true)),
                "false" | "no" | "0" => Ok(PlanData::Bool(false)),
                _ => Err(PlanError::ToolRejected {
                    tool: "extract".into(),
                    reason: format!(
                        "field `{name}` is declared a boolean and `{t}` is not one"
                    ),
                }),
            }
        }

        _ => Ok(rebuild(text, source)),
    }
}

/// Rebuild a string-shaped value, preserving whether it was lifted or authored.
///
/// The distinction is load-bearing and the reason this is not a one-liner:
/// `PlanData::Str` is what the Controller can read as its own, and `Quoted`
/// carries the source it must treat as untrusted. A coercion that swapped one for
/// the other would be laundering a label while appearing to be sanitising a
/// value -- the exact substitution this whole file exists to prevent.
fn rebuild(text: String, source: Option<agentos_types::SourceId>) -> PlanData {
    match source {
        Some(src) => PlanData::Quoted { text, source: src },
        None => PlanData::Str(text),
    }
}

/// Case- and whitespace-insensitive, so `"PAID"` matches a schema's `"paid"`.
///
/// Without this, an extraction would be refused for a reason that is not a
/// security problem, and the natural response -- to stop declaring enums -- would
/// undo the control.
fn normalise(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// The character ceiling a schema declares for its string fields.
///
/// Schema-wide rather than per-field, and the field name says so: `maxLength` is
/// read once across the properties and enforced against every string. That is
/// stricter than giving each field its own ceiling, which is the safe direction to
/// be wrong in -- but it does mean a schema cannot yet say "note is 200, memo is
/// 4000". Adding that would be a feature, and it would also be a way to widen the
/// forwarding surface, so it should be a deliberate decision rather than a
/// convenience.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldBounds {
    /// Longest string any field may carry.
    pub max_chars: usize,
}

/// Read the ceiling a schema declares, if it declares one.
///
/// A schema with no declared bound gets no bound. That default is load-bearing:
/// if a missing `maxLength` silently became *some* limit, every existing schema
/// would look protected and none would be. The absence of a limit is not a limit.
fn bounds_from_schema(spec: &serde_json::Value) -> Option<FieldBounds> {
    let props = spec.get("properties")?.as_object()?;
    let declared = props
        .values()
        .filter_map(|p| p.get("maxLength").and_then(serde_json::Value::as_u64))
        .max()?
        .max(1) as usize;
    Some(FieldBounds {
        max_chars: declared,
    })
}

/// Refuse any string longer than the schema allows.
///
/// Refused rather than truncated. Truncating would let attacker text survive in a
/// form nobody reviewed, and would report a value the extractor never produced --
/// a defence that silently loses data while appearing to hold. A document that
/// does not fit the shape the Controller asked for is a document to stop on.
fn enforce_bound(data: &PlanData, bounds: Option<&FieldBounds>) -> Result<(), PlanError> {
    let Some(bounds) = bounds else {
        return Ok(());
    };
    let mut worst: Option<(usize, String)> = None;
    walk_strings(data, &mut String::new(), &mut worst);
    let Some((len, path)) = worst else {
        return Ok(());
    };
    if len > bounds.max_chars {
        return Err(PlanError::ToolRejected {
            tool: "extract".into(),
            reason: format!(
                "field `{path}` is {len} characters, over the {} this schema \
                 declares; the document does not match the shape the Controller \
                 asked for",
                bounds.max_chars
            ),
        });
    }
    Ok(())
}

/// Find the longest string in the structure, and where it was.
///
/// Walks records and lists rather than stopping at the top level, because nesting
/// is exactly where a payload would be put by anyone who had read this function.
/// A bound that only inspected top-level fields would look like a defence while
/// measuring nothing.
fn walk_strings(data: &PlanData, path: &mut String, worst: &mut Option<(usize, String)>) {
    let mut note = |len: usize, at: &str| {
        let better = worst.as_ref().is_none_or(|(best, _)| len > *best);
        if better {
            *worst = Some((len, at.to_string()));
        }
    };

    match data {
        PlanData::Quoted { text, .. } | PlanData::Str(text) => {
            note(text.chars().count(), path);
        }
        PlanData::Record(fields) => {
            let base = path.clone();
            for (name, value) in fields {
                let here = if base.is_empty() {
                    name.clone()
                } else {
                    format!("{base}.{name}")
                };
                *path = here;
                walk_strings(value, path, worst);
            }
            *path = base;
        }
        PlanData::List(items) => {
            let base = path.clone();
            for (i, value) in items.iter().enumerate() {
                *path = format!("{base}[{i}]");
                walk_strings(value, path, worst);
            }
            *path = base;
        }
        _ => {}
    }
}

/// Convert an extraction's JSON into plan data.
///
/// Every string becomes [`PlanData::Quoted`]. This is the rule the module is
/// about, so it is a free function with no label plumbing in it: there is no way
/// for a caller to pass a trusted label through, because there is nowhere to pass
/// one.
fn from_json(value: &serde_json::Value) -> PlanData {
    match value {
        serde_json::Value::Null => PlanData::Unit,
        serde_json::Value::Bool(b) => PlanData::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => PlanData::Int(i),
            // A non-integer number has no bounded representation in the plan
            // language. `Unit` is the honest answer: the field existed, and its
            // value is not something this language can carry. It is not `0`,
            // because that would be a value the document never contained.
            None => PlanData::Unit,
        },
        // Every string, always. See the module docs.
        serde_json::Value::String(s) => PlanData::Quoted {
            text: s.clone(),
            source: SourceId::nil(),
        },
        serde_json::Value::Array(items) => PlanData::List(items.iter().map(from_json).collect()),
        serde_json::Value::Object(fields) => PlanData::Record(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), from_json(v)))
                .collect(),
        ),
    }
}