use agentos_types::{Label, SourceId, Val};

/// A value the plan language can manipulate.
///
/// Every variant carries a `Val`, so taint is structurally attached to data
/// rather than tracked alongside it. Note that `Str` exists here: the DSL must
/// be able to carry strings, but the policy engine is what decides whether a
/// given string may reach a sensitive argument, not the type system.
///
/// There is deliberately no `impl Display for PlanData`. It used to render
/// `self.to_json()`, and `to_json` renders `Quoted` as a bare JSON string, so
/// the attacker's bytes came out with no quoting, no provenance, and no source
/// id: indistinguishable from a planner-authored `Str` in the output. That
/// matters because `Display` is what an error message, a log line, or a TUI row
/// reaches for by default. `PlanData` carries no label of its own, so no method
/// on it can render honestly; the supported path is
/// `Val::with_label_for_display`, which forces the label into the rendering.
///
/// ```compile_fail
/// // There is no label-free rendering of `PlanData` to reach for by accident.
/// let text = format!("{}", agentos_dsl::PlanData::Int(1));
/// ```
/// The data type the plan language manipulates.
///
/// `Serialize` is required because a user confirmation is a claim about a
/// specific value, and that claim is verified against the value's canonical
/// encoding. A value that cannot be encoded cannot be shown to a user
/// coherently either, so refusing to let it be confirmed is correct rather than
/// an inconvenience.
#[derive(Debug, Clone, serde::Serialize)]
pub enum PlanData {
    Unit,
    Bool(bool),
    Int(i64),
    /// A literal string written by the planner.
    Str(String),
    /// A string extracted from an untrusted source by the quarantined
    /// processor. Carries its own quarantine label.
    Quoted { text: String, source: SourceId },
    Enum(String),
    Record(Vec<(String, PlanData)>),
    List(Vec<PlanData>),
}

pub type PlanValue = Val<PlanData>;

impl PlanData {
    /// Text lifted out of an untrusted document. Always tainted.
    pub fn quoted(text: String, source: SourceId) -> Self {
        PlanData::Quoted { text, source }
    }

    pub fn record<I, K>(fields: I) -> Self
    where
        I: IntoIterator<Item = (K, PlanData)>,
        K: Into<String>,
    {
        PlanData::Record(
            fields
                .into_iter()
                .map(|(k, v)| (k.into(), v))
                .collect(),
        )
    }

    /// Field projection by name, or index into a list when the key parses as a
    /// usize. Extraction returns a list of records, so `inv.0.total` is the
    /// normal way to reach a field.
    pub fn get(&self, field: &str) -> Option<&PlanData> {
        match self {
            PlanData::Record(fields) => fields.iter().find(|(k, _)| k == field).map(|(_, v)| v),
            PlanData::List(items) => field.parse::<usize>().ok().and_then(|i| items.get(i)),
            _ => None,
        }
    }

    /// Render as JSON for a tool argument, preserving quoting.
    ///
    /// Label-free, by construction: `PlanData` does not hold one. The output
    /// renders `Quoted` and `Str` identically, so this must only be used where
    /// the value's provenance is already established and recorded elsewhere.
    /// It is not a renderer.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PlanData::Unit => serde_json::Value::Null,
            PlanData::Bool(b) => serde_json::Value::Bool(*b),
            PlanData::Int(i) => serde_json::Value::from(*i),
            PlanData::Str(s) | PlanData::Enum(s) => serde_json::Value::String(s.clone()),
            PlanData::Quoted { text, .. } => serde_json::Value::String(text.clone()),
            PlanData::Record(fields) => {
                let mut m = serde_json::Map::new();
                for (k, v) in fields {
                    m.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(m)
            }
            PlanData::List(items) => {
                serde_json::Value::Array(items.iter().map(|i| i.to_json()).collect())
            }
        }
    }

    /// The human-visible text of a scalar, for confirmation prompts.
    pub fn as_text(&self) -> Option<String> {
        match self {
            PlanData::Str(s) | PlanData::Enum(s) | PlanData::Quoted { text: s, .. } => {
                Some(s.clone())
            }
            PlanData::Int(i) => Some(i.to_string()),
            PlanData::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PlanData::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[PlanData]> {
        match self {
            PlanData::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            PlanData::Unit => "unit",
            PlanData::Bool(_) => "bool",
            PlanData::Int(_) => "int",
            PlanData::Str(_) => "str",
            PlanData::Quoted { .. } => "quoted",
            PlanData::Enum(_) => "enum",
            PlanData::Record(_) => "record",
            PlanData::List(_) => "list",
        }
    }
}

/// Free functions for hosts that hold a `PlanValue` rather than building
/// `PlanData` directly. Unused until `agentos-core` wires tools up.
#[allow(dead_code)]
pub fn quoted(text: String, source: SourceId) -> PlanData {
    PlanData::Quoted { text, source }
}

/// A value the planner authored. Safe to mark trusted because the planner never
/// observes untrusted bytes (invariant I1).
#[allow(dead_code)]
pub fn plan_trusted(data: PlanData) -> PlanValue {
    Val::trusted(data)
}

#[allow(dead_code)]
pub fn label_of(v: &PlanValue) -> &Label {
    v.label()
}
