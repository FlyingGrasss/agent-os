//! The tool boundary, where invariant I4 is enforced.
//!
//! `ToolHost` in `agentos-dsl` is a trait, so implementing it *is* the security
//! boundary. The previous tests proved the policy engine reaches the right
//! verdict and proved the interpreter propagates taint, but nothing connected
//! the two: a host could call a tool without ever consulting the engine and
//! every test would still pass. `PolicyHost` is that connection.
//!
//! The ordering is the point. For every call it does, in this sequence:
//!
//! 1. resolve the tool, refusing an unknown name
//! 2. build policy views, which carry each argument's label alongside its text
//! 3. evaluate the policy engine
//! 4. append the attempt to the audit log, and only then
//! 5. perform the effect, if and only if the decision was `Allow`
//!
//! A `Deny` and a `Confirm` both stop before step 5. There is no path through
//! this type in which a tool runs without a prior `Allow`.

use std::collections::BTreeMap;

use agentos_dsl::{PlanData, PlanError, PlanValue, ToolHost};
use agentos_policy::{ArgView, ConfirmationRequest, Decision, PolicyEngine};
use agentos_types::Val;

use crate::audit::{ArgumentRecord, AuditLog, AttemptToken, OutcomeKind, PolicySummary};

/// A tool the host is willing to run.
///
/// Implementations receive arguments whose labels the host has already checked.
/// They are still expected to treat their arguments as untrusted: the policy
/// engine decides whether a value *may* be used here, not whether the tool can
/// assume it is safe.
pub trait Tool {
    /// Name used in plans, for example `send_email`.
    fn name(&self) -> &str;

    /// Perform the effect. Called only after the policy engine returned
    /// `Allow` and the attempt was durably recorded.
    fn invoke(&mut self, args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError>;
}

/// A tool host that enforces policy and records every attempt.
pub struct PolicyHost {
    engine: PolicyEngine,
    tools: BTreeMap<String, Box<dyn Tool>>,
    audit: AuditLog,
    /// Confirmation requests raised by calls that were halted. The Controller
    /// drains these to prompt the user, then resumes the plan.
    ///
    /// The request cannot travel inside `PlanError` because that type lives in
    /// `agentos-dsl`, which must not depend on `agentos-policy`. Queuing it on
    /// the host keeps the dependency pointing the right way while still making
    /// the halt observable: the call returns an error, so the plan stops.
    pending: Vec<PendingConfirmation>,
}

/// A halted call awaiting a user's decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingConfirmation {
    pub op: String,
    pub request: ConfirmationRequest,
}

impl PolicyHost {
    pub fn new(engine: PolicyEngine, audit: AuditLog) -> Self {
        Self {
            engine,
            tools: BTreeMap::new(),
            audit,
            pending: Vec::new(),
        }
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut PolicyEngine {
        &mut self.engine
    }

    /// Take the confirmation requests raised since the last drain.
    pub fn take_pending(&mut self) -> Vec<PendingConfirmation> {
        std::mem::take(&mut self.pending)
    }

    /// Build policy views for a call's arguments.
    ///
    /// Every argument becomes a view, including trusted ones, so no argument can
    /// be silently absent from the policy evaluation. Text is taken only from
    /// scalars; records and lists have no single text form and are represented
    /// as opaque, which the `Allowlist` rule treats as a denial rather than as a
    /// pass.
    fn views(args: &BTreeMap<String, PlanValue>) -> BTreeMap<String, ArgView<'_>> {
        args.iter()
            .map(|(name, value)| (name.clone(), ArgView::new(value, plan_text)))
            .collect()
    }

    fn records(args: &BTreeMap<String, PlanValue>) -> Vec<ArgumentRecord> {
        args.iter()
            .map(|(name, value)| {
                // Read the text and the type name in one borrow of the value, so
                // the label attached to the record is the value's own.
                value.with_label_for_display(|data, label| {
                    let view = Val::labeled(data.type_name(), label.clone());
                    match plan_text(data) {
                        Some(text) => ArgumentRecord::text(
                            name,
                            &Val::labeled(text, label.clone()),
                        ),
                        None => ArgumentRecord::opaque(name, &view, data.type_name()),
                    }
                })
            })
            .collect()
    }
}

/// The text form of a plan value, if it has one.
///
/// Deliberately returns `None` for `Quoted` even though it holds text. Quoted
/// values exist precisely to be unreadable by the Controller, so policy
/// evaluation must not render them either.
fn plan_text(data: &PlanData) -> Option<String> {
    match data {
        PlanData::Str(s) | PlanData::Enum(s) => Some(s.clone()),
        PlanData::Int(i) => Some(i.to_string()),
        PlanData::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

impl ToolHost for PolicyHost {
    fn call(
        &mut self,
        tool: &str,
        args: &BTreeMap<String, PlanValue>,
    ) -> Result<PlanValue, PlanError> {
        // 1. Resolve. An unknown tool is refused before any policy work, and
        //    there is no dynamic dispatch that could name something else.
        if !self.tools.contains_key(tool) {
            return Err(PlanError::ToolRejected {
                tool: tool.to_string(),
                reason: "no such tool is registered with this host".into(),
            });
        }

        // 2. Evaluate. Views carry labels, so the engine cannot be handed a
        //    value whose provenance was dropped on the way here.
        let decision = self.engine.evaluate(tool, &Self::views(args));
        let summary = match &decision {
            Decision::Allow => PolicySummary::Allowed,
            Decision::Confirm { .. } => PolicySummary::NeedsConfirmation,
            Decision::Deny { .. } => PolicySummary::Denied,
        };

        // 3. Record the attempt BEFORE the effect. A crash or hang during the
        //    tool still leaves evidence that it was reached.
        let records = Self::records(args);
        let token: AttemptToken = self
            .audit
            .record_intent(tool, &records, summary)
            .map_err(|e| PlanError::ToolRejected {
                tool: tool.to_string(),
                reason: format!("audit log unavailable: {e}"),
            })?;

        // 4. Act only on Allow. The tool is looked up again rather than held
        //    across the audit writes above, so nothing is borrowed from `self`
        //    while it is being mutated.
        match decision {
            Decision::Deny { op, reason } => {
                let _ = self.audit.record_outcome(&token, OutcomeKind::denied(&reason));
                Err(PlanError::PolicyDenied { op, reason })
            }
            Decision::Confirm { request } => {
                let _ = self
                    .audit
                    .record_outcome(&token, OutcomeKind::refused("awaiting user"));
                let op = format!(
                    "{tool}.{}",
                    request
                        .items
                        .first()
                        .map(|i| i.arg.as_str())
                        .unwrap_or("?")
                );
                self.pending.push(PendingConfirmation {
                    op: op.clone(),
                    request,
                });
                Err(PlanError::ConfirmationRequired { op })
            }
            Decision::Allow => {
                let result = self
                    .tools
                    .get_mut(tool)
                    .expect("tool presence checked above and no mutation since")
                    .invoke(args);
                let outcome = match &result {
                    Ok(_) => OutcomeKind::Succeeded { elapsed_ms: 0 },
                    Err(e) => OutcomeKind::failed(&e.to_string()),
                };
                let _ = self.audit.record_outcome(&token, outcome);
                result
            }
        }
    }
}
