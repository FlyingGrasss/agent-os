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
use agentos_types::{approval_key, UserId, Val};

use crate::audit::{ArgumentRecord, AuditLog, AttemptToken, OutcomeKind, PolicySummary};

/// Why an approval could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The value could not be encoded for hashing.
    #[error("value could not be encoded for approval: {0}")]
    Encoding(String),
}

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
    /// Single-use approvals, by `(scope, key)`.
    ///
    /// See [`Self::grant`] for why a resumed plan needs these and why they are
    /// consumed rather than remembered.
    grants: std::collections::HashMap<(String, [u8; 32]), ()>,
    /// The user this session acts for.
    ///
    /// Part of the host rather than a parameter to `grant`, because the key has to
    /// be checked on *every* call and threading a user through the interpreter
    /// would put an identity in the pure evaluator. A host serves one session for
    /// one user.
    user: UserId,
}

/// A halted call awaiting a user's decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingConfirmation {
    pub op: String,
    pub request: ConfirmationRequest,
}

impl PolicyHost {
    pub fn new(engine: PolicyEngine, audit: AuditLog, user: UserId) -> Self {
        Self {
            engine,
            tools: BTreeMap::new(),
            audit,
            pending: Vec::new(),
            grants: std::collections::HashMap::new(),
            user,
        }
    }

    /// Record that `user` approved exactly `value` in the position `scope`.
    ///
    /// ## Why this exists
    ///
    /// A plan halts when the engine says `Confirm`. When the plan resumes, it
    /// re-enters this host with the *same* tainted value it halted on, and the
    /// engine says `Confirm` again. Without something marking that value as
    /// already-decided, the plan halts forever and the user is asked the same
    /// question on every attempt.
    ///
    /// ## Why the grant is scoped and single-use
    ///
    /// **Scoped.** The key binds `(tool.arg, user, label, bytes)`. A user who
    /// approved `payee@x.test` as `send_email.to` has not approved it as
    /// `send_email.reply_to`, and two byte-identical arguments must not share one
    /// approval.
    ///
    /// **Single-use.** Consumed by the first call it authorises. A grant that
    /// persisted would authorise every later identical call in the session, which
    /// turns one approval into a standing capability — the precise confusion I4
    /// exists to prevent.
    ///
    /// ## Why the decision stays here
    ///
    /// Granting lives on the host rather than in the interpreter because the host
    /// is where I4 is enforced. The interpreter is a pure evaluator holding no
    /// secrets; putting an authorisation there would be the first time it held
    /// one.
    pub fn grant(
        &mut self,
        scope: &str,
        value: &Val<PlanData>,
    ) -> Result<(), GrantError> {
        let key = approval_key(scope, self.user, value)
            .map_err(|e| GrantError::Encoding(e.to_string()))?;
        self.grants.insert((scope.to_string(), key), ());
        Ok(())
    }

    /// Whether every argument the engine flagged for confirmation carries an
    /// unspent approval.
    ///
    /// All of them, not any of them. A request listing two tainted arguments with
    /// an approval for one is still a question, because the user has not seen the
    /// other — and a partial approval that let the call through would be the same
    /// confusion `Disclosure::approve` is gated to prevent, reached by a
    /// different route.
    ///
    /// The tainted arguments are taken from the engine's own `request.items`, not
    /// recomputed here, so this cannot disagree with what was actually asked. A
    /// view the engine could not read (an opaque record or list) is not in `items`
    /// and so needs no grant — but it also could not have been confirmed, so the
    /// engine would have denied it earlier and this is never reached.
    fn confirm_is_fully_granted(
        &self,
        request: &ConfirmationRequest,
        args: &BTreeMap<String, PlanValue>,
        views: &BTreeMap<String, ArgView<'_>>,
    ) -> bool {
        if request.items.is_empty() {
            return true;
        }
        request.items.iter().all(|item| {
            let Some(value) = args.get(&item.arg) else {
                return false;
            };
            // The view must be one the engine actually saw as tainted, so a grant
            // cannot be planted against an argument the engine would have skipped.
            let was_tainted = views.get(&item.arg).is_some_and(|v| v.is_tainted());
            was_tainted && self.is_granted(&format!("{}.{}", request.tool, item.arg), value)
        })
    }

    /// Whether `scope`/`value` currently carries an unspent approval.
    fn is_granted(&self, scope: &str, value: &Val<PlanData>) -> bool {
        match approval_key(scope, self.user, value) {
            Ok(key) => self.grants.contains_key(&(scope.to_string(), key)),
            Err(_) => false,
        }
    }

    /// Spend an approval, returning whether one was there.
    fn spend_grant(&mut self, scope: &str, value: &Val<PlanData>) -> bool {
        match approval_key(scope, self.user, value) {
            Ok(key) => self.grants.remove(&(scope.to_string(), key)).is_some(),
            Err(_) => false,
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
        let all_views = Self::views(args);
        let decision = self.engine.evaluate(tool, &all_views);

        // A grant answers exactly one question: "did the user approve this?". It
        // is therefore consulted *after* evaluation and *only* on `Confirm`.
        //
        // The earlier version of this excluded granted arguments from the views
        // before evaluating, which is the obvious implementation and is a hole:
        // a granted `shell.cmd` left the view map empty, the engine had nothing
        // to classify and returned `Allow`, and the guardrail was gone. The
        // test `a_grant_cannot_override_a_deny` caught it. A `Deny` is not a
        // question anybody was asked, so there is no approval to replay, and it
        // must survive any grant.
        let mut spent: Vec<(String, Val<PlanData>)> = Vec::new();
        let decision = match decision {
            Decision::Confirm { request } => {
                if self.confirm_is_fully_granted(&request, args, &all_views) {
                    for item in &request.items {
                        if let Some(value) = args.get(&item.arg) {
                            spent.push((
                                format!("{tool}.{}", item.arg),
                                value.clone(),
                            ));
                        }
                    }
                    Decision::Allow
                } else {
                    Decision::Confirm { request }
                }
            }
            other => other,
        };
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
                // Spend the approvals that made this call possible, and only now.
                // Spending earlier would burn them on a call that then failed.
                for (scope, value) in &spent {
                    self.spend_grant(scope, value);
                }
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
