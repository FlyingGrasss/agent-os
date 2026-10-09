//! The disclosure round trip.
//!
//! A plan that hits a tainted argument in a `Confirm` position halts: the
//! interpreter gets `PlanError::ConfirmationRequired` and stops. That is the
//! correct halt, but on its own it is a dead end, because nothing was
//! consuming the queued request. This module is the consumer.
//!
//! The shape of a round trip is:
//!
//! 1. the host halts and queues a [`PendingConfirmation`]
//! 2. the Controller renders it, showing the exact value and its provenance
//! 3. the user decides
//! 4. on approval, the Controller mints a [`Confirmation`] against the value it
//!    *showed*, and the value is re-confirmed through that token
//! 5. on refusal, the call is recorded as refused and the plan does not resume
//!
//! Step 4 is the subtle one. The Controller mints the token from the value it
//! displayed, and `Trusted::confirmed` recomputes the digest and refuses a
//! mismatch. So if the value changed between display and approval, the approval
//! fails loudly rather than silently authorising different bytes. That is the
//! property that makes confirmation mean something.

use agentos_dsl::{PlanData, PlanError};
use agentos_infer::leak::{record_confirmation_granted, record_confirmation_requested};
use agentos_policy::ConfirmationRequest;
use agentos_tools::{PendingConfirmation, PolicyHost};
use agentos_types::{Confirmation, Trusted, UserId, Val};

/// What the user was asked, and what they decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    pub op: String,
    pub approved: bool,
}

/// Outcome of driving one round trip.
#[derive(Debug, Clone, PartialEq)]
pub enum Disposition {
    /// The user approved. The value is now prompt-eligible.
    Approved,
    /// The user refused. The tool did not run and the plan must not resume.
    Refused { op: String },
}

impl Disposition {
    pub fn is_approved(&self) -> bool {
        matches!(self, Disposition::Approved)
    }
}

/// Resolves confirmation requests by asking a user.
///
/// This is the privileged side of the boundary. Everything it is given comes
/// from the halt that `PolicyHost` already enforced, and [`Self::approve`] now
/// enforces that at the type level: a value can only be promoted against a
/// request this `Disclosure` drained *and* the user approved, and the only way
/// to reach those is a request the policy engine actually raised.
pub struct Disclosure<'a> {
    user: UserId,
    host: &'a mut PolicyHost,
    /// Requests the user said yes to, captured during [`Self::drain`].
    ///
    /// The authority to promote lives here rather than in the caller's hands.
    /// That is the whole point: `Disclosure` is the only component that has seen
    /// both a policy halt and a human decision, so it is the only place a
    /// `Trusted` can honestly come from.
    approved: Vec<PendingConfirmation>,
}

impl<'a> Disclosure<'a> {
    pub fn new(user: UserId, host: &'a mut PolicyHost) -> Self {
        Self {
            user,
            host,
            approved: Vec::new(),
        }
    }

    /// Resolve every queued request, in order, asking `ask` for each.
    ///
    /// `ask` receives what should be shown to the user: the exact value and the
    /// kinds of source that produced it. It returns whether the user approved.
    ///
    /// Stops at the first refusal. A user who says no to one action has not
    /// thereby approved the rest, and continuing would let a single "no" be
    /// followed by a stream of side effects the user did not agree to.
    pub fn drain<F>(&mut self, mut ask: F) -> Result<Vec<Resolution>, PlanError>
    where
        F: FnMut(&ConfirmationRequest) -> bool,
    {
        let mut resolutions = Vec::new();
        for pending in self.host.take_pending() {
            record_confirmation_requested();
            let approved = ask(&pending.request);
            if approved {
                record_confirmation_granted();
            }
            resolutions.push(Resolution {
                op: pending.op.clone(),
                approved,
            });
            if !approved {
                return Ok(resolutions);
            }
            self.approved.push(pending);
        }
        Ok(resolutions)
    }

    /// Promote a value the user just saw and approved.
    ///
    /// Takes the value by reference and mints the token from the same bytes the
    /// caller displayed. If the caller displays one value and passes another,
    /// the digest check in `Trusted::confirmed` fails and this returns an error
    /// rather than promoting the wrong thing.
    ///
    /// `pending` must be a request this `Disclosure` drained and the user
    /// approved. That argument is not decoration: it is what makes promotion
    /// require a policy decision that put the value in a `Confirm` position.
    /// Without it, any caller holding a tainted `Val` could mint a `Trusted` from
    /// it — no host, no engine, no audit entry, no user — and that value would be
    /// indistinguishable from an approved one everywhere downstream. Harmless
    /// while nothing consumes a promoted value, which is the case today, and a
    /// live hole the moment a resumed plan runs a tool with one.
    pub fn approve(
        &self,
        pending: &PendingConfirmation,
        shown: &Val<PlanData>,
    ) -> Result<Trusted<PlanData>, PlanError> {
        if !self.approved.iter().any(|p| p == pending) {
            return Err(PlanError::ToolRejected {
                tool: "confirmation".into(),
                reason: "no approved request corresponds to this value: promotion requires a \
                         request the policy engine raised and the user approved"
                    .into(),
            });
        }
        let confirmation = Confirmation::issued_by_controller(self.user, shown)
            .map_err(|e| PlanError::ToolRejected {
                tool: "confirmation".into(),
                reason: e.to_string(),
            })?;
        Trusted::confirmed(shown.clone(), &confirmation).map_err(|e| PlanError::ToolRejected {
            tool: "confirmation".into(),
            reason: e.to_string(),
        })
    }

    /// The approved requests, in the order the user approved them.
    ///
    /// A resuming caller needs every one, not just the first: a single halted call
    /// queues one pending record carrying every argument the engine flagged, and a
    /// plan can queue several records across successive turns. Handing back the
    /// whole list from the same place `approve` checks against is what keeps an
    /// approval paired with the request it actually answers.
    pub fn approved(&self) -> &[PendingConfirmation] {
        &self.approved
    }

    /// The approved request a caller should promote against, if there is one.
///
/// A caller resuming a plan needs to know *which* halt the user's answer was to.
/// Returning it here rather than making the caller reach into the host's drained
/// queue is what ties the two together: the request comes from the same list
/// `approve` checks against, so a caller cannot pair an approval with a different
/// request.
pub fn approved_request(&self) -> Option<&PendingConfirmation> {
    self.approved.first()
}

pub fn user(&self) -> UserId {
        self.user
    }
}

/// Re-read a pending request's argument names, for display and logging.
///
/// `ConfirmationItem` holds rendered text, which is right for showing a human
/// and wrong for re-confirming: the digest is computed over a value, not over a
/// rendering. So a caller that wants to promote a value must hold onto the
/// value the plan was passing, and promote that one. This helper exists only to
/// name the operations that are outstanding.
pub fn request_ops(pending: &[PendingConfirmation]) -> Vec<String> {
    pending.iter().map(|p| p.op.clone()).collect()
}

