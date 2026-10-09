//! The session loop: the thing that makes a plan finish.
//!
//! # What was missing
//!
//! Every piece existed separately and nothing joined them. The interpreter could
//! halt a plan and — as of `Machine` — carry its state across the halt. The host
//! could queue what the user was being asked and record a grant when they said
//! yes. `Disclosure` could put those two together. But no component drove the
//! cycle, so a halted plan simply stopped, and every measurement of the design
//! had been taken against programs that never reached the interesting case.
//!
//! The loop is:
//!
//! ```text
//!   plan --> advance --+--> Advanced --> advance
//!                      |
//!                      +--> Halted  --> ask --+--> yes --> grant --> advance
//!                      |                     +--> no  --> stop
//!                      |
//!                      +--> Done    --> reports
//!                      |
//!                      +--> Err     --> stop (and the machine is poisoned)
//! ```
//!
//! # Why this is not the Controller
//!
//! It holds no secret and decides nothing. The host still evaluates every
//! argument and owns the grants; the user still answers; `Machine` still decides
//! only where to carry on from. A loop is an ordering, not an authority, and the
//! value of writing it down is that there is now one place where the ordering can
//! be read rather than inferred.
//!
//! # The two failure modes this is shaped around
//!
//! **Asking forever.** A plan that halts on every turn would otherwise ask the
//! user indefinitely. Confirmation fatigue is a security property here, not a UX
//! annoyance — it is the finding that 17 of 33 measured attacks are held *only*
//! by a human prompt. So a session bounds how many times it may ask, and stops
//! with its own distinct outcome rather than appearing to complete.
//!
//! **Asking about one thing and doing another.** The grant is derived from the
//! values the host recorded at the halt, not from anything the caller supplies.
//! The user is shown the engine's own rendering of the engine's own view of the
//! arguments, the approval is matched against that same record, and the grant is
//! computed from it. There is no point in the cycle where a value is
//! reconstructed, and therefore no point where one could be substituted.

use agentos_dsl::{Extractor, Limits, Machine, Plan, PlanError, Step};
use agentos_policy::ConfirmationRequest;
use agentos_tools::PolicyHost;
use agentos_types::UserId;

use crate::disclosure::Disclosure;

/// How a session ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Every statement ran.
    Completed { reports: Vec<String> },
    /// The user said no. The plan did not resume and the refused call did not run.
    Refused { op: String },
    /// The session asked more times than it was allowed to.
    ///
    /// Distinct from [`Outcome::Refused`] on purpose. A refusal is a decision; this
    /// is the loop giving up, and reporting it as a refusal would let a session
    /// that simply could not keep asking be counted as one where a person said no.
    /// Conflating them is how a design claims credit for user attention.
    ConfirmationLimit { asked: usize },
    /// The plan stopped on an error. The machine is poisoned; the plan must not
    /// be re-run.
    ///
    /// The [`PlanError`] is carried typed rather than stringified, and that is not
    /// tidiness. A policy **denial** and a **budget stop** are different claims:
    /// the first says a machine refused without any human involved, the second
    /// says the plan ran out of room. Collapsing them into a reason string makes
    /// the automatic-versus-human split unmeasurable, because the measurement has
    /// to read one off the error. A caller wanting the denial case matches
    /// `Failed { error: PlanError::PolicyDenied { .. } }`.
    Failed { error: PlanError },
}

/// Default cap on how many times one session may ask the user.
///
/// Generous enough not to interfere with an ordinary task, low enough that a plan
/// which halts on every turn is stopped rather than turned into a questionnaire.
pub const DEFAULT_CONFIRMATION_LIMIT: usize = 16;

/// Drives one plan to completion, asking the user when policy requires it.
pub struct Session<'a> {
    host: &'a mut PolicyHost,
    user: UserId,
    limits: Limits,
    confirmation_limit: usize,
    /// How many times this session has asked. Reported in the outcome so a
    /// measurement can distinguish "a person was asked once" from "a person was
    /// asked nine times and said yes each time".
    asked: usize,
}

impl<'a> Session<'a> {
    pub fn new(user: UserId, host: &'a mut PolicyHost) -> Self {
        Self {
            host,
            user,
            limits: Limits::default(),
            confirmation_limit: DEFAULT_CONFIRMATION_LIMIT,
            asked: 0,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Cap the number of times this session may ask the user.
    pub fn with_confirmation_limit(mut self, limit: usize) -> Self {
        self.confirmation_limit = limit;
        self
    }

    /// How many times the user has been asked so far.
    ///
    /// Counts *prompts*, not arguments. One drain may put several arguments to a
    /// single question — a call with two tainted arguments is one thing to decide,
    /// not two — so this is the number of times a person was interrupted, which is
    /// the number a fatigue argument actually turns on.
    pub fn asked(&self) -> usize {
        self.asked
    }

    /// Run `plan`, asking `ask` whenever policy halts on something.
    ///
    /// `ask` receives the engine's own request — the arguments it flagged and the
    /// provenance that made them suspicious — and returns whether the user
    /// approved. It is the only place a human enters the system.
    pub fn run<F>(
        &mut self,
        plan: &Plan,
        extractor: &mut dyn Extractor,
        mut ask: F,
    ) -> Result<Outcome, PlanError>
    where
        F: FnMut(&ConfirmationRequest) -> bool,
    {
        let mut machine = Machine::start_with(plan, self.limits)?;

        loop {
            match machine.advance(self.host, extractor) {
                Ok(Step::Advanced) => continue,
                Ok(Step::Done) => {
                    return Ok(Outcome::Completed {
                        reports: machine
                            .reports()
                            .iter()
                            .map(|r| r.summary.clone())
                            .collect(),
                    })
                }
                Ok(Step::Halted { .. }) => {
                    if self.asked >= self.confirmation_limit {
                        return Ok(Outcome::ConfirmationLimit { asked: self.asked });
                    }
                    if !self.resolve(&mut ask)? {
                        // The user said no. Returned rather than resumed: a plan
                        // that continues past a refusal would be a plan acting
                        // against an answer it was given.
                        let op = self
                            .host
                            .take_pending()
                            .first()
                            .map(|p| p.op.clone())
                            .unwrap_or_else(|| "unknown".into());
                        return Ok(Outcome::Refused { op });
                    }
                }
                // The machine is poisoned from here, so the session stops rather
                // than looping. A `ConfirmationRequired` cannot arrive this way:
                // the interpreter converts it into `Step::Halted`.
                Err(e) => return Ok(Outcome::Failed { error: e }),
            }
        }
    }

    /// Ask about everything currently pending, and grant it if approved.
    ///
    /// Returns whether the session may continue. The `Disclosure` is scoped so
    /// its borrow of the host ends before the grants are written, which is why
    /// this is a method taking `ask` rather than code inlined at the call site.
    fn resolve<F>(&mut self, ask: &mut F) -> Result<bool, PlanError>
    where
        F: FnMut(&ConfirmationRequest) -> bool,
    {
        let approved: Vec<_> = {
            let mut disclosure = Disclosure::new(self.user, self.host);
            self.asked += 1;
            let resolutions = disclosure.drain(ask)?;
            if resolutions.iter().any(|r| !r.approved) {
                return Ok(false);
            }
            disclosure.approved().to_vec()
        };

        for pending in &approved {
            self.host.grant_pending(pending).map_err(|e| {
                PlanError::ToolRejected {
                    tool: pending.request.tool.clone(),
                    reason: format!("could not record the approval: {e}"),
                }
            })?;
        }
        Ok(true)
    }
}