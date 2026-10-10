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
use agentos_pager::Pager;
use agentos_types::{ControllerAuthority, Origin, UserId};

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
    /// What the Controller would see, assembled by the pager.
    ///
    /// Optional because a caller that only wants the outcome should not be forced
    /// to pay for prompt assembly. When present, every step the session accepts
    /// is recorded and the prompt is the **only** way to read it back — so the
    /// I1 guarantee is carried by a type rather than by a convention somebody has
    /// to remember.
    pager: Option<Pager>,
    /// Names of tools the plan has used, for the pager's records.
    ///
    /// The pager records that a tool ran and how it ended, never what it was
    /// given. Tool arguments are where tainted values live, so they are
    /// structurally absent from what reaches the Controller's context.
    tools: Vec<agentos_pager::ToolName>,
}

impl<'a> Session<'a> {
    pub fn new(user: UserId, host: &'a mut PolicyHost) -> Self {
        Self {
            host,
            user,
            limits: Limits::default(),
            confirmation_limit: DEFAULT_CONFIRMATION_LIMIT,
            asked: 0,
            pager: None,
            tools: Vec::new(),
        }
    }

    /// Give this session a pager, so its steps are recorded into the Controller's
    /// context.
    ///
    /// The task is `Trusted` because the user wrote it. It is not the only route
    /// into the prompt — every recorded step and every fact is also trusted — but
    /// it is the one the caller has to get right first, so it is the parameter and
    /// it is a `Trusted` rather than a `String`.
    pub fn with_pager(
        mut self,
        task: &agentos_types::Trusted<String>,
        config: agentos_pager::PagerConfig,
    ) -> Result<Self, PlanError> {
        self.pager = Some(Pager::new(task.clone(), config).map_err(|e| {
            PlanError::ToolRejected {
                tool: "pager".into(),
                reason: e.to_string(),
            }
        })?);
        Ok(self)
    }

    /// The assembled prompt, if a pager was attached.
    ///
    /// Returns a `Trusted<String>` and nothing else. There is no accessor that
    /// hands back the text without its label, which is the point: a caller cannot
    /// read the Controller's context without holding the provenance that says
    /// where it came from.
    pub fn prompt(&self) -> Result<Option<agentos_pager::Prompt>, PlanError> {
        match &self.pager {
            Some(p) => p.assemble().map(Some).map_err(|e| PlanError::ToolRejected {
                tool: "pager".into(),
                reason: e.to_string(),
            }),
            None => Ok(None),
        }
    }

    /// Record the tool calls the machine reported.
    ///
    /// Reads `Machine::events` rather than being told what ran, so the record is
    /// derived from the interpreter's own account rather than this loop's guess.
    ///
    /// An earlier version recorded one bare checkpoint per statement, and that was
    /// wrong in a way only the test caught: the Controller's context said *that*
    /// work happened without saying *what*, and the rolled tally -- whose entire
    /// purpose is to be bounded by the tool schema rather than the task length --
    /// had no tools to count.
    ///
    /// A pager failure is deliberately not fatal. Losing context is bad; stopping a
    /// task because a summary could not be filed would be worse.
    fn record_events(&mut self, events: &[agentos_types::Event]) {
        if self.pager.is_none() {
            return;
        }
        for event in events {
            let agentos_types::Event::ToolCompleted { tool, ok, .. } = event else {
                continue;
            };
            self.record(
                &tool.clone(),
                if *ok {
                    agentos_pager::StepOutcome::Succeeded
                } else {
                    agentos_pager::StepOutcome::Failed
                },
            );
        }
    }

    /// Record one tool call into the pager.
    ///
    /// The name is interned, so the rolled tally holds one entry per *distinct
    /// tool* rather than one per call. That is what keeps the prompt bounded when a
    /// task runs the same tool a thousand times.
    fn record(&mut self, tool: &str, outcome: agentos_pager::StepOutcome) {
        let Some(pager) = self.pager.as_mut() else {
            return;
        };
        let handle = match self.tools.iter().find(|t| t.text() == tool) {
            Some(existing) => existing.clone(),
            None => {
                let handle = agentos_pager::ToolName::new(
                    agentos_types::Trusted::inherited(
                        Origin::Controller(ControllerAuthority::issue()),
                        tool.to_string(),
                    ),
                );
                self.tools.push(handle.clone());
                handle
            }
        };
        // `Val::trusted` is correct rather than convenient: a `StepRecord` is
        // structurally incapable of carrying untrusted text -- tool arguments are
        // deliberately not recorded, because that is where tainted values live --
        // so there is nothing here for a label to protect. The `Val` wrapper is
        // still what `ingest` takes, so a future record type that *could* carry
        // text would be caught at this boundary rather than trusted.
        let _ = pager.ingest(&agentos_types::Val::trusted(
            agentos_pager::StepRecord::tool(handle, outcome),
        ));
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
        // How much of `Machine::events` has already been filed, so each event is
        // recorded exactly once across a run that halts and resumes.
        let mut recorded = 0usize;

        loop {
            match machine.advance(self.host, extractor) {
                Ok(Step::Advanced) => {
                    // Drained, not accumulated: `Machine::events` is cumulative,
                    // so re-reading it every turn would re-record the whole
                    // history on every step and the tally would count the same
                    // call twice.
                    let fresh: Vec<agentos_types::Event> =
                        machine.events()[recorded..].to_vec();
                    recorded = machine.events().len();
                    self.record_events(&fresh);
                    continue;
                }
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
                    if let Some(op) = self.resolve(&mut ask)? {
                        // The user said no. Returned rather than resumed: a plan
                        // that continues past a refusal would be a plan acting
                        // against an answer it was given.
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
    /// Returns the `op` the user refused, or `None` if the session may continue.
    ///
    /// The refused `op` comes back from here rather than being re-read off the
    /// host afterwards. `drain` empties the host's queue as it goes, so a second
    /// `take_pending()` finds nothing and every refusal would be reported as
    /// `unknown` — a small lie, but the kind that makes a refusal unattributable
    /// in exactly the log where attribution is the point.
    fn resolve<F>(&mut self, ask: &mut F) -> Result<Option<String>, PlanError>
    where
        F: FnMut(&ConfirmationRequest) -> bool,
    {
        let approved: Vec<_> = {
            let mut disclosure = Disclosure::new(self.user, self.host);
            self.asked += 1;
            let resolutions = disclosure.drain(ask)?;
            if let Some(refused) = resolutions.iter().find(|r| !r.approved) {
                return Ok(Some(refused.op.clone()));
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
        Ok(None)
    }
}