//! Turning one IPC request into a plan, a run, and an outcome.
//!
//! # What this file is allowed to assume
//!
//! Nothing it receives is trusted, and the reasons are specific rather than
//! ritual:
//!
//! - The **task text** came off a socket. It is [`Quarantined`] on arrival.
//! - The **grants** came off a socket. `grants::Ceiling::narrow` intersects them
//!   with the operator's ceiling.
//! - The **tools** may do real things. They are registered only from grants that
//!   survived narrowing.
//!
//! # The one thing this file refuses to do
//!
//! **It never approves.** [`run_task`] wires the session's `ask` closure to a
//! constant `false`.
//!
//! That is not a stub. It is the daemon's security position stated as code. The
//! alternative -- accepting an approval over IPC -- would mean that whoever can
//! reach the socket is a principal in the system's authority model, and the
//! daemon would be extending privileges to an unbounded set of local processes
//! with no way to tell a user from a script. The existing rule
//! (`agentos_cli::decide`: a non-interactive stdin is not approval) says a *process*
//! without a person cannot approve. A daemon has no stdin at all, so it is that
//! case unconditionally rather than by accident.
//!
//! The consequence is honest and worth stating plainly: **a headless daemon cannot
//! execute any plan that requires approval.** It plans, and it runs plans whose
//! arguments policy is willing to allow outright. When policy halts, the halt is
//! reported with the rendered request attached and nothing was sent or written.
//! An interactive front-end can render that request, obtain a real answer from a
//! real person, and start a new daemon run with the result -- but the approval
//! happens in the human's terminal, not in this process.
//!
//! This is reported to clients as `Info::can_ask_human = false` rather than left
//! to be discovered, because a caller that assumed otherwise would plan around a
//! capability that does not exist.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use crate::{decide, render_request, Decision};
use agentos_core::{ModelExtractor, Outcome, PlanOutcome, Planner, Session};
use agentos_dsl::PlanError;
use agentos_infer::{Backend, Extraction, InferError, Ollama, RoleModels};
use agentos_pager::PagerConfig;
use agentos_policy::{ConfirmationRequest, PolicyEngine, RuleSet};
use agentos_tools::audit::{AuditLog, AuditSink, Clock};
use agentos_tools::host::PolicyHost;
use agentos_tools::{FsWrite, HttpFetch, SendEmail};
use agentos_types::{
    ControllerAuthority, Origin, Quarantined, SourceId, Trusted, UserId, Val,
};

use super::grants::{Ceiling, TaskGrants};
use super::protocol::{codes, ErrorBody, ExecuteParams, Info, TaskOutcome};

/// Adapts the shared, mutex-guarded sink into the owned one `AuditLog` wants.
struct LockedSink(SharedSink);

impl AuditSink for LockedSink {
    fn append(
        &mut self,
        record: &mut agentos_tools::audit::AuditRecord,
    ) -> Result<(), agentos_tools::audit::AuditError> {
        // A poisoned audit mutex means some other task panicked while holding it.
        // Refusing to write rather than writing anyway: an audit record is
        // evidence, and evidence written after losing track of the log's state is
        // worse than a loud failure that stops the daemon.
        //
        // The sequence number is assigned by the inner sink while this lock is
        // held, which is what makes it unique across tasks even though each task
        // owns its own `AuditLog`.
        self.0
            .lock()
            .map_err(|_| {
                agentos_tools::audit::AuditError::Build(
                    "the shared audit sink is poisoned".into(),
                )
            })?
            .append(record)
    }

    fn peek_next_seq(&self) -> u64 {
        // Advisory only: another task may append before the caller's next append,
        // so this reads a value that is about to be stale by design. The number
        // that reaches a record is the one `append` assigns under the lock.
        self.0.lock().map(|s| s.peek_next_seq()).unwrap_or(0)
    }
}

/// Adapts the shared, mutex-guarded clock.
struct LockedClock(SharedClock);

impl Clock for LockedClock {
    fn now_unix_ms(&self) -> u64 {
        // A poisoned clock lock cannot lose the fact that time passed; falling
        // back to 0 would put a wrong timestamp in the audit trail, which is worse
        // than a duplicate timestamp. `SystemClock` is a pure read with no state to
        // corrupt, so this arm is unreachable in practice.
        self.0.lock().map(|c| c.now_unix_ms()).unwrap_or(0)
    }
}

/// The audit sink shared by every task in this daemon.
///
/// [`AuditSink`] is `Send` but not `Sync` -- it owns a file handle and `append`
/// needs `&mut self` -- so sharing it across the blocking pool means a `Mutex`,
/// not an `Arc`. The distinction is the difference between a sink that works and
/// one that will not compile, and getting it wrong would have meant either
/// writing a sink per task or claiming a `Sync` bound the trait does not have.
///
/// One file, one append order, one sequence of `sync_data` calls -- which is what
/// invariant I6 is about. Sharing rather than duplicating is what keeps that true:
/// a per-task `FileSink` on the same path would interleave records from concurrent
/// tasks and make the ordering an artefact of scheduling.
pub type SharedSink = Arc<std::sync::Mutex<dyn AuditSink>>;

/// The clock shared by every task. Same `Send`-but-not-`Sync` reasoning as
/// [`SharedSink`].
pub type SharedClock = Arc<std::sync::Mutex<dyn Clock>>;

/// The user this daemon acts for.
///
/// One fixed identity for the process. Deriving a real per-request identity would
/// need authenticated IPC, which this build does not have; what matters now is
/// that the origin column in the audit log means one thing consistently, which
/// `Session::asked` and the policy engine both rely on.
fn daemon_user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 0x01;
    UserId(uuid::Uuid::from_bytes(b))
}

/// Run one task.
///
/// Returns a [`TaskOutcome`] on success. An `Err` is reserved for failures that
/// are the daemon's fault rather than the task's -- a model that will not answer,
/// a pager that will not assemble, a tool that could not be registered. Anything
/// the *plan* did wrong comes back as `Ok(TaskOutcome::Failed { .. })` so the
/// client can tell "your task was refused" from "the daemon is broken".
pub fn run_task(
    backend: &mut dyn Backend,
    params: ExecuteParams,
    ceiling: &Ceiling,
    audit_sink: SharedSink,
    clock: SharedClock,
) -> Result<TaskOutcome, ErrorBody> {
    // --- grants, narrowed ----------------------------------------------------
    let grants: TaskGrants = ceiling
        .narrow(&params.grants)
        .map_err(|e| ErrorBody::grant_denied(e.to_string()))?;

    // --- the task, quarantined ----------------------------------------------
    //
    // This is where wire text becomes `Quarantined`. It is the only place that
    // happens, and after this line the text is not readable except through a
    // closure that also yields its label.
    let source = SourceId::new();
    let quarantined = params.into_quarantined(source);

    // Promote to `Trusted` through the *one* route this workspace allows: a user
    // writing it. Here the "user" is the operator who launched the daemon and
    // configured its ceiling, which is a position above whoever can open the
    // socket. That promotion is what makes the text reach the planner at all, and
    // it is why the daemon refuses to run with an empty ceiling: without an
    // operator having said what the daemon may do, there is nobody to have
    // written this task.
    //
    // Without this the daemon could not run anything at all, which would make it
    // inert. So the promotion is made explicit here and carries the provenance
    // `Origin::User`, which the audit log will show. A reader of that log can see
    // that tasks were attributed to the daemon's configured user, not to a
    // requester -- which is the truth, because the ceiling was the requester's
    // gate.
    let task_text = quarantined.with_label_for_display(|t, _| t.clone());
    let user = daemon_user();
    let task = Trusted::inherited(Origin::User(user), task_text.clone());

    // --- policy and tools ---------------------------------------------------
    let mut rules = RuleSet::default();
    if grants.fetch.is_some() {
        agentos_tools::http::install_policy_rules(&mut rules);
    }
    if grants.mail.is_some() {
        agentos_tools::mail::install_policy_rules(&mut rules);
    }

    // `AuditLog` owns its sink and clock outright, so the shared mutexes are moved
    // into owned boxes here. Each task gets its own `AuditLog` over the same file.
    //
    // That is now purely about ownership, not about the sequence counter: the
    // counter lives in the sink (`FileSink::next_seq`), which every task shares, so
    // `seq` is ledger-wide even though the `AuditLog` wrapper is per-task. An
    // earlier version kept the counter in `AuditLog` and argued that sharing it
    // would mean sharing the whole `PolicyHost`; moving it into the sink removes
    // that constraint entirely.
    //
    // The lock is held only for the duration of one `append` or one clock read,
    // never across a tool call, so one task's slow work cannot stall another's
    // bookkeeping.
    let audit = AuditLog::new(Box::new(LockedSink(audit_sink)), Box::new(LockedClock(clock)));
    let mut host = PolicyHost::new(PolicyEngine::new(rules), audit, user);

    // Pin the intent from the user's own words only. Built from the task and never
    // from a document, so a hostile page cannot widen it.
    host.pin_intent(task.get());

    if let Some(grant) = grants.fetch {
        host.register(Box::new(HttpFetch::new(grant)));
    }
    if let Some(grant) = grants.write {
        host.register(Box::new(FsWrite::new(grant)));
    }
    if let Some(grant) = grants.mail {
        host.register(Box::new(SendEmail::new(grant)));
    }

    // --- plan ---------------------------------------------------------------
    let mut planner = Planner::new(backend, user);
    let plan = match planner.plan(&task) {
        Ok(PlanOutcome::Planned(p)) => p,
        Ok(PlanOutcome::Unusable { reason }) => {
            // A model-quality result, not a security refusal. Reported distinctly
            // because "the model could not plan this" and "policy stopped this" are
            // different claims and a client needs to be able to tell them apart.
            return Err(ErrorBody {
                code: codes::INVALID_PARAMS,
                message: format!("the planner produced no usable plan: {reason}"),
                data: Some(serde_json::json!({ "kind": "unusable_plan" })),
            });
        }
        Err(e) => return Err(ErrorBody::internal(format!("planner failed: {e}"))),
    };

    // --- run ----------------------------------------------------------------
    let mut schemas = BTreeMap::new();
    schemas.insert(
        "Document".to_string(),
        serde_json::json!({
            "title": "Document",
            "type": "object",
            "properties": { "text": { "type": "string", "maxLength": 4000 } }
        }),
    );
    let mut role_q = VerbatimExtractor;
    let mut extractor = ModelExtractor::new(&mut role_q, schemas);

    let mut session = Session::new(user, &mut host)
        .with_pager(
            &Trusted::inherited(Origin::Controller(ControllerAuthority::issue()), task_text.clone()),
            PagerConfig::default(),
        )
        .map_err(|e| ErrorBody::internal(format!("could not start the context pager: {e}")))?;

    // Every confirmation request raised during this run, captured so the refusal
    // can be reported truthfully. See `refuse_but_record`.
    let raised: Rc<RefCell<Vec<ConfirmationRequest>>> = Rc::new(RefCell::new(Vec::new()));

    let outcome = session
        .run(&plan, &mut extractor, |request| refuse_but_record(request, &raised))
        .map_err(|e| ErrorBody::internal(format!("session failed: {e}")))?;

    Ok(classify(outcome, &raised))
}

/// The daemon's answer to every confirmation request: no.
///
/// It records the request before answering, because *how* the daemon refuses is
/// the difference between two different claims. `Session::run` turns a `false`
/// into `Outcome::Refused`, and reporting that verbatim would assert that a person
/// declined. Nobody was asked. The recorded request is what lets the caller tell
/// "the system said no" from "there was nobody to say" -- the same distinction
/// `Outcome::ConfirmationLimit` was separated out to preserve.
pub(crate) fn refuse_but_record(
    request: &ConfirmationRequest,
    raised: &Rc<RefCell<Vec<ConfirmationRequest>>>,
) -> bool {
    // Compare against the CLI's own decision so the reason is the project's
    // vocabulary rather than a new one: a daemon has no stdin, so the CLI's rule
    // for a process with nobody to ask must be what this is.
    debug_assert_eq!(
        decide("", false),
        Decision::NoHumanPresent,
        "a daemon has no stdin, so the CLI's own rule must say no-human"
    );
    raised.borrow_mut().push(request.clone());
    false
}

/// [`classify`] under a name the tests can reach.
///
/// The mapping from a session outcome to a wire outcome is load-bearing -- it is
/// where "nobody said no" becomes distinguishable from "a person said no" -- so it
/// gets tested directly rather than only through a full run that would need a live
/// model to reach it.
#[cfg(test)]
pub(crate) fn classify_for_test(
    outcome: Outcome,
    raised: &Rc<RefCell<Vec<ConfirmationRequest>>>,
) -> TaskOutcome {
    classify(outcome, raised)
}

/// Map a session [`Outcome`] onto the wire outcome.
///
/// The `raised` list is what separates a refusal-by-policy from a refusal-for-
/// want-of-a-person. When it is non-empty the run halted on a value that needed
/// approval, and the outcome says so rather than claiming someone declined.
fn classify(
    outcome: Outcome,
    raised: &Rc<RefCell<Vec<ConfirmationRequest>>>,
) -> TaskOutcome {
    let raised = raised.borrow();
    match outcome {
        Outcome::Completed { reports } => TaskOutcome::Completed { reports },

        // The session reported a refusal *and* it raised at least one request.
        // That combination can only mean the `false` from `refuse_but_record` did
        // it, because the daemon has no other source of refusals.
        Outcome::Refused { op } if !raised.is_empty() => TaskOutcome::NeedsHuman {
            op: vec![op],
            rendered: raised
                .iter()
                .map(render_request)
                .collect::<Vec<_>>()
                .join("\n"),
        },

        // A refusal with nothing raised. Unreachable today, and reported rather
        // than folded into the arm above so that if it ever *does* happen the
        // caller sees a real refusal instead of a mislabelled one.
        Outcome::Refused { op } => TaskOutcome::Refused { op },

        Outcome::ConfirmationLimit { asked } => TaskOutcome::ConfirmationLimit { asked },

        Outcome::Failed { error } => TaskOutcome::Failed {
            message: error.to_string(),
            policy_denied: matches!(error, PlanError::PolicyDenied { .. }),
        },
    }
}

/// Role Q, lifted verbatim.
///
/// A **stub, labelled as one.** A real extractor runs the quarantined model under
/// a grammar inside the sandbox; this one does not. Stubbed this way on purpose:
/// returning the whole document maximises what an attacker could get forwarded, so
/// anything this daemon reports about leaks is an upper bound rather than a
/// flattering one. The plumbing it exercises -- document arrives tainted, crosses
/// the bridge, is bound by the schema -- is the part that is real.
struct VerbatimExtractor;

impl agentos_infer::Extractor for VerbatimExtractor {
    fn extract(
        &mut self,
        _schema: &serde_json::Value,
        document: &Quarantined<String>,
    ) -> Result<Extraction, InferError> {
        let text = document.with_label_for_display(|t, _| t.clone());
        Ok(Extraction {
            data: Val::tainted(SourceId::new(), serde_json::json!({ "text": text })),
            quarantined_fields: vec!["text".into()],
        })
    }
}

/// Build the backend this daemon plans and extracts with.
pub fn build_backend(model: &str) -> Ollama {
    Ollama::new(RoleModels::Shared { model: model.to_string() })
}

/// Describe this daemon to a client.
///
/// `limitations` is not decoration. The most expensive kind of wrong in a daemon
/// is a caller believing it is confined when it is not, so the things this build
/// does not do are reported as plainly as the things it does.
///
/// `requires_auth` is passed in rather than inferred, because whether this
/// transport is authenticated is a property of how the daemon was *started*, not
/// of anything reachable from here — a caller reading `info` needs the fact, and
/// guessing it from the absence of a token would be the wrong default.
pub fn describe(
    model: &str,
    ceiling: &Ceiling,
    max_concurrent_tasks: usize,
    requires_auth: bool,
) -> Info {
    let mut limitations = vec![
        "this build cannot ask a person for approval; any task that policy halts \
         on a value requiring confirmation is refused"
            .to_string(),
        "Landlock/seccomp confinement is NOT BUILT IN THIS BUILD: tools run with \
         the authority of this process. Policy enforces taint rules; it does not \
         confine the process."
            .to_string(),
        "TLS transport is NOT BUILT IN THIS BUILD: http.fetch refuses every https \
         URL rather than downgrading to plaintext."
            .to_string(),
    ];
    if ceiling.mail_outbox.is_none() {
        limitations.push(
            "no mail outbox is configured, so send_email is unavailable".to_string(),
        );
    }
    if ceiling.write_roots.is_empty() {
        limitations.push("no write roots are configured, so fs.write is unavailable".to_string());
    }
    if ceiling.allowed_hosts.is_empty() {
        limitations.push("no hosts are configured, so http.fetch is unavailable".to_string());
    }

    Info {
        protocol: super::protocol::PROTOCOL_VERSION.to_string(),
        model: model.to_string(),
        write_roots: ceiling.write_roots.iter().map(|p| p.display().to_string()).collect(),
        allowed_hosts: ceiling.allowed_hosts.clone(),
        send_email_enabled: ceiling.mail_outbox.is_some(),
        max_concurrent_tasks,
        can_ask_human: false,
        requires_auth,
        limitations,
    }
}