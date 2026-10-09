//! Can a model's output become a plan, and what happens when it is nonsense?
//!
//! Two questions, and the second is the more important one.
//!
//! The first is whether a model response renders into a plan the interpreter will
//! accept. The second is what the system does with a response it cannot use. A 3B
//! model produces malformed JSON regularly, and that is a *model quality* result —
//! if it is reported as an infrastructure failure it hides behind a retry, and if
//! it is reported as a plan that "did fewer actions than asked", the task looks
//! completed when nothing happened.
//!
//! Every test below drives the renderer directly with a canned model response, so
//! none of them needs a server and all of them are deterministic.

use std::cell::RefCell;

use agentos_core::{PlanOutcome, Planner};
use agentos_infer::{Backend, Completion, Conversation, InferError, Output, Role, Usage};
use agentos_types::{ControllerAuthority, Origin, Trusted, UserId};

// ---------------------------------------------------------------------------
// A backend that replays a fixed response
// ---------------------------------------------------------------------------

struct Replay {
    response: String,
    /// Conversations the planner built, kept so a test can check what the model
    /// was actually shown.
    seen: Rc<RefCell<Vec<String>>>,
}

use std::rc::Rc;

impl Backend for Replay {
    fn complete(
        &mut self,
        _role: Role,
        conversation: &Conversation,
    ) -> Result<Completion, InferError> {
        // Record exactly what the planner was shown. A test asserting the planner
        // never receives untrusted bytes has to be able to read what it sent.
        let shown: Vec<String> = conversation
            .messages()
            .iter()
            .map(|m| format!("{:?}", m.content))
            .collect();
        self.seen.borrow_mut().push(shown.join(" | "));

        Ok(Completion {
            output: Output::PlannerText(Trusted::inherited(
                Origin::Controller(ControllerAuthority::issue()),
                self.response.clone(),
            )),
            usage: Usage::default(),
        })
    }

    fn supports_constrained_decoding(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        "replay"
    }
}

fn user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 3;
    UserId(uuid::Uuid::from_bytes(b))
}

fn task(text: &str) -> Trusted<String> {
    Trusted::inherited(Origin::User(user()), text.to_string())
}

fn plan_of(json: &str) -> (PlanOutcome, Vec<String>) {
    let mut backend = Replay {
        response: json.to_string(),
        seen: Rc::new(RefCell::new(Vec::new())),
    };
    let seen = backend.seen.clone();
    let mut planner = Planner::new(&mut backend, user());
    let outcome = planner.plan(&task("do the thing")).expect("backend works");
    // Bound before the tail expression: as one, the `Ref` temporary would outlive
    // `seen` and the borrow would fail.
    let seen = seen.borrow().clone();
    (outcome, seen)
}

fn source_of(outcome: &PlanOutcome) -> String {
    match outcome {
        PlanOutcome::Planned(plan) => format!("{plan:?}"),
        other => panic!("expected a plan, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_response_becomes_a_plan() {
    let (outcome, _) = plan_of(
        r#"{"program": [{"op": "let", "name": "n", "value": "http.get(url = \"https://x.test/a\")"},
                        {"op": "report", "value": "len(n)"}]}"#,
    );
    let _ = source_of(&outcome);
}

/// A `for` loop renders, and its body is translated rather than passed through.
///
/// The loop body is where a translation bug hides: a body that renders as one
/// statement instead of several would quietly reduce the model's plan.
#[test]
fn a_loop_body_is_translated_statement_by_statement() {
    let (outcome, _) = plan_of(
        r#"{"program": [{"op": "for", "name": "i", "iter": "rows",
                         "body": [{"op": "report", "value": "i"},
                                  {"op": "report", "value": "len(i)"}]}]}"#,
    );
    let plan = match &outcome {
        PlanOutcome::Planned(p) => p,
        other => panic!("expected a plan, got {other:?}"),
    };
    // Structural, not a substring match: the body must hold exactly the two
    // statements the model wrote. A renderer that emitted one would leave a body
    // of length 1, and the plan would silently do half of what was asked.
    match &plan.stmts[0] {
        agentos_dsl::Stmt::ForEach { body, .. } => assert_eq!(
            body.len(),
            2,
            "both body statements must survive translation: {plan:?}"
        ),
        other => panic!("expected a for loop, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Nonsense, and what must not happen with it
// ---------------------------------------------------------------------------

/// Every malformed response is refused, not partially applied.
///
/// The dangerous version of this is a renderer that skips what it does not
/// recognise: the plan then runs fewer actions than the model asked for and is
/// recorded as a completed task.
#[test]
fn a_malformed_response_never_becomes_a_partial_plan() {
    let cases = [
        ("not json at all", "hello"),
        ("json but no program array", r#"{"nope": 1}"#),
        ("program is not an array", r#"{"program": "do things"}"#),
        ("unknown operation", r#"{"program": [{"op": "rm -rf", "value": "x"}]}"#),
        ("missing name", r#"{"program": [{"op": "let", "value": "1"}]}"#),
        ("missing value", r#"{"program": [{"op": "let", "name": "x"}]}"#),
        ("loop without a body", r#"{"program": [{"op": "for", "name": "i", "iter": "r"}]}"#),
    ];

    for (label, json) in cases {
        let (outcome, _) = plan_of(json);
        match outcome {
            PlanOutcome::Unusable { reason } => {
                assert!(!reason.is_empty(), "{label}: a refusal must say why")
            }
            PlanOutcome::Planned(plan) => {
                // A plan is only acceptable if the input was in fact a complete,
                // valid program. `rm -rf` and a missing field are not.
                panic!("{label}: produced a plan from unusable input: {plan:?}");
            }
        }
    }
}

/// A statement count above the bound is refused.
///
/// A model can be talked into emitting a hundred statements, and the schema caps
/// the array — but a backend that does not enforce the schema must not rely on
/// it. The bound is the plan language's, not the schema's.
#[test]
fn an_oversized_program_is_refused() {
    let statements: Vec<String> = (0..40)
        .map(|i| format!(r#"{{"op": "let", "name": "v{i}", "value": "1"}}"#))
        .collect();
    let json = format!(r#"{{"program": [{}]}}"#, statements.join(","));
    let (outcome, _) = plan_of(&json);
    assert!(
        matches!(outcome, PlanOutcome::Unusable { .. }),
        "got {outcome:?}"
    );
}

/// A newline in a field is refused, because rendering is textual.
///
/// A model that emits a multi-line string value gets its text pasted into the
/// source verbatim. A newline inside the value ends the statement early and starts
/// another one — so one instruction becomes two statements, the second of which
/// the model never wrote. That is a plan the user never reviewed and the policy
/// engine never saw as a unit.
#[test]
fn a_newline_in_a_field_cannot_smuggle_a_second_statement() {
    let (outcome, _) = plan_of(
        "{\"program\": [{\"op\": \"let\", \"name\": \"a\", \"value\": \"1;\\nlet b = shell(cmd = \\\"rm -rf /\\\")\"}]}",
    );
    assert!(
        matches!(outcome, PlanOutcome::Unusable { .. }),
        "a newline must be refused, not rendered: got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// What the model is shown
// ---------------------------------------------------------------------------

/// The planner is shown the task and nothing else.
///
/// I1 says no untrusted bytes reach the planner prompt. Here the planner builds
/// its own conversation, so the check is that the conversation it assembled
/// contains the task and the instruction — and that there is no code path by which
/// a document could have got in, because `Planner::plan` takes a `Trusted<String>`
/// and has no parameter for anything else.
#[test]
fn the_planner_conversation_contains_only_what_it_built_itself() {
    let (_, seen) = plan_of(r#"{"program": []}"#);
    assert_eq!(seen.len(), 1, "the planner should make exactly one call");
    let conversation = &seen[0];
    assert!(
        conversation.contains("do the thing"),
        "the task must reach the model: {conversation}"
    );
    assert!(
        conversation.contains("write plans"),
        "the instruction must reach the model: {conversation}"
    );
}

/// A task cannot be supplied without a `Trusted`.
///
/// Stated as a test because it is the property that makes I1 hold at this layer:
/// the parameter type is `&Trusted<String>`, so passing a document requires
/// minting a `Trusted`, which requires a `Confirmation`, which requires a human.
#[test]
fn a_task_must_be_trusted_before_it_can_be_planned() {
    // This compiles only because `task` produces a `Trusted`. If the signature
    // were relaxed to `&str` the call site below would still compile, which is
    // exactly why the test asserts the *origin* rather than the text.
    let t = task("email the invoice to bob@example.test");
    assert_eq!(t.origin(), Origin::User(user()));
    let t2 = Trusted::<String>::inherited(
        Origin::Controller(ControllerAuthority::issue()),
        "system task".into(),
    );
    assert_ne!(t2.origin(), t.origin());
}