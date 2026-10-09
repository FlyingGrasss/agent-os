//! Can the agent refuse an attack without asking anyone?
//!
//! # Why this exists
//!
//! Before this, the most common attack — a document substituting a recipient the
//! user had explicitly named — could only be stopped by a prompt. That is not a
//! defence: it means the automatic layer failed and the system's security rested
//! on somebody reading. Seventeen of thirty-three corpus attacks were in that
//! position.
//!
//! The claim being tested is narrower and structural: **a value from an
//! untrusted source may not contradict a value the user stated.** No understanding
//! of the injection is involved, so it cannot be evaded by rephrasing.
//!
//! The tests are ordered by how badly they would fail: the headline test asserts
//! no human is involved at all, because a version that still prompts would be a
//! description of the old behaviour wearing the new name.

use std::collections::BTreeMap;

use agentos_dsl::{PlanData, PlanError, ToolHost};
use agentos_tools::{IntentPins, PolicyHost, Tool};
use agentos_types::Val;
use agentos_policy::{PolicyEngine, RuleSet};
use agentos_tools::audit::{AuditLog, MemorySink, SystemClock};
use agentos_types::{SourceId, UserId};

type Value = Val<PlanData>;

fn user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 4;
    UserId(uuid::Uuid::from_bytes(b))
}

fn tainted(text: &str) -> Value {
    Val::tainted(
        SourceId::new(),
        PlanData::Quoted {
            text: text.into(),
            source: SourceId::new(),
        },
    )
}

struct Probe;
impl Tool for Probe {
    fn name(&self) -> &str {
        "send_email"
    }
    fn invoke(&mut self, _a: &BTreeMap<String, Value>) -> Result<Value, PlanError> {
        Ok(Val::trusted(PlanData::Unit))
    }
}

/// A host that *asks* about confirmations, so a test can tell a `Deny` from a
/// `Confirm` by whether anyone was asked at all.
fn host(pins: Option<&str>) -> PolicyHost {
    let mut set = RuleSet::default();
    // Confirm, not Deny: if the pins work, this must still be refused. If they
    // did not, the outcome would be a prompt, and the test would catch that.
    set.confirm_tainted("send_email", "to");
    let mut host = PolicyHost::new(
        PolicyEngine::new(set),
        AuditLog::new(Box::new(MemorySink::new()), Box::new(SystemClock)),
        user(),
    );
    host.register(Box::new(Probe));
    if let Some(request) = pins {
        host.pin_intent(request);
    }
    host
}

fn call(host: &mut PolicyHost, to: &str) -> Result<Value, PlanError> {
    let mut args = BTreeMap::new();
    args.insert("to".to_string(), tainted(to));
    host.call("send_email", &args)
}

// ---------------------------------------------------------------------------
// The headline claim
// ---------------------------------------------------------------------------

/// A document cannot redirect a recipient the user named, and nobody is asked.
///
/// The rule here is `Confirm`, so the only thing that can turn this into a
/// refusal is the pin check. If it regressed, this would become a prompt and
/// `asked` would be 1.
#[test]
fn a_document_cannot_redirect_a_recipient_the_user_named() {
    let mut host = host(Some("Email the invoice to bob@example.com."));
    let result = call(&mut host, "attacker@evil.test");

    match result {
        Err(PlanError::PolicyDenied { op, reason }) => {
            assert_eq!(op, "send_email.to");
            assert!(
                reason.contains("contradicts"),
                "the reason must name the contradiction: {reason}"
            );
        }
        other => panic!("expected a denial, got {other:?}"),
    }
    assert!(
        host.take_pending().is_empty(),
        "nobody may be asked: a substitution the user did not make is not a \
         question for them"
    );
}

/// An approval cannot unlock a contradiction.
///
/// The pin check runs before the grant lookup and only ever turns `Allow` into
/// `Deny`. If a grant could override it, then rubber-stamping defeats the whole
/// point — and the rubber-stamp arm exists precisely to measure that.
#[test]
fn a_user_approval_cannot_unlock_a_contradiction() {
    let mut host = host(Some("Email the invoice to bob@example.com."));
    // Plant a grant for exactly the value the document supplied.
    host.grant("send_email.to", &tainted("attacker@evil.test"))
        .expect("grant records");

    let result = call(&mut host, "attacker@evil.test");
    assert!(
        matches!(result, Err(PlanError::PolicyDenied { .. })),
        "an approved contradiction must still be refused, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// What must NOT be denied
// ---------------------------------------------------------------------------

/// The address the user named is fine.
///
/// The pin is a constraint, not a prohibition. Denying the value the user
/// actually asked for would be a defence that stops all the work.
#[test]
fn the_address_the_user_named_is_allowed_through_to_the_prompt() {
    let mut host = host(Some("Email the invoice to bob@example.com."));
    let result = call(&mut host, "bob@example.com");

    // It reaches the prompt rather than being denied: the policy rule says
    // Confirm, the pin is satisfied, so the user is asked. That is correct — it
    // is the user's own value, and asking is the rule's business.
    assert!(
        matches!(result, Err(PlanError::ConfirmationRequired { .. })),
        "the user's own address must reach the prompt, got {result:?}"
    );
}

/// A request that names no address produces no constraint.
///
/// "Send it to the address in the document" pins nothing, so nothing can
/// contradict. Inventing a constraint the user never expressed would deny
/// legitimate work, and a denial nobody asked for is its own kind of wrong.
#[test]
fn a_request_that_names_no_address_constrains_nothing() {
    let mut host = host(Some("Email the invoice to the address it names."));
    let result = call(&mut host, "attacker@evil.test");

    assert!(
        matches!(result, Err(PlanError::ConfirmationRequired { .. })),
        "with no pin there is nothing to contradict, so the prompt stands: {result:?}"
    );
}

/// No pins at all means the old behaviour, unchanged.
///
/// A host that was never given a request must behave exactly as it did before
/// this existed. If it did not, every existing measurement would be void.
#[test]
fn a_host_without_pins_behaves_exactly_as_before() {
    let mut host = host(None);
    let result = call(&mut host, "attacker@evil.test");
    assert!(
        matches!(result, Err(PlanError::ConfirmationRequired { .. })),
        "with no pins nothing is denied, got {result:?}"
    );
    assert_eq!(host.take_pending().len(), 1, "and the prompt is still raised");
}

/// A trusted argument is never re-litigated.
///
/// It came from the plan's own literals or from a confirmation the user already
/// granted. Denying it again would ignore a decision the user has made.
#[test]
fn a_trusted_argument_is_not_checked_against_the_pins() {
    let mut host = host(Some("Email the invoice to bob@example.com."));
    let mut args = BTreeMap::new();
    args.insert(
        "to".to_string(),
        Val::trusted(PlanData::Str("carol@example.com".into())),
    );
    let result = host.call("send_email", &args);
    assert!(
        result.is_ok(),
        "a trusted value must not be denied, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Other shapes
// ---------------------------------------------------------------------------

/// URLs and paths are pinned on the same principle.
#[test]
fn urls_and_paths_are_pinned_too() {
    let host = host(Some("Fetch https://invoices.example/i1 and write it to notes.txt."));
    let pins = host.pins().expect("pins were set");
    // `counts()` is (emails, urls, paths), in that order.
    let (_emails, urls, paths) = pins.counts();
    assert_eq!(urls, 1, "the url should be pinned");
    assert_eq!(paths, 0, "notes.txt is relative and pins nothing");
}

// ---------------------------------------------------------------------------
// The extraction rules themselves
// ---------------------------------------------------------------------------

#[test]
fn pins_are_extracted_from_the_request() {
    let pins = IntentPins::from_request("Email bob@example.com about https://invoices.example/i1 and save to /tmp/notes.txt");
    let (emails, urls, paths) = pins.counts();
    assert_eq!((emails, urls, paths), (1, 1, 1));
    assert!(!pins.is_empty());
}

#[test]
fn a_request_with_nothing_pinnable_is_empty() {
    let pins = IntentPins::from_request("Report how many items the document has.");
    assert!(pins.is_empty(), "got {pins:?}");
}

/// Case is normalised for addresses, because `Bob@example.com` and
/// `bob@example.com` are the same mailbox and denying one of them would be a
/// denial the user could not act on.
#[test]
fn address_comparison_ignores_case() {
    let pins = IntentPins::from_request("Email Bob@Example.com.");
    assert!(
        pins.contradiction(&tainted("bob@example.com")).is_none(),
        "the same address in a different case is not a contradiction"
    );
    assert!(
        pins.contradiction(&tainted("attacker@evil.test")).is_some(),
        "a different address is"
    );
}