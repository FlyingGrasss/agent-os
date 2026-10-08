//! What a single-use approval authorises, and what it must not.
//!
//! # Why these tests exist
//!
//! A plan halts when the policy engine says `Confirm`. When it resumes it
//! re-enters the host with the same tainted value, and without something marking
//! that value as already-decided the engine says `Confirm` again, so the plan
//! halts forever and the user is asked the same question on every attempt.
//!
//! `PolicyHost::grant` is that something, which makes it a way to *skip* a
//! security check. So most of these tests are about the ways it must not work:
//! not across a different value, not across a different argument, not across a
//! different tool, not across a different user, not twice, and not at all when
//! the policy says deny.
//!
//! That last one is the important one. A grant answers "did the user approve
//! this?" and a `Deny` is not a question anybody was asked. The first
//! implementation excluded granted arguments from the views *before* evaluating,
//! so a granted `shell.cmd` left nothing to classify and the engine returned
//! `Allow`. `a_grant_cannot_override_a_deny` caught it.

use std::collections::BTreeMap;

use agentos_dsl::{PlanData, PlanError, PlanValue, ToolHost};
use agentos_policy::PolicyEngine;
use agentos_tools::audit::{AuditLog, MemorySink, SystemClock};
use agentos_tools::{PolicyHost, Tool};
use agentos_types::{SourceId, SourceKind, UserId, Val};

type Seen = std::rc::Rc<std::cell::RefCell<Vec<BTreeMap<String, PlanValue>>>>;

/// The user these tests act for. Fixed bytes so nothing depends on randomness.
fn user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 1;
    UserId(uuid::Uuid::from_bytes(b))
}

fn other_user() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 9;
    UserId(uuid::Uuid::from_bytes(b))
}

struct Spy {
    name: String,
    calls: Seen,
}

impl Spy {
    fn new(name: &str) -> (Self, Seen) {
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        (
            Self {
                name: name.to_string(),
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl Tool for Spy {
    fn name(&self) -> &str {
        &self.name
    }

    fn invoke(&mut self, args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError> {
        self.calls.borrow_mut().push(args.clone());
        Ok(Val::trusted(PlanData::Bool(true)))
    }
}

fn tainted(text: &str) -> PlanValue {
    Val::tainted(
        SourceId::of_kind(SourceKind::Email),
        PlanData::Str(text.to_string()),
    )
}

/// The value out of a call's arguments, by name.
///
/// Used everywhere a grant is issued. The approval key binds the *label* as well
/// as the bytes, and `SourceId::of_kind` mints a fresh random id every call, so
/// building a second `tainted("same")` produces a different label and therefore a
/// different key.
///
/// That is the right behaviour rather than an annoyance: the approval is bound to
/// the provenance the user was actually shown, so a value re-derived with fresh
/// provenance does not inherit the old approval. The real resume path preserves
/// labels because `Literal::Quoted` carries its `SourceId` in the AST, so
/// re-evaluating the same expression yields the same label.
fn arg<'a>(args: &'a BTreeMap<String, PlanValue>, name: &str) -> &'a PlanValue {
    args.get(name).expect("argument present")
}

/// A call whose *only* tainted argument is the recipient.
///
/// Deliberately minimal. `send_email.to`, `.subject` and `.body` are all
/// `Confirm` positions, so a helper that tainted all three would mean granting
/// one still leaves two live questions, which is correct behaviour being
/// mistaken for a broken grant.
fn mail(recipient: &str) -> BTreeMap<String, PlanValue> {
    let mut args = BTreeMap::new();
    args.insert("to".to_string(), tainted(recipient));
    args
}

fn host_with(tool: Box<dyn Tool>, sink: &MemorySink) -> PolicyHost {
    host_for(user(), tool, sink)
}

fn host_for(who: UserId, tool: Box<dyn Tool>, sink: &MemorySink) -> PolicyHost {
    let mut host = PolicyHost::new(
        PolicyEngine::new(PolicyEngine::default_rules()),
        AuditLog::new(Box::new(sink.clone()), Box::new(SystemClock)),
        who,
    );
    host.register(tool);
    host
}

// ---------------------------------------------------------------------------
// The property that makes resuming possible
// ---------------------------------------------------------------------------

/// A granted argument stops being a question.
#[test]
fn a_granted_argument_no_longer_asks() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let args = mail("attacker@evil.test");
    let halted = host.call("send_email", &args);
    assert!(
        matches!(halted, Err(PlanError::ConfirmationRequired { .. })),
        "the first call must halt: {halted:?}"
    );

    host.grant("send_email.to", arg(&args, "to"))
        .expect("grant");

    let resumed = host.call("send_email", &args);
    assert!(
        resumed.is_ok(),
        "after approval the call must proceed: {resumed:?}"
    );
    assert_eq!(calls.borrow().len(), 1, "the tool ran exactly once");
}

/// The grant is single-use. A second identical call asks again.
///
/// This is what stops one approval becoming a standing capability. A plan that
/// legitimately sends twice must be approved twice.
#[test]
fn a_grant_is_spent_by_the_call_it_authorises() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let args = mail("a@b.test");
    host.grant("send_email.to", arg(&args, "to")).unwrap();

    assert!(host.call("send_email", &args).is_ok(), "first use");
    assert_eq!(calls.borrow().len(), 1);

    let second = host.call("send_email", &args);
    assert!(
        matches!(second, Err(PlanError::ConfirmationRequired { .. })),
        "the second identical call must halt again, got {second:?}"
    );
    assert_eq!(calls.borrow().len(), 1, "and must not have run");
}

/// Every tainted argument needs a grant, not just one.
///
/// A request naming two arguments with an approval for one is still a question,
/// because the user has not seen the other.
#[test]
fn a_grant_for_one_of_two_tainted_arguments_does_not_proceed() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let mut args = BTreeMap::new();
    args.insert("to".to_string(), tainted("a@b.test"));
    args.insert("body".to_string(), tainted("body"));

    host.grant("send_email.to", arg(&args, "to")).unwrap();
    let outcome = host.call("send_email", &args);

    assert!(
        matches!(outcome, Err(PlanError::ConfirmationRequired { .. })),
        "a partial approval must not carry the call, got {outcome:?}"
    );
    assert!(calls.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// The ways a grant must not transfer
// ---------------------------------------------------------------------------

/// A grant for one value does not authorise a different value.
#[test]
fn a_grant_does_not_transfer_to_another_value() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let approved = mail("approved@b.test");
    let _ = host.call("send_email", &approved);
    host.grant("send_email.to", arg(&approved, "to")).unwrap();

    let args = mail("someone-else@evil.test");
    let outcome = host.call("send_email", &args);
    assert!(
        matches!(outcome, Err(PlanError::ConfirmationRequired { .. })),
        "a grant for one recipient must not authorise another, got {outcome:?}"
    );
    assert!(calls.borrow().is_empty(), "nothing should have run");
}

/// A grant for one argument does not authorise a different argument.
///
/// The reason `scope` is part of the key. A user who approved a recipient has
/// not approved a body, even when the two carry byte-identical text.
#[test]
fn a_grant_does_not_transfer_to_another_argument() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    // `to` and `subject` both tainted, both holding the same bytes.
    let mut args = BTreeMap::new();
    args.insert("to".to_string(), tainted("same"));
    args.insert("subject".to_string(), tainted("same"));
    let _ = host.call("send_email", &args);

    host.grant("send_email.to", arg(&args, "to")).unwrap();

    let outcome = host.call("send_email", &args);
    assert!(
        matches!(outcome, Err(PlanError::ConfirmationRequired { .. })),
        "approving `to` must leave `subject` a question, got {outcome:?}"
    );
    assert!(calls.borrow().is_empty());
}

/// A grant for one tool does not authorise another tool's argument.
///
/// Two tools can share an argument name and byte-identical values, so the key
/// has to include the tool as well as the argument.
#[test]
fn a_grant_does_not_transfer_across_tools() {
    let sink = MemorySink::new();
    let (mail_spy, mail_calls) = Spy::new("send_email");
    let (shell_spy, shell_calls) = Spy::new("shell");
    let mut host = host_with(Box::new(mail_spy), &sink);
    host.register(Box::new(shell_spy));

    let approved = mail("same");
    host.grant("send_email.to", arg(&approved, "to")).unwrap();

    let mut args = BTreeMap::new();
    args.insert("cmd".to_string(), tainted("same"));
    let outcome = host.call("shell", &args);

    assert!(
        !outcome.is_ok(),
        "a grant issued for a mail recipient must not authorise a shell command: {outcome:?}"
    );
    assert!(shell_calls.borrow().is_empty());
    assert!(mail_calls.borrow().is_empty());
}

/// A grant is bound to the user who made it, not just to the value.
#[test]
fn a_grant_from_one_user_does_not_authorise_for_another() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_for(user(), Box::new(spy), &sink);

    let approved = mail("a@b.test");
    host.grant("send_email.to", arg(&approved, "to")).unwrap();

    let sink2 = MemorySink::new();
    let (spy2, _calls2) = Spy::new("send_email");
    let mut host2 = host_for(other_user(), Box::new(spy2), &sink2);

    let args = mail("a@b.test");
    let outcome = host2.call("send_email", &args);

    assert!(
        matches!(outcome, Err(PlanError::ConfirmationRequired { .. })),
        "another user must not inherit the approval, got {outcome:?}"
    );
    assert!(calls.borrow().is_empty());
}

/// A trusted argument needs no grant and is unaffected by one.
#[test]
fn a_trusted_argument_is_unaffected_by_grants() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let mut args = BTreeMap::new();
    args.insert(
        "to".to_string(),
        Val::trusted(PlanData::Str("me@b.test".into())),
    );
    assert!(
        host.call("send_email", &args).is_ok(),
        "a trusted recipient runs with no grant at all"
    );
    assert_eq!(calls.borrow().len(), 1);

    host.grant("send_email.to", &tainted("unrelated")).unwrap();
    assert!(host.call("send_email", &args).is_ok());
    assert_eq!(calls.borrow().len(), 2);
}

// ---------------------------------------------------------------------------
// The boundary: a grant is an answer, not an override
// ---------------------------------------------------------------------------

/// A grant cannot override a deny.
///
/// The load-bearing test in this file. `Deny` is not a question the user was
/// asked, so there is no approval to replay. If a grant could override it,
/// approving anything would authorise everything and I4 would be decorative.
#[test]
fn a_grant_cannot_override_a_deny() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("shell");
    let mut host = host_with(Box::new(spy), &sink);

    let mut args = BTreeMap::new();
    args.insert("cmd".to_string(), tainted("rm -rf /"));

    // The exact position and the exact bytes.
    host.grant("shell.cmd", arg(&args, "cmd")).unwrap();

    match host.call("shell", &args) {
        Err(PlanError::PolicyDenied { op, .. }) => assert_eq!(op, "shell.cmd"),
        other => panic!("a deny must survive a grant, got {other:?}"),
    }
    assert!(calls.borrow().is_empty(), "nothing may run");
}

/// A halted call does not spend the grant it did not use.
///
/// If a confirmation spent its grants, then a user who approved `to` would have
/// that approval silently eaten by a call that halted on `body`, and would be
/// asked about `to` again next time.
#[test]
fn a_halted_call_does_not_spend_the_grant() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    let mut args = BTreeMap::new();
    args.insert("to".to_string(), tainted("a@b.test"));
    args.insert("body".to_string(), tainted("body"));

    host.grant("send_email.to", arg(&args, "to")).unwrap();
    assert!(matches!(
        host.call("send_email", &args),
        Err(PlanError::ConfirmationRequired { .. })
    ));
    assert!(calls.borrow().is_empty());

    // Drop the ungranted argument, keeping the same `to` value. The approval key
    // binds the label, so a rebuilt value would carry a fresh `SourceId` and
    // correctly fail to match.
    let mut clean = BTreeMap::new();
    clean.insert("to".to_string(), arg(&args, "to").clone());
    assert!(host.call("send_email", &clean).is_ok());
    assert_eq!(calls.borrow().len(), 1);

    // And the grant really was spent by that call.
    assert!(
        matches!(
            host.call("send_email", &clean),
            Err(PlanError::ConfirmationRequired { .. })
        ),
        "the grant must not have survived the call it authorised"
    );
}

/// A grant for an unregistered position is inert.
///
/// Grants are keyed by scope, so one cannot be planted for a position that does
/// not exist and then used if that tool is later registered with different
/// semantics.
#[test]
fn a_grant_for_an_unknown_scope_is_inert() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("send_email");
    let mut host = host_with(Box::new(spy), &sink);

    host.grant("not.a.tool", &tainted("a@b.test")).unwrap();

    let outcome = host.call("send_email", &mail("a@b.test"));
    assert!(
        matches!(outcome, Err(PlanError::ConfirmationRequired { .. })),
        "a grant for an unrelated scope must not apply, got {outcome:?}"
    );
    assert!(calls.borrow().is_empty());
}

/// An allowlisted domain is not made reachable by a grant.
///
/// `http.get.url` is an allowlist rule, and an allowlist refusal is a `Deny` with
/// a message inviting the user to add the domain. A grant must not stand in for
/// that: adding a domain is an engine-level change, not a per-value approval.
#[test]
fn a_grant_does_not_bypass_an_allowlist() {
    let sink = MemorySink::new();
    let (spy, calls) = Spy::new("http.get");
    let mut host = host_with(Box::new(spy), &sink);

    let mut args = BTreeMap::new();
    args.insert("url".to_string(), tainted("https://evil.test/x"));
    host.grant("http.get.url", arg(&args, "url")).unwrap();

    match host.call("http.get", &args) {
        Err(PlanError::PolicyDenied { op, .. }) => assert_eq!(op, "http.get.url"),
        other => panic!("an unallowlisted domain must stay denied, got {other:?}"),
    }
    assert!(calls.borrow().is_empty());
}