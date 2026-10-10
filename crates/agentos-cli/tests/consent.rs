//! Is a human actually present, and did they actually say yes?
//!
//! # Why this file exists
//!
//! Everything else in AgentOS is enforced by types or by the kernel. This is the
//! one place where the system's security rests on a person, which makes it the
//! most likely place for a quiet, total failure.
//!
//! The failure mode is not "a user approves something they should not". It is
//! subtler and far worse: **a scripted run approves everything without a person
//! ever being asked**, and every approval is still recorded as deliberate. The
//! system looks like it has a human in the loop. It does not.
//!
//! So these tests are mostly about the boring cases -- empty input, piped input,
//! EOF -- because those are where the accident happens.
//!
//! # What is deliberately NOT tested here
//!
//! That a person reading a confirmation makes a good decision. That is not a
//! property of this code and cannot be asserted. What can be asserted is that the
//! person was *shown enough to decide*: the value, and where it came from.

use agentos_cli::{ask_with, decide, render_request, Answer, Decision};
use agentos_policy::ConfirmationItem;

fn request(items: Vec<(&str, &str, Vec<&str>)>) -> agentos_policy::ConfirmationRequest {
    agentos_policy::ConfirmationRequest {
        tool: "send_email".to_string(),
        items: items
            .into_iter()
            .map(|(arg, value, provenance)| ConfirmationItem {
                arg: arg.to_string(),
                value: value.to_string(),
                provenance: provenance.into_iter().map(str::to_string).collect(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// The word `yes` approves.
#[test]
fn yes_approves() {
    assert_eq!(decide("yes", true), Decision::Approved);
    assert_eq!(decide("YES", true), Decision::Approved);
    assert_eq!(decide("  yes  ", true), Decision::Approved);
    assert_eq!(decide("Yes", true), Decision::Approved);
}

/// Everything else declines.
///
/// Including the near-misses. `y` is declined because a confirmation that accepts
/// a keystroke is a confirmation a stray keypress satisfies; `yep` because a user
/// who types something we did not expect has not been told what we expect.
#[test]
fn anything_else_declines() {
    for answer in ["", " ", "\n", "n", "no", "y", "yep", "yess", "sure", "ok", "1", "true"] {
        assert_eq!(
            decide(answer, true),
            Decision::Declined,
            "{answer:?} must not approve"
        );
    }
}

/// A non-interactive stdin is not a person.
///
/// This is the load-bearing test in the file. Run from a script, a pipe, a cron
/// job, or CI, there is nobody to ask -- and the honest answer is no. Approving
/// here would produce a run that logged every approval as a deliberate human
/// decision while no human existed, which is worse than having no confirmation at
/// all because it would also be believed.
#[test]
fn a_piped_stdin_never_approves() {
    for answer in ["yes", "YES", "yes\n", "true", "y"] {
        assert_eq!(
            decide(answer, false),
            Decision::NoHumanPresent,
            "{answer:?} on a non-interactive stdin must not count as a person \
             saying yes"
        );
    }
}

/// `NoHumanPresent` is distinct from `Declined`.
///
/// Not cosmetic. "A person said no" and "nobody was asked" are different facts
/// and mean different things when reading an audit log: one is the system working,
/// the other is the system running unattended. Collapsing them would make a
/// guarded deployment and an unguarded one indistinguishable after the fact.
#[test]
fn nobody_present_is_not_the_same_as_somebody_saying_no() {
    assert_ne!(Decision::NoHumanPresent, Decision::Declined);
    assert_ne!(Decision::Approved, Decision::Declined);
    // And the two refusals must still both be refusals -- anything that treats
    // them differently downstream would be a hole.
    assert!(!matches!(decide("yes", false), Decision::Approved));
}

/// The `Answer` type is the vocabulary, and `decide` never invents a third state.
///
/// A three-way answer (yes / no / unclear) would be the more honest API, and it is
/// deliberately not used: "unclear" and "no" have to behave identically, and the
/// only way to guarantee that forever is to not have the state.
#[test]
fn the_answer_vocabulary_is_two_wide() {
    assert_ne!(Answer::Yes, Answer::No);
    assert!(matches!(decide("maybe", true), Decision::Declined));
}

// ---------------------------------------------------------------------------
// What the person is shown
// ---------------------------------------------------------------------------

/// The confirmation shows the value and where it came from.
///
/// A user asked to approve an address with no indication that a web page chose it
/// is being asked a question they cannot answer. Showing provenance is what makes
/// the prompt a decision rather than a formality.
#[test]
fn the_prompt_shows_the_value_and_its_origin() {
    let out = render_request(&request(vec![(
        "to",
        "attacker@evil.test",
        vec!["web page"],
    )]));
    assert!(
        out.contains("attacker@evil.test"),
        "the value must be visible or there is nothing to decide: {out}"
    );
    assert!(
        out.contains("web page"),
        "the origin must be stated or the value cannot be judged: {out}"
    );
    assert!(out.contains("send_email"), "the tool must be named: {out}");
}

/// An unclassified origin is said so, not left blank.
///
/// The engine promises a non-empty provenance list for a tainted value, so this
/// should be unreachable. It is asserted anyway: if it ever *does* happen, the
/// failure mode is a user staring at an empty field and assuming the value came
/// from nowhere.
#[test]
fn an_empty_provenance_is_stated_rather_than_shown_as_a_gap() {
    let out = render_request(&request(vec![("to", "someone@example.com", vec![])]));
    assert!(
        out.contains("origin not classified"),
        "an empty provenance must be stated explicitly: {out}"
    );
    assert!(
        !out.contains("came from: \n"),
        "a blank provenance line would read as 'came from nothing': {out}"
    );
}

/// The prompt tells the person exactly what will count as consent.
///
/// Otherwise the strictness is a trap: a user who presses Enter reasonably
/// expects it to mean "carry on", and discovers otherwise only after the mail was
/// not sent.
#[test]
fn the_prompt_states_what_counts_as_approval() {
    let out = render_request(&request(vec![("to", "bob@example.com", vec!["you"])]));
    assert!(
        out.contains("Type 'yes' to allow"),
        "the prompt must state the rule: {out}"
    );
}

// ---------------------------------------------------------------------------
// The whole path
// ---------------------------------------------------------------------------

/// `ask_with` reaches the same decision as `decide`.
///
/// It takes a request it does not use, which looks like a mistake and is not: it
/// keeps the signature a future TUI will need, where rendering and deciding are
/// separate concerns. Asserted so the two cannot drift apart silently.
#[test]
fn ask_with_agrees_with_decide() {
    let r = request(vec![("to", "bob@example.com", vec!["you"])]);
    assert_eq!(ask_with(&r, "yes", true), decide("yes", true));
    assert_eq!(ask_with(&r, "", true), decide("", true));
    assert_eq!(ask_with(&r, "yes", false), decide("yes", false));
}
