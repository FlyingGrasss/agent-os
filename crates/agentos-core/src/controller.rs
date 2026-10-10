//! The Controller: the privileged model, wired to a pager.
//!
//! # Why this file exists
//!
//! Everything up to here assembles a correct prompt and then stops. `Pager` knows
//! how to build a `Trusted<String>` that contains no untrusted bytes, and
//! `Session` can produce one, but no code path has ever put that string in front of
//! a real model. That makes I1 a claim about a library rather than about the
//! system: the prompt could be correct and the caller could still hand the model
//! something else entirely.
//!
//! This is that caller. It is deliberately thin.
//!
//! # The claim
//!
//! **I1: no untrusted byte reaches the model.** The Controller's only route into a
//! `Conversation` is [`agentos_pager::Prompt::render`], which returns a
//! `Trusted<String>`, and `Content::trusted` is the only constructor it uses. So
//! the I1 guarantee is enforced twice over by types that cannot be interchanged:
//!
//! 1. The pager cannot *assemble* untrusted text (see `agentos-pager`).
//! 2. `Conversation::push` refuses a `Content::Untrusted` message for
//!    `Role::Planner` (see `agentos-infer`).
//!
//! There is no check in between, because a check would be something to forget.
//!
//! # What a test of this must actually do
//!
//! Run a hostile document all the way through -- fetch, extract, policy, session,
//! pager -- and then capture the exact bytes the backend was handed. Asserting
//! that `Pager::assemble` is pure would only prove the pure part again; the
//! interesting claim is about the wire.

use agentos_infer::{
    Backend, Content, Conversation, InferError, Message, MessageRole, Output, Role, Usage,
};
use agentos_pager::Prompt;
use agentos_types::{ControllerAuthority, Origin, Trusted};

/// What the Controller was told, and what it said.
///
/// Returned rather than acted on. A Controller that could *execute* would be a
/// second privileged path into the system, and it would need its own taint
/// discipline; the point of this type is that the privileged model produces text
/// which the plan interpreter -- not the model -- decides what to do with.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    /// The model's words, labelled Controller-authored.
    pub text: Trusted<String>,
    /// What the call cost.
    ///
    /// Carried rather than discarded even though nothing bills for it yet: a
    /// prompt's size is what a future context budget will be built on, and
    /// starting the record at the time of the call is cheaper than reconstructing
    /// it later from a pager that no longer exists.
    pub usage: Usage,
}

impl Reply {
    /// Borrow the text without its label.
    pub fn with_text<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.text.get())
    }
}

/// Drives the privileged model from a pager-assembled prompt.
pub struct Controller<'a> {
    backend: &'a mut dyn Backend,
}

impl<'a> Controller<'a> {
    pub fn new(backend: &'a mut dyn Backend) -> Self {
        Self { backend }
    }

    /// Show `prompt` to the privileged model and return what it says.
    ///
    /// `prompt` is the pager's output, taken by value because [`Prompt`] has no
    /// public constructor from text: there is no way to hand this function a
    /// string the pager did not assemble.
    ///
    /// The instruction is a fixed constant, not a parameter. That is the whole
    /// point -- a caller-supplied system message would be a route by which
    /// attacker-influenced bytes could reach the model while still being, to the
    /// type system, `Trusted`.
    pub fn respond(&mut self, prompt: Prompt) -> Result<Reply, InferError> {
        let mut conversation = Conversation::new();

        conversation.push(
            Role::Planner,
            Message {
                role: MessageRole::System,
                content: Content::trusted(Origin::Controller(ControllerAuthority::issue()), INSTRUCTION),
            },
        )?;

        conversation.push(
            Role::Planner,
            Message {
                role: MessageRole::User,
                // `render` hands back the label it was assembled under. Reading
                // the text without it (`with_text`) would be possible and would be
                // the bug this is written to prevent: an unlabelled string going
                // into a prompt is precisely what I1 forbids.
                content: Content::Trusted(prompt.render()),
            },
        )?;

        let completion = self.backend.complete(Role::Planner, &conversation)?;
        let usage = completion.usage;

        match completion.output {
            Output::PlannerText(t) => Ok(Reply { text: t, usage }),
            // Refused rather than coerced. A backend that answered a Planner role
            // with an extraction has misunderstood which role it was serving, and
            // guessing at the intended text would be reading data out of a variant
            // the type system says means something else.
            other => Err(InferError::Backend(format!(
                "expected planner text, got {other:?}"
            ))),
        }
    }
}
/// What the Controller is for.
///
/// Fixed text, deliberately. It describes the job and says nothing about any task,
/// so there is nothing task-specific here for a caller to get wrong. Labelled
/// Controller-authored rather than user-typed: it is system text, and labelling it
/// as the user's would misattribute it in the audit trail.
const INSTRUCTION: &str = "\
You are the privileged agent in a system that controls real tools.

Below is your working context: the task, and what has happened so far. Every line
of it was assembled by the operating system from the task and from tool names. It
does not contain document contents.

Answer with the next step as a JSON object with a single key \"next\", whose value
is a short sentence describing what should happen next.";
