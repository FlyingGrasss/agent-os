//! Running a task for a person.
//!
//! # Why this crate is small
//!
//! It exists because everything else in the workspace is a library with no way to
//! be *used*. A security system nobody can run is a claim, not a control. But it
//! is deliberately thin: it holds no policy, no taint rules, and no authority. It
//! assembles what the other crates built and gets out of the way.
//!
//! # The one thing this crate decides
//!
//! Whether a human said yes.
//!
//! That sounds trivial and it is the whole risk. Everything above it is enforced
//! by types; everything below it is enforced by process isolation. This is the one
//! place where the system's security rests on a person, and the project's stated
//! position is that *most* of the defence should not. So the default here is
//! refuse, and it is refuse in the specific way that matters:
//!
//! **A non-interactive stdin is not approval.** If this process is run from a
//! script, a cron job, a CI runner, or a pipe, there is no person to ask, and the
//! answer is no. Not "yes, because nothing objected" -- that is precisely how a
//! human-in-the-loop degrades into a rubber stamp while still being logged as
//! deliberate. See [`Decision`].
//!
//! # Why the answer must be typed
//!
//! Approval requires the exact word `yes`. Enter alone declines. A confirmation
//! that a stray newline satisfies is not a confirmation, and requiring a word
//! costs a user nothing while removing the most common accident.

use std::io::{BufRead, IsTerminal, Write};

use agentos_policy::ConfirmationRequest;

/// What the person said, or did not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Typed `yes`.
    Yes,
    /// Anything else, including an empty line.
    No,
}

/// What to do about a confirmation.
///
/// The `non_interactive` case is separate from `Answer` on purpose. It is not
/// "the user said no"; it is "there was no user", which is a different fact with
/// a different meaning in an audit log. Folding them together would make a
/// scripted run indistinguishable from a person declining -- and one of those
/// deserves a record of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A person typed `yes`.
    Approved,
    /// A person typed something else.
    Declined,
    /// Nobody was there to ask.
    ///
    /// Treated as a refusal everywhere, and reported distinctly so a reader can
    /// tell a guarded system from a merely unhelpful one.
    NoHumanPresent,
}

/// Interpret an answer.
///
/// Strict on purpose. `yes` only, case-insensitively and ignoring surrounding
/// whitespace, because a person typing `YES` has meant yes and refusing them would
/// only train them to stop reading. Everything else is a no, *including* an empty
/// line -- which is the most common way an approval gets given by accident.
pub fn decide(answer: &str, interactive: bool) -> Decision {
    if !interactive {
        return Decision::NoHumanPresent;
    }
    if answer.trim().eq_ignore_ascii_case("yes") {
        Decision::Approved
    } else {
        Decision::Declined
    }
}

/// Whether a stream has a person behind it.
///
/// `std::io::stdin().is_terminal()` is the honest test. A piped stdin is not a
/// person, and treating it as one is the bug this exists to prevent.
pub fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Render a confirmation for a person to read.
///
/// The values here are **attacker-controlled text heading for a terminal**. The
/// policy layer has already stripped control characters -- see
/// `agentos_policy::argview` -- and this function adds two things on top:
///
/// - It labels the provenance of every value, so a person is never asked to
///   approve something whose origin is not stated. A user shown an address with
///   no indication that a web page chose it is being asked a question they cannot
///   answer.
/// - It shows *why* the system stopped, so the person is deciding rather than
///   being processed.
///
/// Nothing here is escaped or passed to a shell. There is no shell in this
/// program, and adding one for output formatting would hand an attacker the
/// ability to run code on the machine running the agent.
pub fn render_request(request: &ConfirmationRequest) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str("  The agent wants to do something that needs your approval.\n");
    out.push_str(&format!("\n    tool: {}\n", request.tool));

    for item in &request.items {
        out.push_str(&format!("\n    {}\n", item.arg));
        // Indented and on its own line so a long or multi-line value cannot run
        // past the edge of the terminal and hide its own end.
        out.push_str(&format!("      {}\n", item.value));
        if item.provenance.is_empty() {
            // Should not happen -- the engine promises a non-empty list for a
            // tainted value -- but an empty one would leave the user guessing, and
            // guessing is exactly what this prompt exists to prevent.
            out.push_str("      (origin not classified)\n");
        } else {
            out.push_str(&format!("      came from: {}\n", item.provenance.join(", ")));
        }
    }

    out.push_str("\n  Type 'yes' to allow, anything else to refuse.\n  > ");
    out
}

/// Ask a person, and return what they decided.
///
/// Reads exactly one line. A read error is a refusal: if the answer could not be
/// obtained, no approval happened, and treating an unreadable stdin as consent
/// would be the most dangerous line in the program.
pub fn ask_on_stdin(request: &ConfirmationRequest) -> Decision {
    let interactive = stdin_is_interactive();
    if !interactive {
        return Decision::NoHumanPresent;
    }

    print!("{}", render_request(request));
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => {
            // EOF: the person closed the input. Not consent.
            Decision::Declined
        }
        Ok(_) => decide(&line, true),
        Err(_) => Decision::Declined,
    }
}

/// Ask without touching stdin, for callers supplying their own line.
///
/// Exists so the decision logic is testable without a terminal, and so a future
/// TUI can share one implementation of what counts as consent.
pub fn ask_with(request: &ConfirmationRequest, answer: &str, interactive: bool) -> Decision {
    let _ = request;
    decide(answer, interactive)
}

/// The long-running privileged daemon.
///
/// A library module rather than a binary so that its framing, its grant narrowing,
/// and its refusal behaviour can be tested without binding a port or starting a
/// process. The binary is a three-line shim over [`daemon::main`].
pub mod daemon;

/// Client for connecting to the daemon.
pub mod client;

/// Interactive REPL over the daemon.
pub mod repl;

/// Shared utilities for the CLI.
pub mod util;


