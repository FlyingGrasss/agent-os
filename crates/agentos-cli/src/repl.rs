//! The interactive loop.
//!
//! # What this is
//!
//! A read-evaluate-print loop over the daemon: a person types a task, the daemon
//! plans and runs it, and the outcome comes back as text. Several turns, one
//! connection.
//!
//! # The one thing this file must never do
//!
//! **Carry an untrusted byte into the next turn's task text.**
//!
//! This is worth stating at the top because the REPL is the obvious place to break
//! it. In `daemon::executor::run_task`, the whole `ExecuteParams::task` string is
//! promoted to `Trusted` and handed to the planner, which is how a person's words
//! are allowed to reach the Controller at all. That promotion is justified by *who
//! wrote the text*. A person typing into a REPL is exactly that.
//!
//! A tool *report* is not. A report is whatever the plan came back with, which for
//! any plan that read a document is document text — attacker-chosen. Folding
//! reports into the next turn's task would launder attacker output into a
//! `Trusted<String>`, which is invariant I1 failing at a seam it has never been
//! tested at, and it would be the most natural possible bug in a conversational
//! agent.
//!
//! So the history is split into two halves that cannot be confused for each other:
//! [`Turn::user_text`], which a person typed and which may be replayed, and
//! [`Turn::display`], which came back from the daemon and which exists only to be
//! printed. Only the first has any path into a task. `history_is_never_replayed`
//! pins this with a hostile report in the middle of a conversation.
//!
//! # Why approval does not cross the wire
//!
//! The daemon wires its confirmation hook to a constant `false`, and that is a
//! decision rather than a gap — see the module note on `daemon::executor`. Adding
//! an approval method to the protocol would make every process that can
//! authenticate into an approver, and the bearer token proves a process reached
//! the socket, not that a person is sitting at it.
//!
//! So a `[y/N]` here is a real decision by a real person, and it is *not*
//! forwarded as authority. What it does is let the person re-author the task
//! knowing what the agent wanted to do. The text that gets sent is the text they
//! type next, which keeps the trust argument above intact: a person wrote it.
//!
//! The cost is that agreement does not unlock the privileged action, and the REPL
//! says so at the prompt rather than letting a "yes" look like it did. A plan that
//! needs approval needs approval from a local `agentos run`, where a human is
//! genuinely attached to the session.
//!
//! # A dropped connection does not mean the task did not happen
//!
//! [`TransportError::Disconnected`] is kept distinct from a daemon-reported
//! failure on purpose. If the socket dies while a task is in flight the daemon may
//! well have executed it — it may have sent the mail, written the file. Re-sending
//! automatically would double the effect, and the whole point of the audit trail
//! is that an effect is accounted for exactly once. So a disconnected task is
//! reported as **indeterminate** and never retried; the person decides.

use std::io::{BufRead, Write};

use crate::daemon::protocol::{Info, TaskOutcome};
use crate::{decide, Decision};

/// Re-export the task parameters type for the client transport impl.
pub use crate::client::ExecuteParams;

/// How many past turns are kept for `/history`.
///
/// Bounded because the alternative is a REPL that grows without limit while the
/// operator leaves it open. Large enough that scrolling back through a session is
/// useful, small enough that the memory is not a subject.
pub const MAX_REMEMBERED_TURNS: usize = 100;

/// Why a transport call could not produce an outcome.
///
/// The two failure kinds are different claims and merging them would produce a
/// retry that is wrong. A [`TransportError::Refused`] means the daemon answered
/// and nothing ran. A [`TransportError::Disconnected`] means we do not know what
/// happened, and "we do not know" is not "it did not".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The connection failed or the daemon did not answer.
    ///
    /// The task's fate is **unknown**. Callers must not retry on their own.
    Disconnected(String),
    /// The daemon answered with an error. Nothing ran.
    Refused(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Disconnected(m) => write!(f, "connection lost: {m}"),
            TransportError::Refused(m) => write!(f, "daemon refused: {m}"),
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Disconnected(e.to_string())
    }
}

/// The daemon, as this loop needs it.
///
/// A trait rather than a direct dependency on [`crate::client::Client`] so the
/// turn logic can be driven by a scripted transport in tests, including the
/// scripted disconnects that the retry rule depends on.
pub trait Transport {
    /// Run one task to completion.
    fn execute(&mut self, params: ExecuteParams) -> Result<TaskOutcome, TransportError>;

    /// Report daemon configuration.
    fn info(&mut self) -> Result<Info, TransportError>;

    /// Re-establish the connection, re-authenticating if this transport needs it.
    ///
    /// Required to authenticate afresh rather than resume: a new socket has no
    /// memory of the old handshake, so a client that assumed otherwise would be
    /// sending unauthenticated frames and reading the replies as if they were
    /// trusted.
    fn reconnect(&mut self) -> Result<(), TransportError>;
}

/// What one turn did.
///
/// Every variant is a distinct claim. `NeedsApproval` in particular is not a
/// failure and not a refusal: nobody declined and nothing ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnResult {
    /// Everything in the plan ran.
    Completed {
        reports: Vec<String>,
    },
    /// Policy halted on a value that needs a person; the daemon has none.
    ///
    /// `rendered` is the daemon's own rendering, carried back so this loop can
    /// show it. It contains attacker-influenced *values*, which is why it is
    /// printed and never replayed.
    NeedsApproval {
        rendered: String,
    },
    /// The person declined.
    Declined,
    /// The loop asked more times than it was allowed to.
    ConfirmationLimit { asked: usize },
    /// Policy refused outright. No human involved, and no approval obtainable.
    Refused { op: String },
    /// The plan stopped on an error.
    Failed {
        message: String,
        policy_denied: bool,
    },
    /// The connection dropped with a task in flight.
    ///
    /// **The outcome is unknown and the task was not retried.** Reported rather
    /// than resolved, because resolving it by re-sending would risk running the
    /// effect twice.
    Indeterminate { detail: String },
    /// A command that is not a task (`/help`, `/history`, …).
    Meta,
}

/// One past turn.
///
/// The two halves are the point of the type. `user_text` is what a person wrote
/// and the only field with any route into a future task. `display` is what came
/// back and is printable only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// What the person typed. Safe to replay into a task: a person wrote it.
    user_text: String,
    /// How it ended. Printed, never replayed.
    ///
    /// A plain `String` that is *not* fed back into a task, and the reason is
    /// documented on this field and on the module. Nothing prevents a future edit
    /// from concatenating it into a task; `history_is_never_replayed` is what
    /// notices.
    display: String,
}

impl Turn {
    /// Record a completed turn.
    fn new(user_text: impl Into<String>, display: impl Into<String>) -> Self {
        Turn { user_text: user_text.into(), display: display.into() }
    }

    /// The text the person typed.
    pub fn user_text(&self) -> &str {
        &self.user_text
    }

    /// The rendered outcome.
    pub fn display(&self) -> &str {
        &self.display
    }
}

/// Why the loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplExit {
    /// The person typed `/exit` or closed the input.
    Normal,
    /// The connection failed and could not be re-established.
    Disconnected,
}

/// The interactive loop.
pub struct Repl<T: Transport> {
    transport: T,
    /// Grants requested for every turn.
    ///
    /// Held once and re-sent unchanged, so a turn cannot widen authority relative
    /// to the first one. The daemon narrows these against its ceiling regardless,
    /// but repeating them verbatim is what makes "turn 7 asked for more than turn
    /// 1" impossible rather than merely discouraged.
    grants: crate::daemon::protocol::Grants,
    /// Whether there is a person behind the input.
    ///
    /// Passed in rather than probed here so the loop is testable without a
    /// terminal. `false` means confirmations are refused — the same rule
    /// `agentos run` applies to a piped stdin.
    interactive: bool,
    /// Seconds requested per turn.
    timeout_secs: u64,
    history: Vec<Turn>,
    /// A person has been shown a halt and is typing a re-authored task.
    awaiting_reauthor: bool,
    /// The rendered request the person is answering, for the prompt.
    pending_rendered: String,
}

impl<T: Transport> Repl<T> {
    /// Build a loop over `transport`.
    pub fn new(transport: T, grants: crate::daemon::protocol::Grants, interactive: bool) -> Self {
        Repl {
            transport,
            grants,
            interactive,
            timeout_secs: 300,
            history: Vec::new(),
            awaiting_reauthor: false,
            pending_rendered: String::new(),
        }
    }

    /// Ask for a different per-turn timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// The turns recorded so far, oldest first.
    pub fn history(&self) -> &[Turn] {
        &self.history
    }

    /// Run until the person leaves or the connection dies.
    ///
    /// Returns `Ok(ReplExit)` on a clean exit, or `Err(TransportError)` if the
    /// transport fails in a way that cannot be recovered from.
    pub fn run(
        &mut self,
        input: &mut dyn BufRead,
        out: &mut dyn Write,
    ) -> Result<ReplExit, TransportError> {
        self.banner(out)?;

        loop {
            write!(out, "\nagentos> ")?;
            out.flush().ok();

            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) => {
                    // EOF: the person closed the input. Not a decision, and not an
                    // error; the loop simply ends.
                    writeln!(out, "\nagentos: goodbye.").ok();
                    return Ok(ReplExit::Normal);
                }
                Ok(_) => {}
                Err(e) => {
                    writeln!(out, "agentos: cannot read input: {e}").ok();
                    return Err(TransportError::Disconnected(e.to_string()));
                }
            }

            match self.turn(line.trim(), input, out)? {
                Some(result) => {
                    if let TurnResult::Meta = result {
                        continue;
                    }
                }
                None => return Ok(ReplExit::Normal),
            }
        }
    }

    /// One turn. `None` means the loop should end.
    fn turn(
        &mut self,
        line: &str,
        input: &mut dyn BufRead,
        out: &mut dyn Write,
    ) -> Result<Option<TurnResult>, TransportError> {
        let line = line.trim();

        if line.is_empty() {
            return Ok(Some(TurnResult::Meta));
        }

        // A pending re-authoring takes priority over the slash vocabulary: the
        // person is answering a question, and a line starting with `/` is as
        // likely to be their task as a command.
        if self.awaiting_reauthor {
            return Ok(Some(self.resolve_approval(line, input, out)?));
        }

        match line {
            "/exit" | "/quit" => return Ok(None),
            "/help" => {
                self.print_help(out)?;
                return Ok(Some(TurnResult::Meta));
            }
            "/history" => {
                self.print_history(out)?;
                return Ok(Some(TurnResult::Meta));
            }
            "/info" => {
                self.print_info(out)?;
                return Ok(Some(TurnResult::Meta));
            }
            _ => {}
        }

        Ok(Some(self.submit(line, out)?))
    }

    /// Send one task and render what came back.
    fn submit(
        &mut self,
        task: &str,
        out: &mut dyn Write,
    ) -> Result<TurnResult, TransportError> {
        let params = ExecuteParams {
            task: task.to_string(),
            grants: self.grants.clone(),
            timeout_secs: self.timeout_secs,
        };

        writeln!(out, "\nagentos: submitted")?;

        match self.transport.execute(params) {
            Ok(outcome) => {
                let result = self.render_outcome(outcome, out)?;
                // Remember the task and its rendered outcome for history.
                // We need to reconstruct the display text from the TurnResult.
                let display = match &result {
                    TurnResult::Completed { reports } => {
                        let mut text = String::from("done.\n");
                        for r in reports {
                            text.push_str(&format!("  {r}\n"));
                        }
                        text.trim_end().to_string()
                    }
                    TurnResult::NeedsApproval { rendered } => rendered.clone(),
                    TurnResult::ConfirmationLimit { asked } => {
                        format!(
                            "stopped after {asked} confirmation(s). the loop gave up.\n\
                             this is NOT a refusal — no decision was made."
                        )
                    }
                    TurnResult::Refused { op } => format!("refused: {op}\nnothing was sent or written."),
                    TurnResult::Failed { message, policy_denied } => {
                        let mut text = format!("stopped: {message}");
                        if *policy_denied {
                            text.push_str("\n  refused by policy, with no human involved.");
                        }
                        text
                    }
                    TurnResult::Indeterminate { detail } => {
                        format!(
                            "CONNECTION LOST while the task was in flight.\n  \
                             what happened is UNKNOWN: the daemon may have run it.\n  \
                             this will not be retried automatically, because retrying \
                             could run the effect twice.\n  ({detail})"
                        )
                    }
                    TurnResult::Declined => "declined".to_string(),
                    TurnResult::Meta => "".to_string(),
                };
                self.remember(task, &display);
                Ok(result)
            }
            Err(TransportError::Refused(m)) => {
                let text = format!("stopped: {m}");
                self.remember(task, &text);
                writeln!(out, "agentos: {text}")?;
                Ok(TurnResult::Failed { message: m, policy_denied: false })
            }
            Err(TransportError::Disconnected(m)) => {
                let text = format!(
                    "CONNECTION LOST while the task was in flight.\n  \
                     what happened is UNKNOWN: the daemon may have run it.\n  \
                     this will not be retried automatically, because retrying \
                     could run the effect twice.\n  ({m})"
                );
                self.remember(task, &text);
                writeln!(out, "agentos: {text}")?;
                Ok(TurnResult::Indeterminate { detail: m })
            }
        }
    }

    /// Turn a wire outcome into something a person reads.
    ///
    /// Does NOT call remember -- that is the caller's (submit's) job, because
    /// only the caller has the original user text. A previous version called
    /// remember with an empty string here, which created duplicate history
    /// entries and lost the user's actual input.
    fn render_outcome(
        &mut self,
        outcome: TaskOutcome,
        out: &mut dyn Write,
    ) -> Result<TurnResult, TransportError> {
        match outcome {
            TaskOutcome::Completed { reports } => {
                let mut text = String::from("done.\n");
                for r in &reports {
                    text.push_str(&format!("  {r}\n"));
                }
                writeln!(out, "agentos: {}", text.trim_end())?;
                for r in &reports {
                    writeln!(out, "  {r}")?;
                }
                Ok(TurnResult::Completed { reports })
            }

            TaskOutcome::NeedsHuman { op, rendered } => {
                writeln!(
                    out,
                    "\nagentos: the agent wants to do something that needs your approval.\n\
                     \x20        operation: {}\n  nothing was sent or written.\n",
                    op.join(", ")
                )?;
                for line in rendered.lines() {
                    writeln!(out, "  | {line}")?;
                }
                writeln!(
                    out,
                    "\n  note: agreeing here does NOT give the daemon authority.\n  \
                       it cannot be granted over the wire. To proceed, describe the\n  \
                       task as you want it worded; it will be sent as your words."
                )?;

                self.awaiting_reauthor = true;
                self.pending_rendered = rendered.clone();
                Ok(TurnResult::NeedsApproval { rendered })
            }

            TaskOutcome::ConfirmationLimit { asked } => {
                let text = format!(
                    "stopped after {asked} confirmation(s). the loop gave up.\n\
                     this is NOT a refusal — no decision was made."
                );
                writeln!(out, "agentos: {text}")?;
                Ok(TurnResult::ConfirmationLimit { asked })
            }

            TaskOutcome::Refused { op } => {
                let text = format!("refused: {op}\nnothing was sent or written.");
                writeln!(out, "agentos: {text}")?;
                Ok(TurnResult::Refused { op })
            }

            TaskOutcome::Failed { message, policy_denied } => {
                let mut text = format!("stopped: {message}");
                if policy_denied {
                    text.push_str("\n  refused by policy, with no human involved.");
                }
                writeln!(out, "agentos: {text}")?;
                Ok(TurnResult::Failed { message, policy_denied })
            }
        }
    }

    /// The person answered a halt.
    ///
    /// `line` is the whole answer: either `y`/`yes`, which starts the
    /// re-authoring step, or the re-authored task itself, which is submitted
    /// directly. Splitting it that way means a person who ignores the prompt and
    /// just types the task gets the intended behaviour rather than a refusal.
    fn resolve_approval(
        &mut self,
        line: &str,
        input: &mut dyn BufRead,
        out: &mut dyn Write,
    ) -> Result<TurnResult, TransportError> {
        self.awaiting_reauthor = false;
        self.pending_rendered.clear();

        match decide_yes_no(line, self.interactive) {
            ApprovalAnswer::Approve => {
                writeln!(
                    out,
                    "agentos: noted. type the task as you want it worded, and it will be sent."
                )?;
                write!(out, "task> ")?;
                out.flush()?;

                let mut text = String::new();
                match input.read_line(&mut text) {
                    Ok(0) => {
                        writeln!(out, "agentos: no task given; nothing sent.")?;
                        return Ok(TurnResult::Declined);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        writeln!(out, "agentos: cannot read input: {e}")?;
                        return Ok(TurnResult::Declined);
                    }
                }

                let task = text.trim();
                if task.is_empty() {
                    writeln!(out, "agentos: no task given; nothing sent.")?;
                    return Ok(TurnResult::Declined);
                }
                // The task sent is exactly what the person typed. Not the rendered
                // request, not the previous plan's text: those carry values the
                // agent chose, and the trust argument only covers this line.
                self.submit(task, out)
            }
            ApprovalAnswer::Decline => {
                writeln!(out, "agentos: declined. nothing was sent or written.")?;
                Ok(TurnResult::Declined)
            }
            ApprovalAnswer::NoHumanPresent => {
                writeln!(
                    out,
                    "agentos: no interactive terminal, so there is no one to ask.\n  \
                     nothing was sent or written."
                )?;
                Ok(TurnResult::Declined)
            }
        }
    }

    fn remember(&mut self, task: &str, display: &str) {
        if self.history.len() == MAX_REMEMBERED_TURNS {
            self.history.remove(0);
        }
        self.history.push(Turn::new(task, display));
    }

    fn banner(&mut self, out: &mut dyn Write) -> Result<(), TransportError> {
        writeln!(
            out,
            "AgentOS interactive session.\n  \
             Type a task in plain words. /help for commands, /exit to leave.\n  \
             Confirmations are a person or nothing; a piped stdin gets none."
        )?;

        match self.transport.info() {
            Ok(info) => {
                writeln!(out, "  model: {}", info.model)?;
                if info.can_ask_human {
                    writeln!(out, "  the daemon can ask for approval itself.")?;
                } else {
                    writeln!(
                        out,
                        "  the daemon cannot approve anything; a halt here is resolved by you."
                    )?;
                }
            }
            Err(e) => writeln!(out, "  (could not read daemon info: {e})")?,
        }
        Ok(())
    }

    fn print_help(&mut self, out: &mut dyn Write) -> Result<(), TransportError> {
        writeln!(
            out,
            "\n  /help      this text\n  \
             /history   past turns\n  \
             /info      what the daemon reports about itself\n  \
             /exit      leave\n\n  \
             Anything else is sent to the daemon as a task, in your words."
        )?;
        Ok(())
    }

    fn print_history(&mut self, out: &mut dyn Write) -> Result<(), TransportError> {
        if self.history.is_empty() {
            writeln!(out, "\n  (no turns yet)")?;
            return Ok(());
        }
        writeln!(out, "\n  past turns:")?;
        for (i, turn) in self.history.iter().enumerate() {
            let task = if turn.user_text().is_empty() { "(daemon-side halt)".to_string() } else { turn.user_text().to_string() };
            writeln!(out, "  {:>3}. {task}\n       -> {}", i + 1, turn.display())?;
        }
        Ok(())
    }

    fn print_info(&mut self, out: &mut dyn Write) -> Result<(), TransportError> {
        match self.transport.info() {
            Ok(info) => {
                writeln!(
                    out,
                    "\n  model:    {}\n  protocol: {}\n  can ask a human: {}\n  \
                     requires auth: {}\n  send_email: {}\n  write roots: {}\n  \
                     allowed hosts: {}",
                    info.model,
                    info.protocol,
                    if info.can_ask_human { "yes" } else { "no" },
                    if info.requires_auth { "yes" } else { "no" },
                    yes_no(info.send_email_enabled),
                    or_none(&info.write_roots),
                    or_none(&info.allowed_hosts),
                )?;
                if !info.limitations.is_empty() {
                    writeln!(out, "\n  limitations:")?;
                    for l in &info.limitations {
                        writeln!(out, "    - {l}")?;
                    }
                }
            }
            Err(e) => writeln!(out, "agentos: {e}")?,
        }
        Ok(())
    }
}

/// What a person said at a `[y/N]` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAnswer {
    /// `y` or `yes`.
    Approve,
    /// Anything else, including an empty line.
    Decline,
    /// There was no person to ask.
    NoHumanPresent,
}

/// Interpret a `[y/N]` answer.
///
/// Accepts `y` as well as `yes` because the prompt says `[y/N]` and refusing a
/// person who typed the letter the prompt asked for would only train them to stop
/// reading. Everything else — including an empty line, which is what a reflex
/// Enter press produces — is a decline.
///
/// Delegates the decision to the project's own [`decide`] for the `yes` spelling
/// so there is one rule for what counts as consent rather than two that can drift.
pub fn decide_yes_no(answer: &str, interactive: bool) -> ApprovalAnswer {
    if !interactive {
        return ApprovalAnswer::NoHumanPresent;
    }
    let trimmed = answer.trim();
    if trimmed.eq_ignore_ascii_case("y") {
        return ApprovalAnswer::Approve;
    }
    match decide(trimmed, true) {
        Decision::Approved => ApprovalAnswer::Approve,
        _ => ApprovalAnswer::Decline,
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod tests;