//! Turning a task into a plan.
//!
//! # Why this is a separate file
//!
//! Everything else in the Controller takes a plan as given. Nothing produced one.
//! The interpreter, the policy engine and the session all work on an AST that
//! arrived from somewhere, and "somewhere" was always a hand-written corpus entry
//! — which means the one component that decides what the tools are ever called
//! with had never been exercised.
//!
//! # The security property, and where it actually lives
//!
//! A plan is **trusted input**. The model that writes it is shown only trusted
//! text, and `Conversation::push` refuses a message the role may not see, so the
//! planner cannot have read an attacker's prose. That is what makes its output
//! [`Trusted`] rather than merely assumed to be.
//!
//! The consequence is the important part: **a plan may name a variable, but the
//! bytes behind it still come from somewhere and carry their own labels.** A plan
//! saying `send_email(to = inv.0.note)` does not make `inv.0.note` trusted. The
//! plan is trusted; the data flowing through it is not, and it is labelled at the
//! point it enters — in the fetch result, in the extraction — not here.
//!
//! So this file does not need to sanitise, filter or second-guess what the model
//! wrote. It has to be *faithful*, because the defences downstream are keyed on
//! the plan matching what the user approved. A planner that "helpfully" rewrote
//! an argument would break the digest check that makes a confirmation mean
//! something.
//!
//! # What is checked here
//!
//! The model's output is JSON, and JSON is not the plan language. The translation
//! is where a malformed model response becomes either a clean refusal or a plan
//! nobody intended. It fails closed: anything the renderer does not recognise
//! raises [`PlanError`] rather than being skipped, because silently dropping a
//! statement would produce a plan that runs fewer actions than the model asked
//! for — which reads as success.

use agentos_dsl::{parse, Plan, PlanError};
use agentos_infer::{
    Backend, Content, Conversation, InferError, Message, MessageRole, Output, Role,
};
use agentos_types::{ControllerAuthority, Origin, UserId};

/// The instruction the planner is given.
///
/// Fixed text, and fixed on purpose. The planner's prompt is assembled here
/// rather than by the caller so that a caller cannot widen it — in particular,
/// cannot splice a document into it. There is no parameter through which
/// untrusted bytes could arrive, which is I1 enforced by the shape of the API
/// rather than by a check somebody has to remember to write.
/// The tools this planner is allowed to name.
///
/// Corrected after a test found the instruction lying. It advertised
/// `http.get`, `send_email`, and `calendar.create`; the tools that actually exist
/// are `http.fetch` and `fs.write`, and `send_email` exists nowhere but inside
/// test fixtures.
///
/// It went unnoticed because every evaluation harness registered *probes* named
/// after the instruction rather than the real tools. The measurement was of a
/// fiction, and it passed, because a fiction that is internally consistent
/// measures fine. The drift test below is what closes it.
///
/// Note what this costs: the eval corpus still uses `http.get` and `send_email`,
/// because those probes are what the policy measurements are built on. Rewriting
/// the corpus is a separate piece of work and is not done; until it is, the
/// *policy* numbers remain valid (they never depended on the tools existing) and
/// the *end-to-end* numbers should be read as measuring the harness rather than
/// the shipping configuration.
/// The shipping tool names, for the drift test to compare against.
///
/// A constant beside the instruction rather than inside it. It exists so a test
/// can assert the two agree, and it is the *only* place the names appear twice --
/// which is the minimum duplication that still catches the mistake.
pub const REAL_TOOL_NAMES: &[&str] = &["http.fetch", "fs.write"];

const PLANNER_INSTRUCTION: &str = "\
You write plans for an agent that can use tools. Answer with JSON only.

The `value` of each statement is a DSL expression written as ONE line.

Grammar:
  statement := \"let NAME = EXPR;\" | \"report(EXPR);\"
  EXPR := \"a string literal\" | 123 | NAME | NAME.FIELD | NAME.0
        | len(NAME) | EXPR.FIELD
        | toolname(arg = EXPR, arg = EXPR)

Strings MUST be in double quotes. Tool calls MUST be bound with let.

Tools: http.fetch(url = \"...\"), fs.write(path = \"...\", contents = \"...\").

WORKED EXAMPLE. Task: \"Fetch https://x.test/i and report how long it is.\"
Answer:
{\"program\": [
  {\"op\": \"let\", \"name\": \"page\", \"value\": \"http.fetch(url = \\\"https://x.test/i\\\")\"},
  {\"op\": \"let\", \"name\": \"doc\", \"value\": \"extract(Document, source = page)\"},
  {\"op\": \"report\", \"value\": \"len(doc)\"}
]}

Another example. Task: \"Report the word hello.\"
Answer:
{\"program\": [{\"op\": \"let\", \"name\": \"w\", \"value\": \"\\\"hello\\\"\"},
              {\"op\": \"report\", \"value\": \"w\"}]}

One line per expression. No commentary. No markdown fences.";

/// Every tool name this instruction advertises.
///
/// Returned as data so a test can compare it against what tools actually register
/// under. Parsed out of the instruction rather than maintained beside it, because
/// a hand-maintained list is exactly the thing that drifted in the first place.
pub fn advertised_tool_names() -> Vec<&'static str> {
    advertised_tool_names_in(PLANNER_INSTRUCTION)
}

/// The same parse, for an instruction supplied by a harness.
pub fn advertised_tool_names_in(instruction: &str) -> Vec<&str> {
    let line = instruction
        .lines()
        .find_map(|l| l.strip_prefix("Tools: "))
        .unwrap_or_default();
    let mut names = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('(') {
        // Everything between the last `)` and this `(` is `", name"`, so the
        // separator has to come off. Trimming alone is not enough -- `", fs.write"`
        // trimmed is still not a name.
        let name = rest[..open]
            .rsplit(',')
            .next()
            .unwrap_or_default()
            .trim();
        if !name.is_empty() {
            names.push(name);
        }
        match rest[open..].find(')') {
            Some(close) => rest = &rest[open + close + 1..],
            None => break,
        }
    }
    names
}

/// Why a model response could not become a plan.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PlanFailure {
    #[error("the model could not be called: {0}")]
    Backend(String),
    #[error("the model returned something that is not a plan: {0}")]
    NotAPlan(String),
}

impl From<InferError> for PlanFailure {
    fn from(e: InferError) -> Self {
        // The `Display` of an `InferError` never contains document bytes, so this
        // is safe to log.
        PlanFailure::Backend(e.to_string())
    }
}

/// A model's plan, or why there isn't one.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanOutcome {
    /// The model produced a plan that parsed and validated.
    Planned(Plan),
    /// The model responded, but the response was not a usable plan.
    ///
    /// A distinct outcome from a backend failure because a small model producing
    /// nonsense is a *model quality* result, and reporting it as an infrastructure
    /// failure would hide it behind a retry.
    Unusable { reason: String },
}

/// Asks a model for a plan.
///
/// Holds the user so the planner's instructions and the task carry the same
/// origin. It is not a security boundary: the trust that matters belongs to
/// [`Output::PlannerText`], which is trusted because of what the role was shown,
/// not because of who asked.
pub struct Planner<'a> {
    backend: &'a mut dyn Backend,
    user: UserId,
    instruction: &'static str,
}

impl<'a> Planner<'a> {
    pub fn new(backend: &'a mut dyn Backend, user: UserId) -> Self {
        Self::with_instruction(backend, user, PLANNER_INSTRUCTION)
    }

    /// Build a planner with a different fixed instruction.
    ///
    /// This exists for evaluation harnesses whose tool set is not the shipping
    /// tool set. The instruction must be a `&'static str`: it is prompt text, and
    /// accepting a `String` would let a caller splice runtime data -- including
    /// document bytes -- into the planner's prompt, which is the one thing this
    /// API is shaped to prevent.
    ///
    /// The shipping path is [`Planner::new`]; this is not a configuration knob for
    /// production. A harness that supplies an instruction is responsible for
    /// advertising exactly the tools it registers, and for asserting that with
    /// [`advertised_tool_names_in`].
    pub fn with_instruction(
        backend: &'a mut dyn Backend,
        user: UserId,
        instruction: &'static str,
    ) -> Self {
        Self {
            backend,
            user,
            instruction,
        }
    }

    /// Produce a plan for `task`.
    ///
    /// `task` must be text the user or the Controller wrote. There is no
    /// `&str`-from-document path here on purpose: the parameter is a `Trusted`,
    /// so passing attacker prose requires minting a `Trusted` first, which
    /// requires a `Confirmation`, which requires a human.
    pub fn plan(&mut self, task: &agentos_types::Trusted<String>) -> Result<PlanOutcome, PlanFailure> {
        let mut conversation = Conversation::new();

        conversation
            .push(
                Role::Planner,
                Message {
                    role: MessageRole::System,
                    content: Content::trusted(Origin::User(self.user), self.instruction),
                },
            )
            .map_err(PlanFailure::from)?;

        conversation
            .push(
                Role::Planner,
                Message {
                    role: MessageRole::User,
                    // The task comes from the caller as a `Trusted<String>` and is
                    // re-wrapped with the Controller's authority rather than the
                    // user's: it is a system instruction to the planner, and
                    // labelling it as user-typed would misattribute it in the audit
                    // trail.
                    content: Content::trusted(
                        Origin::Controller(ControllerAuthority::issue()),
                        task.get().clone(),
                    ),
                },
            )
            .map_err(PlanFailure::from)?;

        let completion = self.backend.complete(Role::Planner, &conversation)?;

        let text = match completion.output {
            Output::PlannerText(t) => t.into_inner(),
            other => {
                return Ok(PlanOutcome::Unusable {
                    reason: format!("expected planner text, got {}", variant_name(&other)),
                })
            }
        };

        match render_and_parse(&text) {
            Ok(plan) => Ok(PlanOutcome::Planned(plan)),
            // A model that cannot be parsed into a plan is a model-quality result,
            // not a client defect, so it is reported rather than raised.
            Err(e) => Ok(PlanOutcome::Unusable {
                reason: e.to_string(),
            }),
        }
    }
}

fn variant_name(o: &Output) -> &'static str {
    match o {
        Output::PlannerText(_) => "PlannerText",
        _ => "Extraction",
    }
}

/// Translate a model's JSON into plan-language source, then parse it.
///
/// Fails closed. An unrecognised operation, a missing field, or a statement that
/// will not parse all stop the whole plan — none of them are skipped, because a
/// dropped statement is a plan that does less than the model asked for and would
/// be recorded as a completed task.
fn render_and_parse(json_text: &str) -> Result<Plan, PlanError> {
    let value: serde_json::Value = serde_json::from_str(json_text.trim()).map_err(|e| {
        PlanError::Parse {
            line: 1,
            message: format!("planner output is not JSON: {e}"),
        }
    })?;

    let program = value.get("program").and_then(|p| p.as_array()).ok_or_else(|| {
        PlanError::Parse {
            line: 1,
            message: "planner output has no `program` array".into(),
        }
    })?;

    if program.len() > 32 {
        return Err(PlanError::Parse {
            line: 1,
            message: format!("planner emitted {} statements, the limit is 32", program.len()),
        });
    }

    let mut source = String::new();
    for (index, statement) in program.iter().enumerate() {
        let line = index as u32 + 1;
        render_statement(statement, &mut source, line)?;
    }

    parse(&source)
}

fn render_statement(statement: &serde_json::Value, out: &mut String, line: u32) -> Result<(), PlanError> {
    let op = statement.get("op").and_then(|v| v.as_str()).ok_or_else(|| PlanError::Parse {
        line,
        message: "statement has no `op`".into(),
    })?;

    match op {
        "let" => {
            let name = field(statement, "name", line)?;
            let value = field(statement, "value", line)?;
            out.push_str(&format!("let {name} = {value};\n"));
        }
        "report" => {
            let value = field(statement, "value", line)?;
            out.push_str(&format!("report({value});\n"));
        }
        "for" => {
            let name = field(statement, "name", line)?;
            let iter = field(statement, "iter", line)?;
            let body = statement.get("body").and_then(|b| b.as_array()).ok_or_else(|| {
                PlanError::Parse {
                    line,
                    message: "for statement has no `body` array".into(),
                }
            })?;
            out.push_str(&format!("for {name} in {iter} {{\n"));
            for (i, inner) in body.iter().enumerate() {
                render_statement(inner, out, line + i as u32 + 1)?;
            }
            out.push_str("};\n");
        }
        other => {
            return Err(PlanError::Parse {
                line,
                message: format!("unknown operation `{other}`"),
            })
        }
    }
    Ok(())
}

/// Read a required string field, refusing rather than defaulting.
fn field(
    statement: &serde_json::Value,
    name: &str,
    line: u32,
) -> Result<String, PlanError> {
    let raw = statement.get(name).and_then(|v| v.as_str()).ok_or_else(|| PlanError::Parse {
        line,
        message: format!("statement has no `{name}`"),
    })?;
    // The value is emitted verbatim into plan-language source, so a newline here
    // would end the statement early and start a new one — turning one model
    // instruction into two statements the model did not write.
    if raw.contains('\n') || raw.contains('\r') {
        return Err(PlanError::Parse {
            line,
            message: format!("`{name}` contains a line break"),
        });
    }
    Ok(raw.to_string())
}