//! A resumable interpreter.
//!
//! # Why this exists
//!
//! When the policy engine returns `Confirm`, `ToolHost::call` returns
//! `ConfirmationRequired`. The recursive interpreter in [`crate::interp`] lets that
//! `?` out of `run`, and everything it was holding goes with it: the variables, the
//! statement position, the loop's item index, and the spent step and loop budgets.
//!
//! Two ways to deal with that, and one of them is wrong.
//!
//! **Re-run the plan.** A halt on the second tool call means re-running replays
//! the first call's side effect — a second email, a second write. Memoising the
//! host on `(tool, args)` to prevent that makes the audit log a fiction: it records
//! an attempt and performs no effect, so I6's "recorded before it executes" stops
//! describing what happened. And two identical `fs.write(path, contents)` in one
//! plan may legitimately be two writes.
//!
//! **Resume properly.** This module. State is carried across the halt, budgets are
//! cumulative, and a loop resumes at the item it stopped on.
//!
//! # The three things that must be carried, and why
//!
//! 1. **Variables.** Obvious, and the reason a bare statement cursor is not enough.
//! 2. **Loop frames.** `ForEach` binds a variable per item. A halt in the body
//!    loses the items, the index, and the item's label, so a cursor into
//!    `plan.stmts` cannot express "resume at item 3 of this loop". A frame stack
//!    can.
//! 3. **Spent budgets.** `steps` and `loop_iterations` live here, so a resume that
//!    started a fresh counter would let a plan re-spend its budget on every
//!    approval. That is budget *escalation*, not an inconvenience: a plan that
//!    halts ten times would get ten times the work.
//!
//! # The hazard this closes
//!
//! A tool call's arguments are themselves expressions, so a halting statement can
//! contain earlier tool calls:
//!
//! ```text
//! let m = send_email(to = lookup(key = inv.0.note), subject = "s", body = "b");
//! ```
//!
//! Resuming re-evaluates the statement, which would invoke `lookup` a second time.
//! A second `lookup` is harmless; a second *effecting* call in argument position is
//! the double-execution bug in miniature. So results of tool calls made while a
//! statement is in flight are recorded and reused on resume, and the record is
//! discarded the moment the statement completes or fails for any other reason.
//!
//! The record is keyed by *call site*, not by tool name. Keying by name is the
//! obvious choice and it is wrong: a statement may name the same tool twice, and a
//! nested call restarts the argument index, so `mail(subject = h(k = "a"),
//! body = h(k = "b"))` would hand `body` the result computed for `"a"` and never
//! invoke the second `h`. That is not only a wrong value — it is a taint-laundering
//! path, since a trusted result computed for one argument could be served to a
//! position where a tainted one belonged, with no injection required.
//!
//! # What this deliberately does not do
//!
//! It does not decide policy. The host does, and the grant that lets a resumed
//! call through lives on the host. This module only decides *where to carry on
//! from*, and holds no authorisation of any kind — which is what keeps it a pure
//! evaluator.

use std::collections::{BTreeMap, HashMap};

use agentos_types::{Event, Label, Val};

use crate::ast::{Expr, PlanError, Stmt, MAX_EXPR_DEPTH};
use crate::data::{PlanData, PlanValue};
use crate::interp::{Extractor, Limits, Report, ToolHost};

/// Where a resume carries on from.
///
/// Outermost first, so the head is the statement list the plan started with.
enum Frame {
    /// The plan's top-level statements.
    Program {
        stmts: Vec<Stmt>,
        at: usize,
    },
    /// One `ForEach`, with the item it is currently on.
    Iteration {
        var: String,
        items: Vec<PlanData>,
        /// Every element inherits the list's label, so iterating a tainted result
        /// does not launder its elements. Carried because a resumed item needs
        /// the same label it would have had, or a `Confirmation` issued for it
        /// would fail its label check.
        label: Label,
        /// Index of the current item.
        at: usize,
        body: Vec<Stmt>,
        body_at: usize,
    },
}

/// What one call to [`Machine::advance`] achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Some work was done. Call again.
    Advanced,
    /// A tool call needs a user's decision. The plan has not progressed past it;
    /// grant on the host and call again.
    Halted {
        /// `tool.arg`, for display.
        op: String,
    },
    /// Every statement ran.
    Done,
}

/// What the frame stack says to do next.
///
/// Computed from a frame borrow and then dropped, so the statement it names can
/// be executed with `&mut self`. Holding the frame borrow across the call would
/// be a double mutable borrow, and the reason this is an enum rather than
/// inline control flow.
enum Next {
    /// Execute this statement.
    ///
    /// The cursor is *not* advanced yet. It moves only once the statement has
    /// finished, so a statement that halts is still the current statement when
    /// the machine is resumed and gets retried rather than skipped.
    Exec {
        stmt: Stmt,
        /// Index of the frame the statement came from, so its cursor can be
        /// moved afterwards even if the statement pushed a frame of its own.
        depth: usize,
    },
    /// The top frame is finished; pop it and look again.
    Pop,
    /// The current loop item is finished; move to the next one.
    ItemFinished,
    /// Nothing left at all.
    Finished,
}

/// A resumable plan execution.
///
/// Holds only position and budget. The [`ToolHost`] and [`Extractor`] are passed
/// per call rather than stored, because a stored `&mut` would keep the host
/// borrowed for the machine's whole life — and the host is exactly what the
/// caller has to reach to grant an approval between steps.
pub struct Machine {
    limits: Limits,
    vars: HashMap<String, PlanValue>,
    steps: usize,
    loop_iterations: usize,
    frames: Vec<Frame>,
    reports: Vec<Report>,
    events: Vec<Event>,
    /// Results of tool calls made while the current statement is in flight.
    ///
    /// Keyed by *call site* — the path of argument indices from the statement
    /// root to the argument whose value this is. Deliberately not keyed by tool
    /// name: one statement may contain the same tool more than once, and a name
    /// key would let one call's result be served to another's argument.
    ///
    /// Cleared when the statement completes or fails, so a later statement
    /// re-runs its own tools.
    in_flight: BTreeMap<Vec<usize>, PlanValue>,
}

impl Machine {
    /// A machine with no program loaded.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            vars: HashMap::new(),
            steps: 0,
            loop_iterations: 0,
            frames: Vec::new(),
            reports: Vec::new(),
            events: Vec::new(),
            in_flight: BTreeMap::new(),
        }
    }

    /// Load a validated plan.
    pub fn start(plan: &crate::ast::Plan) -> Result<Self, PlanError> {
        plan.validate()?;
        let mut machine = Self::new(Limits::default());
        machine.frames.push(Frame::Program {
            stmts: plan.stmts.clone(),
            at: 0,
        });
        Ok(machine)
    }

    /// Load a plan with explicit limits.
    pub fn start_with(plan: &crate::ast::Plan, limits: Limits) -> Result<Self, PlanError> {
        plan.validate()?;
        let mut machine = Self::new(limits);
        machine.frames.push(Frame::Program {
            stmts: plan.stmts.clone(),
            at: 0,
        });
        Ok(machine)
    }

    /// Reports produced so far.
    pub fn reports(&self) -> &[Report] {
        &self.reports
    }

    /// Events emitted so far.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Variables bound so far. Used by a caller that needs to show state.
    pub fn bound(&self, name: &str) -> Option<&PlanValue> {
        self.vars.get(name)
    }

    /// Steps spent so far, so a caller can see the budget being consumed across
    /// a resume rather than reset.
    pub fn steps_spent(&self) -> usize {
        self.steps
    }

    /// Loop iterations spent so far.
    pub fn loop_iterations_spent(&self) -> usize {
        self.loop_iterations
    }

    /// Spend one step, failing once the budget is gone.
    ///
    /// Carried on the machine rather than recomputed, so a resume cannot hand a
    /// plan a fresh budget.
    fn step(&mut self) -> Result<(), PlanError> {
        self.steps += 1;
        if self.steps > self.limits.max_steps {
            return Err(PlanError::StepBudgetExhausted {
                max: self.limits.max_steps,
            });
        }
        Ok(())
    }

    /// Run until the plan finishes, halts, or fails.
    ///
    /// `ConfirmationRequired` is returned as [`Step::Halted`] rather than as an
    /// error, because it is not a failure: the plan is waiting for a decision, and
    /// a caller that granted the approval and called again continues from exactly
    /// where it stopped.
    pub fn advance(
        &mut self,
        tools: &mut dyn ToolHost,
        extractor: &mut dyn Extractor,
    ) -> Result<Step, PlanError> {
        loop {
            // Decide from the frame stack, then release the borrow. Nothing is
            // mutated here: the cursor moves in the `Next::Exec` arm below, and
            // only if the statement completes.
            let next = match self.frames.last() {
                None => Next::Finished,
                Some(Frame::Program { stmts, at }) => {
                    if *at >= stmts.len() {
                        Next::Pop
                    } else {
                        Next::Exec {
                            stmt: stmts[*at].clone(),
                            depth: self.frames.len() - 1,
                        }
                    }
                }
                Some(Frame::Iteration { body, body_at, .. }) => {
                    if *body_at < body.len() {
                        Next::Exec {
                            stmt: body[*body_at].clone(),
                            depth: self.frames.len() - 1,
                        }
                    } else {
                        Next::ItemFinished
                    }
                }
            };

            match next {
                Next::Finished => return Ok(Step::Done),
                Next::Pop => {
                    self.frames.pop();
                    continue;
                }
                Next::ItemFinished => {
                    self.advance_item();
                    continue;
                }
                Next::Exec { stmt, depth } => {
                    // A statement already in flight keeps its recorded tool
                    // results; a fresh one starts with a clean record.
                    let resuming = !self.in_flight.is_empty();
                    if !resuming {
                        self.in_flight.clear();
                    }
                    let outcome = self.exec(&stmt, tools, extractor);
                    return match outcome {
                        Ok(()) => {
                            // Only now does the statement count as done.
                            self.advance_cursor(depth);
                            Ok(Step::Advanced)
                        }
                        // The cursor deliberately does not move: the granted call
                        // is still the current statement, so the next `advance`
                        // retries it. Skipping it here would mean an approved tool
                        // call never runs, which is a worse failure than the halt.
                        Err(PlanError::ConfirmationRequired { op }) => Ok(Step::Halted { op }),
                        Err(other) => Err(other),
                    };
                }
            }
        }
    }

    /// Move a `for` loop from the item it just finished to the next one.
    fn advance_item(&mut self) {
        let Some(Frame::Iteration {
            var,
            items,
            label,
            at,
            body_at,
            ..
        }) = self.frames.last_mut()
        else {
            self.frames.pop();
            return;
        };

        // Drop the loop variable before moving on, exactly as the recursive
        // interpreter did, so a later read of that name sees its own mistake
        // rather than a vanished binding.
        let var = var.clone();
        self.vars.remove(&var);
        *at += 1;
        if *at >= items.len() {
            self.frames.pop();
            return;
        }
        let item = items[*at].clone();
        let item_label = label.clone();
        self.vars.insert(var, Val::labeled(item, item_label));
        *body_at = 0;
    }

    /// Execute one statement.
    fn exec(
        &mut self,
        stmt: &Stmt,
        tools: &mut dyn ToolHost,
        extractor: &mut dyn Extractor,
    ) -> Result<(), PlanError> {
        self.step()?;
        let result = self.exec_inner(stmt, tools, extractor);
        // Cleared unless the statement halted: on success the statement is over,
        // and on a hard failure the machine stops, so keeping the record would
        // only risk a later statement reusing it. On a halt the record is
        // exactly what the retry needs.
        if !matches!(result, Err(PlanError::ConfirmationRequired { .. })) {
            self.in_flight.clear();
        }
        result
    }

    /// Move the cursor past a statement that has just completed.
    ///
    /// Indexed by the frame the statement came *from*, not the top of the stack.
    /// A `ForEach` pushes its own frame while executing, so by the time the
    /// statement is done the top of the stack is the new loop rather than the
    /// frame whose cursor needs moving.
    fn advance_cursor(&mut self, depth: usize) {
        // The frame's own kind says which cursor to move, so no flag is needed.
        let Some(frame) = self.frames.get_mut(depth) else {
            return;
        };
        match frame {
            Frame::Program { at, .. } => *at += 1,
            Frame::Iteration { body_at, .. } => *body_at += 1,
        }
    }

    fn exec_inner(
        &mut self,
        stmt: &Stmt,
        tools: &mut dyn ToolHost,
        extractor: &mut dyn Extractor,
    ) -> Result<(), PlanError> {
        match stmt {
            Stmt::Let { name, value } => {
                // An empty path: each statement's expression tree is its own
                // namespace, and the record is cleared between statements.
                let v = self.eval(value, tools, extractor, 0, &[])?;
                if self.vars.insert(name.clone(), v).is_some() {
                    return Err(PlanError::DuplicateBinding { name: name.clone() });
                }
                Ok(())
            }
            Stmt::Report { value } => {
                let v = self.eval(value, tools, extractor, 0, &[])?;
                let summary = v
                    .with_label_for_display(|data, label| match data {
                        PlanData::Int(n) => Some(format!("{n}")),
                        PlanData::Bool(b) => Some(format!("{b}")),
                        PlanData::List(items) => Some(format!("{} item(s)", items.len())),
                        PlanData::Unit => Some("done".to_string()),
                        PlanData::Str(s) if label.is_trusted() => Some(s.clone()),
                        PlanData::Str(_) => None,
                        PlanData::Quoted { .. }
                        | PlanData::Enum(_)
                        | PlanData::Record(_) => None,
                    })
                    .ok_or(PlanError::TaintedReport)?;
                self.reports.push(Report { summary });
                Ok(())
            }
            Stmt::ForEach { var, iter, body } => {
                let list = self.eval(iter, tools, extractor, 0, &[])?;
                // Checked before the loop rather than at the point of binding, so
                // an empty or absent iteration still fails: the plan is ambiguous
                // either way.
                if self.vars.contains_key(var) {
                    return Err(PlanError::DuplicateBinding { name: var.clone() });
                }
                let items = match list
                    .with_label_for_display(|d, _| d.as_list().map(|i| i.to_vec()))
                {
                    Some(items) => items,
                    None => {
                        return Err(PlanError::BadField {
                            field: "<iteration>".into(),
                            found: list.with_label_for_display(|d, _| d.type_name()),
                        })
                    }
                };
                self.loop_iterations += items.len();
                if self.loop_iterations > self.limits.max_loop_iterations {
                    return Err(PlanError::LoopBoundExceeded {
                        max: self.limits.max_loop_iterations,
                    });
                }
                // An empty list completes without binding anything, matching the
                // recursive interpreter, which never entered the body.
                if items.is_empty() {
                    return Ok(());
                }
                let item_label = list.label().clone();
                let first = items[0].clone();
                self.vars
                    .insert(var.clone(), Val::labeled(first, item_label.clone()));
                self.frames.push(Frame::Iteration {
                    var: var.clone(),
                    items,
                    label: item_label,
                    at: 0,
                    body: body.clone(),
                    body_at: 0,
                });
                Ok(())
            }
        }
    }

    /// Evaluate an expression.
    ///
    /// `depth` is checked on the way in, mirroring `validate_expr`, and the
    /// recursion budget is spent here so the spend is counted on the machine and
    /// therefore survives a resume.
    ///
    /// `path` is the route taken to reach this expression from the statement root:
    /// a field or projection appends `Field`, and each tool-call argument appends
    /// its index. It identifies a call site uniquely within the statement, which
    /// is what the in-flight record is keyed by. It is *not* a security decision —
    /// it is bookkeeping so a resume re-uses the right recorded value.
    fn eval(
        &mut self,
        expr: &Expr,
        tools: &mut dyn ToolHost,
        extractor: &mut dyn Extractor,
        depth: usize,
        path: &[usize],
    ) -> Result<PlanValue, PlanError> {
        if depth > MAX_EXPR_DEPTH {
            return Err(PlanError::ExprTooDeep {
                max: MAX_EXPR_DEPTH,
            });
        }
        self.step()?;
        match expr {
            Expr::Literal(l) => Ok(l.clone().into_value()),
            Expr::Var(name) => self
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| PlanError::UndefinedVar(name.clone())),
            Expr::Len(inner) => {
                let v = self.eval(inner, tools, extractor, depth + 1, path)?;
                let n = match v.with_label_for_display(|d, _| d.as_list().map(|l| l.len())) {
                    Some(n) => n as i64,
                    None => {
                        return Err(PlanError::BadField {
                            field: "len".into(),
                            found: v.with_label_for_display(|d, _| d.type_name()),
                        })
                    }
                };
                // Structure stays legible to the plan; only text is restricted, and
                // the label propagates so a length derived from hostile content is
                // still recognised as hostile.
                Ok(Val::labeled(PlanData::Int(n), v.label().clone()))
            }
            Expr::Field { base, field } => {
                let v = self.eval(base, tools, extractor, depth + 1, path)?;
                let projected =
                    match v.with_label_for_display(|d, _| (d.type_name(), d.get(field).cloned())) {
                        (_, Some(f)) => f,
                        (found, None) => {
                            return Err(PlanError::BadField {
                                field: field.clone(),
                                found,
                            })
                        }
                    };
                Ok(Val::labeled(projected, v.label().clone()))
            }
            Expr::Extract { source, schema } => {
                let doc = self.eval(source, tools, extractor, depth + 1, path)?;
                // The extractor is handed the document as opaque data. Whatever it
                // returns is trusted as a *structure* but inherits the document's
                // taint, so a field lifted out of a hostile page cannot flow into a
                // sensitive argument silently.
                let (text, label) = doc.into_labeled_inner();
                let extracted = extractor.extract(schema, &text)?;
                Ok(Val::labeled(extracted, label))
            }
            Expr::ToolCall { tool, args } => {
                let mut map = BTreeMap::new();
                for (index, a) in args.iter().enumerate() {
                    // Reuse a result recorded earlier in this same statement, so a
                    // resume does not re-invoke a tool that already ran.
                    //
                    // The key is the *call site* — this expression's path from the
                    // statement root — not the tool name. Keying by tool name
                    // collides as soon as one statement contains the same tool
                    // twice, because the argument index restarts at zero inside a
                    // nested call: `mail(subject = h(k = "a"), body = h(k = "b"))`
                    // would give `body` the result computed for `"a"` and never run
                    // the second `h`. Beyond being wrong, that is a laundering
                    // path — a trusted result computed for one argument could be
                    // served to a position where a tainted one belonged.
                    let mut site = path.to_vec();
                    site.push(index);
                    let key = site.clone();
                    if let Some(cached) = self.in_flight.get(&key) {
                        map.insert(a.name.clone(), cached.clone());
                        continue;
                    }
                    let value = self.eval(&a.value, tools, extractor, depth + 1, &site)?;
                    self.in_flight.insert(key, value.clone());
                    map.insert(a.name.clone(), value);
                }
                let result = tools.call(tool, &map)?;
                self.events.push(Event::ToolCompleted {
                    tool: tool.clone(),
                    ok: true,
                    summary: None,
                    elapsed_ms: 0,
                });
                Ok(result)
            }
        }
    }
}