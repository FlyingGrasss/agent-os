use std::collections::{BTreeMap, HashMap};

use agentos_types::{Event, Label, SourceId, Trusted, Val};

use crate::ast::{Expr, PlanError, Plan, Stmt};
use crate::data::{PlanData, PlanValue};

/// Tools the interpreter may call. Implemented by the broker, not by the plan.
pub trait ToolHost {
    /// Invoke a tool. Implementations enforce the policy engine before doing
    /// anything observable.
    fn call(&mut self, tool: &str, args: &BTreeMap<String, PlanValue>) -> Result<PlanValue, PlanError>;
}

/// The quarantined processor: extracts typed, schema-checked data from
/// untrusted documents and returns records. It never returns raw document text.
pub trait Extractor {
    fn extract(&mut self, schema: &str, document: &PlanData) -> Result<PlanData, PlanError>;
}

/// What the user is told about progress. Typed summaries only.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_steps: usize,
    pub max_loop_iterations: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_steps: 256,
            max_loop_iterations: 10_000,
        }
    }
}

#[derive(Default)]
struct State {
    vars: HashMap<String, PlanValue>,
    steps: usize,
    loop_iterations: usize,
}

impl State {
    fn step(&mut self, limits: &Limits) -> Result<(), PlanError> {
        self.steps += 1;
        if self.steps > limits.max_steps {
            return Err(PlanError::StepBudgetExhausted {
                max: limits.max_steps,
            });
        }
        Ok(())
    }
}

pub struct Interp<'a> {
    pub tools: &'a mut dyn ToolHost,
    pub extractor: &'a mut dyn Extractor,
    pub limits: Limits,
    pub events: Vec<Event>,
    pub reports: Vec<Report>,
}

/// Execute a plan.
///
/// The interpreter moves `Val` handles, never raw strings, and never gives the
/// host access to an untrusted value's text. Only `report` can emit a value to
/// the user, and it refuses tainted input.
pub fn run(
    plan: &Plan,
    tools: &mut dyn ToolHost,
    extractor: &mut dyn Extractor,
    limits: Limits,
) -> Result<Outcome, PlanError> {
    plan.validate()?;
    let mut interp = Interp {
        tools,
        extractor,
        limits,
        events: Vec::new(),
        reports: Vec::new(),
    };
    let mut st = State::default();
    for stmt in &plan.stmts {
        interp.exec(stmt, &mut st)?;
    }
    Ok(Outcome {
        reports: interp.reports,
        events: interp.events,
    })
}

#[derive(Debug)]
pub struct Outcome {
    pub reports: Vec<Report>,
    pub events: Vec<Event>,
}

impl<'a> Interp<'a> {
    fn exec(&mut self, stmt: &Stmt, st: &mut State) -> Result<(), PlanError> {
        st.step(&self.limits)?;
        match stmt {
            Stmt::Let { name, value } => {
                let v = self.eval(value, st)?;
                if st.vars.insert(name.clone(), v).is_some() {
                    return Err(PlanError::DuplicateBinding { name: name.clone() });
                }
                Ok(())
            }
            Stmt::Report { value } => {
                let v = self.eval(value, st)?;
                let summary = v
                    .with_label_for_display(|data, label| match data {
                        PlanData::Int(n) => Some(format!("{n}")),
                        PlanData::Bool(b) => Some(format!("{b}")),
                        // An enum's values are fixed by the schema, so a tainted
                        // enum still cannot carry an attacker's prose.
                        PlanData::Enum(e) => Some(e.clone()),
                        PlanData::List(items) => Some(format!("{} item(s)", items.len())),
                        PlanData::Unit => Some("done".to_string()),
                        // Text is allowed only when the label says the planner
                        // wrote it. A `Str` recovered from an untrusted document
                        // inherits that document's taint, so this admits
                        // planner-authored prose and nothing else.
                        PlanData::Str(s) if label.is_trusted() => Some(s.clone()),
                        PlanData::Str(_) | PlanData::Quoted { .. } | PlanData::Record(_) => None,
                    })
                    .ok_or(PlanError::TaintedReport)?;
                self.reports.push(Report { summary });
                Ok(())
            }
            Stmt::ForEach { var, iter, body } => {
                let list = self.eval(iter, st)?;
                let items = match list.with_label_for_display(|d, _| d.as_list().map(|i| i.to_vec())) {
                    Some(items) => items,
                    None => {
                        return Err(PlanError::BadField {
                            field: "<iteration>".into(),
                            found: list.with_label_for_display(|d, _| d.type_name()),
                        })
                    }
                };
                st.loop_iterations += items.len();
                if st.loop_iterations > self.limits.max_loop_iterations {
                    return Err(PlanError::LoopBoundExceeded {
                        max: self.limits.max_loop_iterations,
                    });
                }
                // Every element inherits the list's label, so iterating a
                // tainted result does not launder its elements.
                let item_label = list.label().clone();
                for item in items {
                    let scope_key = var.clone();
                    st.vars.insert(scope_key.clone(), Val::labeled(item, item_label.clone()));
                    for s in body {
                        self.exec(s, st)?;
                    }
                    st.vars.remove(&scope_key);
                }
                Ok(())
            }
        }
    }

    fn eval(&mut self, expr: &Expr, st: &mut State) -> Result<PlanValue, PlanError> {
        st.step(&self.limits)?;
        match expr {
            Expr::Literal(l) => Ok(Val::trusted(l.clone().into_data())),
            Expr::Var(name) => st
                .vars
                .get(name)
                .cloned()
                .ok_or_else(|| PlanError::UndefinedVar(name.clone())),
            Expr::Len(inner) => {
                let v = self.eval(inner, st)?;
                let n = match v.with_label_for_display(|d, _| d.as_list().map(|l| l.len())) {
                    Some(n) => n as i64,
                    None => {
                        return Err(PlanError::BadField {
                            field: "len".into(),
                            found: v.with_label_for_display(|d, _| d.type_name()),
                        })
                    }
                };
                // Structure stays legible to the plan; only text is restricted,
                // and the label propagates so a length derived from hostile
                // content is still recognised as hostile.
                Ok(Val::labeled(PlanData::Int(n), v.label().clone()))
            }
            Expr::Field { base, field } => {
                let v = self.eval(base, st)?;
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
                let doc = self.eval(source, st)?;
                // The extractor is handed the document as opaque data. Whatever
                // it returns is trusted as a *structure* but inherits the
                // document's taint, so a field the extractor lifted out of a
                // hostile page cannot flow into a sensitive argument silently.
                let (text, label) = doc.into_labeled_inner();
                let extracted = self.extractor.extract(schema, &text)?;
                Ok(Val::labeled(extracted, label))
            }
            Expr::ToolCall { tool, args } => {
                let mut map = BTreeMap::new();
                for a in args {
                    map.insert(a.name.clone(), self.eval(&a.value, st)?);
                }
                let result = self.tools.call(tool, &map)?;
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

/// Helper for hosts: confirm a value with the user, then mark it trusted.
///
/// Part of the confirmation path that `agentos-core` drives when the policy
/// engine returns `Decision::Confirm`. Unused until that crate exists.
#[allow(dead_code)]
pub fn after_confirmation(val: Val<PlanData>, reason: &str) -> Result<Trusted<PlanData>, PlanError> {
    match val.label() {
        Label::Tainted { .. } => Ok(Trusted::confirmed(val)),
        Label::Trusted => Err(PlanError::ConfirmationRequired {
            op: reason.to_string(),
        }),
    }
}

/// The first recorded source of a tainted value, for display in a confirmation
/// prompt. Unused until `agentos-core` drives confirmations.
#[allow(dead_code)]
pub fn source_of(val: &PlanValue) -> Option<SourceId> {
    val.label().sources().first().copied().copied()
}
