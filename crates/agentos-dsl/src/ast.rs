use agentos_types::{SourceId, Val};

use crate::data::{PlanData, PlanValue};

/// A literal in plan source.
///
/// `Quoted` exists so a quarantined value can travel through the plan language
/// without being mistaken for planner-authored text. The parser has no grammar
/// for it, so `parse` can never produce one, but `Plan` is a public type that a
/// host builds programmatically, and a `Quoted` in a hand-built plan is still
/// text lifted out of a document. See [`Literal::into_value`].
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Bool(bool),
    Str(String),
    Quoted { text: String, source: SourceId },
}

impl Literal {
    /// The value this literal denotes, with its provenance attached.
    ///
    /// There is deliberately no method returning a bare `PlanData`. A bare
    /// `PlanData` carries no label, so the caller's next move would be
    /// `Val::trusted(..)`, and the only thing distinguishing planner-authored
    /// text from attacker text would be which variant the author picked. The
    /// decision is made here instead, in one place.
    ///
    /// `Int`, `Bool` and `Str` are trusted because the planner authored them and
    /// the planner never observes untrusted bytes (invariant I1). `Quoted` is not
    /// planner-authored no matter who built the `Plan`, so it arrives carrying
    /// the taint of the document it came out of. A host that mints a
    /// `Literal::Quoted` gets a value it must argue about at a sensitive
    /// position, which is the outcome a hostile document should get.
    pub fn into_value(self) -> PlanValue {
        match self {
            Literal::Int(i) => Val::trusted(PlanData::Int(i)),
            Literal::Bool(b) => Val::trusted(PlanData::Bool(b)),
            Literal::Str(s) => Val::trusted(PlanData::Str(s)),
            Literal::Quoted { text, source } => {
                Val::tainted(source, PlanData::quoted(text, source))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arg {
    pub name: String,
    pub value: Expr,
}

impl Arg {
    pub fn new(name: impl Into<String>, value: Expr) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Literal),
    Var(String),
    /// A tool invocation.
    ToolCall { tool: String, args: Vec<Arg> },
    /// A field projection on a record or list: `x.name`, `x.0`.
    Field { base: Box<Expr>, field: String },
    /// Send an untrusted document to the quarantined processor for structured
    /// extraction. The result is a typed summary, never raw text.
    Extract {
        source: Box<Expr>,
        schema: String,
    },
    /// Count of a list.
    Len(Box<Expr>),
}

/// A statement. Straight-line assignment, or a bounded loop over a list.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Let { name: String, value: Expr },
    ForEach {
        var: String,
        iter: Box<Expr>,
        body: Vec<Stmt>,
    },
    /// Report a typed summary to the user. Carries no free text from
    /// untrusted sources by construction: the interpreter rejects tainted
    /// values here.
    Report { value: Box<Expr> },
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    pub stmts: Vec<Stmt>,
}

impl Plan {
    /// Structural checks the parser cannot enforce on its own.
    ///
    /// There is no `eval`, no dynamic dispatch by string, no way to name a
    /// path, host, or command other than through a tool the broker holds.
    pub fn validate(&self) -> Result<(), PlanError> {
        let mut depth = 0usize;
        for stmt in &self.stmts {
            validate_stmt(stmt, &mut depth)?;
        }
        Ok(())
    }

    pub fn tool_names(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for stmt in &self.stmts {
            collect_tools(stmt, &mut out);
        }
        out
    }
}

fn collect_tools<'a>(stmt: &'a Stmt, out: &mut Vec<&'a str>) {
    match stmt {
        Stmt::Let { value, .. } => collect_tools_expr(value, out),
        Stmt::Report { value } => collect_tools_expr(value, out),
        Stmt::ForEach { iter, body, .. } => {
            collect_tools_expr(iter, out);
            for s in body {
                collect_tools(s, out);
            }
        }
    }
}

fn collect_tools_expr<'a>(expr: &'a Expr, out: &mut Vec<&'a str>) {
    match expr {
        Expr::ToolCall { tool, args } => {
            out.push(tool.as_str());
            for a in args {
                collect_tools_expr(&a.value, out);
            }
        }
        Expr::Field { base, .. } => collect_tools_expr(base, out),
        Expr::Extract { source, .. } => collect_tools_expr(source, out),
        Expr::Len(inner) => collect_tools_expr(inner, out),
        Expr::Literal(_) | Expr::Var(_) => {}
    }
}

fn validate_stmt(stmt: &Stmt, depth: &mut usize) -> Result<(), PlanError> {
    match stmt {
        Stmt::ForEach { iter, body, .. } => {
            validate_expr(iter, 0)?;
            *depth += 1;
            if *depth > MAX_LOOP_DEPTH {
                return Err(PlanError::LoopTooDeep { max: MAX_LOOP_DEPTH });
            }
            for s in body {
                validate_stmt(s, depth)?;
            }
            *depth -= 1;
            Ok(())
        }
        Stmt::Let { value, .. } => validate_expr(value, 0),
        Stmt::Report { value } => validate_expr(value, 0),
    }
}

/// Structural depth check.
///
/// `MAX_LOOP_DEPTH` bounds statement nesting, which is the cheap axis: the
/// parser builds the body of a block as a flat `Vec`, so nesting loops costs a
/// caller nothing to express and everything to validate. Expression nesting is
/// the opposite. `parse_postfix` builds `a.a.a...` iteratively, so a 20,000
/// segment projection chain parses in constant stack, and then both this
/// function and [`crate::interp::run`]'s `eval` walk it recursively. Without a
/// depth limit the deepest legal-looking expression is a stack overflow, which
/// is an abort rather than a catchable error, so `Limits` cannot help: it is
/// consulted during `run`, long after this recursion has already run.
///
/// `validate` is also the only gate on a `Plan` built programmatically, since
/// `run` calls it before executing anything.
fn validate_expr(expr: &Expr, depth: usize) -> Result<(), PlanError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(PlanError::ExprTooDeep {
            max: MAX_EXPR_DEPTH,
        });
    }
    match expr {
        Expr::ToolCall { args, .. } => args
            .iter()
            .try_for_each(|a| validate_expr(&a.value, depth + 1)),
        Expr::Field { base, .. } => validate_expr(base, depth + 1),
        Expr::Extract { source, .. } => validate_expr(source, depth + 1),
        Expr::Len(inner) => validate_expr(inner, depth + 1),
        Expr::Literal(_) | Expr::Var(_) => Ok(()),
    }
}

pub const MAX_LOOP_DEPTH: usize = 8;

/// Maximum expression nesting depth.
///
/// Bounds the three recursions driven purely by input length: the parser's
/// `LParen` arm, `validate_expr`, and `eval`. 64 is far above anything a
/// readable plan needs (a four-deep projection is typical) and far below the
/// ~10k frames that overflow a default thread stack.
pub const MAX_EXPR_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlanError {
    #[error("loop nesting exceeds maximum depth {max}")]
    LoopTooDeep { max: usize },
    #[error("expression nesting exceeds maximum depth {max}")]
    ExprTooDeep { max: usize },
    #[error("parse error at line {line}: {message}")]
    Parse { line: u32, message: String },
    #[error("undefined variable `{0}`")]
    UndefinedVar(String),
    #[error("variable `{name}` is bound more than once")]
    DuplicateBinding { name: String },
    #[error("cannot project field `{field}` from {found}")]
    BadField { field: String, found: &'static str },
    #[error("tool `{tool}` rejected: {reason}")]
    ToolRejected { tool: String, reason: String },
    #[error("policy denied `{op}`: {reason}")]
    PolicyDenied { op: String, reason: String },
    #[error("confirmation required for `{op}`")]
    ConfirmationRequired { op: String },
    #[error("confirmation denied for `{op}`")]
    ConfirmationDenied { op: String },
    #[error("reporting a tainted value would place untrusted bytes in the prompt")]
    TaintedReport,
    #[error("loop exceeded {max} iterations")]
    LoopBoundExceeded { max: usize },
    #[error("step budget of {max} exhausted")]
    StepBudgetExhausted { max: usize },
    #[error("schema `{schema}` is not registered")]
    UnknownSchema { schema: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_loops_are_rejected() {
        let mut stmt = Stmt::Let {
            name: "leaf".into(),
            value: Expr::Literal(Literal::Int(1)),
        };
        for _ in 0..MAX_LOOP_DEPTH + 1 {
            stmt = Stmt::ForEach {
                var: "i".into(),
                iter: Box::new(Expr::Len(Box::new(Expr::Var("leaf".into())))),
                body: vec![stmt],
            };
        }
        let plan = Plan {
            stmts: vec![stmt],
        };
        assert_eq!(
            plan.validate(),
            Err(PlanError::LoopTooDeep {
                max: MAX_LOOP_DEPTH
            })
        );
    }

    #[test]
    fn deeply_nested_field_chains_are_rejected_by_validate() {
        // `MAX_LOOP_DEPTH` does not help here: this is one statement, and the
        // depth is driven entirely by the tree the caller handed in.
        //
        // Past the limit but nowhere near a stack overflow. `Expr` nests through
        // `Box`, so dropping this tree is itself a recursive walk; `validate`
        // refusing it is not on its own enough to make an absurd tree safe to
        // build.
        let mut expr = Expr::Var("a".into());
        for _ in 0..512 {
            expr = Expr::Field {
                base: Box::new(expr),
                field: "b".into(),
            };
        }
        let plan = Plan {
            stmts: vec![Stmt::Report {
                value: Box::new(expr),
            }],
        };
        assert_eq!(
            plan.validate(),
            Err(PlanError::ExprTooDeep {
                max: MAX_EXPR_DEPTH
            })
        );
    }

    #[test]
    fn deeply_nested_tool_arguments_are_rejected_by_validate() {
        let mut expr = Expr::Literal(Literal::Int(1));
        for _ in 0..512 {
            expr = Expr::Len(Box::new(expr));
        }
        let plan = Plan {
            stmts: vec![Stmt::Let {
                name: "x".into(),
                value: expr,
            }],
        };
        assert_eq!(
            plan.validate(),
            Err(PlanError::ExprTooDeep {
                max: MAX_EXPR_DEPTH
            })
        );
    }

    #[test]
    fn ordinary_expression_depth_passes() {
        let plan = Plan {
            stmts: vec![Stmt::Report {
                value: Box::new(Expr::Len(Box::new(Expr::Field {
                    base: Box::new(Expr::Field {
                        base: Box::new(Expr::Extract {
                            source: Box::new(Expr::Var("page".into())),
                            schema: "Invoice".into(),
                        }),
                        field: "0".into(),
                    }),
                    field: "total".into(),
                }))),
            }],
        };
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn valid_plan_passes() {
        let plan = Plan {
            stmts: vec![Stmt::Let {
                name: "page".into(),
                value: Expr::ToolCall {
                    tool: "http.get".into(),
                    args: vec![Arg::new(
                        "url",
                        Expr::Literal(Literal::Str("https://example.com".into())),
                    )],
                },
            }],
        };
        assert!(plan.validate().is_ok());
        assert_eq!(plan.tool_names(), vec!["http.get"]);
    }
}
