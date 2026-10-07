use agentos_types::SourceId;

use crate::data::PlanData;

/// A literal in plan source.
///
/// `Quoted` exists so the parser round-trips quarantined text without ever
/// placing it in a trusted literal. Only the extractor can construct one.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Int(i64),
    Bool(bool),
    Str(String),
    Quoted { text: String, source: SourceId },
}

impl Literal {
    pub fn into_data(self) -> PlanData {
        match self {
            Literal::Int(i) => PlanData::Int(i),
            Literal::Bool(b) => PlanData::Bool(b),
            Literal::Str(s) => PlanData::Str(s),
            Literal::Quoted { text, source } => PlanData::quoted(text, source),
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
            validate_expr(iter)?;
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
        Stmt::Let { value, .. } => validate_expr(value),
        Stmt::Report { value } => validate_expr(value),
    }
}

fn validate_expr(expr: &Expr) -> Result<(), PlanError> {
    match expr {
        Expr::ToolCall { args, .. } => args.iter().try_for_each(|a| validate_expr(&a.value)),
        Expr::Field { base, .. } => validate_expr(base),
        Expr::Extract { source, .. } => validate_expr(source),
        Expr::Len(inner) => validate_expr(inner),
        Expr::Literal(_) | Expr::Var(_) => Ok(()),
    }
}

pub const MAX_LOOP_DEPTH: usize = 8;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlanError {
    #[error("loop nesting exceeds maximum depth {max}")]
    LoopTooDeep { max: usize },
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
