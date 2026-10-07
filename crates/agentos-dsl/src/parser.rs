use crate::ast::{Arg, Expr, Literal, Plan, PlanError, Stmt};

/// Tokenizer for the plan language.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Str(String),
    Dot,
    Comma,
    Eq,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Semi,
}

fn lex(src: &str) -> Result<Vec<(Tok, u32)>, PlanError> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1u32;

    while i < b.len() {
        let c = b[i];
        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '#' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        let tok = match c {
            '.' => {
                i += 1;
                Tok::Dot
            }
            ',' => {
                i += 1;
                Tok::Comma
            }
            '=' => {
                i += 1;
                Tok::Eq
            }
            '(' => {
                i += 1;
                Tok::LParen
            }
            ')' => {
                i += 1;
                Tok::RParen
            }
            '{' => {
                i += 1;
                Tok::LBrace
            }
            '}' => {
                i += 1;
                Tok::RBrace
            }
            '[' => {
                i += 1;
                Tok::LBracket
            }
            ']' => {
                i += 1;
                Tok::RBracket
            }
            ';' => {
                i += 1;
                Tok::Semi
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= b.len() {
                        return Err(PlanError::Parse {
                            line,
                            message: "unterminated string".into(),
                        });
                    }
                    if b[i] == quote {
                        i += 1;
                        break;
                    }
                    if b[i] == '\\' && i + 1 < b.len() {
                        let esc = b[i + 1];
                        s.push(match esc {
                            'n' => '\n',
                            't' => '\t',
                            '\\' => '\\',
                            '"' => '"',
                            '\'' => '\'',
                            other => other,
                        });
                        i += 2;
                        continue;
                    }
                    s.push(b[i]);
                    i += 1;
                }
                Tok::Str(s)
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let s: String = b[start..i].iter().collect();
                match s.parse::<i64>() {
                    Ok(n) => Tok::Int(n),
                    Err(_) => {
                        return Err(PlanError::Parse {
                            line,
                            message: format!("integer out of range: {s}"),
                        })
                    }
                }
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                    i += 1;
                }
                Tok::Ident(b[start..i].iter().collect())
            }
            other => {
                return Err(PlanError::Parse {
                    line,
                    message: format!("unexpected character `{other}`"),
                })
            }
        };
        out.push((tok, line));
    }
    Ok(out)
}

struct Parser {
    toks: Vec<(Tok, u32)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|(t, _)| t)
    }

    fn line(&self) -> u32 {
        self.toks.get(self.pos).map(|(_, l)| *l).unwrap_or(0)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).map(|(t, _)| t.clone());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: Tok) -> Result<(), PlanError> {
        if self.eat(&t) {
            Ok(())
        } else {
            Err(PlanError::Parse {
                line: self.line(),
                message: format!("expected {t:?}, found {:?}", self.peek()),
            })
        }
    }

    fn ident(&mut self) -> Result<String, PlanError> {
        match self.bump() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(PlanError::Parse {
                line: self.line(),
                message: format!("expected identifier, found {other:?}"),
            }),
        }
    }

    fn keywords_are_idents(s: &str) -> bool {
        matches!(s, "let" | "for" | "in" | "extract" | "report" | "len" | "true" | "false")
    }

    /// True when the tokens after the current identifier spell
    /// `( . Ident )* (`, meaning a dotted name is being called rather than
    /// projected. Scanning without consuming keeps `a.b` and `a.b()` distinct,
    /// which single-token lookahead cannot do.
    fn dotted_call_ahead(&self) -> bool {
        let mut i = self.pos;
        while matches!(self.toks.get(i), Some((Tok::Dot, _)))
            && matches!(self.toks.get(i + 1), Some((Tok::Ident(_), _)))
        {
            i += 2;
        }
        matches!(self.toks.get(i), Some((Tok::LParen, _)))
    }

    /// Consume `( . Ident )*` and append it to an identifier already read.
    fn dotted_name(&mut self, first: String) -> String {
        let mut name = first;
        while matches!(self.peek(), Some(Tok::Dot))
            && matches!(self.toks.get(self.pos + 1), Some((Tok::Ident(_), _)))
        {
            // Step over the dot to the identifier and take that.
            self.pos += 1;
            if let Some(Tok::Ident(s)) = self.bump() {
                name.push('.');
                name.push_str(&s);
            }
        }
        name
    }
}

/// Parse a plan.
///
/// The grammar is deliberately small: straight-line `let` bindings, bounded
/// `for` loops over lists, an `extract` form that routes untrusted input to the
/// quarantined processor, and `report` for user-facing summaries. There is no
/// function definition, no recursion, no dynamic evaluation, and no syntax for
/// naming a filesystem path or network host except as a tool argument.
pub fn parse(src: &str) -> Result<Plan, PlanError> {
    let toks = lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let mut stmts = Vec::new();
    while p.pos < p.toks.len() {
        stmts.push(parse_stmt(&mut p)?);
        if p.eat(&Tok::Semi) {
            continue;
        }
        if p.pos < p.toks.len() && p.peek() != Some(&Tok::Semi) {
            return Err(PlanError::Parse {
                line: p.line(),
                message: "expected `;` between statements".into(),
            });
        }
    }
    let plan = Plan { stmts };
    plan.validate()?;
    Ok(plan)
}

fn parse_stmt(p: &mut Parser) -> Result<Stmt, PlanError> {
    let kw = p.ident()?;
    match kw.as_str() {
        "let" => {
            let name = p.ident()?;
            p.expect(Tok::Eq)?;
            let value = parse_expr(p)?;
            Ok(Stmt::Let {
                name,
                value,
            })
        }
        "report" => {
            let value = parse_expr(p)?;
            Ok(Stmt::Report {
                value: Box::new(value),
            })
        }
        "for" => {
            let var = p.ident()?;
            let in_kw = p.ident()?;
            if in_kw != "in" {
                return Err(PlanError::Parse {
                    line: p.line(),
                    message: "expected `in`".into(),
                });
            }
            let iter = parse_expr(p)?;
            p.expect(Tok::LBrace)?;
            let mut body = Vec::new();
            while !p.eat(&Tok::RBrace) {
                if p.pos >= p.toks.len() {
                    return Err(PlanError::Parse {
                        line: p.line(),
                        message: "unterminated block".into(),
                    });
                }
                body.push(parse_stmt(p)?);
                p.eat(&Tok::Semi);
            }
            Ok(Stmt::ForEach {
                var,
                iter: Box::new(iter),
                body,
            })
        }
        other => Err(PlanError::Parse {
            line: p.line(),
            message: format!("unexpected statement `{other}`"),
        }),
    }
}

fn parse_expr(p: &mut Parser) -> Result<Expr, PlanError> {
    let base = parse_primary(p)?;
    Ok(parse_postfix(p, base))
}

fn parse_postfix(p: &mut Parser, mut expr: Expr) -> Expr {
    while let Some(Tok::Dot) = p.peek() {
        p.pos += 1;
        let field = match p.bump() {
            Some(Tok::Ident(s)) => s,
            Some(Tok::Int(n)) => n.to_string(),
            other => {
                return Expr::Field {
                    base: Box::new(expr),
                    field: format!("<invalid {other:?}>"),
                }
            }
        };
        expr = Expr::Field {
            base: Box::new(expr),
            field,
        };
    }
    expr
}

fn parse_primary(p: &mut Parser) -> Result<Expr, PlanError> {
    match p.peek().cloned() {
        Some(Tok::Int(n)) => {
            p.pos += 1;
            Ok(Expr::Literal(Literal::Int(n)))
        }
        Some(Tok::Str(s)) => {
            p.pos += 1;
            Ok(Expr::Literal(Literal::Str(s)))
        }
        Some(Tok::LParen) => {
            p.pos += 1;
            let e = parse_expr(p)?;
            p.expect(Tok::RParen)?;
            Ok(e)
        }
        Some(Tok::Ident(name)) => {
            p.pos += 1;
            match name.as_str() {
                "true" => return Ok(Expr::Literal(Literal::Bool(true))),
                "false" => return Ok(Expr::Literal(Literal::Bool(false))),
                "len" => {
                    p.expect(Tok::LParen)?;
                    let inner = parse_expr(p)?;
                    p.expect(Tok::RParen)?;
                    return Ok(Expr::Len(Box::new(inner)));
                }
                "extract" => {
                    p.expect(Tok::LParen)?;
                    let schema = p.ident()?;
                    let mut source = None;
                    if p.eat(&Tok::Comma) {
                        if let Some(Tok::Ident(kw)) = p.peek().cloned() {
                            if kw == "source" {
                                p.pos += 1;
                                p.expect(Tok::Eq)?;
                                source = Some(parse_expr(p)?);
                            }
                        }
                    }
                    p.expect(Tok::RParen)?;
                    let source = source.ok_or(PlanError::Parse {
                        line: p.line(),
                        message: "extract requires `source = <expr>`".into(),
                    })?;
                    return Ok(Expr::Extract {
                        source: Box::new(source),
                        schema,
                    });
                }
                _ => {}
            }
            if Parser::keywords_are_idents(&name) {
                return Ok(Expr::Var(name));
            }
            if p.dotted_call_ahead() {
                let tool = p.dotted_name(name);
                p.expect(Tok::LParen)?;
                let mut args = Vec::new();
                while !p.eat(&Tok::RParen) {
                    let arg_name = p.ident()?;
                    p.expect(Tok::Eq)?;
                    let value = parse_expr(p)?;
                    args.push(Arg::new(arg_name, value));
                    if !p.eat(&Tok::Comma) {
                        p.expect(Tok::RParen)?;
                        break;
                    }
                }
                return Ok(Expr::ToolCall { tool, args });
            }
            Ok(Expr::Var(name))
        }
        other => Err(PlanError::Parse {
            line: p.line(),
            message: format!("unexpected token {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_plan() {
        let src = r#"
            let page = http.get(url = "https://example.com/invoice");
            let inv = extract(Invoice, source = page);
            let n = len(inv);
            report(n);
        "#;
        let plan = parse(src).expect("parses");
        assert_eq!(plan.stmts.len(), 4);
        assert_eq!(plan.tool_names(), vec!["http.get"]);
    }

    #[test]
    fn field_projection_works() {
        let plan = parse("let t = x.total;").unwrap();
        let Stmt::Let { value, .. } = &plan.stmts[0] else {
            panic!("expected let");
        };
        assert!(matches!(value, Expr::Field { field, .. } if field == "total"));
    }

    #[test]
    fn loop_body_parses() {
        let plan = parse(
            r#"
            for item in items {
                let s = note(id = item.id);
            }
            "#,
        )
        .unwrap();
        assert_eq!(plan.tool_names(), vec!["note"]);
    }

    #[test]
    fn no_semicolon_between_statements_is_an_error() {
        assert!(parse("let a = len(b) let c = len(d)").is_err());
    }

    #[test]
    fn extract_without_source_is_an_error() {
        assert!(parse("let x = extract(Invoice);").is_err());
    }

    #[test]
    fn unterminated_string_is_an_error() {
        assert!(parse("let x = http.get(url = \"unterminated);").is_err());
    }

    #[test]
    fn statements_are_not_silent_about_unknown_keywords() {
        assert!(parse("exec(\"rm -rf /\");").is_err());
    }

    #[test]
    fn comments_and_escapes_lex() {
        let plan = parse("# leading\nlet x = note(msg = \"a\\nb\"); # trailing").unwrap();
        assert_eq!(plan.stmts.len(), 1);
    }
}
