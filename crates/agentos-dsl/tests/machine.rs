//! Does the resumable machine agree with the recursive interpreter?
//!
//! # Why this test file exists
//!
//! `Machine` is a second implementation of the same language, written to support
//! resuming across a confirmation. A second implementation is a liability: the
//! only thing standing between it and a silent divergence is a test that runs both
//! and compares.
//!
//! So the bulk of this file is differential. Every program is run through
//! [`run`] and through [`Machine::advance`] in lockstep, and the outcomes must
//! match exactly: the same reports, the same events, and the same tool calls with
//! the same arguments.
//!
//! The rest is about resuming specifically, which `run` cannot do at all: that a
//! halt preserves state, that budgets are cumulative rather than reset, and that
//! resuming does not re-invoke a tool that already ran.

use std::collections::BTreeMap;
use std::rc::Rc;

use agentos_dsl::machine::Step;
use agentos_dsl::{parse, Extractor, Limits, Machine, PlanData, PlanError, PlanValue, ToolHost};

// ---------------------------------------------------------------------------
// Shared harness
// ---------------------------------------------------------------------------

type Log = Rc<std::cell::RefCell<Vec<String>>>;

/// A host that records every call and can be told to halt on a chosen one.
struct Recorder {
    /// Name of the tool that should refuse, if any.
    halt_on: Option<String>,
    log: Log,
}

impl Recorder {
    fn new(log: &Log) -> Self {
        Self {
            halt_on: None,
            log: log.clone(),
        }
    }

    fn halting(log: &Log, tool: &str) -> Self {
        Self {
            halt_on: Some(tool.to_string()),
            log: log.clone(),
        }
    }
}

impl ToolHost for Recorder {
    fn call(
        &mut self,
        tool: &str,
        args: &BTreeMap<String, PlanValue>,
    ) -> Result<PlanValue, PlanError> {
        let rendered: Vec<String> = args
            .iter()
            .map(|(k, v)| {
                let text = v.with_label_for_display(|d, _| format!("{d:?}"));
                format!("{k}={text}")
            })
            .collect();
        self.log
            .borrow_mut()
            .push(format!("{tool}({})", rendered.join(",")));

        if self.halt_on.as_deref() == Some(tool) {
            return Err(PlanError::ConfirmationRequired {
                op: format!("{tool}.?"),
            });
        }

        Ok(match tool {
            "http.get" => Val::tainted(
                agentos_types::SourceId::new(),
                PlanData::Quoted {
                    text: "INVOICE total=42 status=paid note=\"hi\"".into(),
                    source: agentos_types::SourceId::nil(),
                },
            ),
            "seed" => {
                let n = args
                    .get("n")
                    .and_then(|v| v.with_label_for_display(|d, _| d.as_i64()))
                    .unwrap_or(0);
                Val::trusted(PlanData::List((0..n.max(0)).map(PlanData::Int).collect()))
            }
            _ => Val::trusted(PlanData::Bool(true)),
        })
    }
}

use agentos_types::Val;

struct Invoices;

impl Extractor for Invoices {
    fn extract(&mut self, schema: &str, document: &PlanData) -> Result<PlanData, PlanError> {
        if schema != "Invoice" {
            return Err(PlanError::UnknownSchema {
                schema: schema.to_string(),
            });
        }
        let _ = document;
        Ok(PlanData::List(vec![PlanData::record(vec![
            ("total", PlanData::Int(42)),
            ("status", PlanData::Enum("paid".into())),
            // Text lifted out of the document. It is deliberately present so a
            // test can pass it to a sensitive argument, which is the case a
            // confirmation exists for.
            ("note", PlanData::Str("INVOICE total=42 status=paid note=\"hi\"".into())),
        ])]))
    }
}

/// Read an `Int` out of a plan value.
fn as_int(v: &PlanValue) -> i64 {
    v.with_label_for_display(|d, _| d.as_i64())
        .expect("expected an Int")
}

/// Everything observable about one execution.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    calls: Vec<String>,
    reports: Vec<String>,
    events: usize,
}

/// Run a program through the recursive interpreter.
///
/// Returns the outcome — the report summaries, or the error text — alongside
/// everything observable about how it got there.
fn run_recursive(source: &str) -> (Result<Vec<String>, String>, Observed) {
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut host = Recorder::new(&log);
    let mut ex = Invoices;
    let result = match agentos_dsl::run(&plan, &mut host, &mut ex, Limits::default()) {
        Ok(outcome) => {
            let summaries: Vec<String> = outcome.reports.iter().map(|r| r.summary.clone()).collect();
            let observed = Observed {
                calls: log.borrow().clone(),
                reports: summaries.clone(),
                events: outcome.events.len(),
            };
            (Ok(summaries), observed)
        }
        Err(e) => (
            Err(e.to_string()),
            Observed {
                calls: log.borrow().clone(),
                reports: Vec::new(),
                events: 0,
            },
        ),
    };
    result
}

/// Run the same program through the resumable machine.
fn run_machine(source: &str) -> (Result<Vec<String>, String>, Observed) {
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut host = Recorder::new(&log);
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");

    // Bounded so a program that never terminates fails loudly instead of hanging.
    let mut outcome: Result<Vec<String>, String> = Err("did not run".into());
    for _ in 0..10_000 {
        match machine.advance(&mut host, &mut ex) {
            Ok(Step::Advanced) => {}
            Ok(Step::Halted { op }) => {
                outcome = Err(format!("halted at {op}"));
                break;
            }
            Ok(Step::Done) => {
                outcome = Ok(machine.reports().iter().map(|r| r.summary.clone()).collect());
                break;
            }
            Err(e) => {
                outcome = Err(e.to_string());
                break;
            }
        }
    }
    // Bound to a local first: as a tail expression the `Ref` temporary would
    // outlive `log` and the borrow would fail.
    let calls = log.borrow().clone();
    let observed = Observed {
        calls,
        reports: machine.reports().iter().map(|r| r.summary.clone()).collect(),
        events: machine.events().len(),
    };
    (outcome, observed)
}

// ---------------------------------------------------------------------------
// Differential: the two implementations must agree
// ---------------------------------------------------------------------------

#[test]
fn the_machine_agrees_with_run_on_every_shape() {
    let programs: &[(&str, &str)] = &[
        (
            "fetch, extract, count",
            r#"let page = http.get(url = "https://x.test/1"); let inv = extract(Invoice, source = page); let n = len(inv); report(n);"#,
        ),
        (
            "report an int from a trusted literal",
            r#"let n = seed(n = 3); report(n);"#,
        ),
        (
            "report a bool from a tool",
            r#"let b = note(text = "x"); report(b);"#,
        ),
        (
            "loop with only report in the body",
            r#"let s = seed(n = 4); for i in s { report(i); }"#,
        ),
        (
            "nested loops",
            r#"let o = seed(n = 3); let i = seed(n = 2); for a in o { for b in i { report(b); } }"#,
        ),
        (
            "an empty loop",
            r#"let s = seed(n = 0); for a in s { report(a); }"#,
        ),
        (
            "tainted report is refused",
            r#"let page = http.get(url = "https://x.test/1"); let inv = extract(Invoice, source = page); report(inv.0.note);"#,
        ),
        (
            "an enum is refused even when trusted",
            r#"let e = enum.of(text = "x"); report(e);"#,
        ),
        (
            "a record is refused",
            r#"let r = lookup(key = "k"); report(r);"#,
        ),
        (
            "undefined variable",
            r#"report(missing);"#,
        ),
        (
            "duplicate binding",
            r#"let a = seed(n = 1); let a = seed(n = 2);"#,
        ),
        (
            "a loop shadowing an existing name",
            r#"let a = seed(n = 1); for a in seed(n = 2) { report(a); }"#,
        ),
        (
            "loop over a non-list",
            r#"for a in seed(n = 1) { report(a); }"#,
        ),
        (
            "a bad field",
            r#"let s = seed(n = 1); report(s.nope);"#,
        ),
        (
            "len of a non-list",
            r#"let b = note(text = "x"); report(len(b));"#,
        ),
        (
            "an unknown schema",
            r#"let page = http.get(url = "https://x.test/1"); let x = extract(Nope, source = page); report(x);"#,
        ),
        (
            "an unknown tool",
            r#"let x = no.such(tool = "a");"#,
        ),
        (
            "deep nesting",
            r#"let a = seed(n = 1); let b = seed(n = 1); let c = seed(n = 1); for x in a { for y in b { for z in c { report(z); } } }"#,
        ),
        (
            "loop body binding, which halts on the second iteration",
            r#"for a in seed(n = 2) { let w = note(text = "x"); }"#,
        ),
        (
            "step budget exhausted by a wide loop",
            r#"for a in seed(n = 400) { report(a); }"#,
        ),
        (
            "nested field projection",
            r#"let page = http.get(url = "https://x.test/1"); let inv = extract(Invoice, source = page); report(inv.0.total);"#,
        ),
        // The shapes below each contain the same tool more than once in one
        // statement, which is what made a name-keyed in-flight record serve one
        // call's result to another's argument. Added after that bug was found by
        // reading rather than by any failing test.
        (
            "the same tool twice in one statement",
            r#"let m = mail(subject = helper(key = "a"), body = helper(key = "b"));"#,
        ),
        (
            "the same tool twice, both arguments nested calls",
            r#"let m = mail(subject = wrap(inner = helper(key = "a")), body = wrap(inner = helper(key = "b")));"#,
        ),
        (
            "the same tool twice at different depths",
            r#"let m = mail(subject = helper(key = helper(key = "a")), body = helper(key = "b"));"#,
        ),
        (
            "a tool called in an argument and again as the loop source",
            r#"let s = seed(n = 2); for i in s { report(helper(key = "x")); }"#,
        ),
    ];

    let mut failures = Vec::new();
    for (name, source) in programs {
        // Every program must parse. A corpus entry that stopped parsing would
        // otherwise be compared as two identical parse failures and read as
        // agreement — a test that passes because it stopped testing anything.
        if let Err(e) = parse(source) {
            failures.push(format!("{name}: does not parse: {e}"));
            continue;
        }
        // Compared inside `catch_unwind` because a program that overflows the
        // recursion budget panics rather than returning an error, and a panic in
        // one implementation but not the other is a disagreement worth reporting
        // rather than a reason to abort the whole comparison.
        let a = std::panic::catch_unwind(|| run_recursive(source));
        let b = std::panic::catch_unwind(|| run_machine(source));
        match (a, b) {
            (Ok((ar, a_obs)), Ok((br, b_obs))) => {
                if ar != br {
                    failures.push(format!("{name}: outcome run={ar:?} machine={br:?}"));
                }
                if a_obs.calls != b_obs.calls {
                    failures.push(format!(
                        "{name}: tool calls run={:?} machine={:?}",
                        a_obs.calls, b_obs.calls
                    ));
                }
                // Reports and events are only comparable when the program
                // succeeded. `run` returns `Err` and discards its whole outcome,
                // so on a failure there is nothing to compare against — the
                // machine's accumulation of reports up to the failure is a
                // capability the recursive interpreter does not have, not a
                // disagreement about what the program did.
                if ar.is_ok() {
                    if a_obs.reports != b_obs.reports {
                        failures.push(format!(
                            "{name}: reports run={:?} machine={:?}",
                            a_obs.reports, b_obs.reports
                        ));
                    }
                    if a_obs.events != b_obs.events {
                        failures.push(format!(
                            "{name}: events run={} machine={}",
                            a_obs.events, b_obs.events
                        ));
                    }
                }
            }
            (Ok(_), Err(_)) => failures.push(format!("{name}: machine panicked, run did not")),
            (Err(_), Ok(_)) => failures.push(format!("{name}: run panicked, machine did not")),
            (Err(_), Err(_)) => {}
        }
    }
    assert!(
        failures.is_empty(),
        "the two implementations disagree:\n  {}",
        failures.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Resuming
// ---------------------------------------------------------------------------

#[test]
fn a_halt_preserves_the_variables_and_resumes_from_the_same_call() {
    let source = r#"let page = http.get(url = "https://x.test/1"); let inv = extract(Invoice, source = page); let m = mail(to = inv.0.note, subject = "s");"#;
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut host = Recorder::halting(&log, "mail");
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");

    // Step until the halt.
    let mut halted = None;
    for _ in 0..100 {
        match machine.advance(&mut host, &mut ex).expect("advance") {
            Step::Advanced => {}
            Step::Halted { op } => {
                halted = Some(op);
                break;
            }
            Step::Done => panic!("expected a halt"),
        }
    }
    let op = halted.expect("the plan must halt");

    // The earlier statements ran, exactly once.
    // Every argument is rendered, so both `subject` and `to` appear. Compared as
    // a set of rendered calls rather than an exact ordering assumption beyond
    // what the recorder guarantees.
    let calls = log.borrow().clone();
    assert_eq!(calls.len(), 2, "expected one fetch and one mail: {calls:?}");
    assert!(
        calls[0].starts_with("http.get(url="),
        "the fetch runs first: {calls:?}"
    );
    assert!(
        calls[1].starts_with("mail(") && calls[1].contains("to=Str(\"INVOICE"),
        "the mail carries the extracted, tainted note: {calls:?}"
    );
    assert!(machine.bound("inv").is_some(), "state must survive the halt");
    let steps_at_halt = machine.steps_spent();

    // Resuming re-evaluates the halting statement only. The fetch must not run a
    // second time: its result is already in `inv`.
    let mut host2 = Recorder::new(&log);
    assert_eq!(machine.advance(&mut host2, &mut ex).expect("advance"), Step::Advanced);
    assert_eq!(
        log.borrow().len(),
        3,
        "resume must add exactly the retry of the halting call, not a refetch: {log:?}"
    );
    assert!(
        machine.steps_spent() > steps_at_halt,
        "budget must be carried, not reset"
    );
    assert_eq!(op, "mail.?", "the op names the halted call");
}

/// A resume must not re-spend the step budget.
///
/// The escalation hole. A plan that halts ten times must not get ten times the
/// work; if `steps` were per-`advance` rather than per-machine, a plan could
/// loop between halt and resume indefinitely and never trip the budget.
#[test]
fn a_resume_does_not_reset_the_step_budget() {
    let plan = parse(r#"let m = mail(to = "x");"#).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut machine = Machine::start_with(
        &plan,
        Limits {
            max_steps: 4,
            max_loop_iterations: 100,
        },
    )
    .expect("starts");

    let mut halts = 0usize;
    let mut budget_error = None;
    for _ in 0..50 {
        let mut host = Recorder::halting(&log, "mail");
        let mut ex = Invoices;
        match machine.advance(&mut host, &mut ex) {
            Ok(Step::Advanced) | Ok(Step::Done) => {}
            Ok(Step::Halted { .. }) => halts += 1,
            Err(PlanError::StepBudgetExhausted { .. }) => {
                budget_error = Some(machine.steps_spent());
                break;
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
    assert!(
        budget_error.is_some(),
        "the step budget must eventually bite after repeated halts, otherwise a plan can \
         halt and resume forever"
    );
    assert!(
        halts >= 1,
        "the test should have exercised at least one halt before the budget ran out"
    );
}

/// A tool used inside a halting statement's arguments is not re-invoked.
///
/// The double-execution hazard in miniature: `mail(to = helper(key = "x"))` has a
/// tool call in argument position, and re-evaluating the statement on resume would
/// invoke `helper` again.
#[test]
fn a_nested_tool_call_in_a_halting_statement_is_not_re_invoked() {
    let source = r#"let m = mail(to = helper(key = "k"));"#;
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut ex = Invoices;

    let mut machine = Machine::start(&plan).expect("starts");
    {
        let mut host = Recorder::halting(&log, "mail");
        assert!(matches!(
            machine.advance(&mut host, &mut ex).expect("advance"),
            Step::Halted { .. }
        ));
    }
    assert_eq!(
        log.borrow().len(),
        2,
        "helper and mail should each have run once before the halt: {log:?}"
    );

    {
        let mut host = Recorder::new(&log);
        assert!(matches!(
            machine.advance(&mut host, &mut ex).expect("advance"),
            Step::Advanced
        ));
    }
    let calls = log.borrow().clone();
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("helper(")).count(),
        1,
        "the nested tool must not run again on resume: {calls:?}"
    );
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("mail(")).count(),
        2,
        "the halting call itself is retried, which is the point: {calls:?}"
    );
}

/// Two calls to the same tool in one statement must not share a cached argument.
///
/// The in-flight record is keyed by call site, not by tool name. Keying it by
/// `(tool, arg index)` looks unambiguous because a statement names each argument
/// once — but that only holds for the *outermost* call. A tool nested in an
/// argument position restarts the index at zero, so this used to collide:
///
/// ```text
/// let m = mail(subject = helper(key = "a"), body = helper(key = "b"));
/// ```
///
/// `body` would be given `helper`'s result for `"a"`, and the second `helper`
/// would never run.
///
/// The security consequence is worse than a wrong value. If the first call's
/// result is trusted and the second's is tainted, the cache hands the trusted
/// value to the position the tainted one belongs in — a laundering path, and one
/// that does not need an injection to fire.
#[test]
fn two_calls_to_one_tool_in_a_statement_do_not_share_a_cached_argument() {
    let source = r#"let m = mail(subject = helper(key = "a"), body = helper(key = "b"));"#;
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut host = Recorder::new(&log);
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");
    assert_eq!(machine.advance(&mut host, &mut ex).expect("advance"), Step::Advanced);

    let calls = log.borrow().clone();
    let helpers: Vec<&String> = calls.iter().filter(|c| c.starts_with("helper(")).collect();
    assert_eq!(
        helpers,
        [r#"helper(key=Str("a"))"#, r#"helper(key=Str("b"))"#],
        "both helper calls must run, with their own arguments"
    );
    // Argument order is alphabetical because the recorder renders a `BTreeMap`.
    assert_eq!(
        calls.last().unwrap(),
        r#"mail(body=Bool(true),subject=Bool(true))"#,
        "the outer call receives both results, not one result twice"
    );
}

/// A halt on the second of two same-tool calls must not serve the first's result.
///
/// A `for` body may not contain a `let` — the binding collides on the second
/// iteration — so the halt has to come from a tool call in `report` position.
/// That is enough: `report` evaluates its expression before deciding whether it
/// may summarise it, so `report(mail(...))` reaches the host and can halt there.
///
/// The assertion is on *which item the loop is on*, observed through the loop
/// variable, because the report itself summarises the tool result rather than the
/// item. A machine that restarted the loop on resume would produce the same three
/// reports; only the item sequence distinguishes the two.
#[test]
fn a_halt_inside_a_loop_resumes_at_the_same_item() {
    let source = r#"let s = seed(n = 3); for i in s { report(mail(to = "x")); }"#;
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");

    // Phase one: run until the halt, with the host refusing `mail`.
    let halted_at = loop {
        let mut host = Recorder::halting(&log, "mail");
        match machine.advance(&mut host, &mut ex) {
            Ok(Step::Advanced) => {}
            Ok(Step::Halted { .. }) => {
                break as_int(machine.bound("i").expect("loop var is bound at a halt"));
            }
            Ok(Step::Done) => panic!("expected a halt"),
            Err(e) => panic!("unexpected before the halt: {e}"),
        }
    };

    // Phase two: resume with a host that allows `mail`, sampling the loop
    // variable after each advance.
    let mut items_seen: Vec<i64> = Vec::new();
    for turn in 0..100 {
        let mut host = Recorder::new(&log);
        match machine.advance(&mut host, &mut ex) {
            Ok(Step::Advanced) => {}
            Ok(Step::Done) => break,
            Ok(Step::Halted { .. }) => panic!("the resumed run halted again"),
            Err(e) => panic!("unexpected on turn {turn}: {e}"),
        }
        if let Some(item) = machine.bound("i") {
            items_seen.push(as_int(item));
        }
    }

    assert_eq!(halted_at, 0, "the halt should land on the first item");
    // Every item in order, each exactly once. Item 0 appears again because the
    // retry of the halted call happens while the loop is still on item 0 —
    // that is the point. The failure this rules out is a machine that restarts
    // the loop, which would visit 0,1,2 *and then* 0,1,2 again.
    assert_eq!(
        items_seen,
        [0, 1, 2],
        "the loop must visit each item once, in order, across the resume"
    );
    assert_eq!(
        machine.reports().len(),
        3,
        "every item reports exactly once, including the one that halted: a \
         retried report statement must not append a second report"
    );
    assert!(
        machine.bound("i").is_none(),
        "the loop variable is unbound once the loop finishes"
    );
}

/// An empty program finishes immediately.
#[test]
fn an_empty_program_is_done() {
    let plan = parse("").expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut host = Recorder::new(&log);
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");
    assert_eq!(machine.advance(&mut host, &mut ex).expect("advance"), Step::Done);
}

/// Reports survive a resume and are not duplicated by it.
#[test]
fn reports_are_not_duplicated_by_a_resume() {
    // The `;` after the loop's closing brace is required: statements are
    // semicolon-separated and the parser does not guess at a boundary.
    let source = r#"let s = seed(n = 2); for i in s { report(i); }; let m = mail(to = "x");"#;
    let plan = parse(source).expect("parses");
    let log: Log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut ex = Invoices;
    let mut machine = Machine::start(&plan).expect("starts");

    for _ in 0..100 {
        let mut host = Recorder::halting(&log, "mail");
        match machine.advance(&mut host, &mut ex) {
            Ok(Step::Advanced) => {}
            Ok(Step::Halted { .. }) => break,
            Ok(Step::Done) => panic!("expected a halt"),
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    let before = machine.reports().len();
    {
        let mut host = Recorder::new(&log);
        machine.advance(&mut host, &mut ex).expect("advance");
    }
    assert_eq!(
        machine.reports().len(),
        before,
        "resuming must not replay the statements before the halt"
    );
}