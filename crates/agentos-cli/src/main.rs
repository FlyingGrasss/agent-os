//! The AgentOS command line.
//!
//! # What this is for
//!
//! Everything else in the workspace is a library. This is the part a person
//! touches: it plans a task with a real model, runs it through the real policy
//! engine, and asks when something needs approval.
//!
//! It holds no authority of its own. It registers tools with narrow grants, hands
//! the plan to `Session`, and prints what happened. Removing this file would not
//! weaken the system, because every decision is made in the crates below.
//!
//! # Usage
//!
//! ```text
//! agentos run --write-root DIR [--allow-host HOST]... "task in plain words"
//! agentos check
//! ```
//!
//! `check` reports what this machine can actually do, rather than what the project
//! hopes it can. It is the first thing to run when something is unavailable,
//! because "the sandbox did nothing" and "the sandbox never started" look
//! identical from the outside and have opposite causes.
//!
//! # Safety properties this program is responsible for
//!
//! - **No shell.** There is no `Command::new("sh")` anywhere. Arguments come from
//!   a model and from documents; giving them to a shell would hand an attacker
//!   code execution on the machine running the agent.
//! - **The task is never passed to anything but the planner**, as a
//!   `Trusted<String>`.
//! - **Confirmation is a human, or it is nothing.** See [`agentos_cli::Decision`].
//! - **Grafts are explicit.** `--allow-host` and `--write-root` are the only ways
//!   authority widens, and both are typed on a command line by a person.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentos_cli::{ask_on_stdin, Decision, client::{dispatch, check, ExecuteParams, Grants}, util::user_id};
use agentos_core::{ModelExtractor, Outcome, Planner, PlanOutcome, Session};
use agentos_dsl::PlanError;
use agentos_infer::{Ollama, RoleModels};
use agentos_pager::PagerConfig;
use agentos_policy::{PolicyEngine, RuleSet};
use agentos_tools::audit::{AuditLog, AuditSink, FileSink, SystemClock};
use agentos_tools::http::{install_policy_rules, FetchGrant, HttpFetch};
use agentos_tools::{FsWrite, PolicyHost, WriteGrant};
use agentos_types::{ControllerAuthority, Origin, Quarantined, SourceId, Trusted, UserId, Val};

const USAGE: &str = "\
agentos - run a task with real privileges and a real policy engine

USAGE:
  agentos run [OPTIONS] <TASK>
  agentos check

OPTIONS:
  --model <NAME>          Ollama model for the planner (default llama3.2:3b)
  --allow-host <HOST>     permit fetching this host (repeatable, https only)
  --write-root <DIR>      permit writing inside this directory
  --no-fetch              register no network tool at all

`check` reports what this machine can actually do. Run it first if something
seems unavailable: a sandbox that did nothing and a sandbox that never started
look identical from the outside.
";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("agentos: {message}");
            eprintln!("\n{USAGE}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<std::process::ExitCode, String> {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return Ok(std::process::ExitCode::from(2));
    };

    match command.as_str() {
        "run" => cmd_run(&args[1..]),
        "check" => cmd_check(),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(std::process::ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/// Report what this machine can do.
///
/// Written to be read by someone debugging a refusal. Every line is either a fact
/// this process established, or a stated limitation -- never an assumption. The
/// distinction matters: "the sandbox is unavailable" and "the sandbox is not
/// implemented" call for completely different responses, and a tool that blurs
/// them sends people to fix the wrong thing.
fn cmd_check() -> Result<std::process::ExitCode, String> {
    // Try the daemon first
    if let Ok(code) = check() {
        return Ok(code);
    }

    // Fall back to local check
    eprintln!("agentos: daemon not reachable, falling back to local check");
    cmd_check_local()
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Options {
    task: Option<String>,
    model: String,
    allow_hosts: Vec<String>,
    write_root: Option<PathBuf>,
    fetch: bool,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        model: "llama3.2:3b".to_string(),
        fetch: true,
        ..Options::default()
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg {
            "--model" => o.model = value()?,
            "--allow-host" => o.allow_hosts.push(value()?),
            "--write-root" => o.write_root = Some(PathBuf::from(value()?)),
            "--no-fetch" => o.fetch = false,
            other if other.starts_with("--") => return Err(format!("unknown option `{other}`")),
            other => o.task = Some(other.to_string()),
        }
        i += 1;
    }
    Ok(o)
}

fn cmd_run(args: &[String]) -> Result<std::process::ExitCode, String> {
    let options = parse_options(args)?;
    let task = options
        .task
        .ok_or_else(|| "no task given".to_string())?;

    // Build grants from options for the daemon
    let grants = ExecuteParams {
        task: task.clone(),
        grants: Grants {
            hosts: options.allow_hosts.clone(),
            write_roots: options.write_root.as_ref().map(|p| p.to_string_lossy().to_string()).into_iter().collect(),
            send_email: false, // not implemented in CLI yet
        },
        timeout_secs: 300,
    };

    // Try to dispatch to the daemon first
    match dispatch(task.clone(), grants) {
        Ok(code) => return Ok(code),
        Err(e) => eprintln!("agentos: daemon error: {}", e),
    }

    // Fall back to local execution if daemon is not reachable
    eprintln!("agentos: daemon not reachable, falling back to local execution");
    cmd_run_local(args)
}

/// One user, fixed.
///
/// The CLI runs as one person on one machine. Deriving a real identity from the
/// OS would be the right thing for a multi-user daemon and is out of scope here;
/// what matters is that it is *deterministic within a run*, so the audit trail's
/// origin column means something.
/// Local execution fallback (the original cmd_run).
fn cmd_run_local(args: &[String]) -> Result<std::process::ExitCode, String> {
    let options = parse_options(args)?;
    let task = options
        .task
        .ok_or_else(|| "no task given".to_string())?;

    let user = user_id();

    // --- the audit log -----------------------------------------------------
    //
    // Append-only and on disk before anything happens, because invariant I6 says
    // every action is recorded *before* it executes. A log written afterwards is
    // a log that can be lost along with the evidence.
    let sink: Box<dyn AuditSink> =
        Box::new(FileSink::open("agentos-audit.log").map_err(|e| {
            format!("cannot open the audit log: {e}\n\
                    (invariant I6 requires it to exist before anything runs, so \
                    this refuses rather than continuing without one)")
        })?);
    let audit = AuditLog::new(sink, Box::new(SystemClock));

    // --- policy ------------------------------------------------------------
    //
    // `RuleSet::default` is the starting point and every tool's own installer
    // adds its rules. A tool with no rule for an argument defaults to Confirm,
    // so a forgotten rule fails toward asking a person rather than toward acting.
    let mut rules = RuleSet::default();
    if options.fetch {
        install_policy_rules(&mut rules);
    }

    let mut host = PolicyHost::new(PolicyEngine::new(rules), audit, user);

    // Constrain the session to what the user actually typed. Built from the task
    // alone and never from a document, so a hostile page cannot widen it.
    host.pin_intent(&task);

    if options.fetch {
        let grant = FetchGrant::new(options.allow_hosts.iter().map(String::as_str))
            .map_err(|e| format!("bad --allow-host: {e}"))?;
        if grant.hosts().is_empty() {
            return Err(
                "--allow-host is required for network access; pass one or more, \
                 or --no-fetch"
                    .into(),
            );
        }
        host.register(Box::new(HttpFetch::new(grant)));
    }

    if let Some(root) = options.write_root.as_ref() {
        let grant = WriteGrant::new(root).map_err(|e| format!("bad --write-root: {e}"))?;
        host.register(Box::new(FsWrite::new(grant)));
    }

    // --- plan --------------------------------------------------------------
    //
    // The task becomes a `Trusted<String>` here, at the boundary, and there is no
    // parameter through which a document's bytes could arrive instead.
    let request = Trusted::inherited(Origin::User(user), task.clone());
    let mut backend = Ollama::new(RoleModels::Shared {
        model: options.model.clone(),
    });

    println!("planning...");
    let plan = {
        let mut planner = Planner::new(&mut backend, user);
        match planner.plan(&request) {
            Ok(PlanOutcome::Planned(p)) => p,
            Ok(PlanOutcome::Unusable { reason }) => {
                println!("\nthe model did not produce a usable plan: {reason}");
                println!("(this is a model-quality result, not a security refusal)");
                return Ok(std::process::ExitCode::from(1));
            }
            Err(e) => return Err(format!("planner failed: {e}")),
        }
    };

    println!("running...");
    let mut schemas = BTreeMap::new();
    schemas.insert(
        "Document".to_string(),
        serde_json::json!({
            "title": "Document",
            "type": "object",
            "properties": { "text": { "type": "string", "maxLength": 4000 } }
        }),
    );
    let mut passthrough = Passthrough;
    let mut extractor = ModelExtractor::new(&mut passthrough, schemas);

    let mut session = Session::new(user, &mut host)
        .with_pager(
            &Trusted::inherited(Origin::Controller(ControllerAuthority::issue()), task.clone()),
            PagerConfig::default(),
        )
        .map_err(|e| format!("could not start the context pager: {e}"))?;

    let outcome = session
        .run(&plan, &mut extractor, |request| {
            // `ask_on_stdin` returns a refusal when stdin is not a terminal, so
            // this closure is a human or it is nothing. There is no branch here
            // that approves without one, and adding one would be the single
            // highest-consequence change this file could receive.
            ask_on_stdin(request) == Decision::Approved
        })
        .map_err(|e| format!("session failed: {e}"))?;

    println!();
    match outcome {
        Outcome::Completed { reports } => {
            println!("done.");
            for report in &reports {
                println!("  {report}");
            }
            Ok(std::process::ExitCode::SUCCESS)
        }
        Outcome::Refused { op } => {
            println!("refused: {op}");
            println!("nothing was sent or written.");
            // Distinct exit code from a failure, because a refusal is the system
            // working and a script should be able to tell the difference.
            Ok(std::process::ExitCode::from(3))
        }
        Outcome::ConfirmationLimit { asked } => {
            println!("stopped after {asked} confirmation(s); the loop gave up.");
            println!("this is NOT a refusal -- no decision was made.");
            Ok(std::process::ExitCode::from(4))
        }
        Outcome::Failed { error } => {
            println!("stopped: {error}");
            match error {
                PlanError::PolicyDenied { op, reason } => {
                    println!("  {op}: {reason}");
                    println!("  refused by policy, with no human involved.");
                }
                other => println!("  ({other}) -- not a policy denial; see the type."),
            }
            Ok(std::process::ExitCode::from(1))
        }
    }
}

/// Local check fallback (the original cmd_check).
fn cmd_check_local() -> Result<std::process::ExitCode, String> {
    println!("AgentOS environment\n");

    println!("user");
    println!("  interactive stdin:   {}", yes_no(agentos_cli::stdin_is_interactive()));
    if !agentos_cli::stdin_is_interactive() {
        println!(
            "    -> confirmations will be REFUSED. There is no person to ask, so\n\
             there is no approval. This is deliberate: a scripted run must\n\
             not be able to log approvals nobody gave."
        );
    }

    println!("\nmodel");
    let model = std::env::var("AGENTOS_MODEL").unwrap_or_else(|_| "llama3.2:3b".into());
    let backend = Ollama::new(RoleModels::Shared {
        model: model.clone(),
    });
    match backend.probe() {
        Ok(models) => {
            if models.iter().any(|m| m.starts_with(&model)) {
                println!("  {model}: available");
            } else {
                println!("  {model}: NOT PULLED");
                println!("    available: {models:?}");
                println!("    -> the planner will not run. `ollama pull {model}`.");
            }
        }
        Err(e) => {
            println!("  server: unreachable ({e})");
            println!("    -> the planner will not run. Start one with `ollama serve`.");
        }
    }

    println!("\nsandbox");
    // Stated as a limitation rather than probed. This build does not link the
    // Landlock/seccomp layer, and claiming otherwise would be the most expensive
    // kind of wrong: a user believing tools are confined when they are not.
    println!("  landlock/seccomp confinement: NOT BUILT IN THIS BUILD");
    println!(
        "    -> tools run with the authority of this process. The policy engine\n\
         still enforces taint rules; it does not confine the process."
    );
    println!("\nnetwork");
    println!("  TLS transport:        NOT BUILT IN THIS BUILD");
    println!(
        "    -> http.fetch refuses every https URL. This is deliberate: the crate\n\
         has no TLS dependency and downgrading to plaintext would make the\n\
         insecure path the easy one. `fetch` will therefore always fail here."
    );
    #[cfg(target_os = "linux")]
    {
        println!("\nlinux kernel");
        println!("  cgroup v2 mounted:   {}", yes_no(std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()));
        println!(
            "  effective caps:      {}",
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("CapEff:"))
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "unknown".into())
        );
        println!(
            "  unprivileged bpf:    {}",
            std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into())
        );
        println!("    -> 0 disabled, 1 restricted, 2 fully off.");
    }

    println!("\n  (run `agentos run --help` for the command form)");
    Ok(std::process::ExitCode::SUCCESS)
}

/// Role Q, stubbed to lift the document verbatim.
///
/// **This is a stub and it is labelled as one.** A real extractor would run the
/// document through the quarantined model under a grammar. This one does not, so
/// the extraction path in this binary proves the *plumbing* -- that a document
/// arrives tainted, crosses the bridge, and is bound by the schema -- and not the
/// extraction quality.
///
/// Stubbed this way deliberately. Returning the whole document as one field is
/// the adversarial choice for the extractor: it maximises what an attacker could
/// get forwarded, so any leak this binary reports is an upper bound rather than a
/// flattering one.
struct Passthrough;

impl agentos_infer::Extractor for Passthrough {
    fn extract(
        &mut self,
        _schema: &serde_json::Value,
        document: &Quarantined<String>,
    ) -> Result<agentos_infer::Extraction, agentos_infer::InferError> {
        let text = document.with_label_for_display(|t, _| t.clone());
        Ok(agentos_infer::Extraction {
            data: Val::tainted(SourceId::new(), serde_json::json!({ "text": text })),
            quarantined_fields: vec!["text".into()],
        })
    }
}
