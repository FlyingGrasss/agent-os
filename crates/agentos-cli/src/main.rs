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

use agentos_cli::{ask_on_stdin, Decision, client::{dispatch, check, ExecuteParams, Grants, Client, discover_endpoint, DaemonEndpoint, AuthToken}, repl::{Repl, ReplExit}, util::user_id};
use agentos_core::{ModelExtractor, Outcome, Planner, PlanOutcome, Session};
use agentos_dsl::PlanError;
use agentos_infer::{Ollama, RoleModels};
use agentos_pager::PagerConfig;
use agentos_policy::{PolicyEngine, RuleSet};
use agentos_tools::audit::{AuditLog, AuditSink, FileSink, SystemClock};
use agentos_tools::http::{install_policy_rules, FetchGrant, HttpFetch};
use agentos_tools::{FsWrite, PolicyHost, WriteGrant};
use agentos_types::{ControllerAuthority, Origin, Quarantined, SourceId, Trusted, Val};

const USAGE: &str = "\
agentos - run a task with real privileges and a real policy engine

USAGE:
  agentos run [OPTIONS] <TASK>
  agentos repl [OPTIONS]
  agentos check
  agentos service <SUBCOMMAND>
  agentos audit <SUBCOMMAND>

OPTIONS:
  --model <NAME>          Ollama model for the planner (default llama3.2:3b)
  --allow-host <HOST>     permit fetching this host (repeatable, https only)
  --write-root <DIR>      permit writing inside this directory
  --no-fetch              register no network tool at all

`check` reports what this machine can actually do. Run it first if something
seems unavailable: a sandbox that did nothing and a sandbox that never started
look identical from the outside.

`repl` starts an interactive session with the daemon. Tasks are sent in your
words; confirmations are a person or nothing. A piped stdin gets no approvals.

`service` manages the agentosd systemd service:
  agentos service install [--user|--system] [--prefix PATH]  Install and enable the service
  agentos service uninstall                              Uninstall the service
  agentos service start                                  Start the service
  agentos service stop                                   Stop the service
  agentos service restart                                Restart the service
  agentos service status                                 Show service status
  agentos service logs [-f]                              Show service logs (follow with -f)
  agentos service enable                                 Enable service at boot
  agentos service disable                                Disable service at boot

`audit` inspects the append-only log (I6):
  agentos audit verify [--path PATH]   Recompute the hash chain and report
                                      whether the ledger is intact. Defaults to
                                      $AGENTOSD_AUDIT_LOG, else ./agentosd-audit.log

The chain is keyless: it detects an edited, deleted, reordered, or partially
written record, but not an attacker who recomputes the whole file. Pin the head
it prints somewhere they cannot write to make that detectable too.
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
        "repl" => cmd_repl(&args[1..]),
        "check" => cmd_check(),
        "service" => cmd_service(&args[1..]),
        "audit" => cmd_audit(&args[1..]),
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
    match dispatch(grants) {
        Ok(code) => return Ok(code),
        Err(e) => eprintln!("agentos: daemon error: {}", e),
    }

    // Fall back to local execution if daemon is not reachable
    eprintln!("agentos: daemon not reachable, falling back to local execution");
    cmd_run_local(args)
}

/// Parse options for the REPL (no task argument needed).
#[derive(Default)]
struct ReplOptions {
    model: String,
    allow_hosts: Vec<String>,
    write_root: Option<PathBuf>,
    fetch: bool,
}

fn parse_repl_options(args: &[String]) -> Result<ReplOptions, String> {
    let mut o = ReplOptions {
        model: "llama3.2:3b".to_string(),
        fetch: true,
        ..ReplOptions::default()
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
            other => return Err(format!("unexpected argument `{other}` (repl takes no task; type it at the prompt)")),
        }
        i += 1;
    }
    Ok(o)
}

fn cmd_repl(args: &[String]) -> Result<std::process::ExitCode, String> {
    let options = parse_repl_options(args)?;

    // Build grants from options
    let grants = Grants {
        hosts: options.allow_hosts.clone(),
        write_roots: options.write_root.as_ref().map(|p| p.to_string_lossy().to_string()).into_iter().collect(),
        send_email: false,
    };

    // Connect to the daemon
    let endpoint = discover_endpoint();
    let token = if matches!(endpoint, DaemonEndpoint::Tcp(_)) {
        Some(AuthToken::read()?)
    } else {
        None
    };

    let client = Client::connect(endpoint, token)?;

    // Print the endpoint we're using
    match client.endpoint_str() {
        Some(s) => eprintln!("agentos: connected via {}", s),
        None => eprintln!("agentos: connected"),
    }

    // Start the REPL
    let mut repl = Repl::new(client, grants, agentos_cli::stdin_is_interactive());
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout();

    let exit_reason = repl
        .run(&mut stdin, &mut stdout)
        .map_err(|e| e.to_string())?;

    match exit_reason {
        ReplExit::Normal => Ok(std::process::ExitCode::SUCCESS),
        ReplExit::Disconnected => Ok(std::process::ExitCode::from(6)),
    }
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

// ---------------------------------------------------------------------------
// service subcommand
// ---------------------------------------------------------------------------

use std::process::Command;

/// Manage the agentosd systemd service.
fn cmd_service(args: &[String]) -> Result<std::process::ExitCode, String> {
    let Some(subcommand) = args.first() else {
        eprintln!("Usage: agentos service <SUBCOMMAND>");
        eprintln!("Subcommands: install, uninstall, start, stop, restart, status, logs, enable, disable");
        return Ok(std::process::ExitCode::from(2));
    };

    match subcommand.as_str() {
        "install" => cmd_service_install(&args[1..]),
        "uninstall" => cmd_service_uninstall(&args[1..]),
        "start" => cmd_service_control("start", &args[1..]),
        "stop" => cmd_service_control("stop", &args[1..]),
        "restart" => cmd_service_control("restart", &args[1..]),
        "status" => cmd_service_control("status", &args[1..]),
        "logs" => cmd_service_logs(&args[1..]),
        "enable" => cmd_service_control("enable", &args[1..]),
        "disable" => cmd_service_control("disable", &args[1..]),
        other => Err(format!("unknown service subcommand `{other}`")),
    }
}

fn cmd_service_install(args: &[String]) -> Result<std::process::ExitCode, String> {
    let mut mode = "user";
    let mut prefix = "/usr/local".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => mode = "user",
            "--system" => mode = "system",
            "--prefix" => {
                i += 1;
                prefix = args.get(i).ok_or("--prefix needs a value")?.clone();
            },
            other => return Err(format!("unknown install option `{other}`")),
        }
        i += 1;
    }

    // Build the install script path
    let script_path = find_install_script()?;
    
    let mut cmd = Command::new("bash");
    cmd.arg(&script_path)
        .arg(format!("--{}", mode))
        .arg("--prefix")
        .arg(prefix);

    let status = cmd.status().map_err(|e| format!("failed to run install script: {e}"))?;
    
    if status.success() {
        println!("Service installed successfully!");
        Ok(std::process::ExitCode::SUCCESS)
    } else {
        Err("Installation failed".into())
    }
}

fn cmd_service_uninstall(_args: &[String]) -> Result<std::process::ExitCode, String> {
    // Determine if user or system mode by checking service existence
    let is_user = service_exists_user()?;
    
    let (systemctl, _service_name) = if is_user {
        ("systemctl --user", "agentosd")
    } else {
        ("sudo systemctl", "agentosd")
    };

    // Stop and disable
    run_systemctl(systemctl, &["stop".to_string(), "agentosd".to_string()])?;
    run_systemctl(systemctl, &["disable".to_string(), "agentosd".to_string()])?;

    // Remove service file
    let service_path = if is_user {
        dirs::home_dir()
            .ok_or("home directory not found")?
            .join(".config/systemd/user/agentosd.service")
    } else {
        std::path::PathBuf::from("/etc/systemd/system/agentosd.service")
    };

    if service_path.exists() {
        std::fs::remove_file(&service_path).map_err(|e| format!("failed to remove service file: {e}"))?;
    }

    // Reload systemd
    run_systemctl(systemctl, &["daemon-reload".to_string()])?;

    println!("Service uninstalled successfully!");
    Ok(std::process::ExitCode::SUCCESS)
}

fn cmd_service_control(action: &str, args: &[String]) -> Result<std::process::ExitCode, String> {
    // Determine if user or system mode
    let is_user = service_exists_user()?;
    let systemctl = if is_user { "systemctl --user" } else { "sudo systemctl" };

    let mut args_vec = vec![action.to_string(), "agentosd".to_string()];
    args_vec.extend(args.iter().cloned());

    run_systemctl(systemctl, &args_vec)?;

    Ok(std::process::ExitCode::SUCCESS)
}

fn cmd_service_logs(args: &[String]) -> Result<std::process::ExitCode, String> {
    let is_user = service_exists_user()?;
    let systemctl = if is_user { "systemctl --user" } else { "sudo systemctl" };

    let mut args_vec = vec!["logs".to_string(), "-u".to_string(), "agentosd".to_string()];
    args_vec.extend(args.iter().cloned());

    run_systemctl(systemctl, &args_vec)?;

    Ok(std::process::ExitCode::SUCCESS)
}

fn service_exists_user() -> Result<bool, String> {
    // Check if user service file exists
    let user_service = dirs::home_dir()
        .ok_or("home directory not found")?
        .join(".config/systemd/user/agentosd.service");
    
    if user_service.exists() {
        return Ok(true);
    }

    // Check system service
    let system_service = std::path::Path::new("/etc/systemd/system/agentosd.service");
    Ok(!system_service.exists())
}

fn run_systemctl(systemctl: &str, args: &[String]) -> Result<(), String> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!("{} {}", systemctl, args.join(" ")));
    
    let status = cmd.status().map_err(|e| format!("failed to run systemctl: {e}"))?;
    
    if !status.success() {
        return Err(format!("systemctl {} failed with status: {}", args.join(" "), status));
    }
    Ok(())
}

fn find_install_script() -> Result<std::path::PathBuf, String> {
    // Try to find the install script relative to the binary
    let current_exe = std::env::current_exe().map_err(|e| format!("failed to get current exe: {e}"))?;
    let script_path = current_exe
        .parent()
        .ok_or("binary has no parent directory")?
        .join("../scripts/install.sh");
    
    if script_path.exists() {
        return Ok(script_path);
    }

    // Try from workspace root
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    
    let script_path = workspace_root.join("scripts/install.sh");
    if script_path.exists() {
        return Ok(script_path);
    }

    Err("install.sh not found. Run from workspace root or install agentos-cli from source.".into())
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

/// Dispatch `agentos audit <sub>`.
fn cmd_audit(args: &[String]) -> Result<std::process::ExitCode, String> {
    let Some(sub) = args.first() else {
        eprintln!("usage: agentos audit verify [--path PATH]");
        eprintln!("  verify   recompute the hash chain and report integrity");
        return Ok(std::process::ExitCode::from(2));
    };
    match sub.as_str() {
        "verify" => cmd_audit_verify(&args[1..]),
        other => Err(format!("unknown audit subcommand `{other}`")),
    }
}

/// Verify the audit ledger and report whether it is intact.
///
/// Exits non-zero on a fault so this is usable from a cron job or a deploy hook,
/// which is the point: a check nobody can fail is not a check.
///
/// Prints the chain head on success. That head is the only thing worth keeping
/// from a verification — pinning it somewhere the log's author cannot reach is
/// what turns "the file is self-consistent" into "the file is still the one I
/// checked", because the chain alone cannot tell the two apart.
fn cmd_audit_verify(args: &[String]) -> Result<std::process::ExitCode, String> {
    let mut path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => {
                i += 1;
                path = Some(args.get(i).ok_or("--path needs a value")?.clone());
            }
            other => return Err(format!("unknown audit verify option `{other}`")),
        }
        i += 1;
    }

    // Same resolution the daemon uses to decide where it writes, so `verify`
    // defaults to the log this install is actually producing.
    let path = path.unwrap_or_else(|| {
        std::env::var("AGENTOSD_AUDIT_LOG").unwrap_or_else(|_| "agentosd-audit.log".to_string())
    });

    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read audit log `{path}`: {e}"))?;

    match agentos_tools::chain::verify(&text) {
        Ok(v) => {
            println!("ok      {} records chained, log is intact", v.records);
            println!("head    {}", v.head_hex());
            Ok(std::process::ExitCode::SUCCESS)
        }
        Err(fault) => {
            eprintln!("COMPROMISED  {fault}");
            eprintln!(
                "head    not established; the chain is broken at the line above"
            );
            Ok(std::process::ExitCode::from(1))
        }
    }
}
