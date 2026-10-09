//! `agentos-eval`: print the measurement, or print why it cannot be trusted.
//!
//! Two jobs, in this order. First the controls, because a rate whose control
//! failed is not a result. Then the rates. If a control fails, this prints the
//! failure and exits non-zero *even if the rates look excellent*, which is the
//! whole reason the controls are computed before the numbers are formatted.
//!
//! Exit codes: 0 when every control passed, 1 when one did not, 2 on a usage
//! error. Deliberately distinct, so a CI job can gate on it without parsing
//! prose.

use agentos_eval::Measurement;

fn pct(x: f64) -> String {
    format!("{:.1}%", x * 100.0)
}

fn main() -> std::process::ExitCode {
    let mut verbose = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--verbose" | "-v" => verbose = true,
            "--help" | "-h" => {
                println!(
                    "agentos-eval\n\n\
                     USAGE:\n    agentos-eval [--verbose]\n\n\
                     Measures the policy engine's decision quality as a defended-versus-\n\
                     counterfactual pair over the DSL corpus. Needs no model.\n\n\
                     It does NOT measure attack success rate against a real model, or\n\
                     benign utility, or invariant I1: there is no agent loop and no model\n\
                     backend yet, so there is no task to attack. See the crate docs.\n\n\
                     OPTIONS:\n    -v, --verbose    Per-program outcomes in both arms.\n\n\
                     EXIT:\n    0  every control passed\n    1  a control failed; the rates below it are not results\n    2  usage error"
                );
                return std::process::ExitCode::from(0);
            }
            other => {
                eprintln!("agentos-eval: unknown argument `{other}` (try --help)");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let m = Measurement::run();

    println!("# AgentOS policy measurement\n");
    println!("Corpus: {} programs, {} benign controls, {} attacks.\n", {
        let b: usize = m.defended.benign_total;
        let a: usize = m.defended.attack_total;
        b + a
    }, m.defended.benign_total, m.defended.attack_total);

    // --- controls first -----------------------------------------------------
    let controls = m.check_controls();
    println!("## Controls\n");
    if controls.is_empty() {
        println!("  all passed\n");
    } else {
        for c in &controls {
            println!("  FAILED  {c}");
        }
        println!();
    }

    // --- rates --------------------------------------------------------------
    println!("## Attack success (a tool ran with a tainted argument)\n");
    println!(
        "  counterfactual (every rule Allow)  {:>6}  {}/{}",
        pct(m.counterfactual.attack_success_rate()),
        m.counterfactual.attack_succeeded,
        m.counterfactual.attack_total
    );
    println!(
        "  defended (default_rules)           {:>6}  {}/{}",
        pct(m.defended.attack_success_rate()),
        m.defended.attack_succeeded,
        m.defended.attack_total
    );
    println!(
        "  reduction                         {:>6}\n",
        format!("-{:.1}pp", m.attack_success_reduction() * 100.0)
    );

    println!("## How the defended arm halted each attack\n");
    println!("  denied outright      {}", m.defended.attack_denied);
    println!("  refused by a person  {}", m.defended.attack_user_refused);
    println!(
        "  gave up asking       {}",
        m.defended.attack_confirmation_limit
    );
    println!("  executed             {}", m.defended.attack_succeeded);
    println!("  did not run (halted) {}", m.defended.attack_halted);
    println!(
        "  prompts shown        {}",
        m.defended.prompts
    );
    println!();

    println!("## Automatic enforcement versus a human in the loop\n");
    println!(
        "  refused outright, no question anyone is asked     {:>4}",
        m.attacks_stopped_automatically()
    );
    println!(
        "  held only by a prompt the user answers            {:>4}",
        m.attacks_held_only_by_a_prompt()
    );
    println!(
        "  same rules, user approves everything              {:>4}  {} of {} attacks ran anyway",
        m.defended_rubber_stamp.attack_succeeded,
        m.defended_rubber_stamp.attack_succeeded,
        m.defended_rubber_stamp.attack_total
    );
    println!(
        "  no rules at all (counterfactual)                   {:>4}  {} of {} attacks ran",
        m.user_approves.attack_succeeded,
        m.user_approves.attack_succeeded,
        m.user_approves.attack_total
    );
    if let Some((classified, derived)) = m.check_accounting() {
        println!(
            "  ACCOUNTING MISMATCH: classification says {classified}, the user-approves arm implies {derived}"
        );
    }
    println!();

    println!("## Benign utility\n");
    println!(
        "  programs that completed in the defended arm   {:>6}  {}/{}",
        pct(m.defended.benign_rate()),
        m.defended.benign_ran,
        m.defended.benign_total
    );
    println!("  tainted arguments observed across both arms  {:>6}", {
        m.defended.tainted_arguments + m.counterfactual.tainted_arguments
    });
    println!();

    if verbose {
        println!("## Per category (attacks only)\n");
        println!(
            "  {:<32} {:>5} {:>10} {:>14} {:>14}",
            "category", "n", "defended", "user-approves", "counterfactual"
        );
        let mut categories: Vec<&str> = m.defended.attacks_by_category.keys().copied().collect();
        categories.sort_unstable();
        for category in categories {
            let n = m.defended.attacks_by_category.get(category).copied().unwrap_or(0);
            let d = m.defended.successes_by_category.get(category).copied().unwrap_or(0);
            let u = m
                .user_approves
                .successes_by_category
                .get(category)
                .copied()
                .unwrap_or(0);
            let c = m
                .counterfactual
                .successes_by_category
                .get(category)
                .copied()
                .unwrap_or(0);
            println!("  {category:<32} {n:>5} {d:>10} {u:>14} {c:>14}");
        }
        println!();

        println!("## Per program\n");
        println!(
            "  {:<38} {:<8} {:<24} {:<24} counterfactual",
            "program", "kind", "defended", "user-approves"
        );
        for (p, d, c, u) in m.per_program() {
            println!(
                "  {:<38} {:<8} {:<24} {:<24} {}",
                p.id,
                match p.kind {
                    agentos_eval::Kind::Benign => "benign",
                    agentos_eval::Kind::Attack => "attack",
                },
                describe(&d.outcome),
                describe(&u.outcome),
                describe(&c.outcome)
            );
        }
        println!();
    }

    println!("## Not measured\n");
    println!("  attack success rate against a real model   no agent loop, no model backend");
    println!("  benign utility vs a baseline                no agent loop, no model backend");
    println!("  invariant I1 label-leak count               no prompt assembly exists yet");
    println!("  sandbox escape rate                         suites pass but are not scored here");

    println!("\n## How to read the 0%\n");
    println!("  A 0% defended rate is a structural consequence of failing closed, not an");
    println!("  empirical surprise: an argument carrying taint can only ever reach Deny or");
    println!("  Confirm, because an absent rule is Confirm. So the number above confirms the");
    println!("  fail-closed default is intact and that the corpus really routes taint into tool");
    println!("  arguments (the counterfactual control is what proves the latter). The number");
    println!("  worth reading is the automatic-versus-human split above: that one says which");
    println!("  attacks a machine ends and which depend on a person saying no.");

    if controls.is_empty() {
        println!("\nEvery control passed; the rates above are results.");
        std::process::ExitCode::from(0)
    } else {
        println!("\nA control failed. The rates above are NOT results.");
        std::process::ExitCode::from(1)
    }
}

fn describe(o: &agentos_eval::Outcome) -> String {
    match o {
        agentos_eval::Outcome::Completed => "completed".into(),
        agentos_eval::Outcome::Denied { op } => format!("denied {op}"),
        agentos_eval::Outcome::Refused { op } => format!("refused {op}"),
        agentos_eval::Outcome::ConfirmationLimit { asked } => {
            format!("gave up after {asked} prompt(s)")
        }
        agentos_eval::Outcome::Halted { reason } => format!("HALTED {reason}"),
    }
}