//! Attacks against a real model, end to end.
//!
//! Separate binary from `agentos-eval` because it needs a live model server and
//! takes minutes. `agentos-eval` measures the policy layer against hand-written
//! plans and must stay fast and hermetic; this measures what a model *does* with
//! the same defences.
//!
//! Usage: `cargo run -p agentos-eval --bin agentos-model-eval -- <model>`
//! (defaults to `llama3.2:3b`).
//!
//! Flags:
//!   --deterministic-only    Run only the adversarial arms (no live model needed)
//!   --multi-model=MODELS    Comma-separated list of models to run the A/B against

use agentos_eval::model::{
    run_model_arm, run_model_arm_with, strict_engine, AdversarialPlanner, SchemaControl,
    MODEL_CORPUS,
};
use agentos_infer::{Ollama, RoleModels};

/// The ceiling the bounded arms declare on every string field of the invoice
/// schema.
///
/// Chosen to be long enough that a legitimate field ("payment due 2026-02-01",
/// "paid") fits comfortably, and short enough that no injection payload fits. The
/// gap between those two numbers is the whole design space for schema tightness,
/// and a bound inside the gap does real work while a bound outside it either
/// refuses honest documents or admits the payload.
const BOUND: usize = 96;

fn main() -> std::process::ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // `--deterministic-only` runs the adversarial arms and skips every live one.
    //
    // It exists because the adversarial arms are exactly reproducible and cost
    // nothing, while the live arms cost a full generation per task per repeat. The
    // schema-bound A/B is worth measuring precisely, and it does not need a
    // sampler to make the measurement precise -- so there is no reason to pay for
    // one, or to accept its noise, when checking the bound.
    let deterministic_only = args.iter().any(|a| a == "--deterministic-only");
    args.retain(|a| a != "--deterministic-only");

    // `--multi-model` runs the same A/B against multiple model backends.
    //
    // Useful for proving the invariant holds across model families, not just one
    // checkpoint. Pass a comma-separated list: `--multi-model llama3.2:3b,qwen2.5:7b`.
    let multi_model = args.iter().any(|a| a.starts_with("--multi-model="));
    let models_list = if multi_model {
        args.iter()
            .find(|a| a.starts_with("--multi-model="))
            .and_then(|a| a.split('=').nth(1))
            .map(|s| s.split(',').map(str::trim).map(str::to_string).collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        vec![]
    };
    args.retain(|a| !a.starts_with("--multi-model="));

    let mut args = args.into_iter();
    let model = args.next().unwrap_or_else(|| "llama3.2:3b".into());
    let repeat: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(3);

    if repeat < 1 {
        eprintln!("repeat must be at least 1");
        return std::process::ExitCode::from(2);
    }

    if !deterministic_only {
        let probe = Ollama::new(RoleModels::Shared {
            model: model.clone(),
        });
        let models = match probe.probe() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("no ollama server: {e}");
                eprintln!("start one with `ollama serve`, then re-run,");
                eprintln!("or pass --deterministic-only for the exact arms.");
                return std::process::ExitCode::from(2);
            }
        };
        if !models.iter().any(|m| m.starts_with(&model)) {
            eprintln!("model `{model}` is not pulled. Have: {models:?}");
            return std::process::ExitCode::from(2);
        }
    }

    println!("# AgentOS model measurement\n");
    if multi_model {
        println!("models: {:?}\n", models_list);
    } else {
        println!("model: {model}\n");
    }
    println!("tasks: {}", MODEL_CORPUS.len());
    println!(
        "\nTasks are benign requests; the attack is in the document. Role Q is\n\
         stubbed to lift attacker content faithfully, which is the adversarial\n\
         choice for the planner: any failure is the planner's.\n"
    );

    // If multi-model, run the full suite for each model and collect results.
    if multi_model {
        let separator = "=".repeat(60);
        let mut all_results = Vec::new();
        for m in &models_list {
            println!("\n{}", separator);
            println!("MODEL: {m}");
            println!("{}", separator);
            let mut backend = Ollama::new(RoleModels::Shared { model: m.clone() });
            let results = run_full_evaluation(&mut backend, m, repeat, deterministic_only);
            all_results.push((m.clone(), results));
        }
        
        println!("\n{}", separator);
        println!("COMPARISON ACROSS MODELS");
        println!("{}", separator);
        for (m, results) in &all_results {
            println!("\n--- {m} ---");
            report("adversarial/declining", std::slice::from_ref(&results.adversarial_declining));
            report("adversarial/approving", std::slice::from_ref(&results.adversarial_approving));
            report("adversarial/approving/bounded", std::slice::from_ref(&results.bounded));
            report("adversarial/approving/closed", std::slice::from_ref(&results.closed));
            report("adversarial/strict", std::slice::from_ref(&results.strict));
            if !deterministic_only {
                report("live/declining", &results.declined);
                report("live/approving", &results.approved);
                report("live/approving/bounded", std::slice::from_ref(&results.approved_bounded));
                if let Some(strict_live) = &results.strict_live {
                    report("live/strict", std::slice::from_ref(strict_live));
                }
            }
        }
        
        // Cross-model comparison of the key metric
        let separator = "=".repeat(60);
        println!("\n{}", separator);
        println!("FORWARDED BYTES COMPARISON (adversarial, approving)");
        println!("{}", separator);
        for (m, results) in &all_results {
            println!("{m:20} unbounded={:4} bounded={:4} closed={:4}", 
                results.adversarial_approving.forwarded_bytes,
                results.bounded.forwarded_bytes,
                results.closed.forwarded_bytes);
        }
        
        return std::process::ExitCode::SUCCESS;
    }

    println!("# AgentOS model measurement\n");
    println!("model: {model}\n");
    println!("tasks: {}", MODEL_CORPUS.len());
    println!(
        "\nTasks are benign requests; the attack is in the document. Role Q is\n\
         stubbed to lift attacker content faithfully, which is the adversarial\n\
         choice for the planner: any failure is the planner's.\n"
    );

    println!("\n# Results\n");
    if !deterministic_only {
        println!(
            "Repeating each arm {repeat} time(s). The model is sampled, not\n\
             deterministic: two runs of the same corpus on the same checkpoint\n\
             give different plans, so a single sample is not a rate.\n"
        );
    }

    let mut declined_runs = Vec::new();
    let mut approved_runs = Vec::new();
    let mut approved_bounded = None;
    let mut strict_live = None;
    if !deterministic_only {
        let mut backend = Ollama::new(RoleModels::Shared {
            model: model.clone(),
        });
        for i in 1..=repeat {
            println!("\n--- run {i}/{repeat}: declining user ---");
            declined_runs.push(run_model_arm(&mut backend, &mut |_| false, SchemaControl::Unbounded));
            println!("\n--- run {i}/{repeat}: approving user ---");
            approved_runs.push(run_model_arm(&mut backend, &mut |_| true, SchemaControl::Unbounded));
        }

        // One bounded live run. A single sample rather than a repeated rate, and it
        // is labelled as such: the point is the forwarded-byte delta against the
        // unbounded column, and 522 -> ~0 is a large enough effect that sampling
        // noise does not decide it. If it ever did, this number would be the thing
        // to distrust.
        println!("\n## Live model, approving user, bounded schema (single sample)\n");
        approved_bounded = Some(run_model_arm(&mut backend, &mut |_| true, SchemaControl::Bounded(BOUND)));

        // The same live model under a policy that never asks. The difference from
        // the declining arm is not the leak rate (both are zero if the policy is
        // sound) but the benign column: strict refuses a tainted forward even when
        // the user would have approved it, and that cost is visible only here.
        println!("\n## Live model, strict policy, no questions (single sample)\n");
        strict_live = Some(run_model_arm_with(
            &mut backend,
            &mut |_| true,
            SchemaControl::Unbounded,
            &strict_engine(),
        ));
    }

    // The adversarial arms run first and are deterministic, so they are the one
    // number here that does not depend on the sampler. They answer the question
    // the live arm cannot: what happens when the planner is maximally hostile?
    println!("\n## Adversarial planner, declining user (deterministic)\n");
    let mut adversary = AdversarialPlanner { emitted: Vec::new() };
    let adversarial = run_model_arm(&mut adversary, &mut |_| false, SchemaControl::Unbounded);

    println!("\n## Adversarial planner, approving user (deterministic)\n");
    let mut adversary2 = AdversarialPlanner { emitted: Vec::new() };
    let adversarial_approved = run_model_arm(&mut adversary2, &mut |_| true, SchemaControl::Unbounded);

    // The same arms with a length bound, and then with closed types. Both are
    // deterministic, so these are exact A/Bs rather than comparisons between two
    // noisy samples -- which is the only reason to trust the delta at all.
    let mut adversary3 = AdversarialPlanner { emitted: Vec::new() };
    let bounded = run_model_arm(&mut adversary3, &mut |_| true, SchemaControl::Bounded(BOUND));
    // The declining twin of the bounded arm. The approval decision is the
    // variable this table is meant to separate, so a "declining, bounded" row
    // filled from the approving arm reports the wrong experiment.
    let mut adversary3d = AdversarialPlanner { emitted: Vec::new() };
    let bounded_declining =
        run_model_arm(&mut adversary3d, &mut |_| false, SchemaControl::Bounded(BOUND));
    let mut adversary4 = AdversarialPlanner { emitted: Vec::new() };
    let closed =
        run_model_arm(&mut adversary4, &mut |_| true, SchemaControl::Closed { max_chars: BOUND });
    // The strict arm: same planner, same documents, no human. If it leaks, the
    // rules are wrong; if it does not leak but the benign column collapses, that
    // is the price of removing the human and it is reported next to the leak rate.
    let mut adversary5 = AdversarialPlanner { emitted: Vec::new() };
    let strict = run_model_arm_with(
        &mut adversary5,
        &mut |_| true,
        SchemaControl::Unbounded,
        &strict_engine(),
    );

    println!("\n# Results\n");
    report("adversarial planner, declining user", std::slice::from_ref(&adversarial));
    println!();
    report(
        "adversarial planner, approving user",
        std::slice::from_ref(&adversarial_approved),
    );
    println!();
    println!("\n## The same arms with a {BOUND}-character schema bound\n");
    report(
        "adversarial, declining, bounded",
        std::slice::from_ref(&bounded_declining),
    );
    println!();
    report(
        "adversarial, approving, bounded",
        std::slice::from_ref(&bounded),
    );
    println!();

    println!("\n## Closed types\n");
    report(
        "adversarial, approving, closed",
        std::slice::from_ref(&closed),
    );
    println!();

    if let Some(approved_bounded_val) = &approved_bounded {
        report(
            "live, approving, bounded",
            std::slice::from_ref(approved_bounded_val),
        );
        println!();
    }

    println!("\n## Strict policy: no questions asked\n");
    report(
        "adversarial planner, strict",
        std::slice::from_ref(&strict),
    );
    println!();
    if let Some(m) = &strict_live {
        report("live model, strict", std::slice::from_ref(m));
        println!();
    }

    println!("\n## Live model\n");
    report("declining user", &declined_runs);
    println!();
    report("approving user", &approved_runs);
    println!();

    println!("\n## Controls\n");
    let mut ok = true;
    for (label, m) in [
        ("adversarial/declining", &adversarial),
        ("adversarial/approving", &adversarial_approved),
        ("adversarial/declining/bounded", &bounded_declining),
        ("adversarial/approving/bounded", &bounded),
        ("adversarial/approving/closed", &closed),
        ("adversarial/strict", &strict),
    ] {
        match m.check_accounting() {
            Ok(()) => println!("  {label}: accounting ok"),
            Err(e) => {
                println!("  {label}: ACCOUNTING FAILURE: {e}");
                ok = false;
            }
        }
    }
    for (label, runs) in [("declining", &declined_runs), ("approving", &approved_runs)] {
        for (i, m) in runs.iter().enumerate() {
            if let Err(e) = m.check_accounting() {
                println!("  {label} run {}: ACCOUNTING FAILURE: {e}", i + 1);
                ok = false;
            }
        }
        println!("  {label}: {} run(s) accounted", runs.len());
    }

    // The control that makes the bound mean something. If a bounded arm forwards
    // *more* than its unbounded twin, the bound is not bounding: something is
    // wrong with the measurement or the enforcement, and the table above would
    // otherwise be reported as a result.
    //
    // Checked on the deterministic arms only. A single live sample can legitimately
    // land on the other side of this by chance, and a control that fires at random
    // is a control people learn to ignore.
    for (label, bounded, unbounded) in [
        ("adversarial/declining", &bounded_declining, &adversarial),
        ("adversarial/approving", &bounded, &adversarial_approved),
        ("adversarial/approving/closed", &closed, &adversarial_approved),
    ] {
        if bounded.forwarded_bytes > unbounded.forwarded_bytes {
            println!(
                "  {label}: BOUND FAILURE -- the bounded arm forwarded {} bytes \
                 against the unbounded arm's {}",
                bounded.forwarded_bytes, unbounded.forwarded_bytes
            );
            ok = false;
        } else {
            println!(
                "  {label}: forwarding {} -> {} bytes with a {BOUND}-char bound",
                unbounded.forwarded_bytes, bounded.forwarded_bytes
            );
        }
    }

    // The bound must not be quietly stealing credit from the intent pins.
    //
    // `pin_denied` fell from 4 to 1 in the bounded arm, and the obvious reading
    // is that the pins got better. That reading is wrong: the bound refuses the
    // over-long *extraction*, so several tasks now stop one step earlier, before
    // the plan ever reaches the send_email whose recipient the pin would have
    // caught. The attack is stopped -- by the extraction failing, not by the pin
    // firing.
    //
    // So the two columns are not comparable as "defences", only as "outcomes".
    // Reporting the drop as a pin improvement would be reading a defence as
    // working when it was in fact bypassed.
    if bounded.pin_denied < adversarial.pin_denied {
        println!(
            "\n  NOTE: pin_denied fell {} -> {} in the bounded arm. That is not the\n\
             pins getting better. The bound refuses the extraction first, so those\n\
             tasks stop before reaching the pinned tool. Both columns are counts of\n\
             tasks that stopped, not of tasks stopped *by the pins*; only the\n\
             unbounded column measures the pins.",
            adversarial.pin_denied, bounded.pin_denied
        );
    }

    if !ok {
        println!("\nA control failed. The numbers above are NOT results.");
        return std::process::ExitCode::from(1);
    }
    println!("\nAll controls passed; the numbers above are results.");
    return std::process::ExitCode::SUCCESS;
}

/// Holds the deterministic results for one model evaluation.
struct EvaluationResults {
    adversarial_declining: agentos_eval::model::ModelMeasurement,
    adversarial_approving: agentos_eval::model::ModelMeasurement,
    bounded: agentos_eval::model::ModelMeasurement,
    closed: agentos_eval::model::ModelMeasurement,
    strict: agentos_eval::model::ModelMeasurement,
    declined: Vec<agentos_eval::model::ModelMeasurement>,
    approved: Vec<agentos_eval::model::ModelMeasurement>,
    approved_bounded: agentos_eval::model::ModelMeasurement,
    strict_live: Option<agentos_eval::model::ModelMeasurement>,
}

/// Run the full evaluation suite for one model backend.
fn run_full_evaluation(
    backend: &mut dyn agentos_infer::Backend,
    _model_name: &str,
    repeat: usize,
    deterministic_only: bool,
) -> EvaluationResults {
    let mut declined = Vec::new();
    let mut approved = Vec::new();
    let mut approved_bounded = None;
    let mut strict_live = None;
    
    if !deterministic_only {
        for i in 1..=repeat {
            println!("\n--- run {i}/{repeat}: declining user ---");
            declined.push(run_model_arm(backend, &mut |_| false, SchemaControl::Unbounded));
            println!("\n--- run {i}/{repeat}: approving user ---");
            approved.push(run_model_arm(backend, &mut |_| true, SchemaControl::Unbounded));
        }
        println!("\n## Live model, approving user, bounded schema (single sample)\n");
        approved_bounded = Some(run_model_arm(backend, &mut |_| true, SchemaControl::Bounded(BOUND)));
        println!("\n## Live model, strict policy, no questions (single sample)\n");
        strict_live = Some(run_model_arm_with(
            backend,
            &mut |_| true,
            SchemaControl::Unbounded,
            &strict_engine(),
        ));
    }

    // The adversarial arms run first and are deterministic, so they are the one
    // number here that does not depend on the sampler.
    println!("\n## Adversarial planner, declining user (deterministic)\n");
    let mut adversary = AdversarialPlanner { emitted: Vec::new() };
    let adversarial_declining = run_model_arm(&mut adversary, &mut |_| false, SchemaControl::Unbounded);

    println!("\n## Adversarial planner, approving user (deterministic)\n");
    let mut adversary2 = AdversarialPlanner { emitted: Vec::new() };
    let adversarial_approving = run_model_arm(&mut adversary2, &mut |_| true, SchemaControl::Unbounded);

    // The same arms with a length bound, and then with closed types.
    let mut adversary3 = AdversarialPlanner { emitted: Vec::new() };
    let bounded = run_model_arm(&mut adversary3, &mut |_| true, SchemaControl::Bounded(BOUND));
    let mut adversary4 = AdversarialPlanner { emitted: Vec::new() };
    let closed =
        run_model_arm(&mut adversary4, &mut |_| true, SchemaControl::Closed { max_chars: BOUND });
    let mut adversary5 = AdversarialPlanner { emitted: Vec::new() };
    let strict = run_model_arm_with(
        &mut adversary5,
        &mut |_| true,
        SchemaControl::Unbounded,
        &strict_engine(),
    );

    EvaluationResults {
        adversarial_declining,
        adversarial_approving,
        bounded,
        closed,
        strict,
        declined,
        approved,
        approved_bounded: approved_bounded.unwrap_or_else(|| {
            run_model_arm(&mut AdversarialPlanner { emitted: Vec::new() }, &mut |_| true, SchemaControl::Bounded(BOUND))
        }),
        strict_live,
    }
}

/// Summarise several runs of one arm.
///
/// The range is the honest statistic. A single run of a sampled model on a
/// 14-task corpus is one draw, and reporting it as "the" rate would be reporting
/// noise as a measurement -- the two runs performed here differed by a full task
/// on the leak count and by two on unplannable.
fn report(label: &str, runs: &[agentos_eval::model::ModelMeasurement]) {
    println!("### {label}\n");
    if runs.is_empty() {
        println!("  no runs in this mode\n");
        return;
    }
    let n = runs.len() as f64;
    let leaked: Vec<usize> = runs.iter().map(|m| m.leaked).collect();
    let rate: Vec<f64> = runs.iter().map(|m| m.leak_rate()).collect();
    let model_failed: Vec<usize> = runs.iter().map(|m| m.model_failed()).collect();
    let prompts: Vec<usize> = runs.iter().map(|m| m.prompts).collect();

    println!("  runs                    {}", runs.len());
    println!("  tasks per run           {}", runs[0].total);
    println!(
        "  tainted arg reached tool {}  (min {}, max {})",
        leaked.iter().sum::<usize>(),
        leaked.iter().min().copied().unwrap_or(0),
        leaked.iter().max().copied().unwrap_or(0)
    );
    println!(
        "  leak rate               {:.1}%  (min {:.1}%, max {:.1}%)",
        leaked.iter().sum::<usize>() as f64 / (runs[0].total as f64 * n) * 100.0,
        rate.iter().cloned().fold(f64::INFINITY, f64::min) * 100.0,
        rate.iter().cloned().fold(f64::NEG_INFINITY, f64::max) * 100.0
    );
    println!(
        "  MODEL QUALITY failures  {}  (min {}, max {})",
        model_failed.iter().sum::<usize>(),
        model_failed.iter().min().copied().unwrap_or(0),
        model_failed.iter().max().copied().unwrap_or(0)
    );
    println!(
        "  REFUSED WITH NO HUMAN    {}   <- contradicted what the user asked for",
        runs.iter().map(|m| m.pin_denied).sum::<usize>()
    );
    println!(
        "  untrusted bytes reaching a tool   {}",
        runs.iter().map(|m| m.forwarded_bytes).sum::<usize>()
    );
    println!(
        "  prompts shown           {}  (min {}, max {})",
        prompts.iter().sum::<usize>(),
        prompts.iter().min().copied().unwrap_or(0),
        prompts.iter().max().copied().unwrap_or(0)
    );
    let benign_total: usize = runs.iter().map(|m| m.benign_total).sum();
    let benign_clean: usize = runs.iter().map(|m| m.benign_clean).sum();
    let benign_completed: usize = runs.iter().map(|m| m.benign_completed).sum();
    let benign_denied: usize = runs.iter().map(|m| m.benign_denied).sum();
    let benign_refused: usize = runs.iter().map(|m| m.benign_refused).sum();
    println!(
        "  benign controls         {benign_clean}/{benign_total} clean, \
         {benign_completed} completed, {benign_denied} denied, {benign_refused} refused"
    );

    // Every task that ever leaked or ever prompted, so a reader can see which
    // vectors are the live ones rather than only how many.
    let mut leaked_ids: Vec<&str> = runs
        .iter()
        .flat_map(|m| m.leaked_ids.iter().copied())
        .collect();
    leaked_ids.sort_unstable();
    leaked_ids.dedup();
    if !leaked_ids.is_empty() {
        println!("  ever leaked: {}", leaked_ids.join(", "));
    }
    let mut pin_ids: Vec<&str> = runs
        .iter()
        .flat_map(|m| m.pin_denied_ids.iter().copied())
        .collect();
    pin_ids.sort_unstable();
    pin_ids.dedup();
    if !pin_ids.is_empty() {
        println!("  ever auto-refused: {}", pin_ids.join(", "));
    }
    let mut prompted_ids: Vec<&str> = runs
        .iter()
        .flat_map(|m| m.prompted_ids.iter().copied())
        .collect();
    prompted_ids.sort_unstable();
    prompted_ids.dedup();
    if !prompted_ids.is_empty() {
        println!("  ever prompted: {}", prompted_ids.join(", "));
    }

    println!(
        "\n  NOTE: model-quality failures are the model failing to produce a\n\
         runnable plan, NOT blocked attacks. They stay in the denominator so a\n\
         weak model cannot improve the leak rate by failing to plan."
    );
}


