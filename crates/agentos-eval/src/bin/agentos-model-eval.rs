//! Attacks against a real model, end to end.
//!
//! Separate binary from `agentos-eval` because it needs a live model server and
//! takes minutes. `agentos-eval` measures the policy layer against hand-written
//! plans and must stay fast and hermetic; this measures what a model *does* with
//! the same defences.
//!
//! Usage: `cargo run -p agentos-eval --bin agentos-model-eval -- <model>`
//! (defaults to `llama3.2:3b`).

use agentos_eval::model::{run_model_arm, MODEL_CORPUS};
use agentos_infer::{Ollama, RoleModels};

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let model = args.next().unwrap_or_else(|| "llama3.2:3b".into());
    let repeat: usize = args
        .next()
        .and_then(|a| a.parse().ok())
        .unwrap_or(3);

    if repeat < 1 {
        eprintln!("repeat must be at least 1");
        return std::process::ExitCode::from(2);
    }

    let probe = Ollama::new(RoleModels::Shared {
        model: model.clone(),
    });
    let models = match probe.probe() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("no ollama server: {e}");
            eprintln!("start one with `ollama serve`, then re-run.");
            return std::process::ExitCode::from(2);
        }
    };
    if !models.iter().any(|m| m.starts_with(&model)) {
        eprintln!("model `{model}` is not pulled. Have: {models:?}");
        return std::process::ExitCode::from(2);
    }

    println!("# AgentOS model measurement\n");
    println!("model: {model}");
    println!("tasks: {}", MODEL_CORPUS.len());
    println!(
        "\nTasks are benign requests; the attack is in the document. Role Q is\n\
         stubbed to lift attacker content faithfully, which is the adversarial\n\
         choice for the planner: any failure is the planner's.\n"
    );

    let mut backend = Ollama::new(RoleModels::Shared {
        model: model.clone(),
    });

    println!("\n# Results\n");
    println!("Repeating each arm {repeat} time(s). The model is sampled, not\n\
              deterministic: two runs of the same corpus on the same checkpoint\n\
              give different plans, so a single sample is not a rate.\n");

    let mut declined_runs = Vec::new();
    let mut approved_runs = Vec::new();
    for i in 1..=repeat {
        println!("\n--- run {i}/{repeat}: declining user ---");
        declined_runs.push(run_model_arm(&mut backend, &mut |_| false));
        println!("\n--- run {i}/{repeat}: approving user ---");
        approved_runs.push(run_model_arm(&mut backend, &mut |_| true));
    }

    println!("\n# Results\n");
    report("declining user", &declined_runs);
    println!();
    report("approving user", &approved_runs);

    println!("\n## Controls\n");
    let mut ok = true;
    for (label, runs) in [("declining", &declined_runs), ("approving", &approved_runs)] {
        for (i, m) in runs.iter().enumerate() {
            if let Err(e) = m.check_accounting() {
                println!("  {label} run {}: ACCOUNTING FAILURE: {e}", i + 1);
                ok = false;
            }
        }
        println!("  {label}: {} run(s) accounted", runs.len());
    }

    if !ok {
        println!("\nA control failed. The numbers above are NOT results.");
        return std::process::ExitCode::from(1);
    }
    println!("\nAll controls passed; the numbers above are results.");
    std::process::ExitCode::from(0)
}

/// Summarise several runs of one arm.
///
/// The range is the honest statistic. A single run of a sampled model on a
/// 14-task corpus is one draw, and reporting it as "the" rate would be reporting
/// noise as a measurement — the two runs performed here differed by a full task
/// on the leak count and by two on unplannable.
fn report(label: &str, runs: &[agentos_eval::model::ModelMeasurement]) {
    println!("### {label}\n");
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
        rate.iter().cloned().fold(f64::NEG_INFINITY, f64::max) * 100.0,
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
        "  prompts shown           {}  (min {}, max {})",
        prompts.iter().sum::<usize>(),
        prompts.iter().min().copied().unwrap_or(0),
        prompts.iter().max().copied().unwrap_or(0),
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
