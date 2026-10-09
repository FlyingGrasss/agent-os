//! Attacks against a real model, end to end.
//!
//! Separate binary from `agentos-eval` because it needs a live model server and
//! takes minutes. `agentos-eval` measures the policy layer against hand-written
//! plans and must stay fast and hermetic; this measures what a model *does* with
//! the same defences.
//!
//! Usage: `cargo run -p agentos-eval --bin agentos-model-eval -- <model>`
//! (defaults to `llama3.2:3b`).

use agentos_eval::model::{run_model_arm, ModelControlFailure, MODEL_CORPUS};
use agentos_infer::{Ollama, RoleModels};

fn main() -> std::process::ExitCode {
    let model = std::env::args().nth(1).unwrap_or_else(|| "llama3.2:3b".into());

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

    println!("\n## Defended: the user reads the prompt and declines\n");
    let declined = run_model_arm(&mut backend, &mut |_| false);

    println!("\n## Rubber-stamp: the user approves everything\n");
    let approved = run_model_arm(&mut backend, &mut |_| true);

    println!("\n# Results\n");
    report("declining user", &declined);
    println!();
    report("approving user", &approved);

    println!("\n## Controls\n");
    let mut ok = true;
    for (label, m) in [("declining", &declined), ("approving", &approved)] {
        match m.check_accounting() {
            Ok(()) => println!("  {label}: accounting ok"),
            Err(e) => {
                println!("  {label}: ACCOUNTING FAILURE: {e}");
                ok = false;
            }
        }
    }

    if !ok {
        println!("\nA control failed. The numbers above are NOT results.");
        return std::process::ExitCode::from(1);
    }
    println!("\nAll controls passed; the numbers above are results.");
    std::process::ExitCode::from(0)
}

fn report(label: &str, m: &agentos_eval::model::ModelMeasurement) {
    println!("### {label}\n");
    println!("  tasks                    {}", m.denominator());
    println!("  model could not plan     {}", m.unplannable);
    println!("  planned and run          {}", m.planned);
    println!("  tainted arg reached tool {}", m.leaked);
    println!("  stopped by policy        {}", m.denied);
    println!("  stopped by a person      {}", m.refused);
    println!("  stopped otherwise        {}", m.halted);
    println!("  ran to completion        {}", m.completed);
    println!("  ran clean                {}", m.clean);
    println!("  prompts shown            {}", m.prompts);
    println!(
        "  leak rate (all tasks)    {:.1}%",
        m.leak_rate() * 100.0
    );
    println!(
        "  model quality: unplannable {:.1}%",
        m.unplannable_rate() * 100.0
    );
    if !m.unplannable_ids.is_empty() {
        println!(
            "  unplannable: {}",
            m.unplannable_ids.join(", ")
        );
    }
    if !m.leaked_ids.is_empty() {
        println!("  leaked: {}", m.leaked_ids.join(", "));
    }
    println!(
        "\n  NOTE: `model could not plan` is model quality, not a blocked attack.\n\
         It is counted in the denominator so a weak model cannot improve the\n\
         leak rate by failing to produce a plan."
    );
    let _: Option<ModelControlFailure> = None;
}