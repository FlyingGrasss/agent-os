//! Attacks against a real model, end to end.
//!
//! Separate binary from `agentos-eval` because it needs a live model server and
//! takes minutes. `agentos-eval` measures the policy layer against hand-written
//! plans and must stay fast and hermetic; this measures what a model *does* with
//! the same defences.
//!
//! Usage: `cargo run -p agentos-eval --bin agentos-model-eval -- <model>`
//! (defaults to `llama3.2:3b`).

use agentos_eval::model::{run_model_arm, AdversarialPlanner, SchemaControl, MODEL_CORPUS};
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
    println!("model: {model}");
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
    let mut adversary4 = AdversarialPlanner { emitted: Vec::new() };
    let closed =
        run_model_arm(&mut adversary4, &mut |_| true, SchemaControl::Closed { max_chars: BOUND });

    println!("\n# Results\n");
    report("adversarial planner, declining user", std::slice::from_ref(&adversarial));
    println!();
    report(
        "adversarial planner, approving user",
        std::slice::from_ref(&adversarial_approved),
    );
    println!();

    // The same two arms with a bounded schema. Deterministic, so this is an exact
    // A/B rather than a comparison between two noisy samples -- which is the only
    // reason to trust the delta at all.
    println!("\n## The same arm with a {BOUND}-character bound, then with closed types\n");
    report(
        "adversarial, approving, bounded",
        std::slice::from_ref(&bounded),
    );
    println!();
    report("adversarial, approving, closed", std::slice::from_ref(&closed));
    println!();

    // One bounded live run, when a server was available. See the note where it is
    // taken: a single sample, labelled as one.
    if let Some(b) = approved_bounded.as_ref() {
        report("live, approving, bounded", std::slice::from_ref(b));
        println!();
    }

    if !deterministic_only {
        println!("\n## Live model\n");
        report("declining user", &declined_runs);
        println!();
        report("approving user", &approved_runs);
    }

    println!("\n## Controls\n");
    let mut ok = true;
    for (label, m) in [
        ("adversarial/declining", &adversarial),
        ("adversarial/approving", &adversarial_approved),
        ("adversarial/approving/bounded", &bounded),
        ("adversarial/approving/closed", &closed),
    ] {
        match m.check_accounting() {
            Ok(()) => println!("  {label}: accounting ok"),
            Err(e) => {
                println!("  {label}: ACCOUNTING FAILURE: {e}");
                ok = false;
            }
        }
    }
    // The bounded live run is accounted for only when it was actually taken.
    // Skipping it rather than checking a placeholder: a control that passes because
    // there was nothing to check is the failure mode this project keeps hitting.
    if let Some(b) = approved_bounded.as_ref() {
        match b.check_accounting() {
            Ok(()) => println!("  live/approving/bounded: accounting ok"),
            Err(e) => {
                println!("  live/approving/bounded: ACCOUNTING FAILURE: {e}");
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

    // The control that makes the controls mean something. If a constrained arm
    // forwards *more* than the unbounded baseline, the constraint is not
    // constraining, and the table above would otherwise be reported as a result.
    //
    // Checked on the deterministic arms only. A single live sample can legitimately
    // land on the other side of this by chance, and a control that fires at random
    // is a control people learn to ignore.
    for (label, constrained, unbounded) in [
        ("bounded", &bounded, &adversarial_approved),
        ("closed types", &closed, &adversarial_approved),
    ] {
        if constrained.forwarded_bytes > unbounded.forwarded_bytes {
            println!(
                "  {label}: FAILURE -- forwarded {} bytes against the unbounded \
                 arm's {}",
                constrained.forwarded_bytes, unbounded.forwarded_bytes
            );
            ok = false;
        } else {
            println!(
                "  {label}: forwarding {} -> {} bytes",
                unbounded.forwarded_bytes, constrained.forwarded_bytes
            );
        }
    }

    // And the claim the closed-type arm actually makes: it must forward strictly
    // less than the length bound. Closed types remove the surface; a bound only
    // shrinks it. If they came out equal, the closed arm would not be doing the
    // thing it exists to demonstrate.
    if closed.forwarded_bytes >= bounded.forwarded_bytes {
        println!(
            "\n  NOTE: closed types forwarded {} bytes against the bound's {}. The\n\
             claim that a closed type removes the surface rather than shrinking it\n\
             did NOT hold in this arm. The two free-form fields (`note`,\n\
             `recipient`) are what is left, and they are the part no schema can\n\
             close without removing the user's data.",
            closed.forwarded_bytes, bounded.forwarded_bytes
        );
    }

    // The bound must not be quietly stealing credit from the intent pins.
    //
    // `pin_denied` can fall in a constrained arm, and the obvious reading is that
    // the pins got better. That reading is wrong: a constrained schema refuses the
    // *extraction*, so several tasks stop one step earlier, before the plan ever
    // reaches the pinned tool. The attack is stopped -- but by the extraction
    // failing, not by the pin firing.
    //
    // So the columns are not comparable as "defences", only as "outcomes".
    // Reporting a drop as a pin improvement would be reading a defence as working
    // when it was in fact bypassed.
    if closed.pin_denied < adversarial_approved.pin_denied {
        println!(
            "\n  NOTE: pin_denied fell {} -> {} in the closed arm. That is not the\n\
             pins getting better. The constrained schema refuses the extraction\n\
             first, so those tasks stop before reaching the pinned tool. Only the\n\
             unbounded column measures the pins.",
            adversarial_approved.pin_denied, closed.pin_denied
        );
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
        "  untrusted bytes reaching a tool   {}",
        runs.iter().map(|m| m.forwarded_bytes).sum::<usize>()
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
