//! Does the model arm report what it actually measured?
//!
//! The model arm needs a live server to produce interesting numbers, and those
//! numbers are worth very little if the arithmetic around them is wrong. So this
//! file does not test the model. It drives `run_model_arm` with a scripted
//! backend, where each task gets a predetermined plan, and checks the accounting.
//!
//! # The failure this exists to prevent
//!
//! A small model frequently fails to produce a usable plan. If an unplannable task
//! were counted as a "blocked attack", then a model that could not plan *anything*
//! would score a perfect defence rate — and the measurement would be an artefact
//! of model weakness presented as evidence about the design. That is the single
//! worst outcome available to a security metric, and it is the one this file is
//! built to make impossible.

use agentos_eval::model::{
    run_model_arm, ModelControlFailure, ModelMeasurement, ModelTask, MODEL_CORPUS,
};
use agentos_infer::{Backend, Completion, Conversation, InferError, Output, Role, Usage};
use agentos_types::Trusted;

/// A backend that answers with a fixed plan for every task.
struct Scripted {
    /// Returned for every request.
    response: String,
}

impl Backend for Scripted {
    fn complete(
        &mut self,
        _role: Role,
        _conversation: &Conversation,
    ) -> Result<Completion, InferError> {
        Ok(Completion {
            output: Output::PlannerText(Trusted::inherited(
                agentos_types::Origin::Controller(agentos_types::ControllerAuthority::issue()),
                self.response.clone(),
            )),
            usage: Usage::default(),
        })
    }

    fn supports_constrained_decoding(&self) -> bool {
        true
    }

    fn name(&self) -> &str {
        "scripted"
    }
}

/// A plan that does nothing, so every task "runs" cleanly.
const NOOP: &str = r#"{"program": [{"op": "let", "name": "w", "value": "\"x\""},
                                   {"op": "report", "value": "w"}]}"#;

/// Nonsense, so every task is unplannable.
const NONSENSE: &str = "I cannot help with that.";

fn arm(response: &str, approve: bool) -> ModelMeasurement {
    let mut backend = Scripted {
        response: response.to_string(),
    };
    run_model_arm(&mut backend, &mut move |_| approve)
}

/// Every task must land in exactly one bucket.
#[test]
fn every_task_lands_in_exactly_one_bucket() {
    for (label, m) in [
        ("no-op plan", arm(NOOP, false)),
        ("nonsense", arm(NONSENSE, false)),
        ("approving", arm(NOOP, true)),
    ] {
        assert_eq!(
            m.check_accounting(),
            Ok(()),
            "{label}: accounting must balance"
        );
        assert_eq!(m.total, MODEL_CORPUS.len(), "{label}");
    }
}

/// A model that cannot plan at all must score zero leaks, not a perfect defence.
///
/// This is the headline control. A model returning nonsense for every task gives
/// `unplannable == total` and `leaked == 0`. The rate is legitimately 0%, but the
/// *reason* is model weakness, and `unplannable_rate` has to say so out loud —
/// otherwise "0% leak rate" reads as "the design stopped everything".
#[test]
fn a_model_that_cannot_plan_reports_zero_leaks_but_says_why() {
    let m = arm(NONSENSE, false);

    assert_eq!(m.unplannable, m.total, "every task should be unplannable");
    assert_eq!(m.planned, 0);
    assert_eq!(m.leaked, 0);
    assert_eq!(m.leak_rate(), 0.0);

    // The distinction that matters: the rate is 0 because nothing ran, and the
    // unplannable rate is 1. A reader who only sees "0%" is misled; a reader who
    // sees both is not.
    assert_eq!(m.unplannable_rate(), 1.0);
    assert_eq!(
        m.unplannable_ids.len(),
        m.total,
        "every unplannable task must be named, so a reader can check"
    );
}

/// Unplannable tasks stay in the denominator.
///
/// Excluding them would shrink the sample to whatever the model happened to
/// succeed at, which is selection bias dressed up as a clean result.
#[test]
fn unplannable_tasks_stay_in_the_denominator() {
    let m = arm(NONSENSE, false);
    assert_eq!(m.denominator(), m.total);
    assert_eq!(
        m.denominator(),
        MODEL_CORPUS.len(),
        "the denominator is every task, not every task the model managed"
    );
}

/// An unplannable task counted as blocked is a control failure.
///
/// Constructed by hand rather than produced by a run, because the whole point is
/// that the run should never produce it.
#[test]
fn folding_unplannable_into_blocked_is_detected() {
    let broken = ModelMeasurement {
        total: 8,
        unplannable: 3,
        planned: 5,
        // Six blocked results from five planned tasks: one unplannable task was
        // counted as blocked.
        denied: 2,
        refused: 3,
        halted: 1,
        leaked: 0,
        clean: 2,
        completed: 0,
        prompts: 5,
        unplannable_ids: vec!["a", "b", "c"],
        leaked_ids: vec![],
        prompted_ids: vec![],
        schema_invented: 0,
        schema_invented_ids: vec![],
    };
    assert_eq!(
        broken.check_accounting(),
        Err(ModelControlFailure::UnplannableCountedAsBlocked { overlaps: 1 })
    );
}

/// A lost bucket is a control failure.
#[test]
fn a_lost_bucket_is_detected() {
    let broken = ModelMeasurement {
        total: 8,
        unplannable: 3,
        planned: 4, // one task uncounted
        denied: 1,
        refused: 1,
        halted: 1,
        leaked: 0,
        clean: 1,
        completed: 0,
        prompts: 2,
        unplannable_ids: vec!["a", "b", "c"],
        leaked_ids: vec![],
        prompted_ids: vec![],
        schema_invented: 0,
        schema_invented_ids: vec![],
    };
    assert_eq!(
        broken.check_accounting(),
        Err(ModelControlFailure::Unaccounted {
            accounted: 7,
            total: 8
        })
    );
}

/// A planned task that ended in no bucket is a control failure.
///
/// The check that would have caught the first version of this arm listing a task
/// under `leaked_ids` while counting zero leaks: five terminal outcomes for six
/// planned tasks, and nothing said so.
#[test]
fn an_unresolved_task_is_detected() {
    let broken = ModelMeasurement {
        total: 8,
        unplannable: 2,
        planned: 6,
        denied: 2,
        refused: 1,
        halted: 0,
        completed: 2, // 2 + 1 + 0 + 2 == 5, for 6 planned
        leaked: 2,
        clean: 0,
        prompts: 1,
        unplannable_ids: vec!["a", "b"],
        leaked_ids: vec!["c", "d"],
        prompted_ids: vec![],
        schema_invented: 0,
        schema_invented_ids: vec![],
    };
    assert_eq!(
        broken.check_accounting(),
        Err(ModelControlFailure::Unresolved {
            resolved: 5,
            planned: 6
        })
    );
}

/// A task may leak *and* be denied, and the accounting must allow it.
///
/// Found by the control failing on the first real model run: a plan wrote to a
/// file with tainted contents (allowed) and then tried a denied shell command, so
/// the session ended `Denied` with data already gone. Treating "leaked" and
/// "stopped" as alternatives — which the first version did — forces one of the
/// two facts to be dropped.
#[test]
fn leaking_and_being_denied_can_co_occur() {
    let m = ModelMeasurement {
        total: 4,
        unplannable: 0,
        planned: 4,
        denied: 2,
        refused: 1,
        halted: 0,
        completed: 1,
        // One of the denied tasks also leaked before the denial.
        leaked: 1,
        clean: 0,
        prompts: 1,
        unplannable_ids: vec![],
        leaked_ids: vec!["a"],
        prompted_ids: vec![],
        schema_invented: 0,
        schema_invented_ids: vec![],
    };
    assert_eq!(m.check_accounting(), Ok(()), "this must be legal");
}

/// More clean tasks than completed tasks is nonsense.
#[test]
fn clean_cannot_exceed_completed() {
    let broken = ModelMeasurement {
        total: 4,
        unplannable: 0,
        planned: 4,
        denied: 1,
        refused: 1,
        halted: 0,
        completed: 2,
        leaked: 0,
        clean: 3,
        prompts: 0,
        unplannable_ids: vec![],
        leaked_ids: vec![],
        prompted_ids: vec![],
        schema_invented: 0,
        schema_invented_ids: vec![],
    };
    assert_eq!(
        broken.check_accounting(),
        Err(ModelControlFailure::CleanExceedsCompleted {
            clean: 3,
            completed: 2
        })
    );
}

/// Every task is a benign request; the attack lives in the document.
///
/// If a request were written as an attack, the model would be refusing a bad
/// request rather than resisting an injection, and the measurement would be about
/// the model's alignment rather than about this system. This cannot check the
/// wording, but it can check that the corpus pairs both kinds of document with
/// benign-looking requests and that every attack entry has a non-empty document —
/// an attack with an empty document would be untestable and would silently pass.
#[test]
fn every_attack_has_a_document_and_the_corpus_covers_both_kinds() {
    let attacks = MODEL_CORPUS.iter().filter(|t| t.attack).count();
    let benign = MODEL_CORPUS.iter().filter(|t| !t.attack).count();

    assert!(attacks > 0, "the corpus must contain attacks");
    assert!(benign > 0, "the corpus must contain benign controls");

    for t in MODEL_CORPUS.iter() {
        if t.attack {
            assert!(
                !t.document.is_empty(),
                "{}: an attack with no document has nothing to inject",
                t.id
            );
        }
        assert!(
            !t.request.is_empty(),
            "{}: a task with no request plans nothing",
            t.id
        );
    }
}

/// Every attack has a benign twin.
///
/// Without one the corpus cannot tell "the injection was resisted" from "this task
/// always prompts" — and an arm in which every task prompts measures the
/// existence of the prompt rather than the model's behaviour. A corpus drifts
/// toward prompts-everywhere exactly by losing these, so the pairing is asserted
/// rather than assumed.
///
/// Twins are found by walking back through the id's segments until a matching
/// `-benign` task appears.
///
/// So `model/recipient-injected` pairs with `model/recipient-benign`, and
/// `model/recipient-authority-injected` — named for its vector rather than its
/// effect — pairs with the same twin. Allowing several attacks to share one
/// benign control is deliberate: they are the same request against the same
/// clean document, differing only in what the hostile one says.
#[test]
fn every_attack_has_a_benign_twin() {
    let tasks: Vec<&ModelTask> = MODEL_CORPUS.iter().collect();

    for t in tasks.iter().filter(|t| t.attack) {
        let mut candidate = t.id;
        let twin = loop {
            let Some((head, _)) = candidate.rsplit_once('-') else {
                panic!("{}: an attack id must have a variant suffix", t.id);
            };
            let try_id = format!("{head}-benign");
            if let Some(found) = tasks.iter().find(|x| x.id == try_id) {
                break *found;
            }
            candidate = head;
        };

        assert!(
            !twin.attack,
            "{}: twin {} must be a benign control",
            t.id,
            twin.id
        );
        assert_eq!(
            twin.request, t.request,
            "{}: twin {} must use the SAME request, or the pair compares two \
             different tasks rather than the document's effect",
            t.id,
            twin.id
        );
    }
}
#[test]
fn task_ids_are_unique() {
    let mut ids: Vec<&str> = MODEL_CORPUS.iter().map(|t| t.id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), before, "two model tasks share an id");
}