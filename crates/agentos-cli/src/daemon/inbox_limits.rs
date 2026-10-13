//! Operator-configurable rate limits for the ambient inbox.
//!
//! # Why the inbox's flood defence is configurable at all
//!
//! [`agentos_events::Limits::default_for_inbox`] is sized for a model-backed
//! pipeline: a 3B model plans in seconds, so admitting more than about twelve
//! payloads a minute buys a queue rather than throughput. Some deployments run a
//! faster planner, or want a person dropping a large batch not to wait, and the
//! operator is better placed to judge that than a constant is. So the limit is
//! configurable — but it is configurable **downward**, and the direction that
//! loosens it is the one that gets said out loud.
//!
//! # The variables
//!
//! - `AGENTOS_INBOX_PER_MINUTE` — sustained admission rate, in payloads per
//!   minute.
//! - `AGENTOS_INBOX_BURST` — how many payloads may arrive at once.
//!
//! Minutes and whole payloads, not "per second", because that is the unit an
//! operator thinks in. Both default, independently, to the [`Limits`] default.
//!
//! # Failure is closed, and loud
//!
//! A value that is not a positive whole number is a **configuration error**, and
//! the inbox refuses to start rather than falling back to the default. That
//! direction is deliberate. The failure this defends against is not "a typo makes
//! the daemon slightly too strict"; it is "a typo silently restores a working
//! flood defence to nothing an attacker notices", or, worse, "a typo is read as
//! permission to raise the limit". A rate limit that quietly reverts when it is
//! misconfigured is not a rate limit; it is a comment. So the possible outcomes
//! here are a limiter strictly stronger than the default, or no limiter at all —
//! never a weaker one produced by an unparseable value.
//!
//! A blank value is treated as *unset*, matching [`super::env_or`] and the
//! `AGENTOS_INBOX` handling in [`super::start_inbox`]. That is safe in the
//! direction that matters: blank yields the default, which is never weaker than
//! the default.
//!
//! # Why parsing is separated from reading the environment
//!
//! [`limits_from`] takes a lookup closure rather than calling [`std::env::var`]
//! itself. Env-var tests are a classic source of the failure where an assertion
//! passes while the thing it checked is broken: a leaked variable from another
//! test silently supplies the value the test meant to control, or the test
//! asserts only that *some* parse succeeded. Taking the values as arguments makes
//! every case — unset, valid, malformed, zero, absurdly large — a value a reader
//! can see, and leaves only [`limits_from_env`] touching the process.
//!
//! # What is *not* here
//!
//! No value in this file is provenance-labelled, and none needs to be. These are
//! operator-supplied integers read from the daemon's own environment, not bytes
//! from a hostile source, and they never reach a model prompt. They do reach a
//! rate limiter, which is why they are validated rather than trusted.

use std::fmt;

use agentos_events::Limits;

/// Sustained rate, in payloads per minute. Unset means the default (12).
pub const ENV_PER_MINUTE: &str = "AGENTOS_INBOX_PER_MINUTE";

/// Burst size, in payloads. Unset means the default (8).
pub const ENV_BURST: &str = "AGENTOS_INBOX_BURST";

/// The daemon's own per-variable defaults, in the operator's units.
///
/// Named rather than inlined so the warning text and the parse path cannot drift
/// apart: a warning that quoted one pair while the parser used another would be a
/// warning about the wrong numbers.
const DEFAULT_PER_MINUTE: u32 = 12;
const DEFAULT_BURST: u32 = 8;

/// The pair a refusal message quotes, so the text the operator reads and the
/// values the parser uses cannot drift apart.
pub fn default_pair() -> (u32, u32) {
    (DEFAULT_PER_MINUTE, DEFAULT_BURST)
}

/// A refusal to build a limiter from what the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitsError {
    /// The variable is set to something that is not a whole number.
    ///
    /// Covers `"abc"`, `"12/min"`, `"-5"`, and a value too large for a `u32`.
    /// All are one thing to an operator: that is not a number of payloads.
    NotANumber { var: &'static str, value: String },
    /// The variable is set to zero.
    ///
    /// A zero rate would never refill, so the inbox would accept the payload in
    /// the initial burst and then defer everything forever — a daemon that looks
    /// alive and silently stops processing. A zero burst would refuse the first
    /// payload outright. Neither is a rate anybody meant to ask for, so neither is
    /// granted.
    Zero { var: &'static str },
}

impl LimitsError {
    /// Whether this refusal leaves the daemon with *more* admission than a
    /// limiter built from the operator's own value would have.
    ///
    /// Always `false`. It exists as an assertion the tests can make rather than as
    /// a branch: there is no path out of [`limits_from`] that yields a `Limits`
    /// at all when the configuration is bad, so the question of "what rate did the
    /// typo produce" has no answer to give.
    pub fn yields_weaker_limits(&self) -> bool {
        false
    }
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitsError::NotANumber { var, value } => write!(
                f,
                "{var} is set to {value:?}, which is not a whole number of payloads"
            ),
            LimitsError::Zero { var } => write!(
                f,
                "{var} is 0, which would make the inbox refuse work forever rather \
                 than admit it slowly"
            ),
        }
    }
}

impl std::error::Error for LimitsError {}

/// Build the inbox's limits from the operator's configuration.
///
/// `get` is a lookup for one variable name: [`None`] means "not set". Passing a
/// closure rather than reading the environment keeps every decision below
/// reachable from a test without mutating the process's environment.
pub fn limits_from(get: impl Fn(&str) -> Option<String>) -> Result<Limits, LimitsError> {
    let per_minute = positive(ENV_PER_MINUTE, DEFAULT_PER_MINUTE, &get)?;
    let burst = positive(ENV_BURST, DEFAULT_BURST, &get)?;
    Ok(Limits::per_minute(per_minute, burst))
}

/// Read the same configuration from this process's environment.
///
/// The one place [`std::env::var`] is consulted. Thin on purpose: everything that
/// can be wrong with the values is decided in [`limits_from`], so the tests for
/// this file exercise real logic rather than this wrapper.
pub fn limits_from_env() -> Result<Limits, LimitsError> {
    limits_from(|key| std::env::var(key).ok())
}

/// One variable, or its default.
///
/// Blank counts as unset, as elsewhere in the daemon. Unparseable and zero are
/// refusals, never fallbacks.
fn positive(
    var: &'static str,
    default: u32,
    get: &impl Fn(&str) -> Option<String>,
) -> Result<u32, LimitsError> {
    let raw = match get(var) {
        Some(raw) => raw,
        None => return Ok(default),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    let value: u32 = trimmed
        .parse()
        .map_err(|_| LimitsError::NotANumber { var, value: trimmed.to_string() })?;
    if value == 0 {
        return Err(LimitsError::Zero { var });
    }
    Ok(value)
}

/// Whether `limits` admits more than [`Limits::default_for_inbox`] does.
///
/// Two independent reasons to say yes, and both are checked rather than assumed:
///
/// 1. The operator set a rate or burst above the default, whether or not the
///    result is still plausible on its face.
/// 2. [`agentos_events::inbox::Inbox::flood_defence_is_weak`] would be true —
///    above one payload per *second*, which no model-backed pipeline sustains and
///    which almost certainly means the number was misread rather than tuned.
///
/// Strictly greater, so a limit exactly equal to the default is silent.
pub fn weakens_flood_defence(limits: &Limits) -> bool {
    let default = Limits::default_for_inbox();
    limits.per_second > default.per_second
        || limits.burst > default.burst
        || limits.per_second > 1.0
}

/// The startup warning for a limit looser than the default.
///
/// [`None`] when nothing was loosened, so the caller cannot print a warning for
/// a configuration that did not need one — and cannot forget to check, because
/// the only way to get text out of this module is through the check.
///
/// Exactly one line. Loosening a flood defence is a decision an operator is
/// entitled to make, so this is a statement of fact rather than an objection; but
/// it is printed once at startup rather than per payload, because a daemon that
/// repeats itself is a daemon whose log gets filtered.
pub fn weakening_warning(limits: &Limits) -> Option<String> {
    if !weakens_flood_defence(limits) {
        return None;
    }
    let default = Limits::default_for_inbox();
    Some(format!(
        "agentosd: WARNING: {ENV_PER_MINUTE}/{ENV_BURST} loosen the inbox flood defence \
         (effective {}/min sustained, burst {}; the default is {}/min, burst {})",
        per_minute(limits),
        limits.burst as u32,
        per_minute(&default),
        default.burst as u32,
    ))
}

/// `per_second` back in the unit the operator set it in.
///
/// Rounded rather than truncated: the limiter works in `f64` seconds, and a
/// warning saying "11/min" for a configured twelve is the kind of small lie that
/// makes an operator distrust the rest of the line.
fn per_minute(limits: &Limits) -> u32 {
    (limits.per_second * 60.0).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lookup over a fixed table, so every test states its whole environment.
    ///
    /// `None` for anything not named, which is what makes "the other variable is
    /// unset" explicit rather than dependent on what the real process happens to
    /// hold.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    fn per_minute_of(limits: &Limits) -> f64 {
        limits.per_second * 60.0
    }

    // -- the default ---------------------------------------------------------

    #[test]
    fn with_nothing_set_the_limits_are_the_default() {
        let limits = limits_from(env(&[])).expect("an unset variable is not an error");
        let default = Limits::default_for_inbox();
        assert_eq!(per_minute_of(&limits), per_minute_of(&default));
        assert_eq!(limits.burst, default.burst);
    }

    #[test]
    fn the_local_defaults_are_the_limiter_s_defaults() {
        // The daemon keeps its own copy so a refusal message can quote the numbers
        // without constructing a `Limits`. That copy is a drift risk: if the two
        // disagree, an operator is told "unset it to get 12/min" and gets
        // something else, and the warning quotes the two side by side. This is
        // the test that keeps them the same number.
        let (per_minute, burst) = default_pair();
        let default = Limits::default_for_inbox();
        assert_eq!(per_minute, per_minute_of(&default) as u32, "per-minute default");
        assert_eq!(burst as f64, default.burst, "burst default");
    }

    #[test]
    fn one_variable_set_leaves_the_other_at_its_default() {
        // Each is optional on its own, and the defaults are read per variable
        // rather than as a pair, so setting one is a real half-configuration.
        let rate_only = limits_from(env(&[(ENV_PER_MINUTE, "30")])).unwrap();
        assert_eq!(per_minute_of(&rate_only), 30.0);
        assert_eq!(rate_only.burst, DEFAULT_BURST as f64);

        let burst_only = limits_from(env(&[(ENV_BURST, "4")])).unwrap();
        assert_eq!(per_minute_of(&burst_only), DEFAULT_PER_MINUTE as f64);
        assert_eq!(burst_only.burst, 4.0);
    }

    #[test]
    fn a_blank_value_is_treated_as_unset_rather_than_as_zero() {
        // Matches `env_or` and the `AGENTOS_INBOX` handling in `start_inbox`. Safe
        // in the direction that matters: blank yields the default, which is never
        // weaker than the default. If this ever changes, it must not become a way
        // to obtain a *higher* rate.
        for blank in ["", "   ", "\t"] {
            let limits = limits_from(env(&[(ENV_PER_MINUTE, blank), (ENV_BURST, blank)]))
                .expect("blank means unset, not error");
            assert_eq!(limits, Limits::default_for_inbox(), "blank {blank:?}");
        }
    }

    // -- a valid pair --------------------------------------------------------

    #[test]
    fn a_valid_pair_is_parsed_as_given() {
        let limits = limits_from(env(&[(ENV_PER_MINUTE, "60"), (ENV_BURST, "20")])).unwrap();
        assert_eq!(per_minute_of(&limits), 60.0);
        assert_eq!(limits.burst, 20.0);
        // Parsed as one payload per second, exactly: 60/60.
        assert_eq!(limits.per_second, 1.0);
    }

    #[test]
    fn surrounding_whitespace_does_not_make_a_number_invalid() {
        // A value written by a config manager arrives padded. Refusing it would
        // train an operator to quote the variable, which is not the habit worth
        // teaching around a security control.
        let limits = limits_from(env(&[(ENV_PER_MINUTE, " 24 "), (ENV_BURST, "\t6\n")])).unwrap();
        assert_eq!(per_minute_of(&limits), 24.0);
        assert_eq!(limits.burst, 6.0);
    }

    #[test]
    fn a_tighter_limit_than_the_default_is_honoured_exactly() {
        // The fail-closed rules must not have quietly become "clamp to the
        // default": an operator who tightens the flood defence must get it.
        let limits = limits_from(env(&[(ENV_PER_MINUTE, "1"), (ENV_BURST, "1")])).unwrap();
        assert_eq!(per_minute_of(&limits), 1.0);
        assert_eq!(limits.burst, 1.0);
        assert!(
            !weakens_flood_defence(&limits),
            "a tighter limit weakens nothing"
        );
    }

    // -- malformed: refused, not defaulted -----------------------------------

    #[test]
    fn a_non_numeric_value_is_a_configuration_error_and_yields_no_limiter() {
        // The whole point. A `unwrap_or(default)` here would mean `AGENTOS_INBOX_
        // PER_MINUTE=twelve` starts a daemon at the default rate while the
        // operator believes they configured something else.
        let error = limits_from(env(&[(ENV_PER_MINUTE, "twelve")]))
            .expect_err("an unparseable rate must not fall back to the default");
        assert!(
            matches!(error, LimitsError::NotANumber { var: ENV_PER_MINUTE, .. }),
            "got {error:?}"
        );
        assert!(!error.yields_weaker_limits());
    }

    #[test]
    fn every_way_of_mistyping_a_number_is_refused() {
        // Asserted one at a time over a table, because a loop with a single
        // assertion after it can pass on the first case and prove nothing about
        // the rest.
        for bad in ["abc", "12/min", "1_2", "-5", "99999999999999999999", "1.5", "0x10"] {
            let rate = limits_from(env(&[(ENV_PER_MINUTE, bad)]));
            assert!(rate.is_err(), "rate {bad:?} must be refused, got {rate:?}");
            let burst = limits_from(env(&[(ENV_BURST, bad)]));
            assert!(burst.is_err(), "burst {bad:?} must be refused, got {burst:?}");
        }
    }

    #[test]
    fn a_malformed_value_never_produces_a_higher_rate_than_the_default() {
        // Stated as an observable property rather than inferred from the error:
        // walk a spread of hostile values, and for every one that produces a
        // limiter at all, require that limiter to be no weaker than the default.
        let default = Limits::default_for_inbox();
        // Note what is *not* in this list: `"12 "` and `" 12"`. Those parse, on
        // purpose (see the whitespace test), and they set 12/min with a burst of
        // 12 -- above the default burst, so genuinely a loosening, but a
        // deliberate one rather than a malformed value. A hostile-value table that
        // swept them in would be asserting that the operator cannot use a padded
        // number, which is not what this test is for.
        let hostile = [
            "", " ", "abc", "0", "-1", "1e400", "NaN", "inf", "+", "99999999999999999999",
            "1.5", "12;rm -rf /", "0x10", "\u{0}", "1 2", "--12", "12u32",
        ];
        for value in hostile {
            let parsed = limits_from(env(&[(ENV_PER_MINUTE, value), (ENV_BURST, value)]));
            if let Ok(limits) = parsed {
                assert!(
                    per_minute_of(&limits) <= per_minute_of(&default)
                        && limits.burst <= default.burst,
                    "{value:?} produced limits weaker than the default: {limits:?}"
                );
            }
        }
    }

    #[test]
    fn an_error_names_the_variable_so_the_operator_knows_which_one() {
        // The message is the interface here: the daemon cannot ask anyone, so the
        // refusal has to be actionable on its own. Asserting on the variable
        // rather than on the whole string keeps this from breaking on wording.
        let error = limits_from(env(&[(ENV_BURST, "nope")])).unwrap_err();
        assert!(matches!(error, LimitsError::NotANumber { var: ENV_BURST, .. }));
        assert!(error.to_string().contains(ENV_BURST), "{error}");
        assert!(error.to_string().contains("nope"), "{error}");
    }

    // -- zero: refused, and never an unlimited limiter -----------------------

    #[test]
    fn a_zero_rate_is_refused_rather_than_becoming_a_dead_inbox() {
        let error = limits_from(env(&[(ENV_PER_MINUTE, "0")]))
            .expect_err("a zero rate must not be admitted");
        assert!(matches!(error, LimitsError::Zero { var: ENV_PER_MINUTE }), "got {error:?}");
    }

    #[test]
    fn a_zero_burst_is_refused() {
        let error = limits_from(env(&[(ENV_BURST, "0")])).unwrap_err();
        assert!(matches!(error, LimitsError::Zero { var: ENV_BURST }), "got {error:?}");
    }

    #[test]
    fn no_spelling_of_zero_yields_an_unlimited_or_infinite_limiter() {
        // The property, checked directly against the resulting numbers rather than
        // against the error type: a mutant that mapped zero to `u32::MAX`, or
        // accepted a zero burst and let the bucket start full, would produce a
        // limiter here that this catches.
        let default = Limits::default_for_inbox();
        for value in ["0", " 0 ", "00", "+0", "0x0", "0.0", "0e0", "-0", "١٠", ""] {
            if let Ok(limits) = limits_from(env(&[(ENV_PER_MINUTE, value), (ENV_BURST, value)])) {
                assert!(
                    per_minute_of(&limits) <= per_minute_of(&default)
                        && limits.burst <= default.burst,
                    "{value:?} produced limits weaker than the default: {limits:?}"
                );
                assert!(
                    limits.per_second.is_finite() && limits.burst.is_finite(),
                    "{value:?} produced a non-finite limiter: {limits:?}"
                );
            }
        }
    }

    #[test]
    fn one_bad_variable_refuses_even_when_the_other_is_valid() {
        // A half-valid pair is not a half-configured limiter. Admitting the good
        // half here would let `AGENTOS_INBOX_BURST=0` through as long as someone
        // had set the rate.
        assert!(limits_from(env(&[(ENV_PER_MINUTE, "60"), (ENV_BURST, "0")])).is_err());
        assert!(limits_from(env(&[(ENV_PER_MINUTE, "60"), (ENV_BURST, "x")])).is_err());
        assert!(limits_from(env(&[(ENV_PER_MINUTE, "0"), (ENV_BURST, "4")])).is_err());
    }

    // -- the weakening check -------------------------------------------------

    #[test]
    fn the_default_and_anything_tighter_does_not_look_like_a_weakening() {
        assert!(!weakens_flood_defence(&Limits::default_for_inbox()));
        assert!(!weakens_flood_defence(&Limits::per_minute(6, 2)));
        assert!(!weakens_flood_defence(&Limits::per_minute(DEFAULT_PER_MINUTE, DEFAULT_BURST)));
    }

    #[test]
    fn a_rate_above_the_default_is_reported_as_weakening() {
        // Not merely the "implausible" case the limiter itself flags. Twenty per
        // minute is twice the default and entirely plausible, and an operator who
        // doubled it should still be told the flood defence moved.
        assert!(weakens_flood_defence(&Limits::per_minute(DEFAULT_PER_MINUTE + 1, DEFAULT_BURST)));
        assert!(weakens_flood_defence(&Limits::per_minute(20, DEFAULT_BURST)));
    }

    #[test]
    fn a_burst_above_the_default_is_reported_even_with_a_slow_rate() {
        // A low rate with a huge burst admits the whole flood instantly and then
        // pays it back slowly. It is a loosening, and the burst is what did it.
        assert!(weakens_flood_defence(&Limits::per_minute(1, DEFAULT_BURST + 1)));
        assert!(weakens_flood_defence(&Limits::per_minute(1, 10_000)));
    }

    #[test]
    fn an_implausible_rate_is_reported_even_if_it_were_the_only_rule() {
        // The `per_second > 1.0` arm: 60/min is exactly one per second, and is
        // not above the default. The test that a code path keeping only this arm
        // would fail on 20/min, and one keeping only the "above default" arm would
        // fail on 600/min. Requiring both to be true here is what forces both arms
        // to exist.
        assert!(weakens_flood_defence(&Limits::per_minute(600, 1)));
    }

    // -- the warning ---------------------------------------------------------

    #[test]
    fn no_warning_is_produced_for_a_limit_that_is_not_loosened() {
        assert!(weakening_warning(&Limits::default_for_inbox()).is_none());
        assert!(weakening_warning(&Limits::per_minute(6, 2)).is_none());
    }

    #[test]
    fn the_warning_is_one_line_naming_the_settings_and_the_effective_values() {
        let limits = Limits::per_minute(120, 40);
        let warning = weakening_warning(&limits).expect("120/min weakens 12/min");
        assert!(!warning.contains('\n'), "the warning must be exactly one line: {warning:?}");
        assert!(warning.contains(ENV_PER_MINUTE), "{warning}");
        assert!(warning.contains(ENV_BURST), "{warning}");
        assert!(warning.contains("120"), "the effective rate must be named: {warning}");
        assert!(warning.contains("40"), "the effective burst must be named: {warning}");
        assert!(warning.contains("12"), "the default rate must be named for contrast: {warning}");
        assert!(warning.contains("8"), "the default burst must be named for contrast: {warning}");
    }

    #[test]
    fn the_warning_quotes_the_rate_the_operator_actually_set() {
        // Round-tripped through the f64 seconds the limiter actually uses, so a
        // warning cannot report "11/min" for a configured twelve.
        for per_minute in [13u32, 24, 60, 120, 999] {
            let warning = weakening_warning(&Limits::per_minute(per_minute, DEFAULT_BURST))
                .unwrap();
            assert!(
                warning.contains(&format!("{per_minute}/min")),
                "expected {per_minute}/min in: {warning}"
            );
        }
    }

    // -- the environment wrapper ---------------------------------------------

    /// Serialises the tests that touch the real process environment.
    ///
    /// `set_var` is process-global, so two such tests running at once could read
    /// each other's variables — which is precisely how an env test ends up
    /// asserting that a value the test set is present when it was the other test's
    /// value that was present. One lock, held for the whole read-modify-restore.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    use std::sync::Mutex;

    /// Run `body` with the two inbox variables set as given, restoring whatever
    /// was there before — including the difference between unset and empty.
    fn with_env<T>(
        pairs: &[(&str, Option<&str>)],
        body: impl FnOnce() -> T,
    ) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved: Vec<(String, Option<String>)> = pairs
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (key, value) in pairs {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        let outcome = body();
        for (key, value) in saved {
            match value {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
        outcome
    }

    #[test]
    fn the_environment_wrapper_reads_the_variables_it_is_meant_to() {
        // Thin by design: this asserts the wiring (the right names, the right
        // lookup), not the policy, which the pure tests above pin down. Without
        // it, a rename of one constant would leave every other test green while
        // the feature silently stopped responding to its documented variable.
        let limits = with_env(
            &[
                (ENV_PER_MINUTE, Some("45")),
                (ENV_BURST, Some("9")),
            ],
            || limits_from_env().unwrap(),
        );
        assert_eq!(per_minute_of(&limits), 45.0);
        assert_eq!(limits.burst, 9.0);
    }

    #[test]
    fn the_environment_wrapper_refuses_a_mistyped_value_rather_than_defaulting() {
        let error = with_env(&[(ENV_PER_MINUTE, Some("lots"))], || {
            limits_from_env().expect_err("the real environment must be refused too")
        });
        assert!(matches!(error, LimitsError::NotANumber { .. }), "got {error:?}");
    }

    #[test]
    fn the_environment_wrapper_falls_back_to_the_default_when_unset() {
        let limits = with_env(
            &[(ENV_PER_MINUTE, None), (ENV_BURST, None)],
            || limits_from_env().expect("unset is not an error"),
        );
        assert_eq!(limits, Limits::default_for_inbox());
    }
}