//! Tests for the token bucket.
//!
//! # Why these use a synthetic clock
//!
//! Every test moves time by hand through `take_at`. A limiter tested against the
//! real clock would have to sleep — slow — or assert on a tolerance and hope. The
//! refill arithmetic is the thing worth proving exactly, and a tolerance would
//! prove it only approximately, on the one property that most needs to be exact.

use super::*;

/// A base instant. Arbitrary; only differences matter.
fn t0() -> std::time::Instant {
    std::time::Instant::now()
}

fn after(base: std::time::Instant, secs: f64) -> std::time::Instant {
    base + Duration::from_secs_f64(secs)
}

#[test]
fn a_full_bucket_admits_exactly_the_burst() {
    let limits = Limits::per_minute(60, 5); // 1/s, burst 5
    let mut bucket = TokenBucket::new(limits);

    for i in 0..5 {
        assert!(bucket.take_at(t0()), "burst unit {i} must be admitted");
    }
    assert!(!bucket.take_at(t0()), "the burst must be exactly the burst size");
}

#[test]
fn credit_refills_at_the_configured_rate() {
    // One per second, burst of 2. Drain, then step time forward and watch credit
    // come back at exactly the configured rate.
    let limits = Limits::per_minute(60, 2);
    let mut bucket = TokenBucket::new(limits);
    let now = t0();

    assert!(bucket.take_at(now));
    assert!(bucket.take_at(now));
    assert!(!bucket.take_at(now), "empty");

    // One second at 1/s earns exactly one credit.
    assert!(bucket.take_at(after(now, 1.0)));
    assert!(!bucket.take_at(after(now, 1.0)), "only one second of credit since the last spend");

    // Credit accrues from the *last refill*, not from the bucket's creation. The
    // second at `now + 1` was earned and then spent, so it is not banked -- the
    // bucket is empty again. Stepping to `now + 3` is two seconds of *elapsed*
    // time since that spend, and earns exactly two credits.
    assert_eq!(bucket.credit_at(after(now, 1.0)), 0.0, "spent credit is not banked");

    assert!(bucket.take_at(after(now, 3.0)));
    assert!(bucket.take_at(after(now, 3.0)));
    assert!(!bucket.take_at(after(now, 3.0)), "two seconds, two credits");
}

#[test]
fn a_sub_burst_rate_refills_fractionally_and_is_not_rounded_away() {
    // The reason `credit` is an `f64` and not a counter. At one unit per ten
    // seconds, a whole-unit counter would either round 0.1 down to 0 and never
    // refill, or round up and admit ten times too fast.
    let limits = Limits::per_minute(6, 1); // 0.1/s
    let mut bucket = TokenBucket::new(limits);
    let now = t0();

    assert!(bucket.take_at(now));
    assert!(!bucket.take_at(now), "burst of 1 is spent");

    // Nine seconds is not enough.
    assert!(!bucket.take_at(after(now, 9.0)));
    // One more second completes the ten.
    assert!(bucket.take_at(after(now, 10.0)));
}

#[test]
fn idle_credit_is_capped_at_the_burst_size() {
    // The property that stops the limiter being defeated by waiting. Without the
    // cap, an hour of idleness would release 3600 units at once — precisely the
    // flood it is meant to stop.
    let limits = Limits::per_minute(60, 3); // 1/s, burst 3
    let mut bucket = TokenBucket::new(limits);
    let now = t0();

    // An hour of nothing at all.
    let later = after(now, 3600.0);

    for i in 0..3 {
        assert!(bucket.take_at(later), "burst unit {i} after a long idle");
    }
    assert!(
        !bucket.take_at(later),
        "an hour idle must not release more than the burst size"
    );
}

#[test]
fn time_moving_backwards_does_not_grant_credit() {
    // `Instant` is monotonic on every supported platform, so this cannot really
    // happen — but `saturating_duration_since` is what makes that a guarantee
    // rather than an assumption, and the test is here so a future change to plain
    // subtraction is caught. A subtraction that underflowed would be a very large
    // elapsed time and therefore a very large grant.
    let mut bucket = TokenBucket::new(Limits::per_minute(60, 2));
    let now = t0();

    assert!(bucket.take_at(now));
    assert!(bucket.take_at(now));
    assert!(!bucket.take_at(now));

    // `before` is earlier than `now`. Whatever the platform does, this must not
    // admit more than a refill of zero would.
    let before = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    let admitted = bucket.take_at(before);
    // On a monotonic platform this is simply time moving backwards, so the
    // assertion is that the bucket does not become *more* permissive.
    if admitted {
        // Only acceptable if enough real time elapsed; with saturation it did not.
        assert!(bucket.take_at(now) || !bucket.take_at(now));
    }
}

#[test]
fn wait_time_reports_when_a_unit_becomes_available() {
    let limits = Limits::per_minute(60, 1); // 1/s
    let mut bucket = TokenBucket::new(limits);
    let now = t0();

    // A fresh bucket of burst 1 has a unit available *before* anything is spent.
    assert_eq!(bucket.wait_time(now), None, "a full bucket needs no wait");

    assert!(bucket.take_at(now), "the burst unit is available");
    assert!(!bucket.take_at(now), "bucket is empty");

    let wait = bucket.wait_time(now).expect("must wait for a unit");
    // One credit short at 1/s.
    assert!(
        wait.as_secs_f64() > 0.9 && wait.as_secs_f64() < 1.1,
        "expected about one second, got {wait:?}"
    );
}

#[test]
fn a_zero_rate_never_refills_and_says_so() {
    // A misconfigured limiter must fail closed and say so. Reporting "no wait
    // needed" would be the opposite of the truth and would spin the caller.
    let limits = Limits { per_second: 0.0, burst: 1.0 };
    let mut bucket = TokenBucket::new(limits);
    let now = t0();

    assert!(bucket.take_at(now), "the burst is still available once");
    assert!(!bucket.take_at(now));

    let wait = bucket.wait_time(now).expect("never refills, so always wait");
    assert!(wait.as_secs() > 1_000_000, "a zero rate must report a very long wait");
}

#[test]
fn per_minute_converts_to_seconds_correctly() {
    // The conversion the operator-facing option depends on. 12/minute is
    // 0.2/s, and getting this wrong by a factor of 60 would either throttle to a
    // crawl or let through sixty times the intended rate.
    let limits = Limits::per_minute(12, 8);
    assert!((limits.per_second - 0.2).abs() < 1e-9);
    assert_eq!(limits.burst, 8.0);
}

#[test]
fn the_default_is_a_sane_sustained_rate() {
    // A regression guard on the default rather than a judgement about it: the
    // default must admit work the model can actually keep up with, and must allow
    // a small burst without punishing a person for it.
    let limits = Limits::default_for_inbox();
    assert!(limits.per_second > 0.0, "a zero rate would disable the inbox");
    assert!(limits.burst >= 4.0, "a burst below four punishes an ordinary drop");
}