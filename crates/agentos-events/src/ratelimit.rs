//! A token bucket for bounding how much work a flood can cause.
//!
//! # Why a token bucket and not a sliding window
//!
//! Both answer "how many per unit time". They differ in what they do to a burst.
//!
//! A sliding window counts events in the trailing interval, so ten files dropped
//! together are refused because the window is full — even though the point of an
//! inbox is that a person drops a handful of things at once. A token bucket holds
//! a capacity of credit that refills continuously, so a burst of ten is allowed
//! immediately and the *sustained* rate is what is bounded.
//!
//! For this use the burst behaviour is the correct one: the thing to defend
//! against is a sustained flood, not a person saving four files in a row.
//!
//! # Why the time source is a parameter
//!
//! [`TokenBucket::take`] takes `now`, and [`TokenBucket::take_at`] supplies the
//! wall clock. A limiter tested against the real clock is either slow or flaky:
//! the tests would have to sleep, or assert on a tolerance and hope. Making the
//! instant a parameter lets the tests move time by hand and assert exactly, which
//! is the difference between a test that proves the refill rate and one that
//! usually does.
//!
//! # What a caller does when refused
//!
//! Nothing is dropped. The caller is expected to *defer* — hold the payload and
//! try again later — so a flood costs bounded model calls rather than losing the
//! user's files. The caller decides that; the bucket only answers "may I now?".
//!
//! # Monotonicity
//!
//! Credit is `min(capacity, credit + elapsed * rate)`. Saturating at capacity
//! matters: without it a long idle period would accumulate unbounded credit and
//! then release a burst far larger than the configured burst size, which would be
//! exactly the flood the limiter exists to prevent.

use std::time::Duration;

/// How much work may be admitted per unit time, and how large a burst is allowed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// Sustained rate, in units per second.
    ///
    /// Stored as a `f64` rather than an integer because a rate of 0.1/s (one
    /// every ten seconds) is a sensible setting for a slow model and cannot be
    /// expressed as an integer per-second count.
    pub per_second: f64,
    /// Maximum burst. The bucket holds at most this much credit.
    pub burst: f64,
}

impl Limits {
    /// Limits allowing `per_minute` sustained, with a burst of `burst`.
    ///
    /// Minutes rather than seconds because that is the unit an operator thinks
    /// in: "ten files a minute" is a number a person can judge, and "0.167 files
    /// per second" is not.
    pub fn per_minute(per_minute: u32, burst: u32) -> Self {
        Limits {
            per_second: per_minute as f64 / 60.0,
            burst: burst as f64,
        }
    }

    /// The default: one payload every five seconds, allowing a burst of eight.
    ///
    /// Sized against the cost of the work being limited. A 3B model plans in
    /// seconds, so a rate much above this admits work that will simply queue
    /// behind the model anyway, and the limiter's job is to stop that queue
    /// growing without bound rather than to maximise throughput. The burst of
    /// eight means a person dropping a morning's worth of files is not punished
    /// for it.
    pub fn default_for_inbox() -> Self {
        Limits::per_minute(12, 8)
    }
}

/// A token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    limits: Limits,
    credit: f64,
    last_refill: Option<std::time::Instant>,
}

impl TokenBucket {
    /// A full bucket, so the first [`Limits::burst`] requests are admitted.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            credit: limits.burst,
            last_refill: None,
        }
    }

    /// Admit one unit of work, if there is credit for it.
    ///
    /// Uses the wall clock. Tests should prefer [`Self::take_at`].
    pub fn take(&mut self) -> bool {
        self.take_at(std::time::Instant::now())
    }

    /// Admit one unit of work at a given instant.
    ///
    /// Refilling first and then spending is what makes a full bucket admit
    /// immediately and an empty one wait, without either case needing a special
    /// case.
    pub fn take_at(&mut self, now: std::time::Instant) -> bool {
        self.refill_at(now);
        if self.credit >= 1.0 {
            self.credit -= 1.0;
            true
        } else {
            false
        }
    }

    /// Add the credit earned since the last refill, capped at the burst size.
    fn refill_at(&mut self, now: std::time::Instant) {
        match self.last_refill {
            None => {
                // First call establishes the clock without granting credit for the
                // time before the bucket existed — which would otherwise be an
                // unbounded amount, since `last_refill` was `None` since creation.
                self.last_refill = Some(now);
            }
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                self.credit = (self.credit + elapsed * self.limits.per_second)
                    .min(self.limits.burst);
                self.last_refill = Some(now);
            }
        }
    }

    /// Credit currently available, for reporting.
    pub fn credit(&mut self) -> f64 {
        self.refill_at(std::time::Instant::now());
        self.credit
    }

    /// Credit available at a given instant, without spending any.
    ///
    /// Refills as a side effect, like [`Self::credit`]. Present so a test can
    /// assert the *arithmetic* rather than inferring it from how many `take_at`
    /// calls happened to succeed — inferring it means a test passes for the wrong
    /// reason whenever the rate and the burst interact.
    #[cfg(test)]
    pub(crate) fn credit_at(&mut self, now: std::time::Instant) -> f64 {
        self.refill_at(now);
        self.credit
    }

    /// How long until at least one unit of credit is available.
    ///
    /// `None` when a unit is available now. Used by the caller to decide whether
    /// to sleep before retrying rather than spinning.
    pub fn wait_time(&mut self, now: std::time::Instant) -> Option<Duration> {
        self.refill_at(now);
        if self.credit >= 1.0 {
            return None;
        }
        let needed = 1.0 - self.credit;
        let seconds = needed / self.limits.per_second;
        if !seconds.is_finite() || seconds <= 0.0 {
            // A zero or non-finite rate can never refill. Reporting `None` would
            // say "admit me now", which is the opposite of the truth; a very long
            // wait says "do not bother", which is right.
            return Some(Duration::from_secs(u64::MAX / 2));
        }
        Some(Duration::from_secs_f64(seconds))
    }

    /// The limits in force.
    pub fn limits(&self) -> Limits {
        self.limits
    }
}

#[cfg(test)]
mod tests;