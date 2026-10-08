//! Bounded inputs. A hostile document is attacker-controlled in size.
//!
//! # Why refuse rather than truncate
//!
//! Truncation is the tempting option and it is wrong here for a reason that has
//! nothing to do with memory. If the extractor reads the first 1 MiB of a 100 MiB
//! document and reports "the invoice total is 42", the user sees an extraction
//! that looks complete and is not. The truncation is invisible at the point
//! where it matters, which is the point where a human decides whether to act on
//! the result. Refusing produces an error that says exactly that.
//!
//! Two bounds apply, independently:
//!
//! - the **host** refuses before staging anything, so an oversized document
//!   never reaches a disk write or a child process;
//! - the **child** refuses again after descriptor handover, because the host's
//!   check is a caller-supplied number and the child does not have to take it on
//!   faith. A host that lies about the limit gets a refusal, not a child that
//!   silently allocated whatever it was handed.

use std::time::Duration;

/// The defaults, and why each one is what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Largest document the host will hand over, in bytes.
    pub max_document_bytes: usize,
    /// Largest document the child will read, in bytes.
    ///
    /// Separate from [`Limits::max_document_bytes`] because they are set by
    /// different parties: the first by the operator running the daemon, the
    /// second by whoever compiled the extractor. Keeping them apart means a
    /// generous operator setting cannot override a conservative extractor, and
    /// neither has to trust the other.
    pub max_read_bytes: usize,
    /// How long the host waits for an answer before killing the child.
    ///
    /// A partial mitigation for the absence of cgroup limits - see the crate
    /// docs on what is still unenforced.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // A web page or an email. Anything much larger is not a document a
            // user is plausibly asking a question about, and a hostile page can
            // always send more, so this is a policy choice rather than a limit
            // the attacker cannot exceed.
            max_document_bytes: 4 * 1024 * 1024,
            // Half the host's bound, so a host that raises its own limit does not
            // automatically raise what the extractor will hold in memory.
            max_read_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_secs(30),
        }
    }
}

impl Limits {
    /// A profile with tighter bounds, for tests and for deployments that would
    /// rather refuse than spend the memory.
    pub fn strict() -> Self {
        Self {
            max_document_bytes: 64 * 1024,
            max_read_bytes: 32 * 1024,
            timeout: Duration::from_secs(5),
        }
    }

    /// Refuse a bound that would make the host's limit meaningless.
    ///
    /// `max_read_bytes > max_document_bytes` is not a mistake the host can
    /// recover from: the host would hand over a document the child then reads
    /// anyway, which is exactly the "the number was advisory" outcome the two
    /// bounds exist to prevent.
    pub fn validate(&self) -> Result<(), LimitsError> {
        if self.max_document_bytes == 0 {
            return Err(LimitsError::ZeroLimit {
                field: "max_document_bytes",
            });
        }
        if self.max_read_bytes == 0 {
            return Err(LimitsError::ZeroLimit {
                field: "max_read_bytes",
            });
        }
        if self.max_read_bytes > self.max_document_bytes {
            return Err(LimitsError::ReadLimitExceedsHostLimit);
        }
        Ok(())
    }
}

/// A limit configuration that would defeat the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// A bound of zero would refuse everything, which is not a usable profile.
    #[error("`{field}` may not be zero")]
    ZeroLimit {
        /// Which field.
        field: &'static str,
    },
    /// The child would read more than the host agreed to hand over.
    #[error("`max_read_bytes` exceeds `max_document_bytes`, so the host's bound would be advisory")]
    ReadLimitExceedsHostLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_consistent_and_not_zero() {
        let d = Limits::default();
        assert!(d.validate().is_ok());
        assert!(d.max_document_bytes > 0 && d.max_read_bytes > 0);
        assert!(d.max_read_bytes <= d.max_document_bytes);
    }

    #[test]
    fn a_read_limit_above_the_host_limit_is_refused() {
        // This is the configuration that would make the host's bound a comment.
        let l = Limits {
            max_document_bytes: 100,
            max_read_bytes: 101,
            ..Limits::default()
        };
        assert_eq!(
            l.validate().unwrap_err(),
            LimitsError::ReadLimitExceedsHostLimit
        );
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_refusing_everything_silently() {
        let l = Limits {
            max_document_bytes: 0,
            ..Limits::default()
        };
        assert!(l.validate().is_err());
        assert!(Limits {
            max_read_bytes: 0,
            max_document_bytes: 1,
            ..Limits::default()
        }
        .validate()
        .is_err());
    }
}