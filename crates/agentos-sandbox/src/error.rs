//! Errors. Every variant means "the confinement did not happen".
//!
//! There is deliberately no `Ok`-but-unchecked path: if a capability the caller
//! asked for could not be enforced, construction of the ruleset fails. Callers
//! cannot obtain an [`crate::confine::Enforced`] handle without a kernel that
//! actually applied the rules.

use std::path::PathBuf;

use thiserror::Error;

use crate::abi::{Abi, Feature, KernelSupport};

/// Something in [`crate::confine::Confine`] could not be enforced.
///
/// Every variant is a refusal. None of them means "degraded but running".
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfineError {
    /// The kernel has no usable Landlock.
    ///
    /// This is never worked around. Running a tool unconfined while the caller
    /// believes it is confined is the failure mode this crate exists to prevent.
    #[error("landlock is not usable on this kernel: {support}")]
    LandlockUnavailable {
        /// What the kernel reported.
        support: KernelSupport,
    },

    /// The kernel's Landlock ABI is older than a requested capability needs.
    #[error(
        "refusing to run: kernel Landlock ABI is {kernel} but this profile needs {required} \
         (missing: {})",
        describe(features)
    )]
    AbiTooOld {
        /// ABI the kernel provides (clamped to what this crate understands).
        kernel: Abi,
        /// ABI the profile needs.
        required: Abi,
        /// The individual rights that push the requirement above `kernel`.
        features: Vec<Feature>,
    },

    /// `PR_SET_NO_NEW_PRIVS` could not be set.
    ///
    /// `landlock_restrict_self(2)` fails with `EPERM` without it, and without it
    /// a setuid binary could regain privileges and shed the ruleset.
    #[error("refusing to run: could not set PR_SET_NO_NEW_PRIVS: {source}")]
    NoNewPrivs {
        /// Underlying `prctl(2)` error.
        source: std::io::Error,
    },

    /// `PR_SET_NO_NEW_PRIVS` returned success but `PR_GET_NO_NEW_PRIVS` still
    /// reports 0. Treated as a refusal rather than assumed success.
    #[error("refusing to run: PR_SET_NO_NEW_PRIVS reported success but PR_GET_NO_NEW_PRIVS is 0")]
    NoNewPrivsNotSticky,

    /// A granted path could not be opened to build its `path_beneath` rule.
    ///
    /// Note this is *not* the same as the `landlock` crate's
    /// `path_beneath_rules()` helper, which silently drops paths it cannot open.
    /// Silently dropping a grant would produce a sandbox with a hole shaped
    /// exactly like a typo.
    #[error("refusing to run: cannot open granted path {path} for a Landlock rule: {source}")]
    GrantPath {
        /// The path the caller granted.
        path: PathBuf,
        /// Underlying `open(2)` error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The ruleset could not be built or enforced. Boxed so this type stays
    /// compilable on non-Linux targets.
    #[error("landlock ruleset error: {0}")]
    Ruleset(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The kernel accepted the ruleset but reported it as not fully enforced.
    ///
    /// This should be unreachable with `CompatLevel::HardRequirement`; it exists
    /// so that a future change to the compatibility level cannot silently turn
    /// into a partial sandbox.
    #[error("refusing to run: Landlock reported a partially applied ruleset: {status}")]
    PartiallyEnforced {
        /// The status the kernel returned.
        status: String,
    },

    /// Landlock applied the ruleset but `no_new_privs` was not in force.
    #[error("refusing to run: ruleset applied but PR_SET_NO_NEW_PRIVS is not confirmed")]
    NoNewPrivsUnconfirmed,

    /// Landlock exists but this build/platform cannot confine anything.
    #[error("landlock confinement is only implemented for linux targets")]
    UnsupportedPlatform,
}

/// `Vec<Feature>` has no `Display`, so render the right names by hand.
fn describe(features: &[Feature]) -> String {
    if features.is_empty() {
        return "none".to_string();
    }
    features
        .iter()
        .map(|f| f.name())
        .collect::<Vec<_>>()
        .join(", ")
}

impl ConfineError {
    /// The Landlock rights that could not be enforced, if that is why we failed.
    ///
    /// Callers use this to decide whether to *refuse to start the tool at all*
    /// versus to surface a specific "this host is too old" message.
    pub fn missing_features(&self) -> &[Feature] {
        match self {
            ConfineError::AbiTooOld { features, .. } => features,
            _ => &[],
        }
    }
}

#[cfg(target_os = "linux")]
impl From<landlock::RulesetError> for ConfineError {
    fn from(value: landlock::RulesetError) -> Self {
        ConfineError::Ruleset(Box::new(value))
    }
}