//! One resolver for the environment variables the daemon and the client share.
//!
//! # What this is for
//!
//! The daemon wrote its configuration under `AGENTOSD_*` and the client read its
//! own under `AGENTOS_*`. For the three variables the two halves must *agree* on
//! -- the socket path, the TCP address, and the token file -- that split was a
//! footgun with a silent failure mode: an operator who set `AGENTOSD_TCP_ADDR`
//! and ran `agentos check` got no error, no warning, and a connection attempt to
//! the hardcoded default port. Both variables were correct. The daemon simply
//! listened somewhere the client was not looking, and the only symptom was a
//! connection refusal that named the wrong address.
//!
//! Naming is not something to re-derive at each call site. Three variables,
//! three implementations, three chances to reintroduce the bug -- so there is one
//! implementation and both halves call it.
//!
//! # The rule
//!
//! Each shared variable has a canonical name and an accepted alias. The canonical
//! name is checked first, so an operator who sets it always wins. If *both* are
//! set to different values that is refused rather than resolved, because silently
//! picking one means the daemon and the client can disagree about where to meet
//! and neither logs will say why.
//!
//! Daemon-only variables (`AGENTOSD_MODEL`, `AGENTOSD_WRITE_ROOTS`,
//! `AGENTOSD_ALLOWED_HOSTS`, `AGENTOSD_MAIL_OUTBOX`, `AGENTOSD_AUDIT_LOG`,
//! `AGENTOS_INBOX`) are deliberately **not** unified: there is no client
//! counterpart to disagree with, so a second spelling would only add a way to
//! misspell it. See [`daemon::serve`](crate::daemon).

/// Unix socket path. Canonical first, daemon spelling accepted.
pub const SOCKET_PATH: &[&str] = &["AGENTOS_SOCKET", "AGENTOSD_SOCKET"];

/// TCP address to bind or connect to. Canonical first, daemon spelling accepted.
pub const TCP_ADDR: &[&str] = &["AGENTOS_TCP_ADDR", "AGENTOSD_TCP_ADDR"];

/// Startup token file. Canonical first, daemon spelling accepted.
pub const TOKEN_PATH: &[&str] = &["AGENTOS_TOKEN_FILE", "AGENTOSD_TOKEN_FILE"];

/// The first of `names` set to something other than whitespace.
///
/// Returns the variable's *name* alongside its value. Callers report the name
/// because "which variable did you actually read" is precisely the question the
/// asymmetry left unanswerable, and a client that prints only the value leaves
/// an operator guessing whether their setting took effect.
///
/// Blank is treated as unset throughout. A variable set to `""` is what an unset
/// variable looks like to a shell that interpolates an unset variable, so honouring
/// it would mean an empty value silently overrides a real one.
pub fn first_set(names: &[&str]) -> Option<(String, String)> {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(((*name).to_string(), trimmed.to_string()));
            }
        }
    }
    None
}

/// [`first_set`], but refusing to guess when an alias disagrees with its canonical.
///
/// `Err` carries every name and both values, because the operator's next move
/// depends on which one they meant and guessing wrong is the failure we are here
/// to prevent. Equal values (modulo surrounding whitespace) are not a conflict --
/// `AGENTOS_TCP_ADDR=$A` and `AGENTOSD_TCP_ADDR=$A` is two spellings of one
/// intention, which is exactly what aliases are for.
pub fn resolve(names: &[&str]) -> Result<Option<(String, String)>, String> {
    let found: Vec<(String, String)> = names
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .map(|value| ((*name).to_string(), value))
        })
        .collect();

    if found.len() > 1 {
        let mut distinct: Vec<&String> = Vec::new();
        for (_, value) in &found {
            if !distinct.contains(&value) {
                distinct.push(value);
            }
        }
        if distinct.len() > 1 {
            let detail = found
                .iter()
                .map(|(name, value)| format!("{name}={value:?}"))
                .collect::<Vec<_>>()
                .join(" and ");
            return Err(format!(
                "{detail} disagree. They are aliases for one setting, so set one. \
                 Refusing to pick, because the daemon and the client would \
                 otherwise choose different ones and never say why."
            ));
        }
    }

    Ok(found.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// `set_var` is process-global, so these tests must not interleave.
    static LOCK: Mutex<()> = Mutex::new(());

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> EnvGuard<'a> {
        let guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let saved: Vec<(String, Option<String>)> = pairs
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (key, value) in pairs {
            match *value {
                "" => std::env::remove_var(key),
                v => std::env::set_var(key, v),
            }
        }
        EnvGuard { _guard: guard, saved }
    }

    struct EnvGuard<'a> {
        _guard: MutexGuard<'a, ()>,
        saved: Vec<(String, Option<String>)>,
    }

    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    const A: &str = "AGENTOS_TCP_ADDR";
    const B: &str = "AGENTOSD_TCP_ADDR";

    #[test]
    fn the_canonical_name_wins_when_only_it_is_set() {
        let _e = env(&[(A, "127.0.0.1:1234"), (B, "")]);
        let got = resolve(&[A, B]).expect("resolves");
        assert_eq!(got, Some((A.into(), "127.0.0.1:1234".into())));
    }

    #[test]
    fn the_daemon_spelling_still_works_on_its_own() {
        // This is the case that used to fail silently for the client.
        let _e = env(&[(A, ""), (B, "127.0.0.1:1234")]);
        let got = resolve(&[A, B]).expect("resolves");
        assert_eq!(got, Some((B.into(), "127.0.0.1:1234".into())));
    }

    #[test]
    fn agreeing_aliases_are_not_a_conflict() {
        let _e = env(&[(A, "127.0.0.1:1234"), (B, "127.0.0.1:1234")]);
        let got = resolve(&[A, B]).expect("agreeing values resolve");
        assert_eq!(got.unwrap().0, A, "canonical name is reported");
    }

    #[test]
    fn agreeing_aliases_ignore_surrounding_whitespace() {
        let _e = env(&[(A, "127.0.0.1:1234"), (B, "  127.0.0.1:1234  ")]);
        assert!(resolve(&[A, B]).is_ok(), "trailing space is not a disagreement");
    }

    #[test]
    fn disagreeing_aliases_are_refused_and_name_both_values() {
        let _e = env(&[(A, "127.0.0.1:1234"), (B, "127.0.0.1:9999")]);
        let err = resolve(&[A, B]).expect_err("must not guess");
        assert!(err.contains(A), "{err}");
        assert!(err.contains(B), "{err}");
        assert!(err.contains("1234") && err.contains("9999"), "{err}");
    }

    #[test]
    fn blank_counts_as_unset_rather_than_overriding() {
        // `FOO=` is what an unset shell variable interpolates to, so honouring an
        // empty value would let an empty string silently beat a real setting.
        let _e = env(&[(A, ""), (B, "127.0.0.1:1234")]);
        let got = resolve(&[A, B]).expect("resolves");
        assert_eq!(got, Some((B.into(), "127.0.0.1:1234".into())));
    }

    #[test]
    fn whitespace_only_counts_as_unset() {
        let _e = env(&[(A, "   "), (B, "127.0.0.1:1234")]);
        assert_eq!(
            resolve(&[A, B]).expect("resolves").unwrap().0,
            B,
            "whitespace is not a setting"
        );
    }

    #[test]
    fn nothing_set_is_none_not_an_error() {
        let _e = env(&[(A, ""), (B, "")]);
        assert_eq!(resolve(&[A, B]).expect("resolves"), None);
    }

    #[test]
    fn the_returned_name_is_the_one_that_was_honoured() {
        // Callers print this, so an operator can tell whether their setting took.
        let _e = env(&[(A, ""), (B, "/tmp/x.sock")]);
        let (name, value) = first_set(&[A, B]).expect("set");
        assert_eq!(name, B);
        assert_eq!(value, "/tmp/x.sock");
    }

    #[test]
    fn the_shared_variables_are_all_spellings_of_one_idea() {
        // Guards the actual fix: if a shared variable is added to one side and not
        // the other, this is where it shows up.
        for names in [SOCKET_PATH, TCP_ADDR, TOKEN_PATH] {
            assert_eq!(names.len(), 2, "{names:?} must name both spellings");
            assert!(names.iter().all(|n| n.starts_with("AGENTOS")), "{names:?}");
            assert!(
                names.iter().any(|n| n.starts_with("AGENTOSD_")),
                "{names:?} must keep the daemon spelling as an alias"
            );
        }
        // And the six names must be distinct, or two settings would share a var.
        let all: Vec<&str> = SOCKET_PATH
            .iter()
            .chain(TCP_ADDR)
            .chain(TOKEN_PATH)
            .copied()
            .collect();
        let mut unique = all.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), all.len(), "shared variable names overlap");
    }
}