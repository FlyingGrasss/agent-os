//! The policy engine.
//!
//! Every sensitive tool argument is classified before the tool runs. The
//! decision depends on the argument's provenance label, which is why a
//! compromised extractor cannot launder a hostile string into a shell command
//! or an outbound recipient.

use std::collections::{BTreeMap, BTreeSet};

use agentos_types::Val;
use serde::{Deserialize, Serialize};

use crate::rule::{Rule, RuleSet};

/// What the policy engine decided about one tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Every argument passed. No human involvement needed.
    Allow,
    /// At least one argument needs the user's explicit approval. The request
    /// carries the exact values and their provenance so the prompt can show the
    /// user precisely what they are approving.
    Confirm {
        request: ConfirmationRequest,
    },
    Deny { op: String, reason: String },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// One thing the user is being asked to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationItem {
    pub arg: String,
    pub value: String,
    /// Rendered for display: the source kinds that influenced this value.
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationRequest {
    pub tool: String,
    pub items: Vec<ConfirmationItem>,
}

pub struct PolicyEngine {
    rules: RuleSet,
    /// Domains the user has allowed for tainted URLs in this session.
    allowlist: BTreeSet<String>,
}

impl PolicyEngine {
    pub fn new(rules: RuleSet) -> Self {
        Self {
            rules,
            allowlist: BTreeSet::new(),
        }
    }

    /// Sensible starting rules: deny tainted values in command and path
    /// positions outright, require confirmation for recipients, and allow
    /// tainted URLs only to domains the user has listed.
    pub fn default_rules() -> RuleSet {
        let mut set = RuleSet::default();
        set.deny_tainted("shell", "argv");
        set.deny_tainted("shell", "cmd");
        set.deny_tainted("fs.write", "path");
        set.deny_tainted("fs.write", "contents");
        set.confirm_tainted("send_email", "to");
        set.confirm_tainted("send_email", "subject");
        set.confirm_tainted("send_email", "body");
        set.allowlist_tainted("http.get", "url");
        set
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn allowlist(&self) -> &BTreeSet<String> {
        &self.allowlist
    }

    /// Add a domain to this session's allowlist.
    pub fn allow_domain(&mut self, domain: impl Into<String>) {
        self.allowlist.insert(domain.into().to_ascii_lowercase());
    }

    /// Evaluate a tool call. Arguments arrive as labeled values.
    pub fn evaluate(&self, tool: &str, args: &BTreeMap<String, Val<String>>) -> Decision {
        let mut items = Vec::new();

        for (arg, value) in args {
            if !value.is_tainted() {
                continue;
            }
            let op = format!("{tool}.{arg}");
            let text = value.with_label_for_display(|t, _| t.clone());

            match self.rules.lookup(tool, arg) {
                Rule::Allow => continue,
                Rule::Confirm => {
                    let provenance = value
                        .label()
                        .sources()
                        .iter()
                        .map(|_| "untrusted source".to_string())
                        .collect();
                    items.push(ConfirmationItem {
                        arg: arg.clone(),
                        value: text,
                        provenance,
                    });
                }
                Rule::Deny { reason } => {
                    return Decision::Deny {
                        op,
                        reason: reason.to_string(),
                    }
                }
                Rule::Allowlist => {
                    let domain = host_of(&text);
                    match domain {
                        Some(d) if self.allowlist.contains(&d) => continue,
                        _ => {
                            return Decision::Deny {
                                op,
                                reason: match domain {
                                    Some(d) => format!(
                                        "`{d}` is not on this session's allowlist; \
                                         confirm the domain to add it"
                                    ),
                                    None => "value is not a parseable URL".to_string(),
                                },
                            }
                        }
                    }
                }
            }
        }

        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Confirm {
                request: ConfirmationRequest {
                    tool: tool.to_string(),
                    items,
                },
            }
        }
    }
}

/// Extract the lowercase host from a URL without pulling in a URL parser.
///
/// Requires an explicit scheme, and validates the host's character set. Being
/// strict matters here: this result is compared against the allowlist, so a
/// lenient parser would either treat arbitrary text as a hostname or let an
/// attacker smuggle a trusted host into a position that is then compared.
fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    // Reject a backslash outright. Browsers treat `\` as a path separator, so
    // `https://evil.test\@good.test/` really targets evil.test, while
    // stripping userinfo first would yield good.test and match the allowlist.
    if authority.contains('\\') {
        return None;
    }
    // Strip any userinfo; the host is after the last `@`.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let valid = labels.iter().all(|l| {
        !l.is_empty()
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    if valid {
        Some(host)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_types::SourceId;

    fn tainted(s: &str) -> Val<String> {
        Val::tainted(SourceId::new(), s.to_string())
    }

    fn trusted(s: &str) -> Val<String> {
        Val::trusted(s.to_string())
    }

    fn args(pairs: &[(&str, Val<String>)]) -> BTreeMap<String, Val<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn trusted_arguments_pass_without_asking() {
        let engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate("send_email", &args(&[("to", trusted("a@b.c"))]));
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn tainted_recipient_requires_confirmation() {
        let engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate("send_email", &args(&[("to", tainted("evil@example.com"))]));
        match d {
            Decision::Confirm { request } => {
                assert_eq!(request.tool, "send_email");
                assert_eq!(request.items[0].arg, "to");
                assert_eq!(request.items[0].value, "evil@example.com");
            }
            other => panic!("expected confirmation, got {other:?}"),
        }
    }

    #[test]
    fn tainted_shell_argv_is_denied_outright() {
        let engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate("shell", &args(&[("argv", tainted("rm -rf /"))]));
        match d {
            Decision::Deny { op, .. } => assert_eq!(op, "shell.argv"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn tainted_write_path_is_denied() {
        let engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate(
            "fs.write",
            &args(&[("path", tainted("~/.ssh/authorized_keys"))]),
        );
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn tainted_url_needs_an_allowlisted_domain() {
        let mut engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate("http.get", &args(&[("url", tainted("https://evil.test/x"))]));
        assert!(
            matches!(d, Decision::Deny { .. }),
            "off-allowlist should deny, got {d:?}"
        );

        engine.allow_domain("good.test");
        let d = engine.evaluate("http.get", &args(&[("url", tainted("https://good.test/x"))]));
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn allowlist_is_case_insensitive_on_both_sides() {
        let mut engine = PolicyEngine::new(PolicyEngine::default_rules());
        engine.allow_domain("Good.Test");
        let d = engine.evaluate("http.get", &args(&[("url", tainted("https://GOOD.test:8443/x"))]));
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn deny_takes_priority_over_confirm_in_the_same_call() {
        let engine = PolicyEngine::new(PolicyEngine::default_rules());
        let d = engine.evaluate(
            "send_email",
            &args(&[("to", tainted("a@b.c")), ("body", tainted("hi"))]),
        );
        // Both are Confirm, so the request must carry both items.
        match d {
            Decision::Confirm { request } => assert_eq!(request.items.len(), 2),
            other => panic!("expected confirmation with both items, got {other:?}"),
        }

        let mut mixed = RuleSet::default();
        mixed.deny_tainted("send_email", "body");
        mixed.confirm_tainted("send_email", "to");
        let engine = PolicyEngine::new(mixed);
        let d = engine.evaluate(
            "send_email",
            &args(&[("to", tainted("a@b.c")), ("body", tainted("hi"))]),
        );
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn unlisted_tool_argument_with_taint_is_not_silently_allowed() {
        // A rule that is absent must fail closed, or adding a new tool would be
        // an invisible security hole.
        let engine = PolicyEngine::new(RuleSet::default());
        let d = engine.evaluate("brand_new_tool", &args(&[("target", tainted("x"))]));
        assert!(matches!(d, Decision::Confirm { .. }));
    }

    #[test]
    fn host_parsing_handles_credentials_and_ports() {
        assert_eq!(
            host_of("https://user:pw@Host.TEST:8443/p"),
            Some("host.test".into())
        );
        assert_eq!(host_of("https://host.test"), Some("host.test".into()));
    }

    #[test]
    fn host_parsing_refuses_text_that_is_not_a_url() {
        // Anything without a scheme is not a URL, and must not be treated as a
        // bare hostname that an allowlist entry could then match.
        assert_eq!(host_of("not a url"), None);
        assert_eq!(host_of("good.test/x"), None);
        assert_eq!(host_of("://good.test"), None);
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://"), None);
        assert_eq!(host_of("https://good test/x"), None);
        assert_eq!(host_of("https://evil.test\\@good.test/x"), None);
    }

    #[test]
    fn allowlisted_host_cannot_be_smuggled_past_the_parser() {
        // An attempt to make the allowlisted host appear as the parsed host via
        // userinfo must not succeed, because the allowlist comparison happens
        // on the host after the `@` is stripped.
        let mut engine = PolicyEngine::new(PolicyEngine::default_rules());
        engine.allow_domain("good.test");
        let attack = "https://good.test@evil.test/x";
        let d = engine.evaluate("http.get", &args(&[("url", tainted(attack))]));
        assert!(
            matches!(d, Decision::Deny { .. }),
            "expected deny for {attack}, got {d:?}"
        );
    }
}
