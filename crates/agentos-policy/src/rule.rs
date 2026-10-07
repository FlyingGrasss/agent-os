//! Per-argument rules.
//!
//! The lookup is by `(tool, argument)`. An absent rule yields `Confirm`, not
//! `Allow`: adding a tool or an argument must never quietly widen authority, so
//! the safe outcome is to ask the user until a rule is written down.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Rule {
    /// Tainted values in this position are permitted without asking.
    Allow,
    /// Tainted values require explicit user confirmation.
    Confirm,
    /// Tainted values are refused. Confirmation cannot override this.
    Deny { reason: String },
    /// Tainted values are permitted only when the URL's host is on the
    /// session allowlist.
    Allowlist,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    rules: Vec<((String, String), Rule)>,
}

impl RuleSet {
    pub fn push(&mut self, tool: &str, arg: &str, rule: Rule) {
        self.rules
            .retain(|((t, a), _)| !(t == tool && a == arg));
        self.rules.push(((tool.to_string(), arg.to_string()), rule));
    }

    pub fn lookup(&self, tool: &str, arg: &str) -> &Rule {
        self.rules
            .iter()
            .find(|((t, a), _)| t == tool && a == arg)
            .map(|(_, r)| r)
            .unwrap_or(&Rule::Confirm)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &Rule)> {
        self.rules
            .iter()
            .map(|((t, a), r)| (t.as_str(), a.as_str(), r))
    }
}

/// Builders, so call sites read as declarations rather than data.
pub trait RuleExt {
    fn deny_tainted(tool: &str, arg: &str) -> Rule;
    fn confirm_tainted(tool: &str, arg: &str) -> Rule;
    fn allowlist_tainted(tool: &str, arg: &str) -> Rule;
    fn allow_tainted(tool: &str, arg: &str) -> Rule;
}

impl RuleExt for Rule {
    fn deny_tainted(tool: &str, arg: &str) -> Rule {
        Rule::Deny {
            reason: format!("`{tool}.{arg}` may not take a value from an untrusted source"),
        }
    }

    fn confirm_tainted(_tool: &str, _arg: &str) -> Rule {
        Rule::Confirm
    }

    fn allowlist_tainted(_tool: &str, _arg: &str) -> Rule {
        Rule::Allowlist
    }

    fn allow_tainted(_tool: &str, _arg: &str) -> Rule {
        Rule::Allow
    }
}

impl RuleSet {
    pub fn deny_tainted(&mut self, tool: &str, arg: &str) -> &mut Self {
        self.push(tool, arg, Rule::deny_tainted(tool, arg));
        self
    }

    pub fn confirm_tainted(&mut self, tool: &str, arg: &str) -> &mut Self {
        self.push(tool, arg, Rule::Confirm);
        self
    }

    pub fn allowlist_tainted(&mut self, tool: &str, arg: &str) -> &mut Self {
        self.push(tool, arg, Rule::Allowlist);
        self
    }

    pub fn allow_tainted(&mut self, tool: &str, arg: &str) -> &mut Self {
        self.push(tool, arg, Rule::Allow);
        self
    }
}
