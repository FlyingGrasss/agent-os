use std::collections::BTreeMap;

use agentos_types::{Label, Val};

/// A single tool argument as the policy engine sees it: a provenance label and
/// whatever text form the engine needs for its rule, together.
///
/// The type exists to close a laundering path. The interpreter hands tools
/// `Val<PlanData>` while the rules are written against text and labels, and the
/// obvious bridge is `PlanData::as_text()` followed by `Val::trusted(that)`.
/// That single line discards the label, which is the one thing the entire
/// design exists to preserve, and it is exactly the line every real host would
/// otherwise contain.
///
/// So `ArgView` cannot be built from a bare `String`. Its only constructor
/// takes a `&Val<T>` and reads the label from that value, so the label and the
/// text can only ever arrive together or not at all. Callers supply a closure
/// that extracts text from the value; the closure never sees the label and
/// therefore cannot be the place the label is lost.
pub struct ArgView<'a> {
    label: &'a Label,
    /// Text form of the argument, if it has one. Non-scalar arguments such as
    /// records and lists have no single text form and are represented by
    /// `None`, which the rules treat as "no text to inspect" rather than as an
    /// empty string.
    text: Option<String>,
    /// A rendering for a human, which may be present even when `text` is `None`.
    ///
    /// Kept separate because the two answer different questions. `text` is what
    /// the *rules* inspect, and a value whose text is attacker-controlled must
    /// not become something a rule pattern-matches against. `display` is what a
    /// *person* reads when deciding, and withholding it there produces a
    /// confirmation nobody can meaningfully give.
    ///
    /// Nothing in policy evaluation reads this field. A rule cannot be moved onto
    /// attacker-controlled text by changing what the user is shown.
    display: Option<String>,
}

impl<'a> ArgView<'a> {
    /// Build a view from a labeled value.
    ///
    /// `text` should return the argument's text form, or `None` for values that
    /// are not scalars. It is called at most once and only when a rule actually
    /// needs the text, so an expensive conversion is not paid for every
    /// argument.
    pub fn new<T>(value: &'a Val<T>, text: impl FnOnce(&T) -> Option<String>) -> Self {
        // The label is borrowed straight off the value. The text is owned, so
        // no borrow of the value's contents can outlive this call and be
        // confused for the label.
        let label = value.label();
        let text = value.with_label_for_display(|v, _| text(v));
        Self {
            label,
            display: None,
            text,
        }
    }

    /// Build a view that also carries a human-facing rendering.
    ///
    /// `display` is used only by [`Self::display_text`]. It exists so a value the
    /// rules must not inspect as text — an extracted, quarantined string — can
    /// still be *shown* to the user who is being asked to approve it.
    ///
    /// Withholding it would not make the system safer. It would make the
    /// confirmation unfalsifiable: a user asked to approve
    /// `send_email(to = <structured value>)` cannot tell where the mail goes, so
    /// the only possible answer is yes without reading. That converts the human
    /// into a rubber stamp, which is the failure mode the confirmation step exists
    /// to avoid — and it would do so while reporting every approval as a
    /// deliberate decision.
    pub fn with_display<T>(
        value: &'a Val<T>,
        text: impl FnOnce(&T) -> Option<String>,
        display: impl FnOnce(&T) -> Option<String>,
    ) -> Self {
        let label = value.label();
        let display = value.with_label_for_display(|v, _| display(v));
        let text = value.with_label_for_display(|v, _| text(v));
        Self {
            label,
            text,
            display,
        }
    }

    /// Build a view for an argument that carries no text form.
    pub fn opaque<T>(value: &'a Val<T>) -> Self {
        Self {
            label: value.label(),
            text: None,
            display: None,
        }
    }

    pub fn label(&self) -> &'a Label {
        self.label
    }

    pub fn is_tainted(&self) -> bool {
        self.label.is_tainted()
    }

    /// The text form, if any. An empty `Option` is not the same as an empty
    /// string: `None` means "this argument is not text".
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Render for a confirmation prompt.
    ///
    /// Confirmation prompts are shown to a human, not fed to a model, so showing
    /// the exact value is the point — and it is the *only* thing that makes the
    /// answer meaningful. A value with no display rendering and no text form is
    /// described structurally, which keeps the user informed without inventing
    /// one.
    pub fn display_text(&self) -> String {
        if let Some(d) = &self.display {
            return d.clone();
        }
        match &self.text {
            Some(t) => t.clone(),
            None => format!("<{}>", self.type_hint()),
        }
    }

    fn type_hint(&self) -> &'static str {
        match &self.text {
            Some(_) => "text",
            None => "structured value",
        }
    }
}

/// Build the argument map the policy engine takes, from labeled values.
///
/// This is the only supported path from interpreter state to a policy
/// decision. It is deliberately free: a caller cannot assemble an `ArgView` for
/// a value it does not hold, so it cannot claim a label the value does not
/// have.
pub fn arg_views<'a, I, T, F>(args: I, text: F) -> BTreeMap<String, ArgView<'a>>
where
    T: 'a,
    I: IntoIterator<Item = (&'a String, &'a Val<T>)>,
    F: Fn(&T) -> Option<String> + Copy,
{
    args.into_iter()
        .map(|(name, value)| (name.clone(), ArgView::new(value, |v| text(v))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentos_types::{SourceId, SourceKind};

    #[test]
    fn label_is_read_from_the_value_not_the_text() {
        let tainted = Val::tainted(SourceId::new(), "rm -rf /".to_string());
        let view = ArgView::new(&tainted, |t: &String| Some(t.clone()));
        assert!(view.is_tainted());
        assert_eq!(view.text(), Some("rm -rf /"));
    }

    #[test]
    fn text_closure_cannot_change_the_label() {
        // The closure sees the value, never the label, so there is no way for it
        // to return a value paired with a different provenance.
        let tainted = Val::tainted(SourceId::of_kind(SourceKind::WebPage), "hostile".to_string());
        let view = ArgView::new(&tainted, |t: &String| Some(t.to_uppercase()));
        assert!(view.is_tainted());
        assert_eq!(view.text(), Some("HOSTILE"));
    }

    #[test]
    fn non_scalar_arguments_have_no_text() {
        let v = Val::tainted(SourceId::new(), vec![1i64, 2, 3]);
        let view = ArgView::opaque(&v);
        assert!(view.is_tainted());
        assert_eq!(view.text(), None);
        assert_ne!(view.display_text(), "");
    }

    #[test]
    fn empty_string_is_distinct_from_absent_text() {
        let v = Val::trusted(String::new());
        let empty = ArgView::new(&v, |t: &String| Some(t.clone()));
        assert_eq!(empty.text(), Some(""));
        let none = ArgView::opaque(&v);
        assert_eq!(none.text(), None);
    }

    #[test]
    fn arg_views_preserves_labels_across_the_whole_map() {
        let trusted: Val<String> = Val::trusted("ok".into());
        let tainted = Val::tainted(SourceId::new(), "bad".into());
        let map: BTreeMap<String, Val<String>> =
            BTreeMap::from([("a".to_string(), trusted), ("b".to_string(), tainted)]);
        let views = arg_views(map.iter(), |t: &String| Some(t.clone()));
        assert!(!views["a"].is_tainted());
        assert!(views["b"].is_tainted());
        assert_eq!(views["b"].text(), Some("bad"));
    }
}
