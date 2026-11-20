//! The finding line's grammar: the words every Batten line opens with and the
//! one spelling of a finding's head (CLOUD-2145), kept in a leaf (CLOUD-2789).
//!
//! A leaf so the modules that print or classify a line (`output`, `verdict`,
//! `findings`, `severity`) do not reach up into `refusal`, which renders whole
//! refusals and re-exports these under their old paths.

/// The word every finding line opens with, naming the binary that raised it and
/// that `policy explain` is run through (CLOUD-2145). No harness writes a line
/// opening `batten <severity> `, so it is also what tells a finding apart from
/// a host's own messages.
pub const PROVENANCE: &str = "batten";

/// What a line is, as its second word (CLOUD-2145): for a finding, how it
/// bears on the call — `deny` refused it, `warn` must be answered soon, `note`
/// eventually — and `remedy` for a line that is no finding at all but how a
/// rule's findings are fixed. One ASCII token each, the shape of a compiler's
/// `error`/`warning`/`help`.
///
/// THE WORD, NOT THE SHAPE, SAYS IT IS A REMEDY: a finding may name no subject
/// (`batten deny plan write refused; run ExitPlanMode…`), so a missing ` at `
/// cannot mark a remedy line, and a reader merging stdout and stderr would read
/// `batten deny <rule> — …` as a second finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Severity {
    /// The call was refused.
    #[default]
    Deny,
    /// An advisory to answer before the work goes much further.
    Warn,
    /// An advisory with no deadline.
    Note,
    /// Not a finding: how a rule's findings, each on its own line, are fixed.
    Remedy,
}

impl Severity {
    /// Every head word.
    pub const ALL: [Severity; 4] = [
        Severity::Deny,
        Severity::Warn,
        Severity::Note,
        Severity::Remedy,
    ];

    /// The word the line carries.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Severity::Deny => "deny",
            Severity::Warn => "warn",
            Severity::Note => "note",
            Severity::Remedy => "remedy",
        }
    }
}

/// Whether `text` opens with a finding's head, `batten <severity> `.
#[must_use]
pub fn is_headed(text: &str) -> bool {
    Severity::ALL.iter().any(|severity| {
        text.strip_prefix(PROVENANCE)
            .and_then(|rest| rest.strip_prefix(' '))
            .and_then(|rest| rest.strip_prefix(severity.word()))
            .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// The ONE spelling of a finding's head, `batten <severity> <name>`. Every line
/// that reports a finding opens with this; `emission_census` refuses a
/// hand-spelled one.
#[must_use]
pub fn head(severity: Severity, name: &str) -> String {
    format!("{PROVENANCE} {} {}", severity.word(), plain(name))
}

/// Pointer text made safe for the grammar: it can never contain the tail
/// opener or the clause separator.
#[must_use]
pub fn plain(text: &str) -> String {
    text.replace(" — ", " - ").replace("; ", ", ")
}

/// CLOUD-1806's class route. The hop `refusal::finding_line` appends names the
/// same verb with the real id, so a route whose target is this placeholder is
/// dropped at render rather than printed twice.
pub const RULE_HOP_PLACEHOLDER: &str = "batten policy explain '<rule-id>'";
