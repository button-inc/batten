//! The asked ledger: a weakening is admitted by a human's recorded answer and by
//! nothing an author can write alone (CLOUD-1078).
//!
//! # The hole this closes
//!
//! `config lint` detects a weakening — a waiver added, a rule removed, a
//! protected path dropped — and used to admit one on a `Weakens:` commit trailer.
//! In CI there is no groom receipt (it lives under `$GIT_DIR` and never reaches a
//! runner), so the trailer was the whole admission, and the trailer is written by
//! the same author making the weakening. Measured: #962's squash self-admitted 16,
//! including the removal of `batten.toml` from the protected set. No rule can close
//! that from inside the config, because a waiver reaches every rule kind and a
//! second waiver silences the rule that bans the first.
//!
//! # What admits instead
//!
//! The owner's decision, recorded on CLOUD-1078: a weakening is admitted only
//! through a question the host puts to the human, clearly explained, with the
//! text presented and the option selected recorded. The host's question tool is a
//! host fact ([`crate::hook::Harness::question_tool`]); at `PostToolUse` on it,
//! the hook appends one [`Entry`] per question to [`LEDGER`], in the working tree,
//! so it is committed with the change it admits and reaches CI with it.
//!
//! The result the host returns carries BOTH halves — every question with its
//! options, and the answers keyed by question text — so the record is taken from
//! the host's own bytes and never from the call's input, which the agent wrote.
//!
//! # The predicate
//!
//! A pair `<smell-id> <key>` is admitted iff a ledger line ADDED on this branch
//! (present at head, beyond the base's lines) has a question containing the pair
//! verbatim and an answer that is exactly the label of one of its presented
//! options, and that label begins with [`ADMIT`]. Free text typed in place of an
//! option never admits: it is recorded, and it is not a selection. A line
//! inherited from the base never admits: an answer given for an earlier change is
//! not an answer about this one.
//!
//! The ledger is append-only against the base. A head that does not begin with
//! every base line is [`Ledger::Rewritten`], and a rewritten ledger admits
//! nothing, because a record that can be edited records nothing.
//!
//! # Threat model
//!
//! Batten's is honest error. The ledger is protected from the host's write tools
//! by the consumer's `protected` set, and only the hook appends to it; an author
//! determined to forge a line can still hand-run the hook, as they could forge any
//! receipt. What this removes is the DECLARED route by which an author admitted
//! their own weakening without anyone being asked.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Where the ledger lives, relative to the repository root.
///
/// Engine vocabulary rather than a consumer's (non-negotiable rule 1): it names
/// no tracker, branch or repository, only the mechanism, the way `batten-receipts`
/// does under `$GIT_DIR`. It is in the WORKING TREE because the record has to
/// travel with the change to the runner that adjudicates it.
pub const LEDGER: &str = ".batten/asked.jsonl";

/// The prefix an option's label must carry for selecting it to admit.
///
/// Stated in the label rather than inferred from position or wording, so the
/// human reads exactly the word that decides: an option that does not say
/// "Admit" cannot admit, however the question around it is phrased.
pub const ADMIT: &str = "Admit";

/// One option as the host presented it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    /// The option's label, verbatim.
    pub label: String,
    /// The option's explanation, verbatim.
    pub description: String,
}

/// One question and its answer, exactly as the host recorded them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The question text presented.
    pub question: String,
    /// Every option presented, in order.
    pub options: Vec<Choice>,
    /// The answer returned: an option's label, or whatever the human typed.
    pub answer: String,
    /// Seconds since the Unix epoch at which the hook recorded it.
    pub at: u64,
    /// The commit checked out when it was asked, if one resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
}

impl Entry {
    /// Whether selecting this answer admits `pair`.
    ///
    /// Three conjuncts and each is load-bearing: the pair is NAMED (an answer
    /// about something else admits nothing), the answer IS a presented option
    /// (free text is recorded, never a selection), and that option SAYS it admits.
    #[must_use]
    pub fn admits(&self, pair: &str) -> bool {
        self.question.contains(pair)
            && self.answer.starts_with(ADMIT)
            && self
                .options
                .iter()
                .any(|option| option.label == self.answer)
    }
}

/// Every question-and-answer pair in one host result.
///
/// Pure over the result so the parse is testable without a host. A question
/// with no answer produces no entry: the host did not report one, and an entry
/// with an invented answer would be exactly the forgery this module removes.
#[must_use]
pub fn entries(result: &serde_json::Value, at: u64, head: Option<&str>) -> Vec<Entry> {
    let Some(questions) = result
        .get("questions")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    let answers = result.get("answers");
    questions
        .iter()
        .filter_map(|asked| {
            let question = asked.get("question")?.as_str()?;
            let answer = answers?.get(question)?.as_str()?;
            let options = asked
                .get("options")
                .and_then(serde_json::Value::as_array)
                .map(|options| {
                    options
                        .iter()
                        .filter_map(|option| {
                            Some(Choice {
                                label: option.get("label")?.as_str()?.to_owned(),
                                description: option
                                    .get("description")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(Entry {
                question: question.to_owned(),
                options,
                answer: answer.to_owned(),
                at,
                head: head.map(str::to_owned),
            })
        })
        .collect()
}

/// Append every entry in `result` to the ledger under `root`.
///
/// # Errors
///
/// Returns the I/O error when the directory cannot be created or a line cannot
/// be durably appended. The hook boundary swallows it, as every recorder there
/// does: the admission that reads the ledger simply refuses again.
pub fn record(root: &Path, result: &serde_json::Value, at: u64) -> Result<usize> {
    let head = crate::git::head_commit(root).ok();
    let found = entries(result, at, head.as_deref());
    if found.is_empty() {
        return Ok(0);
    }
    let path = root.join(LEDGER);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    for entry in &found {
        crate::durable::append(&path, &serde_json::to_string(entry)?)?;
    }
    Ok(found.len())
}

/// What this branch added to the ledger, or that it rewrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ledger {
    /// The head begins with every base line; these are the lines after them
    /// that parse as entries.
    Added(Vec<Entry>),
    /// A base line was removed or changed. Nothing is admitted.
    Rewritten,
}

impl Ledger {
    /// The entries that may admit anything.
    #[must_use]
    pub fn admitting(&self) -> &[Entry] {
        match self {
            Ledger::Added(entries) => entries,
            Ledger::Rewritten => &[],
        }
    }
}

/// Compare two ledger texts: `base` at the fork point, `head` in the tree.
///
/// Pure, so append-only is decided without a repository. A line that does not
/// parse is skipped rather than fatal: it cannot admit, and refusing every other
/// line over it would let one malformed byte revoke answers already given.
#[must_use]
pub fn compare(base: &str, head: &str) -> Ledger {
    let base_lines: Vec<&str> = base.lines().collect();
    let head_lines: Vec<&str> = head.lines().collect();
    if !head_lines.starts_with(&base_lines) {
        return Ledger::Rewritten;
    }
    Ledger::Added(
        head_lines
            .get(base_lines.len()..)
            .unwrap_or_default()
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
    )
}

/// The ledger as this branch changed it, against the fork point with `base`.
///
/// THE FORK POINT, NOT THE TIP. A trunk that gained ledger lines after this
/// branch was cut would otherwise read as this branch having removed them, and
/// every admission here would be refused for someone else's answer.
///
/// # Errors
///
/// Returns an error when `base` does not resolve: a comparison that cannot see
/// its baseline has not shown what was added, and must not admit.
pub fn added_since(root: &Path, base: &str) -> Result<Ledger> {
    let fork = crate::git::merge_base(root, base)?.unwrap_or_else(|| base.to_owned());
    let mut base_text = String::new();
    crate::git::for_each_blob_at_rev(root, &fork, LEDGER, |path, text| {
        if path == LEDGER {
            text.clone_into(&mut base_text);
        }
    })?;
    let head_text = std::fs::read_to_string(root.join(LEDGER)).unwrap_or_default();
    Ok(compare(&base_text, &head_text))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const PAIR: &str = "rule-removed rule[task carry other]";

    fn result(answer: &str) -> serde_json::Value {
        let question = format!("Admit the weakening `{PAIR}`? It deletes the body-count ratchet.");
        serde_json::json!({
            "questions": [{
                "question": question,
                "header": "Weakening",
                "multiSelect": false,
                "options": [
                    {"label": "Admit it", "description": "the line ratchet replaces it"},
                    {"label": "Refuse", "description": "keep the row"}
                ]
            }],
            "answers": {question: answer}
        })
    }

    fn only(answer: &str) -> Entry {
        let mut found = entries(&result(answer), 7, Some("abc"));
        assert_eq!(found.len(), 1);
        found.remove(0)
    }

    #[test]
    fn the_entry_carries_the_text_presented_and_the_answer_verbatim() {
        let entry = only("Admit it");
        assert!(entry.question.contains(PAIR));
        assert_eq!(entry.options.len(), 2);
        assert_eq!(entry.options[0].description, "the line ratchet replaces it");
        assert_eq!(entry.answer, "Admit it");
        assert_eq!(entry.head.as_deref(), Some("abc"));
    }

    #[test]
    fn selecting_the_admit_option_admits_the_named_pair() {
        assert!(only("Admit it").admits(PAIR));
    }

    #[test]
    fn selecting_the_other_option_admits_nothing() {
        assert!(!only("Refuse").admits(PAIR));
    }

    #[test]
    fn free_text_is_recorded_and_never_a_selection() {
        // Typed text that happens to start with the word is still not an option
        // the human was shown, so it admits nothing.
        let entry = only("Admit it, and also the other one");
        assert_eq!(entry.answer, "Admit it, and also the other one");
        assert!(!entry.admits(PAIR));
    }

    #[test]
    fn an_answer_about_another_pair_admits_nothing() {
        assert!(!only("Admit it").admits("waiver-added waiver[x]"));
    }

    #[test]
    fn a_question_the_host_reported_no_answer_for_is_not_recorded() {
        let mut value = result("Admit it");
        value["answers"] = serde_json::json!({});
        assert!(entries(&value, 0, None).is_empty());
    }

    #[test]
    fn only_lines_after_the_base_are_added() {
        let old = serde_json::to_string(&only("Admit it")).unwrap();
        let new = serde_json::to_string(&only("Refuse")).unwrap();
        let ledger = compare(&format!("{old}\n"), &format!("{old}\n{new}\n"));
        assert_eq!(ledger, Ledger::Added(vec![only("Refuse")]));
        // The inherited admit is not among them, so it cannot admit here.
        assert!(!ledger.admitting().iter().any(|entry| entry.admits(PAIR)));
    }

    #[test]
    fn a_rewritten_ledger_admits_nothing() {
        let old = serde_json::to_string(&only("Refuse")).unwrap();
        let new = serde_json::to_string(&only("Admit it")).unwrap();
        let ledger = compare(&format!("{old}\n"), &format!("{new}\n"));
        assert_eq!(ledger, Ledger::Rewritten);
        assert!(ledger.admitting().is_empty());
    }

    #[test]
    fn an_absent_base_makes_every_head_line_added() {
        let line = serde_json::to_string(&only("Admit it")).unwrap();
        let ledger = compare("", &format!("{line}\n"));
        assert!(ledger.admitting().iter().any(|entry| entry.admits(PAIR)));
    }
}
