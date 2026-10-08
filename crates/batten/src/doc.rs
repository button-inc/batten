//! A class's interaction doc: how to deal with a refusal, not why it exists
//! (CLOUD-2143).
//!
//! # What a first sighting owes its reader
//!
//! The full arm a context reads once per compaction cycle used to be a 120-char
//! gloss and, where a row declared one, its `reason`. The class paragraph — the
//! actual definition — sat behind `policy explain`, and nothing told the reader
//! what to do or which wrong responses to skip. This is that text, in four fixed
//! sections, the gloss being the first:
//!
//! * `what` — the class's `gloss`, unchanged: one line, at most `GLOSS_MAX`;
//! * `why` — the harm prevented, one sentence;
//! * `do` — the correct next actions, one to three;
//! * `dont` — the wrong responses observed, up to three.
//!
//! An admission's condition is not a section: it is the override route's own
//! `precondition`, rendered from the route so the two cannot drift.
//!
//! # Budgeted, and history-free
//!
//! A rendered doc (the gloss, these sections and the admissible preconditions)
//! is at most [`DOC_BYTES`] at load, which is 160 tokens on `budget.rs`'s
//! bytes/4, and at most 160 `o200k_base` tokens exactly in the test binary —
//! the shipped binary links no tokenizer (CLOUD-1284). 160 is 4,500 tokens of
//! prose per 90k window over a design point of 24 distinct gates. Rationale and
//! precedent are not interaction: they stay in the class paragraph, which
//! `explain` prints, and no section may cite an issue key.
//MUTANT-SUITE crates/batten/tests/it/refusal_ceiling.rs

use serde::{Deserialize, Serialize};

/// The rendered doc's ceiling at load, in bytes: 160 tokens at bytes/4.
pub const DOC_BYTES: usize = 640;

/// The most items a `do` or `dont` list may carry.
pub const ITEMS_MAX: usize = 3;

/// One class's interaction sections, beside its `gloss`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    /// The harm the class prevents, in one sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The correct next actions, one to three, naming the routes.
    #[serde(default, rename = "do", skip_serializing_if = "Vec::is_empty")]
    pub act: Vec<String>,
    /// The wrong responses observed, up to three.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dont: Vec<String>,
}

impl Doc {
    /// Whether nothing is declared, which serializes as no `doc` at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.why.is_none() && self.act.is_empty() && self.dont.is_empty()
    }
}

/// One vendored doc, keyed by its class's id.
#[derive(Debug)]
pub struct VendoredDoc {
    /// The class token this documents.
    pub id: &'static str,
    /// See [`Doc::why`].
    pub why: Option<&'static str>,
    /// See [`Doc::act`].
    pub act: &'static [&'static str],
    /// See [`Doc::dont`].
    pub dont: &'static [&'static str],
}

impl VendoredDoc {
    /// The owned form a [`crate::verdict::DeclaredVerdict`] carries.
    #[must_use]
    pub fn to_doc(&self) -> Doc {
        Doc {
            why: self.why.map(str::to_owned),
            act: self.act.iter().map(|item| (*item).to_owned()).collect(),
            dont: self.dont.iter().map(|item| (*item).to_owned()).collect(),
        }
    }
}

/// The docs of the engine's own classes, vendored and preset alike, keyed by id.
///
/// A separate table rather than a field on each `VendoredVerdict` literal, so
/// the interaction text is one file to author and review, and
/// `every_vendored_class_has_a_doc` keeps it whole against both tables.
pub const VENDORED_DOCS: &[VendoredDoc] = &[
    // ── native ──────────────────────────────────────────────────────────────
    VendoredDoc {
        id: "path write refused",
        why: Some(
            "The path is one this repository declared protected, so it is refused before the write rather than reported after",
        ),
        act: &[
            "make the change through the surface the line names (its redirect, or the config row that owns it)",
            "undo a change you did not mean with `git restore`",
        ],
        dont: &[
            "reach the same path through another program, a shell redirect or a script",
            "retry the same write",
        ],
    },
    VendoredDoc {
        id: "program name unknown",
        why: Some(
            "The boundary cannot tell what this program does to a protected path, so it will not guess",
        ),
        act: &[
            "run the same work with a program the config declares, or a plain read tool",
            "if the program only reads, declare it in `protected_readers` in `batten.toml`",
        ],
        dont: &["wrap the program in another one to hide it"],
    },
    VendoredDoc {
        id: "rule read missing",
        why: Some(
            "A rule changed by a reader who never saw why it exists loses the reason it was written",
        ),
        act: &[
            "run the `batten policy explain '<id>' --history` the line names, one call with no pipe",
            "then make the same edit",
        ],
        dont: &[
            "edit the row through a shell to get around this",
            "read a different row's history",
        ],
    },
    VendoredDoc {
        id: "task run twice",
        why: Some("A second copy races the first over the same refs, lock and remote"),
        act: &[
            "run `batten task alive` to see what the holder is doing",
            "wait for that run's exit, then act on its result",
        ],
        dont: &[
            "delete the lock file",
            "start the task again under another name",
        ],
    },
    VendoredDoc {
        id: "history drop unpushed",
        why: Some(
            "The reset would discard commits that exist in no other clone, and nothing else holds them",
        ),
        act: &[
            "push or branch the commits first; `git reflog` still holds them",
            "move the ref and keep the work with `git reset --soft`",
            "revert one file with `git checkout -- <path>`",
        ],
        dont: &["reset with a different verb that discards the same commits"],
    },
    VendoredDoc {
        id: "config write refused",
        why: Some(
            "Overwriting the committed authority would replace a reviewed policy with defaults, silently",
        ),
        act: &["edit the `batten.toml` that exists"],
        dont: &["delete it so `init` can write a fresh one"],
    },
    VendoredDoc {
        id: "outcome table refused",
        why: Some(
            "A row that can fire on nothing reads as coverage while its route was never walked",
        ),
        act: &["fix the `[[outcome]]` row and key the refusal names, in `batten.toml`"],
        dont: &["delete the row to make the config load"],
    },
    VendoredDoc {
        id: "plan read stale",
        why: Some("The gate would enforce a step plan nobody reviewed a diff of"),
        act: &["regenerate the projection with `batten hk contract` and review its diff"],
        dont: &["edit the committed projection by hand to match"],
    },
    VendoredDoc {
        id: "handler answer denied",
        why: Some("A program the config registers as a hook handler answered deny for this call"),
        act: &["read that `[hook.handler]` row in `batten.toml` for what it guards, and meet it"],
        dont: &["retry the call unchanged"],
    },
    VendoredDoc {
        id: "scanner pin missing",
        why: Some(
            "An unpinned scanner resolves to whatever is ambient, so its green would say nothing",
        ),
        act: &[
            "declare the scanner as a `[[provision]]` entry in `batten.toml`",
            "then run `batten provision`",
        ],
        dont: &["remove the `secrets` rule"],
    },
    VendoredDoc {
        id: "scanner install missing",
        why: Some("Nothing was scanned, and a scan of nothing must not read as a clean tree"),
        act: &["run `batten provision`, then the check again"],
        dont: &["treat the empty result as a pass"],
    },
    VendoredDoc {
        id: "spawn run refused",
        why: Some("This rule kind runs a command, and `check` is a read-only verb by contract"),
        act: &["run it through `batten enforce`, which may spawn"],
        dont: &["change the rule's kind to get it under `check`"],
    },
    VendoredDoc {
        id: "turn finish unmet",
        why: Some("A stop is a completion claim, and the turn's facts say the work is not landed"),
        act: &[
            "finish what the line names; for unlanded work run `mise run land`",
            "or say in words what blocks it",
        ],
        dont: &[
            "re-declare the work finished",
            "end the turn again unchanged",
        ],
    },
];

/// The vendored doc for `id`, or an empty one where none is declared.
#[must_use]
pub fn vendored(id: &str) -> Doc {
    VENDORED_DOCS
        .iter()
        .find(|entry| entry.id == id)
        .map(VendoredDoc::to_doc)
        .unwrap_or_default()
}

/// The sections after the gloss as the full arm prints them, each a sentence.
///
/// `act` is the class's `do` unless the firing row declared its own remedy,
/// which replaces it (the rule's `reason`, CLOUD-2143).
#[must_use]
pub fn render(doc: &Doc, act: &[&str]) -> String {
    let mut out = String::new();
    if let Some(why) = doc.why.as_deref() {
        push_sentence(&mut out, why);
    }
    if !act.is_empty() {
        push_sentence(&mut out, &format!("Do: {}", act.join("; ")));
    }
    if !doc.dont.is_empty() {
        let dont: Vec<&str> = doc.dont.iter().map(String::as_str).collect();
        push_sentence(&mut out, &format!("Don't: {}", dont.join("; ")));
    }
    out
}

/// Append `text` as one sentence: a space before it, a full stop after it.
fn push_sentence(out: &mut String, text: &str) {
    let text = text.trim().trim_end_matches(['.', ';']);
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(text);
    out.push('.');
}

/// Why a doc does not load, or `None` when it does.
///
/// `rendered` is the whole first-sighting body the class produces — gloss, these
/// sections and its admissible preconditions — measured against [`DOC_BYTES`].
//MUTANT doc-cap-unchecked|s@^    if rendered.len() > DOC_BYTES {$@    if false {@|a_class_doc_over_640_bytes_does_not_load
#[must_use]
pub fn violation(doc: &Doc, rendered: &str) -> Option<String> {
    if rendered.len() > DOC_BYTES {
        return Some(format!(
            "renders to {} bytes, over the {DOC_BYTES}-byte (160-token) budget a first \
             sighting may spend; move rationale to `class`",
            rendered.len()
        ));
    }
    if let Some(why) = doc.why.as_deref()
        && !one_sentence(why)
    {
        return Some("`doc.why` is ONE sentence".to_owned());
    }
    for (name, items) in [("do", &doc.act), ("dont", &doc.dont)] {
        if items.len() > ITEMS_MAX {
            return Some(format!(
                "`doc.{name}` carries {} items; at most {ITEMS_MAX}",
                items.len()
            ));
        }
        if items.iter().any(|item| item.trim().is_empty()) {
            return Some(format!("`doc.{name}` has an empty item"));
        }
    }
    let sections = doc.why.iter().chain(&doc.act).chain(&doc.dont);
    for text in sections {
        if cites_issue_key(text) {
            return Some(
                "a doc section cites an issue key; history belongs in `class`, \
                 which `explain` prints"
                    .to_owned(),
            );
        }
    }
    None
}

/// Whether `text` holds no sentence boundary before its end: a terminator, then
/// whitespace, then a capital — so `e.g. this` and `run x.y` stay one sentence.
fn one_sentence(text: &str) -> bool {
    let chars: Vec<char> = text.trim().chars().collect();
    !chars.windows(3).any(|three| {
        matches!(three[0], '.' | '!' | '?') && three[1].is_whitespace() && three[2].is_uppercase()
    })
}

/// Whether `text` names an issue key: an uppercase prefix, a dash, digits.
fn cites_issue_key(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .any(|word| {
            let Some((prefix, number)) = word.split_once('-') else {
                return false;
            };
            prefix.len() >= 2
                && prefix.chars().all(|c| c.is_ascii_uppercase())
                && !number.is_empty()
                && number.chars().all(|c| c.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(why: Option<&str>, act: &[&str], dont: &[&str]) -> Doc {
        Doc {
            why: why.map(str::to_owned),
            act: act.iter().map(|item| (*item).to_owned()).collect(),
            dont: dont.iter().map(|item| (*item).to_owned()).collect(),
        }
    }

    #[test]
    fn the_sections_render_as_sentences_in_order() {
        let rendered = render(
            &doc(Some("A reader loses the file"), &[], &["retry it verbatim"]),
            &["run `x`", "read y"],
        );
        assert_eq!(
            rendered,
            "A reader loses the file. Do: run `x`; read y. Don't: retry it verbatim."
        );
    }

    #[test]
    fn a_why_of_two_sentences_does_not_load() {
        let two = doc(Some("One thing. Another thing."), &["x"], &[]);
        assert!(violation(&two, "short").is_some());
        let one = doc(Some("One thing, e.g. this."), &["x"], &[]);
        assert_eq!(violation(&one, "short"), None);
    }

    #[test]
    fn four_items_do_not_load() {
        let four = doc(None, &["a", "b", "c", "d"], &[]);
        assert!(violation(&four, "short").is_some());
    }

    #[test]
    fn an_issue_key_is_found_and_a_kebab_word_is_not() {
        assert!(cites_issue_key("see CLOUD-2143 for why"));
        assert!(!cites_issue_key("run `land-lock` or check o200k-base"));
    }
}
