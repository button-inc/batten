//! The delegation-brief handoff schema (CLOUD-84).
//!
//! When one session fans work out to another, most of its context does not
//! travel. The receiving session gets a fresh window: it did not read what the
//! sender read, it does not know which entity the task is about, and it cannot
//! see the scope boundary the sender was holding in its head. Everything that
//! *does* travel has to be written down, and nothing today checks that it was.
//!
//! [`SCHEMA`] is that "everything", stated once as data — the required-section
//! set from CLOUD-84 §1 — and [`problems`] is the predicate over it. The failure
//! this catches is concrete rather than theoretical: a brief that names no file
//! domain, or no durable destination for the result, produces a subagent that
//! guesses at both.
//!
//! # Presence, never prose quality
//!
//! The only question asked is whether a required section is *there*. Whether the
//! instructions are any good is not computable, and a gate that pretended
//! otherwise would be a judge (CLOUD-93, non-negotiable rule 3). That bound is
//! what keeps this a `read`-effect lint with an exit code rather than an opinion.
//!
//! # The one exception, and why it is still structural
//!
//! The `check` section carries [`Section::runnable`]: its body must contain a
//! line inside a fenced code block. That is the assertion CLOUD-84's acceptance
//! calls "the required check section forces the subagent to return a re-runnable
//! pointer" — and it is what retires a separate reply scanner, because a brief
//! that hands over a runnable command needs no second gate reading the reply for
//! one. It never reads what the command *is*: a fence with a non-blank line in it
//! satisfies it, and `rm -rf /` would satisfy it too. Deciding whether a command
//! is a *good* check is the judge this module refuses to be.
//!
//! # Recognizing a section
//!
//! A section is present when a line *labels* it. Briefs in this system are
//! authored as prose for a human as much as for a parser, and they spell a label
//! four ways — `## Check`, `**Check:**`, `- Check:`, `Check:` — so the recognizer
//! normalizes rather than picking one dialect and failing the rest. Requiring a
//! markdown heading and nothing else would have meant no brief in use today
//! validated, which is how a lint teaches people to route around it.
//!
//! Normalization is a byte scan: take the text before the first `:`, strip the
//! marker characters (`#`, `*`, `_`, `-`) and whitespace from both ends, lowercase,
//! collapse internal runs of whitespace, and compare for **equality** against the
//! declared tokens. Equality, not `contains`: a prose line that merely mentions a
//! section's name is not a label, and a substring test would make every brief that
//! discusses its own structure self-satisfying. No regex — the crate carries no
//! regex dependency, and `outputs.rs` and `budget.rs` set that precedent.
//!
//! # Fences are read before labels, not after
//!
//! Fence state is computed over the whole document *first*, and a line inside a
//! fence can never be a label. A brief quoting a shell transcript that contains
//! `# Check` would otherwise declare a section it does not have — the failure mode
//! where the more faithfully a brief quotes its evidence, the more sections it
//! appears to satisfy.
//!
//! # Pointer-only, and this one is load-bearing
//!
//! A brief is the single likeliest document in this system to carry a consumer's
//! name, an account number, a credential pasted "for context", or an entity path.
//! So the emitted value is a section **id** and a count, never a byte of the input
//! (non-negotiable rule 4). `tests::the_report_never_carries_a_byte_of_the_brief`
//! is the assertion, in the shape `judge.rs` uses for its `InvocationRecord`.

use serde::Serialize;

/// One required section of a delegation brief.
///
/// The row *is* the schema: adding a requirement is a row here, and the fixtures
/// and tests cite [`SCHEMA`] rather than restating the set (Definition of Ready
/// §1). Nothing about a row is consumer-specific — the ids name kinds of fact, so
/// non-negotiable rule 1 holds by construction rather than by review.
#[derive(Debug)]
#[non_exhaustive]
pub struct Section {
    /// The stable, lowercase identifier. The only thing ever emitted about a
    /// section, on either channel.
    pub id: &'static str,
    /// The label tokens that satisfy this section, already normalized (lowercase,
    /// single-spaced). Several per row because a brief may reasonably name the
    /// same fact more than one way; a token is matched for equality.
    pub labels: &'static [&'static str],
    /// Whether the section's body must carry a fenced, runnable line.
    pub runnable: bool,
}

/// The handoff schema: what a delegation brief must carry (CLOUD-84 §1).
///
/// Declaration order is report order, which is what makes the output byte-stable
/// (§6) without a sort that would have to invent a comparison.
pub const SCHEMA: &[Section] = &[
    Section {
        // Which entity the task is about. The fact that inherits least: the
        // sender resolved it from context the receiver does not have.
        id: "identifiers",
        labels: &[
            "identifiers",
            "identifier",
            "task identifiers",
            "task-specific identifiers",
        ],
        runnable: false,
    },
    Section {
        // The boundary: which period, which files, which subtree. A brief that
        // omits it produces a subagent that decides its own scope.
        id: "period",
        labels: &[
            "period",
            "scope",
            "period/scope",
            "period and scope",
            "file domain",
        ],
        runnable: false,
    },
    Section {
        // What binds inside that scope — the rules that do not travel with the
        // repository checkout.
        id: "instructions",
        labels: &[
            "instructions",
            "per-scope instructions",
            "scope instructions",
        ],
        runnable: false,
    },
    Section {
        // What the sender has already read, so the receiver neither re-reads it
        // nor assumes it was read.
        id: "read",
        labels: &[
            "read",
            "already read",
            "already-read files",
            "already read files",
            "files already read",
        ],
        runnable: false,
    },
    Section {
        // The deterministic check the subagent must run, and the one section with
        // a shape requirement rather than only a presence one.
        id: "check",
        labels: &[
            "check",
            "checks",
            "deterministic check",
            "required check",
            "verification",
        ],
        runnable: true,
    },
];

/// What a brief is missing, in the two shapes a required-section predicate can
/// answer.
///
/// Two lists rather than one flat enum because the two are *different repairs*:
/// `missing` is answered by writing a section, `unrunnable` by putting a command
/// in one that already exists. Collapsing them would report the same word for both
/// and leave the author to guess which.
///
/// Serialized directly for the `-J` channel: field names are the class names the
/// human channel prints, so the two renderings share one vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Required sections with no label line, in [`SCHEMA`] order.
    pub missing: Vec<&'static str>,
    /// Sections declared [`Section::runnable`] that carry no fenced command line,
    /// in [`SCHEMA`] order. A section that is missing outright is reported once,
    /// as `missing` — naming it twice would double-count one repair.
    pub unrunnable: Vec<&'static str>,
}

impl Report {
    /// Whether the brief satisfies the schema.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.unrunnable.is_empty()
    }

    /// The pointer lines this report renders as (§6), without trailing newlines.
    ///
    /// One line per non-empty class, classes in a fixed order, ids in [`SCHEMA`]
    /// order: `missing: identifiers, check (2)`. A clean report renders nothing —
    /// CLOUD-84 §7(a) pins silence on the complete brief, which is the one place
    /// the house habit of stating a count even at zero is overridden by the issue.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        [("missing", &self.missing), ("unrunnable", &self.unrunnable)]
            .into_iter()
            .filter(|(_, ids)| !ids.is_empty())
            .map(|(class, ids)| format!("{class}: {} ({})", ids.join(", "), ids.len()))
            .collect()
    }
}

/// The marker characters a label may be dressed in.
///
/// Markdown emphasis, headings and list bullets. Stripped from both ends of the
/// label candidate so `## Check`, `**Check**` and `- Check` all reduce to the same
/// token.
const MARKERS: &[char] = &['#', '*', '_', '-', '>'];

/// Whether a line opens or closes a fenced code block.
///
/// Both markdown fence characters, because a brief pasted out of a document that
/// itself contains backtick fences is routinely re-fenced with tildes.
fn is_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// The normalized label a line carries, if it reads as one.
///
/// `None` for every ordinary prose line, which is the common case, so the cheap
/// rejections come first.
fn label_of(line: &str) -> Option<String> {
    // Everything up to the first colon: `**Check:** cargo test` labels a section
    // and states its content on one line, which is how briefs are actually
    // written. A line with no colon is considered whole, so `## Check` still reads.
    let candidate = line.split_once(':').map_or(line, |(before, _)| before);
    let trimmed = candidate.trim_matches(|c: char| MARKERS.contains(&c) || c.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    // Collapse internal whitespace so a label wrapped with a double space, or
    // written with a tab, is the same token as one written plainly.
    let mut normalized = String::with_capacity(trimmed.len());
    for word in trimmed.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(&word.to_lowercase());
    }
    Some(normalized)
}

/// Every way `text` fails the handoff schema.
///
/// A pure function of the bytes: no clock, no filesystem, no config, so the same
/// brief always produces the same report (§6).
#[must_use]
pub fn problems(text: &str) -> Report {
    let lines: Vec<&str> = text.lines().collect();

    // Fence state first, over the whole document, so a label quoted inside a code
    // block can never declare a section. `fenced[i]` is true for lines *inside* a
    // fence, false for the delimiters themselves — a delimiter is not content.
    //
    // An unterminated fence runs to the end of the document rather than being
    // treated as no fence at all. That is the forgiving direction on the label
    // side (fewer sections recognized, so a defect is reported rather than hidden)
    // and it lets a brief whose last block is an unclosed command still satisfy
    // `runnable`, which is what an author obviously meant.
    let mut fenced = Vec::with_capacity(lines.len());
    let mut inside = false;
    for line in &lines {
        if is_fence(line) {
            fenced.push(false);
            inside = !inside;
        } else {
            fenced.push(inside);
        }
    }

    // Where each section's label sits. `SCHEMA` order is preserved by iterating
    // the schema rather than the labels found, so the report never depends on the
    // order the author wrote the sections in.
    let mut label_lines: Vec<Option<usize>> = vec![None; SCHEMA.len()];
    // Every label line in document order, so a section's body can end at the next
    // one — including at a label for a section this schema does not require.
    let mut boundaries: Vec<usize> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if fenced.get(index).copied().unwrap_or(false) {
            continue;
        }
        let Some(normalized) = label_of(line) else {
            continue;
        };
        let Some(position) = SCHEMA
            .iter()
            .position(|section| section.labels.contains(&normalized.as_str()))
        else {
            continue;
        };
        boundaries.push(index);
        // First occurrence wins: a brief that labels one section twice has one
        // section, and taking the last would move the body under the author's feet.
        if label_lines[position].is_none() {
            label_lines[position] = Some(index);
        }
    }

    let mut missing = Vec::new();
    let mut unrunnable = Vec::new();
    for (position, section) in SCHEMA.iter().enumerate() {
        let Some(start) = label_lines[position] else {
            missing.push(section.id);
            continue;
        };
        if !section.runnable {
            continue;
        }
        // The body runs from the label line itself — a one-line `**Check:**` may
        // be followed immediately by its fence — to the next label of any required
        // section, or the end of the document.
        let end = boundaries
            .iter()
            .copied()
            .find(|&boundary| boundary > start)
            .unwrap_or(lines.len());
        let runnable = (start..end).any(|index| {
            fenced.get(index).copied().unwrap_or(false)
                && lines.get(index).is_some_and(|line| !line.trim().is_empty())
        });
        if !runnable {
            unrunnable.push(section.id);
        }
    }

    Report {
        missing,
        unrunnable,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A brief satisfying every row of `SCHEMA`, built *from* the schema so the
    /// fixture cannot drift from the requirement it is meant to satisfy.
    fn complete() -> String {
        let mut text = String::new();
        for section in SCHEMA {
            let label = section.labels[0];
            text.push_str(&format!("## {label}\n\nsome prose\n\n"));
            if section.runnable {
                text.push_str("```\nmise run verify\n```\n\n");
            }
        }
        text
    }

    #[test]
    fn a_complete_brief_has_no_problems() {
        assert!(problems(&complete()).is_clean());
    }

    #[test]
    fn a_missing_section_is_named_once() {
        let text = complete().replace("## check", "## unrelated heading");
        let report = problems(&text);
        assert_eq!(report.missing, vec!["check"]);
        // Reported as missing, never also as unrunnable: one repair, one line.
        assert!(report.unrunnable.is_empty());
        assert_eq!(report.lines(), vec!["missing: check (1)"]);
    }

    #[test]
    fn a_check_section_with_no_fenced_command_is_unrunnable() {
        let text = complete().replace("```\nmise run verify\n```\n", "run the suite, please\n");
        let report = problems(&text);
        assert!(report.missing.is_empty());
        assert_eq!(report.unrunnable, vec!["check"]);
        assert_eq!(report.lines(), vec!["unrunnable: check (1)"]);
    }

    #[test]
    fn every_marker_dialect_labels_a_section() {
        // The answered design question: briefs in use spell a label four ways, and
        // a recognizer that accepted only one would fail every brief written today.
        for label in ["## check", "**Check:**", "- check:", "Check", "###  CHECK "] {
            let text = format!("{label}\n\n```\nmise run verify\n```\n");
            assert!(
                !problems(&text).missing.contains(&"check"),
                "`{label}` must label the check section"
            );
        }
    }

    #[test]
    fn a_label_inside_a_fence_declares_nothing() {
        // The failure mode where the more faithfully a brief quotes its evidence,
        // the more sections it appears to satisfy.
        let text = "```\n## check\n## identifiers\n```\n";
        let report = problems(text);
        assert_eq!(
            report.missing,
            SCHEMA.iter().map(|s| s.id).collect::<Vec<_>>(),
            "a quoted transcript satisfies nothing"
        );
    }

    #[test]
    fn a_mention_in_prose_is_not_a_label() {
        // Equality, not `contains`: a brief that discusses its own structure must
        // not thereby satisfy it.
        let text = "This brief has no check section and names no identifiers.\n";
        assert_eq!(problems(text).missing.len(), SCHEMA.len());
    }

    #[test]
    fn a_one_line_label_still_owns_the_fence_that_follows_it() {
        let text = "**Check:** run the suite\n\n```\nmise run verify\n```\n";
        assert!(!problems(text).unrunnable.contains(&"check"));
    }

    #[test]
    fn a_fence_under_a_later_section_does_not_satisfy_an_earlier_one() {
        // The body ends at the next label, so a command block belonging to another
        // section cannot be borrowed to satisfy `check`.
        let text = "## check\n\nno command here\n\n## identifiers\n\n```\nmise run verify\n```\n";
        assert_eq!(problems(text).unrunnable, vec!["check"]);
    }

    #[test]
    fn an_unterminated_fence_still_carries_its_command() {
        let text = "## check\n\n```\nmise run verify\n";
        assert!(problems(text).unrunnable.is_empty());
    }

    #[test]
    fn an_empty_brief_is_missing_every_section() {
        let report = problems("");
        assert_eq!(report.missing, SCHEMA.iter().map(|s| s.id).collect::<Vec<_>>());
        // `check` is absent, so it is missing rather than unrunnable.
        assert!(report.unrunnable.is_empty());
    }

    #[test]
    fn the_report_is_in_schema_order_whatever_order_the_brief_used() {
        // Byte-stability (§6) cannot depend on how the author arranged the
        // document, or two briefs missing the same two sections would disagree.
        let text = "## check\n\n```\nx\n```\n";
        let report = problems(text);
        let expected: Vec<&str> = SCHEMA
            .iter()
            .filter(|section| section.id != "check")
            .map(|section| section.id)
            .collect();
        assert_eq!(report.missing, expected);
    }

    #[test]
    fn the_report_never_carries_a_byte_of_the_brief() {
        // Non-negotiable rule 4, asserted rather than promised. A brief is the
        // likeliest document here to carry a name, a path or a pasted credential.
        let secret = "swordfish-account-01189998819991197253";
        let text = format!("## check\n\n{secret}\n\nnothing fenced\n");
        let report = problems(&text);
        let rendered = format!("{report:?} {}", report.lines().join(" "));
        assert!(
            !rendered.contains(secret),
            "the report must carry ids and counts only"
        );
    }

    #[test]
    fn every_section_id_is_unique_and_every_label_is_normalized() {
        // Totality over the one table: a duplicate id would make a report
        // ambiguous, and an unnormalized label could never match.
        let mut ids: Vec<&str> = SCHEMA.iter().map(|section| section.id).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "section ids must be unique");
        for section in SCHEMA {
            assert!(!section.labels.is_empty(), "{} declares no label", section.id);
            for label in section.labels {
                assert_eq!(
                    label_of(label).as_deref(),
                    Some(*label),
                    "declared label `{label}` is not in normalized form"
                );
            }
        }
    }
}
