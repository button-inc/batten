//! The commit-subject convention, as policy rather than a task-runner variable
//! (CLOUD-701).
//!
//! # Why the pattern lives in `batten.toml`
//!
//! This repository lands by fast-forward, so every commit reaches `main` with its
//! own SHA and message, and release-plz derives semver and the changelog from
//! those messages. That makes "is this subject conventional" a rule about what a
//! commit may *be* — policy — and policy belongs in the engine's own config.
//!
//! It previously lived as `CONVENTIONAL_RE` in `mise.toml [env]`, read by two
//! shell tasks. That is the task runner's configuration: the right home for how
//! tools are provisioned and run, and the wrong one for a predicate a gate
//! decides. [`crate::attribution`] beside this module was moved for the same
//! reason (CLOUD-274) and is the worked precedent.
//!
//! # Not a classifier
//!
//! This never decides whether a subject is *good* (non-negotiable rule 3). It
//! asks whether one configured pattern matches the subject line, which is a
//! computable predicate over text. The vocabulary of types and the shape of a
//! scope are the consumer's, expressed as a regex in their own config; this
//! module carries none of it.
//!
//! # Pointer, never payload
//!
//! A finding is `<sha8> subject` — the commit and the field, never the subject
//! text (non-negotiable rule 4, house style §6). This is a deliberate tightening:
//! the shell task it replaces printed the offending subject, which §6 does not
//! allow. A subject can carry anything its author typed, and a gate that echoes
//! it back is a gate that republishes whatever that was.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::git;

/// The `[commit]` table: what a commit subject must look like here.
///
/// Consumer-specific by nature (non-negotiable rule 1): the engine holds the
/// matcher, this table holds the answer. Which type words a repository admits,
/// and whether it requires a scope, are that repository's business.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    /// The regular expression every non-merge commit's subject must match.
    ///
    /// Required when the table is present: a `[commit]` declaring no pattern is
    /// the half-change rule 2 refuses — it reads as though a convention is
    /// recorded when nothing is.
    pub subject_pattern: String,
}

/// One commit's judgeable subject, however it was obtained.
///
/// `label` is what a finding points at: a short SHA for a commit that exists, the
/// word `pending` for a message that does not yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The finding's pointer prefix.
    pub label: String,
    /// The subject line — the first line of the message.
    pub text: String,
}

/// A refusal, as a pointer.
///
/// `label` is a SHA or the literal `pending`, and `field` is a field name. The
/// subject text is never carried, so there is no payload to leak downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The commit the refusal is about.
    pub label: String,
    /// Which surface carried it. `subject` for the convention clause, `admits`
    /// and `admits-tampered` for the articulation one — a field rather than a
    /// constant, exactly so a second commit-shape rule does not change the output
    /// schema. CLOUD-1278 is that second rule arriving, and this is the field
    /// doing the job it was written for.
    pub field: String,
    /// The protected path the refusal is about, where the clause has one.
    ///
    /// **A path is a pointer, which is why this does not breach rule 4**: §6 names
    /// `path:line` as an allowed shape outright, and the thing that may not be
    /// carried is the file's or the message's CONTENT. Without it an author is
    /// told a commit lacks an articulation and left to work out which of its
    /// protected paths — the one piece of information that makes the finding
    /// actionable.
    ///
    /// `skip_serializing_if` rather than a bare `Option`, so `-J` over a
    /// subject-clause run is byte-identical to what it was before this field
    /// existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl Finding {
    /// The pointer line, house style §6.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.subject {
            Some(path) => format!("{} {} {path}", self.label, self.field),
            None => format!("{} {}", self.label, self.field),
        }
    }
}

impl Commit {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty pattern or one that
    /// does not compile. Refused here, where the error names the key, rather than
    /// at the gate, where an uncompilable pattern would surface as a rule that
    /// silently matches nothing.
    pub fn validate(&self) -> Result<()> {
        if self.subject_pattern.is_empty() {
            return Err(UsageError::raise(
                "commit.subject_pattern: is empty; a convention matching nothing is not a \
                 convention"
                    .to_owned(),
            ));
        }
        self.matcher().map(|_| ())
    }

    /// The compiled pattern.
    fn matcher(&self) -> Result<Regex> {
        Regex::new(&self.subject_pattern).map_err(|error| {
            // The pattern is the consumer's own config, not commit content, so
            // naming it is a pointer to the line they must fix.
            UsageError::raise(format!(
                "commit.subject_pattern: `{}` is not a valid regular expression: {error}",
                self.subject_pattern
            ))
        })
    }

    /// Judge subjects, returning every refusal as a pointer.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) if the configured pattern does not
    /// compile. Validated at load too, so this is the belt to that suspenders and
    /// keeps the function total.
    pub fn judge(&self, subjects: &[Subject]) -> Result<Vec<Finding>> {
        let matcher = self.matcher()?;
        Ok(subjects
            .iter()
            .filter(|subject| !matcher.is_match(&subject.text))
            .map(|subject| Finding {
                label: subject.label.clone(),
                field: "subject".to_owned(),
                subject: None,
            })
            .collect())
    }
}

/// Judge the articulation clause: a commit that wrote a protected path carries
/// the block that says why (CLOUD-1278).
///
/// # What this closes
///
/// `V-PROTECTED-MUTATION`'s override route makes a protected write ADMISSIBLE —
/// the guarded party articulates, an admission is issued and spent, and the write
/// goes through. That much landed. What it did not do is make the articulation
/// legible to anyone: the record lives in a container-scoped store, so the
/// reasoning an override cost was readable only inside the session that wrote it,
/// and only until that session ended. A forcing function whose product nobody can
/// read is a toll, not an audit trail.
///
/// This is the half that makes it one. The block travels in the commit message,
/// which is durable, offline, and already in front of every reviewer and review
/// bot on the change it justifies.
///
/// # Two findings, and they mean opposite things
///
/// * `admits` — the commit wrote this protected path and no block claims it. The
///   author owes an articulation.
/// * `admits-tampered` — a block claims this path and does not hash to the
///   address it names. Somebody edited the reasoning after it was issued, or
///   assembled a block by hand. That is the graver one, and separating it is the
///   point: rolling both into "missing" would let a doctored block read as an
///   honest omission.
///
/// # The store is never consulted
///
/// [`crate::admission::Articulation::recomputes`] is a pure function of the block,
/// so this clause decides identically on a runner that has never seen the store —
/// which is the whole reason the block spells every binding field out instead of
/// carrying a reference. A tier that needed the store would pass locally and
/// abstain in CI, which is the shape of a gate that is not there.
#[must_use]
pub fn judge_admissions(writes: &[crate::git::CommitWrite]) -> Vec<Finding> {
    let mut found = Vec::new();
    for write in writes {
        let blocks = crate::admission::blocks(&write.message);
        for path in &write.paths {
            let claims: Vec<_> = blocks
                .iter()
                .filter(|block| block.binding.subject == *path)
                .collect();
            // A path with no block at all is the missing case. A path with blocks
            // of which at least one verifies is clean — several are legitimate,
            // since re-articulating the same path on one commit chains rather than
            // replaces.
            let field = if claims.is_empty() {
                "admits"
            } else if claims.iter().any(|block| block.recomputes()) {
                continue;
            } else {
                "admits-tampered"
            };
            found.push(Finding {
                label: short(&write.commit),
                field: field.to_owned(),
                subject: Some(path.clone()),
            });
        }
    }
    found
}

/// The pending-commit twin of [`judge_admissions`]: the message on disk, judged
/// against the paths the INDEX is about to commit.
///
/// The earliest computable moment, for [`read_message`]'s own reason one function
/// down — a refusal here means the unarticulated commit is never created, rather
/// than created and found later in a range where the fix is a rewrite.
///
/// `staged` rather than the working tree: an unstaged edit to a protected path is
/// explicitly not what this commit is about, and demanding a block for it would
/// refuse a commit that does not touch the path at all.
#[must_use]
pub fn judge_pending(message: &str, staged: &std::collections::BTreeSet<String>) -> Vec<Finding> {
    judge_admissions(&[crate::git::CommitWrite {
        commit: "pending".to_owned(),
        message: message.to_owned(),
        paths: staged.clone(),
    }])
}

/// Read every non-merge commit's subject in `base..head`.
///
/// One `git log` rather than a `rev-list` followed by a `show` per commit: the
/// subject is available from the same walk that enumerates the range, so the
/// second pass buys nothing.
///
/// # Errors
///
/// Returns an error when the range does not resolve or git cannot be run. That is
/// exit `1` — "could not look" — never a clean pass over commits nobody read.
pub fn read_range(dir: &Path, base: &str, head: &str) -> Result<Vec<Subject>> {
    Ok(git::subjects_in_range(dir, base, head)?
        .into_iter()
        .map(|read| Subject {
            label: short(&read.commit),
            text: read.subject,
        })
        .collect())
}

/// Read the subject of a pending commit message.
///
/// The earliest computable moment: the message is on disk and the commit does not
/// exist yet, so a refusal here means the offending commit is never created
/// rather than created and found later in a range.
///
/// # Errors
///
/// Returns an error when the message file cannot be read — exit `1`, not a pass.
pub fn read_message(message: &Path) -> Result<Subject> {
    let body = std::fs::read_to_string(message).map_err(|error| {
        UsageError::raise(format!(
            "commit: cannot read the commit message file `{}`: {error}",
            message.display()
        ))
    })?;
    Ok(Subject {
        label: "pending".to_owned(),
        // The subject is the first line, which is git's own definition and the
        // one `%s` reports once the commit exists. A message that is empty or
        // starts blank yields an empty subject, which no sane pattern matches —
        // a refusal, and the correct one.
        text: body.lines().next().unwrap_or_default().to_owned(),
    })
}

/// Render a run's findings as pointer lines, one per line.
#[must_use]
pub fn report(findings: &[Finding]) -> String {
    let mut rendered = String::new();
    for finding in findings {
        // Infallible on a String sink; the `_ =` is what says so.
        _ = writeln!(rendered, "{}", finding.line());
    }
    rendered
}

/// A commit's short form, as every other pointer in this repository renders it.
fn short(sha: &str) -> String {
    sha.chars().take(8).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy() -> Commit {
        Commit {
            subject_pattern: r"^(feat|fix|chore)([(][a-z]+[)])?!?: .+".to_owned(),
        }
    }

    fn subject(text: &str) -> Subject {
        Subject {
            label: "a1b2c3d4".to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_conventional_subject_yields_nothing() {
        let clean = [
            subject("feat: a thing"),
            subject("fix(cli): a thing"),
            subject("chore!: a breaking thing"),
        ];
        assert!(policy().judge(&clean).unwrap().is_empty());
    }

    #[test]
    fn a_non_conventional_subject_is_pointed_at_by_field() {
        let found = policy().judge(&[subject("just did some stuff")]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line(), "a1b2c3d4 subject");
    }

    #[test]
    fn the_subject_text_is_never_carried() {
        // The tightening this module makes over the shell task it replaces. A
        // subject carries whatever its author typed, so echoing it back is the
        // gate republishing arbitrary content.
        let found = policy().judge(&[subject("wip SECRETLEAK stuff")]).unwrap();
        assert!(!report(&found).contains("SECRETLEAK"));
        assert_eq!(report(&found), "a1b2c3d4 subject\n");
    }

    #[test]
    fn every_offending_subject_is_reported_not_just_the_first() {
        let mixed = [
            Subject {
                label: "aaaaaaaa".to_owned(),
                text: "nope".to_owned(),
            },
            subject("feat: fine"),
            Subject {
                label: "cccccccc".to_owned(),
                text: "also nope".to_owned(),
            },
        ];
        let found = policy().judge(&mixed).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].label, "aaaaaaaa");
        assert_eq!(found[1].label, "cccccccc");
    }

    #[test]
    fn an_empty_subject_is_refused_rather_than_waved_through() {
        let found = policy().judge(&[subject("")]).unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn an_empty_pattern_is_refused_at_validate() {
        let empty = Commit {
            subject_pattern: String::new(),
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn an_uncompilable_pattern_is_refused_at_validate() {
        let broken = Commit {
            subject_pattern: "(unclosed".to_owned(),
        };
        assert!(broken.validate().is_err());
    }

    #[test]
    fn a_valid_table_validates() {
        assert!(policy().validate().is_ok());
    }

    #[test]
    fn short_shas_are_eight_characters() {
        assert_eq!(short("a1b2c3d4e5f6"), "a1b2c3d4");
        assert_eq!(short("abc"), "abc");
    }
}
