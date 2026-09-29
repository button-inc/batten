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
    /// Whether every commit in a judged RANGE must name the tracker row it
    /// serves, and which commits are exempt (CLOUD-843).
    ///
    /// Absent is the reading every consumer had before: a range is judged for
    /// its subjects and nothing else. Present, `commit check <base>..<head>`
    /// refuses a commit whose message claims no row — see [`judge_claims`].
    #[serde(default)]
    pub claims: Option<Claims>,
}

/// The `[commit.claims]` table: every commit names the row it serves (CLOUD-843).
///
/// # The server-side half of a claim
///
/// A claim receipt lives in the clone's own git directory and never leaves it,
/// so no reviewer and no workflow can see it. What a server CAN see is whether
/// each commit names the issue it serves — the half of the claim that survives a
/// fresh checkout (CLOUD-431). This repository's `commit-lint` task asked that in
/// shell, one `claim keys` spawn per commit; the question is this table's now,
/// asked in process over the range `commit check` already walks.
///
/// "Names a row" is `claim keys`' own reading of the WHOLE message — a closing
/// keyword first, then the first key of each `Refs:` trailer — through the
/// consumer's `[[pattern]]` grammar, never a key shape spelled here (rule 1).
/// Claiming is stricter than mentioning: a commit citing a row as evidence has
/// not thereby become work on it (CLOUD-338/CLOUD-378).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// The commits that owe no claim, each a property of the COMMIT rather than
    /// of its wording: which paths it touched, and who authored it.
    ///
    /// Empty by default. An exemption keyed to the file set cannot be claimed by
    /// a hand-written commit that merely borrows a release's subject, which is why
    /// the subject is not a column here.
    #[serde(default)]
    pub unclaimed: Vec<Unclaimed>,
}

/// One class of commit that owes no claim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Unclaimed {
    /// The row's name, for a reader of the config — never printed per commit.
    pub id: String,
    /// A regular expression EVERY path the commit changed must match. A commit
    /// that changed nothing matches vacuously, as the retired shell's filter did.
    pub paths: String,
    /// When set, the commit's AUTHOR address — git's `%ae` — must match this too.
    ///
    /// The author rather than the committer, because a forge commits an App's work
    /// as itself and only the author half names which App wrote it.
    #[serde(default)]
    pub author: Option<String>,
}

/// One commit's claim evidence, gathered by the caller.
///
/// Prepared outside for [`judge_admissions`]' reason: the predicate stays a pure
/// function of what git said, testable without a repository.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claimant {
    /// The finding's pointer: a short sha.
    pub label: String,
    /// The author identity as git renders it, `Name <address>`.
    pub author: String,
    /// Every path the commit changed against its first parent.
    pub paths: Vec<String>,
    /// Whether the commit's message claims a row.
    pub claims: bool,
}

impl Claims {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a row with no name or an expression that
    /// does not compile — refused here, where the error names the row, rather
    /// than at the gate, where it would be an exemption that silently matches
    /// nothing and so refuses a class of commit it was written to admit.
    pub fn validate(&self) -> Result<()> {
        for row in &self.unclaimed {
            if row.id.is_empty() {
                return Err(UsageError::raise(
                    "commit.claims.unclaimed: a row carries no `id`".to_owned(),
                ));
            }
            row.matchers()?;
        }
        Ok(())
    }
}

impl Unclaimed {
    /// The two compiled expressions, the author's where declared.
    fn matchers(&self) -> Result<(Regex, Option<Regex>)> {
        let compile = |column: &str, expression: &str| {
            Regex::new(expression).map_err(|error| {
                UsageError::raise(format!(
                    "commit.claims.unclaimed `{}`: `{column}` is not a valid regular expression: {error}",
                    self.id
                ))
            })
        };
        let paths = compile("paths", &self.paths)?;
        let author = match &self.author {
            Some(expression) => Some(compile("author", expression)?),
            None => None,
        };
        Ok((paths, author))
    }

    /// Whether this row exempts `commit`.
    ///
    /// Both conjuncts, cheapest first: the author is one string, the paths a walk.
    fn exempts(paths: &Regex, author: Option<&Regex>, commit: &Claimant) -> bool {
        let address = address_of(commit.author.as_str());
        let authored = match author {
            Some(author) => author.is_match(address),
            None => true,
        };
        authored && every_path_matches(paths, &commit.paths)
    }
}

/// Whether every path matches `expression` — vacuously so for none.
fn every_path_matches(expression: &Regex, paths: &[String]) -> bool {
    for path in paths {
        if !expression.is_match(path) {
            return false;
        }
    }
    true
}

/// The address inside `Name <address>`, or the whole identity when it carries
/// no angle brackets.
fn address_of(identity: &str) -> &str {
    identity
        .rsplit_once('<')
        .and_then(|(_, rest)| rest.strip_suffix('>'))
        .unwrap_or(identity)
}

/// Judge the claim clause: every commit names the row it serves, unless a
/// declared exemption covers it (CLOUD-843).
///
/// A finding is `<sha8> claim` — the commit and the field, never the subject the
/// retired shell echoed, which is exactly the payload rule 4 refuses.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) when an exemption's expression does not
/// compile. Validated at load too, so this keeps the function total.
//MUTANT-SUITE crates/batten/src/commit.rs
//MUTANT unclaimed-commit-passes|s@        if commit.claims {@        if true {@|a_commit_naming_no_row_is_pointed_at_by_field
//MUTANT exemption-ignores-author|s@            Some(author) => author.is_match(address),@            Some(_) => true,@|a_bot_address_is_required_as_well_as_the_bot_paths
//MUTANT exemption-ignores-paths|s@        if !expression.is_match(path) {@        if false {@|a_release_row_does_not_exempt_a_commit_touching_code
pub fn judge_claims(commits: &[Claimant], claims: &Claims) -> Result<Vec<Finding>> {
    let rows = claims
        .unclaimed
        .iter()
        .map(Unclaimed::matchers)
        .collect::<Result<Vec<_>>>()?;
    let mut found = Vec::new();
    for commit in commits {
        if commit.claims {
            continue;
        }
        let exempt = rows
            .iter()
            .any(|(paths, author)| Unclaimed::exempts(paths, author.as_ref(), commit));
        if exempt {
            continue;
        }
        found.push(Finding {
            label: commit.label.clone(),
            field: "claim".to_owned(),
            subject: None,
        });
    }
    Ok(found)
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
        if let Some(claims) = &self.claims {
            claims.validate()?;
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
/// `path write refused`'s override route makes a protected write ADMISSIBLE —
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
///
/// # A path with a sanctioned mutation owes no block, and that is the override
/// route's own precondition read back (CLOUD-1303)
///
/// `path write refused` declares its override route for the case where *"the
/// surface this class names cannot express the change, so writing the protected
/// path directly is the only route left"*. A path a `[[redirect]]` speaks for is
/// the negation of that sentence: the surface exists, the write goes through it,
/// nothing is refused, and so **no admission is ever issued and there is nothing
/// to articulate**. Demanding a block there leaves exactly one route — an
/// override whose precondition is false — so the honest author must either write
/// a false articulation or not commit at all. Measured: `.serena/memories/**`
/// joined `protected` and the `[[redirect]]` table together, and the first commit
/// to write a memory through `write_memory` was refused six times over.
///
/// Articulation is therefore owed by protected paths with **no** sanctioned
/// mutation — which is the set the precondition describes.
///
/// **ONLY THE DEMAND IS DROPPED, NEVER THE INSPECTION.** The earlier shape of
/// this fix exempted the path before looking at it, which silently lost
/// `admits-tampered` for the whole exempted set — a doctored block on a memory
/// would have gone unexamined. Here the redirect answers only the *absence* case:
/// a block that claims the path is still verified, and still reported when it
/// does not recompute. The graver finding keeps its whole subject set.
///
/// `redirects` is the config's own table, passed in rather than resolved here for
/// [`ArmSequence`]'s reason: the predicate stays a pure function of its arguments,
/// so it decides identically on a runner that cannot reach the store OR the
/// config — which is what keeps the range half and the pending half from drifting.
#[must_use]
pub fn judge_admissions(
    writes: &[crate::git::CommitWrite],
    redirects: &[crate::redirect::Redirect],
) -> Vec<Finding> {
    let mut found = Vec::new();
    for write in writes {
        let blocks = crate::admission::blocks(&write.message);
        for path in &write.paths {
            let claims: Vec<_> = blocks
                .iter()
                .filter(|block| block.binding.subject == *path)
                .collect();
            // A path with no block at all is the missing case — unless a
            // `[[redirect]]` sanctions a mutation for it, which means the write
            // had a route that refuses nothing and issues nothing. A path with
            // blocks of which at least one verifies is clean — several are
            // legitimate, since re-articulating the same path on one commit chains
            // rather than replaces.
            let field = if claims.is_empty() {
                if crate::redirect::resolve(redirects, path).is_some() {
                    continue;
                }
                "admits"
            } else if claims.iter().any(|block| block.recomputes()) {
                continue;
            } else {
                // REACHED FOR A REDIRECTED PATH TOO, and that is the half the
                // superseded fix dropped.
                //MUTANT admits-tampered-survives-the-redirect|s/^            } else if claims/            } else if crate::redirect::resolve(redirects, path).is_some() || claims/|a tampered block on a redirected path is still refused
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
pub fn judge_pending(
    message: &str,
    staged: &std::collections::BTreeSet<String>,
    redirects: &[crate::redirect::Redirect],
) -> Vec<Finding> {
    judge_admissions(
        &[crate::git::CommitWrite {
            commit: "pending".to_owned(),
            message: message.to_owned(),
            paths: staged.clone(),
        }],
        redirects,
    )
}

/// One commit's two conserves-ledger sets, ready to intersect (CLOUD-1402).
///
/// Prepared by the caller and never resolved here, for [`judge_admissions`]'s own
/// reason: the predicate stays a pure function of two sets, so it decides
/// identically on a runner that cannot reach git and the whole of it is testable
/// without a fixture repository.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArmSequence {
    /// The finding's pointer prefix — a short SHA, or `pending`.
    pub label: String,
    /// The `[rule.conserves]` arms this commit INTRODUCED, keyed by the config
    /// path a reader would open (`<rule id>.<arm>`) and carrying the token each
    /// arm declares.
    ///
    /// Introduced means absent at the parent and present here. An arm the tree
    /// already carried is not in this map, which is what keeps every ordinary use
    /// of the ledger silent.
    pub introduced: std::collections::BTreeMap<String, String>,
    /// The lines this commit ADDED under the ledger's `declared_in` glob.
    ///
    /// Lines rather than paths, because the spend is a line: the whole question is
    /// whether one of the tokens above is written in a row this same commit wrote.
    pub added_lines: Vec<String>,
}

/// Judge the sequencing clause: an escape hatch is not spent by the commit that
/// creates it (CLOUD-1402).
///
/// # What this closes
///
/// `[rule.conserves]`'s arms are the ledger a ratchet decrease has to satisfy, and
/// two of them are optional — `withdrawn` and `ported` (CLOUD-1080, CLOUD-1268).
/// Adding one is a widening of what a deletion may claim, which is exactly the
/// kind of change that wants an independent reader.
///
/// It did not get one. `65757c86` both added `withdrawn` to `batten.toml` and
/// *spent* it, in the same commit, on the deletion it wanted to make. An escape
/// hatch created and consumed at once is **self-authorizing**: the thing that
/// would have refused the deletion was authored by the same change, so nothing
/// independent ever judged whether that particular withdrawal was correct. That
/// first use shipped a partly-wrong deletion — it retired the `NO_PROXY` fencing
/// on the reasoning that honouring the environment's CA bundle made it
/// unnecessary, conflating TLS re-termination with the proxy's injected-token 403
/// — and the reasoning stood unrefuted in the history for a week (CLOUD-1399).
///
/// # The remedy is sequencing, not permission
///
/// Land the arm, let it be reviewed on its own, then spend it. That costs one
/// extra commit and buys the independent judgement the hatch was supposed to have.
/// There is deliberately no override route: an admission here would be the author
/// authorizing their own hatch one layer up.
///
/// # Bound, stated
///
/// It catches the one-commit case. An author who lands the arm and spends it in
/// the NEXT commit of the same PR has satisfied the letter and not obviously the
/// spirit — but that is a review question, and a gate demanding a merge between
/// the two would be refusing ordinary work. Narrow on purpose.
///
/// # No model verdict reaches the exit code
///
/// Both sides are sets of strings the caller read out of the diff and the config.
/// A line counts as a spend when, trimmed, it STARTS WITH the arm's token — which
/// is [`crate::rules`]'s own rule for reading an arm, asked rather than
/// re-derived, so this clause cannot disagree with the ledger about what an arm
/// row is.
#[must_use]
pub fn judge_arm_sequencing(sequences: &[ArmSequence]) -> Vec<Finding> {
    let mut found = Vec::new();
    for sequence in sequences {
        for (key, token) in &sequence.introduced {
            // An empty token would prefix-match every line, so an arm declared as
            // `""` would refuse any commit that added one. `validate_conserves`
            // refuses that at load; skipping it here means a caller that bypassed
            // validation gets silence rather than a rule that denies everything.
            if token.is_empty() {
                continue;
            }
            if sequence
                .added_lines
                .iter()
                .any(|line| line.trim_start().starts_with(token.as_str()))
            {
                found.push(Finding {
                    label: sequence.label.clone(),
                    field: "arm-self-authorized".to_owned(),
                    subject: Some(key.clone()),
                });
            }
        }
    }
    found
}

// THE MUTATION FOR THIS PREDICATE IS DECLARED IN ITS SUITE, NOT HERE (CLOUD-1402).
//
// `obligations-bound` binds a §7 obligation by reading the declared FILE's lines
// for a row beginning `#MUTANT <slug>|`, and its `line_sources` covers
// `crates/batten/tests/**` where `crates/batten/src/**` is not. So the row lives
// in `crates/batten/tests/it/commit_arm_sequencing.rs`, which is where the claims
// object names it and the only place the gate can see it.
//
// Measured the hard way: the row was written HERE first, with only a prose
// mention of the slug in the suite. `declares_slug` matches a line PREFIX, a
// mention inside a doc comment is not one, and `test name undefined` fired over a
// promise that was in fact kept — which is the gate being right about the
// binding and me being wrong about where it reads.

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
            claims: None,
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
            claims: None,
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn an_uncompilable_pattern_is_refused_at_validate() {
        let broken = Commit {
            subject_pattern: "(unclosed".to_owned(),
            claims: None,
        };
        assert!(broken.validate().is_err());
    }

    #[test]
    fn a_valid_table_validates() {
        assert!(policy().validate().is_ok());
    }

    // --- the claim clause (CLOUD-843) ------------------------------------------
    //
    // Pinned over the PREDICATE, as the sequencing clause below is. The tier that
    // proves `commit check` gathers the evidence — the range walked, the message
    // read through `claim keys`' grammar, the paths and the author taken off each
    // commit — is `crates/batten/tests/it/commit_claims.rs`.

    /// This repository's two exemptions, shaped as its `batten.toml` declares
    /// them — spelled here rather than read, because the subject is the predicate
    /// and a fixture following the committed table would move with it.
    fn claims() -> Claims {
        Claims {
            unclaimed: vec![
                Unclaimed {
                    id: "release".to_owned(),
                    paths: r"^(Cargo\.(toml|lock)|.*CHANGELOG\.md)$".to_owned(),
                    author: None,
                },
                Unclaimed {
                    id: "update-bot".to_owned(),
                    paths:
                        r"^(\.github/workflows/[^/]+\.ya?ml|mise\.(toml|lock)|Cargo\.(toml|lock))$"
                            .to_owned(),
                    author: Some(r"\[bot\]@users\.noreply\.github\.com$".to_owned()),
                },
            ],
        }
    }

    fn claimant(label: &str, author: &str, paths: &[&str], claims: bool) -> Claimant {
        Claimant {
            label: label.to_owned(),
            author: author.to_owned(),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            claims,
        }
    }

    /// `#MUTANT unclaimed-commit-passes` reddens here: a commit naming no row,
    /// touching code, by a person, is the finding — as a pointer.
    #[test]
    fn a_commit_naming_no_row_is_pointed_at_by_field() {
        let found = judge_claims(
            &[claimant(
                "a1b2c3d4",
                "Someone <someone@example.com>",
                &["crates/batten/src/lib.rs"],
                false,
            )],
            &claims(),
        )
        .unwrap();
        assert_eq!(report(&found), "a1b2c3d4 claim\n");
    }

    /// The mirror: a commit that claims a row is never a finding, whatever it
    /// touched.
    #[test]
    fn a_commit_that_claims_its_row_yields_nothing() {
        let found = judge_claims(
            &[claimant(
                "a1b2c3d4",
                "Someone <someone@example.com>",
                &["crates/batten/src/lib.rs"],
                true,
            )],
            &claims(),
        )
        .unwrap();
        assert!(found.is_empty());
    }

    /// A release commit — version and changelog only — owes no claim, and an
    /// empty commit matches vacuously, as the retired shell's filter did.
    #[test]
    fn a_version_and_changelog_commit_owes_no_claim() {
        let found = judge_claims(
            &[
                claimant(
                    "aaaaaaaa",
                    "release-plz <r@example.com>",
                    &["Cargo.lock", "Cargo.toml", "crates/batten/CHANGELOG.md"],
                    false,
                ),
                claimant("bbbbbbbb", "Someone <someone@example.com>", &[], false),
            ],
            &claims(),
        )
        .unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    /// `#MUTANT exemption-ignores-paths` reddens here: the release row is a
    /// property of the file set, so a commit touching code is not exempt.
    #[test]
    fn a_release_row_does_not_exempt_a_commit_touching_code() {
        let found = judge_claims(
            &[claimant(
                "aaaaaaaa",
                "release-plz <r@example.com>",
                &["Cargo.toml", "crates/batten/src/lib.rs"],
                false,
            )],
            &claims(),
        )
        .unwrap();
        assert_eq!(report(&found), "aaaaaaaa claim\n");
    }

    /// `#MUTANT exemption-ignores-author` reddens here. The bot row is two
    /// conjuncts: a workflow-only diff is ordinary human work, so a person
    /// touching only workflows still owes a claim (CLOUD-431).
    #[test]
    fn a_bot_address_is_required_as_well_as_the_bot_paths() {
        let by_a_person = claimant(
            "cccccccc",
            "Someone <someone@example.com>",
            &[".github/workflows/ci.yml"],
            false,
        );
        let by_the_bot = claimant(
            "dddddddd",
            "renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
            &[".github/workflows/ci.yml", "mise.toml"],
            false,
        );
        let found = judge_claims(&[by_a_person, by_the_bot], &claims()).unwrap();
        assert_eq!(report(&found), "cccccccc claim\n");
    }

    /// And the bot's address alone is not enough: a bump reaching anything but a
    /// manifest is not a bump.
    #[test]
    fn a_bot_commit_reaching_past_the_manifests_owes_a_claim() {
        let found = judge_claims(
            &[claimant(
                "eeeeeeee",
                "renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
                &["mise.toml", "crates/batten/src/lib.rs"],
                false,
            )],
            &claims(),
        )
        .unwrap();
        assert_eq!(report(&found), "eeeeeeee claim\n");
    }

    #[test]
    fn an_exemption_that_does_not_compile_is_refused_at_validate() {
        let broken = Claims {
            unclaimed: vec![Unclaimed {
                id: "broken".to_owned(),
                paths: "(unclosed".to_owned(),
                author: None,
            }],
        };
        assert!(broken.validate().is_err());
        let nameless = Claims {
            unclaimed: vec![Unclaimed {
                id: String::new(),
                paths: ".*".to_owned(),
                author: None,
            }],
        };
        assert!(nameless.validate().is_err());
        assert!(claims().validate().is_ok());
    }

    #[test]
    fn an_identity_yields_its_address() {
        assert_eq!(address_of("A B <a@b.c>"), "a@b.c");
        assert_eq!(address_of("a@b.c"), "a@b.c");
    }

    #[test]
    fn short_shas_are_eight_characters() {
        assert_eq!(short("a1b2c3d4e5f6"), "a1b2c3d4");
        assert_eq!(short("abc"), "abc");
    }

    // --- the sequencing clause (CLOUD-1402) --------------------------------
    //
    // The load-time tier. It pins the PREDICATE over two sets these cases build.
    // `crates/batten/tests/it/commit_arm_sequencing.rs` is the tier that proves
    // the RESOLVER builds them — whether the parent's config is read at all, and
    // whether a ledger line the commit added is told apart from one already
    // there. Neither substitutes for the other.

    fn sequence(arm: &str, token: &str, added: &[&str]) -> ArmSequence {
        ArmSequence {
            label: "a1b2c3d4".to_owned(),
            introduced: std::iter::once((arm.to_owned(), token.to_owned())).collect(),
            added_lines: added.iter().map(|line| (*line).to_owned()).collect(),
        }
    }

    #[test]
    fn an_arm_introduced_and_spent_at_once_is_refused() {
        let found = judge_arm_sequencing(&[sequence(
            "suites-not-gutted.withdrawn",
            "// withdrawn:",
            &["// withdrawn: \"one\" the subject is gone"],
        )]);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].line(),
            "a1b2c3d4 arm-self-authorized suites-not-gutted.withdrawn"
        );
    }

    #[test]
    fn an_indented_arm_row_is_still_a_spend() {
        // The trim is `rules.rs`'s own rule for reading an arm, asked rather than
        // re-derived: an arm row inside a function body is indented, and a clause
        // anchoring at column zero would miss every real one.
        let found = judge_arm_sequencing(&[sequence(
            "suites-not-gutted.withdrawn",
            "// withdrawn:",
            &["    // withdrawn: \"one\" the subject is gone"],
        )]);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn an_arm_introduced_and_not_spent_is_silent() {
        // The remedy's own shape. A clause that refused this would refuse landing
        // the arm at all, which is a wall rather than a sequencing rule.
        let found = judge_arm_sequencing(&[sequence(
            "suites-not-gutted.withdrawn",
            "// withdrawn:",
            &["// carried: \"one\" successors/beta.rs"],
        )]);
        assert!(found.is_empty());
    }

    #[test]
    fn an_arm_the_commit_did_not_introduce_is_never_judged() {
        // THE DISCRIMINATING CASE, at this tier: the spend is present and the
        // introduced set is empty, which is every honest use of the ledger. A
        // predicate keyed only on the spend would refuse it.
        let found = judge_arm_sequencing(&[ArmSequence {
            label: "a1b2c3d4".to_owned(),
            added_lines: vec!["// withdrawn: \"one\" the subject is gone".to_owned()],
            ..ArmSequence::default()
        }]);
        assert!(found.is_empty());
    }

    #[test]
    fn a_blank_token_claims_nothing_rather_than_everything() {
        // `validate_conserves` refuses a declared-but-blank arm at load, so this
        // is the belt to that suspenders — and it fails in the safe direction. An
        // empty token prefix-matches every line, so honouring it would refuse
        // every commit that added one.
        let found = judge_arm_sequencing(&[sequence(
            "suites-not-gutted.withdrawn",
            "",
            &["anything at all"],
        )]);
        assert!(found.is_empty());
    }

    #[test]
    fn every_introduced_arm_spent_is_reported_not_just_the_first() {
        let both = ArmSequence {
            label: "a1b2c3d4".to_owned(),
            introduced: [
                (
                    "suites-not-gutted.withdrawn".to_owned(),
                    "// withdrawn:".to_owned(),
                ),
                (
                    "suites-not-gutted.ported".to_owned(),
                    "// ported:".to_owned(),
                ),
            ]
            .into_iter()
            .collect(),
            added_lines: vec![
                "// withdrawn: \"one\" the subject is gone".to_owned(),
                "// ported: \"two\" successors/beta.rs suites/beta.t".to_owned(),
            ],
        };
        let found = judge_arm_sequencing(&[both]);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn the_ledger_row_text_is_never_carried() {
        // Rule 4 at this clause. An arm row carries a REASON, which is prose its
        // author typed, so a finding echoing it would republish whatever that was.
        let found = judge_arm_sequencing(&[sequence(
            "suites-not-gutted.withdrawn",
            "// withdrawn:",
            &["// withdrawn: \"one\" SECRETLEAK"],
        )]);
        assert!(!report(&found).contains("SECRETLEAK"));
    }
}
