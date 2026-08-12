//! Commit-metadata attribution policy (CLOUD-274), the mechanism for the
//! agent-neutral attribution decision record (CLOUD-268).
//!
//! The record separates three surfaces. Two of them reach public history and are
//! this module's subject:
//!
//! - **Authorship** — `author`/`committer` identity, `Co-authored-by`,
//!   `Signed-off-by` — asserts *accountability*. Accountability attaches to the
//!   human or service identity that directs, reviews and adopts a change, never
//!   to a model identity. Origin certification is a human act.
//! - **Disclosure** — one trailer in tool-identity form — asserts *what tooling
//!   assisted*. Consumer communities diverge from disclosure-required to
//!   AI-forbidden, so the posture is data in `[attribution]`, never a constant
//!   here.
//!
//! The third surface, provenance records, is deliberately out of scope: it is
//! Batten's own observability rather than git (CLOUD-275).
//!
//! # Why this is a gate over the artifact and not a setting
//!
//! Measured 2026-08-09 on this repository: 39 of the first 50 commits on `main`
//! were authored by an environment-injected vendor identity, 18 carried a
//! model-versioned co-authorship trailer, 20 a session URL. The injection is
//! environment-level — container git config plus harness prompt — and the host's
//! own suppression setting demonstrably does not govern every path: one trailer
//! is added by a path that ignores the off-switch. So the invariant is only ever
//! checkable on the produced commit. Trusting configuration here would be
//! trusting the thing that already lied.
//!
//! # Deny is the default; the allow-set is the carve-out
//!
//! One pair of lists expresses every posture. A trailer matching `trailer_deny`
//! is refused *unless* it matches `trailer_allow`. Listing the disclosure form in
//! both is how a repository opts in: silent leaves `trailer_allow` empty, so
//! every disclosure trailer is refused; disclosing sets it to the well-formed
//! shape, so a well-formed trailer passes and a malformed one is still refused.
//!
//! **An empty `trailer_allow` exempts nothing.** It cannot be implemented as an
//! empty pattern: an empty regex matches every input, which would exempt
//! everything and silently invert the gate. The emptiness is a branch, not a
//! pattern, and it has its own test.
//!
//! # Not a classifier
//!
//! This never decides whether a phrase *means* marketing or whether a name *is* a
//! model (non-negotiable rule 3). It asks whether a configured pattern matches a
//! named field, which is a computable predicate over text. Every pattern is
//! consumer data in `batten.toml`; this module carries none, and neither does the
//! rest of the crate.
//!
//! # Pointer, never payload
//!
//! A finding names the commit and the **field** — `a1b2c3d4 trailer:Co-Authored-By`
//! — never the matched text (non-negotiable rule 4, house style §6). Everything
//! this gate reads is by definition content someone wanted suppressed, so echoing
//! it back would make the gate republish exactly what it exists to catch.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::git;

/// The `[attribution]` table: what produced commits may carry about the tooling.
///
/// Consumer-specific by nature (non-negotiable rule 1, extended from consumers to
/// vendors): the engine holds the matcher, this table holds the answer. A vendor
/// name is configuration here and never a literal in the crate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// Patterns refused in the `author` and `committer` identity fields.
    ///
    /// Both fields, because the environment sets both and a repair reaching only
    /// `author` leaves the vendor identity on every commit's `committer` — absent
    /// from `git log`'s default format and fully public regardless.
    pub identity_deny: Vec<String>,
    /// Patterns refused in any trailer, matched against the whole `Key: value`
    /// line: a co-authorship form lives in the key, a session URL in the value.
    pub trailer_deny: Vec<String>,
    /// Patterns refused in the commit message body — attribution-as-advertising.
    pub body_deny: Vec<String>,
    /// The carve-out from [`Attribution::trailer_deny`]. Absent or empty exempts
    /// **nothing**, which is how a silent posture is expressed as data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trailer_allow: Vec<String>,
    /// The accountable identity `--set-identity` writes into the repo-local git
    /// config.
    pub identity: Identity,
}

/// The identity a commit is accountable to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// `user.name`.
    pub name: String,
    /// `user.email`.
    pub email: String,
}

impl Identity {
    /// The identity as git renders it in `%an <%ae>` form.
    #[must_use]
    pub fn rendered(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

/// The compiled form of one pattern list.
struct Matchers(Vec<Regex>);

impl Matchers {
    fn compile(key: &str, patterns: &[String]) -> Result<Self> {
        let mut compiled = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let regex = Regex::new(pattern).map_err(|error| {
                // The pattern is the consumer's own config, not commit content,
                // so naming it here is a pointer to the line they must fix.
                UsageError::raise(format!(
                    "attribution.{key}: `{pattern}` is not a valid regular expression: {error}"
                ))
            })?;
            compiled.push(regex);
        }
        Ok(Self(compiled))
    }

    fn matches(&self, text: &str) -> bool {
        self.0.iter().any(|regex| regex.is_match(text))
    }

    /// Whether this list exempts anything at all. An empty list is **no
    /// exemption**, never "exempt everything".
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One commit's judgeable metadata, however it was obtained.
///
/// `label` is what a finding points at: a short SHA for a commit that exists, the
/// word `pending` for a message that does not yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMeta {
    /// The finding's pointer prefix.
    pub label: String,
    /// `Name <email>` as git renders the author.
    pub author: String,
    /// `Name <email>` as git renders the committer.
    pub committer: String,
    /// Trailer lines, each a whole `Key: value`.
    pub trailers: Vec<String>,
    /// The full commit message.
    pub body: String,
}

/// A refusal, as a pointer.
///
/// Both fields are safe to print: `label` is a SHA or the literal `pending`, and
/// `field` is a field name or a trailer **key**. The matched text is never
/// carried, so there is no payload to leak downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The commit the refusal is about.
    pub label: String,
    /// Which surface carried it: `author`, `committer`, `body`, or
    /// `trailer:<Key>`.
    pub field: String,
}

impl Finding {
    /// The pointer line, house style §6.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{} {}", self.label, self.field)
    }
}

impl Attribution {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when a deny list is empty or any
    /// pattern fails to compile. An empty deny list is refused because a table
    /// declaring no patterns is the half-change rule 2 exists to catch: it reads
    /// as though a policy is recorded when nothing is. `trailer_allow` may be
    /// empty — there, emptiness is a meaningful posture.
    pub fn validate(&self) -> Result<()> {
        for (key, patterns) in [
            ("identity_deny", &self.identity_deny),
            ("trailer_deny", &self.trailer_deny),
            ("body_deny", &self.body_deny),
        ] {
            if patterns.is_empty() {
                return Err(UsageError::raise(format!(
                    "attribution.{key}: declares no patterns; a deny list matching nothing is not \
                     a policy"
                )));
            }
            Matchers::compile(key, patterns)?;
        }
        Matchers::compile("trailer_allow", &self.trailer_allow)?;
        if self.identity.name.is_empty() || self.identity.email.is_empty() {
            return Err(UsageError::raise(
                "attribution.identity: name and email are both required; an accountable identity \
                 with a blank half is not one"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Judge one commit's metadata, returning every refusal as a pointer.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) if a configured pattern does not
    /// compile. Validated at load too, so this is the belt to that suspenders and
    /// keeps the function total.
    pub fn judge(&self, commit: &CommitMeta) -> Result<Vec<Finding>> {
        let identity = Matchers::compile("identity_deny", &self.identity_deny)?;
        let trailer = Matchers::compile("trailer_deny", &self.trailer_deny)?;
        let body = Matchers::compile("body_deny", &self.body_deny)?;
        let allow = Matchers::compile("trailer_allow", &self.trailer_allow)?;

        let mut findings = Vec::new();
        let point = |field: &str| Finding {
            label: commit.label.clone(),
            field: field.to_owned(),
        };

        if identity.matches(&commit.author) {
            findings.push(point("author"));
        }
        if identity.matches(&commit.committer) {
            findings.push(point("committer"));
        }
        for line in &commit.trailers {
            if !trailer.matches(line) {
                continue;
            }
            // The carve-out. `is_empty` is checked first and separately: passing
            // an empty list to `matches` would answer `false` here, which happens
            // to be right, but the explicit branch is what documents that
            // emptiness means *no exemption* rather than a pattern that matches
            // everything.
            if !allow.is_empty() && allow.matches(line) {
                continue;
            }
            // The key alone. The value is the payload.
            let key = line.split_once(':').map_or(line.as_str(), |(key, _)| key);
            findings.push(point(&format!("trailer:{key}")));
        }
        if body.matches(&commit.body) {
            findings.push(point("body"));
        }
        Ok(findings)
    }
}

/// The git pretty-format placeholders one `git show -s` call needs, joined by a
/// separator no identity or trailer can contain.
const RECORD_SEPARATOR: &str = "\u{1e}";

/// Read every non-merge commit in `base..head`.
///
/// # Errors
///
/// Returns an error when the range does not resolve or git cannot be run. That is
/// exit `1` — "could not look" — never a clean pass over commits nobody read.
pub fn read_range(dir: &Path, base: &str, head: &str) -> Result<Vec<CommitMeta>> {
    let range = format!("{base}..{head}");
    let listed = git::query(
        dir,
        &["rev-list", "--no-merges", &range],
        "could not resolve the commit range",
    )?;

    let mut commits = Vec::new();
    for sha in listed.lines().filter(|line| !line.trim().is_empty()) {
        let format = format!(
            "%an <%ae>{RECORD_SEPARATOR}%cn <%ce>{RECORD_SEPARATOR}%(trailers:only,unfold)\
             {RECORD_SEPARATOR}%B"
        );
        let shown = git::query(
            dir,
            &["show", "-s", &format!("--format={format}"), sha],
            "could not read a commit in the range",
        )?;
        let mut parts = shown.splitn(4, RECORD_SEPARATOR);
        let author = parts.next().unwrap_or_default().to_owned();
        let committer = parts.next().unwrap_or_default().to_owned();
        let trailers = trailer_lines(parts.next().unwrap_or_default());
        let body = parts.next().unwrap_or_default().to_owned();
        commits.push(CommitMeta {
            label: short(sha),
            author,
            committer,
            trailers,
            body,
        });
    }
    Ok(commits)
}

/// Read the pending commit message plus the identity git is about to stamp.
///
/// This is the earliest computable moment: the message is on disk and `git var`
/// already resolves what the commit will carry, so a refusal here means the bad
/// commit is never created rather than created and found later in a range.
///
/// # Errors
///
/// Returns an error when the message file cannot be read or git cannot resolve an
/// identity — exit `1`, not a pass.
pub fn read_message(dir: &Path, message: &Path) -> Result<CommitMeta> {
    let body = std::fs::read_to_string(message).map_err(|error| {
        UsageError::raise(format!(
            "attribution: cannot read the commit message file `{}`: {error}",
            message.display()
        ))
    })?;
    let path = message.to_string_lossy().into_owned();
    // `git interpret-trailers --parse` applies git's own rules for where the
    // trailer block starts, so this does not re-derive them and cannot disagree
    // with what `%(trailers:only)` reports once the commit exists.
    let parsed = git::query(
        dir,
        &["interpret-trailers", "--parse", "--", &path],
        "could not parse the pending message's trailers",
    )?;
    Ok(CommitMeta {
        label: "pending".to_owned(),
        author: pending_identity(dir, "GIT_AUTHOR_IDENT")?,
        committer: pending_identity(dir, "GIT_COMMITTER_IDENT")?,
        trailers: trailer_lines(&parsed),
        body,
    })
}

/// Set the repo-local identity when it is unset or denied; report what happened.
///
/// **Repo-local only, never `--global`.** The wider scope covers a developer's own
/// unrelated repositories, and nothing here has the standing to change those.
///
/// The current identity is read as git *resolves* it rather than from the local
/// file, because the defect is an identity inherited from a wider scope: asking
/// only `--local` would report "unset" for an accountable global identity and write a
/// redundant copy into every clone.
///
/// # Errors
///
/// Returns an error when git cannot be run or the write fails.
pub fn set_identity(dir: &Path, attribution: &Attribution) -> Result<Outcome> {
    let name = git::query_optional(dir, &["config", "--get", "user.name"])?.unwrap_or_default();
    let email = git::query_optional(dir, &["config", "--get", "user.email"])?.unwrap_or_default();

    let outcome = if name.trim().is_empty() || email.trim().is_empty() {
        Outcome::WasUnset
    } else {
        let current = format!("{} <{}>", name.trim(), email.trim());
        let deny = Matchers::compile("identity_deny", &attribution.identity_deny)?;
        if deny.matches(&current) {
            Outcome::WasDenied
        } else {
            // A contributor who set their own accountable identity keeps it.
            // Overwriting a real person's name with a configured default would
            // assert the opposite of what the record says accountability is.
            return Ok(Outcome::LeftAlone);
        }
    };

    git::query(
        dir,
        &["config", "--local", "user.name", &attribution.identity.name],
        "could not write the repo-local user.name",
    )?;
    git::query(
        dir,
        &[
            "config",
            "--local",
            "user.email",
            &attribution.identity.email,
        ],
        "could not write the repo-local user.email",
    )?;
    Ok(outcome)
}

/// What [`set_identity`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// No identity resolved; one was written.
    WasUnset,
    /// The resolved identity matched the deny-set; it was replaced.
    WasDenied,
    /// An accountable identity was already configured and was not touched.
    LeftAlone,
}

impl Outcome {
    /// The one-line report, pointer-only: it names the prior *state*, never the
    /// denied value.
    #[must_use]
    pub fn line(self, identity: &Identity) -> String {
        match self {
            Self::WasUnset => format!(
                "attribution: repo-local identity set to {} (was: unset)",
                identity.rendered()
            ),
            Self::WasDenied => format!(
                "attribution: repo-local identity set to {} (was: denied)",
                identity.rendered()
            ),
            Self::LeftAlone => {
                "attribution: identity already accountable; left as configured".to_owned()
            }
        }
    }
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

/// Split a trailer block into whole `Key: value` lines, dropping blanks.
fn trailer_lines(block: &str) -> Vec<String> {
    block
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// The identity git is about to stamp, without the timestamp it appends.
///
/// `git var` prints `Name <email> <epoch> <tz>`; the time is not identity.
fn pending_identity(dir: &Path, var: &str) -> Result<String> {
    let raw = git::query(
        dir,
        &["var", var],
        "could not resolve the identity git would stamp",
    )?;
    Ok(raw
        .rfind('>')
        .map_or_else(|| raw.trim().to_owned(), |end| raw[..=end].to_owned()))
}

/// A commit's short form, as every other pointer in this repository renders it.
fn short(sha: &str) -> String {
    sha.chars().take(8).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy() -> Attribution {
        Attribution {
            identity_deny: vec![r"^Vendor <".to_owned(), r"@no-reply\.example>$".to_owned()],
            trailer_deny: vec![
                r"^Co-Authored-By:.*Vendor".to_owned(),
                r"^Vendor-Session:".to_owned(),
                r"^Assisted-by:".to_owned(),
            ],
            body_deny: vec![r"[Gg]enerated with".to_owned()],
            trailer_allow: Vec::new(),
            identity: Identity {
                name: "Accountable Human".to_owned(),
                email: "human@example.test".to_owned(),
            },
        }
    }

    fn commit() -> CommitMeta {
        CommitMeta {
            label: "a1b2c3d4".to_owned(),
            author: "Accountable Human <human@example.test>".to_owned(),
            committer: "Accountable Human <human@example.test>".to_owned(),
            trailers: vec!["Refs: CLOUD-274".to_owned()],
            body: "fix(x): a real change\n\nRefs: CLOUD-274\n".to_owned(),
        }
    }

    #[test]
    fn a_clean_commit_yields_nothing() {
        assert!(policy().judge(&commit()).unwrap().is_empty());
    }

    #[test]
    fn a_denied_author_is_pointed_at_by_field() {
        let mut subject = commit();
        subject.author = "Vendor <bot@no-reply.example>".to_owned();
        let found = policy().judge(&subject).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line(), "a1b2c3d4 author");
    }

    #[test]
    fn the_committer_field_is_judged_too() {
        // The field `git log` does not show by default, and the one a repair
        // reaching only `author` leaves behind.
        let mut subject = commit();
        subject.committer = "Vendor <bot@no-reply.example>".to_owned();
        let found = policy().judge(&subject).unwrap();
        assert_eq!(found[0].line(), "a1b2c3d4 committer");
    }

    #[test]
    fn a_denied_trailer_reports_the_key_and_never_the_value() {
        let mut subject = commit();
        subject
            .trailers
            .push("Vendor-Session: https://example.test/session_secret".to_owned());
        let found = policy().judge(&subject).unwrap();
        assert_eq!(found[0].line(), "a1b2c3d4 trailer:Vendor-Session");
        assert!(!report(&found).contains("session_secret"));
    }

    #[test]
    fn a_denied_body_reports_the_field_and_never_the_text() {
        let mut subject = commit();
        subject.body = "fix(x): a change\n\nGenerated with SomeTool\n".to_owned();
        let found = policy().judge(&subject).unwrap();
        assert_eq!(found[0].line(), "a1b2c3d4 body");
        assert!(!report(&found).contains("SomeTool"));
    }

    #[test]
    fn an_empty_allow_set_exempts_nothing() {
        // The inversion this branch exists to prevent: an empty pattern matches
        // every input, so an allow-set implemented as one would exempt everything
        // — silently disarming the gate for the exact configuration that means
        // "disclose nothing".
        let mut subject = commit();
        subject
            .trailers
            .push("Assisted-by: some-agent:some-model".to_owned());
        let found = policy().judge(&subject).unwrap();
        assert_eq!(found[0].line(), "a1b2c3d4 trailer:Assisted-by");
    }

    #[test]
    fn opting_in_carves_out_the_well_formed_shape_and_only_that_shape() {
        let mut disclosing = policy();
        disclosing.trailer_allow = vec![r"^Assisted-by: [a-z0-9-]+:[a-z0-9.-]+$".to_owned()];

        let mut well_formed = commit();
        well_formed
            .trailers
            .push("Assisted-by: some-agent:some-model".to_owned());
        assert!(disclosing.judge(&well_formed).unwrap().is_empty());

        // Opting in must not mean "stop checking".
        let mut malformed = commit();
        malformed
            .trailers
            .push("Assisted-by: Vendor Model <bot@no-reply.example>".to_owned());
        assert_eq!(
            disclosing.judge(&malformed).unwrap()[0].line(),
            "a1b2c3d4 trailer:Assisted-by"
        );
    }

    #[test]
    fn every_offending_surface_on_one_commit_is_reported() {
        // Findings are not short-circuited: an author fixed in isolation would
        // otherwise reveal a trailer nobody had been told about.
        let mut subject = commit();
        subject.author = "Vendor <bot@no-reply.example>".to_owned();
        subject.committer = "Vendor <bot@no-reply.example>".to_owned();
        subject.trailers.push("Vendor-Session: x".to_owned());
        subject.body = "Generated with SomeTool".to_owned();
        assert_eq!(policy().judge(&subject).unwrap().len(), 4);
    }

    #[test]
    fn an_empty_deny_list_is_refused_at_validate() {
        let mut empty = policy();
        empty.body_deny = Vec::new();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn an_uncompilable_pattern_is_refused_at_validate() {
        let mut broken = policy();
        broken.identity_deny = vec!["(unclosed".to_owned()];
        assert!(broken.validate().is_err());
    }

    #[test]
    fn a_blank_half_of_the_identity_is_refused() {
        let mut blank = policy();
        blank.identity.email = String::new();
        assert!(blank.validate().is_err());
    }

    #[test]
    fn a_valid_table_validates() {
        assert!(policy().validate().is_ok());
    }

    #[test]
    fn trailer_blocks_drop_blank_lines() {
        assert_eq!(
            trailer_lines("Refs: CLOUD-1\n\nSigned-off-by: A <a@b.test>\n"),
            vec!["Refs: CLOUD-1", "Signed-off-by: A <a@b.test>"]
        );
    }

    #[test]
    fn a_trailer_with_no_colon_points_at_the_whole_line() {
        // Defensive: `%(trailers:only)` should never emit one, and a panic here
        // would be a gate that crashes on malformed input rather than judging it.
        let mut subject = commit();
        subject.trailers = vec!["Assisted-by".to_owned()];
        let mut policy = policy();
        policy.trailer_deny = vec!["^Assisted-by".to_owned()];
        assert_eq!(
            policy.judge(&subject).unwrap()[0].line(),
            "a1b2c3d4 trailer:Assisted-by"
        );
    }

    #[test]
    fn the_outcome_line_names_the_state_not_the_denied_value() {
        let identity = policy().identity;
        assert!(Outcome::WasDenied.line(&identity).contains("was: denied"));
        assert!(Outcome::WasUnset.line(&identity).contains("was: unset"));
        assert!(
            Outcome::LeftAlone
                .line(&identity)
                .contains("left as configured")
        );
    }

    #[test]
    fn short_shas_are_eight_characters() {
        assert_eq!(short("a1b2c3d4e5f6"), "a1b2c3d4");
        assert_eq!(short("abc"), "abc");
    }
}
