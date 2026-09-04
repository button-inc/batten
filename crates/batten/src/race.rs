//! Which OTHER open pull request already claims this branch's issue
//! (CLOUD-446, moved into the engine by CLOUD-1422).
//!
//! # Why this is here rather than in `mise-tasks/`
//!
//! `mise-tasks/claim-race-check.sh` answered this question and answered it
//! wrongly in the one environment that decides whether work lands. It excluded
//! the branch's OWN pull request from the competitor list by resolving it with
//! `gh pr view` and no argument — which reads the CURRENT BRANCH. Under
//! `actions/checkout` on a `pull_request` event the checkout is detached at the
//! merge ref, so that call fails:
//!
//! ```text
//! could not determine current branch: failed to run git: not on any branch
//! ```
//!
//! The shell absorbed it with `|| true`, so the self number was empty, no
//! competitor could equal it, and every pull request was judged as racing
//! **itself**. Measured on PR #793, run 33825308497: `CLOUD-1170 is already
//! claimed by open PR #793`. It is not intermittent — `commit-lint` requires a
//! `Refs:` trailer on every commit, so the detached reading always resolves a
//! claim through source 3 — and it is invisible locally, where a branch name
//! exists and the same gate is green on the same tree.
//!
//! # The fix is the port, not a repair carried across
//!
//! [`identify`] resolves this branch's pull request by **head SHA**, taken from
//! the same listing that supplies the competitors. A SHA survives a detached
//! checkout where a branch name does not, so the failing arm cannot be reached
//! rather than being handled. That is the whole reason this is a retirement and
//! not a patch: the shell had no spelling for the question.
//!
//! # No tracker vocabulary lives here (non-negotiable rule 1)
//!
//! The issue-key pattern arrives as a parameter, from the consumer's own
//! `[[pattern]]` registry. A grep of `crates/` for a specific tracker's key
//! shape returns nothing, which `no-tracker-key-in-core` gates.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! A [`Race`] carries a key, a number and a head ref — three tokens. Never a
//! title, a body or a commit message: everything this reads is prose somebody
//! else wrote.

use regex::Regex;

/// One open pull request, as the forge lists it.
///
/// `head_sha` is what makes the self-comparison work in a detached checkout and
/// is the field the retired shell had no access to: `gh pr view` answered from
/// the branch, so there was nothing to compare a commit against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull {
    /// The pull request number, as a token.
    pub number: String,
    /// Its head branch name.
    pub head_ref: String,
    /// Its head commit.
    pub head_sha: String,
    /// Its title — a self-declaration, and source 2.
    pub title: String,
    /// Its body — evidence, and source 1 only through a closing keyword.
    pub body: String,
    /// Its commit messages, joined — sources 1 and 3.
    pub log: String,
}

/// One refusal: a key this branch claims that another open pull request claims
/// too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    /// The contested key.
    pub key: String,
    /// The competing pull request's number.
    pub number: String,
    /// Its head branch, so the reader can find it without a second lookup.
    pub head_ref: String,
}

/// The three sources a claim may come from, most explicit first.
///
/// Ported from `claimed-keys.sh` unchanged in meaning, and the ORDER is the
/// whole of it: a closing keyword OVERRIDES the branch, which is the escape
/// hatch for a branch whose name no longer reflects the work; a `Refs:` trailer
/// answers only when neither of the first two does.
///
/// A body CITES related issues, prior measurements and superseded work as
/// evidence — that is not a claim, and treating it as one made a pull request
/// citing a key read as racing it. Both sides of the comparison go through this
/// one function for exactly that reason.
#[must_use]
pub fn claimed(branch: &str, title: &str, log: &str, body: &str, key: &Regex) -> Vec<String> {
    let closing = closing_keys(&format!("{body}\n{log}"), key);
    if !closing.is_empty() {
        return closing;
    }
    let declared = keys_in(&format!("{branch} {title}"), key);
    if !declared.is_empty() {
        return declared;
    }
    refs_first(log, key)
}

/// Every key a closing keyword names, uppercased and deduplicated.
fn closing_keys(text: &str, key: &Regex) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        for capture in CLOSING.find_iter(line) {
            found.extend(keys_in(capture.as_str(), key));
        }
    }
    dedup(found)
}

/// The FIRST key of each `Refs:` trailer, which is source 3.
///
/// Only whitespace is allowed between the trailer and the key, so the citations
/// that may follow it on the same line are not claims. That is a property of
/// this pattern rather than a filter applied afterwards, which is what keeps a
/// caller from reintroducing the conflation by forgetting the filter.
fn refs_first(log: &str, key: &Regex) -> Vec<String> {
    let mut found = Vec::new();
    for line in log.lines() {
        if let Some(hit) = TRAILER.find(line) {
            found.extend(keys_in(hit.as_str(), key).into_iter().take(1));
        }
    }
    dedup(found)
}

/// Every key the pattern matches in `text`, uppercased and deduplicated.
fn keys_in(text: &str, key: &Regex) -> Vec<String> {
    dedup(
        key.find_iter(text)
            .map(|hit| hit.as_str().to_uppercase())
            .collect(),
    )
}

/// Sorted and deduplicated, so the output is byte-stable for one input (§6).
fn dedup(mut keys: Vec<String>) -> Vec<String> {
    keys.sort();
    keys.dedup();
    keys
}

/// This branch's own pull request, resolved by HEAD SHA.
///
/// **The whole defect this module retires lives in the alternative.** Resolving
/// by branch name asks a question a detached checkout cannot answer, and the
/// shell's answer to not being able to answer was to carry on with an empty
/// self — so the branch raced itself. A SHA is carried by the listing and by the
/// checkout alike.
#[must_use]
pub fn identify<'a>(pulls: &'a [Pull], head_sha: &str) -> Option<&'a Pull> {
    pulls.iter().find(|pull| pull.head_sha == head_sha)
}

/// Every key this branch claims that a DIFFERENT open pull request claims too.
///
/// `mine` is the claimed set for this branch, computed by the caller through
/// [`claimed`] so that the branch's local evidence — its own log, and its
/// pull request's body where it has one — reaches the same function the
/// competitors are read through.
///
/// Returns an empty vector when nothing races, which is the clean verdict. A
/// caller that cannot establish the competitor set must not call this at all:
/// an empty list here means *looked and found none*, and conflating that with
/// *could not look* is the dead gate this whole module is a correction for.
#[must_use]
pub fn races(mine: &[String], pulls: &[Pull], self_number: Option<&str>, key: &Regex) -> Vec<Race> {
    let mut found = Vec::new();
    for pull in pulls {
        if Some(pull.number.as_str()) == self_number {
            continue;
        }
        let theirs = claimed(&pull.head_ref, &pull.title, &pull.log, &pull.body, key);
        for contested in mine.iter().filter(|key| theirs.contains(key)) {
            found.push(Race {
                key: contested.clone(),
                number: pull.number.clone(),
                head_ref: pull.head_ref.clone(),
            });
        }
    }
    found
}

/// A closing keyword in any of its inflections, with the key that follows it.
///
/// The verbs are the forge's, not the tracker's, so they are engine vocabulary
/// rather than a consumer fact — what a closing keyword CLOSES is decided by the
/// forge for every repository alike.
static CLOSING: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "a literal pattern with no input: it compiles or the binary does not"
    )]
    Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+\S+").unwrap()
});

/// A `Refs:` trailer and the one key that may follow it.
static TRAILER: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "a literal pattern with no input: it compiles or the binary does not"
    )]
    Regex::new(r"(?i)^\s*refs:\s*\S+").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    /// The consumer's pattern, supplied the way the verb supplies it — never a
    /// literal in the module under test.
    fn key() -> Regex {
        #[expect(clippy::unwrap_used, reason = "a fixture pattern")]
        Regex::new("[A-Z]+-[0-9]+").unwrap()
    }

    fn pull(number: &str, head_ref: &str, head_sha: &str) -> Pull {
        Pull {
            number: number.to_owned(),
            head_ref: head_ref.to_owned(),
            head_sha: head_sha.to_owned(),
            title: String::new(),
            body: String::new(),
            log: String::new(),
        }
    }

    #[test]
    fn a_closing_keyword_overrides_the_branch_name() {
        assert_eq!(
            claimed(
                "user/proj-843-campaign",
                "",
                "",
                "Closes PROJ-1170.",
                &key()
            ),
            vec!["PROJ-1170".to_owned()]
        );
    }

    #[test]
    fn a_bare_mention_in_a_body_is_a_citation_and_not_a_claim() {
        assert_eq!(
            claimed(
                "",
                "",
                "",
                "Supersedes the measurement in PROJ-133.",
                &key()
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_refs_trailer_answers_only_when_nothing_more_explicit_does() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "", &key()),
            vec!["PROJ-1170".to_owned()]
        );
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "Closes PROJ-9.", &key()),
            vec!["PROJ-9".to_owned()]
        );
    }

    #[test]
    fn a_trailer_claims_its_first_key_and_cites_the_rest() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170, PROJ-843\n", "", &key()),
            vec!["PROJ-1170".to_owned()]
        );
    }

    /// The regression this module exists for, as a unit: the shell resolved the
    /// branch's own pull request by NAME, so a detached checkout produced no
    /// self and the branch raced itself.
    #[test]
    fn this_branch_is_identified_by_head_sha_and_never_races_itself() {
        let mine = vec!["PROJ-1170".to_owned()];
        let pulls = vec![Pull {
            title: String::new(),
            body: "Closes PROJ-1170.".to_owned(),
            log: String::new(),
            ..pull("793", "user/proj-843-campaign", "e97703b2")
        }];
        let me = identify(&pulls, "e97703b2").map(|pull| pull.number.clone());
        assert_eq!(me.as_deref(), Some("793"));
        assert!(
            races(&mine, &pulls, me.as_deref(), &key()).is_empty(),
            "a branch may not race its own pull request"
        );
    }

    /// The same input with the self number unresolved — the state the retired
    /// shell was in on every CI run. It is a refusal, which is why the verb
    /// must never call `races` with `None` after a failed lookup.
    #[test]
    fn an_unresolved_self_is_what_made_the_branch_race_itself() {
        let mine = vec!["PROJ-1170".to_owned()];
        let pulls = vec![Pull {
            title: String::new(),
            body: "Closes PROJ-1170.".to_owned(),
            log: String::new(),
            ..pull("793", "user/proj-843-campaign", "e97703b2")
        }];
        assert_eq!(races(&mine, &pulls, None, &key()).len(), 1);
    }

    #[test]
    fn a_different_pull_request_claiming_the_key_is_the_race_this_refuses() {
        let mine = vec!["PROJ-49".to_owned()];
        let pulls = vec![
            Pull {
                body: "Closes PROJ-49.".to_owned(),
                ..pull("400", "other/proj-49", "aaaa")
            },
            pull("793", "mine", "bbbb"),
        ];
        let races = races(&mine, &pulls, Some("793"), &key());
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].key, "PROJ-49");
        assert_eq!(races[0].number, "400");
    }

    #[test]
    fn a_competitor_that_only_cites_the_key_does_not_race_it() {
        let mine = vec!["PROJ-133".to_owned()];
        let pulls = vec![Pull {
            title: "docs(agents): the sweep (PROJ-268)".to_owned(),
            body: "| PROJ-133 | measured 2026-08-08 |".to_owned(),
            ..pull("306", "user/proj-268-sweep", "aaaa")
        }];
        assert!(races(&mine, &pulls, Some("793"), &key()).is_empty());
    }

    #[test]
    fn a_head_sha_no_listed_pull_request_carries_identifies_nothing() {
        assert!(identify(&[pull("1", "a", "aaaa")], "bbbb").is_none());
    }
}
