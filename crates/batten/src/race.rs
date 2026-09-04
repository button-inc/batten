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
//! # What a key is, and what CLOSES one, is asked and never re-derived
//!
//! Both questions are [`ready::Grammar`]'s, reached here through [`Keys`]. That
//! is not tidiness: this module's first draft carried its own closing-verb
//! regex, which would have been a SECOND authority over the one distinction
//! that has already misfired in this repository — a pull request citing a key as
//! evidence, read as claiming it. Two authorities that can disagree about what
//! closes a key is the same defect one level up from the one being retired.
//!
//! The grammar resolves every token from the consumer's own `[[pattern]]`
//! registry, so no tracker vocabulary enters the crate (non-negotiable rule 1)
//! and `no-tracker-key-in-core` stays silent.
//!
//! [`Keys`] is a trait rather than a bare `&Grammar` so the predicate can be
//! driven by a double in a unit test. A grammar is resolved from ~18 declared
//! patterns, and a test that had to build one would be asserting the registry's
//! shape on the way to asserting this module's.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! A [`Race`] carries a key, a number and a head ref — three tokens. Never a
//! title, a body or a commit message: everything this reads is prose somebody
//! else wrote.

use regex::Regex;

use crate::ready::Grammar;

/// What a key is, and what closes one — the two questions this predicate asks
/// of somebody else.
///
/// Implemented for [`Grammar`], which resolves both from the consumer's
/// `[[pattern]]` registry. A caller may not answer either itself: that is what
/// keeps one concept to one spelling, and what stopped this module shipping a
/// closing-verb regex of its own.
pub trait Keys {
    /// Every key the text names, however it names it.
    fn named(&self, text: &str) -> Vec<String>;
    /// Every key the text names in CLOSING form — the ones a merge will move.
    fn closed(&self, text: &str) -> Vec<String>;
}

impl Keys for Grammar {
    fn named(&self, text: &str) -> Vec<String> {
        self.keys_in(text)
            .into_iter()
            .map(|key| key.to_string())
            .collect()
    }

    fn closed(&self, text: &str) -> Vec<String> {
        self.keys_closed_in(text)
            .into_iter()
            .map(|key| key.to_string())
            .collect()
    }
}

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
pub fn claimed(branch: &str, title: &str, log: &str, body: &str, keys: &dyn Keys) -> Vec<String> {
    let closing = dedup(keys.closed(&folded(&format!("{body}\n{log}"))));
    if !closing.is_empty() {
        return closing;
    }
    let declared = dedup(keys.named(&folded(&format!("{branch} {title}"))));
    if !declared.is_empty() {
        return declared;
    }
    refs_first(log, keys)
}

/// Upper-cased, because a key pattern is not obliged to be case-insensitive and
/// a BRANCH NAME is routinely not upper case.
///
/// **This is a fidelity requirement, not a nicety, and leaving it out is a
/// silent dead gate.** The retired shell extracted case-insensitively and
/// upper-cased the result. A consumer's key row need not carry an `(?i)` flag —
/// this one does not — while a tracker's own branch names are routinely lower
/// case. So a port that handed the branch to the grammar as written would
/// resolve NO key from source 2 on every branch such a consumer makes: the
/// claim would silently fall through to a `Refs:` trailer, or to nothing, and a
/// gate that finds nothing looks exactly like a gate that passed.
///
/// Folding the INPUT rather than relaxing the pattern is deliberate: the row is
/// consumer config read by other gates too, and widening it here would change
/// their answers to buy this one.
fn folded(text: &str) -> String {
    text.to_uppercase()
}

/// The FIRST key of each `Refs:` trailer, which is source 3.
///
/// The trailer itself is a commit-message convention rather than a tracker's
/// vocabulary, so the pattern for it belongs to this module. WHAT FOLLOWS it is
/// still the grammar's to recognise, which is why only the trailer and its
/// immediate neighbourhood is matched here and the key is read out of that span
/// by [`Keys::named`].
///
/// Only the first key counts. A trailer may go on to cite others, and citing is
/// not claiming — a property of taking the head of the span rather than a filter
/// applied afterwards, so a caller cannot reintroduce the conflation by
/// forgetting a step.
fn refs_first(log: &str, keys: &dyn Keys) -> Vec<String> {
    let mut found = Vec::new();
    for line in log.lines() {
        if let Some(hit) = TRAILER.find(line) {
            found.extend(keys.named(&folded(hit.as_str())).into_iter().take(1));
        }
    }
    dedup(found)
}

/// Sorted and deduplicated, so the output is byte-stable for one input (§6).
fn dedup(mut keys: Vec<String>) -> Vec<String> {
    keys.sort();
    keys.dedup();
    keys
}

/// The `owner/name` slug a remote URL points at, or `None` where it points at
/// something this cannot read.
///
/// Both spellings the forge hands out — `https://host/owner/name(.git)` and
/// `git@host:owner/name(.git)` — reduce to the same two segments. `None` rather
/// than a guess: a slug derived wrongly would ask the forge about a DIFFERENT
/// repository and get a confident answer about it, which is worse here than not
/// looking, because the verdict would read as this repository's.
#[must_use]
pub fn slug_of(url: &str) -> Option<String> {
    // The scp form puts the path after a colon; the URL form puts it after the
    // host. Reduce both to the path, then require exactly the two segments a
    // slug has — a URL naming only one is not a repository this can ask about,
    // and `None` is the honest answer rather than a slug built from the host.
    let path = url.split_once("://").map_or_else(
        || url.rsplit_once(':').map_or(url, |(_, tail)| tail),
        |(_, rest)| rest.split_once('/').map_or("", |(_, path)| path),
    );
    let path = path.strip_suffix(".git").unwrap_or(path).trim_matches('/');
    let mut segments = path.split('/');
    let owner = segments.next().filter(|part| !part.is_empty())?;
    let name = segments.next().filter(|part| !part.is_empty())?;
    segments.next().is_none().then(|| format!("{owner}/{name}"))
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
pub fn races(
    mine: &[String],
    pulls: &[Pull],
    self_number: Option<&str>,
    keys: &dyn Keys,
) -> Vec<Race> {
    let mut found = Vec::new();
    for pull in pulls {
        if Some(pull.number.as_str()) == self_number {
            continue;
        }
        let theirs = claimed(&pull.head_ref, &pull.title, &pull.log, &pull.body, keys);
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

    /// A [`Keys`] double, so this suite asserts THIS module's predicate rather
    /// than the pattern registry's shape on the way to it.
    ///
    /// It is deliberately dumber than the real grammar — a key is two uppercase
    /// runs around a dash, and a close is one of the forge's verbs immediately
    /// before one. Anything subtler is `ready::Grammar`'s to get right and
    /// `ready`'s own suite to pin; re-asserting it here would be the second
    /// authority this module exists to avoid.
    struct Fake;

    impl Keys for Fake {
        fn named(&self, text: &str) -> Vec<String> {
            KEY.find_iter(text)
                .map(|hit| hit.as_str().to_owned())
                .collect()
        }

        fn closed(&self, text: &str) -> Vec<String> {
            CLOSED
                .captures_iter(text)
                .filter_map(|hit| hit.get(1))
                .map(|hit| hit.as_str().to_owned())
                .collect()
        }
    }

    static KEY: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        #[expect(clippy::unwrap_used, reason = "a fixture pattern with no input")]
        Regex::new("[A-Z]+-[0-9]+").unwrap()
    });

    static CLOSED: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        #[expect(clippy::unwrap_used, reason = "a fixture pattern with no input")]
        Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+([A-Z]+-[0-9]+)").unwrap()
    });

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
            claimed("user/proj-843-campaign", "", "", "Closes PROJ-1170.", &Fake),
            vec!["PROJ-1170".to_owned()]
        );
    }

    #[test]
    fn a_bare_mention_in_a_body_is_a_citation_and_not_a_claim() {
        assert_eq!(
            claimed("", "", "", "Supersedes the measurement in PROJ-133.", &Fake),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_refs_trailer_answers_only_when_nothing_more_explicit_does() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "", &Fake),
            vec!["PROJ-1170".to_owned()]
        );
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "Closes PROJ-9.", &Fake),
            vec!["PROJ-9".to_owned()]
        );
    }

    #[test]
    fn a_trailer_claims_its_first_key_and_cites_the_rest() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170, PROJ-843\n", "", &Fake),
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
            races(&mine, &pulls, me.as_deref(), &Fake).is_empty(),
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
        assert_eq!(races(&mine, &pulls, None, &Fake).len(), 1);
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
        let races = races(&mine, &pulls, Some("793"), &Fake);
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
        assert!(races(&mine, &pulls, Some("793"), &Fake).is_empty());
    }

    #[test]
    fn both_remote_spellings_reduce_to_one_slug() {
        assert_eq!(
            slug_of("https://github.com/owner/name").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            slug_of("https://github.com/owner/name.git").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            slug_of("git@github.com:owner/name.git").as_deref(),
            Some("owner/name")
        );
    }

    #[test]
    fn a_url_naming_no_owner_is_none_rather_than_a_guess() {
        assert_eq!(slug_of("https://github.com/name"), None);
        assert_eq!(slug_of("name"), None);
    }

    #[test]
    fn a_head_sha_no_listed_pull_request_carries_identifies_nothing() {
        assert!(identify(&[pull("1", "a", "aaaa")], "bbbb").is_none());
    }
}
