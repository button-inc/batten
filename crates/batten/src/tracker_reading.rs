//! The readings the `tracker-hygiene` preset decides over: a tracker's issue
//! payloads, and a pull request's body, each reduced to one record family
//! (CLOUD-843).
//!
//! # What retired into here, and what did not
//!
//! Five inline task bodies carried these readings in bash — `done-record`,
//! `done-pr-check`, `duplicate-close-record`, `deferral-record` and
//! `closing-key-record` — parsing `get_issue` payloads with `jq`, walking `git
//! log` twice, splitting paragraphs with `awk` and re-deriving the issue key with
//! `grep`. None of that decided anything a module could not, and none of it
//! could be tested except by running the task body. It is mechanism, so it is
//! here; every DECISION over the records lives in the preset's modules, and this
//! module mints no finding.
//!
//! **THE EFFECTS STAY OUTSIDE** (house-style §5). The payloads and the body
//! arrive on stdin exactly as they did: fetching them needs a tracker credential
//! the engine does not hold. The git walks are in process, through `gix`, which
//! is the one git reader the crate has.
//!
//! # Repo-agnostic by construction (non-negotiable rule 1)
//!
//! Every consumer fact arrives as an input or a `[[pattern]]` row: which status
//! name means Done, which tag glob marks a release, which rev is the trunk,
//! which phrase is a deferral, and which marker declines a close. The issue key
//! is the consumer's `ready-issue-key` row through [`crate::ready::Grammar`], the
//! one definition CLOUD-1142 converged the crate on — never a literal here.
//!
//! # Could-not-look writes nothing
//!
//! Every refusal the retired bodies made is a [`UsageError`] here, and the
//! caller clears the family's stale record before reading, so a refusal leaves
//! the store ABSENT — which the modules read as "nobody looked" — rather than a
//! previous run's record answering as this one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use crate::error::UsageError;
use crate::pattern::NamedPattern;
use crate::ready::Grammar;

/// Every family this module reads, which is also every record the
/// `tracker-hygiene` preset decides over.
///
/// **One producer clears them all, and that is what lets one preset row carry
/// five modules.** A preset row compiles every module it ships, so `check` over
/// that row judges whatever tracker record the branch happens to hold. A
/// `deferral` record left by a landing lap would otherwise refuse the next
/// `done` question for a reason nobody asked about. Clearing the set before each
/// reading makes the record in the store the answer to the question just asked
/// and nothing older.
pub const FAMILIES: &[&str] = &[
    "done",
    "done-pr",
    "duplicate-close",
    "deferral",
    "closing-key",
];

/// How many leading ISO-8601 characters two closes are compared over when the
/// caller names no window: `19` is the second.
pub const DEFAULT_WINDOW: usize = 19;

/// Whether `family` is one this module reads.
#[must_use]
pub fn is_family(family: &str) -> bool {
    FAMILIES.contains(&family)
}

/// One family's record, from its declared inputs and whatever is on stdin.
///
/// `root` is the checkout the git-reading families walk; `patterns` is the
/// consumer's `[[pattern]]` table, read by the families that need a concept only
/// the consumer can spell.
///
/// # Errors
///
/// A [`UsageError`] for an unknown family, an input the family does not read or
/// is missing, an undeclared `[[pattern]]` row, or any input the family cannot
/// look at — the refusals are each family's own, named below.
pub fn reading(
    family: &str,
    inputs: &BTreeMap<String, String>,
    patterns: &[NamedPattern],
    root: &Path,
    stdin: &str,
) -> Result<String> {
    match family {
        "done" => done(inputs, root, stdin),
        "done-pr" => done_pr(inputs, stdin),
        "duplicate-close" => duplicate_close(inputs, stdin),
        "deferral" => deferral(inputs, patterns, root, stdin),
        "closing-key" => closing_key(inputs, patterns, root, stdin),
        _ => Err(UsageError::raise(format!(
            "record derive: no reading is declared for family `{family}`"
        ))),
    }
}

/// Refuse an input key the family does not read — a misspelled input must not
/// ride a clean exit.
fn only(inputs: &BTreeMap<String, String>, family: &str, accepted: &[&str]) -> Result<()> {
    if let Some(key) = inputs.keys().find(|key| !accepted.contains(&key.as_str())) {
        return Err(UsageError::raise(format!(
            "record derive {family}: reads no input `{key}`"
        )));
    }
    Ok(())
}

/// One required input, or a usage error naming it.
fn required<'a>(inputs: &'a BTreeMap<String, String>, family: &str, key: &str) -> Result<&'a str> {
    inputs.get(key).map(String::as_str).ok_or_else(|| {
        UsageError::raise(format!(
            "record derive {family}: needs `--input {key}=<value>`"
        ))
    })
}

/// A could-not-look refusal, worded once so every family says the same thing
/// about what it did not write.
fn refuse(family: &str, why: &str) -> anyhow::Error {
    UsageError::raise(format!("record derive {family}: {why}. Nothing recorded."))
}

/// One declared `[[pattern]]` row, compiled.
fn declared(patterns: &[NamedPattern], family: &str, id: &str) -> Result<Regex> {
    let row = patterns
        .iter()
        .find(|row| row.id == id)
        .ok_or_else(|| refuse(family, &format!("no `[[pattern]]` row declares `{id}`")))?;
    Regex::new(&row.regex).map_err(|_| {
        refuse(
            family,
            &format!("`[[pattern]]` row `{id}` will not compile"),
        )
    })
}

/// The payload set on stdin: one JSON array, or a stream of values.
///
/// **`jq -s`'s normalisation, carried**: a single array is the set itself, and
/// anything else — one object, or several concatenated — is the list of values.
/// Empty stdin and unparseable stdin are both could-not-look, never an empty
/// board.
fn payloads(family: &str, stdin: &str) -> Result<Vec<Value>> {
    if stdin.trim().is_empty() {
        return Err(refuse(family, "stdin is empty; expected tracker payloads"));
    }
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_str(stdin).into_iter::<Value>() {
        values.push(value.map_err(|_| refuse(family, "stdin is not a tracker payload set"))?);
    }
    if let [Value::Array(items)] = values.as_slice() {
        return Ok(items.clone());
    }
    Ok(values)
}

/// A JSON value as `jq -r` renders it: a string bare, anything else as JSON.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// One payload's `id`, or `None` where it carries none.
fn id_of(issue: &Value) -> Option<String> {
    issue.get("id").map(text_of).filter(|id| !id.is_empty())
}

/// The digits after an id's first `-`, for a byte-stable numeric order.
///
/// ORDER ONLY, never a decision: `sort -t- -k2,2n` is what the retired bodies
/// ran, and a key with no such digits sorts first rather than being refused —
/// the tracker decides what a key looks like, and this only lays lines out.
fn ordinal(id: &str) -> u64 {
    id.split_once('-')
        .map(|(_, rest)| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

/// Keys, numerically ordered and deduplicated.
fn by_ordinal(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: BTreeSet<(u64, String)> = keys.into_iter().map(|key| (ordinal(&key), key)).collect();
    set.into_iter().map(|(_, key)| key).collect()
}

/// A key list as one record column: space-joined, or `-` for none.
///
/// `-` rather than an empty column, because a tab-separated line with an empty
/// last column is indistinguishable from one that was cut short.
fn column(keys: &[String]) -> String {
    if keys.is_empty() {
        String::from("-")
    } else {
        keys.join(" ")
    }
}

/// Whether `text` names `id` as a whole key.
///
/// **Bounded on both sides**, which is the retired body's
/// `(^|[^0-9A-Za-z-])ID([^0-9]|$)`: `CLOUD-17` is not named by a commit naming
/// `CLOUD-179`, and a key inside a longer hyphenated token is not named at all.
/// The bytes either side are READ rather than matched, so no expression is
/// composed out of an id a payload supplied.
//MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
//MUTANT prefix-matches-a-longer-id|s@^            && after.is_none_or(not_a_digit)$@            \&\& after.is_none_or(char::is_alphanumeric)@|a_prefix_does_not_match_a_longer_id
fn names(text: &str, id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    text.match_indices(id).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + id.len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-')
            && after.is_none_or(not_a_digit)
    })
}

/// The right-hand bound of [`names`]: a key ends where no digit follows it.
///
/// A named function rather than a closure, so the `#MUTANT` row above can name
/// the call site: `mutate` splits a row on `|`, and a closure's bars would break it.
fn not_a_digit(c: char) -> bool {
    !c.is_ascii_digit()
}

/// `done`: each piped issue's status, and whether a release, the trunk, or
/// nothing carries a commit naming it (CLOUD-192).
///
/// Record: `issue\t<id>\t<done|other>\t<shipped|landed|unlanded>` per issue,
/// closed by `census\tissues=<n>`. The status column is NORMALISED against the
/// `done` input, so the module compares a token the engine minted rather than a
/// tracker's column name — which is what lets it ship as a preset.
///
/// Refuses where the retired body did, because each is a verdict about a fetch
/// problem rather than about the board: payloads lacking `id` or `status`, a
/// `landed` rev that does not resolve (every Done would read unlanded — a false
/// green), and no tag matching `released` (every Done would read unreleased — a
/// false red).
fn done(inputs: &BTreeMap<String, String>, root: &Path, stdin: &str) -> Result<String> {
    const FAMILY: &str = "done";
    only(inputs, FAMILY, &["released", "landed", "done"])?;
    let glob = required(inputs, FAMILY, "released")?;
    let landed = required(inputs, FAMILY, "landed")?;
    let done_status = required(inputs, FAMILY, "done")?;
    let issues = payloads(FAMILY, stdin)?;
    if !issues
        .iter()
        .all(|issue| issue.get("id").is_some() && issue.get("status").is_some())
    {
        return Err(refuse(
            FAMILY,
            "stdin is not a set of tracker payloads (need id and status per issue)",
        ));
    }
    if crate::git::resolve_ref(root, landed)
        .ok()
        .flatten()
        .is_none()
    {
        return Err(refuse(
            FAMILY,
            &format!("`{landed}` does not resolve, so landedness cannot be read"),
        ));
    }
    let tags: Vec<String> = crate::git::tag_facts(root, &[glob.to_owned()])?
        .remove(glob)
        .unwrap_or_default()
        .into_iter()
        .map(|tag| tag.commit)
        .collect();
    if tags.is_empty() {
        return Err(refuse(
            FAMILY,
            &format!(
                "no tag matches `{glob}` in this clone, so releasedness cannot be read; fetch tags"
            ),
        ));
    }
    // Each history read ONCE, into a value: the retired body learned that a
    // `git log | grep -q` under `pipefail` reports SIGPIPE even when it matched.
    let released = crate::git::messages_reachable(root, &tags, &[])?;
    let unreleased = crate::git::messages_reachable(root, &[landed.to_owned()], &tags)?;

    let rows: BTreeSet<(u64, String, &str)> = issues
        .iter()
        .filter_map(|issue| {
            let id = id_of(issue)?;
            let status = issue.get("status").map(text_of).unwrap_or_default();
            let token = if status == done_status {
                "done"
            } else {
                "other"
            };
            Some((ordinal(&id), id, token))
        })
        .collect();
    let mut record = String::new();
    for (_, id, status) in &rows {
        let shipped = if names(&released, id) {
            "shipped"
        } else if names(&unreleased, id) {
            "landed"
        } else {
            "unlanded"
        };
        writeln!(record, "issue\t{id}\t{status}\t{shipped}")?;
    }
    writeln!(record, "census\tissues={}", rows.len())?;
    Ok(record)
}

/// The number a pull-request URL names, by [`crate::landed::is_pull_request_url`]'s
/// one spelling (CLOUD-1623): the digits after the first `/pull/` that has any.
fn pull_number(url: &str) -> Option<u64> {
    if !crate::landed::is_pull_request_url(url) {
        return None;
    }
    url.match_indices("/pull/").find_map(|(at, marker)| {
        let digits: String = url[at + marker.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    })
}

/// `done-pr`: each piped issue's attached pull requests and the state the caller
/// fetched for each (CLOUD-468).
///
/// Record: `issue\t<id>\t<attached>` per issue, then `pull\t<id>\t<n>\t<state>`
/// per attached pull request — the state one of `draft`, `open` or `closed` —
/// closed by `census\tissues=<n>`. A
/// draft is recorded as a draft even though it is open, because naming it as one
/// is the point: CLOUD-420 read Done for 35 minutes over a draft nobody noticed.
///
/// Refuses on an empty set, a payload with no `id`, and — the load-bearing one —
/// an attached pull request with no state under `.pulls`. An unread pull request
/// must not be the cheapest route to Done.
//MUTANT absent-state-recorded-closed|s@^            let Some(state) = state else {$@            let Some(state) = state.or(Some(\&Value::Null)) else {@|an_attached_pr_with_no_state_is_could_not_look
//MUTANT draft-recorded-open|s@^                "draft"$@                "open"@|the_defect_a_draft_pull_request_refuses_named_as_a_draft
fn done_pr(inputs: &BTreeMap<String, String>, stdin: &str) -> Result<String> {
    const FAMILY: &str = "done-pr";
    only(inputs, FAMILY, &[])?;
    let issues = payloads(FAMILY, stdin)?;
    if issues.is_empty() || !issues.iter().all(|issue| issue.get("id").is_some()) {
        return Err(refuse(
            FAMILY,
            "stdin is not a set of tracker payloads (need an id per issue)",
        ));
    }
    let mut record = String::new();
    let mut counted = 0usize;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for issue in &issues {
        // ONE LINE PER ISSUE: a payload piped twice would otherwise write two
        // identical lines, which the module's set collapses into a torn census.
        let Some(id) = id_of(issue).filter(|id| seen.insert(id.clone())) else {
            continue;
        };
        let numbers: BTreeSet<u64> = issue
            .get("attachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|attachment| attachment.get("url").and_then(Value::as_str))
            .filter_map(pull_number)
            .collect();
        writeln!(record, "issue\t{id}\t{}", numbers.len())?;
        counted += 1;
        let pulls = issue.get("pulls").and_then(Value::as_array);
        for number in &numbers {
            let state = pulls.and_then(|listed| {
                listed
                    .iter()
                    .find(|pull| pull.get("number").and_then(Value::as_u64) == Some(*number))
            });
            let Some(state) = state else {
                return Err(refuse(
                    FAMILY,
                    &format!(
                        "{id} names PR #{number} and stdin carries no state for it; fetch it \
                         and pipe it under .pulls — a Done over an unread pull request is the \
                         defect this reading exists to refuse"
                    ),
                ));
            };
            let token = if state.get("draft").and_then(Value::as_bool) == Some(true) {
                "draft"
            } else if state.get("state").and_then(Value::as_str) == Some("open") {
                "open"
            } else {
                "closed"
            };
            writeln!(record, "pull\t{id}\t{number}\t{token}")?;
        }
    }
    writeln!(record, "census\tissues={counted}")?;
    Ok(record)
}

/// Whether a payload carries `relations.duplicateOf` at all — an explicit `null`
/// included, because null is data and only total absence is a projection that
/// dropped the relation.
fn keys_duplicate_of(issue: &Value) -> bool {
    issue
        .get("relations")
        .and_then(Value::as_object)
        .is_some_and(|relations| relations.contains_key("duplicateOf"))
}

/// The id a payload is a duplicate of: `duplicateOf.id`, or `duplicateOf` when
/// the tracker spelled it as a bare string, or `None`.
fn duplicate_target(issue: &Value) -> Option<String> {
    let relation = issue.get("relations")?.get("duplicateOf")?;
    let target = match relation {
        Value::String(id) => id.clone(),
        Value::Object(_) => relation.get("id").map(text_of)?,
        _ => return None,
    };
    (!target.is_empty() && target != "null").then_some(target)
}

/// The first `window` characters of a stamp — the comparison's whole precision.
fn truncated(stamp: &str, window: usize) -> String {
    stamp.chars().take(window).collect()
}

/// `duplicate-close`: each piped duplicate close beside its target's completion,
/// both stamps truncated to the window (CLOUD-829).
///
/// Record: `dup\t<id>\t<closed>\t<target>\t<target completed>` per duplicate
/// whose target completed, closed by `census\tduplicates=<n>`.
///
/// Every could-not-look the retired body had is a refusal: an empty or
/// unparseable set; a set in which NO payload carries `relations.duplicateOf`
/// (a projection that dropped the relation reads as "no duplicates" otherwise —
/// the anti-vacuity term); a duplicate with no `canceledAt`; and a duplicate
/// whose target was not piped, because a question nobody asked is not a clean
/// answer.
//MUTANT absent-key-reads-as-clean|s@^    if !issues.iter().any(keys_duplicate_of) {$@    if false {@|a_set_with_no_duplicateof_key_anywhere_is_could_not_look
//MUTANT target-outside-the-set-passes|s@^        if !ids.contains(target.as_str()) {$@        if false {@|a_duplicate_whose_target_was_not_piped_is_unjudgeable
//MUTANT window-input-ignored|s@^    let window = match inputs.get("window") {$@    let window = match None::<String> {@|a_duplicate_close_window_input_narrows_the_stamps_and_refuses_a_non_number
//MUTANT unstamped-close-passes|s@^        let Some(closed) = closed else {$@        let Some(closed) = closed.or(Some(String::new())) else {@|a_duplicate_close_with_no_stamp_is_unjudgeable
fn duplicate_close(inputs: &BTreeMap<String, String>, stdin: &str) -> Result<String> {
    const FAMILY: &str = "duplicate-close";
    only(inputs, FAMILY, &["window"])?;
    let window = match inputs.get("window") {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| refuse(FAMILY, &format!("window `{raw}` is not a whole number")))?,
        None => DEFAULT_WINDOW,
    };
    let issues = payloads(FAMILY, stdin)?;
    if issues.is_empty() {
        return Err(refuse(FAMILY, "stdin is not a tracker payload set"));
    }
    if !issues.iter().any(keys_duplicate_of) {
        return Err(refuse(
            FAMILY,
            "no payload carries relations.duplicateOf — re-fetch with get_issue(includeRelations: true)",
        ));
    }
    let ids: BTreeSet<String> = issues.iter().filter_map(id_of).collect();
    let mut duplicates: Vec<(u64, String, Option<String>, String)> = issues
        .iter()
        .filter_map(|issue| {
            let id = id_of(issue)?;
            let target = duplicate_target(issue)?;
            let closed = issue
                .get("canceledAt")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Some((ordinal(&id), id, closed, target))
        })
        .collect();
    duplicates.sort_by_key(|(order, ..)| *order);
    // One line per duplicate, for `done_pr`'s reason: a repeated payload must not
    // write a second identical line and tear the census.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    duplicates.retain(|(_, id, ..)| seen.insert(id.clone()));
    let mut record = String::new();
    let mut counted = 0usize;
    for (_, id, closed, target) in duplicates {
        let Some(closed) = closed else {
            return Err(refuse(
                FAMILY,
                &format!(
                    "{id} is a duplicate of {target} and carries no canceledAt, so its close cannot be compared"
                ),
            ));
        };
        if !ids.contains(target.as_str()) {
            return Err(refuse(
                FAMILY,
                &format!(
                    "{id} is a duplicate of {target}, which was not piped — a question nobody asked is not a clean answer"
                ),
            ));
        }
        let completed = issues
            .iter()
            .find(|issue| id_of(issue).as_deref() == Some(target.as_str()))
            .and_then(|issue| issue.get("completedAt"))
            .and_then(Value::as_str);
        let Some(completed) = completed else {
            continue;
        };
        writeln!(
            record,
            "dup\t{id}\t{}\t{target}\t{}",
            truncated(&closed, window),
            truncated(completed, window)
        )?;
        counted += 1;
    }
    writeln!(record, "census\tduplicates={counted}")?;
    Ok(record)
}

/// A body's paragraphs, each joined onto one line.
///
/// `awk`'s paragraph mode, carried: a run of blank lines separates paragraphs,
/// leading and trailing ones make none, and a paragraph's lines join with one
/// space. A line holding only whitespace is blank here, as it is to every
/// Markdown renderer the body is written for.
fn paragraphs(body: &str) -> Vec<String> {
    let clean = body.replace('\r', "");
    let mut found = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in clean.split('\n') {
        if line.trim().is_empty() {
            if !current.is_empty() {
                found.push(current.join(" "));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        found.push(current.join(" "));
    }
    found
}

/// A paragraph with every backtick code span replaced by a placeholder.
///
/// A span NAMING a phrase is not a paragraph USING it — a body documenting the
/// gate writes the phrase in backticks. An unmatched backtick opens nothing.
//MUTANT code-span-read-as-prose|s@^        out.push_str("CODESPAN");$@        out.push_str(\&rest[open..=open + 1 + close]);@|a_code_span_names_the_phrase_without_using_it_and_other_shapes_pass
fn without_code_spans(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        out.push_str(&rest[..open]);
        out.push_str("CODESPAN");
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The keys this branch claims, by `claim keys`' one authority
/// ([`crate::race::claimed_from`]) over the branch, its authored log since
/// `base`, and the body.
///
/// **Empty where there is no branch**, which is `claim keys`' own fail-open: an
/// unresolvable claim subtracts nothing, so every owner a paragraph names stands.
fn claimed(root: &Path, base: &str, body: &str, grammar: &Grammar) -> Vec<String> {
    let Some(branch) = crate::git::current_branch(root).ok().flatten() else {
        return Vec::new();
    };
    let log = crate::race::authored_log(root, base);
    crate::race::claimed_from(&branch, "", &log, body, grammar, crate::race::Source::All)
}

/// `deferral`: each pull-request-body paragraph using a declared deferral shape,
/// with the keys it names and the keys the pull request claims (CLOUD-323,
/// CLOUD-338).
///
/// Record: `claimed\t<keys|->`, then `deferral\t<paragraph>\t<keys|->` per hit,
/// closed by `census\tdeferrals=<n>` — the paragraph's NUMBER and its keys,
/// never its prose (rule 4). An empty body is a clean record, not an error: the
/// retired program passed it.
///
/// Inputs: `shape`, the `[[pattern]]` row naming the deferral phrases, and
/// `base`, the trunk the authored log is read against.
fn deferral(
    inputs: &BTreeMap<String, String>,
    patterns: &[NamedPattern],
    root: &Path,
    stdin: &str,
) -> Result<String> {
    const FAMILY: &str = "deferral";
    only(inputs, FAMILY, &["shape", "base"])?;
    let shape = declared(patterns, FAMILY, required(inputs, FAMILY, "shape")?)?;
    let base = required(inputs, FAMILY, "base")?;
    let grammar = Grammar::resolve(patterns)?;
    let mut record = String::new();
    writeln!(
        record,
        "claimed\t{}",
        column(&claimed(root, base, stdin, &grammar))
    )?;
    let mut counted = 0usize;
    for (index, paragraph) in paragraphs(stdin).iter().enumerate() {
        if !shape.is_match(&without_code_spans(paragraph)) {
            continue;
        }
        let keys: Vec<String> = grammar
            .keys_in(paragraph)
            .into_iter()
            .map(|key| key.to_string())
            .collect();
        writeln!(record, "deferral\t{}\t{}", index + 1, column(&keys))?;
        counted += 1;
    }
    writeln!(record, "census\tdeferrals={counted}")?;
    Ok(record)
}

/// The keys a span names, case-folded first.
///
/// FOLDED, because a body writing the lowercase form still names the row, and
/// `claim keys` folds for the same reason: the consumer's key row is not obliged
/// to be case-insensitive.
fn named_in(grammar: &Grammar, text: &str) -> Vec<String> {
    grammar
        .keys_in(&text.to_uppercase())
        .into_iter()
        .map(|key| key.to_string())
        .collect()
}

/// The body lines the declared hold marker matches.
///
/// A loop rather than `filter` with a closure, so the `#MUTANT` row on
/// [`closing_key`] can name the match line: `mutate` splits a row on `|`.
fn marker_lines<'a>(hold: &Regex, body: &'a str) -> Vec<&'a str> {
    let mut marked = Vec::new();
    for line in body.lines() {
        if hold.is_match(line) {
            marked.push(line);
        }
    }
    marked
}

/// `closing-key`: the key sets a pull request body names and closes, the keys
/// its branch served, and any declared hold (CLOUD-192, CLOUD-674).
///
/// Record: `named`, `closing`, `served` and `hold` lines, each a key column; the
/// hold column is `none` without a marker line, `global` for a marker naming no
/// key, or the keys the marker lines name. Never a line of the body.
///
/// `closing` is the grammar's closing reading, `served` the first key of each
/// `Refs:` trailer the branch authored since `base` — source 3 alone, so the
/// subtraction is not circular. Inputs: `hold`, the `[[pattern]]` row naming the
/// line-anchored marker, and `base`. An empty body is could-not-look.
//MUTANT marker-anywhere-holds|s@^        if hold.is_match(line) {$@        if line.contains("DO-NOT-CLOSE") {@|the_marker_opts_out_only_when_used_not_when_mentioned
fn closing_key(
    inputs: &BTreeMap<String, String>,
    patterns: &[NamedPattern],
    root: &Path,
    stdin: &str,
) -> Result<String> {
    const FAMILY: &str = "closing-key";
    only(inputs, FAMILY, &["hold", "base"])?;
    let hold = declared(patterns, FAMILY, required(inputs, FAMILY, "hold")?)?;
    let base = required(inputs, FAMILY, "base")?;
    if stdin.trim().is_empty() {
        return Err(refuse(
            FAMILY,
            "stdin is empty; expected a pull request body",
        ));
    }
    let grammar = Grammar::resolve(patterns)?;
    let named = named_in(&grammar, stdin);
    let closing = by_ordinal(crate::race::claimed_from(
        "",
        "",
        "",
        stdin,
        &grammar,
        crate::race::Source::ClosingOnly,
    ));
    let served = match crate::git::current_branch(root).ok().flatten() {
        Some(branch) => by_ordinal(crate::race::claimed_from(
            &branch,
            "",
            &crate::race::authored_log(root, base),
            "",
            &grammar,
            crate::race::Source::RefsFirstOnly,
        )),
        None => Vec::new(),
    };
    let marked = marker_lines(&hold, stdin);
    let hold_column = if marked.is_empty() {
        String::from("none")
    } else {
        let keys = named_in(&grammar, &marked.join("\n"));
        if keys.is_empty() {
            String::from("global")
        } else {
            keys.join(" ")
        }
    };
    let mut record = String::new();
    writeln!(record, "named\t{}", column(&named))?;
    writeln!(record, "closing\t{}", column(&closing))?;
    writeln!(record, "served\t{}", column(&served))?;
    writeln!(record, "hold\t{hold_column}")?;
    Ok(record)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DEFAULT_WINDOW, by_ordinal, done_pr, duplicate_close, names, paragraphs, payloads,
        pull_number, without_code_spans,
    };

    use std::collections::BTreeMap;

    fn no_inputs() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn a_key_is_named_only_whole() {
        assert!(names("feat: work\n\nRefs: ACME-17\n", "ACME-17"));
        assert!(!names("Refs: ACME-179\n", "ACME-17"));
        assert!(!names("Refs: XACME-17\n", "ACME-17"));
        assert!(!names("Refs: pre-ACME-17\n", "ACME-17"));
        assert!(names("(ACME-17)", "ACME-17"));
        assert!(!names("anything", ""));
    }

    #[test]
    fn a_single_array_and_a_stream_are_the_same_set() {
        let array = payloads("t", r#"[{"id":"A-1"},{"id":"A-2"}]"#).unwrap();
        let stream = payloads("t", "{\"id\":\"A-1\"}\n{\"id\":\"A-2\"}\n").unwrap();
        assert_eq!(array, stream);
        assert!(payloads("t", "  \n").is_err());
        assert!(payloads("t", "not json").is_err());
    }

    #[test]
    fn paragraphs_split_on_blank_lines_and_join_their_lines() {
        let found = paragraphs("one\r\ntwo\n\n\n  \nthree\n");
        assert_eq!(found, vec!["one two".to_owned(), "three".to_owned()]);
        assert!(paragraphs("").is_empty());
    }

    #[test]
    fn a_code_span_is_neutralised_and_an_unmatched_backtick_is_not() {
        assert_eq!(without_code_spans("a `judgement call` b"), "a CODESPAN b");
        assert_eq!(without_code_spans("a ` b"), "a ` b");
    }

    #[test]
    fn a_pull_number_is_read_from_the_shared_spelling() {
        assert_eq!(pull_number("https://forge.example/o/r/pull/346"), Some(346));
        assert_eq!(pull_number("https://example.com/how-to-pull/123"), None);
        assert_eq!(pull_number("https://tracker.example/document/x"), None);
    }

    #[test]
    fn keys_order_numerically() {
        let ordered = by_ordinal(["A-10", "A-2", "A-2"].map(String::from));
        assert_eq!(ordered, vec!["A-2".to_owned(), "A-10".to_owned()]);
    }

    #[test]
    fn a_done_pr_record_names_a_draft_and_refuses_an_unread_pull() {
        let set = r#"[{"id":"A-1","attachments":[{"url":"https://f.example/o/r/pull/7"},{"url":"https://f.example/o/r/pull/7"}],"pulls":[{"number":7,"state":"open","draft":true}]}]"#;
        let record = done_pr(&no_inputs(), set).unwrap();
        assert_eq!(
            record,
            "issue\tA-1\t1\npull\tA-1\t7\tdraft\ncensus\tissues=1\n"
        );
        let unread = r#"[{"id":"A-1","attachments":[{"url":"https://f.example/o/r/pull/7"}]}]"#;
        assert!(done_pr(&no_inputs(), unread).is_err());
    }

    #[test]
    fn a_duplicate_close_record_truncates_both_stamps_to_the_window() {
        let set = r#"[
            {"id":"A-777","canceledAt":null,"completedAt":"2026-08-21T02:37:51.492Z","relations":{"duplicateOf":null}},
            {"id":"A-817","canceledAt":"2026-08-21T02:37:51.492Z","completedAt":null,"relations":{"duplicateOf":{"id":"A-777"}}}
        ]"#;
        let record = duplicate_close(&no_inputs(), set).unwrap();
        assert_eq!(
            record,
            "dup\tA-817\t2026-08-21T02:37:51\tA-777\t2026-08-21T02:37:51\ncensus\tduplicates=1\n"
        );
        assert_eq!(DEFAULT_WINDOW, "2026-08-21T02:37:51".len());
        let unkeyed = r#"[{"id":"A-1","relations":{"blockedBy":[]}}]"#;
        assert!(duplicate_close(&no_inputs(), unkeyed).is_err());
    }

    #[test]
    fn a_duplicate_close_window_input_narrows_the_stamps_and_refuses_a_non_number() {
        let set = r#"[
            {"id":"A-777","canceledAt":null,"completedAt":"2026-08-21T02:37:52.000Z","relations":{"duplicateOf":null}},
            {"id":"A-817","canceledAt":"2026-08-21T02:37:51.492Z","completedAt":null,"relations":{"duplicateOf":{"id":"A-777"}}}
        ]"#;
        let minute = BTreeMap::from([("window".to_owned(), "16".to_owned())]);
        assert_eq!(
            duplicate_close(&minute, set).unwrap(),
            "dup\tA-817\t2026-08-21T02:37\tA-777\t2026-08-21T02:37\ncensus\tduplicates=1\n"
        );
        let word = BTreeMap::from([("window".to_owned(), "sixty".to_owned())]);
        assert!(duplicate_close(&word, set).is_err());
    }
}
