//! The forge's verdict for a commit, read back from a record something else
//! wrote (CLOUD-1154).
//!
//! # The READING half opens no socket, and that is the whole design
//!
//! House style §5 forbids an HTTP client on the `check` surface and CLOUD-689's
//! ~100ms budget forbids one on the mediated path, so ~22 governed gates that
//! read the forge had no expressible successor. The answer is not to widen the
//! engine but to move WHO RESOLVES: the producer fetches once, outside — a
//! workflow step, an agent call — and writes a keyed record this reads back.
//!
//! # This module has TWO halves now, and the split is the §5 line itself
//!
//! **This heading used to read "the engine opens no socket", full stop, and
//! CLOUD-1712 makes that false for half the file** — so it is corrected rather
//! than left to read as a property the reader can rely on everywhere.
//!
//! * [`verdicts`], [`record_path`] and [`parse`] are the READER. No I/O beyond
//!   opening a file under the git directory, no clock, no network. This is what
//!   `check` reaches, it is `Cost::Read`, and the paragraph above is its
//!   contract in full.
//! * [`window`] is the PRODUCER's side. It fetches, over
//!   [`crate::rest`], and it exists because seven shell programs each
//!   reimplemented the same paginated read — two of them carrying a literal copy
//!   of one 45-line `conditional_get`.
//!
//! **The split is enforced by WHO CALLS, exactly as `record-verdicts` already
//! is.** `check` is `Cost::Read` and structurally cannot spawn or fetch; a
//! producer verb is `Effect::Write` and may. Nothing on the read path calls
//! [`window`], and a rule wanting windowed data reads the record a producer
//! wrote — which is the same seam, one collection wider. `evaluator-io-check` is
//! a different question and is untouched: it gates the Rego EVALUATOR reaching
//! `http.send`, which no part of this module changes.
//!
//! # Truncation is a verdict, never a short list
//!
//! The reason [`window`] returns [`Window::Truncated`] rather than the rows it
//! managed to read is measured rather than theoretical. Three programs
//! discovered the trap independently and guarded it three ways —
//! `merged-pr-keys` against its `--limit`, `land-divergence` against
//! `total_count`, and `timeout-drift` **not at all**, silently trusting one
//! unpaginated page. A caller handed a prefix cannot tell it from the whole
//! collection, so every reduction over it — a percentile, a max, an
//! is-there-any — answers about a window and reports about a population.
//!
//! That is exactly [`crate::facts::AGENT_SOURCED`]'s argument, moved from the
//! hook surface to the tree one: *the same answer that is `verify-only` when the
//! ENGINE would fetch it is not when something else already did.* The table is
//! about who resolves, never about what is known — the second axis earning
//! itself a third time. `evaluator-io-check` stays the gate on the engine
//! opening nothing.
//!
//! # Keyed by SHA, which is the safety property rather than a convenience
//!
//! A record taken against a different commit is not evidence about this one. A
//! family that merged every record into one listing would let a gate inherit a
//! green verdict from a commit nobody is asking about — which is worse than no
//! gate, because it reports a judgement that was never made. So the reading is
//! per declared SHA and a record under any other key is invisible.
//!
//! # Three answers, kept apart
//!
//! * **no record for a declared SHA** — absent from the map. Nothing has judged
//!   this commit yet.
//! * **a record holding no checks** — present, empty. The producer looked and
//!   the forge had nothing to say.
//! * **no store at all** — the whole fact is `None`, projected as `null`.
//!
//! Collapsing any pair reports green on a commit nothing ever judged, which is
//! CLOUD-845's dead gate on the surface that decides whether work lands.
//!
//! # Pointer-only, at the boundary
//!
//! A check's NAME and its CONCLUSION, both tokens. Never a check-run's body, its
//! annotations, or the log it points at — non-negotiable rule 4 is decided here
//! rather than at the report, because a check-run body is the likeliest place in
//! this whole surface for a secret to appear.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where a producer leaves its records, under the git directory.
///
/// Beside `receipt.rs`'s `batten-receipts` and the recorder's own store, for
/// their reason: it is per-checkout state that must never be committed, and the
/// git directory is the one place this crate already treats that way.
const DIRECTORY: &str = "batten-forge";

/// The record file for one commit.
#[must_use]
pub fn record_path(git_dir: &Path, sha: &str) -> PathBuf {
    git_dir.join(DIRECTORY).join(sha)
}

/// Read the forge's verdicts for each DECLARED sha.
///
/// A record is lines of `<check name> <conclusion>`, which is the shape a
/// producer can write with no serializer and a reader can parse with no schema —
/// the same reasoning `findings::pointer_lines` records one family over.
///
/// **A sha with no record is absent from the result**, never present with an
/// empty map: "nothing has judged this commit" and "the forge judged it and said
/// nothing" are different answers, and a landing gate acts on the second.
///
/// Unreadable records and malformed lines are skipped rather than fatal: one
/// torn record is not evidence about the others, and a whole family refused for
/// one bad line would take a gate offline for a producer's transient failure.
#[must_use]
pub fn verdicts(git_dir: &Path, declared: &[String]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    for sha in declared {
        let Ok(text) = std::fs::read_to_string(record_path(git_dir, sha)) else {
            // ABSENT, not empty. This is the arm the whole family turns on.
            continue;
        };
        found.insert(sha.clone(), parse(&text));
    }
    found
}

/// One keyed record's lines, as `name -> token`.
///
/// `pub(crate)` because [`crate::tools`] reads the same shape (CLOUD-1171): this
/// family and the tool-verdict one differ in their KEY and in nothing else, so
/// two parsers would be two authorities over one byte format that can disagree
/// about a torn line — the shape `rules/policy-modules.md` records for
/// patterns, one layer down.
///
/// Split on the FIRST whitespace run only: a conclusion is a token, and a name
/// that somehow carries a space would otherwise silently become two records.
/// A line with no conclusion is skipped — a name with no verdict is not a
/// verdict, and recording it as an empty string would let a predicate comparing
/// against `""` succeed.
pub(crate) fn parse(text: &str) -> BTreeMap<String, String> {
    let mut checks = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(conclusion)) = (parts.next(), parts.next()) else {
            continue;
        };
        checks.insert(name.to_owned(), conclusion.to_owned());
    }
    checks
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_record_for_another_sha_does_not_answer() {
        // THE ANTI-FORGERY CASE, and the property the whole family rests on: a
        // verdict taken against a different commit is not evidence about this
        // one. Without the per-sha key a gate could inherit a green reading from
        // a commit nobody asked about — a judgement that was never made,
        // reported as one that was.
        let dir = std::env::temp_dir().join("batten-forge-keying");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(record_path(&dir, "aaaa"), "final success\n").unwrap();

        let asked = verdicts(&dir, &[String::from("bbbb")]);
        assert!(
            !asked.contains_key("bbbb"),
            "a record keyed to another sha must not answer: {asked:?}"
        );

        let own = verdicts(&dir, &[String::from("aaaa")]);
        assert_eq!(
            own.get("aaaa").and_then(|checks| checks.get("final")),
            Some(&String::from("success")),
            "the sha's own record must answer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_record_is_not_an_empty_one() {
        // The two answers a landing gate must never confuse. `verdicts` leaves a
        // sha with no record ABSENT; a record that exists and holds no checks is
        // present and empty.
        let dir = std::env::temp_dir().join("batten-forge-absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(record_path(&dir, "empty"), "").unwrap();

        let found = verdicts(&dir, &[String::from("empty"), String::from("missing")]);
        assert_eq!(
            found.get("empty").map(BTreeMap::len),
            Some(0),
            "a record that exists and holds nothing is present and empty"
        );
        assert!(
            !found.contains_key("missing"),
            "a sha with no record is absent, never an empty map"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_with_no_conclusion_is_not_a_verdict() {
        // Recording it as an empty string would let a predicate comparing against
        // `""` succeed, which is a verdict nobody wrote.
        let checks = parse("final success\nlonely\n  \nother failure\n");
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert!(!checks.contains_key("lonely"), "{checks:?}");
    }
}

// --- the producer's half: one windowed read, and truncation is a verdict -----
//
// CLOUD-1712. Everything below fetches; nothing above it does. The module header
// states why that line is where it is.

/// Where the conditional-read validators live, under the git directory.
///
/// Beside [`DIRECTORY`] and for its reason: per-checkout state that must never be
/// committed. `land-divergence` hand-rolled this under
/// `.git/batten-divergence`, keyed by a hash of the URL; the key is the same
/// idea, spelled once.
const VALIDATORS: &str = "batten-forge-validators";

/// How a collection's rows are carried in the response body.
///
/// **Named by the caller rather than sniffed**, and that is deliberate. The
/// forge answers some endpoints with a bare array and others with an object
/// wrapping a named array beside a `total_count`. A reader that guessed — "the
/// one field that is an array" — would be one schema change away from silently
/// reducing over the wrong field, and it could not tell an object with two
/// arrays from an object with one. The caller knows its endpoint; the guess only
/// moves the knowledge somewhere it cannot be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape<'a> {
    /// The body IS the array, e.g. `pulls`.
    Bare,
    /// The body is an object; the rows are under this key, e.g. `check_runs`.
    Wrapped(&'a str),
}

/// What one windowed read found.
///
/// Three answers rather than two, on this module's own three-valued discipline:
/// a whole collection, a collection the window could not reach the end of, and
/// a forge that could not be asked. Collapsing the last two would report a
/// network failure as a truncation; collapsing the first two is the defect the
/// type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Window {
    /// Every row the collection holds. The walk reached the end.
    Whole(Vec<serde_json::Value>),
    /// The window ended before the collection did.
    ///
    /// **Carries what it could not see, because a truncation that cannot say
    /// how much it missed is only marginally better than a silent one.** `read`
    /// is how many rows were collected; `total` is the forge's own count where
    /// the endpoint states one, and `None` where it does not — in which case the
    /// evidence is that the last page came back full at the page budget.
    Truncated {
        /// Rows collected before the window ran out.
        read: usize,
        /// The collection's own size, where the endpoint reports it.
        total: Option<usize>,
        /// Pages actually fetched — the budget that was spent.
        pages: u32,
    },
    /// The forge could not be asked, or answered something unparseable.
    ///
    /// **Could-not-look, never an empty collection.** `rest::get` returns `None`
    /// only where the exchange did not happen, but a completed exchange carrying
    /// a `403` has an error document for a body — which parses to zero rows and
    /// is byte-identical, on the decision surface, to a genuinely empty
    /// collection. That is the defect `Answer::is_reading` records one layer
    /// down, and this arm is where it is refused here.
    ///
    /// The payload is a POINTER — the endpoint and a status — never a body.
    /// Rule 4 is decided here rather than at the report, for this module's own
    /// stated reason: a forge error document is a likely place for a secret.
    CouldNotLook {
        /// The endpoint asked about, without its query string.
        endpoint: String,
        /// The status the forge answered with, where it answered at all.
        status: Option<u16>,
    },
}

/// How a window reaches the forge.
///
/// **A parameter rather than a hard call to [`crate::rest::get`], and the reason
/// is testability rather than abstraction for its own sake.** The transport's
/// own test seam is the `BATTEN_REST_FIXTURE` environment variable, which a
/// suite in this process cannot set: `std::env::set_var` is `unsafe` under this
/// edition and this crate forbids `unsafe` outright, and the established way
/// round that is to run the compiled binary as a subprocess — which needs a CLI
/// leaf this row deliberately does not add (the retirements bring their own).
///
/// So the seam moves up one level, where it is an ordinary argument. A case
/// supplies canned pages and drives the REAL walk: the same pagination, the same
/// `total_count` arithmetic, the same validator store on disk. Only the socket
/// is stubbed, which is the only part a fixture was ever stubbing.
pub type Transport<'a> = &'a dyn Fn(&str, Option<&str>) -> Option<crate::rest::Answer>;

/// The validator store's path for one URL.
///
/// Keyed by a digest of the whole URL, query string included, because two pages
/// of one collection are two different readings and a key that collapsed them
/// would serve page 1's body for page 2.
fn validator_path(git_dir: &Path, url: &str) -> PathBuf {
    git_dir
        .join(VALIDATORS)
        .join(crate::tools::digest(url.as_bytes()))
}

/// One conditional GET, answering from the store on a `304`.
///
/// Returns the body and the status. A `304` is answered from the cached body and
/// reported as `200`, because to this caller they are the same reading — which
/// is the whole point of sending the validator.
///
/// **A `304` with no cached body is could-not-look, not an empty one.** The
/// store can be pruned between runs while the forge still holds the validator,
/// and reading that as an empty page would end the walk one page early and
/// report the prefix as whole. `land-divergence`'s own `conditional_get`
/// returned failure here for the same reason.
fn conditional_get(git_dir: &Path, path: &str, fetch: Transport<'_>) -> Option<(u16, String)> {
    let stored = validator_path(git_dir, path);
    let etag = std::fs::read_to_string(stored.join("etag")).ok();
    let answer = fetch(path, etag.as_deref().map(str::trim))?;

    if answer.status == 304 {
        let cached = std::fs::read_to_string(stored.join("body")).ok()?;
        return Some((200, cached));
    }
    if !answer.is_reading() {
        return Some((answer.status, String::new()));
    }
    // PERSIST BEFORE ANSWERING, and a failure to persist is not a failure to
    // read: the store is an optimisation, so a read-only git directory costs a
    // conditional request next time rather than the answer this time.
    if let Some(validator) = answer.etag.as_deref() {
        if std::fs::create_dir_all(&stored).is_ok() {
            let _ = std::fs::write(stored.join("etag"), validator);
            let _ = std::fs::write(stored.join("body"), &answer.body);
        }
    }
    Some((answer.status, answer.body))
}

/// Read a paginated collection over a bounded window.
///
/// `path` is API-relative and carries no leading slash, exactly as
/// [`crate::rest::get`] takes it, and no `page` parameter — this appends one per
/// lap. `params` is the rest of the query string, already URL-safe.
///
/// # Why the shape is a parameter and the page budget is not optional
///
/// The signature CLOUD-1712 sketched was `window(endpoint, params, max_pages)`.
/// [`Shape`] is the fourth because the alternative is a guess the caller already
/// knows the answer to — its own doc argues that. `max_pages` has no default
/// because every caller that took one took a DIFFERENT one, and a shared default
/// would silently re-truncate the program with the widest window.
///
/// # Errors
///
/// Never returns an error type: the two failure readings are
/// [`Window::Truncated`] and [`Window::CouldNotLook`], which are answers rather
/// than faults. A caller that wants to refuse on either must say so; a caller
/// that pattern-matches only `Whole` gets a compile error rather than a prefix.
#[must_use]
pub fn window(
    git_dir: &Path,
    path: &str,
    params: &[(&str, &str)],
    shape: Shape,
    max_pages: u32,
) -> Window {
    window_over(git_dir, path, params, shape, max_pages, &|path, etag| {
        crate::rest::get(path, etag)
    })
}

/// [`window`], over a caller-supplied [`Transport`].
///
/// The whole of the walk lives here; [`window`] is this with the live transport
/// bound. See [`Transport`] for why the seam is an argument.
#[must_use]
pub fn window_over(
    git_dir: &Path,
    path: &str,
    params: &[(&str, &str)],
    shape: Shape,
    max_pages: u32,
    fetch: Transport<'_>,
) -> Window {
    // `git_dir` EXPLICITLY, as every other function in this module takes it.
    // Resolving it from the process's cwd would make the validator store depend
    // on where the caller happened to be standing, and would make this untestable
    // without a chdir — which is shared mutable state across a parallel suite.
    let query: String = params
        .iter()
        .map(|(key, value)| format!("&{key}={value}"))
        .collect();
    // THE PAGE SIZE IS THE END-OF-COLLECTION SIGNAL where the endpoint reports
    // no `total_count`: a page carrying fewer rows than were asked for is the
    // last one. Read off the caller's own `per_page` rather than assumed,
    // because the forge's default differs per endpoint — `timeout-drift`'s
    // unpaginated `/jobs` call silently takes 30 — and a wrong constant here
    // would end the walk early and report a prefix as whole.
    let page_size = params
        .iter()
        .find(|(key, _)| *key == "per_page")
        .and_then(|(_, value)| value.parse::<usize>().ok());

    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut total: Option<usize> = None;
    let mut pages = 0_u32;
    let mut ended = false;

    while pages < max_pages {
        let page = pages + 1;
        let url = format!("{path}?page={page}{query}");
        let Some((status, body)) = conditional_get(git_dir, &url, fetch) else {
            return Window::CouldNotLook {
                endpoint: path.to_owned(),
                status: None,
            };
        };
        if status != 200 {
            return Window::CouldNotLook {
                endpoint: path.to_owned(),
                status: Some(status),
            };
        }
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
            // UNPARSEABLE IS COULD-NOT-LOOK. A body that is not JSON is not an
            // empty collection, and `serde_json`'s error carries a fragment of
            // the input, so it is dropped rather than reported (rule 4).
            return Window::CouldNotLook {
                endpoint: path.to_owned(),
                status: Some(status),
            };
        };
        let batch = match shape {
            Shape::Bare => parsed.as_array().cloned(),
            Shape::Wrapped(key) => {
                if let Some(count) = parsed
                    .get("total_count")
                    .and_then(serde_json::Value::as_u64)
                {
                    total = Some(usize::try_from(count).unwrap_or(usize::MAX));
                }
                parsed.get(key).and_then(|rows| rows.as_array()).cloned()
            }
        };
        let Some(batch) = batch else {
            return Window::CouldNotLook {
                endpoint: path.to_owned(),
                status: Some(status),
            };
        };
        pages = page;
        // A SHORT OR EMPTY PAGE ENDS THE COLLECTION, which is the same evidence
        // `land-divergence` recorded measuring its own window: page 10 came back
        // full and page 11 empty. Empty alone is not enough — a walk that only
        // stopped on an empty page would spend one request past every collection
        // whose size divides evenly, and against a fixture or a rate limit that
        // extra request is the difference between an answer and could-not-look.
        let short = match page_size {
            Some(size) => batch.len() < size,
            None => batch.is_empty(),
        };
        rows.extend(batch);
        // `total_count` ends it too, and is checked FIRST where the endpoint
        // states one: it is the forge's own answer about the collection, where
        // a short page is an inference from the window.
        if total.is_some_and(|count| rows.len() >= count) || short {
            ended = true;
            break;
        }
    }

    let reached_the_end = match total {
        Some(count) => rows.len() >= count,
        None => ended,
    };
    if reached_the_end {
        Window::Whole(rows)
    } else {
        Window::Truncated {
            read: rows.len(),
            total,
            pages,
        }
    }
}
