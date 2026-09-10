//! `forge::window`: one paginated read, and truncation is a verdict (CLOUD-1712).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! Nothing is retired by this tier yet: this row builds the primitive and the
//! seven retirements that consume it are separate rows. The arms land with them.
//!
//! # Why these cases and not a happy path
//!
//! The discriminating case is the one three shell programs got wrong. A window
//! that returns the rows it managed to read is green on every test a happy path
//! can write — the collection comes back, the rows parse, the reduction runs —
//! and it is wrong in exactly the way `timeout-drift` is wrong today. So the
//! anti-vacuity case (CLOUD-418) is `a_collection_larger_than_the_window_is_truncated`,
//! and its mirror asserts the same walk over a collection that FITS returns
//! `Whole`, because a `window` that answered `Truncated` unconditionally would
//! also pass the first.

use std::path::{Path, PathBuf};

use batten::forge::{Shape, Window};

/// A canned page: a status, an `ETag`, and a body.
#[derive(Clone)]
struct Page {
    status: u16,
    etag: Option<&'static str>,
    body: &'static str,
}

/// A transport that serves `pages` in order and records what it was asked.
///
/// Records the validator sent with each request, because the conditional read
/// IS the economy this layer exists to take — a walk that stopped sending
/// `If-None-Match` would still pass every row-count assertion here.
struct Canned {
    pages: Vec<Page>,
    calls: std::cell::RefCell<Vec<(String, Option<String>)>>,
}

impl Canned {
    fn new(pages: &[Page]) -> Self {
        Self {
            pages: pages.to_vec(),
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn answer(&self, path: &str, etag: Option<&str>) -> Option<batten::rest::Answer> {
        let mut calls = self.calls.borrow_mut();
        let page = self.pages.get(calls.len())?.clone();
        calls.push((path.to_owned(), etag.map(str::to_owned)));
        let mut headers = std::collections::BTreeMap::new();
        if let Some(validator) = page.etag {
            headers.insert(String::from("etag"), validator.to_owned());
        }
        Some(batten::rest::Answer {
            status: page.status,
            etag: page.etag.map(str::to_owned),
            poll_floor: None,
            backoff: None,
            body: page.body.to_owned(),
            headers,
        })
    }
}

/// A scratch git directory for the validator store.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-forge-window-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("git dir");
    dir
}

/// Run one walk over canned pages.
fn windowed(git_dir: &Path, canned: &Canned, path: &str, shape: Shape, max_pages: u32) -> Window {
    batten::forge::window_over(
        git_dir,
        path,
        &[("per_page", "2")],
        shape,
        max_pages,
        &|path, etag| canned.answer(path, etag),
    )
}

#[test]
fn a_collection_larger_than_the_window_is_truncated() {
    // THE DISCRIMINATING CASE (CLOUD-418). `total_count` says four; the window
    // is one page of two. A reader that returned the two rows it read would be
    // indistinguishable from one that read the whole collection, which is
    // exactly `timeout-drift`'s defect: it trusts one unpaginated page and
    // reports a percentile over a prefix as a percentile over a population.
    let git = scratch("truncated");
    let canned = Canned::new(&[Page {
        status: 200,
        etag: Some("W/\"p1\""),
        body: r#"{"total_count": 4, "check_runs": [{"id": 1}, {"id": 2}]}"#,
    }]);
    let answer = windowed(
        &git,
        &canned,
        "repos/o/r/check-runs",
        Shape::Wrapped("check_runs"),
        1,
    );
    match answer {
        Window::Truncated { read, total, pages } => {
            assert_eq!(read, 2, "the truncation names how much it read");
            assert_eq!(total, Some(4), "and what the collection actually holds");
            assert_eq!(pages, 1, "and the budget it spent");
        }
        other => panic!("a window short of `total_count` must be Truncated, got {other:?}"),
    }
}

#[test]
fn a_collection_the_window_reaches_the_end_of_is_whole() {
    // THE ANTI-VACUITY MIRROR. Without it, a `window` that answered `Truncated`
    // unconditionally would pass the case above — so this is what makes that one
    // a discrimination rather than a restatement of the return type.
    let git = scratch("whole");
    let canned = Canned::new(&[
        Page {
            status: 200,
            etag: Some("W/\"p1\""),
            body: r#"{"total_count": 3, "check_runs": [{"id": 1}, {"id": 2}]}"#,
        },
        Page {
            status: 200,
            etag: Some("W/\"p2\""),
            body: r#"{"total_count": 3, "check_runs": [{"id": 3}]}"#,
        },
    ]);
    let answer = windowed(
        &git,
        &canned,
        "repos/o/r/check-runs",
        Shape::Wrapped("check_runs"),
        5,
    );
    match answer {
        Window::Whole(rows) => assert_eq!(rows.len(), 3, "every row, across both pages"),
        other => panic!("a walk that reached `total_count` must be Whole, got {other:?}"),
    }
}

#[test]
fn a_refusal_is_could_not_look_rather_than_an_empty_collection() {
    // A 403 carries an ERROR DOCUMENT, which parses to zero rows and is
    // byte-identical on the decision surface to a genuinely empty collection.
    // That is the false green `Answer::is_reading` records one layer down.
    let git = scratch("refused");
    let canned = Canned::new(&[Page {
        status: 403,
        etag: None,
        body: r#"{"message": "Resource not accessible"}"#,
    }]);
    let answer = windowed(
        &git,
        &canned,
        "repos/o/r/check-runs",
        Shape::Wrapped("check_runs"),
        3,
    );
    match answer {
        Window::CouldNotLook { endpoint, status } => {
            assert_eq!(status, Some(403));
            assert_eq!(
                endpoint, "repos/o/r/check-runs",
                "the pointer is the endpoint"
            );
            assert!(
                !endpoint.contains("Resource"),
                "rule 4: the forge's body never reaches the report"
            );
        }
        other => panic!("a 403 must be CouldNotLook, got {other:?}"),
    }
}

#[test]
fn a_cold_cache_fetches_and_a_304_reuses_the_stored_body() {
    // THE ECONOMY, in both directions. The first walk populates the validator
    // store; the second is answered `304` with no body, and must return the
    // SAME rows rather than an empty page. `land-divergence`'s hand-rolled
    // `conditional_get` returned failure on a 304 with no cached body for this
    // reason, and the store is what makes the hit possible at all.
    let git = scratch("conditional");
    let canned = Canned::new(&[
        Page {
            status: 200,
            etag: Some("W/\"v1\""),
            body: r#"{"total_count": 1, "check_runs": [{"id": 7}]}"#,
        },
        Page {
            status: 304,
            etag: Some("W/\"v1\""),
            body: "",
        },
    ]);
    let cold = windowed(
        &git,
        &canned,
        "repos/o/r/check-runs",
        Shape::Wrapped("check_runs"),
        2,
    );
    assert!(
        matches!(&cold, Window::Whole(rows) if rows.len() == 1),
        "{cold:?}"
    );

    let warm = windowed(
        &git,
        &canned,
        "repos/o/r/check-runs",
        Shape::Wrapped("check_runs"),
        2,
    );
    match warm {
        Window::Whole(rows) => assert_eq!(
            rows.len(),
            1,
            "a 304 must answer from the store, never as an empty page"
        ),
        other => panic!("a 304 with a stored body is a reading, got {other:?}"),
    }

    let sent = canned.calls.borrow();
    assert_eq!(sent.len(), 2, "one request per walk");
    assert_eq!(
        sent[0].1, None,
        "the cold walk holds no validator and must send none"
    );
    assert_eq!(
        sent[1].1.as_deref(),
        Some("W/\"v1\""),
        "the warm walk must send the stored validator, or the economy is not taken"
    );
}

#[test]
fn a_bare_array_endpoint_reads_without_a_wrapper_key() {
    // The other body shape. `pulls` answers with the array itself and states no
    // `total_count`, so the end of the collection is a short page — which is the
    // evidence `merged-pr-keys` had and `land-divergence` did not.
    let git = scratch("bare");
    let canned = Canned::new(&[Page {
        status: 200,
        etag: None,
        body: r#"[{"number": 1}]"#,
    }]);
    let answer = windowed(&git, &canned, "repos/o/r/pulls", Shape::Bare, 3);
    match answer {
        Window::Whole(rows) => assert_eq!(rows.len(), 1),
        other => panic!("a short bare page ends the collection, got {other:?}"),
    }
}

#[test]
fn a_full_last_page_with_no_total_is_truncated_rather_than_whole() {
    // NO `total_count` AND THE BUDGET SPENT is the ambiguous case, and it
    // resolves toward refusing. The collection may or may not continue; a reader
    // that guessed "whole" would report a prefix as a population precisely when
    // it has the least evidence. `merged-pr-keys` took the same direction
    // against its `--limit`.
    let git = scratch("bare-full");
    let canned = Canned::new(&[Page {
        status: 200,
        etag: None,
        body: r#"[{"number": 1}, {"number": 2}]"#,
    }]);
    let answer = windowed(&git, &canned, "repos/o/r/pulls", Shape::Bare, 1);
    match answer {
        Window::Truncated { read, total, pages } => {
            assert_eq!(read, 2);
            assert_eq!(total, None, "the endpoint states no count");
            assert_eq!(pages, 1);
        }
        other => panic!("a full page at the budget with no count is Truncated, got {other:?}"),
    }
}
