//! What the lap actually ASKS the forge, over the compiled binary (CLOUD-1338).
//!
//! # Why this tier exists rather than another `with input as` case
//!
//! Every read in the landing family used to be a spawn of the forge's own client,
//! and that client performed two substitutions on the caller's behalf before the
//! request left the process: it expanded `{owner}/{repo}` from the checkout, and
//! it was the only thing that ever saw the endpoint string. Moving those reads
//! in-process (`crate::rest`) inherits neither for free — and a request that goes
//! out malformed comes back as a `404`, which every caller here is written to read
//! as *could not look* and therefore to survive quietly.
//!
//! That is the class this file drives: a defect visible ONLY in the bytes of the
//! request, invisible to any test that constructs the answer. `rest`'s fixture
//! seam records each URL to `args`, so the request is the assertion.
//!
//! Both cases below were live in this branch when it was written, and both were
//! green under every other tier in the crate.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The repository a case names. Two segments, and deliberately not this
/// repository's own: a placeholder that leaked through would be a literal
/// `{owner}` rather than a plausible-looking slug.
const REPO: &str = "acme/widgets";

/// An empty pull-request list, in the response shape the fixture reads.
const NO_PULL_REQUESTS: &str = "HTTP/2 200\ncontent-type: application/json\n\n[]\n";

/// A repository on a branch, with the fixture wired and one canned answer.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::init_repo(&dir);
    common::git_in(&dir, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(dir.join("resp.last"), NO_PULL_REQUESTS).expect("write the canned answer");
    dir
}

/// Everything the fixture recorded about the requests that went out.
fn requests(dir: &std::path::Path) -> String {
    std::fs::read_to_string(dir.join("args")).unwrap_or_default()
}

/// Run `batten land fast-forward` against the fixture.
fn fast_forward(dir: &std::path::Path) -> std::process::Output {
    common::batten()
        .arg("land")
        .arg("fast-forward")
        .env("GH_REPO", REPO)
        .env("LAND_WORKFLOW", "land.yml")
        .env("BATTEN_REST_FIXTURE", dir)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// **THE LOOKUP ASKS ABOUT THE CONFIGURED REPOSITORY, NOT ABOUT A PLACEHOLDER.**
///
/// `pr_watch::REPO_PLACEHOLDER` is the literal `{owner}/{repo}` — the FORGE
/// CLIENT's substitution, performed in the process that no longer runs. This step
/// sent it as the path, so the forge answered `404`, `open_pull_request` answered
/// `None`, and every `land fast-forward` — the lap's commit point included —
/// stopped with *"no open pull request"*. It is the one site in the family that
/// did not read `GH_REPO`; the assertion is over the bytes that went out, because
/// the exit code is identical either way.
#[test]
fn the_fast_forward_lookup_names_the_configured_repository() {
    let dir = fixture("land-forge-reads-repo");
    let _ = fast_forward(&dir);

    let asked = requests(&dir);
    assert!(
        asked.contains(&format!("repos/{REPO}/pulls")),
        "the lookup should name the configured repository; it asked: {asked}"
    );
    // THE MIRROR, and it is what makes this discriminate: an assertion that only
    // looked for the slug would pass over a request that carried both, which is
    // exactly what a partial fix produces.
    assert!(
        !asked.contains("{owner}"),
        "the client's own substitution reached the endpoint: {asked}"
    );
}

/// **THE HEAD FILTER CARRIES THE OWNER, because the forge documents it as
/// `user:ref-name` and IGNORES anything else.**
///
/// An ignored filter is not an error: the endpoint answers with the newest open
/// pull request of ANY branch, so the lap can comment `/fast-forward` on — and
/// ready, and re-draft — a pull request that is not this branch's. The failure is
/// silent in both directions, which is why the request is the subject here.
#[test]
fn the_head_filter_is_owner_qualified_rather_than_a_bare_branch() {
    let dir = fixture("land-forge-reads-head");
    let _ = fast_forward(&dir);

    let asked = requests(&dir);
    let owner = REPO.split('/').next().expect("the slug has an owner");
    assert!(
        asked.contains(&format!("head={owner}:topic")),
        "the head filter should be owner-qualified; it asked: {asked}"
    );
    assert!(
        !asked.contains("head=topic"),
        "a bare branch is silently ignored by the forge: {asked}"
    );
}
