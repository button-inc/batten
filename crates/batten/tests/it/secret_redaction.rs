//! No credential-bearing value renders its credential.
//!
//! # Why this tier exists rather than a rule saying "don't print secrets"
//!
//! Non-negotiable rule 2: a rule without a runnable gate is half a change. The
//! rule here is already written, in `lease.rs`'s own words — *"a token in a
//! struct is a token in that struct's `Debug`, and non-negotiable rule 4 makes
//! every report here a pointer"* — and it was held by convention. Measured
//! 2026-09-06, the convention had failed three times by three different routes:
//!
//! | where | how it leaked |
//! | --- | --- |
//! | `provision::EnvAction::Set(String)` | a `pub` type deriving `Debug` over the launcher's resolved environment |
//! | `fetch::Call` | derived `Debug` over `headers`, which both callers fill with `Authorization: Bearer …` |
//! | `tests/it/provision.rs` | an assertion message interpolating a launcher's whole inherited environment — its panic printed a live session PAT |
//!
//! The third is the one that decides the SHAPE of this file. It was not found by
//! reading; it was found by the case going red and putting a credential in the
//! output. A gate that only inspects source would not have caught it either,
//! because the leak was in a format string that looked entirely ordinary.
//!
//! # The predicate: a canary, rendered every way the type can be rendered
//!
//! Each case builds the real value the engine builds, over a canary credential,
//! and asserts the canary appears in no rendering. That decides over an
//! OBJECT — the rendered string — with an exit code, which is what
//! non-negotiable rule 3 requires of a gate; "did the author think about
//! secrets" is not a thing a gate can ask.
//!
//! **Every case is shown able to fail** (CLOUD-418) by removing the hand-written
//! `Debug` and letting the derive back in — which is exactly the edit a future
//! author makes, so the case fails in the direction the defect arrives from.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::secret::{REDACTED, Secret};

/// Distinctive enough that finding it is proof rather than coincidence, and
/// DELIBERATELY NOT SHAPED LIKE A REAL CREDENTIAL.
///
/// It was `ghp_`-prefixed first, because a fixture standing in for a leaked PAT
/// reads better if it looks like one. `no-secrets` refused the tree for it and
/// was right to — a scanner that skipped a well-formed token because it sat in a
/// test file would have a hole in exactly the place this suite is about. The
/// shape buys nothing here: every assertion is over a rendering, and redaction
/// never reads the value. So the fixture changed and the gate did not.
const CANARY: &str = "CANARY-not-a-credential-CANARY-not-a-credential";

/// The substring every assertion looks for.
///
/// Deliberately a FRAGMENT rather than the whole canary: a rendering that
/// truncated, escaped or line-wrapped the value would still be a leak, and a
/// whole-string search would call it clean.
const FRAGMENT: &str = "not-a-credential";

/// THE PREMISE (CLOUD-249's shape). Every case below asserts an ABSENCE, and an
/// absence passes vacuously if the canary could never have appeared — a
/// misspelled fragment, a value that never reached the type. So one case
/// asserts the search itself works, over a rendering that genuinely carries it.
#[test]
fn the_search_would_find_a_leak() {
    let leaked = format!("{{ token: {CANARY} }}");
    assert!(
        leaked.contains(FRAGMENT),
        "the fragment must actually match a credential that IS rendered, or \
         every absence below is vacuous"
    );
}

#[test]
fn a_secret_renders_as_the_marker_alone() {
    let rendered = format!("{:?}", Secret::new(CANARY.to_owned()));
    assert_eq!(rendered, REDACTED);
    assert!(!rendered.contains(FRAGMENT));
}

/// The compositional property, over the type the leak was actually in. This is
/// what makes the fix survive an author who never reads `secret.rs`: they derive
/// `Debug` as usual and the credential still does not render.
#[test]
fn the_launcher_action_does_not_render_its_credential() {
    let action = batten::provision::EnvAction::Set(Secret::new(CANARY.to_owned()));
    let rendered = format!("{action:?}");
    assert!(
        !rendered.contains(FRAGMENT),
        "EnvAction::Set carried a String in a Debug-deriving pub type, which is \
         the defect this file exists for: {rendered}"
    );
    assert!(
        rendered.contains(REDACTED),
        "and it says a value was there rather than rendering nothing: {rendered}"
    );
}

/// A whole COLLECTION of them, which is the shape a caller actually holds:
/// `resolved_env` returns `Vec<(String, EnvAction)>`, and `{:?}` over the vector
/// is the single most likely accidental leak on this path.
#[test]
fn a_resolved_environment_does_not_render_its_credentials() {
    let resolved = vec![
        (
            "GITHUB_TOKEN".to_owned(),
            batten::provision::EnvAction::Set(Secret::new(CANARY.to_owned())),
        ),
        (
            "HTTPS_PROXY".to_owned(),
            batten::provision::EnvAction::Unset,
        ),
    ];
    let rendered = format!("{resolved:?}");
    assert!(!rendered.contains(FRAGMENT), "{rendered}");
    assert!(
        rendered.contains("GITHUB_TOKEN") && rendered.contains("HTTPS_PROXY"),
        "the NAMES still render — a report nobody can read gets switched off, \
         and rule 4 asks for a pointer rather than for silence: {rendered}"
    );
}

/// `fetch::Call`, over the header both real callers attach.
#[test]
fn a_request_does_not_render_its_authorization_header() {
    let headers = [("Authorization".to_owned(), format!("Bearer {CANARY}"))];
    let call = batten::fetch::Call {
        url: "https://api.github.com/rate_limit",
        headers: &headers,
        body: None,
        direct: true,
    };
    let rendered = format!("{call:?}");
    assert!(
        !rendered.contains(FRAGMENT),
        "`lease::headers` and `provision::probe_credential` both fill this \
         field with a bearer token: {rendered}"
    );
    assert!(
        rendered.contains("Authorization"),
        "the header's NAME is kept, so a report still says the request was \
         authenticated: {rendered}"
    );
    assert!(
        rendered.contains("api.github.com"),
        "and the rest of the request stays debuggable: {rendered}"
    );
}

/// Case-insensitively, because HTTP field names are and a caller writing
/// `authorization` in lower case is writing the same header.
#[test]
fn the_header_match_is_case_insensitive() {
    for spelling in ["authorization", "AUTHORIZATION", "AuThOrIzAtIoN"] {
        let headers = [((*spelling).to_owned(), format!("Bearer {CANARY}"))];
        let call = batten::fetch::Call {
            url: "https://example.invalid/",
            headers: &headers,
            body: None,
            direct: false,
        };
        let rendered = format!("{call:?}");
        assert!(
            !rendered.contains(FRAGMENT),
            "spelled {spelling}: {rendered}"
        );
    }
}

/// A body is a count, never bytes. A POST here is a git-protocol pack or an MCP
/// payload, and neither belongs in a report.
#[test]
fn a_request_body_renders_as_a_length() {
    let body = format!("secret-pack-{CANARY}").into_bytes();
    let call = batten::fetch::Call {
        url: "https://example.invalid/",
        headers: &[],
        body: Some(&body),
        direct: false,
    };
    let rendered = format!("{call:?}");
    assert!(!rendered.contains(FRAGMENT), "{rendered}");
    assert!(
        rendered.contains(&body.len().to_string()),
        "the length is the pointer at it: {rendered}"
    );
}
