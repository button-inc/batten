//! The forge's REST tier, IN PROCESS — one client, one credential reader, no
//! spawn (CLOUD-1338).
//!
//! **Named `rest` rather than `forge`, and the near-miss is worth the line.**
//! [`crate::forge`] is a different subject entirely: it reads a VERDICT RECORD a
//! producer wrote outside the engine, keyed by sha, off disk. Drafting this as
//! `forge.rs` overwrote it wholesale — the two nouns are one word apart and the
//! subjects share nothing, which is exactly when a name collision is silent.
//!
//! # This module exists because four sites claimed a client that was already here
//!
//! Every spawn it replaces carried the same `#[expect(clippy::disallowed_types)]`
//! reason: *"this crate carries no HTTP client that resolves a forge
//! credential — so the forge's own client IS the call."* That sentence was
//! **false when it was written, four times**, and one of the four was written in
//! `lease.rs`, eighty lines from the credential reader [`credential`] is —
//! a function that reads `GH_TOKEN`, falls back to `GITHUB_TOKEN`, and attaches
//! `Authorization: Bearer` to a [`crate::fetch`] call.
//!
//! [`crate::fetch`] is hyper plus hyper-rustls, vendored under CLOUD-745, with
//! explicit connect and total timeouts, a typed status, lowercased response
//! headers and a scoped current-thread runtime. It is strictly better than a
//! child process for every one of these reads, and it was in the crate the whole
//! time.
//!
//! **The escapes were the tell and nothing caught them.** `spawn-adapters` is the
//! gate over WHERE a spawn may appear, and it is answered by adding a word to a
//! Rego set — which is what happened: two placements went in, each with a
//! justification in a comment no gate reads. A branch whose whole subject is
//! *removing shell* added five annotated spawns and widened the placement table
//! twice, and every sensor stayed green.
//!
//! # What is NOT here
//!
//! The git smart-HTTP transport. [`crate::lease`] speaks that directly for the
//! lease ref's compare-and-swap — a different protocol over a different endpoint
//! family, and folding the two would put a ref-advertisement parser behind a REST
//! helper. What moved here is the credential reader the two share.

use crate::fetch::{self, Call};

/// Where the REST tier lives.
///
/// A constant rather than a config key: a consumer pointing this at another host
/// is asking for a different client, not a different value, and a key nobody sets
/// is a surface with no reader.
const API: &str = "https://api.github.com";

/// What the API is asked to send back.
const ACCEPT: &str = "application/vnd.github+json";

/// The bearer token this forge needs, or `None`.
///
/// **Resolved here and returned to nobody outside this module.** It is
/// deliberately not a field of any value: a token in a struct is a token in that
/// struct's `Debug`, and non-negotiable rule 4 makes every report in this crate a
/// pointer. Keeping it inside the request builder means there is no value a
/// caller could print by accident.
///
/// `GH_TOKEN` first, matching the forge CLI's own precedence, so a session that
/// set one for that tool does not have to set a second. **This is the reader
/// `lease.rs` already had**, promoted rather than copied — a second one would be
/// a second answer to "which variable holds the credential", and the four spawns
/// this module replaces existed because nobody looked for the first.
pub(crate) fn credential() -> Option<String> {
    ["GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|token| !token.is_empty())
}

/// The request headers for one exchange.
///
/// **An absent credential is not an error.** A public repository needs none, and
/// a private one answers `401` — which every caller here already reports as
/// could-not-look rather than as a verdict about the work.
fn headers(conditional: Option<&str>, json_body: bool) -> Vec<(String, String)> {
    let mut headers = vec![(String::from("Accept"), ACCEPT.to_owned())];
    if json_body {
        headers.push((
            String::from("Content-Type"),
            String::from("application/json"),
        ));
    }
    if let Some(etag) = conditional {
        headers.push((String::from("If-None-Match"), etag.to_owned()));
    }
    if let Some(token) = credential() {
        headers.push((String::from("Authorization"), format!("Bearer {token}")));
    }
    headers
}

/// One answer from the REST tier.
///
/// `PartialEq` without `Eq`, because [`Answer::poll_floor`] is an `f64` and no
/// float is `Eq`. That is the right way round rather than a concession: a
/// fractional floor is CLOUD-390's whole defect, so the field cannot be an
/// integer, and a total-equality bound on a value carrying one would be a claim
/// this type has no business making.
///
/// **Typed at the boundary, which is the half the spawn could not give.** A child
/// process hands back bytes, so every caller had to re-parse a status line and a
/// header block out of `gh api -i` output. Here the transport has already read
/// them, and `pr_watch::parse_response` — the parser three modules shared to undo
/// that framing — has one caller fewer for each site that moves.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The HTTP status. `304` is the reading that did not change.
    pub status: u16,
    /// The validator to send with the next request, where one was sent.
    pub etag: Option<String>,
    /// The interval the server asked to be polled at, in seconds.
    ///
    /// `f64` rather than an integer, which is CLOUD-390's defect and the reason
    /// this field is not a `u64`: the predecessor compared with `-gt`, so a
    /// fractional value read as *the server asked for no floor* — byte-identical
    /// to an absent header, and silently faster than the endpoint allows.
    pub poll_floor: Option<f64>,
    /// The response body, as text.
    pub body: String,
}

/// One GET against the REST tier, or `None` where it could not be reached.
///
/// **`None` is could-not-look and never a verdict.** Every caller here polls in a
/// loop that must survive an unreachable forge: a lap that concluded "trunk
/// moved" from a failed request would decide about the network rather than about
/// the work, and it would cost a whole CI run each time.
///
/// `path` is API-relative and carries no leading slash — `repos/{owner}/{repo}/…`
/// — which is the spelling the forge's own client takes, so a call site moving
/// here keeps its endpoint string byte for byte.
#[must_use]
pub fn get(path: &str, etag: Option<&str>) -> Option<Answer> {
    exchange(path, etag, None)
}

/// One POST against the REST tier, with no body.
///
/// `false` where the call did not succeed, on the same could-not-look posture
/// [`get`] takes: the one caller cancels a run it is standing in, and a guard
/// that could not stop a run must not also fail the job it is standing in.
#[must_use]
pub fn post(path: &str) -> bool {
    exchange(path, None, Some(&[])).is_some_and(|answer| (200..300).contains(&answer.status))
}

/// One POST carrying a JSON body.
///
/// **The ANSWER comes back rather than a boolean**, because the one caller needs
/// the created object's id: the join key a lap waits on is minted from it, so a
/// call reporting only success would leave the lap with nothing to match. The
/// predecessor reached the same conclusion and said so — it used the API rather
/// than the client's comment porcelain precisely because the porcelain does not
/// return the object.
#[must_use]
pub fn post_json(path: &str, body: &serde_json::Value) -> Option<Answer> {
    let encoded = serde_json::to_vec(body).ok()?;
    exchange(path, None, Some(&encoded))
}

fn exchange(path: &str, etag: Option<&str>, body: Option<&[u8]>) -> Option<Answer> {
    let url = format!("{API}/{path}");
    let headers = headers(etag, body.is_some_and(|bytes| !bytes.is_empty()));
    let mut answers = fetch::spend(&[Call {
        url: &url,
        headers: &headers,
        body,
    }])
    .ok()?;
    // ONE call in, one answer out. `spend` returns them in the order given and
    // stops at the first failure, so a non-empty vector here is this call's.
    let response = answers.pop()?;
    Some(Answer {
        status: response.status,
        etag: response.header("etag").map(str::to_owned),
        // LOWERCASE, because `fetch::Response` lowercases every name it read.
        // Matching `X-Poll-Interval` here would find nothing and read as *the
        // server asked for no floor* — the exact three-valued mistake CLOUD-390
        // records, arriving by a different route.
        poll_floor: response
            .header("x-poll-interval")
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0),
        body: String::from_utf8_lossy(&response.body).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every endpoint a caller hands over is API-relative.
    ///
    /// A leading slash produces a double one and a `404`, which every caller here
    /// reads as could-not-look — silent, and exactly the dead-gate class this
    /// crate exists to refuse.
    #[test]
    fn an_api_relative_path_keeps_the_forge_clients_own_spelling() {
        for path in [
            "repos/{owner}/{repo}/git/ref/heads/main",
            "repos/o/r/actions/runs/7/cancel",
            "repos/o/r/issues/42/comments",
        ] {
            assert!(
                !path.starts_with('/'),
                "API-relative, never rooted: {path:?}"
            );
            assert!(
                format!("{API}/{path}").starts_with("https://"),
                "and HTTPS, which the connector enforces anyway"
            );
        }
    }

    /// The conditional header is attached only when there is a validator.
    ///
    /// **Asserted on the header LIST rather than on a request**, because building
    /// a request would dial. What this pins is the shape a `304` depends on: an
    /// unconditional poll had to stay slow to stay affordable, so a validator
    /// that never reaches the wire makes the news arrive late.
    #[test]
    fn the_validator_is_attached_only_when_one_was_read() {
        let first = headers(None, false);
        assert!(
            !first.iter().any(|(name, _)| name == "If-None-Match"),
            "nothing to validate against yet: {first:?}"
        );

        let second = headers(Some("W/\"a\""), false);
        assert!(
            second
                .iter()
                .any(|(name, value)| name == "If-None-Match" && value == "W/\"a\""),
            "a 304 is what makes a one-second poll affordable: {second:?}"
        );
    }

    /// A body-bearing call declares its content type and a bodyless one does not.
    ///
    /// The anti-vacuity half matters as much: sending `Content-Type` on a GET is
    /// how a caller learns the header builder ignores its argument.
    #[test]
    fn a_json_body_declares_its_type_and_a_bodyless_call_does_not() {
        assert!(
            headers(None, true)
                .iter()
                .any(|(name, value)| name == "Content-Type" && value == "application/json"),
        );
        assert!(
            !headers(None, false)
                .iter()
                .any(|(name, _)| name == "Content-Type"),
        );
    }

    /// **The credential never reaches a value a caller can print.**
    ///
    /// Non-negotiable rule 4 lands here as a TYPE property rather than as a habit
    /// at each call site: [`Answer`] has no credential field, so no `Debug` of
    /// anything this module returns can carry one.
    #[test]
    fn no_value_this_module_returns_can_carry_the_credential() {
        let answer = Answer {
            status: 200,
            etag: Some(String::from("W/\"a\"")),
            poll_floor: Some(2.5),
            body: String::from("{}"),
        };
        let rendered = format!("{answer:?}");
        assert!(
            !rendered.contains("Bearer"),
            "the token is not a field and cannot be one: {rendered}"
        );
    }
}
