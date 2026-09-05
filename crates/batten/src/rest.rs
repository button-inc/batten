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
/// header block out of `gh api -i` output. `pr_watch` carried the parser three
/// modules shared to undo that framing; with the last spawn gone the transport
/// has already read them, and that second parser is **retired** rather than left
/// standing beside this one. Two readings of one status line is the disagreement
/// class, not a duplication to tidy up later.
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
    /// How long the forge asked the caller to back off for, in seconds.
    ///
    /// **A DIFFERENT HEADER ANSWERING A DIFFERENT QUESTION from
    /// [`Answer::poll_floor`]**, and conflating them is what made the
    /// predecessor's loop respond to being rate-limited by generating more of
    /// the request that had just been refused. `X-Poll-Interval` is *how often
    /// to ask*; this is *stop asking until*. A poll honouring only the first
    /// keeps its polite cadence straight into a secondary limit.
    ///
    /// Resolved from `Retry-After` where the forge states one, and otherwise
    /// from `X-RateLimit-Reset` — but only once `X-RateLimit-Remaining` is `0`,
    /// because a reset instant is always present and reading it as a backoff
    /// would pause on every successful call.
    pub backoff: Option<u64>,
    /// The response body, as text.
    pub body: String,
}

impl Answer {
    /// Whether this answer's body is a READING, rather than the forge declining.
    ///
    /// # `Some(Answer)` is not the same claim as *the forge answered the question*
    ///
    /// [`get`] answers `None` only where the exchange could not happen at all. A
    /// `401`, a `403`, a `404` or a `5xx` is a completed exchange carrying a
    /// refusal, so it arrives as `Some` — and its body is an error document
    /// rather than the collection a caller parses. A caller that reads the body
    /// without reading the status therefore gets an EMPTY parse, which is
    /// byte-identical on the decision surface to a genuinely empty collection.
    ///
    /// Measured on this crate (PR #848's review): the lap's ready step read the
    /// head's check-runs without this test, so a forge blip parsed as zero runs,
    /// `checks_green::decide` answered *unregistered*, `land::buys_a_matrix` read
    /// that as `Refire`, and the lap re-drafted and re-readied the pull request —
    /// cancelling the in-flight matrix the arm exists to protect.
    ///
    /// # `304` is deliberately NOT a reading
    ///
    /// A not-modified says *your cached copy still stands*, which is an answer
    /// only to a caller that HAS one. A one-shot read sends no validator and holds
    /// no cache, so treating it as a reading would report the empty cache as the
    /// forge's answer — the same defect one status along. A polling caller does
    /// not use this: [`crate::pr_watch::Poll::absorb`] keeps its own runs across a
    /// `304` precisely because it is the one that has something to keep.
    #[must_use]
    pub const fn is_reading(&self) -> bool {
        self.status == 200
    }
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

/// Where a SUITE may put canned responses instead of the forge.
///
/// **A test seam, and it is here because retiring a spawn retired a tier.** The
/// suites over `pr watch` and its siblings drove the engine by putting a stubbed
/// `gh` on `PATH`: the program was the seam, so a case could hand the poll a
/// `304`, a rate-limit header or a green body and count the calls. Moving the
/// read in-process removed that seam and left those cases with no way to answer,
/// so `pr watch`'s unbounded loop polled a forge it could not reach — measured at
/// 46 minutes on two cases before the run was killed.
///
/// The alternative was to leave the spawn, and that is the wrong trade: a
/// compiled-binary tier is what proves the ENGINE builds what the caller reads,
/// and losing it is exactly the class `.claude/rules/policy-modules.md` names.
/// So the seam moves to the boundary the read moved to.
///
/// **`LEASE_FROM_REF`'s standing, in the same words**: overridable only so the
/// suite can point it at a fixture. It is read once, here, at the one exchange
/// every verb in this module goes through — so there is no second route and
/// nothing a consumer gains by setting it except responses they wrote
/// themselves.
const FIXTURE: &str = "BATTEN_REST_FIXTURE";

/// Serve one response from the fixture directory, counting the call.
///
/// The protocol is the stubbed program's, conserved exactly so the cases that
/// read it back need no rewrite: `resp.<n>` for the n-th call and `resp.last`
/// once they run out, the count in `calls`, and the request appended to `args`.
fn from_fixture(dir: &std::path::Path, url: &str, etag: Option<&str>, now: u64) -> Option<Answer> {
    let calls = dir.join("calls");
    let n = std::fs::read_to_string(&calls)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(0)
        + 1;
    let _ = std::fs::write(&calls, format!("{n}\n"));
    if let Ok(mut args) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("args"))
    {
        use std::io::Write as _;
        // THE VALIDATOR IS PART OF THE REQUEST A CASE READS BACK. The stubbed
        // program recorded its whole argv, so `-H "If-None-Match: …"` was
        // visible and the 304 case asserts on it — the conditional poll IS the
        // economy, so a fixture that hid it would let the header go away
        // silently. Written in the client's own spelling, which is what keeps
        // that assertion's bytes unchanged.
        match etag {
            Some(etag) => {
                let _ = writeln!(args, "{url} -H If-None-Match: {etag}");
            }
            None => {
                let _ = writeln!(args, "{url}");
            }
        }
    }
    let raw = std::fs::read_to_string(dir.join(format!("resp.{n}")))
        .or_else(|_| std::fs::read_to_string(dir.join("resp.last")))
        .ok()?;
    Some(canned(&raw, now))
}

/// One `-i`-style response text, as an [`Answer`].
///
/// The fixtures are written in the shape the forge's own client printed, which
/// is what lets a case that predates this seam keep its bytes.
fn canned(raw: &str, now: u64) -> Answer {
    let clean = raw.replace('\r', "");
    let (head, body) = clean.split_once("\n\n").unwrap_or((clean.as_str(), ""));
    let mut lines = head.split('\n');
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let header = |name: &str| {
        lines.clone().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
        })
    };
    Answer {
        status,
        etag: header("etag"),
        poll_floor: header("x-poll-interval")
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0),
        backoff: backoff_of(header, now),
        body: body.to_owned(),
    }
}

fn exchange(path: &str, etag: Option<&str>, body: Option<&[u8]>) -> Option<Answer> {
    let now = crate::now_unix();
    let url = format!("{API}/{path}");
    if let Some(dir) = std::env::var_os(FIXTURE) {
        return from_fixture(std::path::Path::new(&dir), &url, etag, now);
    }
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
        backoff: backoff_from(&response, now),
        body: String::from_utf8_lossy(&response.body).into_owned(),
    })
}

/// The backoff a response asks for, in seconds, or `None`.
///
/// **`now` is the CALLER'S instant rather than a clock read here**, which is the
/// rule `.claude/rules/policy-modules.md` states for every other comparison in
/// this crate: the clock belongs to the boundary, so one exchange yields one
/// answer whoever asks and whenever they ask again.
fn backoff_from(response: &fetch::Response, now: u64) -> Option<u64> {
    backoff_of(|name| response.header(name).map(str::to_owned), now)
}

/// The backoff a response states, over a header accessor rather than a response.
///
/// **ONE READER FOR BOTH PATHS, and this module's header names the class the
/// split belonged to: two readings of one header block.** The fixture seam
/// parsed `Retry-After` alone, so a fixture stating the RATE-LIMIT headers
/// yielded `backoff: None` — and a case asserting rate-limit backoff passed
/// without exercising the behaviour, which is coverage that has stopped testing
/// the thing it names. Found in review.
fn backoff_of(header: impl Fn(&str) -> Option<String>, now: u64) -> Option<u64> {
    // `Retry-After` FIRST, because a forge that states one has stated it about
    // this exact refusal. The reset instant below is a property of the window.
    if let Some(seconds) = header("retry-after")
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
    {
        return Some(seconds);
    }
    // ONLY AT ZERO REMAINING. The reset instant rides every response, so reading
    // it unconditionally would back off after each successful call.
    if header("x-ratelimit-remaining").and_then(|raw| raw.trim().parse::<u64>().ok()) != Some(0) {
        return None;
    }
    header("x-ratelimit-reset")
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|reset| *reset > now)
        .map(|reset| reset - now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A REFUSAL IS AN ANSWER THAT ARRIVED, AND IT IS NOT A READING.**
    ///
    /// `get` answers `Some` for every completed exchange, so a `401`, a `403` and
    /// a `5xx` all reach a caller carrying an error document where a collection
    /// was expected. A caller reading the body alone parses that as EMPTY, which
    /// is indistinguishable from a genuinely empty collection — the defect
    /// measured on the lap's ready step, where it re-drafted a pull request over
    /// a forge blip.
    ///
    /// The `200` arm is what keeps this from being satisfied by a predicate that
    /// refuses everything, and the `304` arm pins the deliberate exclusion rather
    /// than leaving it to be re-argued: a one-shot read holds no cache, so
    /// not-modified answers a question it never asked.
    #[test]
    fn only_a_two_hundred_carries_a_reading() {
        let with = |status: u16| Answer {
            status,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: String::new(),
        };
        assert!(with(200).is_reading());
        for status in [304, 401, 403, 404, 422, 500, 502] {
            assert!(
                !with(status).is_reading(),
                "{status} is the forge declining, not a reading"
            );
        }
    }

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
            backoff: Some(60),
            body: String::from("{}"),
        };
        let rendered = format!("{answer:?}");
        assert!(
            !rendered.contains("Bearer"),
            "the token is not a field and cannot be one: {rendered}"
        );
    }

    fn answered(headers: &[(&str, &str)]) -> fetch::Response {
        fetch::Response {
            status: 200,
            body: Vec::new(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    /// **THE HEADER THE POLL FLOOR IS NOT.** `X-Poll-Interval` says how often to
    /// ask; `Retry-After` says stop asking. The predecessor's loop honoured only
    /// the first, so being rate-limited made it generate more of exactly the
    /// request that had just been refused.
    #[test]
    fn a_stated_retry_after_is_the_backoff_and_wins_over_the_reset() {
        let response = answered(&[
            ("retry-after", "45"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "9000"),
        ]);
        assert_eq!(
            backoff_from(&response, 1000),
            Some(45),
            "a forge stating one has stated it about THIS refusal"
        );
    }

    /// The reset instant answers only once the window is actually spent.
    ///
    /// **The anti-vacuity half is the load-bearing one**: the reset rides every
    /// response, so a reader that did not check `remaining` would back off after
    /// each successful call and turn a healthy poll into a stall.
    #[test]
    fn the_reset_answers_at_zero_remaining_and_never_otherwise() {
        let spent = answered(&[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1060"),
        ]);
        assert_eq!(backoff_from(&spent, 1000), Some(60));

        let healthy = answered(&[
            ("x-ratelimit-remaining", "4999"),
            ("x-ratelimit-reset", "1060"),
        ]);
        assert_eq!(
            backoff_from(&healthy, 1000),
            None,
            "a reset instant is not a backoff while requests remain"
        );
    }

    /// A response stating nothing asks for nothing, and a reset already past is
    /// not a wait.
    #[test]
    fn a_silent_response_and_a_lapsed_reset_both_ask_for_no_backoff() {
        assert_eq!(backoff_from(&answered(&[]), 1000), None);
        assert_eq!(
            backoff_from(
                &answered(&[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "900")]),
                1000
            ),
            None,
            "the window already reopened"
        );
    }
}
