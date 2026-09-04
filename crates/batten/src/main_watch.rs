//! The staleness half of a landing lap's wait: has `main` moved past the base
//! this branch was replayed onto?
//!
//! # Why this is a conditional forge read and not a ref advertisement
//!
//! The two questions a lap races are "is this SHA green" ([`crate::pr_watch`])
//! and "is this SHA still landable" (here). The moment `main` advances, the
//! branch stops being a direct descendant, the run in flight cannot be used, the
//! fast-forward bot will refuse, and every remaining second of that run is
//! billed. Waiting it out to be told what is already knowable is the expensive
//! way to learn nothing.
//!
//! **An earlier revision of `land::wait` answered this arm with
//! [`crate::lease::advertise`] instead, and the reasoning was wrong.** It ran:
//! `main-watch` polls conditionally only because it goes through the forge's
//! metered REST tier, a ref advertisement is neither metered nor a spawn,
//! therefore the conditional poll is a regression. Three things are wrong with
//! that.
//!
//! *Conditionality is not about the meter, it is about the PACE.* The whole
//! reason `ci-wait` and `main-watch` can poll every second is that an unchanged
//! reading answers `304` with no body — `.claude/rules/toolchain.md` states it
//! plainly: "an unconditional poll had to stay slow to stay affordable, so the
//! news arrived late". A ref advertisement has no `304`. It re-sends the whole
//! ref list every ask, so it must either stay slow — which is the late-news
//! failure — or be fast and wasteful.
//!
//! *A git advertisement carries no server-directed backoff.* `X-Poll-Interval`
//! is the endpoint saying how often it is willing to be asked. Ref discovery
//! offers nothing to honour, so the arm cannot be a good citizen even in
//! principle.
//!
//! *And the `ETag` conditionality of the green arm is not shared with this one.*
//! That was the load-bearing error: `pr_watch`'s conditional read is over
//! check-runs, and a staleness arm answered by ref discovery inherits none of it.
//! "Both properties already exist on the green arm" was a claim about a different
//! arm.
//!
//! # The endpoint
//!
//! `git/ref/heads/main` rather than `commits/main`, because the body is a single
//! ref object: the smallest response that answers the question. The predecessor
//! (`mise-tasks/main-watch.sh`) chose it for the same reason and says so.
//!
//! # What this module does NOT do
//!
//! It never writes, and it holds no loop. The loop is the lap's — see
//! [`crate::land::wait`] — because a module with its own unbounded loop cannot be
//! raced without becoming a second authority over when to stop asking, which is
//! the mistake `pr_watch::read` was made public to avoid (CLOUD-1338).

use crate::pr_watch::interval_for;

/// What the staleness poll needs.
#[derive(Debug, Clone)]
pub struct Config {
    /// The repository, in whatever spelling the client resolves. Defaults to
    /// [`crate::pr_watch::REPO_PLACEHOLDER`].
    pub repo: String,
    /// The trunk ref's short name, as the endpoint path spells it.
    pub branch: String,
    /// The sha the branch was replayed onto — what "moved" is measured against.
    pub base: String,
    /// Seconds between polls, a FLOOR the server may raise and nothing may lower.
    pub interval: u64,
}

/// The request this poll makes, as argv.
///
/// Built rather than formatted at the call site so the endpoint and the
/// conditional header are one object a test can read — the same reason
/// [`crate::pr_watch::request`] is a function.
#[must_use]
pub fn request(config: &Config, etag: Option<&str>) -> Vec<String> {
    let mut args = vec![
        String::from("api"),
        String::from("-i"),
        format!("repos/{}/git/ref/heads/{}", config.repo, config.branch),
    ];
    if let Some(etag) = etag {
        args.push(String::from("-H"));
        args.push(format!("If-None-Match: {etag}"));
    }
    args
}

/// The sha a ref-object body names.
///
/// A body that will not parse yields `None` rather than an error, which is the
/// predecessor's posture: an unreadable reading is "no answer yet", so the lap
/// asks again instead of concluding from a response it never understood.
#[must_use]
pub fn head_from_body(body: &str) -> Option<String> {
    let document = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let sha = document.get("object")?.get("sha")?.as_str()?;
    (!sha.is_empty()).then(|| sha.to_owned())
}

/// One conditional read of the trunk ref.
///
/// **IN PROCESS, over [`crate::rest`].** This was a `gh` spawn, annotated
/// `#[expect(clippy::disallowed_types)]` with the reason *"this crate carries no
/// HTTP client that resolves a forge credential"* — which was false when it was
/// written: `fetch.rs` is a vendored hyper client and `lease.rs` was already
/// reading `GH_TOKEN` through it. The spawn bought nothing and cost three
/// things: a child process per poll, a `spawn-adapters` placement to admit it,
/// and a hand-rolled response parser to undo the framing.
///
/// `None` is could-not-look, never an error: every failure to reach the forge is
/// a reading the caller's own poll must survive. A lap that concluded "main
/// moved" from an unreachable forge would decide about the network rather than
/// about the work, at a cost of one CI run each time.
#[must_use]
pub fn read(config: &Config, etag: Option<&str>) -> Option<crate::rest::Answer> {
    crate::rest::get(
        &format!("repos/{}/git/ref/heads/{}", config.repo, config.branch),
        etag,
    )
}

/// The state one staleness poll carries into the next.
#[derive(Debug, Default)]
pub struct Poll {
    /// The validator to send with the next request.
    etag: Option<String>,
    /// The last sha a body named. A `304` leaves this alone.
    head: Option<String>,
    /// How many requests this poll has made.
    polls: u64,
}

impl Poll {
    /// Fold one answer in, returning how long to wait before the next request.
    ///
    /// A `304` is the server saying the ref is byte-identical to the last
    /// reading, so there is nothing to compare and the body is not parsed.
    ///
    /// **`None` is a poll that could not look**, and it is folded rather than
    /// skipped: the count still advances, the previous reading still stands, and
    /// the caller waits its configured interval. Dropping it would let an
    /// unreachable forge make a bounded loop unbounded.
    pub fn absorb(&mut self, answer: Option<&crate::rest::Answer>, configured: u64) -> f64 {
        self.polls += 1;
        let Some(answer) = answer else {
            return interval_for(configured, None);
        };
        // AN ETAG SURVIVES A RESPONSE THAT CARRIES NONE, which is what keeps a
        // single unvalidated answer from turning every later request
        // unconditional.
        if let Some(etag) = &answer.etag {
            self.etag = Some(etag.clone());
        }
        if answer.status != 304 {
            self.head = head_from_body(&answer.body);
        }
        interval_for(configured, answer.poll_floor)
    }

    /// The validator for the next request.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// The sha this poll currently holds, where it has read one.
    #[must_use]
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// How many requests have been made.
    #[must_use]
    pub const fn polls(&self) -> u64 {
        self.polls
    }

    /// Where the trunk has moved to, or `None` for "still landable".
    ///
    /// **A READING THAT IS NOT AN ANSWER IS NOT MOVEMENT.** No body read yet, an
    /// unparseable one, and a reading equal to the base all report `None` — the
    /// three of them deliberately indistinguishable to the lap, because each
    /// means the same thing to it: keep going. Reporting a could-not-look as
    /// movement would cost a whole CI run per unreachable forge.
    #[must_use]
    pub fn moved(&self, base: &str) -> Option<&str> {
        let head = self.head.as_deref()?;
        (head != base).then_some(head)
    }
}

#[cfg(test)]
// Panicking on a failed assertion is how a test fails loudly; these are the
// module's own cases, not a reachable path.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const MOVED: &str = "2222222222222222222222222222222222222222";

    fn config() -> Config {
        Config {
            repo: String::from(crate::pr_watch::REPO_PLACEHOLDER),
            branch: String::from("main"),
            base: String::from(BASE),
            interval: 1,
        }
    }

    fn ref_body(sha: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status: 200,
            etag: Some(String::from("W/\"a\"")),
            poll_floor: None,
            body: format!("{{\"object\":{{\"sha\":\"{sha}\"}}}}"),
        }
    }

    fn answer(status: u16, floor: Option<f64>, body: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status,
            etag: Some(String::from("W/\"a\"")),
            poll_floor: floor,
            body: body.to_owned(),
        }
    }

    /// **The discriminating pair: an unmoved trunk is not movement and a moved
    /// one is.**
    #[test]
    fn a_trunk_at_the_base_is_not_movement_and_one_past_it_is() {
        let mut poll = Poll::default();
        poll.absorb(Some(&ref_body(BASE)), 1);
        assert_eq!(poll.moved(BASE), None, "the base is where it was");

        let mut poll = Poll::default();
        poll.absorb(Some(&ref_body(MOVED)), 1);
        assert_eq!(
            poll.moved(BASE),
            Some(MOVED),
            "a different sha is the branch losing its descent"
        );
    }

    /// The request is conditional from the second ask, and the endpoint is the
    /// single ref object rather than the commit.
    #[test]
    fn the_second_request_carries_the_etag_the_first_was_given() {
        let config = config();
        let first = request(&config, None);
        assert!(
            !first.iter().any(|arg| arg.starts_with("If-None-Match")),
            "nothing to validate against yet: {first:?}"
        );
        assert!(
            first
                .iter()
                .any(|arg| arg == "repos/{owner}/{repo}/git/ref/heads/main"),
            "the smallest body that answers the question: {first:?}"
        );

        let mut poll = Poll::default();
        poll.absorb(Some(&ref_body(BASE)), 1);
        let second = request(&config, poll.etag());
        assert!(
            second.contains(&String::from("If-None-Match: W/\"a\"")),
            "a 304 is what makes a one-second poll affordable: {second:?}"
        );
    }

    /// A `304` leaves the reading alone, so an unchanged trunk costs no parse and
    /// reports no movement.
    #[test]
    fn a_not_modified_response_leaves_the_previous_reading_standing() {
        let mut poll = Poll::default();
        poll.absorb(Some(&ref_body(BASE)), 1);
        poll.absorb(Some(&answer(304, None, "")), 1);

        assert_eq!(poll.head(), Some(BASE), "the body was not re-read");
        assert_eq!(poll.moved(BASE), None);
        assert_eq!(poll.polls(), 2, "the loop turned twice");
    }

    /// **CLOUD-390, and it is why the floor is an `f64` at the boundary.**
    ///
    /// The predecessor compared with `-gt`, which is integer-only, so a
    /// fractional `X-Poll-Interval` read as "the server asked for no floor". The
    /// first Rust port reproduced it exactly: `poll_floor` was `Option<u64>` and
    /// `"0.5".parse()` yields `None`, byte-identical to an absent header. It is
    /// [`crate::rest::Answer`]'s field now, parsed once where the header is read
    /// rather than at each caller.
    #[test]
    fn a_fractional_server_floor_is_honoured_rather_than_silently_dropped() {
        let mut poll = Poll::default();
        let waited = poll.absorb(
            Some(&answer(200, Some(2.5), "{\"object\":{\"sha\":\"a\"}}")),
            1,
        );
        assert!(
            (waited - 2.5).abs() < f64::EPSILON,
            "the endpoint asked for 2.5s and is entitled to it, got {waited}"
        );

        // ANTI-VACUITY: the floor only ever raises. A server asking to be polled
        // FASTER than configured does not get to turn this into a spin.
        let mut poll = Poll::default();
        let waited = poll.absorb(
            Some(&answer(200, Some(0.1), "{\"object\":{\"sha\":\"a\"}}")),
            5,
        );
        assert!(
            (waited - 5.0).abs() < f64::EPSILON,
            "a floor is a floor, never an absolute: {waited}"
        );
    }

    /// Every failure to look reports "not moved", because the lap must survive it.
    ///
    /// **`None` is the shape a request that never completed now takes**, and it
    /// heads the list deliberately: with the read in process it is the only way a
    /// transport failure reaches here, where the spawn used to deliver it as
    /// empty bytes indistinguishable from a body.
    #[test]
    fn an_unreadable_answer_is_never_read_as_movement() {
        let unreadable: [Option<crate::rest::Answer>; 5] = [
            None,
            Some(answer(500, None, "")),
            Some(answer(200, None, "not json at all")),
            Some(answer(200, None, "{\"object\":{}}")),
            Some(answer(200, None, "{\"object\":{\"sha\":\"\"}}")),
        ];
        for raw in &unreadable {
            let mut poll = Poll::default();
            poll.absorb(raw.as_ref(), 1);
            assert_eq!(
                poll.moved(BASE),
                None,
                "a could-not-look would cost a whole CI run if read as movement: {raw:?}"
            );
        }
    }
}
