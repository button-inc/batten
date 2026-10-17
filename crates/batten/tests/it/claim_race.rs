//! `batten claim race` — the compiled tier for `mise-tasks/claim-race-check.sh`'s
//! retirement (CLOUD-1422).
//!
//! # What the dying suite could not test, and this does
//!
//! Every case below that names a competitor ran in the bats suite against a
//! stubbed `gh`, so the SUBJECT — which pull request is this branch's own — was
//! always supplied by the fixture. That is exactly the input the real program
//! could not resolve in CI, and the reason its defect survived eleven green
//! cases: `gh pr view` reads the CURRENT BRANCH, `actions/checkout` leaves a
//! `pull_request` build detached, and the failure was absorbed by `|| true`.
//!
//! So the two cases the suite never had are the first two here, and they are the
//! same input twice: identified by head SHA it passes, unidentified it refuses.
//!
//! # Where each case runs
//!
//! The decision is pure, so most cases drive `race::` directly and need no
//! forge. The could-not-look arms drive the COMPILED BINARY in a fixture with no
//! reachable remote, because those are properties of the verb rather than of the
//! predicate — and a `with input as` equivalent would fabricate the very shape
//! the verb may be unable to produce.
//!
//! # Writing a verb-tier case against the forge fixture
//!
//! `rest::from_fixture`'s seam is not concurrency-safe, and `with_logs` fetches
//! up to `FETCH_WIDTH` competitors at once. Routing by URL settles WHICH answer
//! each request gets, but every request is also appended to one shared `args`
//! file and a request body replaces one `<file>.request` per route — so what a
//! case READS BACK is in scheduler order, with a last writer winning where two
//! requests route to one file.
//!
//! So: route every endpoint the verb will ask, and assert over the exit code
//! and the two streams, never over `args`. A case that genuinely needs `args`
//! must read it as a set rather than a sequence.

use batten::race::{self, Keys, Pull};

use crate::common::{
    Fixture, batten, declared_patterns, git_in, run, scratch, stderr, stdout, write,
};

/// A [`Keys`] double, for `race.rs`'s own reason: `ready::Grammar` resolves ~18
/// declared patterns, and a tier that had to build one would assert the
/// registry's shape on the way to asserting this predicate's.
struct Fake;

impl Keys for Fake {
    fn named(&self, text: &str) -> Vec<String> {
        key()
            .find_iter(text)
            .map(|m| m.as_str().to_owned())
            .collect()
    }

    fn closed(&self, text: &str) -> Vec<String> {
        closed()
            .captures_iter(text)
            .filter_map(|hit| hit.get(1))
            .map(|hit| hit.as_str().to_owned())
            .collect()
    }
}

fn key() -> regex::Regex {
    regex::Regex::new("[A-Z]+-[0-9]+").expect("a fixture pattern")
}

fn closed() -> regex::Regex {
    regex::Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+([A-Z]+-[0-9]+)")
        .expect("a fixture pattern")
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

/// THE DEFECT, as the case the retired suite had no way to write.
///
/// A branch whose own pull request is in the listing must never race itself.
/// The shell resolved that pull request by branch NAME, which a detached
/// checkout cannot answer, so `self` was empty and this passed straight into a
/// refusal. Measured on PR #793, run 33825308497.
#[test]
fn a_branch_identified_by_head_sha_does_not_race_its_own_pull_request() {
    let pulls = vec![Pull {
        body: "Closes PROJ-1170.".to_owned(),
        ..pull("793", "user/proj-843-campaign", "e97703b2")
    }];
    let me = race::identify(&pulls, "e97703b2").expect("the listing carries this head");
    let mine = race::claimed(&me.head_ref, &me.title, &me.log, &me.body, &Fake);
    assert_eq!(mine, vec!["PROJ-1170".to_owned()]);
    assert!(race::races(&mine, &pulls, Some(&me.number), &Fake).is_empty());
}

/// The other half of the pair: the identical input with the subject
/// unresolved, which is the state the shell was in on every CI run.
///
/// It refuses — which is why `run_claim_race` treats an unidentified head as a
/// refusal to DECIDE rather than as an input to the decision.
#[test]
fn the_same_listing_with_no_resolved_self_is_what_produced_the_defect() {
    let pulls = vec![Pull {
        body: "Closes PROJ-1170.".to_owned(),
        ..pull("793", "user/proj-843-campaign", "e97703b2")
    }];
    let mine = vec!["PROJ-1170".to_owned()];
    assert_eq!(race::races(&mine, &pulls, None, &Fake).len(), 1);
}

// carried: "a key claimed by a different open PR is refused" crates/batten/tests/it/claim_race.rs
/// The CLOUD-49 case, which is why this predicate exists: two sessions on one
/// issue, the second having read the board while it was still Todo.
#[test]
fn a_key_claimed_by_a_different_open_pull_request_is_refused() {
    let pulls = vec![pull("306", "user/proj-49-someone-else", "aaaa")];
    let races = race::races(&["PROJ-49".to_owned()], &pulls, Some("471"), &Fake);
    assert_eq!(races.len(), 1);
    assert_eq!(races[0].key, "PROJ-49");
    assert_eq!(races[0].number, "306");
}

// carried: "POINTER, NEVER PAYLOAD: the refusal carries no title or body" crates/batten/tests/it/claim_race.rs
/// Non-negotiable rule 4, and here it is STRUCTURAL rather than a habit of the
/// renderer: `Race` has no field a title or a body could occupy, so a refusal
/// cannot carry one however it is formatted.
#[test]
fn a_refusal_carries_no_title_and_no_body() {
    let pulls = vec![Pull {
        title: "feat: the secret internal codename (PROJ-49)".to_owned(),
        body: "a body nobody else should read".to_owned(),
        ..pull("306", "user/proj-49-someone-else", "aaaa")
    }];
    let races = race::races(&["PROJ-49".to_owned()], &pulls, Some("471"), &Fake);
    let rendered = format!("{races:?}");
    assert!(!rendered.contains("codename"), "{rendered}");
    assert!(!rendered.contains("nobody else should read"), "{rendered}");
}

// carried: "a competitor that merely CITES the key is allowed — CLOUD-378" crates/batten/tests/it/claim_race.rs
/// The narrowing applied to BOTH sides. PR #306 named CLOUD-133 in one row of an
/// evidence table and refused CLOUD-133's own pull request; a body is evidence,
/// and counts only through a closing keyword.
#[test]
fn a_competitor_that_merely_cites_the_key_is_allowed() {
    let pulls = vec![Pull {
        title: "docs(agents): the attribution decision record (PROJ-268)".to_owned(),
        body: "Prior measurement in PROJ-49 said otherwise.".to_owned(),
        ..pull("306", "user/proj-268-attribution", "aaaa")
    }];
    assert!(race::races(&["PROJ-49".to_owned()], &pulls, Some("471"), &Fake).is_empty());
}

// carried: "our own PR is not a competitor" crates/batten/tests/it/claim_race.rs
/// Otherwise every verify on a branch that has published would refuse itself.
#[test]
fn our_own_pull_request_is_not_a_competitor() {
    let pulls = vec![pull("471", "user/proj-49-the-work", "aaaa")];
    assert!(race::races(&["PROJ-49".to_owned()], &pulls, Some("471"), &Fake).is_empty());
}

// carried: "a branch claiming nothing is not judged" crates/batten/tests/it/claim_race.rs
/// A claim that resolves to nothing is not a claim, and a gate that guesses one
/// is a gate that blocks correct work.
#[test]
fn a_branch_claiming_nothing_is_not_judged() {
    let pulls = vec![pull("306", "user/proj-49-someone-else", "aaaa")];
    assert!(race::races(&[], &pulls, Some("471"), &Fake).is_empty());
    assert!(race::claimed("a-branch", "a title", "", "", &Fake).is_empty());
}

// carried: "a body closing a DIFFERENT key overrides the branch name" crates/batten/tests/it/claim_race.rs
/// The escape hatch for a branch whose name no longer reflects the work.
#[test]
fn a_body_closing_a_different_key_overrides_the_branch_name() {
    assert_eq!(
        race::claimed("user/proj-843-campaign", "", "", "Closes PROJ-1170.", &Fake),
        vec!["PROJ-1170".to_owned()]
    );
}

// carried: "CLOUD-4 does not match CLOUD-49" crates/batten/tests/it/claim_race.rs
/// The comparison is over WHOLE keys, so a shorter key is not a prefix match of
/// a longer one. The bats case spelled this with `grep -qxF`; here both sides
/// are key sets and the containment is by value.
#[test]
fn a_shorter_key_does_not_match_a_longer_one() {
    let pulls = vec![pull("306", "user/proj-49-someone-else", "aaaa")];
    assert!(race::races(&["PROJ-4".to_owned()], &pulls, Some("471"), &Fake).is_empty());
}

// carried: "outside a checkout there is nothing to judge" crates/batten/tests/it/claim_race.rs
/// Outside a repository there is no HEAD and no remote, so there is no subject.
/// This is a usage error rather than a verdict — exit 1, never 2, because "this
/// is not a checkout" is a statement about the environment and reading it as a
/// policy refusal would make the gate decide something nobody asked it.
#[test]
fn outside_a_checkout_there_is_nothing_to_judge() {
    let dir = crate::common::scratch_outside_tree("claim-race", "no-repo");
    let output = run(&dir, &["claim", "race"]);
    assert_ne!(
        output.status.code(),
        Some(2),
        "not a checkout is not a verdict: {}",
        stderr(&output)
    );
}

// carried: "no gh at all is could-not-look, never a verdict" crates/batten/tests/it/claim_race.rs
// carried: "a gh that fails is could-not-look too" crates/batten/tests/it/claim_race.rs
/// Could-not-look ALLOWS, and it says which arm it took.
///
/// The two bats cases were one predicate reached twice — a missing client and a
/// failing one — and both land here: a repository with no origin remote cannot
/// establish a competitor set at all. A gate that cannot reach the forge must
/// never be the reason a branch cannot be verified; this runs inside `verify`,
/// where a false red costs the whole pre-flight.
#[test]
fn a_forge_that_cannot_be_reached_is_could_not_look_and_allows() {
    let dir = Fixture::new("claim-race-unreachable")
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let output = run(&dir, &["claim", "race"]);
    assert!(
        output.status.success(),
        "could-not-look allows: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("could not look"),
        "and says so: {}",
        stdout(&output)
    );
}

// The two deleted paths, one arm each. `kind:verb` because the successor widens
// the command surface: this predicate needs a network round trip and its own
// arguments, so it cannot be a tree-scoped module — `RuleKind::scopes` pairs
// every spawning kind with `RuleScope::Tree` alone, and a module cannot spawn.
//
// carried: mise-tasks/claim-race-check.sh crates/batten/src/race.rs kind:verb crates/batten/tests/it/claim_race.rs
// carried: tests/claim-race-check.bats crates/batten/src/race.rs kind:verb crates/batten/tests/it/claim_race.rs

/// The dead gate the port nearly shipped, pinned as its own case.
///
/// The declared key row carries no `(?i)` flag, and a tracker's own branch
/// names are lower case. The retired shell extracted case-insensitively and
/// upper-cased; a port that handed the branch to the grammar as written
/// resolves NO key from source 2 on any such branch.
///
/// The double below is case-SENSITIVE for exactly that reason — a permissive
/// one would pass whether or not `claimed` folds, which is a test that cannot
/// fail and therefore is not evidence.
#[test]
fn a_lower_case_branch_name_still_resolves_its_key() {
    assert_eq!(
        race::claimed("user/proj-843-campaign", "", "", "", &Fake),
        vec!["PROJ-843".to_owned()]
    );
}

// carried: "the bypass is honoured and is a decision, not a shortcut" crates/batten/tests/it/claim_race.rs
/// The obligation the retired case pinned, at the layer that now carries it.
///
/// `BATTEN_CLAIM_RACE_BYPASS` was the shell program's own hatch, read by the
/// program before it did anything. The successor is a `command` row, so a
/// deliberate second pull request against one issue takes the row's declared
/// bypass through the engine like every other rule — one hatch for the set
/// rather than one per gate.
///
/// So this asserts the obligation rather than the old spelling: the verb itself
/// holds no private escape, and a reader looking for one finds the engine's.
/// A case pinning the retired variable would pin a mechanism that no longer
/// decides anything, which is worse than no case — it would read as coverage.
#[test]
fn the_retired_variable_no_longer_decides_anything() {
    let dir = Fixture::new("claim-race-no-private-hatch")
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let plain = run(&dir, &["claim", "race"]);
    let spent = batten()
        .args(["claim", "race"])
        .current_dir(&dir)
        .env("BATTEN_CLAIM_RACE_BYPASS", "1")
        .output()
        .expect("run batten");
    assert_eq!(
        (plain.status.code(), stdout(&plain)),
        (spent.status.code(), stdout(&spent)),
        "the retired variable must not steer the verb: {}",
        stderr(&spent)
    );
}

/// What the `fetch` double records, behind one lock (CLOUD-2382).
#[derive(Default)]
struct Seen {
    /// Every number asked for, in arrival order — so a SECOND ask for one pull
    /// shows up as a duplicate rather than being absorbed by a set.
    asked: Vec<String>,
    /// Calls inside `fetch` right now, and the most there ever were.
    in_flight: usize,
    peak: usize,
    /// Calls that have returned, which is the condition `"2"` waits on.
    done: usize,
    /// Raised once `FETCH_WIDTH` calls were in flight together — or once the
    /// first waiter gave up, so that only one call ever pays the deadline and a
    /// sequential implementation fails rather than hanging once per pull.
    opened: bool,
}

/// The listing the concurrency case drives, and the numbers it expects fetched.
///
/// `"1"` is passed as `mine`, `FETCH_WIDTH + 2` competitors name no key, and two
/// name one in their titles. **Every count is derived from the width rather than
/// written beside it**, so a retune cannot leave the case asserting a bound the
/// code no longer has: the eligible set stays wider than the width, and the
/// keyed pulls stay numbered past the eligible range, where a literal would
/// collide and put one number in the listing twice.
///
/// Branch names carry no digit after a dash, so `claimed` resolves no key from
/// them however it folds the case — the eligibility this varies has to come
/// from the title alone.
fn listing() -> (Vec<Pull>, Vec<String>) {
    let eligible: Vec<String> = (2..=(race::FETCH_WIDTH + 3))
        .map(|number| number.to_string())
        .collect();
    let mut pulls = vec![pull("1", "user/branch-one", "sha1")];
    for number in &eligible {
        pulls.push(pull(
            number,
            &format!("user/branch{number}"),
            &format!("sha{number}"),
        ));
    }
    for (number, title) in [
        (race::FETCH_WIDTH + 4, "feat: somebody else's work (PROJ-7)"),
        (race::FETCH_WIDTH + 5, "fix: and more of it (PROJ-8)"),
    ] {
        pulls.push(Pull {
            title: title.to_owned(),
            ..pull(
                &number.to_string(),
                &format!("user/branch{number}"),
                &format!("sha{number}"),
            )
        });
    }
    (pulls, eligible)
}

/// The competitor fill is concurrent, bounded at `FETCH_WIDTH`, once per
/// eligible pull, and in listing order (CLOUD-2382).
///
/// # How each clause discriminates
///
/// The double imposes two conditions, neither of them a duration. Every call
/// parks until `FETCH_WIDTH` of them are inside together, and `"2"` parks again
/// until some other call has completed:
///
/// * today's sequential `.map` never gets a second call in flight, so the first
///   gives up at the deadline and the peak reads 1;
/// * a pool narrower than the bound it claims never fills the barrier either,
///   and the peak comes out below `FETCH_WIDTH`;
/// * a collect in COMPLETION order puts `"2"` after the pulls that finished
///   while it waited, which breaks the returned order;
/// * dropping the key predicate fetches the two pulls whose titles name one,
///   and dropping the `mine` arm fetches `"1"`.
///
/// **What the peak equality does NOT discriminate is a spawn-per-item**, and
/// saying so is the point: the implementation spawns `FETCH_WIDTH.min(len)`
/// threads, so the upper bound is structural rather than behavioural, and a
/// per-item spawn retires early threads before the late ones are created — the
/// peak then reads a handful rather than the whole set. The equality is kept
/// because it catches a future refactor that makes the width a soft target,
/// but the bound itself is held by construction, not by this case.
///
/// **Nothing here asserts on the clock.** The ten-second deadline is an input:
/// it turns a serial implementation's hang into a failure instead of a hung
/// suite. A passing run never reaches it. A regression pays it TWICE — once at
/// the barrier, which the first waiter then opens for everyone, and once at
/// `"2"`'s order wait, whose condition a sequential fill never satisfies either
/// — so expect roughly twenty seconds, not ten, when this case is failing.
#[test]
fn competitor_logs_are_fetched_concurrently_once_each_and_returned_in_listing_order() {
    let (pulls, eligible) = listing();
    let seen = std::sync::Mutex::new(Seen::default());
    let bell = std::sync::Condvar::new();
    let deadline = std::time::Duration::from_secs(10);
    let fetch = |number: &str| -> Option<String> {
        {
            // THE WIDTH BARRIER. Every call parks until `FETCH_WIDTH` of them
            // are inside at once, so the peak the case asserts is reached
            // deliberately rather than observed by luck. With the width honoured
            // exactly that many workers exist, all arrive, and the barrier
            // opens; with a narrower pool nobody ever arrives and the first
            // waiter gives up, leaving a peak below the width.
            let mut state = seen.lock().expect("the fixture lock");
            state.asked.push(number.to_owned());
            state.in_flight += 1;
            state.peak = state.peak.max(state.in_flight);
            state.opened |= state.in_flight >= race::FETCH_WIDTH;
            if !state.opened {
                let (reopened, timeout) = bell
                    .wait_timeout_while(state, deadline, |state| !state.opened)
                    .expect("the fixture lock");
                state = reopened;
                state.opened |= timeout.timed_out();
            }
        }
        bell.notify_all();
        // AND THE ORDER HALF, which the barrier does not cover: `"2"` must not
        // be among the first to finish, or a collect in COMPLETION order could
        // still come out in listing order by luck.
        if number == "2" {
            let waiting = seen.lock().expect("the fixture lock");
            drop(
                bell.wait_timeout_while(waiting, deadline, |state| state.done == 0)
                    .expect("the fixture lock"),
            );
        }
        {
            let mut state = seen.lock().expect("the fixture lock");
            state.in_flight -= 1;
            state.done += 1;
        }
        bell.notify_all();
        Some(format!("Refs: CLOUD-{number}"))
    };

    let race::Filled {
        pulls: filled,
        unanswered,
    } = race::with_logs(pulls.clone(), "1", &[], &Fake, fetch);

    assert!(
        unanswered.is_empty(),
        "every eligible competitor answered, so this fill is a reading"
    );
    assert_eq!(
        filled
            .iter()
            .map(|pull| pull.number.clone())
            .collect::<Vec<_>>(),
        pulls
            .iter()
            .map(|pull| pull.number.clone())
            .collect::<Vec<_>>(),
        "the returned listing is the input's, whatever order the fetches finished in"
    );
    for pull in &filled {
        if eligible.contains(&pull.number) {
            assert_eq!(
                pull.log,
                format!("Refs: CLOUD-{}", pull.number),
                "each fetched pull carries its own answer"
            );
        } else {
            assert!(
                pull.log.is_empty(),
                "#{} was not eligible and must keep its empty log, not {:?}",
                pull.number,
                pull.log
            );
        }
    }

    let state = seen.lock().expect("the fixture lock");
    let mut asked = state.asked.clone();
    asked.sort();
    let mut once_each = eligible.clone();
    once_each.sort();
    assert_eq!(
        asked, once_each,
        "exactly the eligible pulls, exactly once each — never `mine`, never a keyed one"
    );
    assert_eq!(
        state.peak,
        race::FETCH_WIDTH,
        "the width is used and not exceeded: a lower peak is a narrower pool \
         than the bound claims (1 being a sequential fill), a higher one is a \
         spawn that ignores the bound"
    );
}

/// A fill that lost a worker names it in `unanswered`, so the verb reads it as
/// could-not-look instead of taking a verdict over it (CLOUD-2382).
///
/// # Why this case exists at all
///
/// The sequential fill could not produce this state: a panic in the fetch took
/// the process with it. Absorbing the panic is right — the alternative is one
/// through `verify`'s whole pre-flight — but absorbing it silently would leave a
/// competitor carrying an empty log for no reason the forge gave, and `races`
/// would then report "no races" over a pull request nobody read. That is the
/// exact conflation `race.rs` exists to correct, so the flag that prevents it
/// owes a case.
///
/// It discriminates by construction: an `unanswered` hardcoded empty, or taken
/// against the listing rather than the eligible set, passes every other
/// assertion in this file and fails only here. Asserting the NUMBER rather than
/// emptiness is what pins the second half of the field's job — the caller asks
/// which competitor went unread, not merely whether one did.
#[test]
fn a_fill_that_lost_a_worker_is_not_complete_and_keeps_the_answers_it_got() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        pull("2", "user/branch-two", "sha2"),
        pull("3", "user/branch-three", "sha3"),
    ];
    // `"2"` is fetched by a worker that unwinds; `"3"` is fetched by another
    // that does not, which is what pins "keeps the answers it got".
    let race::Filled {
        pulls: filled,
        unanswered,
    } = race::with_logs(pulls, "1", &[], &Fake, |number| {
        assert!(number != "2", "a deliberate panic inside one worker");
        Some(format!("Refs: CLOUD-{number}"))
    });

    assert_eq!(
        unanswered,
        ["2".to_owned()],
        "the competitor that was never answered is named, not just counted"
    );
    assert_eq!(
        filled
            .iter()
            .map(|pull| pull.log.as_str())
            .collect::<Vec<_>>(),
        ["", "", "Refs: CLOUD-3"],
        "the lost worker costs its own fetch and nothing else, and the order holds"
    );
}

/// A competitor whose read FAILED is not read as claiming nothing, and one whose
/// log is genuinely empty still is (CLOUD-2421).
///
/// # The pair is the case
///
/// The sequential fill collapsed every failure to `""` with
/// `unwrap_or_default`, so a 403 on a scopeless token, a 502 and a timeout all
/// presented as "this competitor names no key". `commit-lint` requires a
/// `Refs:` trailer on every commit here and a closing keyword on almost none,
/// so the trailer is the source that actually resolves a claim — and it lives
/// in the log the failed read did not return. The gate then printed "no open
/// pull request races this branch's claim" over a real collision.
///
/// So BOTH halves are asserted, and the second is what stops the fix from
/// over-reaching: `None` must make the fill incomplete, and `Some("")` must
/// not, because an empty log is a real answer that a competitor with no key
/// genuinely produces. A seam that treated them alike would pass the first
/// assertion and fail the second.
#[test]
fn a_read_that_failed_is_not_a_competitor_that_claims_nothing() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        pull("2", "user/branch-two", "sha2"),
    ];

    let refused = race::with_logs(pulls.clone(), "1", &[], &Fake, |_| None);
    assert_eq!(
        refused.unanswered,
        ["2".to_owned()],
        "a read that failed leaves the fill a could-not-look, never a verdict"
    );
    assert!(
        refused.pulls.iter().all(|pull| pull.log.is_empty()),
        "and nothing is invented for the competitor that was not read"
    );

    let answered = race::with_logs(pulls, "1", &[], &Fake, |_| Some(String::new()));
    assert!(
        answered.unanswered.is_empty(),
        "an empty log is an ANSWER — a competitor whose commits name no key reads \
         exactly that way, and conflating the two is the defect this fixes"
    );
}

/// A competitor whose cheap key COLLIDES with this branch's is fetched even
/// though the cheap sources answered, and one whose cheap key collides with
/// nothing is still skipped (CLOUD-2382).
///
/// # Why the widening is free
///
/// The skip reads a competitor under its branch where its COMMITS close another
/// key, which misjudges in both directions — and the refusing direction is a
/// false `Violation` inside `verify` over a collision that does not exist. Only
/// a competitor whose cheap key is one THIS BRANCH claims can refuse anything,
/// so those are the only ones worth the round trip, and a run that answers
/// clean has none of them. That is what the second assertion pins: `"3"` names
/// a key nobody claims and must stay unfetched, or the widening has quietly
/// become "fetch every competitor" and the bound this row exists for is gone.
#[test]
fn a_competitor_whose_cheap_key_collides_is_fetched_and_one_that_collides_with_nothing_is_not() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        Pull {
            title: "feat: somebody else on PROJ-7".to_owned(),
            ..pull("2", "user/branch-two", "sha2")
        },
        Pull {
            title: "fix: and someone on PROJ-8".to_owned(),
            ..pull("3", "user/branch-three", "sha3")
        },
    ];
    let asked = std::sync::Mutex::new(Vec::new());

    let filled = race::with_logs(pulls, "1", &["PROJ-7".to_owned()], &Fake, |number| {
        asked
            .lock()
            .expect("the fixture lock")
            .push(number.to_owned());
        Some(format!("Closes PROJ-{number}0"))
    });

    assert_eq!(
        *asked.lock().expect("the fixture lock"),
        vec!["2".to_owned()],
        "only the competitor whose cheap key this branch also claims is worth a round trip"
    );
    assert!(
        filled.unanswered.is_empty(),
        "the one eligible competitor answered, so this fill is a reading"
    );
    // AND THE FALSE REFUSAL IS GONE, which is the whole point and the only
    // assertion here that is `with_logs`'s rather than `claimed`'s: #2 read as
    // claiming PROJ-7 from its title, its commits close PROJ-20, and the race
    // the cheap sources would have reported against PROJ-7 does not survive the
    // answer the widening went and got.
    assert!(
        race::races(&["PROJ-7".to_owned()], &filled.pulls, Some("1"), &Fake).is_empty(),
        "a competitor the cheap sources misread must not refuse this branch once its log is in"
    );
}

/// A collider whose BODY closes the key is settled, so it is not fetched even
/// though it collides (CLOUD-2382).
///
/// Why the widening stops at the branch and title is `with_logs`'s own
/// comment, and is not re-derived here.
///
/// The pair is the case: `"2"` and `"3"` both collide on PROJ-7, and they
/// differ only in WHERE the key came from — `"2"`'s title, `"3"`'s body. So
/// the asked set discriminates on that difference alone, and `"2"` earns its
/// place by keeping `asked == ["2"]` from passing vacuously.
#[test]
fn a_collider_whose_body_closes_the_key_is_settled_and_not_fetched() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        Pull {
            title: "feat: somebody else on PROJ-7".to_owned(),
            ..pull("2", "user/branch-two", "sha2")
        },
        Pull {
            body: "Closes PROJ-7, and this one means it.".to_owned(),
            ..pull("3", "user/branch-three", "sha3")
        },
    ];
    let asked = std::sync::Mutex::new(Vec::new());

    let filled = race::with_logs(pulls, "1", &["PROJ-7".to_owned()], &Fake, |number| {
        asked
            .lock()
            .expect("the fixture lock")
            .push(number.to_owned());
        Some(String::new())
    });

    assert_eq!(
        *asked.lock().expect("the fixture lock"),
        vec!["2".to_owned()],
        "the title-named collider is distrusted and asked; the body-closed one is settled"
    );
    // NAMED, not merely non-empty: `"2"` races PROJ-7 from its title whatever
    // happens to `"3"`, so `!is_empty()` would pass without `"3"` in the list
    // at all — an assertion that cannot fail for the reason its message gives.
    assert!(
        race::races(&["PROJ-7".to_owned()], &filled.pulls, Some("1"), &Fake)
            .iter()
            .any(|race| race.number == "3"),
        "and the settled one still races, on evidence no round trip could improve"
    );
}

/// A body that closes a key NOBODY HERE CLAIMS settles nothing, so its commits
/// are still read (from /code-review over #1198).
///
/// The sibling case above it settles `"3"` because the key its body closes is
/// the key at issue. `"4"` here closes PROJ-9, which this branch does not claim
/// — so the settling argument, whose whole content is "the key that refuses is
/// the body's", has nothing to say about PROJ-7. Its commits are the only place
/// a PROJ-7 claim of its own could still be, exactly as for a competitor whose
/// body closes nothing at all.
///
/// Asserted over BOTH the asked set and the verdict: fetching it is only
/// interesting because the log then refuses, and a case that checked the round
/// trip alone would pass over a fill that threw the answer away.
#[test]
fn a_body_closing_a_key_nobody_claims_settles_nothing_and_its_commits_are_read() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        Pull {
            body: "Closes PROJ-9, which is not what is being asked.".to_owned(),
            ..pull("4", "user/branch-four", "sha4")
        },
    ];
    let asked = std::sync::Mutex::new(Vec::new());

    let filled = race::with_logs(pulls, "1", &["PROJ-7".to_owned()], &Fake, |number| {
        asked
            .lock()
            .expect("the fixture lock")
            .push(number.to_owned());
        Some("fix: the real work\n\nCloses PROJ-7".to_owned())
    });

    assert_eq!(
        *asked.lock().expect("the fixture lock"),
        vec!["4".to_owned()],
        "a body closing an unrelated key is not a settled competitor"
    );
    assert!(
        race::races(&["PROJ-7".to_owned()], &filled.pulls, Some("1"), &Fake)
            .iter()
            .any(|race| race.number == "4"),
        "and the log it answered with is what refuses"
    );
}

/// A body closing SEVERAL keys is settled by the claimed one wherever it sits.
///
/// The two cases around this one each put exactly one key in a body, so between
/// them they cannot tell `any` from `first`: swapping the collision test for
/// `settled.first().is_some_and(..)` or a `.take(1).any(..)` leaves both green.
/// Here PROJ-9 comes first and is claimed by nobody, PROJ-7 second and is the
/// key at issue — so under `first` this competitor would be fetched though it
/// is settled, re-spending the round trip and re-earning the unconfirmed mark
/// the module's cost argument exists to avoid.
///
/// Reachable rather than exotic: `run_claim_race` passes everything this branch
/// claims, which is routinely more than one key, and nothing orders a body's
/// closing keywords.
#[test]
fn a_body_closing_an_unclaimed_key_before_a_claimed_one_is_still_settled() {
    let pulls = vec![
        pull("1", "user/branch-one", "sha1"),
        Pull {
            body: "Closes PROJ-9. Also closes PROJ-7, and means that one.".to_owned(),
            ..pull("5", "user/branch-five", "sha5")
        },
    ];
    let asked = std::sync::Mutex::new(Vec::new());

    let filled = race::with_logs(pulls, "1", &["PROJ-7".to_owned()], &Fake, |number| {
        asked
            .lock()
            .expect("the fixture lock")
            .push(number.to_owned());
        Some(String::new())
    });

    assert!(
        asked.lock().expect("the fixture lock").is_empty(),
        "the claimed key settles it even behind an unclaimed one: {:?}",
        asked.lock().expect("the fixture lock")
    );
    assert!(
        race::races(&["PROJ-7".to_owned()], &filled.pulls, Some("1"), &Fake)
            .iter()
            .any(|race| race.number == "5"),
        "and it still races, on the body alone"
    );
}

/// The repository the verb derives from `origin`, deliberately not this one's:
/// a slug taken from the environment rather than from the remote would read as
/// a passing case.
const REPO: &str = "acme/widgets";

/// The two statuses the fixtures below choose between, named at the call site
/// for the reason `unread_log` takes an `Option` rather than a second `bool`:
/// `self_log`'s two are the same type and a swap would compile, turning the
/// unconfirmed-race case into the already-covered refused-self-log one.
const OK: u16 = 200;
const REFUSED: u16 = 403;

/// One `-i`-style response, in the shape `rest`'s fixture seam reads.
fn answer(status: u16, body: &str) -> String {
    format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n")
}

/// A checkout the verb can resolve itself in: the real grammar, an `origin` the
/// slug derives from, one commit, and the forge directory beside it.
///
/// The REAL grammar rather than [`Fake`], because the subject of every case
/// built on this is the verb: the compiled binary resolves `[[pattern]]` rows
/// out of the config it finds, and a fixture spelling its own would assert
/// about a grammar nothing uses.
///
/// Returns the repository, its HEAD — which a listing must carry as some pull
/// request's head SHA or [`race::identify`] finds no subject — and the forge.
fn checkout(name: &str) -> (std::path::PathBuf, String, std::path::PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n")
        .config_append(&declared_patterns())
        .git()
        .base_commit()
        .build();
    git_in(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            &format!("https://github.com/{REPO}.git"),
        ],
    );
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let forge = root.join("forge");
    (repo, head, forge)
}

/// A checkout that IS pull request #7, and a forge answering the three
/// endpoints `batten claim race` asks: the open listing, #7's own commit log,
/// and #8's — the latter two with statuses the caller chooses.
///
/// **The listing is the collision in miniature.** #7's body closes CLOUD-1
/// while its COMMITS close CLOUD-2, and #8 names CLOUD-2 in its title. So
/// whether this branch races turns entirely on whether its own log was read.
///
/// #8's commits are routed too, and close CLOUD-2 as its title says: once the
/// self log resolves CLOUD-2 into `mine`, #8's cheap key collides with it and
/// `with_logs` asks for its commits to confirm. The confirmation agrees, so
/// the race is real.
fn self_log(
    name: &str,
    commits: u16,
    body: &str,
    rival: u16,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let (repo, head, forge) = checkout(name);
    write(
        &forge,
        "routes",
        "pulls/7/commits\tcommits.json\npulls/8/commits\trival.json\npulls?\tpulls.json\n",
    );
    write(
        &forge,
        "rival.json",
        &answer(
            rival,
            r#"[{"commit":{"message":"feat: the rival's work\n\nCloses CLOUD-2"}}]"#,
        ),
    );
    write(
        &forge,
        "pulls.json",
        &answer(
            200,
            &format!(
                r#"[{{"number":7,"title":"fix: the work","body":"{body}",
                   "head":{{"ref":"user/topic","sha":"{head}"}}}},
                  {{"number":8,"title":"feat: somebody else on CLOUD-2","body":"",
                   "head":{{"ref":"user/rival","sha":"beef"}}}}]"#
            ),
        ),
    );
    write(
        &forge,
        "commits.json",
        &answer(
            commits,
            r#"[{"commit":{"message":"fix: more of it\n\nCloses CLOUD-2"}}]"#,
        ),
    );
    (repo, forge)
}

/// A listing with TWO colliding competitors, one of which answers.
///
/// Its own fixture rather than a fourth axis on [`self_log`]: #9 claims CLOUD-1,
/// which that listing's branch also claims, so adding it there would turn the
/// could-not-look cases into refusals — they allow precisely because nobody
/// else holds CLOUD-1.
///
/// #7 is this branch: body closes CLOUD-1, commits close CLOUD-2, both read. So
/// `mine` is both keys, and both competitors collide and are fetched. #8's
/// confirming read is REFUSED; #9's answers and agrees with its title.
///
/// Two eligible competitors is the shape `race.rs` warns about for this seam —
/// `rest::from_fixture` appends every request to one shared `args` file — so
/// this asserts over exit code and stderr only, never over `args`. Which
/// ANSWER each request gets is routed by URL and is safe concurrently.
fn two_rivals(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let (repo, head, forge) = checkout(name);
    write(
        &forge,
        "routes",
        "pulls/7/commits\tmine.json\npulls/8/commits\tunread.json\n\
         pulls/9/commits\tanswered.json\npulls?\tpulls.json\n",
    );
    write(
        &forge,
        "pulls.json",
        &answer(
            200,
            &format!(
                r#"[{{"number":7,"title":"fix: the work","body":"Closes CLOUD-1.",
                   "head":{{"ref":"user/topic","sha":"{head}"}}}},
                  {{"number":8,"title":"feat: somebody else on CLOUD-2","body":"",
                   "head":{{"ref":"user/rival","sha":"beef"}}}},
                  {{"number":9,"title":"fix: a third party on CLOUD-1","body":"",
                   "head":{{"ref":"user/third","sha":"cafe"}}}}]"#
            ),
        ),
    );
    write(
        &forge,
        "mine.json",
        &answer(
            OK,
            r#"[{"commit":{"message":"fix: more of it\n\nCloses CLOUD-2"}}]"#,
        ),
    );
    write(
        &forge,
        "unread.json",
        &answer(
            REFUSED,
            r#"[{"commit":{"message":"feat: the rival's work\n\nCloses CLOUD-2"}}]"#,
        ),
    );
    write(
        &forge,
        "answered.json",
        &answer(
            OK,
            r#"[{"commit":{"message":"fix: the third party's work\n\nCloses CLOUD-1"}}]"#,
        ),
    );
    (repo, forge)
}

/// The three commit messages [`speculating`] is built from.
///
/// Constants because two of them are spelled in BOTH encodings — a real commit
/// made with `-m`, and a JSON string in the forge's answer — and the fixture is
/// a replay only while the two agree. Typed twice, editing one spelling leaves
/// every case green while the fixture quietly stops modelling a rebase, which
/// is the one invariant its whole value rests on. [`commit_list`] derives the
/// JSON spelling from these, so there is nothing to keep in step by hand.
const HOLDER: &str = "feat: the holder's work\n\nCloses CLOUD-2";
const OURS: &str = "fix: our own work\n\nCloses CLOUD-3";
const THIRD: &str = "fix: the third party's work\n\nCloses CLOUD-3";

/// One `-i`-style commit-list body, each message escaped as JSON needs it.
fn commit_list(messages: &[&str]) -> String {
    let entries: Vec<String> = messages
        .iter()
        .map(|message| {
            format!(
                r#"{{"commit":{{"message":"{}"}}}}"#,
                message.replace('\n', "\\n")
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// A checkout mid-speculative-lap: the lease holder's commit IS the borrowed
/// base, this branch's own commit is the one after it, and a competitor holds
/// each of the two keys they close.
///
/// The holder's commit being the base exactly — not merely somewhere behind it
/// — is the mechanism, since `base..HEAD` excludes its endpoint. A fixture
/// described as "behind the base" admits `base == HEAD`, which is what the
/// previous version of this case did and why a mutant survived it.
///
/// Its own fixture rather than an axis on [`self_log`], for the reason
/// [`two_rivals`] has one: the local history has to differ from the pull
/// request's commit list, which means a real second commit and a listing that
/// carries the head it produced — neither of which the other cases want.
///
/// **The two keys are what make the source observable in both directions.** The
/// forge answers #7's whole commit list, holder's commit included, as a real
/// rebase leaves it: `Closes CLOUD-2` from the holder and `Closes CLOUD-3` from
/// this branch. #8 holds CLOUD-2 and #9 holds CLOUD-3. So reading the forge
/// races both, reading `base..HEAD` races only #9, and reading nothing at all
/// — an empty log presented as an answer — races neither. Three sources, three
/// outcomes, which is what the one-variable claim needs to rest on.
///
/// Returns the repository, the forge, and the base to export.
fn speculating(name: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let (repo, _, forge) = checkout(name);
    // REPLAYED, not merely listed: the holder's commit really is in this
    // checkout's history, and the base is taken AT it, which is the state
    // `land` leaves. A fixture that left it out of local history would exclude
    // it by accident rather than by the bound under test — and one that took
    // the base at HEAD would exclude everything, which is the empty range a
    // mutant answering `Some("")` is indistinguishable from.
    git_in(&repo, &["commit", "--allow-empty", "-m", HOLDER]);
    let base = git_in(&repo, &["rev-parse", "HEAD"]);
    git_in(&repo, &["commit", "--allow-empty", "-m", OURS]);
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    write(
        &forge,
        "routes",
        "pulls/7/commits\tmine.json\npulls/8/commits\tholder.json\n\
         pulls/9/commits\tthird.json\npulls?\tpulls.json\n",
    );
    write(
        &forge,
        "pulls.json",
        &answer(
            200,
            &format!(
                r#"[{{"number":7,"title":"fix: the work","body":"Closes CLOUD-1.",
                   "head":{{"ref":"user/topic","sha":"{head}"}}}},
                  {{"number":8,"title":"feat: the lease holder on CLOUD-2","body":"",
                   "head":{{"ref":"user/holder","sha":"beef"}}}},
                  {{"number":9,"title":"fix: a third party on CLOUD-3","body":"",
                   "head":{{"ref":"user/third","sha":"cafe"}}}}]"#
            ),
        ),
    );
    // #7's list is the local history, holder's commit first, which is what
    // makes this a replay rather than two unrelated texts that happen to agree.
    write(
        &forge,
        "mine.json",
        &answer(OK, &commit_list(&[HOLDER, OURS])),
    );
    write(&forge, "holder.json", &answer(OK, &commit_list(&[HOLDER])));
    write(&forge, "third.json", &answer(OK, &commit_list(&[THIRD])));
    (repo, forge, base)
}

/// The refusal line carrying the unconfirmed mark, or empty where none does.
///
/// A line rather than the whole stream, because every assertion about the mark
/// is about WHICH row carries it: the stream also holds the other refusals and
/// the closing summary, so a bare `contains` over it proves nothing.
fn unconfirmed_line(output: &std::process::Output) -> String {
    stderr(output)
        .lines()
        .find(|line| line.contains("unconfirmed"))
        .unwrap_or_default()
        .to_owned()
}

/// Run `batten claim race` in `repo` against `forge`.
fn raced(repo: &std::path::Path, forge: &std::path::Path) -> std::process::Output {
    batten()
        .args(["claim", "race"])
        .current_dir(repo)
        .env("BATTEN_REST_FIXTURE", forge)
        .output()
        .expect("the compiled binary runs")
}

/// The same run inside a speculative `land` lap, which exports the base it
/// borrowed.
fn raced_speculating(
    repo: &std::path::Path,
    forge: &std::path::Path,
    base: &str,
) -> std::process::Output {
    batten()
        .args(["claim", "race"])
        .current_dir(repo)
        .env("BATTEN_REST_FIXTURE", forge)
        .env("BATTEN_SPEC_BASE", base)
        .output()
        .expect("the compiled binary runs")
}

/// A speculative lap judges this branch on ITS OWN commits, not on the lease
/// holder's (CLOUD-748's defect by a different door).
///
/// # What a speculative lap does to the forge's answer
///
/// `land` rebases a waiting branch onto the lease holder's published head and
/// pushes, so the holder's unlanded commits are in this pull request's commit
/// list — and `claimed_from` reads a closing keyword out of that list before
/// it consults branch or title. The forge here answers exactly that shape:
/// #7's commits close CLOUD-2, which is #8's key. Read from the forge, `mine`
/// becomes CLOUD-2 and the verb refuses against #8 — the very pull request a
/// speculating branch is waiting on.
///
/// With `BATTEN_SPEC_BASE` exported, as `land` exports it to every body gate,
/// the claim comes from `race::authored_log` over `base..HEAD` instead, where
/// the holder's commit is excluded and this branch's own CLOUD-3 commit is not.
///
/// **BOTH HALVES ARE ASSERTED, because only one of them is about the forge.**
/// Dropping #8 proves the holder's commits stopped speaking; keeping #9 proves
/// the local ones started. A speculative arm that answered an empty log would
/// satisfy the first and fail the second — it would exit 0 here — which is the
/// whole difference between reading this branch's history and reading nothing.
/// [`a_speculative_lap_without_the_variable_reads_the_whole_pull_request`] is
/// the same fixture with the variable withheld.
#[test]
fn a_speculative_lap_does_not_race_the_branch_it_borrowed_its_base_from() {
    let (repo, forge, base) = speculating("claim-race-speculating");
    let output = raced_speculating(&repo, &forge, &base);

    assert_eq!(
        output.status.code(),
        Some(2),
        "this branch's own CLOUD-3 commit still claims CLOUD-3: {} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("CLOUD-3") && stderr(&output).contains("#9"),
        "so the race it reports is the one its own history earns: {}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("#8"),
        "and never the lease holder it was replayed onto: {}",
        stderr(&output)
    );
}

/// The pair, which is one environment variable: the same fixture read from the
/// forge races the lease holder it was replayed onto.
///
/// This is the defect, not a second feature — it is what `batten claim race`
/// does inside a speculative lap when nothing tells it one is in force, and it
/// is pinned here so
/// [`a_speculative_lap_does_not_race_the_branch_it_borrowed_its_base_from`]
/// cannot be deleted silently.
#[test]
fn a_speculative_lap_without_the_variable_reads_the_whole_pull_request() {
    let (repo, forge, _) = speculating("claim-race-speculating-unbounded");
    let output = raced(&repo, &forge);

    assert_eq!(
        output.status.code(),
        Some(2),
        "the holder's CLOUD-2 is in #7's commit list and resolves into `mine`: {} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("#8"),
        "so the waiter refuses against the very pull request it is waiting on: {}",
        stderr(&output)
    );
}

/// A BLANK export is not an export, which is the predicate `race::authored_log`
/// already applies and the one this verb has to apply with it.
///
/// `authored_log` reads the variable through `!value.trim().is_empty()`, so a
/// whitespace-only base is absent to it and the range falls back. Were the
/// source switched on a bare `!is_empty()` instead, this run would take the
/// local path while the range fell back to the trunk — one decision on two
/// predicates, and in this checkout the trunk resolves to nothing, so `mine`
/// would collapse to the body's CLOUD-1 and the verb would exit 0 over a
/// listing holding two collisions.
///
/// Pinned over the exit code rather than the source directly, because the
/// source is not observable from outside: what distinguishes the two readings
/// is exactly which pull requests get named.
#[test]
fn a_blank_speculative_base_is_no_base_and_the_forge_still_answers() {
    let (repo, forge, _) = speculating("claim-race-speculating-blank");
    let output = raced_speculating(&repo, &forge, "   ");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a blank base leaves the forge as the source, as it does for the range: {} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("#8"),
        "so the holder's CLOUD-2 is in `mine` and #8 races: {}",
        stderr(&output)
    );
}

/// The branch races on a key only its OWN commits close, which is the half
/// that gives [`a_self_log_that_could_not_be_read_is_not_a_clean_board`]
/// something to lose: same fixture, same keys, only the self log's status
/// differs, so a refusal there is a refusal this case proves was available.
///
/// Named rather than placed. A case says which case it pairs with, never
/// "above" or "below" — an insert between them makes a positional claim false
/// and nothing reads it.
#[test]
fn a_key_closed_by_this_branch_s_commits_alone_still_races() {
    let (repo, forge) = self_log("claim-race-self-log-read", OK, "Closes CLOUD-1.", OK);
    let output = raced(&repo, &forge);

    assert_eq!(
        output.status.code(),
        Some(2),
        "CLOUD-2 is claimed twice and the log says so: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("CLOUD-2") && stderr(&output).contains("#8"),
        "the refusal names the key and the competitor: {}",
        stderr(&output)
    );
}

/// And a self log that could NOT be read is could-not-look, never "no race"
/// (CLOUD-2382).
///
/// # The pair is the case
///
/// The arm one commit back judged every failed self read whose body closes a
/// key, on the sound ground that `closed(body)` is a SUBSET of
/// `closed(body + log)` — so a race found over the short set is a true refusal.
/// What it did not carry is the other half of a subset: a race NOT found over it
/// is unproven. Over [`self_log`]'s listing that is a collision compared against
/// nothing, and the verb printed *"no open pull request races this branch's
/// claim"* at exit 0 over the pull request it exists to refuse.
///
/// The two cases differ in ONE byte of fixture — the status of the commits
/// endpoint — so neither the listing, the grammar, nor the fan-out can account
/// for the difference. The third assertion is the load-bearing one: an arm that
/// allowed while saying nothing would pass the first two.
#[test]
fn a_self_log_that_could_not_be_read_is_not_a_clean_board() {
    let (repo, forge) = self_log(
        "claim-race-self-log-refused",
        REFUSED,
        "Closes CLOUD-1.",
        OK,
    );
    let output = raced(&repo, &forge);

    assert!(
        output.status.success(),
        "a forge this cannot reach is never the reason a branch fails `verify`: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("could not look"),
        "and it says which arm it took: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("no open pull request races"),
        "a claim set short of the keys its own commits close cannot report a clean board: {}",
        stdout(&output)
    );
}

/// A self log that could not be read AND a body that closes nothing takes the
/// other self arm — the one that declines before judging anything.
///
/// # Why it is a separate arm, and why it owed a case
///
/// With a closing body the degraded claim set is a SUBSET of the true one, so
/// judging it can only under-report and the verb judges. With a silent body the
/// set is not a subset at all: `claimed_from` falls through to the branch and
/// title, so a branch whose log closes one key and whose name carries another
/// resolves to the WRONG key and could refuse over a claim it does not make.
/// That arm therefore returns before `races`, and its message says which of the
/// two reasons it took.
///
/// Until this case, deleting the guard — or inverting it — left the whole suite
/// green, because every other fixture-driven run either exits before the log
/// read or has a body that closes a key. The branch name here resolves no key
/// either, which is what makes the arm reachable rather than hypothetical.
#[test]
fn a_silent_body_behind_an_unreadable_self_log_judges_nothing() {
    let (repo, forge) = self_log(
        "claim-race-self-log-silent",
        REFUSED,
        "no key here at all",
        OK,
    );
    let output = raced(&repo, &forge);

    assert!(
        output.status.success(),
        "could-not-look allows, on this arm as on the others: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("body closes no key"),
        "and it names THIS arm rather than the subset one: {}",
        stdout(&output)
    );
}

/// A race whose confirming read FAILED still refuses, and says it is
/// unconfirmed (CLOUD-2382).
///
/// # Which error this gate prefers
///
/// #8 is fetched only because its cheap key collides with this branch's — that
/// is, precisely because the branch-derived key might be wrong. Declining when
/// that confirming read fails would lose a refusal the un-widened fill made,
/// over nothing worse than a 502; the monotonicity argument for refusing
/// instead is at `run_claim_race`'s `races` call and is not re-derived here.
///
/// The fixture is the confirmed case with one byte changed, the status of
/// `pulls/8/commits`. The exit code is the inversion these commits make, and
/// the marked line is what stops a silent refusal from passing it.
#[test]
fn a_race_whose_confirming_read_failed_refuses_and_says_it_is_unconfirmed() {
    let (repo, forge) = self_log("claim-race-rival-unread", OK, "Closes CLOUD-1.", REFUSED);
    let output = raced(&repo, &forge);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a collision the cheap sources see still refuses: {} {}",
        stdout(&output),
        stderr(&output)
    );
    let marked = unconfirmed_line(&output);
    assert!(
        marked.contains("#8") && marked.contains("CLOUD-2"),
        "and the marked row is the refusal itself, naming key and competitor: {marked:?}"
    );
}

/// A mixed listing reports BOTH collisions and marks only the unconfirmed one
/// (CLOUD-2382).
///
/// # Why no arm throws the list away
///
/// A single 502 mid-fan-out, or the worker unwind `with_logs` absorbs, leaves
/// one competitor unread while the rest answered. Any arm keyed on "some race
/// is unconfirmed" discards collisions this run fully read, which is the
/// "refusing information the run already holds" that `run_claim_race`'s
/// judge-first ordering exists to keep (`crates/batten/src/lib.rs`, at the
/// `races` call). The unconfirmed one is annotated, not withheld.
///
/// So this listing is deliberately mixed: #8 collides on CLOUD-2 and its
/// confirming read is refused, #9 collides on CLOUD-1 and its read agrees.
/// Both are refusals; only #8 is named as unconfirmed. An implementation that
/// declined over #8, or that marked #9 too, fails here.
#[test]
fn a_mixed_listing_reports_both_races_and_marks_only_the_unconfirmed_one() {
    let (repo, forge) = two_rivals("claim-race-mixed-confirmation");
    let output = raced(&repo, &forge);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a listing with any confirmed collision refuses: {} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("#9") && stderr(&output).contains("#8"),
        "both collisions are reported, the read one and the unread one: {}",
        stderr(&output)
    );
    let marked = unconfirmed_line(&output);
    assert!(
        marked.contains("#8") && !marked.contains("#9"),
        "and only the one whose confirming read failed is marked: {marked:?}"
    );
}
