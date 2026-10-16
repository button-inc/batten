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

use batten::race::{self, Keys, Pull};

use crate::common::{Fixture, batten, run, stderr, stdout};

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

/// The competitor fill is concurrent, bounded at eight, once per eligible pull,
/// and in listing order (CLOUD-2382).
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
/// suite, and it is paid once, because whoever gives up opens the barrier.
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

#[test]
fn competitor_logs_are_fetched_concurrently_once_each_and_returned_in_listing_order() {
    let (pulls, eligible) = listing();
    let seen = std::sync::Mutex::new(Seen::default());
    let bell = std::sync::Condvar::new();
    let deadline = std::time::Duration::from_secs(10);
    let fetch = |number: &str| -> String {
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
        format!("Refs: CLOUD-{number}")
    };

    let race::Filled {
        pulls: filled,
        complete,
    } = race::with_logs(pulls.clone(), "1", &Fake, fetch);

    assert!(
        complete,
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

/// A fill that lost a worker is `complete: false`, so the verb reads it as
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
/// It discriminates by construction: a `complete` hardcoded to `true`, or
/// counted against the listing rather than the eligible set, passes every other
/// assertion in this file and fails only here.
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
        complete,
    } = race::with_logs(pulls, "1", &Fake, |number| {
        assert!(number != "2", "a deliberate panic inside one worker");
        format!("Refs: CLOUD-{number}")
    });

    assert!(
        !complete,
        "a competitor that was never answered makes the fill a could-not-look"
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
