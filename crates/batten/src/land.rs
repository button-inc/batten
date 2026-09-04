//! The landing lap, in-process (CLOUD-1335).
//!
//! # What this owns and what it deliberately does not
//!
//! A lap is fetch → replay → verify → push → wait → fast-forward, and a refusal
//! starts the next one by itself. This module owns the **git and record** work:
//! bring the base forward, replay the branch onto it, and write down what the
//! replay and the wait did. It stands beside the consumer's lander rather than
//! replacing it — the same shape `batten lease` took beside `land-lock`.
//!
//! # It DECIDES nothing, and that separation is the whole design
//!
//! Two policy questions arise in a lap and neither is answered here. *May a lap
//! continue past a conflicted replay?* is `rebase-conflict-stops-the-lap`'s.
//! *Which answer may a lap act on when its wait raced two questions?* is
//! `lap-waits-on-one-answer`'s. Both are `landing-loop` preset predicates over
//! the records this module writes, which is CLOUD-1148's thesis read forwards:
//! the mechanics move to the engine and the decisions become Rego. So nothing
//! here branches on "should we stop" — it does the work, writes down what it
//! did, and reports. A consumer wanting different rules writes different modules
//! and this code does not change.
//!
//! **That is also why the wait's LOSER is recorded.** The obvious shape writes
//! only the arm that won, and then a lap that raced properly and a lap that read
//! both answers produce identical records — so the module has nothing to decide
//! over. Writing the loser as an explicit could-not-look is what keeps the
//! property visible to something outside this file.
//!
//! The one thing it will not do is **resolve** a conflict.
//! [`crate::gitwrite::rebase`] refuses with `Rebase::Conflicted` rather than
//! taking a strategy, and this module carries that refusal outward unchanged.
//! `mem:workflow/landing-loop` gives the loop exactly one human stop and this is
//! it.
//!
//! # No `git` binary, which is the property the whole campaign exists to keep
//!
//! Every write below goes through [`crate::gitwrite`] and [`crate::lease`], which
//! speak to the odb and to the remote in process. `git.rs`'s
//! `no_second_git_invoker_exists` scans this file like every other, and it stays
//! green over a module that performs every write CLOUD-1148 §D recorded as
//! unreachable.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::gitwrite::{self, Rebase};

/// What one replay did.
///
/// Three outcomes rather than a `Result`, because none of them is an error: a
/// conflict is the mechanism working, and an already-current branch is the
/// ordinary state of a lap that has nothing to catch up on. An error here means
/// the replay could not be attempted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replay {
    /// Two sides changed the same lines. **The one human stop.** Nothing moved:
    /// the branch and the worktree are exactly as they were.
    Conflicted {
        /// The original commit that would not replay.
        commit: String,
        /// The paths that would not merge, in the order the merge reported them.
        paths: Vec<String>,
    },
    /// The branch already descended from the base, so nothing was replayed and
    /// no sha was minted — which is what keeps a still-good `verify` receipt
    /// alive for another lap.
    Current,
    /// The branch was replayed onto the moved base.
    Replayed {
        /// The sha the branch now points at.
        head: String,
        /// How many commits were replayed.
        commits: usize,
    },
}

impl Replay {
    /// The record line this outcome writes.
    ///
    /// Four columns, `rebase <verdict> <commit> <path>`, which is the layout
    /// `rebase-conflict-stops-the-lap` reads and the reason it is stated in both
    /// places rather than derived: the module is vendored into every consumer's
    /// binary and this writer is one consumer of it, so neither can be the
    /// other's authority. `crates/batten/tests/it/land.rs` holds them together.
    ///
    /// `-` IS THE COULD-NOT-LOOK SPELLING and is what an absent column carries,
    /// never an empty string — a column that collapsed to nothing would shift
    /// every column after it and be read through the wrong lens.
    ///
    /// POINTER-ONLY (non-negotiable rule 4): a sha and a path, never a hunk and
    /// never a conflict marker, which is the whole of what a conflict consists
    /// of and exactly what a reader must not be handed here.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Conflicted { commit, paths } => {
                // THE FIRST PATH, because the record has one column for it and a
                // list would need a separator this format does not have. The
                // count is not lost: the caller reports it, and the module's job
                // is to say WHERE to look first rather than to enumerate.
                let path = paths.first().map_or("-", String::as_str);
                format!("rebase conflicted {commit} {path}")
            }
            Self::Current => String::from("rebase current - -"),
            Self::Replayed { head, .. } => format!("rebase replayed {head} -"),
        }
    }
}

/// Bring `reference` forward from `remote` into this clone, and answer where it
/// now points.
///
/// Three steps that have to stay in this order and are easy to get wrong as two:
/// the objects are fetched, then WRITTEN to the odb, and only then does the ref
/// move. A ref moved before its objects landed names a commit this clone cannot
/// read, which is a corrupt clone rather than a failed fetch.
///
/// # Errors
///
/// A transport failure, a reference the remote does not advertise, or an odb that
/// will not take the objects.
fn advance(root: &Path, remote: &str, reference: &str, tracking: &str) -> Result<String> {
    let fetched = crate::lease::fetch(remote, root, reference)
        .with_context(|| format!("land: fetch {reference} from the remote"))?;
    // EMPTY IS NOT A FAILURE — `Fetched::objects` is empty when the odb already
    // had the commit, which is the common case on a quiet base. Writing an empty
    // slice is a no-op and the ref still has to move, so there is no early
    // return here.
    gitwrite::write_objects(root, &fetched.objects)
        .with_context(|| format!("land: write the objects {reference} brought"))?;
    gitwrite::set_ref(root, tracking, &fetched.head)
        .with_context(|| format!("land: move {tracking} to the fetched head"))?;
    Ok(fetched.head)
}

/// One lap's replay: advance the base, replay the branch onto it, record it.
///
/// # Errors
///
/// A fetch that will not complete, an odb that will not take what it brought, or
/// a replay that could not be attempted. **A conflict is not an error** — it is
/// [`Replay::Conflicted`], and reporting it as a failure is what would let a
/// caller's `?` turn the loop's one human stop into a stack trace.
pub fn replay(root: &Path, remote: &str, reference: &str, branch: &str) -> Result<Replay> {
    let tracking = tracking_ref(reference);
    advance(root, remote, reference, &tracking)?;

    let outcome = gitwrite::rebase(root, &format!("refs/heads/{branch}"), &tracking)
        .with_context(|| format!("land: replay {branch} onto {tracking}"))?;
    let replayed = match outcome {
        Rebase::Conflicted { commit, paths } => Replay::Conflicted { commit, paths },
        Rebase::Current => Replay::Current,
        Rebase::Replayed { head, commits } => Replay::Replayed { head, commits },
    };

    // RECORDED WHATEVER HAPPENED, INCLUDING THE CLEAN CASE. A store written only
    // on conflict cannot tell "this lap replayed cleanly" from "no lap has run",
    // and the module reads the LAST line precisely so a resolved conflict stops
    // refusing — which only works if the resolution writes a line of its own.
    record(root, branch, &replayed)?;
    Ok(replayed)
}

/// Where a remote reference is tracked locally.
///
/// `refs/heads/main` on the remote is `refs/remotes/origin/main` here. Written as
/// a function rather than formatted at the call site so the one place that
/// decides this is greppable, and so a caller cannot pass a tracking ref where a
/// remote one belongs.
fn tracking_ref(reference: &str) -> String {
    let leaf = reference.rsplit('/').next().unwrap_or(reference);
    format!("refs/remotes/origin/{leaf}")
}

/// Append this lap's outcome to the branch's record.
///
/// PUBLIC BECAUSE THE SECOND TIER HAS TO DRIVE IT. `replay` needs a real remote,
/// so a compiled-binary case cannot reach this writer through it — and a case
/// that fabricated the store instead would assert the very shape the engine may
/// be unable to produce, which is the failure `.claude/rules/policy-modules.md`
/// records for exactly this pair. `crates/batten/tests/it/land.rs` writes through
/// here and reads back through `batten check`, so the writer and the vendored
/// module meet over the engine rather than over a fixture somebody typed.
///
/// APPEND, NEVER REPLACE, because the store is a HISTORY and the predicate over
/// it reads the last line: a lap that conflicted and a later lap that resolved
/// the conflict are two facts, and a store keeping only the newer one cannot say
/// that the older was ever true. `record::store` replaces, which is right for the
/// stores that answer "what is the current state" and wrong for this one.
///
/// # Errors
///
/// A store directory or file that will not open or append.
pub fn record(root: &Path, branch: &str, outcome: &Replay) -> Result<()> {
    append(root, branch, std::slice::from_ref(&outcome.line()))
}

/// Append `lines` to this branch's lap record.
///
/// ONE WRITER FOR BOTH FAMILIES, because the store is shared: a replay outcome
/// and a wait outcome go to the same file and are told apart by their KIND
/// column, so two writers computing the path separately would be two authorities
/// over one location.
///
/// A DETACHED HEAD HAS NOTHING TO KEY ON, exactly as the claim receipt does not,
/// so the write is skipped rather than failing the lap. The work itself happened
/// either way, and turning "nowhere to write this down" into "the lap failed"
/// would report a verdict about the clone as a verdict about the branch.
///
/// ONE OPEN FOR THE WHOLE BATCH, which is what makes `record_wait`'s both-arms
/// signature mean something: a race's two lines land together or not at all,
/// rather than leaving a record with a winner and no loser — the exact shape a
/// lap reading both sides would also produce.
fn append(root: &Path, branch: &str, lines: &[String]) -> Result<()> {
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return Ok(());
    };
    let claim = crate::claim::claimed_token(&git_dir.join("batten-receipts"), branch);
    let path = crate::recorder::record_path(&git_dir, LAP_RECORD, branch, claim.as_deref());
    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)
        .with_context(|| format!("land: create the record store {}", directory.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("land: open the lap record {}", path.display()))?;
    for line in lines {
        writeln!(file, "{line}")
            .with_context(|| format!("land: append to the lap record {}", path.display()))?;
    }
    Ok(())
}

/// The record this module writes, and the one `record::VERB_WRITTEN` names so a
/// module can read it back.
pub const LAP_RECORD: &str = "lap";

/// Which arm of the lap's raced wait an answer came from (CLOUD-1338).
///
/// # The race, and why it is two arms rather than one wait
///
/// A lap asks two questions at once — *is this commit green?* and *is this
/// commit still landable?* — and whichever answers first decides. The loser's
/// answer is **voided**: the moment the base advances, the run in flight is
/// spend for a verdict nobody will read, and the next lap's push supersedes it
/// through the forge's own cancel-in-progress, which is why nothing here cancels
/// a run by hand.
///
/// The arms are named rather than numbered because the record is what
/// `lap-waits-on-one-answer` reads, and a reviewer chasing a refusal needs to
/// know WHICH question answered, not that some arm did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Is the commit green? — the check-run roster's verdict.
    Green,
    /// Has the base moved out from under it? — the staleness question.
    Stale,
}

impl Arm {
    /// The token this arm writes into the record's second column.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Stale => "stale",
        }
    }
}

/// One arm's answer, or its silence.
///
/// **A LOSER IS RECORDED, AND RECORDING IT IS THE POINT.** The obvious shape is
/// to write down only the arm that won — and then a lap that read both is
/// indistinguishable from a lap that raced properly, because the record looks
/// the same either way. Writing the loser as an explicit could-not-look is what
/// makes the difference legible to a module: two answers is a defect, one answer
/// beside one silence is the design working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    /// Which question this is.
    pub arm: Arm,
    /// What it answered, or `None` where it was abandoned unread — the loser of
    /// the race, or a poller that could not reach the forge.
    pub verdict: Option<String>,
    /// The commit the question was about.
    pub sha: String,
}

impl Answered {
    /// The record line this answer writes.
    ///
    /// Four columns, `wait <arm> <verdict> <sha>`, which is the layout
    /// `lap-waits-on-one-answer` reads. Stated in both places rather than derived
    /// for the reason its sibling gives: the module is vendored into every
    /// consumer's binary and this writer is one consumer of it, so neither can be
    /// the other's authority.
    ///
    /// POINTER-ONLY (rule 4): an arm token, a verdict token and a sha. Never a
    /// check's log body, and never the forge's payload.
    #[must_use]
    pub fn line(&self) -> String {
        let verdict = self.verdict.as_deref().unwrap_or("-");
        format!("wait {} {verdict} {}", self.arm.token(), self.sha)
    }
}

/// How a lap's wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waited {
    /// The green question answered first: every required check is terminal.
    Green {
        /// The forge's verdict, as a token.
        verdict: String,
    },
    /// The staleness question answered first: the base moved, so the run in
    /// flight is already spend for a verdict nobody will read.
    Stale {
        /// Where the base points now.
        base: String,
    },
    /// Neither question answered inside the lap's bound.
    ///
    /// **Exit `3`'s reading, and not an error.** A wait that ran out of asks has
    /// learned nothing, which is a different state from either answer and from a
    /// failure — the caller laps again rather than concluding anything.
    Unanswered,
}

/// Ask both questions concurrently and take whichever answers first.
///
/// # The race is a race
///
/// Two arms, each its own conditional poll, run in a [`std::thread::scope`] and
/// report through one channel; the first message decides the lap. `ci-wait ∥
/// main-watch` is what the predecessor did and the reason is economic: the
/// moment `main` advances, the run in flight is already waste — its verdict
/// cannot be used, the fast-forward bot will refuse, and every remaining second
/// of that run is billed. Learning that only after the green arm's round trip
/// costs a lap.
///
/// **AN EARLIER REVISION OF THIS FUNCTION ALTERNATED THE ARMS IN ONE LOOP AND
/// ARGUED THAT WAS STRICTLY BETTER. IT WAS NOT.** The argument ran: a scoped join
/// would hang on the loser and a detached one would keep spending rate limit, so
/// alternating is the only shape available without a second authority. Both
/// halves are answered by the shape below rather than by taste. The loser is not
/// joined-while-blocked: it checks [`std::sync::atomic::AtomicBool`] at its own
/// interval boundary, which is a bounded wait it was already taking, so the scope
/// closes without hanging. And it spends nothing after the winner speaks,
/// because it stops asking — the flag is read before the request, never after.
///
/// The alternating loop also serialised the two round trips, so the staleness
/// answer was always at least one green-arm round trip late. That is the latency
/// the race exists to remove.
///
/// # The bound is a COUNT
///
/// `asks` is how many times each arm asks, never a deadline. A wall clock would
/// reintroduce the VM-reap gap `mem:workflow/landing-loop` records, and
/// `clippy.toml`'s timer ban is the mechanism that refuses one in this crate. The
/// delay between asks is the server's own interval — a derived delay bounded by a
/// real exit condition, which is the shape `run-shape-guard` admits.
///
/// # Errors
///
/// Only for a stream that will not accept output. **Every failure to reach the
/// forge is a could-not-look**: the arm reports nothing that cycle and asks
/// again, because a lap that concluded from an unreachable forge would decide
/// about the network rather than about the work.
pub fn wait(
    config: &crate::pr_watch::Config,
    roster: &crate::checks_green::Roster,
    trunk: &crate::main_watch::Config,
    asks: u32,
    out: &mut dyn std::io::Write,
) -> Result<Waited> {
    writeln!(
        out,
        "land: waiting on {} — green or stale, whichever answers first",
        config.sha
    )?;

    // ONE CHANNEL, NOT TWO RETURN VALUES. The first message IS the verdict, so
    // the loser's answer is voided by construction rather than by the caller
    // remembering to drop it — the property the alternating loop was defending,
    // kept.
    let (tx, rx) = std::sync::mpsc::channel::<Waited>();
    let decided = std::sync::atomic::AtomicBool::new(false);

    let waited = std::thread::scope(|scope| {
        let green = tx.clone();
        let stop = &decided;
        drop(scope.spawn(move || {
            let mut poll = crate::pr_watch::Poll::default();
            for _ in 0..asks {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                // The conditional read is `pr_watch`'s, so the argv, the client
                // and the empty-string-on-failure posture stay its business and
                // this arm only decides when to ask.
                let raw = crate::pr_watch::read(config, poll.etag());
                let interval = poll.absorb(&raw, config.interval);
                if let Ok(crate::checks_green::Verdict::Green) =
                    crate::checks_green::decide(poll.runs(), roster)
                {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    drop(green.send(Waited::Green {
                        verdict: String::from("green"),
                    }));
                    return;
                }
                crate::pr_watch::pause(interval);
            }
        }));

        let stale = tx.clone();
        drop(scope.spawn(move || {
            let mut poll = crate::main_watch::Poll::default();
            for _ in 0..asks {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let raw = crate::main_watch::read(trunk, poll.etag());
                let interval = poll.absorb(raw.as_ref(), trunk.interval);
                if let Some(moved) = poll.moved(&trunk.base) {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    drop(stale.send(Waited::Stale {
                        base: moved.to_owned(),
                    }));
                    return;
                }
                // `pr_watch`'s pause deliberately, not a second one: there is one
                // sleep in this crate and it carries the one `disallowed_methods`
                // exemption, so a second arm cannot grow a timer of its own.
                crate::pr_watch::pause(interval);
            }
        }));

        // THE LAST LIVE SENDER MUST BE DROPPED OR THE RECV BELOW NEVER RETURNS.
        // Both arms exhausting `asks` without answering closes their clones; this
        // one is the outer handle and would keep the channel open forever.
        drop(tx);
        rx.recv().ok()
    });

    Ok(waited.unwrap_or(Waited::Unanswered))
}

/// Both arms of one wait, from whichever of them answered.
///
/// **THE SIGNATURE IS THE MECHANISM.** A caller cannot build one arm and forget
/// the other: it hands in what each question said — `None` where a question was
/// abandoned unread — and gets the pair back. The alternative, letting the caller
/// assemble a `Vec`, is what makes recording only the winner writable, and a
/// record with a winner and no loser is byte-identical to what a lap that read
/// BOTH sides produces. `lap-waits-on-one-answer` would then have nothing to
/// tell the two apart, which is the whole property.
///
/// Both arms always appear, so the count of ANSWERING arms is what varies and
/// the module's reading of it is meaningful.
#[must_use]
pub fn answers(sha: &str, green: Option<&str>, stale: Option<&str>) -> Vec<Answered> {
    vec![
        Answered {
            arm: Arm::Green,
            verdict: green.map(ToOwned::to_owned),
            sha: sha.to_owned(),
        },
        Answered {
            arm: Arm::Stale,
            // THE STALE ARM'S VERDICT IS A TOKEN, NEVER THE NEW BASE. The sha it
            // moved to is a pointer a reader may want, but this column is what
            // the module compares against `-`, so it stays a closed vocabulary.
            verdict: stale.map(|_| String::from("moved")),
            sha: sha.to_owned(),
        },
    ]
}

/// Append this wait's outcomes to the branch's record.
///
/// BOTH ARMS IN ONE CALL, so a caller cannot write the winner and forget the
/// loser — which would produce exactly the record a lap reading both sides
/// produces, and make the module unable to tell them apart. The signature is the
/// mechanism: there is no way to record half a race.
///
/// # Errors
///
/// A store directory or file that will not open or append.
pub fn record_wait(root: &Path, branch: &str, answers: &[Answered]) -> Result<()> {
    append(
        root,
        branch,
        &answers.iter().map(Answered::line).collect::<Vec<_>>(),
    )
}

/// What the lap's push did to the branch's own ref on the remote.
///
/// # A lost race is an OUTCOME, never an error
///
/// [`crate::lease::push`] speaks receive-pack's own compare-and-swap, so the
/// server applies the update only while the ref still reads what the
/// advertisement said — decided under the server's lock rather than against
/// whatever this clone last saw. Losing that is the fleet working: somebody else
/// pushed the same branch between the advertisement and the update, and the
/// answer is another lap rather than a failure.
///
/// That is why `Raced` is a variant here and not an `Err`. A lap that reported a
/// lost CAS as an error would stop for something the loop already knows how to
/// resolve, and the ONE human stop is a rebase conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    /// The remote took the update; its ref now reads this sha.
    Landed(String),
    /// The ref moved under the push and the server refused. Lap again.
    Raced,
}

impl Pushed {
    /// The record line this outcome writes.
    ///
    /// Four columns, `push <verdict> <sha> <path>`, the same layout every other
    /// family in this store uses, so a module reading the store narrows on
    /// column zero and never on a line's arity. The fourth column is always `-`:
    /// a push has no path to point at, and a family with three columns would
    /// shift every reader that split on four.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Landed(sha) => format!("push landed {sha} -"),
            Self::Raced => String::from("push raced - -"),
        }
    }
}

/// Push this branch to its own ref on `remote`, and record what happened.
///
/// The object set is `lease::push`'s: the remote's ADVERTISED value is the
/// subtraction base, so a branch this clone just replayed sends the commits the
/// remote lacks rather than either re-sending settled history or, worse, sending
/// too little because the base was guessed locally.
///
/// # Errors
///
/// A transport failure, an unreadable report, or a HEAD this clone cannot
/// resolve. A rejected update is [`Pushed::Raced`] rather than an error.
pub fn push(root: &Path, remote: &str, branch: &str) -> Result<Pushed> {
    let head = crate::git::head_commit(root).context("land: read this clone's HEAD")?;
    let reference = format!("refs/heads/{branch}");
    let outcome = crate::lease::push(remote, root, &reference, &head)
        .with_context(|| format!("land: push {reference}"))?;
    let pushed = match outcome {
        crate::lease::Outcome::Applied => Pushed::Landed(head),
        // THE SERVER'S REASON IS DROPPED HERE DELIBERATELY. It is a pointer for
        // a reader on the lease's own path, and this store is read by a
        // predicate: a free-form string in a fixed-column record is a channel
        // for prose to travel down, which rule 4 refuses.
        crate::lease::Outcome::Rejected { .. } => Pushed::Raced,
    };
    append(root, branch, std::slice::from_ref(&pushed.line()))?;
    Ok(pushed)
}

/// What the lap's verification said about this head.
///
/// # The engine does not know what "verify" means here
///
/// A lap verifies by running the consumer's own gate, and the NAME of that gate
/// is the consumer's — `mise run verify` in this repository, something else
/// everywhere else. Non-negotiable rule 1 puts that name outside `crates/batten`
/// entirely, so the command arrives as argv the caller resolved and this module
/// never composes one.
///
/// # And it spawns nothing itself
///
/// [`crate::exec::run_in`] is the sanctioned child-process boundary and is
/// already placed in `policy/spawn-adapters.rego`; routing through it is what
/// keeps `land` off that table. A `Command::new` here would be a second spawning
/// site for a job the boundary already does, which is what the placement rule
/// exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// The gate answered clean for this sha.
    Clean(String),
    /// The gate refused. The lap stops here — this is a failed `verify`, which
    /// the design names as one of the three things that end a lap.
    Refused(String),
}

impl Verified {
    /// The record line this outcome writes.
    ///
    /// Four columns, `verify <verdict> <sha> <path>`, the store's shape. The
    /// fourth is always `-`: a verdict about a whole tree has no one path to
    /// point at, and inventing one would be worse than the dash.
    ///
    /// POINTER-ONLY. The gate's own output is not carried at any width — it went
    /// to the caller's terminal where it belongs, and a record read by a
    /// predicate is no place for a test runner's stdout.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Clean(sha) => format!("verify clean {sha} -"),
            Self::Refused(sha) => format!("verify refused {sha} -"),
        }
    }
}

/// Run the consumer's gate over this head and record what it said.
///
/// `command` is argv the CALLER resolved, for the reason [`Verified`] states.
/// An empty one is a usage error rather than a default, because guessing a
/// consumer's gate would put that consumer's vocabulary in this crate.
///
/// # Errors
///
/// An empty command, a HEAD this clone cannot resolve, or a boundary that cannot
/// start the program. A gate that RAN and refused is [`Verified::Refused`], not
/// an error: that is an answer about the tree.
pub fn verify(root: &Path, branch: &str, command: &[String]) -> Result<Verified> {
    if command.is_empty() {
        return Err(crate::error::UsageError::raise(String::from(
            "land: no verify command is configured, and this engine does not know what verifying means here",
        )));
    }
    let head = crate::git::head_commit(root).context("land: read this clone's HEAD")?;
    // THE RESOLVED ROOT, NEVER THE ANCHOR — and this is the only call
    // `exec::run_in` has, so getting it wrong made the verb unreachable rather
    // than merely awkward. `exec`'s capture store is keyed by the repository's
    // own directory NAME, which `state::derive_repo_name` cannot read off `.`;
    // every caller above anchors at `.`, so handing that straight through raised
    // "cannot derive a repository name from ." on EVERY invocation in every
    // clone. `exec::run_with` resolves at its own site for exactly this reason,
    // as do `admission::store_dir` and `lib::run_board`. This was the fourth
    // site and the only one that did not.
    //
    // IT WAS INVISIBLE TWICE OVER, which is why the fix is a resolution here
    // rather than a message: the refusal is a `UsageError`, so `main`'s reporter
    // prints one clean line and drops the chain, and the `None` arm below then
    // wrapped it in a context naming the gate — so a boundary that never started
    // the program read as the program having run and failed. `LAND_VERIFY=true`
    // and `LAND_VERIFY=false` were byte-identical.
    let started = crate::git::repo_root(root).context("land: resolve this clone's root")?;
    // A REFUSAL TRAVELS AS AN ERROR THROUGH THIS BOUNDARY, because `exec` exists
    // to pass a child's status through to the caller. Here it is an ANSWER, so
    // the two are told apart rather than collapsed: a code that came back at all
    // is the gate speaking, and only a failure to START is this lap's problem.
    let verified = match crate::exec::run_in(&started, command) {
        Ok(crate::exit::ExitCode::Success) => Verified::Clean(head),
        Ok(_) => Verified::Refused(head),
        Err(problem) => match problem.downcast_ref::<crate::error::Passthrough>() {
            Some(_) => Verified::Refused(head),
            None => return Err(problem.context("land: run the configured verify command")),
        },
    };
    append(root, branch, std::slice::from_ref(&verified.line()))?;
    Ok(verified)
}

/// Has the base moved since this lap replayed onto it?
///
/// # Why this exists between the gate and the push
///
/// A gate runs for minutes, and on a busy trunk that is long enough for the base
/// this lap replayed onto to move. The lap then pushes a head that can no longer
/// fast-forward, CI grades it, and the whole matrix is spent learning what one
/// ref read already knew. The predecessor measured the steady state at ~45% of
/// laps paying a full gate to discover trunk had moved (CLOUD-423), and answered
/// it by RACING the gate against a watcher so the gate could be aborted early.
///
/// **This is the cheaper half of that, and the difference is stated rather than
/// absorbed.** It does not abort the gate — the gate runs to completion and its
/// result is then discarded if the base moved. So the gate's minutes are still
/// spent where the predecessor could reclaim them; what is saved is the CI matrix
/// and the fast-forward round trip behind it, which is the metered half. Aborting
/// early needs a poller that can be stopped mid-wait; [`wait`] now has that shape
/// (a scoped pair over a stop flag), and applying it to the GATE is a different
/// problem — the gate is a spawn, not a poll — so CLOUD-423's other half stays
/// open rather than being claimed here.
///
/// # ONE ASK, THROUGH THE CONDITIONAL ENDPOINT
///
/// This is [`crate::main_watch`]'s poll asked exactly once, not ref discovery. A
/// single unconditional ref advertisement is affordable in isolation — that is
/// what made an earlier revision of this function look fine — but it is the same
/// question [`wait`] asks in a loop, and answering one question two ways is how
/// the two readings drift. The first ask carries no validator and costs a full
/// body; every later lap's does, because the [`crate::main_watch::Poll`] is the
/// lap's.
///
/// # It fails OPEN, unlike every gate in this module
///
/// A read that did not answer is not evidence the base moved, and this is an
/// ECONOMY rather than a gate: refusing to push because the forge hiccuped would
/// stop a landing to save a matrix, which is the wrong trade in the wrong
/// direction. `None` therefore means "carry on" for both *unmoved* and *could not
/// look*, and the two are deliberately one reading here.
#[must_use]
pub fn stale(root: &Path, trunk: &crate::main_watch::Config, reference: &str) -> Option<String> {
    let tracking = tracking_ref(reference);
    // The base this lap actually replayed onto, read from the ref `advance` set
    // rather than passed down through five signatures. Local, so it costs nothing
    // and cannot itself fail to reach anybody.
    let replayed_onto = crate::git::resolve_ref(root, &tracking).ok()??;
    let mut poll = crate::main_watch::Poll::default();
    poll.absorb(
        crate::main_watch::read(trunk, None).as_ref(),
        trunk.interval,
    );
    poll.moved(&replayed_onto).map(ToOwned::to_owned)
}

/// One step of the lap, named so the table below reads as a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// Advance the base and replay this branch onto it.
    Replay,
    /// Run the consumer's gate over this head.
    Verify,
    /// Ask the gates that read the pull request's BODY, then commit to review.
    ///
    /// **A step of its own rather than a clause inside the push**, because it is
    /// where a lap stops being free: readying is what starts CI, so it is the one
    /// site that buys a matrix and the last place a refusal costs nothing. The
    /// bash ran these three gates BEFORE its own conditional ready block, for
    /// the same reason stated the other way round: a lap that happened not to
    /// re-ready must not be a way through.
    Ready,
    /// Push under receive-pack's compare-and-swap.
    Push,
    /// Race green against stale and act on whichever answers.
    Wait,
    /// Ask the bot to land this head, and read the keyed answer.
    FastForward,
}

/// What the lap does once a step has answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Progress {
    /// Carry on to the next step of this lap.
    Proceed,
    /// Lap again. The base moved, or the answer is not in yet.
    Lap,
    /// Stop, carrying the step's own code. A human owns this one.
    Stop,
    /// The head is on the landing target.
    Landed,
}

/// What a lap does with `code` from `step`.
///
/// # This is the whole design, as one table
///
/// The split is **whether a rebase would clear the refusal**, and nothing else:
///
/// * A **conflict** and a **refused gate** stop. Both are decisions a human
///   owns, and lapping re-runs them against the same commits to reach the same
///   answer — paying a full gate each time. Lapping OFTEN is what keeps the
///   conflict small; lapping over one is what makes it pointless.
/// * A **raced push**, a **stale base**, an **unanswered wait**, and a
///   **refused or unreadable fast-forward** all lap. Every one means the base
///   moved or nobody has answered yet, and the next lap's replay is the remedy.
///
/// # Why a refused fast-forward laps rather than stopping
///
/// It looks like a verdict and is not. The bot refuses when the head stopped
/// being a direct descendant — which is a fact about the BASE having moved, so
/// it is staleness wearing a refusal's clothes. Reading it as a stop would halt
/// a branch whose only problem is that trunk advanced.
///
/// The mirror mistake is the one CLOUD-413 measured: every non-success
/// conclusion was narrated as "main moved" across 24 laps of one landing, and
/// that diagnosis was wrong twice over — 7 of 8 laps in one run reached green CI,
/// and several refusals were the rate limit rather than trunk. So the two
/// READINGS stay apart (only the staleness arm may assert trunk moved) while
/// their REMEDY is the same lap.
///
/// # A step's own usage or internal code is never the lap's
///
/// An unconfigured gate is a usage error about this clone, and a forge that
/// cannot be read is a could-not-look. Neither is a verdict about the branch, so
/// both stop carrying their own code rather than being laundered into a lap that
/// would ask the same unanswerable question again.
/// # Usage always stops, and could-not-look depends on the step
///
/// `Usage` is a misconfiguration of this clone — an unnamed gate, an unnamed
/// workflow — so every step stops on it. Lapping would ask the same
/// unanswerable question again, which is the CLOUD-235 hang with a tidier
/// cause.
///
/// `Internal` is could-not-look, and it means two different things depending on
/// who said it. From `replay`, `verify` or `push` it is a clone or a remote this
/// lap cannot read, and there is nothing to lap toward. From `wait` and
/// `fast-forward` it is the loop's ORDINARY state — nobody has answered yet —
/// so it laps, which is the whole reason exit `3` is a first-class outcome on
/// those two rather than an error.
#[must_use]
pub const fn progress(step: Step, code: crate::exit::ExitCode) -> Progress {
    use crate::exit::ExitCode::{Internal, Success, Usage, Violation};
    match (step, code) {
        // Four of the five steps answering cleanly only means the lap may go on;
        // the fifth is the one that ends it.
        (Step::Replay | Step::Verify | Step::Ready | Step::Push | Step::Wait, Success) => {
            Progress::Proceed
        }
        (Step::FastForward, Success) => Progress::Landed,

        // LAPS. A raced push is the first place the base can move under a lap
        // that had already replayed — receive-pack's CAS is what noticed, and the
        // next replay is what fixes it. A stale base and an unanswered wait are
        // the same lap for different reasons, and a refused fast-forward joins
        // them because the bot refuses on a head that stopped descending, which
        // is a fact about the base.
        (Step::Push, Violation) | (Step::Wait | Step::FastForward, Violation | Internal) => {
            Progress::Lap
        }

        // STOPS. The replay and the gate both answer about THIS tree, so a
        // refusal from either is a decision no rebase clears. A push that could
        // not look reached a remote it cannot read, which is a clone problem
        // rather than a race. And `Usage` stops everywhere: a gate or a workflow
        // this clone never named is not a question another lap can answer.
        // The ready gates read the pull request's BODY, so a refusal is a
        // statement about what the author wrote — a deferral with no ticket, a
        // key the merge will not close. No rebase clears prose, which puts it
        // beside the replay and the gate rather than beside the push.
        (Step::Replay | Step::Verify | Step::Ready, Violation | Internal)
        | (Step::Push, Internal)
        | (_, Usage) => Progress::Stop,
    }
}

/// The gate invocations a ready phase runs, decoded from one declared string.
///
/// `|`-separated argvs, each space-separated words. **Both the runner and the
/// task names are the CONSUMER's** — a task name inside `crates/batten` is
/// non-negotiable rule 1's plainest violation, and a compiled-in default would
/// be one with extra steps. The separator is `|` rather than `,` because an argv
/// contains spaces and a comma would make one argv per word.
///
/// Empty entries are dropped rather than becoming an empty argv: a trailing
/// separator is a typo, not a gate, and [`ready`] treats an unrunnable gate as a
/// refusal — so an empty argv would stop every lap on a stray character.
#[must_use]
pub fn body_gates(declared: &str) -> Vec<Vec<String>> {
    declared
        .split('|')
        .map(|entry| {
            entry
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|argv| !argv.is_empty())
        .collect()
}

/// What a ready phase decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readied {
    /// Every declared gate passed, or there was no body to judge.
    Clear,
    /// A gate refused, naming itself.
    Refused {
        /// The gate's own first word, which is the pointer a reader follows.
        gate: String,
        /// What the gate printed. Its own report, forwarded rather than
        /// summarised — the gate is the authority on its own finding.
        detail: String,
    },
    /// A declared gate could not be run at all.
    ///
    /// **A REFUSAL, NOT A PASS**, and that is the whole reason this variant is
    /// distinct from [`Readied::Clear`]. A declared gate that cannot run is the
    /// dead-gate class this engine exists to refuse, and the bash agreed by
    /// construction: `mise run <task>` for a task that does not exist exits
    /// non-zero, which was a stop.
    Unrunnable {
        /// The gate that would not run.
        gate: String,
    },
}

/// Run the declared body gates over `body`.
///
/// # An empty body is a PASS, and that is the predecessor's posture
///
/// The body is fetched from the forge, and a fetch that failed is not evidence
/// about what the author wrote: these gates are about what a body SAYS, and one
/// they never saw says nothing. The bash spelled it `[[ -n "$body" ]] && ! gate`
/// — the gate simply does not run. Reading a failed fetch as a refusal would
/// stop every lap on a network blip.
///
/// # An unrunnable gate is a REFUSAL
///
/// The opposite direction, and both are the predecessor's. `mise run <task>` for
/// a task that does not exist exits non-zero, so the bash stopped — and it is the
/// right way round: a gate that cannot run has not passed, and treating it as
/// clean is exactly how a retired or renamed gate goes silently dead.
#[must_use]
pub fn ready(root: &Path, gates: &[Vec<String>], body: &str) -> Readied {
    if body.trim().is_empty() {
        return Readied::Clear;
    }
    for argv in gates {
        let Some(gate) = argv.first().cloned() else {
            continue;
        };
        let Some((code, output)) = crate::exec::piped_argv(root, argv, body) else {
            return Readied::Unrunnable { gate };
        };
        if code != 0 {
            return Readied::Refused {
                gate,
                detail: output.trim().to_owned(),
            };
        }
    }
    Readied::Clear
}

/// Which bound a charge ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// Never won the lease. The fleet is saturated — and this is the ONE
    /// exhaustion that has spent no CI at all, which is why a caller reports it
    /// differently: a `land-lock-check` tells a saturated fleet apart from a
    /// wedged lease, and they look identical from inside the loop.
    LeaseWaits,
    /// The fast-forward bot gave no readable answer. Nothing about the branch is
    /// wrong and `main` has not moved under it.
    Unknowns,
    /// CI failed before reaching a verdict, repeatedly. Past this bound it is not
    /// a flake any more: the provisioning path is broken, and re-running would
    /// spend jobs to learn the same thing.
    Transients,
}

/// What a charge decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// Inside the bound; the lap goes round again.
    Lap,
    /// The bound is spent.
    Stop(Bound),
}

/// A lap's accounting.
///
/// # SPEND IS COUNTED, NEVER INFERRED FROM THE ATTEMPT COUNTER
///
/// [`Ledger::laps`] and [`Ledger::paid`] look interchangeable and are not, and
/// the difference was measured rather than reasoned. The inference — "every lap
/// that bought no CI is refunded, so the lap counter IS the spend" — fails in
/// both directions.
///
/// There are FIVE refund sites, not the three CLOUD-904 named: the two in the
/// lease wait, bot silence, an absorbed transient, and the admitted-successor
/// push. And they still miss the ordinary case: a lap where `main` moves while
/// the gate runs aborts before the ready, buys nothing, and is charged anyway.
///
/// Measured on PR #651 while landing the change that fixed it — two laps, both
/// lost to `main` moving under the gate, the ready never reached, ZERO check-runs
/// on the head — and the refusal announced "having spent 2 CI matrices". So
/// `laps` is an attempt counter and nothing more; `paid` is the spend,
/// incremented at the ONE site that buys one.
///
/// # Counts, never clocks
///
/// Every bound here is a count. `clippy.toml` bans the sleeps that would let one
/// become a deadline, and `tests/sleep_ban.rs` holds each `reason` to a named
/// bound — a wall clock would reintroduce the VM-reap gap
/// `mem:workflow/landing-loop` records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ledger {
    /// Attempts. Bounded by the caller's lap maximum as a runaway backstop.
    pub laps: u32,
    /// CI matrices actually bought.
    pub paid: u32,
    /// Passes that never won the lease.
    pub lease_waits: u32,
    /// Passes that got no readable answer from the bot.
    pub unknowns: u32,
    /// Runs that failed before reaching a verdict.
    pub transients: u32,
}

impl Ledger {
    /// Open a lap.
    pub const fn attempt(&mut self) {
        self.laps = self.laps.saturating_add(1);
    }

    /// A matrix was bought. **The one site that increments this.**
    pub const fn bought_a_matrix(&mut self) {
        self.paid = self.paid.saturating_add(1);
    }

    /// A pass that never won the lease: refund the lap, charge the wait.
    ///
    /// The refund is what keeps a saturated fleet from exhausting a budget that
    /// exists to catch "main moves faster than a lap takes" — and from reporting
    /// THAT diagnosis, which CLOUD-413 measured being wrong twice over across 24
    /// laps.
    pub const fn waited(&mut self, max: u32) -> Charge {
        self.laps = self.laps.saturating_sub(1);
        self.lease_waits = self.lease_waits.saturating_add(1);
        if self.lease_waits > max {
            Charge::Stop(Bound::LeaseWaits)
        } else {
            Charge::Lap
        }
    }

    /// A pass the bot gave no readable answer to.
    ///
    /// The same shape as [`Ledger::waited`] for the same reason: the pass spent
    /// nothing. An unknown re-ask laps, and on an unmoved `main` that lap is free
    /// by construction — the receipt short-circuits on the unchanged HEAD, the
    /// head already graded so neither re-fire can fire, and a force-push that
    /// moves nothing emits no event and buys no run.
    pub const fn unknown(&mut self, max: u32) -> Charge {
        self.laps = self.laps.saturating_sub(1);
        self.unknowns = self.unknowns.saturating_add(1);
        if self.unknowns > max {
            Charge::Stop(Bound::Unknowns)
        } else {
            Charge::Lap
        }
    }

    /// A run that failed before reaching a verdict.
    pub const fn transient(&mut self, max: u32) -> Charge {
        self.laps = self.laps.saturating_sub(1);
        self.transients = self.transients.saturating_add(1);
        if self.transients > max {
            Charge::Stop(Bound::Transients)
        } else {
            Charge::Lap
        }
    }

    /// What a refusal may honestly say was spent.
    #[must_use]
    pub const fn spent(&self) -> u32 {
        self.paid
    }
}

/// Was this head's CI failure a provisioning transient rather than a verdict?
///
/// `records` is one line per failed run, as the non-verdict scanner reported them.
/// **A run is absorbed only if EVERY record is a non-verdict**: one line naming a
/// verdict means the branch was judged, and re-running would spend jobs to
/// re-learn a real refusal.
///
/// `None` for could-not-look, and the three causes are deliberately one reading:
/// no failed runs, a scan that produced nothing, and a scan that answered. A
/// caller cannot act differently on which, and inventing a distinction would
/// invite one to.
#[must_use]
pub fn absorbed(records: &[String]) -> Option<Vec<String>> {
    let lines: Vec<&str> = records
        .iter()
        .flat_map(|record| record.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }
    if lines.iter().any(|line| line.starts_with("verdict")) {
        return None;
    }
    Some(
        lines
            .iter()
            .filter(|line| line.starts_with("nonverdict"))
            .map(|line| (*line).to_owned())
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// CLOUD-900 / CLOUD-1338: abandoning the matrix a red check made worthless.
// ---------------------------------------------------------------------------

/// One run still spending on a head, as the pair the decision needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spending {
    /// The run id, for the cancel endpoint.
    pub id: String,
    /// The workflow file it came from — what the fan-in is recognised by.
    pub path: String,
}

/// What one abandon pass did. Counts, never a log line from a cancelled run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Abandoned {
    /// Runs this pass asked the forge to stop.
    pub cancelled: u32,
    /// Runs deliberately left alone.
    pub spared: u32,
    /// Cancellations the forge refused. Not a stop: those minutes bill out.
    pub refused: u32,
}

/// Which runs on a head a red verdict makes worthless, sparing the fan-in's.
///
/// **THE FAN-IN'S RUN IS NEVER CANCELLED, and that is the whole safety
/// property.** `final` is the one context branch protection requires; it is
/// `always()` over a `needs:` assertion, so cancelling its run leaves that
/// context `cancelled` — which is not an answer, and buys a branch that can
/// never grade and never land. The predecessor states it at length and this
/// conserves it exactly.
///
/// Split from the forge calls so the decision is testable without a network,
/// which is the same split [`crate::lease::decide`] makes for the staleness
/// read.
#[must_use]
pub fn worthless(spending: &[Spending], fanin: &str) -> (Vec<Spending>, u32) {
    let mut spared = 0;
    let doomed = spending
        .iter()
        .filter(|run| {
            if run.path == fanin {
                spared += 1;
                return false;
            }
            true
        })
        .cloned()
        .collect();
    (doomed, spared)
}

/// The runs still in flight on `sha`, read from the forge.
///
/// **`status != "completed"` is the whole filter**, and it is the
/// predecessor's: a run that has already finished bills nothing further, so
/// asking to cancel it is a call that buys nothing.
///
/// `None` is could-not-look. Every failure here is best-effort by contract —
/// the caller is on its way to reporting the real failure, and a cleanup step
/// that could not reach the forge must not replace that message with its own.
#[must_use]
pub fn spending(repo: &str, sha: &str) -> Option<Vec<Spending>> {
    let answer = crate::rest::get(
        &format!("repos/{repo}/actions/runs?head_sha={sha}&per_page=100"),
        None,
    )?;
    let document = serde_json::from_str::<serde_json::Value>(&answer.body).ok()?;
    let runs = document.get("workflow_runs")?.as_array()?;
    Some(
        runs.iter()
            .filter(|run| {
                run.get("status").and_then(serde_json::Value::as_str) != Some("completed")
            })
            .filter_map(|run| {
                let id = run.get("id")?;
                let id = id
                    .as_u64()
                    .map(|found| found.to_string())
                    .or_else(|| id.as_str().map(str::to_owned))?;
                let path = run.get("path")?.as_str()?.to_owned();
                Some(Spending { id, path })
            })
            .collect(),
    )
}

/// Cancel every run a red verdict made worthless, sparing the fan-in's.
///
/// **BEST-EFFORT THROUGHOUT AND NEVER A VERDICT.** A refused cancellation costs
/// the minutes it would have saved and changes no conclusion, so nothing here
/// stops and the count is reported rather than raised.
///
/// **NOT "cancelling somebody else's runs".** A head sha is one no other branch
/// has, so the blast radius is one push's worth of runs by construction rather
/// than by filtering — the same argument the lease guard's own cancel carries.
#[must_use]
pub fn abandon(repo: &str, sha: &str, fanin: &str) -> Abandoned {
    let Some(in_flight) = spending(repo, sha) else {
        return Abandoned::default();
    };
    let (doomed, spared) = worthless(&in_flight, fanin);
    let mut report = Abandoned {
        spared,
        ..Abandoned::default()
    };
    for run in doomed {
        if crate::rest::post(&format!("repos/{repo}/actions/runs/{}/cancel", run.id)) {
            report.cancelled += 1;
        } else {
            report.refused += 1;
        }
    }
    report
}

#[cfg(test)]
mod lap_tests {
    use super::{Progress, Step, progress};
    use crate::exit::ExitCode::{Internal, Success, Usage, Violation};

    /// **The discriminating claim: a refusal a rebase would clear laps, and one
    /// it would not stops.**
    ///
    /// Asserted as the whole table rather than as two cases, because the design
    /// is the SPLIT rather than either side of it. A version that lapped on
    /// everything and a version that stopped on everything both satisfy any
    /// single case here; only the pairing rules both out.
    #[test]
    fn a_refusal_a_rebase_would_clear_laps_and_one_it_would_not_stops() {
        // Stops: the tree's own answer. Lapping re-runs a gate against the same
        // commits to reach the same verdict, paying it again each time.
        assert_eq!(progress(Step::Replay, Violation), Progress::Stop);
        assert_eq!(progress(Step::Verify, Violation), Progress::Stop);

        // Laps: the base moved, or nobody has answered. The next replay is the
        // remedy for all three.
        assert_eq!(progress(Step::Push, Violation), Progress::Lap);
        assert_eq!(progress(Step::Wait, Violation), Progress::Lap);
        assert_eq!(progress(Step::FastForward, Violation), Progress::Lap);
    }

    /// A refused fast-forward is staleness wearing a refusal's clothes.
    ///
    /// The bot refuses when the head stopped being a direct descendant, which is
    /// a fact about the BASE. Stopping on it would halt a branch whose only
    /// problem is that trunk advanced — and the mirror error, reading every
    /// non-success as "main moved", is what CLOUD-413 measured going wrong twice
    /// over across 24 laps. The readings stay apart; the remedy is one lap.
    #[test]
    fn a_refused_fast_forward_laps_because_it_is_a_fact_about_the_base() {
        assert_eq!(progress(Step::FastForward, Violation), Progress::Lap);
        assert_ne!(progress(Step::FastForward, Violation), Progress::Stop);
    }

    /// Could-not-look means two different things, and which step said it decides.
    ///
    /// From `wait` and `fast-forward` it is the loop's ordinary state — exit `3`
    /// is first-class on those two. From the other three it is a clone or a
    /// remote this lap cannot read, and there is nothing to lap toward.
    #[test]
    fn could_not_look_laps_only_where_it_means_nobody_has_answered_yet() {
        assert_eq!(progress(Step::Wait, Internal), Progress::Lap);
        assert_eq!(progress(Step::FastForward, Internal), Progress::Lap);

        assert_eq!(progress(Step::Replay, Internal), Progress::Stop);
        assert_eq!(progress(Step::Verify, Internal), Progress::Stop);
        assert_eq!(progress(Step::Push, Internal), Progress::Stop);
    }

    /// **The freshness probe fails OPEN, which is the opposite of every gate in
    /// this module and is the whole of its correctness.**
    ///
    /// It is an economy, not a gate: it exists to avoid spending a CI matrix on
    /// a head whose base moved. A ref read that did not answer is not evidence
    /// the base moved, so reading could-not-look as "stale" would stop a landing
    /// to save a matrix — the wrong trade in the wrong direction, and the one a
    /// fail-closed reading makes by default.
    ///
    /// Driven over a path that is not a repository, which is the strongest form
    /// of could-not-look this suite can produce without a network: `resolve_ref`
    /// cannot answer and the conditional read reaches no forge.
    #[test]
    fn the_freshness_probe_reads_could_not_look_as_carry_on_rather_than_as_stale() {
        let dir = std::env::temp_dir().join("batten-land-stale-no-remote");
        let trunk = crate::main_watch::Config {
            repo: String::from("nobody/nothing"),
            branch: String::from("main"),
            base: String::new(),
            interval: 1,
        };

        assert_eq!(
            super::stale(&dir, &trunk, "refs/heads/main"),
            None,
            "a probe that could not look must not report the base as moved"
        );
    }

    /// **The raced wait TERMINATES when neither arm answers, and this case is
    /// here because the failure it pins is a HANG rather than a wrong verdict.**
    ///
    /// Both arms send on clones of one channel and the outer handle stays live
    /// in this function's frame. Forget to drop it and `recv()` waits on a
    /// sender that will never send — for ever, inside a `thread::scope` that has
    /// already joined both arms. No assertion catches that; only the suite not
    /// coming back does. So the case is written to reach exactly that state:
    /// `asks: 1`, a forge nothing can reach, so both arms exhaust their count
    /// and close their clones without answering.
    ///
    /// It also pins the direction of an unanswered race. `Unanswered` is a
    /// could-not-look and never a verdict — a lap that read an unreachable forge
    /// as "green" would fast-forward on nothing, and one that read it as "stale"
    /// would burn a lap per network hiccup.
    #[test]
    fn a_race_neither_arm_answers_returns_rather_than_waiting_on_a_sender() {
        let config = crate::pr_watch::Config {
            sha: String::from("0000000000000000000000000000000000000000"),
            repo: String::from("nobody/nothing"),
            interval: 1,
            progress: None,
        };
        let roster = crate::checks_green::Roster {
            required: vec![String::from("ci")],
            absent_ok: Vec::new(),
            answered: vec![String::from("success")],
            fanin: None,
        };
        let trunk = crate::main_watch::Config {
            repo: String::from("nobody/nothing"),
            branch: String::from("main"),
            base: String::from("1111111111111111111111111111111111111111"),
            interval: 1,
        };

        let mut out = Vec::new();
        // `Ok(_)` matched rather than unwrapped: the only `Err` here is a stream
        // that will not accept output, and a `Vec` always accepts, so a panic
        // would be reporting the impossible case as the interesting one.
        assert_eq!(
            super::wait(&config, &roster, &trunk, 1, &mut out).ok(),
            Some(super::Waited::Unanswered),
            "an unreachable forge is a could-not-look, never a verdict about the work"
        );
    }

    /// Anti-vacuity: a misconfiguration stops everywhere, and success never does.
    ///
    /// Without the first half, `Usage` would lap and the loop would spend its
    /// whole count asking a question no lap can answer. Without the second, a
    /// table that stopped on everything would pass every case above.
    #[test]
    fn a_misconfiguration_stops_every_step_and_success_stops_none() {
        for step in [
            Step::Replay,
            Step::Verify,
            Step::Push,
            Step::Wait,
            Step::FastForward,
        ] {
            assert_eq!(
                progress(step, Usage),
                Progress::Stop,
                "{step:?} must not lap over a clone it cannot be configured to answer"
            );
            assert_ne!(
                progress(step, Success),
                Progress::Stop,
                "{step:?} answering cleanly is never a stop"
            );
        }
        assert_eq!(progress(Step::FastForward, Success), Progress::Landed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verify family writes the same four columns every other family does.
    #[test]
    fn every_verify_outcome_writes_four_columns_led_by_the_kind() {
        for outcome in [
            Verified::Clean(String::from("abc1234")),
            Verified::Refused(String::from("abc1234")),
        ] {
            let line = outcome.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "verify", "the kind column leads: {line:?}");
        }
    }

    /// NO DEFAULT COMMAND, asserted rather than described. A default would be a
    /// consumer's task name compiled into this crate, which non-negotiable rule
    /// 1 forbids — and the failure mode of guessing one is worse than refusing,
    /// because a lap would report a gate as clean having run something else.
    #[test]
    fn an_unconfigured_verify_command_refuses_rather_than_guessing() {
        let Err(problem) = verify(Path::new("."), "work", &[]) else {
            panic!("an empty command must refuse rather than run something");
        };
        assert!(
            format!("{problem}").contains("does not know what verifying means"),
            "the refusal names the missing configuration: {problem}"
        );
    }

    /// The push family writes the same four columns every other family does.
    ///
    /// Asserted here rather than trusted, for `Replay`'s reason one family over:
    /// a module narrows on column zero and splits on four, so a family that
    /// shipped three columns would be read through the wrong lens by every
    /// predicate over this store rather than by its own.
    #[test]
    fn every_push_outcome_writes_four_columns_led_by_the_kind() {
        for outcome in [Pushed::Landed(String::from("abc1234")), Pushed::Raced] {
            let line = outcome.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "push", "the kind column leads: {line:?}");
        }
    }

    /// The four columns the vendored module reads, pinned on this side too.
    ///
    /// The writer and the reader are deliberately not each other's authority —
    /// the module ships into every consumer's binary and this is one consumer —
    /// so the layout is asserted at both ends rather than derived at one.
    #[test]
    fn every_outcome_writes_four_columns_led_by_the_kind() {
        for outcome in [
            Replay::Conflicted {
                commit: String::from("abc1234"),
                paths: vec![String::from("shared.txt")],
            },
            Replay::Current,
            Replay::Replayed {
                head: String::from("def5678"),
                commits: 1,
            },
        ] {
            let line = outcome.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "rebase", "the kind column leads: {line:?}");
        }
    }

    /// A conflict names the commit and the first path, and nothing else.
    #[test]
    fn a_conflict_records_a_pointer_and_never_a_hunk() {
        let line = Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: vec![String::from("shared.txt"), String::from("other.txt")],
        }
        .line();
        assert_eq!(line, "rebase conflicted abc1234 shared.txt");
    }

    /// A CONFLICT WITH NO PATH still writes four columns, with `-` where the
    /// pointer would be. An empty column would shift every column after it, and
    /// the reader's own length check would then skip the line entirely — turning
    /// the loop's one human stop into silence.
    #[test]
    fn a_conflict_with_no_path_keeps_the_column_count() {
        let line = Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: Vec::new(),
        }
        .line();
        assert_eq!(line, "rebase conflicted abc1234 -");
    }

    /// The two clean outcomes are distinguishable from each other and from a
    /// conflict — a replay that minted a sha, and one that had nothing to mint.
    #[test]
    fn the_clean_outcomes_are_told_apart() {
        assert_eq!(Replay::Current.line(), "rebase current - -");
        assert_eq!(
            Replay::Replayed {
                head: String::from("def5678"),
                commits: 3,
            }
            .line(),
            "rebase replayed def5678 -"
        );
    }

    #[test]
    fn a_remote_reference_resolves_to_its_tracking_ref() {
        assert_eq!(tracking_ref("refs/heads/main"), "refs/remotes/origin/main");
        assert_eq!(tracking_ref("main"), "refs/remotes/origin/main");
    }

    /// A wait line carries four columns led by its kind, like a replay line.
    #[test]
    fn every_wait_answer_writes_four_columns_led_by_the_kind() {
        for answer in [
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            },
            Answered {
                arm: Arm::Stale,
                verdict: None,
                sha: String::from("abc1234"),
            },
        ] {
            let line = answer.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "wait", "the kind column leads: {line:?}");
        }
    }

    /// **THE LOSER IS WRITTEN AS COULD-NOT-LOOK, and that is what makes the race
    /// legible.** An arm abandoned unread records `-` rather than being omitted:
    /// omitting it would make a lap that raced properly and a lap that read both
    /// sides produce records nothing can tell apart.
    #[test]
    fn a_voided_loser_records_could_not_look_rather_than_vanishing() {
        assert_eq!(
            Answered {
                arm: Arm::Stale,
                verdict: None,
                sha: String::from("abc1234"),
            }
            .line(),
            "wait stale - abc1234"
        );
        assert_eq!(
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            }
            .line(),
            "wait green success abc1234"
        );
    }

    /// The two arms are distinguishable, which is what lets a module count
    /// ANSWERING ARMS rather than recorded lines.
    #[test]
    fn the_two_arms_carry_different_tokens() {
        assert_ne!(Arm::Green.token(), Arm::Stale.token());
    }

    /// `|`-separated argvs, and the separator is not a comma for a reason.
    #[test]
    fn a_declared_gate_list_decodes_to_one_argv_per_entry() {
        assert_eq!(
            super::body_gates("mise run deferral-check|mise run closing-key-check"),
            vec![
                vec![
                    String::from("mise"),
                    String::from("run"),
                    String::from("deferral-check")
                ],
                vec![
                    String::from("mise"),
                    String::from("run"),
                    String::from("closing-key-check")
                ],
            ],
            "a comma would give one argv per WORD"
        );
    }

    /// An empty entry is dropped rather than becoming an empty argv.
    ///
    /// Load-bearing rather than tidy: `ready` treats an unrunnable gate as a
    /// refusal, so an empty argv would stop every lap on a trailing separator.
    #[test]
    fn a_stray_separator_does_not_become_a_gate_that_cannot_run() {
        assert!(super::body_gates("").is_empty());
        assert!(super::body_gates("  |  ").is_empty());
        assert_eq!(super::body_gates("one|").len(), 1);
    }

    /// **THE TWO DIRECTIONS, and they are opposite on purpose.**
    ///
    /// An empty body is a PASS — the body is fetched from a forge, and one this
    /// never saw is not evidence about what the author wrote, which is the
    /// predecessor's `[[ -n "$body" ]] &&`. A declared gate that cannot run is a
    /// REFUSAL — `mise run <task>` for a task that does not exist exited
    /// non-zero, and treating it as clean is how a renamed gate goes dead.
    ///
    /// Asserted as the pair, because a version that passed on both and a version
    /// that refused on both each satisfy one half.
    #[test]
    fn an_unseen_body_passes_and_an_unrunnable_gate_refuses() {
        let root = std::env::temp_dir();
        let gate = vec![vec![String::from(
            "batten-no-such-program-for-the-ready-phase",
        )]];

        assert_eq!(
            super::ready(&root, &gate, "   \n "),
            super::Readied::Clear,
            "a body the fetch never produced says nothing, so there is nothing to judge"
        );

        assert_eq!(
            super::ready(&root, &gate, "Closes CLOUD-1"),
            super::Readied::Unrunnable {
                gate: String::from("batten-no-such-program-for-the-ready-phase"),
            },
            "a declared gate that cannot run has not passed"
        );
    }

    /// No declared gates is a clear ready, and the distinction from `Unrunnable`
    /// is the optional-versus-dead one the driver's own header states.
    #[test]
    fn a_consumer_declaring_no_body_gates_is_clear_rather_than_unrunnable() {
        assert_eq!(
            super::ready(&std::env::temp_dir(), &[], "Closes CLOUD-1"),
            super::Readied::Clear
        );
    }

    /// The ready step stops rather than laps, and that is the table's claim.
    ///
    /// A refusal is about the BODY — a deferral with no ticket, a key the merge
    /// will not close — and no rebase clears prose, which puts it beside the
    /// replay and the gate rather than beside the push.
    #[test]
    fn a_body_gate_refusal_stops_the_lap_rather_than_lapping_it() {
        use crate::exit::ExitCode::{Internal, Success, Violation};
        assert_eq!(
            super::progress(super::Step::Ready, Violation),
            super::Progress::Stop
        );
        assert_eq!(
            super::progress(super::Step::Ready, Internal),
            super::Progress::Stop
        );
        assert_eq!(
            super::progress(super::Step::Ready, Success),
            super::Progress::Proceed
        );
        // And the contrast that makes it a claim rather than a default: the push
        // laps on the same code, because a raced push IS cleared by a rebase.
        assert_eq!(
            super::progress(super::Step::Push, Violation),
            super::Progress::Lap
        );
    }

    /// **SPEND IS COUNTED, NOT INFERRED, and this is the case PR #651 produced.**
    ///
    /// Two laps, both lost to `main` moving under the gate, the ready never
    /// reached, zero check-runs on the head — and the refusal announced "having
    /// spent 2 CI matrices". The attempt counter is not the spend, and the
    /// inference that they agree fails in both directions.
    #[test]
    fn a_lap_that_bought_nothing_is_not_reported_as_a_spend() {
        let mut ledger = Ledger::default();
        ledger.attempt();
        ledger.attempt();
        assert_eq!(ledger.laps, 2, "two attempts were made");
        assert_eq!(
            ledger.spent(),
            0,
            "and neither bought a matrix, so nothing was spent"
        );

        ledger.attempt();
        ledger.bought_a_matrix();
        assert_eq!(ledger.spent(), 1, "the one site that buys one, counted");
    }

    /// **A pass that spent nothing is refunded, and the refund is the point.**
    ///
    /// Without it a saturated fleet exhausts the lap budget — a budget that
    /// exists to catch "main moves faster than a lap takes" — and then reports
    /// THAT diagnosis, which CLOUD-413 measured being wrong twice over across 24
    /// laps.
    #[test]
    fn a_pass_that_never_won_the_lease_refunds_its_lap() {
        let mut ledger = Ledger::default();
        ledger.attempt();
        assert_eq!(ledger.waited(3), Charge::Lap);
        assert_eq!(ledger.laps, 0, "the attempt was refunded");
        assert_eq!(ledger.lease_waits, 1, "and charged to its own bound");
    }

    /// The three bounds are separate, and exhausting one names it.
    ///
    /// Asserted as the whole set rather than one arm: a version with one shared
    /// counter satisfies any single case here, and only the three together rule
    /// it out. The bounds must stay distinct because the refusals differ — a
    /// saturated fleet has spent no CI at all, which is the one exhaustion a
    /// caller can honestly describe as costless.
    #[test]
    fn each_bound_is_charged_and_named_separately() {
        let mut ledger = Ledger::default();
        assert_eq!(ledger.waited(0), Charge::Stop(Bound::LeaseWaits));

        let mut ledger = Ledger::default();
        assert_eq!(ledger.unknown(0), Charge::Stop(Bound::Unknowns));

        let mut ledger = Ledger::default();
        assert_eq!(ledger.transient(0), Charge::Stop(Bound::Transients));

        // And a bound not yet reached laps rather than stopping, on each.
        let mut ledger = Ledger::default();
        assert_eq!(ledger.waited(1), Charge::Lap);
        assert_eq!(ledger.unknown(1), Charge::Lap);
        assert_eq!(ledger.transient(1), Charge::Lap);
    }

    /// A refund cannot take the attempt counter below zero.
    ///
    /// Reachable rather than defensive: a bot-silence refund can fire on a pass
    /// that never opened a lap, and an underflow there would panic in a loop
    /// whose whole purpose is to keep running.
    #[test]
    fn a_refund_with_no_attempt_to_refund_does_not_underflow() {
        let mut ledger = Ledger::default();
        assert_eq!(ledger.unknown(5), Charge::Lap);
        assert_eq!(ledger.laps, 0);
    }

    /// **The discriminating pair: every record a non-verdict is absorbed, one
    /// verdict is not.**
    ///
    /// A run that reached a verdict was a judgement on this branch, and
    /// re-running it would spend jobs to re-learn a real refusal.
    #[test]
    fn a_failure_before_any_verdict_is_absorbed_and_one_after_is_not() {
        let absorbed_runs = absorbed(&[
            String::from("nonverdict 111 provision\n"),
            String::from("nonverdict 222 checkout\n"),
        ]);
        assert_eq!(
            absorbed_runs,
            Some(vec![
                String::from("nonverdict 111 provision"),
                String::from("nonverdict 222 checkout"),
            ]),
            "neither run reached a verdict, so neither judged the branch"
        );

        assert_eq!(
            absorbed(&[
                String::from("nonverdict 111 provision\n"),
                String::from("verdict 222 test-failed\n"),
            ]),
            None,
            "ONE verdict means the branch was judged; absorbing the pair would \
             re-run a real refusal"
        );
    }

    /// Could-not-look is one reading, and its three causes are deliberately
    /// indistinguishable: no failed runs, an empty scan, and a scan that
    /// answered nothing. No caller can act differently on which.
    #[test]
    fn an_empty_scan_is_could_not_look_rather_than_an_absorbed_transient() {
        assert_eq!(absorbed(&[]), None);
        assert_eq!(absorbed(&[String::new()]), None);
        assert_eq!(absorbed(&[String::from("   \n\n")]), None);
    }

    fn run(id: &str, path: &str) -> Spending {
        Spending {
            id: String::from(id),
            path: String::from(path),
        }
    }

    /// **THE ROW THAT MATTERS: the run carrying the fan-in is never cancelled.**
    ///
    /// `final` is the one context branch protection requires, and it is
    /// `always()` over a `needs:` assertion — so cancelling its run leaves that
    /// context `cancelled`, which is not an answer. The saving would buy a
    /// branch that can never grade and never land, which is strictly worse than
    /// paying for the matrix.
    #[test]
    fn the_run_carrying_the_fan_in_is_spared_and_the_rest_are_not() {
        let (doomed, spared) = worthless(
            &[
                run("1", ".github/workflows/rust.yml"),
                run("2", ".github/workflows/ci.yml"),
                run("3", ".github/workflows/test.yml"),
            ],
            ".github/workflows/ci.yml",
        );
        assert_eq!(spared, 1, "exactly the fan-in's run");
        assert_eq!(
            doomed.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["1", "3"],
            "and every sibling is still doomed: {doomed:?}"
        );
    }

    /// A fan-in declared for a file no run carries spares nothing — and still
    /// cancels the rest.
    ///
    /// The anti-vacuity mirror for the pair above: a predicate that spared
    /// everything would satisfy the sparing half and save nothing at all.
    #[test]
    fn a_fan_in_no_run_carries_spares_nothing_and_still_cancels() {
        let (doomed, spared) = worthless(
            &[
                run("1", ".github/workflows/rust.yml"),
                run("2", ".github/workflows/test.yml"),
            ],
            ".github/workflows/absent.yml",
        );
        assert_eq!(spared, 0);
        assert_eq!(doomed.len(), 2, "nothing is spared by accident");
    }

    /// **AN UNSET FAN-IN CANCELS NOTHING RATHER THAN GUESSING.**
    ///
    /// The predecessor refuses to run at all without `$CI_FANIN_WORKFLOW`,
    /// because without it the task cannot tell which run carries the fan-in and
    /// cancelling that one wedges the branch. Conserved here as the caller's
    /// guard: an empty name matches no path, so this arm is what makes the
    /// caller's refusal the only safe reading.
    #[test]
    fn an_empty_fan_in_name_matches_no_run() {
        let (doomed, spared) = worthless(&[run("1", ".github/workflows/ci.yml")], "");
        assert_eq!(spared, 0);
        assert_eq!(
            doomed.len(),
            1,
            "so the CALLER must refuse rather than let this decide"
        );
    }

    /// Nothing in flight is a clean no-op.
    #[test]
    fn nothing_in_flight_cancels_nothing() {
        let (doomed, spared) = worthless(&[], ".github/workflows/ci.yml");
        assert!(doomed.is_empty());
        assert_eq!(spared, 0);
    }
}
