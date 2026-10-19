//! Which OTHER open pull request already claims this branch's issue
//! (CLOUD-446, moved into the engine by CLOUD-1422).
//!
//! # Why this is here rather than in `mise-tasks/`
//!
//! `mise-tasks/claim-race-check.sh` answered this question and answered it
//! wrongly in the one environment that decides whether work lands. It excluded
//! the branch's OWN pull request from the competitor list by resolving it with
//! `gh pr view` and no argument — which reads the CURRENT BRANCH. Under
//! `actions/checkout` on a `pull_request` event the checkout is detached at the
//! merge ref, so that call fails:
//!
//! ```text
//! could not determine current branch: failed to run git: not on any branch
//! ```
//!
//! The shell absorbed it with `|| true`, so the self number was empty, no
//! competitor could equal it, and every pull request was judged as racing
//! **itself**. Measured on PR #793, run 33825308497: `CLOUD-1170 is already
//! claimed by open PR #793`. It is not intermittent — `commit-lint` requires a
//! `Refs:` trailer on every commit, so the detached reading always resolves a
//! claim through source 3 — and it is invisible locally, where a branch name
//! exists and the same gate is green on the same tree.
//!
//! # The fix is the port, not a repair carried across
//!
//! [`identify`] resolves this branch's pull request by **head SHA**, taken from
//! the same listing that supplies the competitors. A SHA survives a detached
//! checkout where a branch name does not, so the failing arm cannot be reached
//! rather than being handled. That is the whole reason this is a retirement and
//! not a patch: the shell had no spelling for the question.
//!
//! # What a key is, and what CLOSES one, is asked and never re-derived
//!
//! Both questions are [`ready::Grammar`]'s, reached here through [`Keys`]. That
//! is not tidiness: this module's first draft carried its own closing-verb
//! regex, which would have been a SECOND authority over the one distinction
//! that has already misfired in this repository — a pull request citing a key as
//! evidence, read as claiming it. Two authorities that can disagree about what
//! closes a key is the same defect one level up from the one being retired.
//!
//! The grammar resolves every token from the consumer's own `[[pattern]]`
//! registry, so no tracker vocabulary enters the crate (non-negotiable rule 1)
//! and `no-tracker-key-in-core` stays silent.
//!
//! [`Keys`] is a trait rather than a bare `&Grammar` so the predicate can be
//! driven by a double in a unit test. A grammar is resolved from ~18 declared
//! patterns, and a test that had to build one would be asserting the registry's
//! shape on the way to asserting this module's.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! A [`Race`] carries a key, a number and a head ref — three tokens. Never a
//! title, a body or a commit message: everything this reads is prose somebody
//! else wrote.

use regex::Regex;

use crate::ready::Grammar;

/// What a key is, and what closes one — the two questions this predicate asks
/// of somebody else.
///
/// Implemented for [`Grammar`], which resolves both from the consumer's
/// `[[pattern]]` registry. A caller may not answer either itself: that is what
/// keeps one concept to one spelling, and what stopped this module shipping a
/// closing-verb regex of its own.
pub trait Keys {
    /// Every key the text names, however it names it.
    fn named(&self, text: &str) -> Vec<String>;
    /// Every key the text names in CLOSING form — the ones a merge will move.
    fn closed(&self, text: &str) -> Vec<String>;
}

impl Keys for Grammar {
    fn named(&self, text: &str) -> Vec<String> {
        self.keys_in(text)
            .into_iter()
            .map(|key| key.to_string())
            .collect()
    }

    fn closed(&self, text: &str) -> Vec<String> {
        self.keys_closed_in(text)
            .into_iter()
            .map(|key| key.to_string())
            .collect()
    }
}

/// One open pull request, as the forge lists it.
///
/// `head_sha` is what makes the self-comparison work in a detached checkout and
/// is the field the retired shell had no access to: `gh pr view` answered from
/// the branch, so there was nothing to compare a commit against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull {
    /// The pull request number, as a token.
    pub number: String,
    /// Its head branch name.
    pub head_ref: String,
    /// Its head commit.
    pub head_sha: String,
    /// Its title — a self-declaration, and source 2.
    pub title: String,
    /// Its body — evidence, and source 1 only through a closing keyword.
    pub body: String,
    /// Its commit messages, joined — sources 1 and 3.
    pub log: String,
}

/// One refusal: a key this branch claims that another open pull request claims
/// too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Race {
    /// The contested key.
    pub key: String,
    /// The competing pull request's number.
    pub number: String,
    /// Its head branch, so the reader can find it without a second lookup.
    pub head_ref: String,
}

/// The three sources a claim may come from, most explicit first.
///
/// Ported from `claimed-keys.sh` unchanged in meaning, and the ORDER is the
/// whole of it: a closing keyword OVERRIDES the branch, which is the escape
/// hatch for a branch whose name no longer reflects the work; a `Refs:` trailer
/// answers only when neither of the first two does.
///
/// A body CITES related issues, prior measurements and superseded work as
/// evidence — that is not a claim, and treating it as one made a pull request
/// citing a key read as racing it. Both sides of the comparison go through this
/// one function for exactly that reason.
#[must_use]
pub fn claimed(branch: &str, title: &str, log: &str, body: &str, keys: &dyn Keys) -> Vec<String> {
    claimed_from(branch, title, log, body, keys, Source::All)
}

/// Source 1 alone, over one text: which keys does this CLOSE?
///
/// [`claimed`]'s twin for the narrowed source, and it exists for the same
/// reason — to own an argument list rather than make each caller re-derive it.
/// `claimed_from`'s branch and title go in EMPTY under
/// [`Source::ClosingOnly`], because that source returns before either is read
/// (see below), so a caller passing the real ones adds two dead arguments to a
/// question that is about one text.
///
/// **Use it whenever the question is about one text — but `claimed_from` is
/// not wrong where the full arity is already in hand.** `tracker_reading`'s
/// closing read sits directly above a [`Source::RefsFirstOnly`] call that
/// needs a real branch and log, and the two reading as a pair is worth more
/// there than this spelling. Callers were not swept; a conditional rule keeps
/// without maintenance, where a census of which sites have converted would be
/// prose nothing checks.
///
/// The text may be a body or a log: `claimed_from` joins the two before the
/// closing scan, so under this source the slot a caller uses does not change
/// the answer.
#[must_use]
pub fn closes(text: &str, keys: &dyn Keys) -> Vec<String> {
    claimed_from("", "", "", text, keys, Source::ClosingOnly)
}

/// Which of the three sources may answer.
///
/// **The shell's two narrowing flags as a type** (CLOUD-1711). `claimed-keys.sh`
/// spells these `--closing-only` and `--refs-first-only`, and they are mutually
/// exclusive there because each names a different SINGLE source — asking for both
/// is a caller that has not decided which question it is asking, never an
/// intersection to compute. An enum makes that unrepresentable rather than
/// checked, which is the one thing a port can improve without changing a
/// decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// All three, most explicit first. The default, and every existing caller.
    #[default]
    All,
    /// Source 1 alone — a closing keyword — never falling through.
    ///
    /// For a caller asking about a LOG rather than a branch (CLOUD-804): over
    /// `main`'s history the fallbacks answer a different question, and source 3
    /// in particular is the exact citation signal CLOUD-480 was swept wrong on.
    ClosingOnly,
    /// Source 3 alone — the first key of each `Refs:` trailer.
    ///
    /// The exact mirror, for one caller with one need: `closing-key-check` asks
    /// which keys a branch SERVED, to subtract the keys the body closes
    /// (CLOUD-674). That comparison is only meaningful against a set derived
    /// WITHOUT reference to the closing keys — the full chain returns source 1
    /// first, so the answer would agree with the body by construction and the
    /// gate would pass on exactly the bodies it must refuse.
    RefsFirstOnly,
}

/// [`claimed`], narrowed to one source.
///
/// The precedence and the citation rule are unchanged; `source` only decides
/// which branches may run at all.
#[must_use]
pub fn claimed_from(
    branch: &str,
    title: &str,
    log: &str,
    body: &str,
    keys: &dyn Keys,
    source: Source,
) -> Vec<String> {
    if source == Source::RefsFirstOnly {
        return refs_first(log, keys);
    }
    let closing = dedup(keys.closed(&folded(&format!("{body}\n{log}"))));
    if !closing.is_empty() || source == Source::ClosingOnly {
        return closing;
    }
    let declared = dedup(keys.named(&folded(&format!("{branch} {title}"))));
    if !declared.is_empty() {
        return declared;
    }
    refs_first(log, keys)
}

/// The commit messages this branch AUTHORED, which is narrower than the ones it
/// carries (CLOUD-748).
///
/// **Carrying this bound is the whole of the port's fidelity.** `land`'s
/// speculative linearization rebases a waiting branch onto the lease holder's
/// published head, putting ANOTHER BRANCH'S unlanded commits into this branch's
/// history. Those commits carry the holder's keys, and the holder has an open
/// pull request by construction — so a claim derived over the whole branch
/// history reported the waiter as racing the very pull request the bet was
/// placed on. Measured twice in one session, each costing a full `verify`. A
/// port that read `origin/main..HEAD` unconditionally would silently reintroduce
/// exactly that, and it would look like a passing gate.
///
/// [`crate::speculation::PUBLISHED_AS`] is the boundary: the commit the branch
/// was replayed ONTO, so everything after it on HEAD is this branch's own work.
///
/// **Honoured only when it is an ancestor of HEAD**, which is what makes a stale
/// export harmless: an unwound bet, a `land` that died, or a variable inherited
/// from an unrelated run all fail that test and the range falls back to
/// `origin/main`. The failure direction is the WIDER set, which is the one that
/// refuses — never the narrower one, which would silently stop catching races.
#[must_use]
pub fn authored_log(dir: &std::path::Path, base: &str) -> String {
    authored_log_from(
        dir,
        base,
        std::env::var(crate::speculation::PUBLISHED_AS).ok(),
    )
}

/// [`authored_log`] over the published-as value read from the environment, so
/// a case can drive both arms without setting a variable.
fn authored_log_from(dir: &std::path::Path, base: &str, published: Option<String>) -> String {
    let speculated = published.filter(|value| !value.trim().is_empty());
    if let Some(spec_base) = speculated {
        // ANCESTOR OF HEAD, spelled as "the merge base with HEAD is the base
        // itself". `merge_base` already answers against HEAD, so an unrelated or
        // unwound base disagrees with its own resolved id and the range falls
        // back — which is the wider, refusing direction the shell chose.
        let resolved = crate::git::resolve_ref(dir, &spec_base).ok().flatten();
        let shared = crate::git::merge_base(dir, &spec_base).ok().flatten();
        if resolved.is_some()
            && resolved == shared
            && let Ok(Some(text)) = crate::git::log_messages(dir, &spec_base)
        {
            return text;
        }
    }
    crate::git::log_messages(dir, base)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Upper-cased, because a key pattern is not obliged to be case-insensitive and
/// a BRANCH NAME is routinely not upper case.
///
/// **This is a fidelity requirement, not a nicety, and leaving it out is a
/// silent dead gate.** The retired shell extracted case-insensitively and
/// upper-cased the result. A consumer's key row need not carry an `(?i)` flag —
/// this one does not — while a tracker's own branch names are routinely lower
/// case. So a port that handed the branch to the grammar as written would
/// resolve NO key from source 2 on every branch such a consumer makes: the
/// claim would silently fall through to a `Refs:` trailer, or to nothing, and a
/// gate that finds nothing looks exactly like a gate that passed.
///
/// Folding the INPUT rather than relaxing the pattern is deliberate: the row is
/// consumer config read by other gates too, and widening it here would change
/// their answers to buy this one.
fn folded(text: &str) -> String {
    text.to_uppercase()
}

/// The FIRST key of each `Refs:` trailer, which is source 3.
///
/// The trailer itself is a commit-message convention rather than a tracker's
/// vocabulary, so the pattern for it belongs to this module. WHAT FOLLOWS it is
/// still the grammar's to recognise, which is why only the trailer and its
/// immediate neighbourhood is matched here and the key is read out of that span
/// by [`Keys::named`].
///
/// Only the first key counts. A trailer may go on to cite others, and citing is
/// not claiming — a property of taking the head of the span rather than a filter
/// applied afterwards, so a caller cannot reintroduce the conflation by
/// forgetting a step.
fn refs_first(log: &str, keys: &dyn Keys) -> Vec<String> {
    let mut found = Vec::new();
    for line in log.lines() {
        if let Some(hit) = TRAILER.find(line) {
            found.extend(keys.named(&folded(hit.as_str())).into_iter().take(1));
        }
    }
    dedup(found)
}

/// Sorted and deduplicated, so the output is byte-stable for one input (§6).
fn dedup(mut keys: Vec<String>) -> Vec<String> {
    keys.sort();
    keys.dedup();
    keys
}

/// The `owner/name` slug a remote URL points at, or `None` where it points at
/// something this cannot read.
///
/// Both spellings the forge hands out — `https://host/owner/name(.git)` and
/// `git@host:owner/name(.git)` — reduce to the same two segments. `None` rather
/// than a guess: a slug derived wrongly would ask the forge about a DIFFERENT
/// repository and get a confident answer about it, which is worse here than not
/// looking, because the verdict would read as this repository's.
#[must_use]
pub fn slug_of(url: &str) -> Option<String> {
    // The scp form puts the path after a colon; the URL form puts it after the
    // host. Reduce both to the path, then require exactly the two segments a
    // slug has — a URL naming only one is not a repository this can ask about,
    // and `None` is the honest answer rather than a slug built from the host.
    let path = url.split_once("://").map_or_else(
        || url.rsplit_once(':').map_or(url, |(_, tail)| tail),
        |(_, rest)| rest.split_once('/').map_or("", |(_, path)| path),
    );
    let path = path.strip_suffix(".git").unwrap_or(path).trim_matches('/');
    let mut segments = path.split('/');
    let owner = segments.next().filter(|part| !part.is_empty())?;
    let name = segments.next().filter(|part| !part.is_empty())?;
    segments.next().is_none().then(|| format!("{owner}/{name}"))
}

/// This branch's own pull request, resolved by HEAD SHA.
///
/// **The whole defect this module retires lives in the alternative.** Resolving
/// by branch name asks a question a detached checkout cannot answer, and the
/// shell's answer to not being able to answer was to carry on with an empty
/// self — so the branch raced itself. A SHA is carried by the listing and by the
/// checkout alike.
#[must_use]
pub fn identify<'a>(pulls: &'a [Pull], head_sha: &str) -> Option<&'a Pull> {
    pulls.iter().find(|pull| pull.head_sha == head_sha)
}

/// How many competitor log fetches may be in flight at once.
///
/// A width rather than a pool size: the listing is one page by construction —
/// `open_pulls_are_complete` refuses a full one — so the work is tens of items,
/// and the bound exists to keep a burst away from the forge's rate limit rather
/// than to saturate anything. Eight is the same order as a `--jobs` wave and
/// well inside the forge's concurrent-request budget.
///
/// `pub` so the suite asserts the bound it is actually built with rather than a
/// literal beside it: retuned upward a literal fails with a message blaming an
/// unbounded spawn, and retuned downward it passes having stopped testing
/// anything.
pub const FETCH_WIDTH: usize = 8;

/// A competitor fill, and whether it is one a verdict may be taken over.
///
/// **The two are separate because conflating them is the defect this whole
/// module corrects.** [`races`]'s own header says an empty result means *looked
/// and found none*, and that reading a *could not look* as one is the dead gate
/// it exists to replace. A fill that lost a worker mid-flight has competitors
/// carrying empty logs for no reason the forge gave, so judging it would report
/// exactly that false green — the sequential fill this replaces could not
/// produce the state at all, because a panic took the process with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filled {
    /// The listing in input order, each eligible competitor carrying its log.
    pub pulls: Vec<Pull>,
    /// The competitors this asked for and did not get, by pull request number.
    ///
    /// Empty is the whole-reading case. A number lands here for either of two
    /// causes, which are the same fact — it was never read: its `fetch`
    /// answered `None`, or the worker carrying it unwound before it could send.
    ///
    /// **An empty log is NOT one of them.** `Some("")` is an answer — a
    /// competitor whose commits genuinely name no key reads exactly that way,
    /// and conflating it with a read that failed is what let a 403 or a 502
    /// present as "claims nothing". That conflation is why `fetch` answers an
    /// `Option` at all.
    ///
    /// **Numbers rather than a count**, because the caller has two different
    /// questions and only one of them is "was this a whole reading". The other
    /// is WHICH of the races it is about to report rest on a competitor nobody
    /// read, since it marks those rows and no others — a bool cannot answer
    /// that. What to do in either case is the caller's, and stated there.
    pub unanswered: Vec<String>,
}

/// Does ANY key in `found` collide with one this branch claims?
///
/// Named because [`with_logs`]'s predicate asks it in BOTH of its terms, of
/// two different sets — what a competitor's body closes, and what its branch
/// and title resolve — and the argument written around that predicate turns on
/// the word "colliding" throughout. Two spellings of one concept inside one
/// closure is how the two drift apart.
///
/// **ANY, not the first.** Both sides are sets: `claims` is everything this
/// branch claims, routinely more than one key, and a competitor's body may
/// close several. So a body closing an unclaimed key and a claimed one is
/// settled by the claimed one wherever in the text it sits.
fn collides(found: &[String], claims: &[String]) -> bool {
    found.iter().any(|key| claims.contains(key))
}

/// Fill in each competitor's `log`, fetching the eligible ones concurrently.
///
/// # Why this is concurrent, and what the number was
///
/// The fill is the largest single cost `enforce` pays. CLOUD-2382 measured the
/// rule running `claim race` at **15.8 s** on 2026-10-15 on a head carrying an
/// open pull request — the largest in that run — against 1.1 s on a head with
/// none, where [`identify`] finds nothing and the verb never reaches here. The
/// difference is one `GET pulls/<n>/commits` per eligible competitor, each
/// waiting on the last.
///
/// **IT SCALES WITH THE ELIGIBLE COUNT, WHICH IS NARROWER THAN THE LISTING.**
/// The skip below answers most competitors without a round trip, in
/// [`claimed_from`]'s order — a body's closing keyword first, then a branch or
/// title naming a key — so this fan-out covers only what that leaves, and on
/// this repository (25 open pull requests on 2026-10-16) that remainder is a
/// fraction of the listing. **No split is quoted here on purpose**: two
/// attempts to state one, by emulating the predicate with a bare key pattern,
/// both disagreed with it and with each other, because the operative source is
/// the body rather than the name. A reader who wants the number should take it
/// from the predicate rather than from a regex that resembles it. A consumer
/// whose bodies close nothing and whose branch names carry no key has the whole
/// listing eligible and gains proportionally more.
///
/// Every request builds its own current-thread runtime inside `rest::get`, and
/// `fetch` holds no statics, so concurrent live calls are sound. The
/// one-runtime-per-invocation bound `rules/rust.md` carries names `batten
/// hook`'s mediated path rather than a `command`-kind verb; CLOUD-2410 moves
/// that reading into the table along with the row this site owes it, so it is
/// stated once there rather than re-derived here.
///
/// What this does NOT recover is the handshake: the client and the TLS config
/// are rebuilt per call below here, so eight workers mean eight of each.
/// CLOUD-2411 owns that — worth a few hundred milliseconds against the 15.8 s
/// measured above, and it needs an async seam this does not cut.
///
/// # A pool rather than a wave, and tail latency is what the choice buys
///
/// `exec::dispatch` solves a shape like this with `chunks(jobs)` and refuses a
/// pool in as many words — *"a pool would buy throughput on a workload nobody
/// has"* — so reaching for one here is owed a reason. A wave is only as fast as
/// its slowest member, and these are network round trips whose spread belongs
/// to the forge: one competitor with a long commit list would hold seven idle
/// workers to the end of its wave. `exec`'s members are local processes in a
/// short bundle, where that spread does not arise and the wave's free ordering
/// is worth more than it is here.
///
/// **The fixture seam is not concurrency-safe, and routing by URL is only half
/// the remedy.** `rest::from_fixture` read-modify-writes a `calls` counter to
/// answer by call ORDER, which concurrent callers tear outright. Its `routes`
/// path is safe about WHICH answer each request gets — it matches on the URL —
/// but it also appends every request to one shared `args` file and replaces one
/// `<file>.request` per route, so what a suite READS BACK afterwards is in
/// scheduler order, and a last writer wins where two requests route to one
/// file. `claim_race.rs`'s verb-tier cases DO drive this seam; the rule that
/// keeps them safe is stated in that file's own header, where a case author
/// looks, rather than here.
///
/// # What is decided where
///
/// Eligibility is decided on the CALLING thread, and only `fetch` runs on a
/// worker. **That is a choice, not a law** — `Grammar` is `Sync`, and a
/// `Keys: Sync` bound or a `&(dyn Keys + Sync)` would compile, so a reader who
/// wants the predicate on a worker is not stopped by the type system and
/// should not be told they are. What makes it the right choice is cheapness
/// and determinism: `claimed` is microseconds of regex over strings already in
/// hand, so overlapping it buys nothing, and settling the whole fetch set
/// before any worker starts is what lets the slot write-back below be a plain
/// index rather than a synchronised one.
///
/// # Which competitors are asked
///
/// `mine_number` is this branch's own pull request number. It is never fetched
/// — the caller has already read its log, and a branch cannot race itself.
///
/// `claims` is the key set this branch claims, and it only ever WIDENS the
/// fetch set. **Pass the same set you will hand [`races`]**: the widening is
/// sound against that set and no other, since its whole purpose is to confirm
/// the competitors that set can collide with. `&[]` is accepted and asks only
/// the key-less competitors, which is the bound below without its soundness
/// clause — correct for a caller that is not about to refuse anyone, and what
/// the cases exercising the bound itself pass.
///
/// # Order is the input's, whatever the scheduler does
///
/// Each answer is written back into the slot it was taken from, so the returned
/// `Vec` is in listing order however the fetches interleave — the property a
/// collect over completion order would quietly lose, and the one
/// [`races`]'s output depends on being stable (§6).
///
/// # A read that failed is not a competitor that claims nothing
///
/// `fetch` answers an `Option` so those two can be told apart. The sequential
/// fill this replaces collapsed every failure to `""` with `unwrap_or_default`,
/// which made a 403 on a scopeless token, a 502 and a timeout read exactly like
/// a competitor whose commits name no key. `commit-lint` requires a `Refs:`
/// trailer on every commit here and a closing keyword on almost none, so the
/// trailer is the source that actually resolves a claim — and it lives in the
/// log a failed read did not return. The gate then prints "no open pull request
/// races this branch's claim" over a real collision, which is the defect
/// CLOUD-1422 retired the shell for and the same one arriving by a different
/// door. `None` keeps that out of the verdict; `Some("")` is still a real
/// answer and still judged.
///
/// **`Option` rather than [`crate::facts::Look`]**, which is the crate's type
/// for this same distinction and argues it in the same words. Two reasons it
/// is not reached for here: `Look` is three-valued and a log read has no
/// `IsNot`, so one arm would carry no meaning; and the distinction this
/// function must return is PER COMPETITOR, which is [`Filled::unanswered`],
/// not a verdict over the fill as a whole. The caller is one `.ok()` from an
/// `Option` and two from a `Look`.
#[must_use]
pub fn with_logs(
    mut pulls: Vec<Pull>,
    mine_number: &str,
    claims: &[String],
    keys: &dyn Keys,
    fetch: impl Fn(&str) -> Option<String> + Sync,
) -> Filled {
    // FETCH A COMPETITOR WHOSE CHEAP READING IS LOAD-BEARING FOR THIS VERDICT,
    // and whose cheap reading could be WRONG. The predicate below is those two
    // factors in that order; the known miss is the case they do not reach.
    //
    // **COULD BE WRONG** is the outer one, and a body that closes A KEY THIS
    // BRANCH CLAIMS settles it: source 1 outranks branch and title, and more
    // text can only add matches, so `closed(body) ⊆ closed(body + log)` and
    // that key stands whatever the commits say. Fetching such a competitor buys
    // nothing the VERDICT rests on — the log can still ADD a second key, so the
    // reported set may be a row short, but never on the key that refuses, which
    // is the body's by construction. And it costs something real: the pull
    // would land in `unanswered` on a 502, and every refusal it is in would
    // then carry an "unconfirmed" mark it has not earned — the collision is
    // PROVEN from data already in hand. `closing-key-check` requires the body
    // to close its key here, so a body that closes SOMETHING is near-universal
    // — distinct from `commit-lint` above, which is why a COMMIT rarely closes
    // one. What is rare is a body closing a key WE claim, which is a real
    // collision; so this factor spares few, and the paragraph below is where
    // the rest of that population goes.
    //
    // **THE COLLISION TEST IS LOAD-BEARING IN THAT SENTENCE** and read over
    // #1198: the argument says the refusing key is the body's, which holds only
    // where the body closes the key at issue. A competitor whose body closes
    // some OTHER key is settled about a question nobody asked, and its commits
    // are still where a key of ours could be — so it has the same claim on a
    // round trip as a competitor whose body closes nothing at all. Testing the
    // mere PRESENCE of a closing keyword put it with the claimed-key bodies
    // instead, which is the pair that is not alike, and no round trip went out
    // for a collider the log would have proven.
    //
    // THAT IS THIS FACTOR'S COST, and it is the population `closing-key-check`
    // makes large: a competitor whose body closes only keys we do not claim is
    // now fetched where it used to be skipped. Bounded by the inner factor
    // below — it still needs a cheap reading that is empty or colliding — and
    // by `FETCH_WIDTH`.
    //
    // **LOAD-BEARING** is the inner one, and it has two cases:
    //
    // * CHEAP-EMPTY — the log could ADD a key, and nothing else can speak for
    //   such a competitor. This is the bound that keeps the fill from being a
    //   round trip per open pull request however wide the fan-out is allowed
    //   to be.
    // * CHEAP-COLLIDES — the log could REMOVE one, and only here can that
    //   refuse anybody. [`claimed_from`] returns a log's closing set before it
    //   looks at the branch, so a competitor whose commits close a different
    //   key than its branch names is judged under its branch's: that hides a
    //   real race AND refuses a branch claiming the branch-named key at
    //   `Violation` inside `verify`, over a collision that does not exist.
    //   `claims` narrows the widening to the pulls that can produce one, so a
    //   listing that cheaply collides with nothing pays nothing.
    //
    // `unanswered` stays EMPTY through every pull this skips, because an
    // unfetched competitor is not an unanswered one, so no could-not-look arm
    // in `run_claim_race` sees one.
    //
    // A COLLIDER WHOSE FETCH FAILS IS THE CASE THE CALLER MUST HANDLE, and it
    // is why [`Filled::unanswered`] carries numbers rather than a count. Such a
    // pull keeps the empty log the listing was built with, so its cheap key
    // stands and [`races`] still reports it — on exactly the evidence this
    // widening exists to distrust. `run_claim_race` refuses on it anyway and
    // marks that row unconfirmed, for the monotonicity argument stated at its
    // `races` call: a widening that exists to catch more collisions must never
    // catch fewer.
    //
    // **THE CASE THE PREDICATE DOES NOT REACH** is the remaining load-bearing
    // one, and it bears on the CLEAN verdict rather than on a refusal: a
    // competitor whose BRANCH OR TITLE resolves a key nobody here claims while
    // its commits close one this branch does. It collides with nothing, so
    // nothing above asks for its log, and the key that would have refused is
    // the one not read. (A body-closing competitor is spared by the outer
    // factor instead, and its cost is the row-short set named above, not this.)
    // Reaching it means dropping the `claims` term and keeping only the outer
    // factor — fetch every competitor whose body closes nothing — which is a
    // latency decision for the row that owns latency, since what it costs
    // depends on how many open pull requests carry a body that closes no key.
    //
    // EACH ENTRY CARRIES ITS DESTINATION, not its queue position. Two parallel
    // vectors — slots here, numbers there — would have to stay in step for the
    // write-back below to put an answer on the pull it was fetched for, and
    // nothing would say so when they did not.
    let eligible: Vec<(usize, &str)> = pulls
        .iter()
        .enumerate()
        .filter(|(_, pull)| {
            // A COLLIDING key, not merely A key. The settling argument is that
            // the key which refuses is the body's, so no round trip can improve
            // it — and that holds only of a body key THIS BRANCH CLAIMS. A body
            // closing some unrelated key settles that key and says nothing
            // about ours, so skipping on it would leave the commits unread on
            // precisely the question being asked.
            //
            // AFTER the number test, so our own body is not scanned for an
            // answer that is thrown away.
            pull.number != mine_number && !collides(&closes(&pull.body, keys), claims) && {
                // THE BODY GOES IN EMPTY on this second call, and that is
                // a CORRECTNESS guard rather than a saving. [`claimed_from`]
                // returns source 1's set before it looks at branch or
                // title, so passing the body here would hand back the very
                // keys the term above just weighed — a competitor settled
                // on an unrelated key would come back with that key as its
                // "cheap" reading, collide with nothing, and be skipped
                // again through the inner term. Blanked, this reads branch
                // and title alone, which is the question being asked.
                let cheap = claimed(&pull.head_ref, &pull.title, "", "", keys);
                cheap.is_empty() || collides(&cheap, claims)
            }
        })
        .map(|(slot, pull)| (slot, pull.number.as_str()))
        .collect();
    // ONE SHARED INDEX TAKEN BY AT MOST `FETCH_WIDTH` WORKERS, never a thread
    // per pull: the width is the whole of the bound, and spawning per item
    // would make the peak the listing's length. An empty `eligible` spawns
    // nothing and falls through both loops, so it needs no arm of its own.
    let next = std::sync::atomic::AtomicUsize::new(0);
    // EACH ANSWER IS PUBLISHED AS IT ARRIVES, never batched per worker, so a
    // worker that panics keeps the answers it had already sent — returning a
    // vector per worker lost every one of them.
    //
    // THAT NARROWS THE LOSS AND DOES NOT BOUND IT AT ONE FETCH, WHICH IS WHY
    // THE COUNT IS RETURNED. A worker that unwinds is gone and takes no further
    // index, so the pool runs one narrower and the loss is its in-flight fetch
    // plus whatever no surviving worker reaches. Absorbing the panic is still
    // right — the alternative is one through `verify`'s whole pre-flight — but
    // absorbing it SILENTLY would leave competitors carrying empty logs for no
    // reason the forge gave, and the caller would read that as "no races" at
    // exit 0. So the answers are taken against the eligible set and
    // [`Filled::unanswered`] carries the difference out, by number.
    //
    // A CHANNEL RATHER THAN A `Mutex<Vec<_>>`, which is how this crate already
    // spells "workers publish answers to the calling thread" — `land::wait`'s
    // two arms, `collect`, `handler`, `exec`, `mutate`. The accumulators that
    // are a mutex here are read WHILE their workers still run, which is a
    // different need. The difference that matters is poison: a mutex adds a
    // failure mode this function would then have to answer, and no answer to it
    // is honest when nothing can produce it — dropping a log already fetched
    // reads a competitor as claiming nothing after a successful round trip, and
    // recovering pretends the arm was considered. A channel has no such axis.
    let (tx, rx) = std::sync::mpsc::channel::<(usize, String)>();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..FETCH_WIDTH.min(eligible.len()))
            .map(|_| {
                let (next, eligible, fetch) = (&next, &eligible, &fetch);
                let tx = tx.clone();
                scope.spawn(move || {
                    loop {
                        let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&(slot, number)) = eligible.get(at) else {
                            return;
                        };
                        // A `None` IS NOT SENT, so it never counts as an
                        // answer and the fill comes back incomplete. That is
                        // the whole of how a failed read reaches the caller.
                        if let Some(log) = fetch(number) {
                            drop(tx.send((slot, log)));
                        }
                    }
                })
            })
            .collect();
        // JOINED, AND THE RESULT CONSUMED: a scope re-panics for a panicked
        // thread nobody joined, and `join` is what takes the payload out of the
        // packet, so this is the line that absorbs it rather than ceremony
        // around one. Never `unwrap`. Live only where the profile unwinds —
        // dev and test, which is what `mise run claim-race` builds;
        // `[profile.dist]` aborts, so a shipped binary never reaches here and
        // this only has to not make that case worse. The bound on what the
        // absorption costs is stated above, with the false-green it admits.
        for handle in handles {
            drop(handle.join());
        }
    });
    // THIS SENDER IS DROPPED BEFORE THE DRAIN, and the drain is what ends the
    // iteration: every cloned sender died with its worker inside the scope, so
    // `rx` runs dry exactly when the last answer has been taken. Holding `tx`
    // across the loop would hang here forever.
    drop(tx);
    // TAKEN AGAINST THE ELIGIBLE SET, never against the listing: `mine_number`
    // and every competitor a cheap source already answered were deliberately
    // not asked, so reading this off `pulls` would report every ordinary fill
    // incomplete.
    //
    // EVERY ELIGIBLE PULL STARTS OWED AND IS STRUCK AS IT ANSWERS, which keeps
    // the drain one pass and leaves `unanswered` in listing order by
    // construction — the map is keyed by slot, so `into_values` is already the
    // order the rest of this function promises.
    let mut unanswered: std::collections::BTreeMap<usize, String> = eligible
        .iter()
        .map(|(slot, number)| (*slot, (*number).to_owned()))
        .collect();
    for (slot, log) in rx {
        unanswered.remove(&slot);
        if let Some(pull) = pulls.get_mut(slot) {
            pull.log = log;
        }
    }
    Filled {
        pulls,
        unanswered: unanswered.into_values().collect(),
    }
}

/// Every key this branch claims that a DIFFERENT open pull request claims too.
///
/// `mine` is the claimed set for this branch, computed by the caller through
/// [`claimed`] so that the branch's local evidence — its own log, and its
/// pull request's body where it has one — reaches the same function the
/// competitors are read through.
///
/// Returns an empty vector when nothing races, which is the clean verdict. A
/// caller that cannot establish the competitor set must not call this at all:
/// an empty list here means *looked and found none*, and conflating that with
/// *could not look* is the dead gate this whole module is a correction for.
#[must_use]
pub fn races(
    mine: &[String],
    pulls: &[Pull],
    self_number: Option<&str>,
    keys: &dyn Keys,
) -> Vec<Race> {
    let mut found = Vec::new();
    for pull in pulls {
        if Some(pull.number.as_str()) == self_number {
            continue;
        }
        let theirs = claimed(&pull.head_ref, &pull.title, &pull.log, &pull.body, keys);
        for contested in mine.iter().filter(|key| theirs.contains(key)) {
            found.push(Race {
                key: contested.clone(),
                number: pull.number.clone(),
                head_ref: pull.head_ref.clone(),
            });
        }
    }
    found
}

/// A `Refs:` trailer and the one key that may follow it.
static TRAILER: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    #[expect(
        clippy::unwrap_used,
        reason = "a literal pattern with no input: it compiles or the binary does not"
    )]
    Regex::new(r"(?i)^\s*refs:\s*\S+").unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`Keys`] double, so this suite asserts THIS module's predicate rather
    /// than the pattern registry's shape on the way to it.
    ///
    /// It is deliberately dumber than the real grammar — a key is two uppercase
    /// runs around a dash, and a close is one of the forge's verbs immediately
    /// before one. Anything subtler is `ready::Grammar`'s to get right and
    /// `ready`'s own suite to pin; re-asserting it here would be the second
    /// authority this module exists to avoid.
    struct Fake;

    impl Keys for Fake {
        fn named(&self, text: &str) -> Vec<String> {
            KEY.find_iter(text)
                .map(|hit| hit.as_str().to_owned())
                .collect()
        }

        fn closed(&self, text: &str) -> Vec<String> {
            CLOSED
                .captures_iter(text)
                .filter_map(|hit| hit.get(1))
                .map(|hit| hit.as_str().to_owned())
                .collect()
        }
    }

    static KEY: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        #[expect(clippy::unwrap_used, reason = "a fixture pattern with no input")]
        Regex::new("[A-Z]+-[0-9]+").unwrap()
    });

    static CLOSED: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        #[expect(clippy::unwrap_used, reason = "a fixture pattern with no input")]
        Regex::new(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+([A-Z]+-[0-9]+)").unwrap()
    });

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

    #[test]
    fn a_closing_keyword_overrides_the_branch_name() {
        assert_eq!(
            claimed("user/proj-843-campaign", "", "", "Closes PROJ-1170.", &Fake),
            vec!["PROJ-1170".to_owned()]
        );
    }

    #[test]
    fn a_bare_mention_in_a_body_is_a_citation_and_not_a_claim() {
        assert_eq!(
            claimed("", "", "", "Supersedes the measurement in PROJ-133.", &Fake),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_refs_trailer_answers_only_when_nothing_more_explicit_does() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "", &Fake),
            vec!["PROJ-1170".to_owned()]
        );
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170\n", "Closes PROJ-9.", &Fake),
            vec!["PROJ-9".to_owned()]
        );
    }

    #[test]
    fn a_trailer_claims_its_first_key_and_cites_the_rest() {
        assert_eq!(
            claimed("", "", "Refs: PROJ-1170, PROJ-843\n", "", &Fake),
            vec!["PROJ-1170".to_owned()]
        );
    }

    /// The regression this module exists for, as a unit: the shell resolved the
    /// branch's own pull request by NAME, so a detached checkout produced no
    /// self and the branch raced itself.
    #[test]
    fn this_branch_is_identified_by_head_sha_and_never_races_itself() {
        let mine = vec!["PROJ-1170".to_owned()];
        let pulls = vec![Pull {
            title: String::new(),
            body: "Closes PROJ-1170.".to_owned(),
            log: String::new(),
            ..pull("793", "user/proj-843-campaign", "e97703b2")
        }];
        let me = identify(&pulls, "e97703b2").map(|pull| pull.number.clone());
        assert_eq!(me.as_deref(), Some("793"));
        assert!(
            races(&mine, &pulls, me.as_deref(), &Fake).is_empty(),
            "a branch may not race its own pull request"
        );
    }

    /// The same input with the self number unresolved — the state the retired
    /// shell was in on every CI run. It is a refusal, which is why the verb
    /// must never call `races` with `None` after a failed lookup.
    #[test]
    fn an_unresolved_self_is_what_made_the_branch_race_itself() {
        let mine = vec!["PROJ-1170".to_owned()];
        let pulls = vec![Pull {
            title: String::new(),
            body: "Closes PROJ-1170.".to_owned(),
            log: String::new(),
            ..pull("793", "user/proj-843-campaign", "e97703b2")
        }];
        assert_eq!(races(&mine, &pulls, None, &Fake).len(), 1);
    }

    #[test]
    fn a_different_pull_request_claiming_the_key_is_the_race_this_refuses() {
        let mine = vec!["PROJ-49".to_owned()];
        let pulls = vec![
            Pull {
                body: "Closes PROJ-49.".to_owned(),
                ..pull("400", "other/proj-49", "aaaa")
            },
            pull("793", "mine", "bbbb"),
        ];
        let races = races(&mine, &pulls, Some("793"), &Fake);
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].key, "PROJ-49");
        assert_eq!(races[0].number, "400");
    }

    #[test]
    fn a_competitor_that_only_cites_the_key_does_not_race_it() {
        let mine = vec!["PROJ-133".to_owned()];
        let pulls = vec![Pull {
            title: "docs(agents): the sweep (PROJ-268)".to_owned(),
            body: "| PROJ-133 | measured 2026-08-08 |".to_owned(),
            ..pull("306", "user/proj-268-sweep", "aaaa")
        }];
        assert!(races(&mine, &pulls, Some("793"), &Fake).is_empty());
    }

    #[test]
    fn both_remote_spellings_reduce_to_one_slug() {
        assert_eq!(
            slug_of("https://github.com/owner/name").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            slug_of("https://github.com/owner/name.git").as_deref(),
            Some("owner/name")
        );
        assert_eq!(
            slug_of("git@github.com:owner/name.git").as_deref(),
            Some("owner/name")
        );
    }

    #[test]
    fn a_url_naming_no_owner_is_none_rather_than_a_guess() {
        assert_eq!(slug_of("https://github.com/name"), None);
        assert_eq!(slug_of("name"), None);
    }

    #[test]
    fn a_head_sha_no_listed_pull_request_carries_identifies_nothing() {
        assert!(identify(&[pull("1", "a", "aaaa")], "bbbb").is_none());
    }

    // --- CLOUD-1711: the `Source` selector -----------------------------------
    //
    // THE DISCRIMINATING CASE IS THE CITATION TRAP, and it is the one the whole
    // module exists for: a body CITES related issues as evidence, and reading a
    // citation as a claim made a pull request racing the very key it cited.

    #[test]
    fn a_body_that_cites_a_key_without_closing_it_does_not_claim_it() {
        assert!(
            claimed_from(
                "",
                "",
                "",
                "Supersedes the measurement in PROJ-133.",
                &Fake,
                Source::All,
            )
            .is_empty(),
            "citing is not claiming"
        );
    }

    #[test]
    fn closing_only_never_falls_through_to_the_branch() {
        // `--closing-only`'s whole reason: over a LOG rather than a branch the
        // fallbacks answer a different question, and source 3 in particular is
        // the citation signal CLOUD-480 was swept wrong on.
        assert!(
            claimed_from(
                "user/proj-843-campaign",
                "a title (PROJ-9)",
                "Refs: PROJ-1170\n",
                "",
                &Fake,
                Source::ClosingOnly,
            )
            .is_empty(),
            "with no closing keyword the answer is empty, never the branch or a trailer"
        );
        assert_eq!(
            claimed_from("", "", "", "Closes PROJ-7.", &Fake, Source::ClosingOnly),
            vec![String::from("PROJ-7")],
            "and a closing keyword still answers"
        );
    }

    #[test]
    fn refs_first_only_ignores_a_closing_keyword_in_the_body() {
        // CLOUD-674's circularity: `closing-key-check` subtracts the keys a body
        // CLOSES from the keys the branch SERVED, so the served set must be
        // derived without reference to the closing keys — otherwise it agrees
        // with the body by construction and the gate passes on exactly the
        // bodies it must refuse.
        assert_eq!(
            claimed_from(
                "user/proj-9-thing",
                "",
                "Refs: PROJ-1170\n",
                "Closes PROJ-7.",
                &Fake,
                Source::RefsFirstOnly,
            ),
            vec![String::from("PROJ-1170")],
            "source 3 alone, never sources 1 or 2"
        );
    }

    #[test]
    fn the_default_source_is_the_whole_chain_in_order() {
        // The anti-vacuity mirror for the two narrowing cases: a selector that
        // returned nothing for every variant would pass both of them.
        assert_eq!(
            claimed_from(
                "user/proj-843-x",
                "",
                "",
                "Closes PROJ-1170.",
                &Fake,
                Source::All
            ),
            vec![String::from("PROJ-1170")],
            "a closing keyword OVERRIDES the branch"
        );
        assert_eq!(
            claimed_from("user/proj-843-x", "", "", "", &Fake, Source::All),
            vec![String::from("PROJ-843")],
            "failing that, the branch"
        );
        assert_eq!(
            claimed_from("", "", "Refs: PROJ-1170\n", "", &Fake, Source::All),
            vec![String::from("PROJ-1170")],
            "failing that, the first key of a `Refs:` trailer"
        );
    }

    /// Fails by: the published-as base ignored, honoured when blank, or
    /// honoured only when it is NOT the merge base, so another branch's
    /// replayed commits read as this one's own.
    #[test]
    fn a_published_ancestor_narrows_the_log_and_anything_else_does_not() {
        let dir = crate::scratch::scratch("race-authored-log");
        crate::gitwrite::init_on_main(&dir).unwrap();
        crate::gitwrite::commit_paths(&dir, &[], "base").unwrap();
        let base = crate::git::head_commit(&dir).unwrap();
        crate::gitwrite::commit_paths(&dir, &[], "feat: theirs").unwrap();
        let published = crate::git::head_commit(&dir).unwrap();
        crate::gitwrite::commit_paths(&dir, &[], "feat: mine").unwrap();

        let whole = authored_log_from(&dir, &base, None);
        assert!(
            whole.contains("feat: theirs") && whole.contains("feat: mine"),
            "{whole}"
        );
        let narrowed = authored_log_from(&dir, &base, Some(published));
        assert!(narrowed.contains("feat: mine"), "{narrowed}");
        assert!(!narrowed.contains("feat: theirs"), "{narrowed}");
        assert_eq!(
            authored_log_from(&dir, &base, Some(String::from("  "))),
            whole
        );
    }
}
