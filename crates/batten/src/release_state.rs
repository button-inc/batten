//! The release path's decisions (CLOUD-2033 P3, P4): which release may be
//! deleted, whether one is in flight, where a `land` job resumes, and when a
//! version is unusable and how it is bumped.
//!
//! Each verb is a thin shell over one pure function here, so every branch a
//! workflow `case`s on is driven alone by a test:
//!
//! * `batten release discard vX` — [`discard`];
//! * `batten release in-flight` — [`in_flight`];
//! * `batten release land-state vX --sha S` — [`land_state`];
//! * `batten release bump-unusable vX` — [`unusable`], then [`bump`].

use crate::release::Get;

/// What the forge holds under one tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// No release carries the tag.
    Absent,
    /// A draft, by its release id.
    Draft(u64),
    /// A published release.
    Published,
}

/// One deletion `discard` performs, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Delete the draft release with this id.
    DeleteRelease(u64),
    /// Delete `refs/tags/vX`; a 404 is success.
    DeleteTag,
}

/// The deletions `discard` performs, or `Err` when it must refuse.
///
/// A draft loses itself and then its tag. No release means nothing is deleted,
/// so a tag left behind by a deleted immutable release is never touched. A
/// published release is refused and left intact.
///
/// # Errors
///
/// The refusal pointer, for a published release.
//MUTANT-SUITE crates/batten/tests/it/release_verify.rs
//MUTANT discard-deletes-published|s@^        Found::Published => Err(PUBLISHED.to_owned()),$@        Found::Published => Ok(vec![Step::DeleteTag]),@|discard_refuses_a_published_release
//MUTANT discard-deletes-orphan-tag|s@^        Found::Absent => Ok(Vec::new()),$@        Found::Absent => Ok(vec![Step::DeleteTag]),@|discard_leaves_an_orphan_tag_alone
pub fn discard(found: &Found) -> Result<Vec<Step>, String> {
    const PUBLISHED: &str = "it is published; a published release is never discarded";
    match found {
        Found::Absent => Ok(Vec::new()),
        Found::Draft(id) => Ok(vec![Step::DeleteRelease(*id), Step::DeleteTag]),
        Found::Published => Err(PUBLISHED.to_owned()),
    }
}

/// How long a draft counts as in flight: the gap between dispatch and queue.
pub const DRAFT_WINDOW_SECS: u64 = 10 * 60;

/// How long a failed `land` holds the landers, by default (`land_hold`).
pub const LAND_HOLD_SECS: u64 = 6 * 60 * 60;

/// How a commit relates to `main`, one answer whichever source read it
/// (CLOUD-2245). Two booleans spelled `identical` differently by the forge's
/// compare and by local ancestry, and could not say "no commit" at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// `main` is the commit.
    Identical,
    /// `main` contains the commit and has moved past it.
    MainAhead,
    /// The commit contains `main`: `main` has not reached it yet.
    MainBehind,
    /// Neither contains the other.
    Diverged,
    /// There is no commit to relate.
    Absent,
}

//MUTANT identical-read-as-behind|s@^            Some((true, true)) => Self::Identical,$@            Some((true, true)) => Self::MainBehind,@|both_producers_agree_on_every_relation
impl Relation {
    /// The forge's `compare/{main}...{commit}` status, or `None` for one it
    /// does not define. `ahead` and `behind` are the commit's, against `main`.
    #[must_use]
    pub fn of_compare(status: &str) -> Option<Self> {
        match status {
            "identical" => Some(Self::Identical),
            "behind" => Some(Self::MainAhead),
            "ahead" => Some(Self::MainBehind),
            "diverged" => Some(Self::Diverged),
            _ => None,
        }
    }

    /// Local ancestry: whether the commit is an ancestor of `main`, and
    /// whether `main` is an ancestor of the commit, or `None` for no commit.
    #[must_use]
    pub fn of_ancestry(pair: Option<(bool, bool)>) -> Self {
        match pair {
            None => Self::Absent,
            Some((true, true)) => Self::Identical,
            Some((true, false)) => Self::MainAhead,
            Some((false, true)) => Self::MainBehind,
            Some((false, false)) => Self::Diverged,
        }
    }
}

/// A published pre-release that is not latest, as the freeze reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Its tag.
    pub tag: String,
    /// How its tag commit relates to `main`.
    pub relation: Relation,
    /// Seconds since its `land` job concluded as failed, or `None` where no
    /// failed conclusion was read (still running, or never failed).
    pub land_failed_ago: Option<u64>,
}

/// What the freeze reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flight {
    /// A `release-artifacts` run is queued or in progress, by its title.
    pub active_run: Option<String>,
    /// Drafts, by tag and age in seconds.
    pub drafts: Vec<(String, u64)>,
    /// Published, non-latest pre-releases.
    pub pending: Vec<Pending>,
    /// How long a failed `land` holds.
    pub land_hold: u64,
}

/// Whether a release is in flight, naming it and the arm that holds, or `None`.
//MUTANT freeze-ignores-pending-land|s@^        if pending.relation != Relation::MainBehind {$@        if true {@|a_pending_land_is_in_flight_until_its_hold_expires
#[must_use]
pub fn in_flight(flight: &Flight) -> Option<String> {
    if let Some(run) = &flight.active_run {
        return Some(format!("a release-artifacts run is building: {run}"));
    }
    if let Some((tag, age)) = flight
        .drafts
        .iter()
        .find(|(_, age)| *age < DRAFT_WINDOW_SECS)
    {
        return Some(format!("{tag} is a draft {age}s old"));
    }
    for pending in &flight.pending {
        if pending.relation != Relation::MainBehind {
            continue;
        }
        match pending.land_failed_ago {
            Some(ago) if ago >= flight.land_hold => {}
            _ => {
                return Some(format!(
                    "{} is published and main has not reached it: its land is still owed",
                    pending.tag
                ));
            }
        }
    }
    None
}

/// What `land`'s step (a) reads about vX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// No release carries the tag.
    Absent,
    /// A draft: its `target_commitish`.
    Draft {
        /// What the draft says it was built from.
        target: String,
    },
    /// A published release: its tag commit.
    Published {
        /// What its tag points at, or `None` where it points at nothing.
        tag_commit: Option<String>,
    },
}

/// The facts `land-state` decides over, read by the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandFacts {
    /// The release as read.
    pub read: Read,
    /// The release's tag.
    pub tag: String,
    /// The `sha` input the build was dispatched with.
    pub sha: String,
    /// How the commit in question (the tag commit when published, the target
    /// when a draft) relates to `main`.
    pub relation: Relation,
    /// The commit `refs/tags/vX` points at, if the ref exists.
    pub tag_ref: Option<String>,
    /// The pin and version at the draft's target, as `git show` read them.
    pub pin_at_target: Option<String>,
    /// The version at the draft's target.
    pub version_at_target: Option<String>,
    /// `sha` as a release head, read where the draft targets another commit:
    /// whether it is that target's bake is [`baked_onto`]'s (CLOUD-2287).
    pub head: Option<Head>,
    /// The draft's own `SHA256SUMS`, read where `head` is.
    pub draft_sums: Option<String>,
}

/// A release head as the bake's readers see it (CLOUD-2287).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Its first parent, or `None` for a root commit.
    pub parent: Option<String>,
    /// The paths it changes from that parent.
    pub changed: std::collections::BTreeSet<String>,
    /// Its `install.lock`, where it carries one.
    pub lock: Option<String>,
}

/// Whether `head` is a BAKED head of the draft target `target` (CLOUD-2287): a
/// child of it whose diff is exactly `install.lock` and `install.sh`, and whose
/// lock names release `tag` with every line the draft's `sums` publishes.
#[must_use]
pub fn baked_onto(head: &Head, target: &str, tag: &str, sums: &str) -> bool {
    let baked: std::collections::BTreeSet<String> = [crate::install::LOCK_FILE, BOOTSTRAP_FILE]
        .into_iter()
        .map(String::from)
        .collect();
    let lock_agrees = head
        .lock
        .as_deref()
        .and_then(|text| crate::install::Lock::parse(text).ok())
        .is_some_and(|lock| {
            lock.tag == tag && !lock.sums.is_empty() && lock.disagreements(sums).is_empty()
        });
    head.parent.as_deref() == Some(target) && head.changed == baked && lock_agrees
}

/// What the release-head build does with a draft already open (CLOUD-2287).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutOrLand {
    /// Discard the draft and cut again at the head: the release head moved.
    Cut,
    /// The head is the draft target's bake: land it, never cut it again.
    Land,
}

/// `run_cut`'s decision, before it discards anything: a green baked head of the
/// open draft's target is landed; any other head is cut as before, which is what
/// keeps the bake from looping — its own CI completing on the release branch
/// would otherwise discard the draft it was baked from.
//MUTANT-SUITE crates/batten/tests/it/release_verify.rs
//MUTANT baked-head-recut|s@^    if draft_target.is_some_and(\x7ctarget\x7c baked_onto(head, target, tag, sums)) {$@    if false {@|cut_or_land_lands_a_baked_head_and_cuts_any_other
#[must_use]
pub fn cut_or_land(draft_target: Option<&str>, head: &Head, tag: &str, sums: &str) -> CutOrLand {
    if draft_target.is_some_and(|target| baked_onto(head, target, tag, sums)) {
        return CutOrLand::Land;
    }
    CutOrLand::Cut
}

/// Whether `facts.sha` is the bake of the draft target `target`.
fn is_baked(facts: &LandFacts, target: &str) -> bool {
    match (&facts.head, facts.draft_sums.as_deref()) {
        (Some(head), Some(sums)) => baked_onto(head, target, &facts.tag, sums),
        _ => false,
    }
}

/// `land`'s branch, as one line the workflow `case`s on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandState {
    /// Published at S and `main` contains it: skip to (f).
    SkipToF,
    /// Published at S and `main` is behind it: resume at (d).
    ResumeAtD,
    /// Published otherwise.
    Burned,
    /// A draft every assertion of (a) holds for.
    DraftOk,
    /// A draft an assertion of (a) fails for.
    DraftBad(String),
    /// No release.
    Absent,
}

impl LandState {
    /// The exact line printed.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::SkipToF => String::from("skip-to-f"),
            Self::ResumeAtD => String::from("resume-at-d"),
            Self::Burned => String::from("burned"),
            Self::DraftOk => String::from("draft-ok"),
            Self::DraftBad(why) => format!("draft-bad {why}"),
            Self::Absent => String::from("absent"),
        }
    }
}

/// Whether `text` is a full 40-hex commit id.
fn full_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `land`'s step (a), decided. A draft targeting A is landed at `sha` when
/// `sha` is A itself or A's bake (CLOUD-2287): the bake commits only the
/// install lock and the script rendered from it, so A's pin, version and
/// relation to `main` are the release's.
//MUTANT baked-head-refused|s@^            let baked = is_baked(facts, target);$@            let baked = false;@|a_baked_head_of_the_drafts_target_is_draft_ok
//MUTANT land-state-resume-as-burned|s@^                (true, Relation::MainBehind) => LandState::ResumeAtD,$@                (true, Relation::MainBehind) => LandState::Burned,@|land_state_resumes_a_published_release_main_is_behind
#[must_use]
pub fn land_state(facts: &LandFacts) -> LandState {
    match &facts.read {
        Read::Absent => LandState::Absent,
        Read::Published { tag_commit } => {
            let at_sha = tag_commit.as_deref() == Some(facts.sha.as_str());
            match (at_sha, facts.relation) {
                (true, Relation::Identical | Relation::MainAhead) => LandState::SkipToF,
                (true, Relation::MainBehind) => LandState::ResumeAtD,
                _ => LandState::Burned,
            }
        }
        Read::Draft { target } => {
            let version = facts.tag.trim_start_matches('v');
            let baked = is_baked(facts, target);
            if !full_sha(target) || (*target != facts.sha && !baked) {
                LandState::DraftBad(format!("its target {target} is not {}", facts.sha))
            } else if facts.tag_ref.as_ref().is_some_and(|at| at != target) {
                LandState::DraftBad(format!("refs/tags/{} is at another commit", facts.tag))
            } else if facts.pin_at_target.as_deref() != Some(facts.tag.as_str())
                || facts.version_at_target.as_deref() != Some(version)
            {
                LandState::DraftBad(format!(
                    "the pin and version at {target} are not {} and {version}",
                    facts.tag
                ))
            } else if !matches!(facts.relation, Relation::Identical | Relation::MainBehind) {
                LandState::DraftBad(format!("main is not an ancestor of {target}"))
            } else {
                LandState::DraftOk
            }
        }
    }
}

/// Whether a build of `sha` may upload into the release vX: only into a draft
/// whose target is `sha`, so a build of one commit never fills a draft for
/// another and never replaces a published release's assets.
///
/// # Errors
///
/// The refusal pointer.
//MUTANT published-release-overwritten|s@^        Read::Published { .. } => Err(PUBLISHED.to_owned()),$@        Read::Published { .. } => Ok(()),@|guard_refuses_a_published_release_and_a_foreign_draft
pub fn guard(read: &Read, sha: &str) -> Result<(), String> {
    const PUBLISHED: &str = "it is published, and a published release's assets are never replaced";
    match read {
        Read::Draft { target } if target == sha => Ok(()),
        Read::Draft { target } => Err(format!("the draft targets {target}, not {sha}")),
        Read::Published { .. } => Err(PUBLISHED.to_owned()),
        Read::Absent => Err(String::from("no release carries the tag")),
    }
}

/// Why a version cannot be released again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// A published release whose tag commit `main` cannot reach.
    Burned,
    /// `refs/tags/vX` exists and no release carries it.
    StrayTag,
}

/// Whether vX is unusable: burned, or a stray tag.
///
/// `reachable` is whether `main` reaches a published release's tag commit.
//MUTANT stray-tag-not-unusable|s@^        Found::Absent if tag_exists => Some(Unusable::StrayTag),$@        Found::Absent if false => Some(Unusable::StrayTag),@|a_stray_tag_is_unusable
#[must_use]
pub fn unusable(found: &Found, reachable: bool, tag_exists: bool) -> Option<Unusable> {
    match found {
        Found::Published if !reachable => Some(Unusable::Burned),
        Found::Absent if tag_exists => Some(Unusable::StrayTag),
        _ => None,
    }
}

/// The next patch version: `0.0.214` → `0.0.215`, or `None` for a version
/// that is not three dot-separated numbers.
#[must_use]
pub fn next_version(version: &str) -> Option<String> {
    let mut parts: Vec<u64> = version
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.len() != 3 {
        return None;
    }
    parts[2] += 1;
    Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
}

/// The four files a bump moves, as text in and text out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
    /// `Cargo.toml`.
    pub manifest: String,
    /// `Cargo.lock`.
    pub lock: String,
    /// `batten.toml`.
    pub config: String,
    /// `crates/batten/CHANGELOG.md`.
    pub changelog: String,
}

/// Move X to X+1 in all four release paths, in one change: `Cargo.toml`'s
/// version, every `Cargo.lock` entry of a workspace package at X, the pin, and
/// the changelog's `## [X]` heading with its compare link.
///
/// # Errors
///
/// The pointer naming the file that does not carry X where it must.
//MUTANT bump-keeps-changelog-heading|s@^    let changelog = bump_heading(\&files.changelog, from, \&to)$@    let changelog = Some(files.changelog.clone())@|an_unusable_version_bumps_all_four_paths
pub fn bump(files: &Files, from: &str, packages: &[String]) -> Result<(String, Files), String> {
    let to = next_version(from).ok_or_else(|| format!("{from} is not a patch version"))?;
    let old_line = format!("version = \"{from}\"");
    let new_line = format!("version = \"{to}\"");
    if !files.manifest.lines().any(|line| line.trim() == old_line) {
        return Err(format!("Cargo.toml does not carry {old_line}"));
    }
    let manifest = files.manifest.replacen(&old_line, &new_line, 1);
    let lock = bump_lock(&files.lock, packages, &old_line, &new_line);
    let old_pin = format!("release = \"v{from}\"");
    if !files.config.contains(&old_pin) {
        return Err(format!("batten.toml does not pin v{from}"));
    }
    let config = files
        .config
        .replacen(&old_pin, &format!("release = \"v{to}\""), 1);
    let changelog = bump_heading(&files.changelog, from, &to)
        .ok_or_else(|| format!("the changelog has no ## [{from}] heading"))?;
    Ok((
        to,
        Files {
            manifest,
            lock,
            config,
            changelog,
        },
    ))
}

/// `Cargo.lock` with each named package's `version = "X"` line moved.
fn bump_lock(lock: &str, packages: &[String], old_line: &str, new_line: &str) -> String {
    let mut ours = false;
    let mut out: Vec<String> = Vec::new();
    for line in lock.lines() {
        if line == "[[package]]" {
            ours = false;
        } else if let Some(name) = line
            .strip_prefix("name = \"")
            .and_then(|rest| rest.strip_suffix('"'))
        {
            ours = packages.iter().any(|package| package == name);
        }
        if ours && line == old_line {
            out.push(new_line.to_owned());
        } else {
            out.push(line.to_owned());
        }
    }
    let mut text = out.join("\n");
    if lock.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// The changelog with its `## [X]` heading, and that heading's compare link,
/// moved to X+1, or `None` where no such heading exists.
fn bump_heading(changelog: &str, from: &str, to: &str) -> Option<String> {
    let opener = format!("## [{from}]");
    let mut found = false;
    let lines: Vec<String> = changelog
        .lines()
        .map(|line| {
            if !found && line.starts_with(&opener) {
                found = true;
                line.replacen(&opener, &format!("## [{to}]"), 1).replacen(
                    &format!("...v{from})"),
                    &format!("...v{to})"),
                    1,
                )
            } else {
                line.to_owned()
            }
        })
        .collect();
    if !found {
        return None;
    }
    let mut text = lines.join("\n");
    if changelog.ends_with('\n') {
        text.push('\n');
    }
    Some(text)
}

/// The forge's answer at `path` parsed as JSON, `Ok(None)` on a 404, or the
/// could-not-look pointer.
fn json_at(get: Get<'_>, path: &str) -> Result<Option<serde_json::Value>, String> {
    let answer = get(path).ok_or_else(|| format!("{path} did not answer"))?;
    if answer.status == 404 {
        return Ok(None);
    }
    if !answer.is_reading() {
        return Err(format!("{path} answered {}", answer.status));
    }
    serde_json::from_str(&answer.body)
        .map(Some)
        .map_err(|_| format!("{path} is not JSON"))
}

/// What the forge holds under `tag`: a published release by its tag read, a
/// draft from the release list, or neither.
///
/// # Errors
///
/// The could-not-look pointer.
pub fn read_found(slug: &str, tag: &str, get: Get<'_>) -> Result<Found, String> {
    if json_at(get, &format!("repos/{slug}/releases/tags/{tag}"))?.is_some() {
        return Ok(Found::Published);
    }
    let list = format!("repos/{slug}/releases?per_page=100");
    let listed = json_at(get, &list)?.ok_or_else(|| format!("{list} answered 404"))?;
    let entry = listed
        .as_array()
        .ok_or_else(|| format!("{list} is not a release list"))?
        .iter()
        .find(|entry| entry.get("tag_name").and_then(serde_json::Value::as_str) == Some(tag));
    let Some(entry) = entry else {
        return Ok(Found::Absent);
    };
    if entry.get("draft").and_then(serde_json::Value::as_bool) != Some(true) {
        return Ok(Found::Published);
    }
    entry
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .map(Found::Draft)
        .ok_or_else(|| format!("the draft {tag} carries no id"))
}

/// Whether `refs/tags/<tag>` exists.
///
/// # Errors
///
/// The could-not-look pointer.
pub fn tag_exists(slug: &str, tag: &str, get: Get<'_>) -> Result<bool, String> {
    Ok(json_at(get, &format!("repos/{slug}/git/ref/tags/{tag}"))?.is_some())
}

/// Whether the `settings` job of the latest completed run of the release guard
/// `workflow` on the trunk concluded success. No run is not green.
///
/// # Errors
///
/// The could-not-look pointer.
pub fn settings_green(
    slug: &str,
    trunk: &str,
    workflow: &str,
    get: Get<'_>,
) -> Result<bool, String> {
    let runs = format!(
        "repos/{slug}/actions/workflows/{workflow}/runs?branch={trunk}&status=completed&per_page=1"
    );
    let Some(listed) = json_at(get, &runs)? else {
        return Ok(false);
    };
    let Some(id) = listed
        .get("workflow_runs")
        .and_then(serde_json::Value::as_array)
        .and_then(|runs| runs.first())
        .and_then(|run| run.get("id"))
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(false);
    };
    let path = format!("repos/{slug}/actions/runs/{id}/jobs?per_page=100");
    let jobs = json_at(get, &path)?.ok_or_else(|| format!("{path} answered 404"))?;
    Ok(jobs
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|job| {
            job.get("name").and_then(serde_json::Value::as_str) == Some("settings")
                && crate::forge::RunState::of_row(job)
                    .conclusion()
                    .is_some_and(crate::forge::Conclusion::publishes)
        }))
}

/// How `commit` relates to `main`, by the forge's compare.
fn compare(slug: &str, main: &str, commit: &str, get: Get<'_>) -> Result<Relation, String> {
    let path = format!("repos/{slug}/compare/{main}...{commit}");
    let value = json_at(get, &path)?.ok_or_else(|| format!("{path} answered 404"))?;
    value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .and_then(Relation::of_compare)
        .ok_or_else(|| format!("{path} carries no status"))
}

/// Seconds since the `land` job of the build titled for `tag` concluded as
/// failed, or `None` where no such conclusion was read.
fn land_failed_ago(
    slug: &str,
    tag: &str,
    runs: &[serde_json::Value],
    now: i64,
    get: Get<'_>,
) -> Result<Option<u64>, String> {
    let field = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };
    let Some(run) = runs.iter().find(|run| {
        field(run, "display_title")
            .is_some_and(|title| title.split_whitespace().any(|word| word == tag))
    }) else {
        return Ok(None);
    };
    let id = run
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("the build run for {tag} carries no id"))?;
    let path = format!("repos/{slug}/actions/runs/{id}/jobs?per_page=100");
    let jobs = json_at(get, &path)?.ok_or_else(|| format!("{path} answered 404"))?;
    let failed = jobs
        .get("jobs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|job| field(job, "name").as_deref() == Some("land"))
        .filter(|job| field(job, "conclusion").as_deref() == Some("failure"))
        .filter_map(|job| field(job, "completed_at").and_then(|at| crate::ci_signal::epoch(&at)))
        .max();
    Ok(failed.map(|at| u64::try_from(now.saturating_sub(at)).unwrap_or(0)))
}

/// Everything the freeze reads, from the forge: each release `workflow`'s runs
/// — the build's and, since CLOUD-2287, the land's — titled by their tag, and
/// the releases.
///
/// # Errors
///
/// The could-not-look pointer: any read that did not answer.
pub fn read_flight(
    slug: &str,
    (main, workflows): (&str, &[String]),
    now: i64,
    land_hold: u64,
    get: Get<'_>,
) -> Result<Flight, String> {
    let mut runs = Vec::new();
    for workflow in workflows {
        let runs_path = format!("repos/{slug}/actions/workflows/{workflow}/runs?per_page=30");
        runs.extend(
            json_at(get, &runs_path)?
                .and_then(|value| value.get("workflow_runs").cloned())
                .and_then(|runs| runs.as_array().cloned())
                .unwrap_or_default(),
        );
    }
    let active_run = runs
        .iter()
        .find(|run| crate::forge::RunState::of_row(run).conclusion().is_none())
        .map(|run| {
            run.get("display_title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("untitled")
                .to_owned()
        });
    let list = format!("repos/{slug}/releases?per_page=30");
    let listed = json_at(get, &list)?.ok_or_else(|| format!("{list} answered 404"))?;
    let latest = json_at(get, &format!("repos/{slug}/releases/latest"))?.and_then(|value| {
        value
            .get("tag_name")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    });
    let mut drafts = Vec::new();
    let mut pending = Vec::new();
    for entry in listed.as_array().into_iter().flatten() {
        let tag = entry
            .get("tag_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let flag = |key: &str| entry.get(key).and_then(serde_json::Value::as_bool) == Some(true);
        if flag("draft") {
            let created = entry
                .get("created_at")
                .and_then(serde_json::Value::as_str)
                .and_then(crate::ci_signal::epoch)
                .ok_or_else(|| format!("the draft {tag} carries no created_at"))?;
            drafts.push((tag, u64::try_from(now.saturating_sub(created)).unwrap_or(0)));
        } else if flag("prerelease") && latest.as_deref() != Some(tag.as_str()) {
            let commit = crate::release_verify::tag_commit(slug, &tag, get)
                .ok_or_else(|| format!("the pre-release {tag} has no readable tag"))?;
            let relation = compare(slug, main, &commit, get)?;
            let land_failed_ago = land_failed_ago(slug, &tag, &runs, now, get)?;
            pending.push(Pending {
                tag,
                relation,
                land_failed_ago,
            });
        }
    }
    Ok(Flight {
        active_run,
        drafts,
        pending,
        land_hold,
    })
}

/// The forge slug of the clone at `here`, or the could-not-look line printed
/// and `None`.
fn slug_or_say(
    here: &std::path::Path,
    verb: &str,
    err: &mut dyn std::io::Write,
) -> std::io::Result<Option<String>> {
    let slug = crate::repo_slug(here);
    if slug.is_none() {
        writeln!(
            err,
            "batten: release {verb}: could not look: no forge remote names the repository"
        )?;
    }
    Ok(slug)
}

/// The trunk's tracking ref and short name in the clone at `here`, or the
/// could-not-look pointer.
fn trunk(here: &std::path::Path) -> Result<(String, String), String> {
    match crate::worktree::declared_trunk(here) {
        Ok(Some(trunk)) => Ok((trunk.tracking, trunk.short)),
        Ok(None) => Err(crate::worktree::NO_TRUNK.to_owned()),
        Err(why) => Err(why.to_string()),
    }
}

/// `batten release discard <tag>`: a draft and its tag deleted, nothing
/// deleted for no release, a published release refused. `here` is the clone
/// whose forge remote names the repository.
///
/// The deletions are [`perform_discard`]'s, the one loop `cut` shares, rather
/// than a second copy of it (CLOUD-2509).
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_discard(
    here: &std::path::Path,
    tag: &str,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let Some(slug) = slug_or_say(here, "discard", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    match perform_discard(&slug, tag, &get) {
        Ok(Ok(0)) => {
            writeln!(
                out,
                "release discard: no release is tagged {tag}; nothing deleted"
            )?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Ok(_)) => {
            writeln!(out, "release discard: deleted the draft {tag} and its tag")?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Err(why)) => {
            writeln!(err, "release discard: {tag}: {why}")?;
            Ok(crate::ExitCode::Violation)
        }
        Err(why) => {
            writeln!(err, "batten: release discard: could not finish: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// `batten release in-flight --workflow <file>...`: exit 0 when nothing is in
/// flight, 2 naming what is, 3 when it could not look. `workflow` is the build
/// workflow's file, whose runs are titled by their tag.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_in_flight(
    workflows: &[String],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let here = std::path::Path::new(".");
    let Some(slug) = slug_or_say(here, "in-flight", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    let now = i64::try_from(crate::now_unix()).unwrap_or(i64::MAX);
    let flight = trunk(here)
        .and_then(|(_, short)| read_flight(&slug, (&short, workflows), now, LAND_HOLD_SECS, &get));
    match flight.map(|flight| in_flight(&flight)) {
        Ok(None) => {
            writeln!(out, "release in-flight: nothing is in flight")?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Some(why)) => {
            writeln!(err, "release in-flight: {why}")?;
            Ok(crate::ExitCode::Violation)
        }
        Err(why) => {
            writeln!(err, "batten: release in-flight: could not look: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// `land`'s step (a) facts, read from the forge and the local clone.
fn land_facts(
    here: &std::path::Path,
    slug: &str,
    (tag, sha): (&str, &str),
    get: Get<'_>,
) -> Result<LandFacts, String> {
    let (tracking, _) = trunk(here)?;
    let read = read_release(slug, tag, get)?;
    let commit = match &read {
        Read::Absent => None,
        Read::Draft { target } => Some(target.clone()),
        Read::Published { tag_commit } => tag_commit.clone(),
    };
    let ancestry = |ancestor: &str, descendant: &str| {
        crate::git::is_ancestor(here, ancestor, descendant)
            .map(|answer| answer == Some(true))
            .map_err(|why| why.to_string())
    };
    let relation = Relation::of_ancestry(match &commit {
        Some(commit) => Some((ancestry(commit, &tracking)?, ancestry(&tracking, commit)?)),
        None => None,
    });
    let at = |path: &str| {
        commit
            .as_deref()
            .and_then(|commit| crate::git::show(here, commit, path).ok())
    };
    let (head, draft_sums) = match &read {
        Read::Draft { target } if target != sha => (
            Some(read_head(here, sha)?),
            release_sums(slug, tag, get)?.ok(),
        ),
        _ => (None, None),
    };
    Ok(LandFacts {
        head,
        draft_sums,
        tag_ref: matches!(read, Read::Draft { .. })
            .then(|| crate::release_verify::tag_commit(slug, tag, get))
            .flatten(),
        pin_at_target: at("batten.toml").and_then(|config| crate::release_path::pin_of(&config)),
        version_at_target: at("Cargo.toml")
            .and_then(|manifest| crate::release_path::version_of(&manifest)),
        read,
        tag: tag.to_owned(),
        sha: sha.to_owned(),
        relation,
    })
}

/// `batten release land-state <tag> --sha <sha>`: exactly one line `land`
/// `case`s on, exit 0, or exit 3 when it could not look.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_land_state(
    tag: &str,
    sha: &str,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let here = std::path::Path::new(".");
    let Some(slug) = slug_or_say(here, "land-state", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    match land_facts(here, &slug, (tag, sha), &get) {
        Ok(facts) => {
            writeln!(out, "{}", land_state(&facts).line())?;
            Ok(crate::ExitCode::Success)
        }
        Err(why) => {
            writeln!(err, "batten: release land-state: could not look: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// The release as `guard` and `land-state` read it.
fn read_release(slug: &str, tag: &str, get: Get<'_>) -> Result<Read, String> {
    Ok(match read_found(slug, tag, get)? {
        Found::Absent => Read::Absent,
        Found::Draft(_) => Read::Draft {
            target: crate::release_verify::read(slug, tag, get)?.target,
        },
        Found::Published => Read::Published {
            tag_commit: crate::release_verify::tag_commit(slug, tag, get),
        },
    })
}

/// `batten release guard <tag> --sha <sha>`: exit 0 only when a build of
/// `sha` may upload into vX, 1 when it may not, 3 when it could not look.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_guard(
    tag: &str,
    sha: &str,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let Some(slug) = slug_or_say(std::path::Path::new("."), "guard", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    match read_release(&slug, tag, &get).map(|read| guard(&read, sha)) {
        Ok(Ok(())) => {
            writeln!(out, "release guard: {tag} is a draft of {sha}")?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Err(why)) => {
            writeln!(err, "release guard: {tag}: {why}")?;
            Ok(crate::ExitCode::Violation)
        }
        Err(why) => {
            writeln!(err, "batten: release guard: could not look: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// The workspace's own package names, from `Cargo.lock`'s path-sourced entries
/// (those without a `source` line).
fn workspace_packages(lock: &str) -> Vec<String> {
    let mut packages = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        if block.lines().any(|line| line.starts_with("source = ")) {
            continue;
        }
        if let Some(name) = block.lines().find_map(|line| {
            line.strip_prefix("name = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        }) {
            packages.push(name.to_owned());
        }
    }
    packages
}

/// The sha a forge answer names under `key`, or the could-not-look pointer.
fn sha_in(answer: Option<crate::rest::Answer>, what: &str, key: &str) -> Result<String, String> {
    let answer = answer.ok_or_else(|| format!("{what} did not answer"))?;
    if !(200..300).contains(&answer.status) {
        return Err(format!("{what} answered {}", answer.status));
    }
    let value: serde_json::Value =
        serde_json::from_str(&answer.body).map_err(|_| format!("{what} is not JSON"))?;
    value
        .pointer(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{what} names no {key}"))
}

/// Whether vX is unusable, read from the forge and the local trunk.
fn judge_unusable(
    here: &std::path::Path,
    slug: &str,
    tag: &str,
    get: Get<'_>,
) -> Result<Option<Unusable>, String> {
    let found = read_found(slug, tag, get)?;
    let reachable = match &found {
        Found::Published => {
            let (tracking, _) = trunk(here)?;
            crate::release_verify::tag_commit(slug, tag, get).is_some_and(|commit| {
                crate::git::is_ancestor(here, &commit, &tracking)
                    .ok()
                    .flatten()
                    == Some(true)
            })
        }
        _ => true,
    };
    Ok(unusable(&found, reachable, tag_exists(slug, tag, get)?))
}

/// Commit `files` onto `branch`'s head through the forge's git-data API and
/// move the branch to it, fast-forward only. No checkout of the branch is made
/// and nothing on it runs: the four texts were read with `git show`.
fn commit_onto(
    slug: &str,
    (branch, head): (&str, &str),
    files: &[(&str, &str, &str)],
    message: &str,
    get: Get<'_>,
) -> Result<String, String> {
    let commit_path = format!("repos/{slug}/git/commits/{head}");
    let base_tree = json_at(get, &commit_path)?
        .and_then(|commit| {
            commit
                .pointer("/tree/sha")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| format!("{commit_path} names no tree"))?;
    let mut entries = Vec::new();
    for (path, text, mode) in files {
        let body = serde_json::json!({ "content": text, "encoding": "utf-8" });
        let blob = sha_in(
            crate::rest::post_json(&format!("repos/{slug}/git/blobs"), &body),
            &format!("the blob for {path}"),
            "/sha",
        )?;
        entries
            .push(serde_json::json!({ "path": path, "mode": mode, "type": "blob", "sha": blob }));
    }
    let tree = sha_in(
        crate::rest::post_json(
            &format!("repos/{slug}/git/trees"),
            &serde_json::json!({ "base_tree": base_tree, "tree": entries }),
        ),
        "the bumped tree",
        "/sha",
    )?;
    let commit = sha_in(
        crate::rest::post_json(
            &format!("repos/{slug}/git/commits"),
            &serde_json::json!({ "message": message, "tree": tree, "parents": [head] }),
        ),
        "the bump commit",
        "/sha",
    )?;
    let moved = crate::rest::patch_json(
        &format!("repos/{slug}/git/refs/heads/{branch}"),
        &serde_json::json!({ "sha": commit, "force": false }),
    )
    .ok_or_else(|| format!("moving {branch} did not answer"))?;
    if (200..300).contains(&moved.status) {
        Ok(commit)
    } else {
        Err(format!("moving {branch} answered {}", moved.status))
    }
}

/// `batten release bump-unusable <tag> --branch <branch> --changelog <path>`:
/// when vX is burned or a stray tag, move the four release paths to X+1 in one
/// commit on the release branch — made through the forge, so the credential
/// that moves the branch is the one that fires its CI — and print `bumped vX
/// vY`; otherwise print `usable vX` and change nothing. Exit 3 when it could
/// not look.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_bump_unusable(
    tag: &str,
    (branch, changelog): (&str, &str),
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let here = std::path::Path::new(".");
    let Some(slug) = slug_or_say(here, "bump-unusable", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    let why = match judge_unusable(here, &slug, tag, &get) {
        Ok(Some(why)) => why,
        Ok(None) => {
            writeln!(out, "usable {tag}")?;
            return Ok(crate::ExitCode::Success);
        }
        Err(why) => {
            writeln!(err, "batten: release bump-unusable: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    let paths = ["Cargo.toml", "Cargo.lock", "batten.toml", changelog];
    let read = (|| -> Result<(String, Vec<String>), String> {
        let ref_path = format!("repos/{slug}/git/ref/heads/{branch}");
        let head = json_at(&get, &ref_path)?
            .and_then(|found| {
                found
                    .pointer("/object/sha")
                    .and_then(serde_json::Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .ok_or_else(|| format!("{ref_path} names no commit"))?;
        let texts = paths
            .iter()
            .map(|path| crate::git::show(here, &head, path).map_err(|why| why.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((head, texts))
    })();
    let (head, texts) = match read {
        Ok(read) => read,
        Err(why) => {
            writeln!(err, "batten: release bump-unusable: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    let [manifest, lock, config, log]: [String; 4] = texts
        .try_into()
        .map_err(|_| anyhow::anyhow!("four paths read"))?;
    let packages = workspace_packages(&lock);
    let files = Files {
        manifest,
        lock,
        config,
        changelog: log,
    };
    let (to, bumped) = match bump(&files, tag.trim_start_matches('v'), &packages) {
        Ok(bumped) => bumped,
        Err(why) => {
            writeln!(err, "release bump-unusable: {tag}: {why}")?;
            return Ok(crate::ExitCode::Violation);
        }
    };
    let reason = match why {
        Unusable::Burned => "burned",
        Unusable::StrayTag => "a stray tag",
    };
    let message = format!("chore(release): {tag} is {reason}; bump to v{to}");
    let written = [
        (paths[0], bumped.manifest.as_str(), "100644"),
        (paths[1], bumped.lock.as_str(), "100644"),
        (paths[2], bumped.config.as_str(), "100644"),
        (paths[3], bumped.changelog.as_str(), "100644"),
    ];
    match commit_onto(&slug, (branch, &head), &written, &message, &get) {
        Ok(commit) => {
            writeln!(out, "bumped {tag} v{to} at {commit} ({tag} is {reason})")?;
            Ok(crate::ExitCode::Success)
        }
        Err(why) => {
            writeln!(err, "batten: release bump-unusable: could not write: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// The body of the changelog's `## [version]` section — every line after its
/// heading up to the next `## [` heading — or `None` where there is none.
//MUTANT notes-section-unbounded|s@^        if line.starts_with("## \[") {$@        if false {@|the_notes_are_the_versions_own_section
#[must_use]
pub fn section(changelog: &str, version: &str) -> Option<String> {
    let opener = format!("## [{version}]");
    let mut lines = changelog
        .lines()
        .skip_while(|line| !line.starts_with(&opener));
    lines.next()?;
    let mut body = Vec::new();
    for line in lines {
        if line.starts_with("## [") {
            break;
        }
        body.push(line);
    }
    Some(body.join("\n").trim().to_owned())
}

/// Delete whatever `discard` says to for `tag`: `Ok(Ok(n))` deletions made,
/// `Ok(Err(why))` a refusal, `Err` could-not-look.
fn perform_discard(slug: &str, tag: &str, get: Get<'_>) -> Result<Result<usize, String>, String> {
    let steps = match discard(&read_found(slug, tag, get)?) {
        Ok(steps) => steps,
        Err(why) => return Ok(Err(why)),
    };
    let made = steps.len();
    for step in steps {
        let (path, gone_is_fine) = match step {
            Step::DeleteRelease(id) => (format!("repos/{slug}/releases/{id}"), false),
            Step::DeleteTag => (format!("repos/{slug}/git/refs/tags/{tag}"), true),
        };
        match crate::rest::delete(&path) {
            Some(answer) if (200..300).contains(&answer.status) => {}
            Some(answer) if gone_is_fine && matches!(answer.status, 404 | 422) => {}
            Some(answer) => return Err(format!("{path} answered {}", answer.status)),
            None => return Err(format!("{path} did not answer")),
        }
    }
    Ok(Ok(made))
}

/// `batten release cut <tag> --sha <sha> --changelog <path> --workflow <file>`
/// (P3.1): discard any draft of vX, create the draft at the release head with
/// the changelog section the head carries, and dispatch the build workflow with
/// that tag and sha. It creates no tag — a draft's tag is GitHub's, made at
/// publish — and runs nothing from the head: the notes are read with `git
/// show`.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_cut(
    here: &std::path::Path,
    (tag, sha): (&str, &str),
    (changelog, workflow, land_workflow): (&str, &str, Option<&str>),
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let Some(slug) = slug_or_say(here, "cut", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    let dispatch = |file: &str, trunk: &str| -> Result<(), String> {
        let body = serde_json::json!({ "ref": trunk, "inputs": { "tag": tag, "sha": sha } });
        let path = format!("repos/{slug}/actions/workflows/{file}/dispatches");
        match crate::rest::post_json(&path, &body) {
            Some(answer) if (200..300).contains(&answer.status) => Ok(()),
            Some(answer) => Err(format!("{path} answered {}", answer.status)),
            None => Err(format!("{path} did not answer")),
        }
    };
    let cut = (|| -> Result<Result<Option<String>, String>, String> {
        let (_, trunk) = trunk(here)?;
        // CUT OR LAND, BEFORE ANYTHING IS DISCARDED (CLOUD-2287): the bake's own
        // CI on the release branch brings this job back at B, and cutting B
        // again would discard the draft B was baked from, forever.
        if let Some(land) = land_workflow
            && let Read::Draft { target } = read_release(&slug, tag, &get)?
            && target != sha
            && let Ok(sums) = release_sums(&slug, tag, &get)?
        {
            let head = read_head(here, sha)?;
            if cut_or_land(Some(&target), &head, tag, &sums) == CutOrLand::Land {
                dispatch(land, &trunk)?;
                return Ok(Ok(Some(land.to_owned())));
            }
        }
        if let Err(why) = perform_discard(&slug, tag, &get)? {
            return Ok(Err(why));
        }
        let text = crate::git::show(here, sha, changelog).map_err(|why| why.to_string())?;
        let Some(notes) = section(&text, tag.trim_start_matches('v')) else {
            return Ok(Err(format!(
                "{changelog} at {sha} has no section for {tag}"
            )));
        };
        let body = serde_json::json!({
            "tag_name": tag,
            "target_commitish": sha,
            "name": tag,
            "body": notes,
            "draft": true,
        });
        sha_in(
            crate::rest::post_json(&format!("repos/{slug}/releases"), &body),
            &format!("the draft {tag}"),
            "/tag_name",
        )?;
        dispatch(workflow, &trunk)?;
        Ok(Ok(None))
    })();
    match cut {
        Ok(Ok(Some(land))) => {
            writeln!(
                out,
                "release cut: {sha} is the bake of {tag}'s draft; {land} dispatched"
            )?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Ok(None)) => {
            writeln!(
                out,
                "release cut: {tag} drafted at {sha}; {workflow} dispatched"
            )?;
            Ok(crate::ExitCode::Success)
        }
        Ok(Err(why)) => {
            writeln!(err, "release cut: {tag}: {why}")?;
            Ok(crate::ExitCode::Violation)
        }
        Err(why) => {
            writeln!(err, "batten: release cut: could not look: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// The lock release `tag` bakes: its `SHA256SUMS`, read through the assets API
/// for a draft or its public URL once published, cut to the bootstrap's targets.
/// `Ok(Err)` is the release's fault, `Err` could-not-look.
fn read_lock(
    slug: &str,
    tag: &str,
    get: Get<'_>,
) -> Result<Result<crate::install::Lock, String>, String> {
    let sums = match release_sums(slug, tag, get)? {
        Ok(sums) => sums,
        Err(why) => return Ok(Err(why)),
    };
    Ok(
        crate::install::Lock::from_sums(env!("CARGO_PKG_NAME"), tag, &sums)
            .map_err(|why| why.to_string()),
    )
}

/// Release `tag`'s `SHA256SUMS` text: through the assets API for a draft, its
/// public URL once published. `Ok(Err)` for a release carrying none.
fn release_sums(slug: &str, tag: &str, get: Get<'_>) -> Result<Result<String, String>, String> {
    let release = crate::release_verify::read(slug, tag, get)?;
    let Some(manifest) = release
        .published
        .assets
        .iter()
        .find(|asset| asset.name == crate::release_verify::SUMS)
    else {
        return Ok(Err(format!(
            "{tag} carries no {}",
            crate::release_verify::SUMS
        )));
    };
    let sums =
        crate::release_verify::fetch(slug, tag, release.draft, manifest, &crate::rest::download)?;
    Ok(Ok(String::from_utf8_lossy(&sums).into_owned()))
}

/// `sha` as a release head, read from the local clone.
fn read_head(here: &std::path::Path, sha: &str) -> Result<Head, String> {
    let parent =
        crate::git::resolve_ref(here, &format!("{sha}^")).map_err(|why| why.to_string())?;
    let changed = match &parent {
        Some(parent) => crate::git::paths_changed_between(here, parent, sha)
            .map_err(|why| why.to_string())?
            .into_iter()
            .collect(),
        None => std::collections::BTreeSet::new(),
    };
    Ok(Head {
        parent,
        changed,
        lock: crate::git::show(here, sha, crate::install::LOCK_FILE).ok(),
    })
}

/// The branch of the open pull request whose head is `sha`: the release PR
/// the bake commits onto.
fn head_branch(slug: &str, sha: &str, get: Get<'_>) -> Result<String, String> {
    let path = format!("repos/{slug}/commits/{sha}/pulls");
    let pulls = json_at(get, &path)?.ok_or_else(|| format!("{path} answered 404"))?;
    pulls
        .as_array()
        .into_iter()
        .flatten()
        .find(|pull| {
            pull.get("state").and_then(serde_json::Value::as_str) == Some("open")
                && pull
                    .pointer("/head/sha")
                    .and_then(serde_json::Value::as_str)
                    == Some(sha)
        })
        .and_then(|pull| {
            pull.pointer("/head/ref")
                .and_then(serde_json::Value::as_str)
        })
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("no open pull request's head is {sha}; name --branch"))
}

/// The bootstrap script's path, beside the lock it is rendered from.
pub const BOOTSTRAP_FILE: &str = "install.sh";

/// `batten release bake <tag> (--sha <sha> --branch <branch> | --write-only)`
/// (CLOUD-2287): bake release `tag` into `install.lock` — its tag and each
/// bootstrap archive's `SHA256SUMS` line — and render `install.sh` from it.
///
/// With `--sha` and `--branch` the two files are committed onto the release
/// head `sha` as one commit, `chore(release): bake install.lock for <tag>`,
/// made through the forge so the credential that moves the branch is the one
/// that fires its CI, fast-forward only; the commit's sha is printed. With
/// `--write-only` they are written to the working tree, nothing is committed,
/// and their paths are printed. Exit 1 for a release whose sums cannot be
/// baked, 3 when it could not look or could not write.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_bake(
    here: &std::path::Path,
    tag: &str,
    (sha, branch): (Option<&str>, Option<&str>),
    write_only: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let onto = match (write_only, sha, branch) {
        (true, None, None) => None,
        (false, Some(sha), branch) => Some((sha, branch)),
        _ => {
            return Err(crate::error::UsageError::raise(String::from(
                "release bake: name --sha (and --branch, or the open pull request whose head \
                 it is names it), or --write-only alone",
            )));
        }
    };
    let Some(slug) = slug_or_say(here, "bake", err)? else {
        return Ok(crate::ExitCode::Internal);
    };
    let get = |path: &str| crate::rest::get(path, None);
    let lock = match read_lock(&slug, tag, &get) {
        Ok(Ok(lock)) => lock,
        Ok(Err(why)) => {
            writeln!(err, "release bake: {tag}: {why}")?;
            return Ok(crate::ExitCode::Violation);
        }
        Err(why) => {
            writeln!(err, "batten: release bake: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    let locked = lock.render();
    let script = crate::install::render_bootstrap(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_REPOSITORY"),
        &lock,
    );
    let Some((sha, branch)) = onto else {
        let root = crate::git::worktree_root(here)?;
        crate::durable::replace(root.join(crate::install::LOCK_FILE), &locked)?;
        writeln!(out, "{}", crate::install::LOCK_FILE)?;
        crate::durable::replace(root.join(BOOTSTRAP_FILE), &script)?;
        crate::engine::make_executable(&root.join(BOOTSTRAP_FILE))?;
        writeln!(out, "{BOOTSTRAP_FILE}")?;
        return Ok(crate::ExitCode::Success);
    };
    let files = [
        (crate::install::LOCK_FILE, locked.as_str(), "100644"),
        (BOOTSTRAP_FILE, script.as_str(), "100755"),
    ];
    let message = format!("chore(release): bake install.lock for {tag}");
    let branch = match branch {
        Some(branch) => branch.to_owned(),
        None => match head_branch(&slug, sha, &get) {
            Ok(branch) => branch,
            Err(why) => {
                writeln!(err, "batten: release bake: could not look: {why}")?;
                return Ok(crate::ExitCode::Internal);
            }
        },
    };
    match commit_onto(&slug, (&branch, sha), &files, &message, &get) {
        Ok(commit) => {
            writeln!(out, "{commit}")?;
            Ok(crate::ExitCode::Success)
        }
        Err(why) => {
            writeln!(err, "batten: release bake: could not write: {why}")?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

/// `batten release pin [--at <rev>]`: print the release `batten.toml` pins, in
/// the working tree or at `rev`; exit 1 when it pins none.
///
/// # Errors
///
/// Only a failed write to `out` or `err`.
pub fn run_pin(
    at: Option<&str>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<crate::ExitCode> {
    let text = match at {
        Some(rev) => crate::git::show(std::path::Path::new("."), rev, "batten.toml")
            .map_err(|why| why.to_string()),
        None => std::fs::read_to_string("batten.toml").map_err(|why| why.to_string()),
    };
    let text = match text {
        Ok(text) => text,
        Err(why) => {
            writeln!(err, "batten: release pin: could not look: {why}")?;
            return Ok(crate::ExitCode::Internal);
        }
    };
    if let Some(pin) = crate::release_path::pin_of(&text) {
        writeln!(out, "{pin}")?;
        Ok(crate::ExitCode::Success)
    } else {
        writeln!(err, "release pin: batten.toml pins no release")?;
        Ok(crate::ExitCode::Violation)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
            headers: std::collections::BTreeMap::new(),
        }
    }

    /// A forge whose every path answers from `routes`, by the first needle the
    /// path contains, and 404 otherwise.
    fn forge(
        routes: &[(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<crate::rest::Answer> + use<> {
        let routes = routes.to_vec();
        move |path: &str| {
            Some(
                routes
                    .iter()
                    .find(|(needle, _)| path.contains(needle))
                    .map_or_else(|| answer(404, "{}"), |(_, body)| answer(200, body)),
            )
        }
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The slug a clone whose `origin` names `o/r` reads as: `GH_REPO`
    /// outranks the remote, so a runner that sets it is answered too.
    fn slug() -> String {
        std::env::var("GH_REPO")
            .ok()
            .filter(|declared| !declared.trim().is_empty())
            .unwrap_or_else(|| String::from("o/r"))
    }

    /// A clone whose `origin` names `o/r` with `main` its default branch:
    /// `commits` made in order, each adding its files to what the last one
    /// tracked, and `origin/main` at commit `main_at`. Answers the clone and
    /// each commit's sha (CLOUD-2509).
    fn clone_of(
        case: &str,
        commits: &[&[(&str, &str)]],
        main_at: usize,
    ) -> (std::path::PathBuf, Vec<String>) {
        let dir = crate::scratch::scratch(case);
        crate::gitwrite::init_on_main(&dir).unwrap();
        let mut tracked: Vec<String> = Vec::new();
        let mut shas = Vec::new();
        for (n, files) in commits.iter().enumerate() {
            for (path, text) in *files {
                std::fs::write(dir.join(path), text).unwrap();
                if !tracked.iter().any(|known| known == path) {
                    tracked.push((*path).to_owned());
                }
            }
            crate::gitwrite::commit_paths(&dir, &tracked, &format!("commit {n}")).unwrap();
            shas.push(crate::git::resolve_ref(&dir, "HEAD").unwrap().unwrap());
        }
        let mut config = std::fs::read_to_string(dir.join(".git/config")).unwrap();
        config.push_str(
            "[remote \"origin\"]\n\turl = https://github.com/o/r.git\n\
             \tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        );
        std::fs::write(dir.join(".git/config"), config).unwrap();
        std::fs::create_dir_all(dir.join(".git/refs/remotes/origin")).unwrap();
        std::fs::write(
            dir.join(".git/refs/remotes/origin/main"),
            format!("{}\n", shas[main_at]),
        )
        .unwrap();
        std::fs::write(
            dir.join(".git/refs/remotes/origin/HEAD"),
            "ref: refs/remotes/origin/main\n",
        )
        .unwrap();
        (dir, shas)
    }

    fn rest_get(path: &str) -> Option<crate::rest::Answer> {
        crate::rest::get(path, None)
    }

    #[test]
    fn the_slug_and_the_trunk_are_the_clone_s_own() {
        let (dir, _) = clone_of("release-state-clone", &[&[("a", "1")]], 0);
        let mut err = Vec::new();
        assert_eq!(slug_or_say(&dir, "x", &mut err).unwrap(), Some(slug()));
        assert!(err.is_empty());
        assert_eq!(
            trunk(&dir),
            Ok((
                String::from("refs/remotes/origin/main"),
                String::from("main")
            ))
        );
        let bare = crate::scratch::scratch("release-state-no-clone");
        let declared = std::env::var("GH_REPO")
            .ok()
            .filter(|declared| !declared.trim().is_empty());
        assert_eq!(slug_or_say(&bare, "x", &mut err).unwrap(), declared);
        assert_eq!(
            String::from_utf8(err)
                .unwrap()
                .contains("release x: could not look"),
            declared.is_none()
        );
        assert!(trunk(&bare).is_err());
    }

    /// A draft `v1` (id 5), its release deleted with `release` and its tag
    /// with `tag`.
    fn discarding(case: &str, release: u16, tag: u16) -> std::path::PathBuf {
        crate::rest::routed(
            case,
            &[
                ("releases/tags/v1", 404, "{}"),
                (
                    "releases?per_page",
                    200,
                    r#"[{"tag_name":"v0","draft":true,"id":4},{"tag_name":"v1","draft":true,"id":5}]"#,
                ),
                ("/releases/5", release, ""),
                ("/git/refs/tags/v1", tag, ""),
            ],
        )
    }

    #[test]
    fn a_discard_deletes_the_draft_and_tolerates_only_a_tag_already_gone() {
        let over = |case: &str, release: u16, tag: u16| {
            crate::rest::with_fixture(&discarding(case, release, tag), || {
                perform_discard("o/r", "v1", &rest_get)
            })
        };
        assert_eq!(over("discard-gone-tag", 204, 422), Ok(Ok(2)));
        assert_eq!(over("discard-404-tag", 200, 404), Ok(Ok(2)));
        assert!(over("discard-gone-release", 404, 204).is_err());
        assert!(over("discard-refused-release", 500, 204).is_err());
        assert!(over("discard-refused-tag", 204, 500).is_err());
        let absent = crate::rest::routed(
            "discard-absent",
            &[
                ("releases/tags/v1", 404, "{}"),
                ("releases?per_page", 200, "[]"),
            ],
        );
        assert_eq!(
            crate::rest::with_fixture(&absent, || perform_discard("o/r", "v1", &rest_get)),
            Ok(Ok(0))
        );
        let published =
            crate::rest::routed("discard-published", &[("releases/tags/v1", 200, "{}")]);
        assert!(matches!(
            crate::rest::with_fixture(&published, || perform_discard("o/r", "v1", &rest_get)),
            Ok(Err(_))
        ));
    }

    #[test]
    fn the_discard_verb_reports_each_outcome() {
        let (dir, _) = clone_of("release-discard-clone", &[&[("a", "1")]], 0);
        let run = |fixture: &std::path::Path| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = crate::rest::with_fixture(fixture, || {
                run_discard(&dir, "v1", &mut out, &mut err).unwrap()
            });
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        };
        let (code, out, _) = run(&discarding("discard-verb-draft", 204, 204));
        assert_eq!(
            (code, out.as_str()),
            (
                crate::ExitCode::Success,
                "release discard: deleted the draft v1 and its tag\n"
            )
        );
        let absent = crate::rest::routed(
            "discard-verb-absent",
            &[
                ("releases/tags/v1", 404, "{}"),
                ("releases?per_page", 200, "[]"),
            ],
        );
        let (code, out, _) = run(&absent);
        assert_eq!(code, crate::ExitCode::Success);
        assert!(out.contains("nothing deleted"), "{out}");
        let published =
            crate::rest::routed("discard-verb-published", &[("releases/tags/v1", 200, "{}")]);
        assert_eq!(run(&published).0, crate::ExitCode::Violation);
        assert_eq!(
            run(&discarding("discard-verb-refused", 500, 204)).0,
            crate::ExitCode::Internal
        );
    }

    #[test]
    fn the_land_facts_relate_the_release_to_the_local_trunk() {
        let (dir, shas) = clone_of(
            "release-land-facts",
            &[&[("CHANGELOG.md", "a")], &[("CHANGELOG.md", "b")]],
            1,
        );
        let (a, b) = (shas[0].as_str(), shas[1].as_str());
        let published = crate::rest::routed(
            "land-facts-published",
            &[
                ("releases/tags/v1", 200, r#"{"tag_name":"v1"}"#),
                (
                    "git/ref/tags/v1",
                    200,
                    &format!(r#"{{"object":{{"sha":"{a}","type":"commit"}}}}"#),
                ),
            ],
        );
        let facts =
            crate::rest::with_fixture(&published, || land_facts(&dir, "o/r", ("v1", b), &rest_get))
                .unwrap();
        assert_eq!(facts.relation, Relation::MainAhead);
        assert_eq!(facts.head, None);
        let listing = format!(
            r#"[{{"tag_name":"v1","draft":true,"id":5,"target_commitish":"{a}",
                 "assets":[{{"id":6,"name":"other"}},{{"id":7,"name":"SHA256SUMS"}}]}}]"#
        );
        let draft = crate::rest::routed(
            "land-facts-draft",
            &[
                ("releases/tags/v1", 404, "{}"),
                ("releases?per_page", 200, &listing),
                ("releases/assets/7", 200, "sums"),
            ],
        );
        let moved =
            crate::rest::with_fixture(&draft, || land_facts(&dir, "o/r", ("v1", b), &rest_get))
                .unwrap();
        assert_eq!(moved.relation, Relation::MainAhead);
        assert_eq!(moved.head.map(|head| head.parent), Some(Some(a.to_owned())));
        assert_eq!(moved.draft_sums.as_deref(), Some("sums"));
        let at_target =
            crate::rest::with_fixture(&draft, || land_facts(&dir, "o/r", ("v1", a), &rest_get))
                .unwrap();
        assert_eq!((at_target.head, at_target.draft_sums), (None, None));
    }

    #[test]
    fn a_published_release_is_burned_only_where_the_trunk_cannot_reach_its_tag() {
        let (dir, shas) = clone_of(
            "release-judge",
            &[&[("a", "1")], &[("a", "2")], &[("a", "3")]],
            1,
        );
        let judged = |case: &str, commit: &str| {
            let tagged = format!(r#"{{"object":{{"sha":"{commit}","type":"commit"}}}}"#);
            let fixture = crate::rest::routed(
                case,
                &[
                    ("releases/tags/v1", 200, "{}"),
                    ("git/ref/tags/v1", 200, &tagged),
                ],
            );
            crate::rest::with_fixture(&fixture, || judge_unusable(&dir, "o/r", "v1", &rest_get))
        };
        assert_eq!(judged("judge-reached", &shas[0]), Ok(None));
        assert_eq!(judged("judge-burned", &shas[2]), Ok(Some(Unusable::Burned)));
    }

    /// The forge's git-data API accepting every write onto `head`.
    fn writing(case: &str, head: &str, moved: u16) -> std::path::PathBuf {
        crate::rest::routed(
            case,
            &[
                (
                    &format!("git/commits/{head}"),
                    200,
                    r#"{"tree":{"sha":"t"}}"#,
                ),
                ("git/blobs", 201, r#"{"sha":"b"}"#),
                ("git/trees", 201, r#"{"sha":"t2"}"#),
                ("git/commits", 201, r#"{"sha":"c"}"#),
                ("git/refs/heads/", moved, "{}"),
            ],
        )
    }

    #[test]
    fn a_commit_onto_a_branch_answers_the_commit_the_forge_made() {
        let files = [("x", "text", "100644")];
        let made = |case: &str, moved: u16| {
            crate::rest::with_fixture(&writing(case, "h", moved), || {
                commit_onto("o/r", ("rel", "h"), &files, "m", &rest_get)
            })
        };
        assert_eq!(made("commit-onto", 200), Ok(String::from("c")));
        assert!(made("commit-onto-refused", 422).is_err());
    }

    #[test]
    fn a_cut_drafts_at_the_head_and_dispatches_the_build() {
        let (dir, shas) = clone_of(
            "release-cut",
            &[&[("CHANGELOG.md", "## [1.0.0]\nnotes\n## [0.9.0]\nold\n")]],
            0,
        );
        let cut = |case: &str, dispatched: u16| {
            let fixture = crate::rest::routed(
                case,
                &[
                    ("releases/tags/v1.0.0", 404, "{}"),
                    ("releases?per_page", 200, "[]"),
                    ("actions/workflows/ra.yml/dispatches", dispatched, ""),
                    (
                        "POST https://api.github.com/repos/",
                        201,
                        r#"{"tag_name":"v1.0.0"}"#,
                    ),
                ],
            );
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = crate::rest::with_fixture(&fixture, || {
                run_cut(
                    &dir,
                    ("v1.0.0", &shas[0]),
                    ("CHANGELOG.md", "ra.yml", None),
                    &mut out,
                    &mut err,
                )
                .unwrap()
            });
            (code, String::from_utf8(out).unwrap(), fixture)
        };
        let (code, out, fixture) = cut("cut-dispatched", 204);
        assert_eq!(code, crate::ExitCode::Success, "{out}");
        assert!(out.contains("v1.0.0 drafted at"), "{out}");
        let drafted = std::fs::read_to_string(fixture.join("route.3.request")).unwrap();
        assert!(
            drafted.contains("notes") && !drafted.contains("old"),
            "{drafted}"
        );
        assert_eq!(cut("cut-refused", 500).0, crate::ExitCode::Internal);
    }

    /// A release whose `SHA256SUMS` lists every bootstrap archive of `tag`.
    fn sums_of(tag: &str) -> String {
        crate::install::TARGETS
            .iter()
            .map(|target| {
                format!(
                    "{}  {}{}\n",
                    "a".repeat(64),
                    crate::dist::archive_stem(
                        env!("CARGO_PKG_NAME"),
                        tag.trim_start_matches('v'),
                        target
                    ),
                    crate::dist::archive_ext(target)
                )
            })
            .collect()
    }

    #[test]
    fn a_cut_of_the_draft_target_s_bake_lands_it_instead() {
        let sums = sums_of("v1.0.0");
        let lock = crate::install::Lock::from_sums(env!("CARGO_PKG_NAME"), "v1.0.0", &sums)
            .unwrap()
            .render();
        let (dir, shas) = clone_of(
            "release-cut-bake",
            &[
                &[("CHANGELOG.md", "## [1.0.0]\nnotes\n")],
                &[
                    (crate::install::LOCK_FILE, &lock),
                    (BOOTSTRAP_FILE, "#!/bin/sh\n"),
                ],
            ],
            0,
        );
        let listing = format!(
            r#"[{{"tag_name":"v1.0.0","draft":true,"id":5,"target_commitish":"{}",
                 "assets":[{{"id":7,"name":"SHA256SUMS"}}]}}]"#,
            shas[0]
        );
        let fixture = crate::rest::routed(
            "cut-bake",
            &[
                ("releases/tags/v1.0.0", 404, "{}"),
                ("releases?per_page", 200, &listing),
                ("releases/assets/7", 200, &sums),
                ("actions/workflows/rl.yml/dispatches", 204, ""),
            ],
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = crate::rest::with_fixture(&fixture, || {
            run_cut(
                &dir,
                ("v1.0.0", &shas[1]),
                ("CHANGELOG.md", "ra.yml", Some("rl.yml")),
                &mut out,
                &mut err,
            )
            .unwrap()
        });
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, crate::ExitCode::Success, "{out}");
        assert!(out.contains("rl.yml dispatched"), "{out}");
    }

    /// A published `v1.0.0` carrying `SHA256SUMS` for every bootstrap archive.
    fn published_with_sums(case: &str, extra: &[(&str, u16, &str)]) -> std::path::PathBuf {
        let sums = sums_of("v1.0.0");
        let mut routes = vec![
            (
                "releases/tags/v1.0.0",
                200,
                r#"{"tag_name":"v1.0.0","draft":false,"assets":[{"id":7,"name":"SHA256SUMS"}]}"#,
            ),
            ("releases/download/v1.0.0/SHA256SUMS", 200, sums.as_str()),
        ];
        routes.extend_from_slice(extra);
        crate::rest::routed(case, &routes)
    }

    #[test]
    fn a_bake_writes_the_lock_and_an_executable_bootstrap_or_commits_them() {
        let (dir, shas) = clone_of("release-bake", &[&[("a", "1")]], 0);
        let fixture = published_with_sums("bake-write", &[]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = crate::rest::with_fixture(&fixture, || {
            run_bake(&dir, "v1.0.0", (None, None), true, &mut out, &mut err).unwrap()
        });
        assert_eq!(code, crate::ExitCode::Success);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "install.lock\ninstall.sh\n"
        );
        assert!(
            std::fs::read_to_string(dir.join(crate::install::LOCK_FILE))
                .unwrap()
                .contains("\ntag v1.0.0\n")
        );
        assert!(dir.join(BOOTSTRAP_FILE).is_file());
        let head = shas[0].as_str();
        let commits = format!("git/commits/{head}");
        let fixture = published_with_sums(
            "bake-commit",
            &[
                (&commits, 200, r#"{"tree":{"sha":"t"}}"#),
                ("git/blobs", 201, r#"{"sha":"b"}"#),
                ("git/trees", 201, r#"{"sha":"t2"}"#),
                ("git/commits", 201, r#"{"sha":"c"}"#),
                ("git/refs/heads/rel", 200, "{}"),
            ],
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = crate::rest::with_fixture(&fixture, || {
            run_bake(
                &dir,
                "v1.0.0",
                (Some(head), Some("rel")),
                false,
                &mut out,
                &mut err,
            )
            .unwrap()
        });
        assert_eq!(
            (code, String::from_utf8(out).unwrap().as_str()),
            (crate::ExitCode::Success, "c\n")
        );
    }

    #[test]
    fn a_full_sha_is_forty_hex_digits() {
        assert!(full_sha(SHA));
        assert!(!full_sha(&SHA[..39]));
        assert!(!full_sha(&format!("{}g", &SHA[..39])));
    }

    fn baked(lock: &str) -> Head {
        Head {
            parent: Some(String::from("target")),
            changed: [crate::install::LOCK_FILE, BOOTSTRAP_FILE]
                .into_iter()
                .map(String::from)
                .collect(),
            lock: Some(lock.to_owned()),
        }
    }

    #[test]
    fn a_bake_is_a_child_of_the_target_carrying_only_a_lock_that_agrees() {
        let digest = "a".repeat(64);
        let sums = format!("{digest}  x.tar.gz\n");
        let lock = format!("tag v1\n{digest}  x.tar.gz\n");
        assert!(baked_onto(&baked(&lock), "target", "v1", &sums));
        assert!(!baked_onto(&baked(&lock), "other", "v1", &sums));
        assert!(!baked_onto(&baked(&lock), "target", "v2", &sums));
        assert!(
            !baked_onto(&baked("tag v1\n"), "target", "v1", &sums),
            "lists nothing"
        );
        let other = format!("{}  x.tar.gz\n", "b".repeat(64));
        assert!(!baked_onto(&baked(&lock), "target", "v1", &other));
        let mut wider = baked(&lock);
        wider.changed.insert(String::from("src/lib.rs"));
        assert!(!baked_onto(&wider, "target", "v1", &sums));
    }

    fn facts(target: &str) -> LandFacts {
        LandFacts {
            read: Read::Draft {
                target: target.to_owned(),
            },
            tag: String::from("v1.2.3"),
            sha: String::from(SHA),
            relation: Relation::Identical,
            tag_ref: None,
            pin_at_target: Some(String::from("v1.2.3")),
            version_at_target: Some(String::from("1.2.3")),
            head: None,
            draft_sums: None,
        }
    }

    #[test]
    fn a_draft_at_the_sha_with_its_pin_and_version_is_draft_ok() {
        assert_eq!(land_state(&facts(SHA)), LandState::DraftOk);
        let other = "f".repeat(40);
        assert!(matches!(land_state(&facts(&other)), LandState::DraftBad(_)));
        let wrong_version = LandFacts {
            version_at_target: Some(String::from("1.2.4")),
            ..facts(SHA)
        };
        assert!(matches!(land_state(&wrong_version), LandState::DraftBad(_)));
    }

    #[test]
    fn a_bump_moves_all_four_paths_and_only_the_workspace_s_lock_lines() {
        let files = Files {
            manifest: String::from("[workspace.package]\nversion = \"0.0.9\"\n"),
            lock: String::from(
                "[[package]]\nname = \"batten\"\nversion = \"0.0.9\"\n\n\
                 [[package]]\nname = \"other\"\nversion = \"0.0.9\"\n",
            ),
            config: String::from("engine = { release = \"v0.0.9\" }\n"),
            changelog: String::from(
                "# Changelog\n\n## [0.0.9](https://x/compare/v0.0.8...v0.0.9) - 2026\n\n## [0.0.8]\n",
            ),
        };
        let (to, bumped) = bump(&files, "0.0.9", &[String::from("batten")]).unwrap();
        assert_eq!(to, "0.0.10");
        assert_eq!(
            bumped.manifest,
            "[workspace.package]\nversion = \"0.0.10\"\n"
        );
        assert_eq!(
            bumped.lock,
            "[[package]]\nname = \"batten\"\nversion = \"0.0.10\"\n\n\
             [[package]]\nname = \"other\"\nversion = \"0.0.9\"\n"
        );
        assert_eq!(bumped.config, "engine = { release = \"v0.0.10\" }\n");
        assert_eq!(
            bumped.changelog,
            "# Changelog\n\n## [0.0.10](https://x/compare/v0.0.8...v0.0.10) - 2026\n\n## [0.0.8]\n"
        );
        let unpinned = Files {
            config: String::from("engine = { release = \"v0.0.8\" }\n"),
            ..files.clone()
        };
        assert!(bump(&unpinned, "0.0.9", &[String::from("batten")]).is_err());
        let unversioned = Files {
            manifest: String::from("version = \"0.0.8\"\n"),
            ..files.clone()
        };
        assert!(bump(&unversioned, "0.0.9", &[String::from("batten")]).is_err());
        let unheaded = Files {
            changelog: String::from("# Changelog\n"),
            ..files
        };
        assert!(bump(&unheaded, "0.0.9", &[String::from("batten")]).is_err());
    }

    #[test]
    fn only_the_path_sourced_packages_are_the_workspace_s() {
        let lock = "version = 4\n\n[[package]]\nname = \"batten\"\nversion = \"1\"\n\n\
                    [[package]]\nname = \"serde\"\nversion = \"1\"\nsource = \"registry\"\n";
        assert_eq!(workspace_packages(lock), vec![String::from("batten")]);
    }

    #[test]
    fn a_sha_is_read_from_an_accepted_answer_or_refused() {
        assert_eq!(
            sha_in(Some(answer(201, r#"{"sha":"abc"}"#)), "the blob", "/sha"),
            Ok(String::from("abc"))
        );
        assert!(sha_in(Some(answer(422, r#"{"sha":"abc"}"#)), "the blob", "/sha").is_err());
        assert!(sha_in(Some(answer(200, "{}")), "the blob", "/sha").is_err());
        assert!(sha_in(None, "the blob", "/sha").is_err());
    }

    #[test]
    fn a_tag_exists_where_its_ref_reads() {
        assert!(tag_exists("o/r", "v1", &forge(&[("git/ref/tags/v1", "{}")])).unwrap());
        assert!(!tag_exists("o/r", "v1", &forge(&[])).unwrap());
    }

    #[test]
    fn the_settings_are_green_only_when_the_latest_run_s_settings_job_succeeded() {
        let runs = ("/runs?branch=main", r#"{"workflow_runs":[{"id":7}]}"#);
        let green = forge(&[
            runs,
            (
                "runs/7/jobs",
                r#"{"jobs":[{"name":"other","status":"completed","conclusion":"failure"},
                            {"name":"settings","status":"completed","conclusion":"success"}]}"#,
            ),
        ]);
        assert!(settings_green("o/r", "main", "guard.yml", &green).unwrap());
        let red = forge(&[
            runs,
            (
                "runs/7/jobs",
                r#"{"jobs":[{"name":"other","status":"completed","conclusion":"success"},
                            {"name":"settings","status":"completed","conclusion":"failure"}]}"#,
            ),
        ]);
        assert!(!settings_green("o/r", "main", "guard.yml", &red).unwrap());
        let none = forge(&[("/runs?branch=main", r#"{"workflow_runs":[]}"#)]);
        assert!(!settings_green("o/r", "main", "guard.yml", &none).unwrap());
    }

    #[test]
    fn a_failed_land_is_dated_from_its_latest_failed_land_job() {
        let runs = vec![
            serde_json::json!({"id": 1, "display_title": "build v1"}),
            serde_json::json!({"id": 2, "display_title": "build v2"}),
        ];
        let get = forge(&[(
            "runs/2/jobs",
            r#"{"jobs":[
                {"name":"land","conclusion":"failure","completed_at":"2026-01-01T00:00:00Z"},
                {"name":"land","conclusion":"failure","completed_at":"2026-01-01T00:01:00Z"},
                {"name":"land","conclusion":"success","completed_at":"2026-01-01T00:05:00Z"},
                {"name":"build","conclusion":"failure","completed_at":"2026-01-01T00:09:00Z"}]}"#,
        )]);
        let at = crate::ci_signal::epoch("2026-01-01T00:01:00Z").unwrap();
        assert_eq!(
            land_failed_ago("o/r", "v2", &runs, at + 100, &get).unwrap(),
            Some(100)
        );
        assert_eq!(land_failed_ago("o/r", "v3", &runs, at, &get).unwrap(), None);
    }

    #[test]
    fn the_freeze_reads_runs_drafts_and_the_non_latest_pre_releases() {
        let get = forge(&[
            (
                "workflows/build.yml/runs",
                r#"{"workflow_runs":[{"id":1,"display_title":"build v3","status":"in_progress"}]}"#,
            ),
            ("releases/latest", r#"{"tag_name":"v1"}"#),
            (
                "releases?per_page=30",
                r#"[{"tag_name":"v3","draft":true,"created_at":"2026-01-01T00:00:00Z"},
                    {"tag_name":"v2","prerelease":true},
                    {"tag_name":"v1","prerelease":true}]"#,
            ),
            (
                "git/ref/tags/v2",
                r#"{"object":{"sha":"c2","type":"commit"}}"#,
            ),
            ("compare/main...c2", r#"{"status":"ahead"}"#),
        ]);
        let now = crate::ci_signal::epoch("2026-01-01T00:00:30Z").unwrap();
        let flight =
            read_flight("o/r", ("main", &[String::from("build.yml")]), now, 9, &get).unwrap();
        assert_eq!(flight.active_run.as_deref(), Some("build v3"));
        assert_eq!(flight.drafts, vec![(String::from("v3"), 30)]);
        assert_eq!(
            flight.pending,
            vec![Pending {
                tag: String::from("v2"),
                relation: Relation::MainBehind,
                land_failed_ago: None,
            }]
        );
        assert_eq!(flight.land_hold, 9);
    }

    /// A draft is in flight for its first ten minutes, and a failed land holds
    /// six hours by default.
    #[test]
    fn a_draft_is_in_flight_for_ten_minutes_and_a_failed_land_holds_six_hours() {
        let flight = |age: u64| Flight {
            active_run: None,
            drafts: vec![(String::from("v3"), age)],
            pending: Vec::new(),
            land_hold: 0,
        };
        assert_eq!(
            in_flight(&flight(599)).as_deref(),
            Some("v3 is a draft 599s old")
        );
        assert_eq!(in_flight(&flight(600)), None);
        assert_eq!(LAND_HOLD_SECS, 21_600);
    }

    #[test]
    fn the_head_branch_is_the_open_pull_request_whose_head_is_the_sha() {
        let get = forge(&[(
            "commits/abc/pulls",
            r#"[{"state":"closed","head":{"sha":"abc","ref":"old"}},
                {"state":"open","head":{"sha":"def","ref":"moved"}},
                {"state":"open","head":{"sha":"abc","ref":"release/v1"}}]"#,
        )]);
        assert_eq!(head_branch("o/r", "abc", &get).unwrap(), "release/v1");
        let none = forge(&[("commits/abc/pulls", "[]")]);
        assert!(head_branch("o/r", "abc", &none).is_err());
    }
}
