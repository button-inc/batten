//! The CI-signal producers: how far the landing loop diverged from linear over a
//! window, and which required-check failures never reached a verdict (CLOUD-843).
//!
//! # What this retires, and the line it holds
//!
//! `[tasks.land-divergence-record]` and `[tasks.nonverdict-record]` were two
//! ~300-line bash bodies, each carrying its own copy of one 45-line
//! `conditional_get` over `gh api -i`, its own ETag store under `.git/`, a `jq`
//! projection per endpoint and an `awk` join. The fetch is now
//! [`crate::forge::window_over`] — the ETag-cached, `total_count`-checked walk
//! built to replace exactly those copies — and the join, the percentiles and the
//! emission are plain functions over parsed rows.
//!
//! **Both MEASURE; neither DECIDES.** The budgets are the vendored `ci-signal`
//! preset's, whose two modules read the two families. What is here is the
//! reduction the retired bodies already did before any decision: which runs a
//! landing bought, a cancellation's latency, a leg's queue wait, and whether a
//! failed job's failed step is one the consumer names as verdict-bearing.
//!
//! # Mechanism only (non-negotiable rule 1)
//!
//! No workflow file, job name or step spelling is named here. The two workflows
//! arrive as flags or through `$LAND_CI_WORKFLOW` / `$LAND_WORKFLOW` — the latter
//! the variable `land fast-forward` already reads — the required roster through
//! `$CI_REQUIRED_CHECKS`, which `land` reads, the fan-in as `--exclude-job` or
//! `$CI_FANIN_CHECK`, which `land` reads too, and the verdict-step prefixes as
//! `--verdict-step` or `$CI_VERDICT_STEPS`. A flag outranks its variable; the
//! variable is how a consumer states each fact ONCE for every caller. The two
//! FAMILY names are this module's own vocabulary: a verb writes the family it is
//! named for, as `record closes` does.
//!
//! # The byte format is the retired bodies', on purpose
//!
//! The records these write are byte-for-byte what the tasks piped into `record
//! named`, so the two modules reading them — and every recorded window a reader
//! compares against — are unchanged. That includes two quirks kept rather than
//! "fixed": a percentile is the FLOOR nearest rank (`awk`'s `int((n-1)*p/100)`),
//! not [`crate::arm::percentile`]'s ceiling, and the run-to-landing join compares
//! the two instants as TEXT, as `awk` did. Both are stated where they are applied.
//!
//! # Three answers, kept apart
//!
//! * **recorded** — the window was read, possibly in part. A part is counted in
//!   `unreadable`, which is a finding the module owns, and the prefix is judged.
//! * **could not look** — no remote to name the repository, no clock, or the
//!   one read the whole window hangs on (the CI run list, the landing list, the
//!   failed-run list) was refused or unparseable. The stale record is REMOVED and
//!   the verb exits 3: a module cannot tell a stale window from a fresh one.
//! * **usage** — an argument that cannot run as written.
//!
//! # Pointer-only (rule 4)
//!
//! Run ids, branch names, job and step names, conclusions and counts. No log
//! body, commit message or PR title is ever fetched, so none can be written.

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::forge::{self, Shape, Transport, Window};
use crate::forge_query::Produced;

/// The divergence leaf, as a refusal names it.
const DIVERGENCE: &str = "record divergence";

/// The non-verdict leaf, as a refusal names it.
const NONVERDICT: &str = "record nonverdict";

/// The family `record divergence` writes, which `input.tree.records` projects.
pub const DIVERGENCE_FAMILY: &str = "land-divergence";

/// The family `record nonverdict` writes.
pub const NONVERDICT_FAMILY: &str = "nonverdict";

/// The window when none is given: the day before now, in seconds.
const DAY: i64 = 86_400;

/// The page budget per collection when none is given — the retired body's
/// `MAX_PAGES`, measured against the Actions endpoint's 1000-item cap.
const DEFAULT_PAGES: u32 = 10;

/// The forge's page ceiling, which it clamps to silently.
const PAGE: &str = "100";

/// How many recent failed runs `record nonverdict` reads when none is given.
const DEFAULT_WINDOW: u32 = 30;

// --- shared reductions ----------------------------------------------------------

/// A field as `jq`'s `.key // alternative` reads it: absent, `null` and `false`
/// are "no value"; a string is itself; anything else is its JSON text.
fn field(row: &Value, key: &str) -> Option<String> {
    match row.get(key)? {
        Value::Null | Value::Bool(false) => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

/// A dotted field, as [`field`] reads the last segment.
fn nested(row: &Value, outer: &str, key: &str) -> Option<String> {
    row.get(outer).and_then(|inner| field(inner, key))
}

/// One cell as `jq`'s `@tsv` escaped it, so a name holding a tab cannot forge a
/// column in the line it is written into.
fn tsv(cell: &str) -> String {
    cell.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// An RFC 3339 instant in epoch seconds, or `None` where it does not parse.
fn epoch(instant: &str) -> Option<i64> {
    crate::landed::second_of(instant)
}

/// The FLOOR nearest-rank percentile of a series, `0` for an empty one.
///
/// **Not [`crate::arm::percentile`], and the difference is the point.** That one
/// takes the CEILING rank, so a p50 over two cancellations is the later one; the
/// retired body's `awk` took `int((n - 1) * p / 100)`, the earlier. Every recorded
/// window a reader holds was computed this way, and the modules' budgets were
/// seeded against it — so switching ranks would move a reading without anything
/// about the fleet having changed.
fn floor_rank(mut series: Vec<i64>, percent: usize) -> i64 {
    if series.is_empty() {
        return 0;
    }
    series.sort_unstable();
    let rank = (series.len() - 1).saturating_mul(percent) / 100;
    series.get(rank).copied().unwrap_or(0)
}

/// Records sorted bytewise (`LC_ALL=C sort`), then the closing line.
fn compose(mut records: Vec<String>, window: &str) -> String {
    records.sort_unstable();
    let mut body = String::new();
    for record in records {
        body.push_str(&record);
        body.push('\n');
    }
    body.push_str(window);
    body.push('\n');
    body
}

/// A could-not-look pointer for a window that refused: the endpoint and a status.
fn refused(what: &str, endpoint: &str, status: Option<u16>) -> Produced {
    let status = status.map_or_else(|| String::from("no answer"), |code| code.to_string());
    Produced::CouldNotLook(format!(
        "{what} ({endpoint}: {status}), so this window judged nothing"
    ))
}

// --- record divergence ------------------------------------------------------------

/// One CI run as the join reads it — the retired body's seven TSV columns.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Run {
    id: String,
    branch: String,
    conclusion: String,
    created: String,
    started: String,
    updated: String,
    attempt: String,
}

impl Run {
    fn of(row: &Value) -> Self {
        Run {
            id: field(row, "id").unwrap_or_default(),
            branch: field(row, "head_branch").unwrap_or_else(|| String::from("-")),
            conclusion: field(row, "conclusion")
                .or_else(|| field(row, "status"))
                .unwrap_or_else(|| String::from("-")),
            created: field(row, "created_at").unwrap_or_default(),
            started: field(row, "run_started_at").unwrap_or_default(),
            updated: field(row, "updated_at").unwrap_or_default(),
            attempt: field(row, "run_attempt").unwrap_or_else(|| String::from("1")),
        }
    }

    /// A draft-era push: it spent no matrix and is never graded.
    fn skipped(&self) -> bool {
        self.conclusion == "skipped"
    }
}

/// What `record divergence` measures, resolved from its flags and environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The workflow file whose runs are the graded CI runs.
    pub ci_workflow: String,
    /// The workflow file whose runs are the landing bot's answers.
    pub land_workflow: String,
    /// The window's start as given, which the summary line carries verbatim.
    pub since: String,
    /// The same instant in epoch seconds.
    pub since_at: i64,
    /// Pages per collection before the window reads as truncated.
    pub max_pages: u32,
}

/// How a collection's read ended, for a producer that judges a prefix.
enum Read {
    /// Every row, or a prefix whose truncation the caller has already counted.
    Rows(Vec<Value>),
    /// Refused or unparseable: the endpoint and the status.
    Refused(String, Option<u16>),
}

/// A window's rows, counting a truncated one as one `unreadable` and keeping its
/// prefix — the retired walk's `return 2`, which judged what it had read.
fn prefix(window: Window, unreadable: &mut u64) -> Read {
    match window {
        Window::Whole(rows) => Read::Rows(rows),
        Window::Truncated { rows, .. } => {
            *unreadable += 1;
            Read::Rows(rows)
        }
        Window::CouldNotLook { endpoint, status } => Read::Refused(endpoint, status),
    }
}

/// An exact count for one conclusion, off the endpoint's own `total_count` with
/// one row asked for: no pagination, so no cap to be truncated by.
fn count_runs(
    git_dir: &Path,
    path: &str,
    created: &str,
    status: &str,
    fetch: Transport<'_>,
) -> Option<usize> {
    match forge::window_over(
        git_dir,
        path,
        &[("created", created), ("status", status), ("per_page", "1")],
        Shape::Wrapped("workflow_runs"),
        1,
        fetch,
    ) {
        // A count of at most one fits on the page, so the page IS the count.
        Window::Whole(rows) => Some(rows.len()),
        Window::Truncated { total, .. } => total,
        Window::CouldNotLook { .. } => None,
    }
}

/// Whether a pull request was last updated before the window opened — the row
/// that ends the walk over a list sorted by `updated` descending. An undated row
/// never ends it: the walk would stop at the very row nobody could place.
fn updated_before(row: &Value, since_at: i64) -> bool {
    let Some(at) = field(row, "updated_at").and_then(|at| epoch(&at)) else {
        return false;
    };
    at < since_at
}

/// Per-PR attribution: each landing's graded runs, and the totals over all.
///
/// Joined by branch AND bounded by `merged_at`, so a branch's post-merge runs
/// and a reused name's later life are not attributed to it. The bound compares
/// TEXT, as the retired `awk` did: both are the forge's own fixed-width UTC
/// spelling, where text order is time order.
fn attribute(
    landed: &[(String, String, String)],
    runs: &[Run],
    records: &mut Vec<String>,
) -> (u64, u64, u64, u64) {
    let (mut graded, mut green, mut red, mut cancelled) = (0_u64, 0_u64, 0_u64, 0_u64);
    for (number, branch, merged) in landed {
        let (mut g, mut s, mut f, mut c) = (0_u64, 0_u64, 0_u64, 0_u64);
        for run in runs.iter().filter(|run| {
            run.branch == *branch && run.created.as_str() <= merged.as_str() && !run.skipped()
        }) {
            g += 1;
            match run.conclusion.as_str() {
                "success" => s += 1,
                "failure" => f += 1,
                "cancelled" => c += 1,
                _ => {}
            }
        }
        graded += g;
        green += s;
        red += f;
        cancelled += c;
        // Only a PR that diverged earns a record: one graded green run is the
        // ideal and says nothing a reader needs.
        if g > 1 || f > 0 {
            records.push(format!(
                "pr\tnumber={}\tbranch={}\tgraded={g}\tgreen={s}\tred={f}\tcancelled={c}",
                tsv(number),
                tsv(branch)
            ));
        }
    }
    (graded, green, red, cancelled)
}

/// Each cancelled run's lifetime — LATENCY, never count — with its record.
fn cancellations(runs: &[Run], records: &mut Vec<String>) -> Vec<i64> {
    let mut latencies = Vec::new();
    for run in runs.iter().filter(|run| {
        run.conclusion == "cancelled" && !run.started.is_empty() && !run.updated.is_empty()
    }) {
        let (Some(started), Some(updated)) = (epoch(&run.started), epoch(&run.updated)) else {
            continue;
        };
        let latency = updated - started;
        latencies.push(latency);
        records.push(format!(
            "cancel\trun={}\tbranch={}\tlatency={latency}",
            tsv(&run.id),
            tsv(&run.branch)
        ));
    }
    latencies
}

/// The queue delay per JOB (CLOUD-501), for graded runs only, and how many
/// runs' jobs could not be read.
///
/// One request per graded run, bounded rather than waved at; a run whose jobs
/// cannot be read is counted, never dropped — dropping it would report a p90
/// over the legs that happened to answer.
fn job_queue(
    spec: &Divergence,
    slug: &str,
    git_dir: &Path,
    runs: &[Run],
    fetch: Transport<'_>,
    records: &mut Vec<String>,
) -> (Vec<i64>, u64) {
    let (mut latencies, mut unreadable) = (Vec::new(), 0_u64);
    for run in runs
        .iter()
        .filter(|run| !run.skipped() && run.conclusion != "-")
    {
        let jobs_path = format!("repos/{slug}/actions/runs/{}/jobs", run.id);
        match forge::window_over(
            git_dir,
            &jobs_path,
            &[("per_page", PAGE)],
            Shape::Wrapped("jobs"),
            spec.max_pages,
            fetch,
        ) {
            Window::Whole(jobs) => {
                for job in &jobs {
                    let (Some(created), Some(started)) =
                        (field(job, "created_at"), field(job, "started_at"))
                    else {
                        continue;
                    };
                    let (Some(created), Some(started)) = (epoch(&created), epoch(&started)) else {
                        continue;
                    };
                    let seconds = started - created;
                    latencies.push(seconds);
                    // A zero-wait leg is the ideal and earns no record.
                    if seconds > 0 {
                        let name = field(job, "name").unwrap_or_else(|| String::from("-"));
                        records.push(format!(
                            "job\trun={}\tjob={}\tqueue={seconds}",
                            tsv(&run.id),
                            tsv(&name)
                        ));
                    }
                }
            }
            _ => unreadable += 1,
        }
    }
    (latencies, unreadable)
}

/// Peak concurrency: a sweep over start/end events.
///
/// At one instant a start sorts before an end, as the retired `sort -k2,2r`
/// ordered them, so two runs touching at a boundary count as overlapping.
fn peak_concurrency(runs: &[Run]) -> i64 {
    let mut events: Vec<(i64, i64)> = Vec::new();
    for run in runs
        .iter()
        .filter(|run| !run.skipped() && !run.started.is_empty() && !run.updated.is_empty())
    {
        let (Some(started), Some(updated)) = (epoch(&run.started), epoch(&run.updated)) else {
            continue;
        };
        events.push((started, 1));
        events.push((updated, -1));
    }
    events.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let (mut current, mut peak) = (0_i64, 0_i64);
    for (_, step) in events {
        current += step;
        peak = peak.max(current);
    }
    peak
}

/// Measure the divergence over `spec`'s window and compose the record.
///
/// Every input is an argument — the slug, the git directory, the transport — so
/// the whole reduction is testable without a network or a remote.
// THE PRODUCER'S OWN DISCRIMINATION, each over the compiled binary against the
// fixture forge so the mutation has to survive the whole path: flags, the walk,
// the join, the store. Each row restores a failure the retired suite caught.
//MUTANT-SUITE crates/batten/tests/it/land_divergence.rs
//MUTANT post-merge-run-attributed|s@^            run.branch == \*branch && run.created.as_str() <= merged.as_str() && !run.skipped()$@            run.branch == *branch \&\& !run.skipped()@|the_producer_joins_runs_to_landings_and_records_what_the_module_reads
//MUTANT skipped-run-graded|s@ <= merged.as_str() && !run.skipped()$@ <= merged.as_str()@|the_producer_joins_runs_to_landings_and_records_what_the_module_reads
//MUTANT truncated-walk-reads-whole|s@^            \*unreadable += 1;$@@|a_truncated_ci_walk_is_judged_as_a_prefix_and_counted_unreadable
//MUTANT unreadable-jobs-dropped|s@^            _ => unreadable += 1,$@            _ => {}@|a_run_whose_jobs_cannot_be_read_is_unreadable_never_a_zero_wait
//MUTANT merged-list-unpaged|s@^    at < since_at$@    at < i64::MIN@|the_merged_pr_list_is_paged_until_it_leaves_the_window
//MUTANT stale-record-survives|s@^            crate::record::clear_named(verb, family)?;$@@|an_unreadable_ci_window_is_could_not_look_and_removes_the_stale_record
//MUTANT environment-unread|s@^                .ok()$@                .ok().and(None::<String>)@|the_environment_names_the_window_when_no_flag_does
#[must_use]
pub fn divergence(spec: &Divergence, slug: &str, git_dir: &Path, fetch: Transport<'_>) -> Produced {
    let mut unreadable = 0_u64;
    let created = format!(">={}", spec.since);
    let created = crate::forge_query::encode(&created);

    // --- CI runs over the window --------------------------------------------------
    let runs_of = |workflow: &str| format!("repos/{slug}/actions/workflows/{workflow}/runs");
    let ci_path = runs_of(&spec.ci_workflow);
    let runs: Vec<Run> = match prefix(
        forge::window_over(
            git_dir,
            &ci_path,
            &[("created", &created), ("per_page", PAGE)],
            Shape::Wrapped("workflow_runs"),
            spec.max_pages,
            fetch,
        ),
        &mut unreadable,
    ) {
        Read::Rows(rows) => rows.iter().map(Run::of).collect(),
        Read::Refused(endpoint, status) => {
            return refused("could not read the CI run window", &endpoint, status);
        }
    };

    // --- the landing bot's refusal:success ratio -----------------------------------
    //
    // `skipped` is not a refusal: it is every issue comment that was not the
    // bot's command. So the two conclusions are counted, never the whole list.
    let land_path = runs_of(&spec.land_workflow);
    let mut counted = |status: &str| {
        count_runs(git_dir, &land_path, &created, status, fetch).unwrap_or_else(|| {
            unreadable += 1;
            0
        })
    };
    let ff_refused = counted("failure");
    let ff_success = counted("success");

    // --- landings: merged PRs in the window ---------------------------------------
    //
    // THE RETIRED BODY READ ONE UNPAGINATED PAGE, so a window with more than a
    // hundred closed PRs updated in it silently lost landings. The list is sorted
    // by `updated` descending, and a PR merged inside the window was updated no
    // earlier than its merge — so the first row updated before the window's start
    // ends the walk, and the window is whole there.
    let since_at = spec.since_at;
    let stop = move |row: &Value| updated_before(row, since_at);
    let pulls_path = format!("repos/{slug}/pulls");
    let pulls = forge::window_until(
        git_dir,
        &pulls_path,
        &[
            ("state", "closed"),
            ("sort", "updated"),
            ("direction", "desc"),
            ("per_page", PAGE),
        ],
        Shape::Bare,
        spec.max_pages,
        Some(&stop as forge::Stop<'_>),
        fetch,
    );
    let landed: Vec<(String, String, String)> = match prefix(pulls, &mut unreadable) {
        Read::Rows(rows) => rows
            .iter()
            .filter_map(|row| {
                let merged = field(row, "merged_at")?;
                (epoch(&merged)? >= spec.since_at).then(|| {
                    (
                        field(row, "number").unwrap_or_default(),
                        nested(row, "head", "ref").unwrap_or_else(|| String::from("-")),
                        merged,
                    )
                })
            })
            .collect(),
        Read::Refused(endpoint, status) => {
            return refused(
                "could not read the merged-PR list, so there is no denominator",
                &endpoint,
                status,
            );
        }
    };

    let mut records: Vec<String> = Vec::new();
    let (graded, green, red, cancelled) = attribute(&landed, &runs, &mut records);
    let cancel_p50 = floor_rank(cancellations(&runs, &mut records), 50);

    // --- queue delay: created -> run_started, per run -------------------------------
    let queue: Vec<i64> = runs
        .iter()
        .filter(|run| !run.created.is_empty() && !run.started.is_empty() && !run.skipped())
        .filter_map(|run| Some(epoch(&run.started)? - epoch(&run.created)?))
        .collect();
    let queue_p90 = floor_rank(queue, 90);

    let (job_lat, unread_jobs) = job_queue(spec, slug, git_dir, &runs, fetch, &mut records);
    unreadable += unread_jobs;
    let queue_job_p90 = floor_rank(job_lat, 90);
    let peak = peak_concurrency(&runs);

    let retries = runs
        .iter()
        .filter(|run| run.attempt.parse::<i64>().is_ok_and(|attempt| attempt > 1))
        .count();

    let window = format!(
        "window\tsince={}\tlandings={}\tgraded={graded}\tgreen={green}\tred={red}\t\
         cancelled={cancelled}\tcancel_p50={cancel_p50}\tpeak_concurrency={peak}\t\
         queue_p90={queue_p90}\tqueue_job_p90={queue_job_p90}\tretries={retries}\t\
         ff_refused={ff_refused}\tff_success={ff_success}\tunreadable={unreadable}",
        spec.since,
        landed.len()
    );
    Produced::Recorded(compose(records, &window))
}

// --- record nonverdict ---------------------------------------------------------------

/// What `record nonverdict` measures, resolved from its flags and environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonverdict {
    /// How many recent failed runs to read — a count, deliberately not a date
    /// range: a window of runs cannot silently widen when the repo gets busier.
    pub window: u32,
    /// The required roster: the only jobs whose failures are the population.
    pub roster: Vec<String>,
    /// Jobs excluded by name — a fan-in whose failure its siblings manufacture.
    pub excluded: Vec<String>,
    /// Step-name prefixes that mark a step as verdict-bearing.
    pub verdict_steps: Vec<String>,
}

/// One failed job's classification: `verdict` or `nonverdict`, and the step.
fn classify(job: &Value, verdict_steps: &[String]) -> (&'static str, String) {
    let mut failed: Vec<&Value> = job
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter(|step| step.get("conclusion").and_then(Value::as_str) == Some("failure"))
                .collect()
        })
        .unwrap_or_default();
    failed.sort_by_key(|step| step.get("number").and_then(Value::as_i64).unwrap_or(0));
    let name = |step: &&Value| step.get("name").and_then(Value::as_str).map(str::to_owned);
    // THE PREDICATE IS CLOSED: a job rendered a verdict iff one of its failed
    // steps is one the consumer names. It names the ways a verdict is rendered,
    // never the growing set of ways a prelude can fail.
    let task = failed.iter().filter_map(name).find(|step| {
        verdict_steps
            .iter()
            .any(|prefix| step.starts_with(prefix.as_str()))
    });
    match task {
        Some(step) => ("verdict", step),
        None => (
            "nonverdict",
            failed
                .first()
                .and_then(name)
                .unwrap_or_else(|| String::from("unknown")),
        ),
    }
}

/// Classify the failed required jobs over `spec`'s window and compose the record.
// THE CLASSIFIER'S OWN DISCRIMINATION. Its cases live in `nonverdict.rs`: the
// gate's one suite declaration above names `land_divergence.rs`, and a Rust suite
// runs `cargo test -- <case>` across every target, so each filter still selects.
//MUTANT roster-ignored|s@^                    && spec.roster.iter().any(.required. required == name))$@                    \&\& true)@|the_producer_classifies_failed_required_jobs_and_the_module_decides
//MUTANT fan-in-counted|s@^                (!spec.excluded.iter().any(.excluded. excluded == name)$@                (true@|the_producer_classifies_failed_required_jobs_and_the_module_decides
//MUTANT every-failure-a-verdict|s@^        Some(step) => ("verdict", step),$@        Some(step) => ("nonverdict", step),@|the_producer_classifies_failed_required_jobs_and_the_module_decides
//MUTANT unreadable-run-dropped|s@^            unread_runs += 1;$@@|a_run_whose_jobs_cannot_be_read_is_counted_unreadable
//MUTANT verdict-steps-unread|s@^    let verdict_steps = listed(verdict_steps, "CI_VERDICT_STEPS", false);$@    let verdict_steps = verdict_steps.to_vec();@|the_producer_classifies_failed_required_jobs_and_the_module_decides
//MUTANT fan-in-unread|s@^    let excluded = listed(excluded, "CI_FANIN_CHECK", true);$@    let excluded = excluded.to_vec();@|the_producer_classifies_failed_required_jobs_and_the_module_decides
#[must_use]
pub fn nonverdict(spec: &Nonverdict, slug: &str, git_dir: &Path, fetch: Transport<'_>) -> Produced {
    let per_page = spec.window.to_string();
    let runs_path = format!("repos/{slug}/actions/runs");
    // ONE PAGE, BY DESIGN: the window IS the most recent `window` failed runs, so
    // a collection larger than it is the expected case, never a truncation.
    let rows = match forge::window_over(
        git_dir,
        &runs_path,
        &[("status", "failure"), ("per_page", &per_page)],
        Shape::Wrapped("workflow_runs"),
        1,
        fetch,
    ) {
        Window::Whole(rows) | Window::Truncated { rows, .. } => rows,
        Window::CouldNotLook { endpoint, status } => {
            return refused("could not read the failed-run list", &endpoint, status);
        }
    };
    // `.conclusion == "failure"` re-checks the query's own filter rather than
    // trusting it: a `cancelled` run is the lease declining a branch, which is
    // another sensor's case.
    let mut ids: Vec<u64> = rows
        .iter()
        .filter(|row| row.get("conclusion").and_then(Value::as_str) == Some("failure"))
        .filter_map(|row| row.get("id").and_then(Value::as_u64))
        .collect();
    ids.sort_unstable();

    let mut records = Vec::new();
    let (mut failed_jobs, mut nonverdicts, mut verdicts, mut unread_runs) =
        (0_u64, 0_u64, 0_u64, 0_u64);
    for id in &ids {
        let jobs_path = format!("repos/{slug}/actions/runs/{id}/jobs");
        // A RUN WHOSE JOBS CANNOT BE READ IS COUNTED, never an empty run
        // silently dropped from the window.
        let Window::Whole(jobs) = forge::window_over(
            git_dir,
            &jobs_path,
            &[("per_page", PAGE)],
            Shape::Wrapped("jobs"),
            DEFAULT_PAGES,
            fetch,
        ) else {
            unread_runs += 1;
            continue;
        };
        let mut failed: Vec<(String, &Value)> = jobs
            .iter()
            .filter(|job| job.get("conclusion").and_then(Value::as_str) == Some("failure"))
            .filter_map(|job| {
                let name = job.get("name").and_then(Value::as_str)?;
                // EXACT MEMBERSHIP, never a substring: a job named `action` is not
                // `action (ubuntu-latest)`.
                (!spec.excluded.iter().any(|excluded| excluded == name)
                    && spec.roster.iter().any(|required| required == name))
                .then(|| (name.to_owned(), job))
            })
            .collect();
        failed.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, job) in failed {
            let (kind, step) = classify(job, &spec.verdict_steps);
            failed_jobs += 1;
            if kind == "verdict" {
                verdicts += 1;
            } else {
                nonverdicts += 1;
            }
            records.push(format!(
                "{kind}\trun={id}\tjob={}\tstep={}",
                tsv(&name),
                tsv(&step)
            ));
        }
    }
    let window = format!(
        "window\truns={}\tfailed_jobs={failed_jobs}\tnonverdict={nonverdicts}\t\
         verdict={verdicts}\tunreadable={unread_runs}",
        ids.len()
    );
    Produced::Recorded(compose(records, &window))
}

// --- the verbs --------------------------------------------------------------------------

/// A flag's value, else a non-empty environment variable's.
fn flag_or_env(flag: Option<&str>, variable: &str) -> Option<String> {
    flag.map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var(variable)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

/// A repeatable flag's values, else a comma-separated environment variable's.
///
/// **The environment is the consumer's one spelling.** The scheduled job, the
/// `[[record]]` writer and every route that names this verb would otherwise each
/// carry the same list, and a spelling added to one and missed in another
/// classifies a verdict as a non-verdict without a word. `trim` is `false` for a
/// list whose entries are PREFIXES: `Run mise run ` ends in the space that stops
/// it matching `Run mise runner`, and trimming would drop exactly that.
fn listed(flags: &[String], variable: &str, trim: bool) -> Vec<String> {
    let given: Vec<String> = flags
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect();
    if !given.is_empty() {
        return given;
    }
    std::env::var(variable)
        .unwrap_or_default()
        .split(',')
        .map(|entry| if trim { entry.trim() } else { entry })
        .filter(|entry| !entry.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// A page budget or window size: a whole number in `1..=ceiling`.
fn bounded(verb: &str, flag: &str, value: &str, ceiling: u32) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|n| (1..=ceiling).contains(n))
        .ok_or_else(|| {
            UsageError::raise(format!(
                "{verb}: `{flag}` takes a whole number from 1 to {ceiling}"
            ))
        })
}

/// Write a produced window, or clear the stale one and say what could not be asked.
fn settle(
    verb: &str,
    family: &str,
    produced: Produced,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match produced {
        Produced::Recorded(body) => {
            crate::record::store_named(verb, family, &body)?;
            // THE SAME BYTES TO STDOUT, where a scheduled job publishes them: the
            // numbers are the point, and a summary that only appears on green is a
            // report nobody reads at the moment it matters.
            out.write_all(body.as_bytes())?;
            Ok(ExitCode::Success)
        }
        Produced::CouldNotLook(why) => {
            crate::record::clear_named(verb, family)?;
            writeln!(err, "batten: {verb}: could not look: {why}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// The repository slug and git directory, or the could-not-look a missing remote is.
fn locate() -> Result<(Option<String>, std::path::PathBuf)> {
    let root = Path::new(".");
    Ok((crate::repo_slug(root), crate::git::git_dir(root)?))
}

/// `batten record divergence`: measure the window and write `land-divergence`.
///
/// # Errors
///
/// A [`UsageError`] when a workflow is named by neither flag nor environment, or
/// when `--since` or `--max-pages` cannot be read; an internal error when the
/// store cannot be written. Could-not-look is not an error: it removes any stale
/// record, names what could not be asked on `err`, and answers
/// [`ExitCode::Internal`].
pub fn run_divergence(
    ci_workflow: Option<&str>,
    land_workflow: Option<&str>,
    since: Option<&str>,
    max_pages: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let named = |flag: Option<&str>, variable: &str, what: &str| {
        flag_or_env(flag, variable).ok_or_else(|| {
            UsageError::raise(format!(
                "{DIVERGENCE}: {what} is named by neither its flag nor `${variable}`, and this \
                 engine does not know which of the repository's workflows it is"
            ))
        })
    };
    let ci_workflow = named(ci_workflow, "LAND_CI_WORKFLOW", "`--ci-workflow`")?;
    let land_workflow = named(land_workflow, "LAND_WORKFLOW", "`--land-workflow`")?;
    let max_pages = match max_pages {
        Some(value) => bounded(DIVERGENCE, "--max-pages", value, u32::MAX)?,
        None => DEFAULT_PAGES,
    };
    let (since, since_at) = if let Some(text) = flag_or_env(since, "BATTEN_DIVERGENCE_SINCE") {
        let Some(at) = epoch(text.trim()) else {
            return Err(UsageError::raise(format!(
                "{DIVERGENCE}: `--since` is not an RFC 3339 instant with a zone"
            )));
        };
        (text.trim().to_owned(), at)
    } else {
        // A CLOCK THAT DID NOT READ IS NOT AN INSTANT: `now_unix` answers 0 on
        // failure, and a window measured back from the epoch is not the day.
        let now = crate::now_unix();
        if now == 0 {
            crate::record::clear_named(DIVERGENCE, DIVERGENCE_FAMILY)?;
            writeln!(
                err,
                "batten: {DIVERGENCE}: could not look: the clock did not read, so the window has no start"
            )?;
            return Ok(ExitCode::Internal);
        }
        let at = i64::try_from(now).unwrap_or(i64::MAX).saturating_sub(DAY);
        (
            crate::receipt::rfc3339_utc(u64::try_from(at).unwrap_or(0)),
            at,
        )
    };
    let spec = Divergence {
        ci_workflow,
        land_workflow,
        since,
        since_at,
        max_pages,
    };
    let (slug, git_dir) = locate()?;
    let produced = match slug {
        Some(slug) => divergence(&spec, &slug, &git_dir, &|path, etag| {
            crate::rest::get(path, etag)
        }),
        None => Produced::CouldNotLook(String::from(
            "no forge remote names the repository the window is about",
        )),
    };
    settle(DIVERGENCE, DIVERGENCE_FAMILY, produced, out, err)
}

/// `batten record nonverdict`: classify the window and write `nonverdict`.
///
/// # Errors
///
/// A [`UsageError`] when `$CI_REQUIRED_CHECKS` is empty — without the roster a
/// count over every job is meaningless — when neither `--verdict-step` nor
/// `$CI_VERDICT_STEPS` names a verdict step, or when
/// `--window` cannot be read; an internal error when the store cannot be
/// written. Could-not-look is [`ExitCode::Internal`], as for
/// [`run_divergence`].
pub fn run_nonverdict(
    window: Option<&str>,
    excluded: &[String],
    verdict_steps: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let roster: Vec<String> = std::env::var("CI_REQUIRED_CHECKS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    if roster.is_empty() {
        return Err(UsageError::raise(format!(
            "{NONVERDICT}: `$CI_REQUIRED_CHECKS` is empty, so there is no roster to tell a \
             required job from an unrelated one. Nothing was recorded."
        )));
    }
    let verdict_steps = listed(verdict_steps, "CI_VERDICT_STEPS", false);
    let excluded = listed(excluded, "CI_FANIN_CHECK", true);
    if verdict_steps.is_empty() {
        return Err(UsageError::raise(format!(
            "{NONVERDICT}: neither `--verdict-step` nor `$CI_VERDICT_STEPS` names how a \
             verdict is rendered, so every failure would read as a non-verdict"
        )));
    }
    let window = match window {
        Some(value) => bounded(NONVERDICT, "--window", value, 100)?,
        None => DEFAULT_WINDOW,
    };
    let spec = Nonverdict {
        window,
        roster,
        excluded,
        verdict_steps,
    };
    let (slug, git_dir) = locate()?;
    let produced = match slug {
        Some(slug) => nonverdict(&spec, &slug, &git_dir, &|path, etag| {
            crate::rest::get(path, etag)
        }),
        None => Produced::CouldNotLook(String::from(
            "no forge remote names the repository the window is about",
        )),
    };
    settle(NONVERDICT, NONVERDICT_FAMILY, produced, out, err)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rest::Answer;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A transport answering by the longest route whose needle the URL contains.
    fn forge(routes: Vec<(&'static str, String)>) -> impl Fn(&str, Option<&str>) -> Option<Answer> {
        let asked = RefCell::new(Vec::<String>::new());
        move |path: &str, _etag: Option<&str>| {
            asked.borrow_mut().push(path.to_owned());
            let body = routes
                .iter()
                .filter(|(needle, _)| path.contains(needle))
                .max_by_key(|(needle, _)| needle.len())
                .map(|(_, body)| body.clone())?;
            Some(Answer {
                status: 200,
                etag: None,
                poll_floor: None,
                backoff: None,
                body,
                headers: BTreeMap::new(),
            })
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("batten-ci-signal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn recorded(produced: Produced) -> String {
        match produced {
            Produced::Recorded(body) => body,
            other @ Produced::CouldNotLook(_) => panic!("expected a record, got {other:?}"),
        }
    }

    #[test]
    fn the_floor_rank_is_the_retired_awks_and_not_the_ceiling() {
        assert_eq!(floor_rank(vec![], 50), 0);
        assert_eq!(floor_rank(vec![300, 20], 50), 20, "p50 of two is the lower");
        assert_eq!(floor_rank((1..=10).collect(), 90), 9);
    }

    #[test]
    fn a_cell_holding_a_tab_cannot_forge_a_column() {
        assert_eq!(tsv("a\tb\\c\nd"), "a\\tb\\\\c\\nd");
    }

    #[test]
    fn a_field_reads_as_jq_alternative_reads_it() {
        let row = serde_json::json!({"a": null, "b": false, "c": 7, "d": "x"});
        assert_eq!(field(&row, "a"), None);
        assert_eq!(field(&row, "b"), None);
        assert_eq!(field(&row, "c").as_deref(), Some("7"));
        assert_eq!(field(&row, "d").as_deref(), Some("x"));
        assert_eq!(field(&row, "missing"), None);
    }

    #[test]
    fn a_failed_job_is_a_verdict_only_through_a_named_step() {
        let steps = vec![
            String::from("Run mise run "),
            String::from("Run mise exec -- "),
        ];
        let job = serde_json::json!({"steps": [
            {"number": 2, "name": "Run mise exec -- cargo test", "conclusion": "failure"},
            {"number": 1, "name": "Set up job", "conclusion": "success"},
        ]});
        assert_eq!(
            classify(&job, &steps),
            ("verdict", String::from("Run mise exec -- cargo test"))
        );
        let died = serde_json::json!({"steps": [
            {"number": 3, "name": "Run actions/checkout@x", "conclusion": "failure"},
            {"number": 2, "name": "Set up job", "conclusion": "failure"},
        ]});
        assert_eq!(
            classify(&died, &steps),
            ("nonverdict", String::from("Set up job"))
        );
        assert_eq!(
            classify(&serde_json::json!({}), &steps),
            ("nonverdict", String::from("unknown"))
        );
    }

    #[test]
    fn the_window_line_closes_the_divergence_record() {
        let dir = scratch("divergence");
        let fetch = forge(vec![
            (
                "workflows/ci.yml/runs",
                String::from(r#"{"total_count": 0, "workflow_runs": []}"#),
            ),
            (
                "workflows/land.yml/runs",
                String::from(r#"{"total_count": 0, "workflow_runs": []}"#),
            ),
            ("pulls", String::from("[]")),
        ]);
        let spec = Divergence {
            ci_workflow: String::from("ci.yml"),
            land_workflow: String::from("land.yml"),
            since: String::from("2026-08-12T00:00:00Z"),
            since_at: epoch("2026-08-12T00:00:00Z").unwrap(),
            max_pages: 10,
        };
        let body = recorded(divergence(&spec, "acme/widgets", &dir, &fetch));
        assert_eq!(
            body,
            "window\tsince=2026-08-12T00:00:00Z\tlandings=0\tgraded=0\tgreen=0\tred=0\t\
             cancelled=0\tcancel_p50=0\tpeak_concurrency=0\tqueue_p90=0\tqueue_job_p90=0\t\
             retries=0\tff_refused=0\tff_success=0\tunreadable=0\n"
        );
    }
}
