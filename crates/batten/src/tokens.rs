//! The token-economics benchmark: what a capability costs an agent's context
//! with Batten against without it (CLOUD-119), ported off
//! `mise-tasks/token-bench.sh` under CLOUD-1753.
//!
//! # The word that matters is MEASURE
//!
//! The market is full of unmethodical "cheaper" claims with no workload, no
//! baseline and no method behind them; they do not survive scrutiny and they
//! poison trust. What makes this saving defensible is that Batten's output
//! contract is deterministic, so the saving is reproducible — by someone else,
//! from this repository, with no credential and no network.
//!
//! # WHAT THIS CONTRIBUTES, AND WHAT IT MUST NOT
//!
//! It executes what `bench/tokens/workloads.toml` declares and prices it with
//! what `bench/tokens/method.toml` declares. It bakes in **no price, no divisor,
//! no re-run coefficient and no workload**. A constant written into a
//! benchmark's code is a number nobody re-derives, and re-derivation is the only
//! thing separating this from the claims it is meant to beat.
//!
//! # THE ARITHMETIC IS OVER BYTES, WHICH ARE EXACT
//!
//! Tokens are an estimate through one declared divisor, and dollars are that
//! estimate times a quoted published rate. Both arms of every comparison go
//! through the same divisor, so a RATIO is independent of it and only the
//! absolute columns move if the true tokenizer differs.
//!
//! # EVERY ARM RUNS `runs` TIMES AND IS COMPARED BYTE FOR BYTE
//!
//! An arm that differs between runs is reported as not byte-stable and carries
//! no figure. Averaging a non-deterministic tool is how a number arrives that
//! nothing supports, and byte-stability is exactly the property the
//! cross-session cache claim rests on — so a workload that lacks it has lost the
//! mechanism, not merely the precision.
//!
//! # NO AGGREGATE IS PUBLISHED, and the refusal is printed
//!
//! An aggregate across capabilities is a weighted mean over a workload mix
//! nobody here has measured, so it would be exactly the unmethodical figure this
//! benchmark exists to beat.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

/// Where the method lives, relative to the repository root.
pub const METHOD: &str = "bench/tokens/method.toml";

/// Where the workloads live.
pub const WORKLOADS: &str = "bench/tokens/workloads.toml";

/// Where the published table is written.
pub const RESULTS: &str = "bench/tokens/RESULTS.md";

/// How bytes become tokens, as data.
#[derive(Debug, Clone, Deserialize)]
pub struct Tokens {
    /// The divisor.
    pub bytes_per_token: u64,
    /// What the divisor is, in words.
    pub basis: String,
    /// Where it was read.
    pub source: String,
    /// When.
    pub retrieved: String,
    /// The direction the estimate can be wrong in.
    pub affects: String,
}

/// How tokens become dollars, as data.
#[derive(Debug, Clone, Deserialize)]
pub struct Price {
    /// Whose rates these are.
    pub model: String,
    /// Fresh input, per million.
    pub input_fresh: f64,
    /// Cache read, per million.
    pub input_cached_read: f64,
    /// Output, per million.
    pub output: f64,
    /// Where the rates were read.
    pub source: String,
    /// When.
    pub retrieved: String,
}

/// A gap the method states rather than leaves for a reader to find.
#[derive(Debug, Clone, Deserialize)]
pub struct Gap {
    /// What is not measured.
    pub subject: String,
    /// Why.
    pub reason: String,
    /// What is measured in its place.
    pub what_is_measured_instead: String,
}

/// `bench/tokens/method.toml`, whole.
#[derive(Debug, Clone, Deserialize)]
pub struct Method {
    /// The divisor and its provenance.
    pub tokens: Tokens,
    /// The rates and theirs.
    pub price: Price,
    /// The stated gaps.
    #[serde(default)]
    pub not_measured: Vec<Gap>,
}

/// One capability's workload.
#[derive(Debug, Clone, Deserialize)]
pub struct Workload {
    /// The workload's id, and its section heading.
    pub id: String,
    /// What capability it prices.
    pub capability: String,
    /// The question an agent is trying to answer.
    pub question: String,
    /// The committed fixture it runs against.
    #[serde(default)]
    pub fixture: String,
    /// How many times each arm runs.
    #[serde(default)]
    pub runs: usize,
    /// The step sequence without Batten.
    #[serde(default)]
    pub baseline: Vec<String>,
    /// What that sequence models.
    #[serde(default)]
    pub baseline_model: String,
    /// The step sequence with Batten.
    #[serde(default)]
    pub batten: Vec<String>,
    /// What that models.
    #[serde(default)]
    pub batten_model: String,
    /// Present where the capability is deliberately not measured, carrying why.
    ///
    /// **A stated gap is not a silent one.** A capability with no figure and no
    /// reason reads as covered because nothing says it is not, which is worse
    /// than a gap somebody chose.
    pub not_measured: Option<String>,
}

/// `bench/tokens/workloads.toml`, whole.
#[derive(Debug, Clone, Deserialize)]
pub struct Workloads {
    /// One per capability.
    #[serde(default)]
    pub workload: Vec<Workload>,
}

/// Read the method.
///
/// # Errors
///
/// A file that is missing or will not parse. **The method and the workloads are
/// the INPUTS, not defaults this program supplies** — a benchmark that invented
/// a divisor when it could not read one would publish a number with no primary
/// behind it.
pub fn method(root: &Path) -> Result<Method> {
    let path = root.join(METHOD);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!("token-bench: {METHOD} is missing — the method is an input, not a default")
    })?;
    toml::from_str(&text).with_context(|| format!("token-bench: {METHOD} did not parse"))
}

/// Read the workloads.
///
/// # Errors
///
/// A file that is missing or will not parse.
pub fn workloads(root: &Path) -> Result<Workloads> {
    let path = root.join(WORKLOADS);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!("token-bench: {WORKLOADS} is missing — the workloads are an input, not a default")
    })?;
    toml::from_str(&text).with_context(|| format!("token-bench: {WORKLOADS} did not parse"))
}

/// Tokens from bytes, through the declared divisor, rounding up.
///
/// Ceiling rather than truncation: a partial token is a token an agent pays for,
/// and rounding down would flatter every arm by the same sub-token amount while
/// making a one-byte difference invisible.
#[must_use]
pub fn tokens_of(bytes: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    bytes.div_ceil(divisor)
}

/// USD per 1,000 tasks at a per-million rate.
///
/// **Per 1k rather than per task**, and it is a readability decision with a
/// measurement consequence: a single wrapped command costs a fraction of a cent,
/// and a column of zeroes is a table nobody can read or check.
#[must_use]
pub fn usd_per_1k(tokens: u64, per_million: f64) -> f64 {
    // LOSSLESS BY CONSTRUCTION rather than by annotation, which is the idiom
    // `pr_watch::interval_for` records for CLOUD-1338: narrowing to `u32` first
    // makes the conversion exact for every value that survives it, and
    // saturating states the bound in code instead of in a `reason` string
    // claiming callers stay small. `u32::MAX` tokens is four billion — two
    // orders of magnitude past the largest workload this benchmark prices.
    let tokens = f64::from(u32::try_from(tokens).unwrap_or(u32::MAX));
    tokens * per_million / 1_000_000.0 * 1000.0
}

/// What one arm cost, or why it carries no figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arm {
    /// Every run produced identical bytes, and this is how many.
    Stable {
        /// Bytes the arm put in front of an agent.
        bytes: u64,
        /// The exit status of its last step.
        exit: i32,
        /// How many steps the arm costs.
        steps: usize,
    },
    /// The runs disagreed, so there is no single figure to report.
    Unstable {
        /// How many runs there were.
        runs: usize,
        /// How many steps the arm costs.
        steps: usize,
    },
}

impl Arm {
    /// The byte count, where there is one.
    #[must_use]
    pub const fn bytes(&self) -> Option<u64> {
        match self {
            Arm::Stable { bytes, .. } => Some(*bytes),
            Arm::Unstable { .. } => None,
        }
    }

    /// How many steps this arm costs.
    #[must_use]
    pub const fn steps(&self) -> usize {
        match self {
            Arm::Stable { steps, .. } | Arm::Unstable { steps, .. } => *steps,
        }
    }
}

/// Reduce a set of runs to an arm.
///
/// **Byte-for-byte across every run.** `arm::stability` is the shared reduction
/// and this is one of its callers, so "did every run agree" has one answer in
/// this crate rather than two that could disagree about what identical means.
#[must_use]
pub fn reduce(runs: &[Vec<u8>], exit: i32, steps: usize) -> Arm {
    let stable = matches!(
        crate::arm::stability(runs),
        crate::arm::Outcome::Observed(crate::arm::Reading::Stable)
    );
    if stable && let Some(first) = runs.first() {
        return Arm::Stable {
            bytes: first.len() as u64,
            exit,
            steps,
        };
    }
    Arm::Unstable {
        runs: runs.len(),
        steps,
    }
}

/// Materialise a committed fixture, stripping the inertness suffix.
///
/// Fixture files are committed with a trailing `.in` and the suffix comes off
/// here — the same convention `crates/batten/tests/fixtures/repos/` uses, so a
/// fixture may carry a shape this repository's own gates refuse (a banned
/// pattern, a lying build log) without tripping them over the same tree.
///
/// # Errors
///
/// A missing fixture, or a file inside one without the suffix — which would be a
/// fixture the gates DO see, and is a defect rather than a variation.
pub fn materialize(root: &Path, name: &str, into: &Path) -> Result<PathBuf> {
    let source = root.join("bench/tokens/fixtures").join(name);
    if !source.is_dir() {
        bail!("token-bench: no fixture at bench/tokens/fixtures/{name}");
    }
    let target = into.join(name);
    if target.is_dir() {
        return Ok(target);
    }
    std::fs::create_dir_all(&target).context("token-bench: could not create the fixture")?;

    let mut files: Vec<PathBuf> = Vec::new();
    collect(&source, &mut files)?;
    files.sort();
    for file in &files {
        let relative = file
            .strip_prefix(&source)
            .context("token-bench: a fixture file escaped its fixture")?;
        let Some(stripped) = relative
            .to_string_lossy()
            .strip_suffix(".in")
            .map(PathBuf::from)
        else {
            bail!(
                "token-bench: fixture file {} is missing the .in suffix",
                relative.display()
            );
        };
        let destination = target.join(&stripped);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).context("token-bench: could not stage a fixture")?;
        }
        std::fs::copy(file, &destination).context("token-bench: could not stage a fixture")?;
    }
    Ok(target)
}

/// Every file under `dir`, depth first.
fn collect(dir: &Path, into: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).context("token-bench: could not read a fixture")? {
        let entry = entry.context("token-bench: could not read a fixture entry")?;
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into)?;
        } else {
            into.push(path);
        }
    }
    Ok(())
}

/// The ratio of two byte counts, or `None` where the denominator is zero.
#[must_use]
pub fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator != 0).then(|| {
        // `usd_per_1k`'s conversion, for its reason: exact for everything that
        // survives the narrowing, and `u32::MAX` bytes is four gigabytes of
        // output from a single benchmark arm. BOTH SIDES SATURATE, so the ratio
        // stays a ratio of two bounded counts rather than of one bounded and one
        // not.
        let numerator = f64::from(u32::try_from(numerator).unwrap_or(u32::MAX));
        let denominator = f64::from(u32::try_from(denominator).unwrap_or(u32::MAX));
        numerator / denominator
    })
}

/// What a whole run produced, per workload.
#[derive(Debug, Clone)]
pub struct Measured {
    /// The workload this describes.
    pub id: String,
    /// Its arms, by name, where it was measured at all.
    pub arms: BTreeMap<String, Arm>,
}

/// Run one arm's step sequence once, returning everything it put in front of an
/// agent.
///
/// # BOTH STREAMS, and the reason is not symmetry
///
/// stdout AND stderr, concatenated across steps, because both reach the caller:
/// Batten's pointer report is on stderr and a wrapped child's teed output is on
/// stdout, so counting one would flatter whichever arm happened to use the
/// other.
///
/// **A failing step is the normal case, not an error.** `check` exits 2 over
/// findings and `exec` exits 1 over a promoted zero, and both codes are part of
/// the answer rather than a harness problem.
fn run_arm(dir: &Path, steps: &[String], binary: &Path) -> Result<(Vec<u8>, i32)> {
    let mut output = Vec::new();
    let mut exit = 0;
    for step in steps {
        let step = step.replace("$BATTEN", &binary.to_string_lossy());
        // THROUGH THE PLACED ADAPTER (review of #928). Running the step sequence
        // is this module's effect, but that is an argument for the spawn
        // EXISTING, never for it being written here: `exec` is the sanctioned
        // child-process boundary and `piped_argv` resolves a first word on
        // `PATH`, which is what `sh` is. With this, `tokens` holds no spawn of
        // its own and comes off `policy/spawn-adapters.rego`'s table.
        //
        // `Diagnostics::Keep` is the both-streams decision stated above, and the
        // one byte-level difference it makes is deterministic — the adapter
        // trims the diagnostic's trailing whitespace and separates the two
        // streams with a newline — so a stability comparison still decides
        // exactly what it decided before.
        let argv = ["sh", "-c", step.as_str()].map(ToOwned::to_owned);
        let (code, text) =
            crate::exec::piped_argv(dir, &argv, "", crate::exec::Diagnostics::Keep, &[])
                .with_context(|| format!("token-bench: could not run `{step}`"))?;
        output.extend_from_slice(text.as_bytes());
        exit = code;
    }
    Ok((output, exit))
}

/// Measure every workload the consumer declares.
///
/// # Errors
///
/// A missing input, a fixture that will not stage, or a step that will not run.
pub fn measure(root: &Path, binary: &Path, scratch: &Path) -> Result<Vec<Measured>> {
    let declared = workloads(root)?;
    let mut measured = Vec::new();
    for workload in &declared.workload {
        if workload.not_measured.is_some() {
            measured.push(Measured {
                id: workload.id.clone(),
                arms: BTreeMap::new(),
            });
            continue;
        }
        let dir = materialize(root, &workload.fixture, scratch)?;
        // `exec` resolves its capture store from the repository root, so a
        // fixture without a git dir is not a runnable workload.
        seed_git(&dir)?;

        let mut arms = BTreeMap::new();
        for (name, steps) in [
            ("baseline", &workload.baseline),
            ("batten", &workload.batten),
        ] {
            let mut runs = Vec::new();
            let mut exit = 0;
            for _ in 0..workload.runs.max(1) {
                let (bytes, code) = run_arm(&dir, steps, binary)?;
                exit = code;
                runs.push(bytes);
            }
            arms.insert(name.to_owned(), reduce(&runs, exit, steps.len()));
        }
        measured.push(Measured {
            id: workload.id.clone(),
            arms,
        });
    }
    Ok(measured)
}

/// Give a staged fixture a committed git dir, which `exec` needs to resolve its
/// store.
///
/// **In-process through `gitwrite::seed`, not three `git` children.** CLOUD-740
/// emptied this crate of `git` spawns and `git.rs` asserts it terminally; a
/// fixture is not an exception to that. Seeding is also not part of what this
/// module measures — the subject is the step sequence's output, not the setup —
/// so there was never an argument for the child processes.
///
/// # Errors
///
/// A directory that will not initialise or a file that will not read.
fn seed_git(dir: &Path) -> Result<()> {
    crate::gitwrite::seed(dir)
}

/// Append one line, which is the shape every renderer below writes in.
///
/// A free function rather than a closure per renderer: a closure borrows `out`
/// mutably for its whole life, which is exactly what stopped [`render`] from
/// being split before.
fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// The document's preamble: how to reproduce it, what is counted, and the
/// constants every figure below is derived through.
///
/// **Split out of [`render`] rather than annotated** (review of #928). The
/// previous shape carried `#[expect(clippy::too_many_lines)]` whose reason said
/// the table's shape IS the artifact and splitting it would put the document in
/// pieces — but the three pieces here are the document's own three parts, and
/// each one is still contiguous in the file. `policy/spawn-widening.rego`
/// refuses an added escape in engine source, and the escape was the only thing
/// the annotation bought.
fn render_method(out: &mut String, method: &Method) {
    let tokens = &method.tokens;
    let price = &method.price;
    line(out, "# Token economics, measured");
    line(out, "");
    line(
        out,
        "Generated by `mise run token-bench` from the committed fixtures. Do not hand-edit:",
    );
    line(
        out,
        "`mise run token-bench-check` regenerates this file and diffs it byte-for-byte, so an",
    );
    line(
        out,
        "edited number fails the gate rather than becoming the published one.",
    );
    line(out, "");
    line(
        out,
        "Reproduce it yourself — no credential, no network, committed inputs only:",
    );
    line(out, "");
    line(out, "```");
    line(
        out,
        "git clone https://github.com/button-inc/batten && cd batten",
    );
    line(out, "git submodule update --init && mise install");
    line(out, "mise run token-bench");
    line(out, "```");
    line(out, "");
    line(out, "## What is counted");
    line(out, "");
    line(
        out,
        "Bytes an arm puts in front of an agent — stdout **and** stderr, across every",
    );
    line(
        out,
        "step the task costs. Bytes are exact. Tokens are an estimate through one",
    );
    line(
        out,
        "declared divisor, and dollars are that estimate at one quoted published rate.",
    );
    line(out, "");
    line(out, "| constant | value | source | retrieved |");
    line(out, "| --- | --- | --- | --- |");
    line(
        out,
        &format!(
            "| bytes per token | {} — {} | <{}> | {} |",
            tokens.bytes_per_token, tokens.basis, tokens.source, tokens.retrieved
        ),
    );
    for (what, rate) in [
        ("fresh input", price.input_fresh),
        ("cache read", price.input_cached_read),
        ("output", price.output),
    ] {
        line(
            out,
            &format!(
                "| {}, {what} | ${rate:.2} / MTok | <{}> | {} |",
                price.model, price.source, price.retrieved
            ),
        );
    }
    line(out, "");
    line(out, &format!("The divisor affects {}.", tokens.affects));
    line(out, "");
    line(out, "## Per capability");
    line(out, "");
}

/// Whether a capability's section published a figure.
///
/// A two-state answer rather than a `bool`, because the aggregate prints BOTH
/// counts and a reader of `false` cannot tell "no figure" from "no section".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Published {
    /// A figure, with its method stated.
    Figure,
    /// No figure, with a stated reason — which is the honest half of the
    /// contract `unmethodical` holds the artifact to.
    Reason,
}

/// One capability's section.
///
/// `None` where the section renders nothing a reader could count: a workload
/// with no `baseline`/`batten` pair measured at all. That is distinct from
/// [`Published::Reason`], which is a section that DID say why.
fn render_capability(
    out: &mut String,
    workload: &Workload,
    result: &Measured,
    price: &Price,
    divisor: u64,
) -> Option<Published> {
    line(
        out,
        &format!("### {} — {}", workload.id, workload.capability),
    );
    line(out, "");
    line(out, &format!("**Question.** {}", workload.question));
    line(out, "");

    if let Some(ref reason) = workload.not_measured {
        line(out, &format!("**not measured** — {reason}"));
        line(out, "");
        line(
            out,
            "No figure is published for this capability, and none is projected from a",
        );
        line(
            out,
            "neighbouring one. A projection is an assertion wearing a measurement's clothes.",
        );
        line(out, "");
        return Some(Published::Reason);
    }

    let joined = |steps: &[String]| steps.join("` then `");
    line(
        out,
        &format!(
            "**Baseline** ({} step(s), `{}`). {}",
            workload.baseline.len(),
            joined(&workload.baseline),
            workload.baseline_model.trim().replace('\n', " ")
        ),
    );
    line(out, "");
    line(
        out,
        &format!(
            "**Batten** ({} step(s), `{}`). {}",
            workload.batten.len(),
            joined(&workload.batten).replace("$BATTEN", "batten"),
            workload.batten_model.trim().replace('\n', " ")
        ),
    );
    line(out, "");

    let (Some(base), Some(mine)) = (result.arms.get("baseline"), result.arms.get("batten")) else {
        return None;
    };
    let (Some(base_bytes), Some(batten_bytes)) = (base.bytes(), mine.bytes()) else {
        line(
            out,
            &format!(
                "**not measured** — an arm's output was not byte-identical across {} runs",
                workload.runs
            ),
        );
        line(out, "(baseline byte-stable: no, batten byte-stable: no),");
        line(
            out,
            "so there is no single figure to report. Byte-stability is the precondition the",
        );
        line(
            out,
            "cross-session cache claim rests on, so a workload that lacks it has lost the",
        );
        line(out, "mechanism, not merely the precision.");
        line(out, "");
        return Some(Published::Reason);
    };

    let (base_tokens, batten_tokens) = (
        tokens_of(base_bytes, divisor),
        tokens_of(batten_bytes, divisor),
    );
    line(
        out,
        &format!(
            "**Method.** measured; {} runs per arm, byte-identical across all of them; run",
            workload.runs
        ),
    );
    line(out, "count for the task is the step count above.");
    line(out, "");
    line(
        out,
        "| arm | steps | bytes | est. tokens | USD / 1k tasks (fresh) | USD / 1k tasks (cache read) | exit |",
    );
    line(out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (name, arm, bytes, count) in [
        ("baseline", base, base_bytes, base_tokens),
        ("batten", mine, batten_bytes, batten_tokens),
    ] {
        let exit = match arm {
            Arm::Stable { exit, .. } => *exit,
            Arm::Unstable { .. } => -1,
        };
        line(
            out,
            &format!(
                "| {name} | {} | {bytes} | {count} | {:.4} | {:.4} | {exit} |",
                arm.steps(),
                usd_per_1k(count, price.input_fresh),
                usd_per_1k(count, price.input_cached_read),
            ),
        );
    }
    let show =
        |value: Option<f64>| value.map_or_else(|| String::from("n/a"), |r| format!("{r:.2}"));
    line(
        out,
        &format!(
            "| **ratio** | | **{}×** | **{}×** | | | |",
            show(ratio(base_bytes, batten_bytes)),
            show(ratio(base_tokens, batten_tokens)),
        ),
    );
    line(out, "");
    Some(Published::Figure)
}

/// The closing halves: the aggregate this benchmark refuses to publish, and the
/// gaps the method states.
fn render_tail(out: &mut String, method: &Method, counted: usize, uncounted: usize) {
    line(out, "## Aggregate");
    line(out, "");
    line(
        out,
        "**Not published.** An aggregate across capabilities is a weighted mean over a",
    );
    line(
        out,
        "workload mix nobody here has measured, so it would be exactly the unmethodical",
    );
    line(
        out,
        &format!(
            "figure this benchmark exists to beat. Measured capabilities: {counted}. Reporting"
        ),
    );
    line(
        out,
        &format!("\"not measured\" with a reason above: {uncounted}."),
    );
    line(out, "");
    line(out, "## Stated gaps");
    line(out, "");
    for gap in &method.not_measured {
        line(
            out,
            &format!(
                "- **{}: not measured.** {}",
                gap.subject,
                gap.reason.trim().replace('\n', " ")
            ),
        );
        line(
            out,
            &format!(
                "  Measured instead: {}",
                gap.what_is_measured_instead.trim().replace('\n', " ")
            ),
        );
    }
    line(out, "");
}

/// Render the published table.
///
/// Byte-stable: the same inputs render the same bytes, which is what lets
/// `--check` diff a fresh run against the committed file.
///
/// # Errors
///
/// A missing input.
pub fn render(root: &Path, measured: &[Measured]) -> Result<String> {
    let method = method(root)?;
    let declared = workloads(root)?;
    let by_id: BTreeMap<&str, &Workload> = declared
        .workload
        .iter()
        .map(|workload| (workload.id.as_str(), workload))
        .collect();

    let mut out = String::new();
    render_method(&mut out, &method);

    let (mut counted, mut uncounted) = (0_usize, 0_usize);
    for result in measured {
        let Some(workload) = by_id.get(result.id.as_str()) else {
            continue;
        };
        match render_capability(
            &mut out,
            workload,
            result,
            &method.price,
            method.tokens.bytes_per_token,
        ) {
            Some(Published::Figure) => counted += 1,
            Some(Published::Reason) => uncounted += 1,
            None => {}
        }
    }

    render_tail(&mut out, &method, counted, uncounted);
    Ok(out)
}

/// What a section of the published table failed to state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmethodical {
    /// The 1-based line the section's heading is on.
    pub line: usize,
    /// What it owes.
    pub owed: &'static str,
}

/// The markers a published figure obliges, and what each one means.
///
/// A number with no workload, no baseline and no run count is the unmethodical
/// claim this benchmark exists to beat.
const OWED: &[(&str, &str)] = &[
    ("**Question.**", "the question the capability answers"),
    ("**Baseline**", "the arm the saving is measured against"),
    ("**Method.** measured;", "the run count behind the figure"),
];

/// The marker that opens a stated gap. The text AFTER it is the reason.
const GAP: &str = "**not measured** — ";

/// Hold the published table to its own method (CLOUD-119).
///
/// # WHY THIS RE-READS THE ARTIFACT rather than trusting the generator
///
/// [`render`] is what formats the rows, so a check implemented inside it would
/// be a program checking its own arithmetic. This reads the PUBLISHED bytes —
/// the thing a reader actually sees — so a generator bug that dropped a method
/// line fails here instead of shipping.
///
/// # A FIGURE OWES ITS METHOD; A GAP OWES A REASON
///
/// A section carrying a figure states its question, its baseline and its
/// run count. A section carrying none owes a reason, and the `not measured`
/// marker alone is not one: a capability that reads as covered because nothing
/// says it is not is worse than a gap somebody chose.
#[must_use]
pub fn unmethodical(report: &str) -> Vec<Unmethodical> {
    let lines: Vec<&str> = report.lines().collect();
    let opens = |line: &str| line.starts_with("### ");
    let closes = |line: &str| line.starts_with("## ") && !line.starts_with("### ");

    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !opens(line) {
            continue;
        }
        let end = lines
            .iter()
            .enumerate()
            .skip(index + 1)
            .find_map(|(other, text)| (opens(text) || closes(text)).then_some(other))
            .unwrap_or(lines.len());
        let body = &lines[index + 1..end];

        let carries = |prefix: &str| body.iter().any(|line| line.starts_with(prefix));
        let publishes = carries("| baseline |") || carries("| batten |");

        if publishes {
            for (marker, owed) in OWED {
                if !carries(marker) {
                    found.push(Unmethodical {
                        line: index + 1,
                        owed,
                    });
                }
            }
        } else if !body.iter().any(|line| {
            line.strip_prefix(GAP)
                .is_some_and(|rest| !rest.trim().is_empty())
        }) {
            found.push(Unmethodical {
                line: index + 1,
                owed: "a figure, or a stated reason for publishing none",
            });
        }
    }
    found
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_up_because_a_partial_token_is_paid_for() {
        assert_eq!(tokens_of(0, 4), 0);
        assert_eq!(tokens_of(1, 4), 1);
        assert_eq!(tokens_of(4, 4), 1);
        assert_eq!(tokens_of(5, 4), 2);
    }

    /// A divisor of zero is a method that could not be read; answering zero is
    /// the could-not-look direction rather than a division that panics.
    #[test]
    fn a_zero_divisor_answers_zero_rather_than_dividing() {
        assert_eq!(tokens_of(100, 0), 0);
    }

    #[test]
    fn dollars_are_per_thousand_tasks() {
        // 1000 tokens at $2.00/MTok is $0.002 per task, $2.00 per 1k tasks.
        let cost = usd_per_1k(1_000_000, 2.00);
        assert!((cost - 2000.0).abs() < 1e-9, "{cost}");
    }

    #[test]
    fn identical_runs_reduce_to_a_byte_count() {
        let runs = vec![b"same".to_vec(), b"same".to_vec()];
        assert_eq!(
            reduce(&runs, 0, 2),
            Arm::Stable {
                bytes: 4,
                exit: 0,
                steps: 2
            }
        );
    }

    /// CARRIES: "an arm that differs between runs is reported as not byte-stable
    /// and carries no figure."
    #[test]
    fn differing_runs_carry_no_figure() {
        let runs = vec![b"one".to_vec(), b"two".to_vec()];
        assert_eq!(reduce(&runs, 0, 1).bytes(), None);
        assert!(matches!(reduce(&runs, 0, 1), Arm::Unstable { runs: 2, .. }));
    }

    /// A ratio is independent of the divisor, which is what lets the absolute
    /// columns be an estimate while the comparison is not.
    #[test]
    fn a_ratio_is_independent_of_the_divisor() {
        let (baseline, batten) = (4000_u64, 400_u64);
        let by_bytes = ratio(baseline, batten).expect("a ratio");
        for divisor in [1_u64, 4, 100] {
            let by_tokens =
                ratio(tokens_of(baseline, divisor), tokens_of(batten, divisor)).expect("a ratio");
            assert!(
                (by_bytes - by_tokens).abs() < 1e-9,
                "divisor {divisor} moved the ratio: {by_bytes} vs {by_tokens}"
            );
        }
    }

    const METHODICAL: &str = "## Per capability\n\n\
        ### scan-pointer — pointer-only output\n\n\
        **Question.** Which files carry it?\n\n\
        **Baseline** (1 step(s), `grep`). Everything.\n\n\
        **Method.** measured; 3 runs per arm, byte-identical across all of them; run\n\
        count for the task is the step count above.\n\n\
        | arm | bytes |\n| baseline | 100 |\n| batten | 10 |\n\n\
        ## Aggregate\n";

    #[test]
    fn a_methodical_section_owes_nothing() {
        assert_eq!(unmethodical(METHODICAL), Vec::new());
    }

    #[test]
    fn a_figure_without_a_baseline_owes_one() {
        let stripped: String = METHODICAL
            .lines()
            .filter(|line| !line.starts_with("**Baseline**"))
            .collect::<Vec<_>>()
            .join("\n");
        let found = unmethodical(&stripped);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].owed.contains("measured against"), "{found:?}");
    }

    #[test]
    fn a_figure_without_a_question_or_run_count_owes_both() {
        let stripped: String = METHODICAL
            .lines()
            .filter(|line| {
                !line.starts_with("**Question.**") && !line.starts_with("**Method.** measured;")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(unmethodical(&stripped).len(), 2);
    }

    /// A STATED GAP IS CLEAN. A capability nobody measured is admissible; one
    /// nobody measured and nobody explained is not.
    #[test]
    fn a_stated_gap_owes_nothing() {
        let report = "## Per capability\n\n### cache — cross-session cache\n\n\
                      **Question.** What does a warm cache save?\n\n\
                      **not measured** — it needs two sessions, which this harness cannot stage.\n\n\
                      ## Aggregate\n";
        assert_eq!(unmethodical(report), Vec::new());
    }

    /// THE MARKER ALONE IS NOT A REASON. A capability that reads as covered
    /// because nothing says it is not is worse than a gap somebody chose.
    #[test]
    fn the_marker_alone_is_not_a_reason() {
        let report = "## Per capability\n\n### cache — cross-session cache\n\n\
                      **not measured**\n\n## Aggregate\n";
        let found = unmethodical(report);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].owed.contains("stated reason"), "{found:?}");
    }

    #[test]
    fn a_section_with_neither_a_figure_nor_a_reason_owes_one() {
        let report = "## Per capability\n\n### orphan — nothing\n\n## Aggregate\n";
        assert_eq!(unmethodical(report).len(), 1);
    }

    /// A SECTION ENDS AT THE NEXT HEADING OF EITHER LEVEL, and getting that
    /// wrong is how one section's method is read as another's.
    #[test]
    fn a_method_line_does_not_leak_across_a_section_boundary() {
        let report = "## Per capability\n\n### first — a\n\n\
                      **Question.** q\n\n**Baseline** (1). b\n\n\
                      **Method.** measured; 3 runs per arm, x\n\n\
                      | baseline | 1 |\n\n\
                      ### second — b\n\n| batten | 2 |\n\n## Aggregate\n";
        let found = unmethodical(report);
        assert_eq!(
            found.len(),
            3,
            "the second section owes all three: {found:?}"
        );
        assert!(found.iter().all(|f| f.line > 10), "{found:?}");
    }

    #[test]
    fn a_zero_denominator_has_no_ratio() {
        assert_eq!(ratio(10, 0), None);
    }
}
