//! Parsing the command surface into the typed values `run` dispatches on.
//!
//! The surface itself is *not* defined here — it is one declaration in
//! [`crate::surface`], from which the live [`clap::Command`] tree is built
//! (house-style §11). This module owns the other half: turning the parsed
//! [`clap::ArgMatches`] into a typed [`Cli`], so dispatch stays an exhaustive
//! `match` over enums rather than a lookup on strings.
//!
//! The split is what keeps the tree honest. A verb's path, summary, effect, and
//! flags exist once, as data; adding one is adding a [`crate::surface::SURFACE`]
//! row plus the arm here that gives it a typed shape.
//! [`tests::every_leaf_verb_dispatches`] fails if a row ever ships without its
//! arm, so a declared command can never parse into `None` and silently succeed.

use clap::{ArgMatches, ValueEnum};

use crate::config::Strictness;
use crate::hook::{Field as HookFieldName, Harness};
use crate::rules::ReceiptKey;
use crate::surface;

/// The parsed invocation: the global flags plus the chosen command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cli {
    /// `--strictness`, when passed.
    ///
    /// `BATTEN_STRICTNESS` is the env equivalent, resolved by
    /// [`crate::resolve`] as its own layer rather than by `clap`, so `config
    /// show` can attribute the value to `env` or `flag` and not conflate them.
    pub strictness: Option<Strictness>,
    /// `--fail-on-warning`, promoting a warn-severity finding to a violation.
    ///
    /// One setting, not a per-verb flag: `BATTEN_FAIL_ON_WARNING` and the
    /// `fail_on_warning` key are the same setting, layered by
    /// [`crate::resolve`]. Raise-only and with no negative form, so a committed
    /// `true` cannot be turned off for a run.
    pub fail_on_warning: bool,
    /// `--config-from <ref>`, when passed: read the committed authority from
    /// this git ref instead of the working tree (CLOUD-31).
    pub config_from: Option<String>,
    /// `--config-in <dir>`, when passed: read the committed authority from this
    /// directory instead of the one being judged (CLOUD-1228).
    ///
    /// `BATTEN_CONFIG_IN` is the env equivalent, read by `clap` exactly as
    /// `BATTEN_CONFIG_FROM` is — both select a *source* rather than a value, so
    /// neither joins the layered chain [`crate::resolve`] attributes.
    pub config_in: Option<String>,
    /// The chosen command, or `None` for a bare invocation.
    pub command: Option<Command>,
}

/// `check`'s flags, which travel together because they narrow one run.
///
/// A payload struct rather than four fields on the variant: `check` is the verb
/// with the most flags, and grouping them keeps every dispatch site one line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CheckFlags {
    /// Emit findings as byte-stable JSON instead of pointer lines.
    pub json: bool,
    /// Run only the declared row with this id (CLOUD-1051).
    ///
    /// `None` is every applicable row, which is what `check` has always meant. A
    /// `Some` naming no declared row is a usage error rather than a clean run
    /// over nothing — see `surface::CHECK_RULE`.
    pub rule: Option<String>,
    /// `--staged`: judge only what the git index holds differently from `HEAD`
    /// (CLOUD-519).
    pub staged: bool,
    /// `--since <rev>`: judge only what changed against this rev.
    ///
    /// Carried raw beside `staged` rather than pre-resolved into one scope,
    /// because the two are mutually exclusive and this module has no channel to
    /// refuse with — it maps `ArgMatches` to types and nothing else. The refusal,
    /// and the git read that turns either into a path set, both live where a
    /// `Result` and the repository root do.
    pub since: Option<String>,
}

/// The top-level subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Run the applicable read-only gates against the repository.
    Check(CheckFlags),
    /// Run every configured rule, including kinds that execute a configured command.
    Enforce {
        /// Emit findings as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Inspect configuration.
    Config {
        /// The chosen sub-verb.
        command: ConfigCommand,
    },
    /// Print the tool's own command spec.
    Spec {
        /// The output format for the spec.
        format: SpecFormat,
    },
    /// Diagnose whether Batten can run in this repository.
    Doctor {
        /// The chosen diagnosis: the bare report, or a focused sub-diagnostic.
        command: DoctorCommand,
    },
    /// Emit an artifact derived from the command spec.
    Generate {
        /// The chosen sub-verb.
        command: GenerateCommand,
    },
    /// Run a command — or a `:::` bundle — and report a pointer to what it wrote.
    Exec(ExecRequest),
    /// Captured command output, and the verbs that navigate it.
    Capture {
        /// The chosen sub-verb.
        command: CaptureCommand,
    },
    /// Dispatch a declared MCP call and hand back a reduction.
    Mcp {
        /// The chosen sub-verb.
        command: McpCommand,
    },
    /// Inspect and reclaim this repository's build tree.
    Target {
        /// The chosen sub-verb.
        command: TargetCommand,
    },
    /// Adjudicate a mediated tool call read from stdin.
    Hook {
        /// The harness whose payload to decode and whose decision channel to answer in.
        harness: Harness,
    },
    /// Print one allowlisted field of a hook payload read from stdin.
    HookField {
        /// The harness whose payload dialect to decode.
        harness: Harness,
        /// Which field to print.
        field: HookFieldName,
    },
    /// Verification receipts, keyed by SHA.
    Receipt {
        /// The chosen sub-verb.
        command: ReceiptCommand,
    },
    /// Inspect the thresholds and path sets this repository holds itself to.
    Policy {
        /// The chosen sub-verb.
        command: PolicyCommand,
    },
    /// What produced commits may carry about the tooling that made them.
    Attribution {
        /// The chosen sub-verb.
        command: AttributionCommand,
    },
    /// Worktrees and the work in them.
    Worktree {
        /// The chosen sub-verb.
        command: WorktreeCommand,
    },
    /// The out-of-tree findings store.
    State {
        /// The chosen sub-verb.
        command: StateCommand,
    },
    /// The out-of-tree verdict stores' write half (CLOUD-1265).
    Record {
        /// The chosen sub-verb.
        command: RecordCommand,
    },
    /// The append-only defect ledger.
    Defects {
        /// The chosen sub-verb.
        command: DefectsCommand,
    },
    /// Pinned tools this repository provisions.
    Provision {
        /// The chosen sub-verb.
        command: ProvisionCommand,
    },
    /// Lint an artifact against a declared schema.
    Lint {
        /// The chosen kind.
        command: LintCommand,
    },
    /// Design-evidence claims and the integrity of the record behind them.
    Design {
        /// The chosen sub-verb.
        command: DesignCommand,
    },
    /// Write a starter `batten.toml` into the working directory.
    ///
    /// Appended rather than placed beside `generate`, where the surface groups
    /// it: this enum carries no `repr`, so a variant inserted in the middle
    /// shifts every later discriminant and `mise run semver` reads that as a
    /// break the crate would have to declare. Declaration order here is not a
    /// contract with anything — dispatch is an exhaustive match and the surface
    /// is `surface.rs`'s — so appending is free and declaring a breaking change
    /// for a cosmetic ordering would not be.
    Init {
        /// Report what would be written, writing nothing.
        dry_run: bool,
    },
    /// Record the findings that already exist, so only new ones fail.
    Baseline {
        /// Drop entries whose finding no longer exists, and ratchet reduced
        /// counts down. Two verbs' worth of behaviour behind one flag because
        /// both write the same artifact — see `surface::PRUNE`.
        prune: bool,
        /// Report what would be recorded, writing nothing.
        dry_run: bool,
    },
    /// The shape a commit must take here.
    ///
    /// Appended rather than placed beside `attribution`, where the surface
    /// groups it, for the reason `Init` above states: this enum carries no
    /// `repr`, so a variant inserted in the middle shifts every later
    /// discriminant and `mise run semver` reads that as a break the crate would
    /// have to declare. Declaration order here is not a contract with anything —
    /// dispatch is an exhaustive match and the surface is `surface.rs`'s.
    Commit {
        /// The chosen sub-verb.
        command: CommitCommand,
    },
    /// Issued admissions — an override that is a record, not knowledge.
    ///
    /// Appended for the reason `Init` above states, and it is the same one every
    /// new variant here answers to: this enum carries no `repr`, so a variant
    /// placed beside its neighbours in the surface would shift every later
    /// discriminant and `mise run semver` would read that as a break the crate
    /// has to declare.
    Override {
        /// The chosen sub-verb.
        command: OverrideCommand,
    },
    /// The API-compatibility gate (CLOUD-1050), ported off `mise-tasks/semver.sh`.
    ///
    /// Appended for the reason `Override` above states, which this variant is the
    /// first to be judged by: `mise run semver` reads a shifted discriminant as a
    /// break the crate has to declare.
    Semver {
        /// The chosen sub-verb.
        command: SemverCommand,
    },
    /// The paired latency measurement (CLOUD-875), ported off
    /// `mise-tasks/perf-pair.sh` under CLOUD-1059's retirement campaign.
    ///
    /// Appended for the reason `Override` states and `Semver` was first judged
    /// by: a shifted discriminant reads as a break the crate has to declare.
    Perf {
        /// The chosen sub-verb.
        command: PerfCommand,
    },
    /// Repair a host's hook registrations.
    ///
    /// Appended AFTER `Perf`, for the reason `Semver` is the first to state and
    /// the first to be judged by: this enum carries no `repr`, so a variant
    /// placed beside its neighbours shifts every later discriminant and the
    /// compatibility gate reads that as a break the crate has to declare.
    ///
    /// `Perf` and this arrived on separate branches, each appended after
    /// `Semver`, which is the one shape that conflicts textually while both
    /// sides are individually correct. Resolved by ORDER OF LANDING — `Perf` is
    /// already on `main`, so it keeps the discriminant it landed with and this
    /// one takes the next.
    Wiring {
        /// The chosen sub-verb.
        command: WiringCommand,
    },
    /// The refinement gate over an issue's Ready block (CLOUD-1121), ported off
    /// `mise-tasks/ready-lint.sh`.
    ///
    /// Appended for the reason `Override` states: a shifted discriminant is a
    /// break the crate has to declare.
    Ready {
        /// The chosen sub-verb.
        command: ReadyCommand,
    },
    /// The pull-time claim gate (CLOUD-1121), ported off
    /// `mise-tasks/claim-check.sh`.
    Claim {
        /// The chosen sub-verb.
        command: ClaimCommand,
    },
    /// The green-verdict gate (CLOUD-1143), ported off
    /// `mise-tasks/checks-green.sh`.
    ///
    /// Appended for the reason `Override` states: a shifted discriminant is a
    /// break the crate has to declare.
    Checks {
        /// The chosen sub-verb.
        command: ChecksCommand,
    },
    /// The conditional poll (CLOUD-1143), ported off `mise-tasks/ci-wait.sh`.
    ///
    /// Appended for the same reason `Checks` is.
    Pr {
        /// The chosen sub-verb.
        command: PrCommand,
    },
    /// Mutation coverage over the declared gate set (CLOUD-1267), ported off
    /// `mise-tasks/mutant.sh` and `mise-tasks/mutant-census.sh`.
    ///
    /// Appended for the same reason `Checks` is: a shifted discriminant is a
    /// break the crate has to declare.
    Mutate {
        /// The chosen sub-verb.
        command: MutateCommand,
    },
    /// The landing lease (CLOUD-1274), ported off `mise-tasks/land-lock.sh`.
    ///
    /// Appended for the same reason `Mutate` is: this enum carries no `repr`, so
    /// a variant placed beside its neighbours in the surface shifts every later
    /// discriminant and the compatibility gate reads that as a break the crate
    /// has to declare.
    Lease {
        /// The chosen sub-verb.
        command: LeaseCommand,
    },
}

/// Subcommands of `mutate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MutateCommand {
    /// Apply every declared mutation and report the ones its suite did not
    /// catch.
    Sweep,
    /// Report every gate that is neither enforced nor carrying a filed
    /// exemption, in both directions.
    Census,
}

/// Subcommands of `pr`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrCommand {
    /// Poll a head's check runs until the required set answers.
    Watch {
        /// The commit whose checks are read.
        sha: String,
        /// The repository, in whatever spelling the forge's client resolves.
        repo: Option<String>,
        /// Seconds between requests — a floor the server may raise. Carried as
        /// written, because a value that is not a number is a usage error and
        /// parsing it here would have to spell that as `None`, which is the
        /// spelling for "not given".
        interval: Option<String>,
        /// The program that records the two progress signals.
        progress: Option<String>,
        /// The identity that recorder keys on.
        progress_id: Option<String>,
        /// The names that carry a verdict about this repository.
        required: String,
        /// The names for which no run at all is a legitimate reading.
        absent_ok: Option<String>,
        /// The conclusions that constitute an answer.
        answered: String,
        /// The fan-in whose failure a cancelled sibling can manufacture.
        fanin: Option<String>,
    },
}

/// Subcommands of `checks`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksCommand {
    /// Decide whether a reading says this head is green.
    Green {
        /// The names that carry a verdict about this repository.
        required: String,
        /// The names for which no run at all is a legitimate reading. Absent is
        /// the STRICT direction — every roster name must be present.
        absent_ok: Option<String>,
        /// The conclusions that constitute an answer.
        answered: String,
        /// The fan-in whose failure a cancelled sibling can manufacture. Absent
        /// leaves every failure manufacturable, which is the safe default.
        fanin: Option<String>,
        /// Emit the verdict on the structured channel.
        json: bool,
    },
}

/// Subcommands of `ready`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadyCommand {
    /// Lint one issue's Ready block.
    Lint {
        /// Resolve the payload from the capture store under this key instead of
        /// reading stdin. **Never a fallback**: a resolve that fails is
        /// could-not-look, because dropping through to an empty stdin would
        /// report a refined issue as carrying no block at all.
        issue: Option<String>,
        /// Emit the findings on the structured channel.
        json: bool,
    },
}

/// Subcommands of `claim`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimCommand {
    /// Judge a set of payloads and mint the receipt when they are pullable.
    Check {
        /// Claim over the competitor refusals, recording what was overridden.
        takeover: bool,
        /// Skip the refinement-sequence rules, recorded as a bypass.
        bypass_sequence: bool,
        /// Re-key an orphaned receipt onto this branch instead of judging.
        adopt: bool,
        /// Which orphan to adopt, where more than one is stranded.
        adopt_from: Option<String>,
        /// Resolve the payload from the capture store under this key.
        issue: Option<String>,
        /// Emit the refusals on the structured channel.
        json: bool,
    },
}

/// Subcommands of `semver`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SemverCommand {
    /// Compare this branch's public API against a baseline.
    Check {
        /// The rev to measure against. `None` is `origin/main`.
        baseline: Option<String>,
        /// The bump being claimed. `None` is `patch`, which is the honest claim
        /// below `0.1.0` because release-plz bumps the patch whatever the commit
        /// type says.
        release_type: Option<String>,
        /// The package compared. `None` is `batten`.
        package: Option<String>,
    },
}

/// Subcommands of `perf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PerfCommand {
    /// Measure this branch and its merge base back to back on one machine.
    Pair {
        /// Measure HEAD against itself, so the ratio is the noise floor rather
        /// than a comparison. It is how `perf-compare`'s threshold was derived,
        /// and the flag exists so that floor stays re-measurable.
        null: bool,
    },
}

/// Everything `batten exec` was asked for, as one value.
///
/// A struct rather than six variant fields, and the reason is a readability one
/// a lint happens to enforce: [`crate::run`]'s dispatch is a table of one line
/// per verb, and a verb whose arm is eighteen lines of field-shuffling stops
/// being readable as a table. The fields are the same either way.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecRequest {
    /// The command and its arguments, exactly as the caller wrote them,
    /// including any `:::` separators (CLOUD-430).
    pub command: Vec<String>,
    /// Store the child's streams and report their handles instead of passing
    /// the bytes through.
    ///
    /// Kept, and now what happens by DEFAULT rather than the opt-in it was
    /// (CLOUD-429): it survives as the inverse spelling of `--tee`, so a caller
    /// who learned it is not told a flag disappeared. Both may be typed; `--tee`
    /// wins, because asking for the bytes is the specific request.
    pub capture_only: bool,
    /// Whether to copy the child's streams onto Batten's own (CLOUD-429).
    pub tee: bool,
    /// How Batten's own record is encoded — hk's axis.
    ///
    /// `None` means the caller did not ask, which is **not** the same as asking
    /// for the default: the `[exec]` table sets the default, and a flag that
    /// always answered would overwrite it on every call.
    pub format: Option<crate::exec::OutputFormat>,
    /// How a teed child's bytes are presented — mise's axis. `None` as above.
    pub style: Option<crate::exec::OutputStyle>,
    /// How many of a `:::` bundle's commands run at once, as the caller typed
    /// it. Unparsed on purpose: a bad value must reach a `UsageError` naming
    /// what was wrong, and silently reading it as the default would run a bundle
    /// at a width nobody asked for.
    pub jobs: Option<String>,
    /// Whether a bundle keeps going past a failure. `false` when unasked, which
    /// the committed table may still turn on.
    pub continue_on_error: bool,
}

/// Subcommands of `lint` — one arm per *kind* of artifact, which is what the
/// house-style `lint <kind>` shape names (CLOUD-84).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LintCommand {
    /// Check a delegation brief against the handoff schema.
    Brief {
        /// The brief to read. `None` or `-` reads stdin, so a brief can be piped
        /// straight from whatever composed it without a temporary file.
        path: Option<String>,
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `design`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DesignCommand {
    /// Audit a JSONL claim stream read on stdin.
    Audit {
        /// Emit the problems as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `defects`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefectsCommand {
    /// List recorded defects as pointers.
    Query {
        /// Emit the records as byte-stable JSON instead of pointer lines.
        json: bool,
        /// Only records in this taxonomy class.
        class: Option<String>,
        /// Only the record with this id.
        id: Option<String>,
        /// Only records nothing gates yet.
        ungated: bool,
    },
    /// Append records read as JSONL on stdin.
    Add {
        /// Validate and report the would-append count without writing.
        dry_run: bool,
    },
}

/// Subcommands of `provision`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisionCommand {
    /// Report which provisioned tools do not match the manifest.
    Status {
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Fetch, verify, and install into the out-of-tree cache.
    Apply {
        /// Preview what would be applied, writing nothing.
        dry_run: bool,
    },
}

/// Subcommands of `lease` (CLOUD-1274).
///
/// **Nine arms, and only three of them write.** The split is what the surface's
/// effect column already records per row; it is repeated here as a type so a
/// caller pattern-matching on this enum sees the same partition the allowlist is
/// derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseCommand {
    /// May this branch spend a matrix right now? The one question a runner asks.
    Authorises {
        /// The branch asking.
        branch: String,
    },
    /// Who holds it, for how long, and who is admitted behind them.
    Status {
        /// Emit the report as byte-stable JSON instead of a pointer line.
        json: bool,
    },
    /// Print one advisory field of the held lease, or nothing.
    Peek {
        /// Which field: `branch`, `head` or `next`.
        field: String,
    },
    /// Is this clone's lease still held, with a beat of margin to act on?
    Held,
    /// Take the lease, waiting out a live holder and reaping a dead one.
    Acquire {
        /// The branch the lease will authorise.
        branch: String,
    },
    /// Extend this clone's lease by one term.
    Renew,
    /// Renew every beat until the lease is lost or the hold ends.
    Hold,
    /// Hand the lease back, leaving a tombstone.
    Release,
    /// Take the one slot behind the current holder.
    Reserve {
        /// The branch reserving.
        branch: String,
    },
}

/// Subcommands of `override` (CLOUD-1051).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OverrideCommand {
    /// Answer a class's declared precondition and receive an admission.
    Request {
        /// The rule whose refusal is being overridden.
        rule: String,
        /// The declared class that refusal carries.
        verdict: String,
        /// The gate's canonical subject.
        subject: String,
    },
    /// Spend an issued admission against the situation it was issued for.
    ///
    /// Appended rather than placed beside its sibling, for the reason this
    /// enum's own `Override` variant records: no `repr`, so a variant in the
    /// middle re-numbers every later discriminant and `semver` reads that as a
    /// break the crate has to declare.
    ///
    /// **The write half, and it is a separate verb rather than a flag on a gate
    /// for the reason house-style §5 draws.** `check` is `read`: a read-effect
    /// verb that left a record behind would be a verb that changes what it is
    /// judging. Consuming an admission is a WRITE — it moves a record from
    /// issued to spent — so it is its own verb, called by the gate's task after
    /// the refusal rather than folded into the thing that refused.
    Spend {
        /// The admission address to consume.
        admission: String,
        /// The rule whose refusal it was issued against.
        rule: String,
        /// The declared class that refusal carries.
        verdict: String,
        /// The gate's canonical subject.
        subject: String,
    },
}

/// Subcommands of `wiring`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WiringCommand {
    /// Remove non-batten hook registrations from this host's merged surfaces.
    Reclaim {
        /// The global `-y --yes`, which this verb requires: it never prompts.
        yes: bool,
        /// Report what would be removed and remove nothing.
        dry_run: bool,
    },
}

/// Subcommands of `worktree`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorktreeCommand {
    /// Report work that is uncommitted, unpushed, or not landed.
    Status {
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyCommand {
    /// Judge the always-loaded instruction set against its token budget.
    Budget {
        /// Emit the measurement as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Run each registered module's own `test_` rules (CLOUD-835).
    ///
    /// Appended rather than placed alphabetically: this enum carries no `repr`,
    /// so a variant inserted in the middle re-numbers every later discriminant
    /// and `semver` reads that as `enum_no_repr_variant_discriminant_changed`.
    Test {
        /// Emit the suite as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Print the tool names the `mediated_call` rows decide (CLOUD-312 row 4).
    ///
    /// Appended for the reason `Test` states above.
    Tools {
        /// Emit the names as byte-stable JSON instead of one per line.
        json: bool,
    },
    /// Resolve a verdict token to its class definition and routes (CLOUD-1053).
    ///
    /// Appended for [`PolicyCommand::Test`]'s reason: a variant inserted in the
    /// middle re-numbers every later discriminant and `semver` reads that as
    /// `enum_no_repr_variant_discriminant_changed`.
    Explain {
        /// The token to resolve, e.g. `V-TASK-UNDEFINED`.
        token: String,
        /// Emit the class as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `attribution`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributionCommand {
    /// Judge commit metadata against the `[attribution]` policy.
    Check {
        /// Emit the findings as byte-stable JSON instead of pointer lines.
        json: bool,
        /// The commit range to judge. Mutually exclusive with `message`;
        /// exactly one must be given, and neither is a usage error rather than
        /// a vacuous pass over nothing.
        range: Option<String>,
        /// The pending commit-message file to judge.
        message: Option<String>,
        /// The host whose attribution capabilities the emitted document reports,
        /// and at whose declared fidelity a caller field may be captured
        /// (CLOUD-276).
        ///
        /// `None` is "no host was named" and stays distinguishable from every
        /// host's row: it declares nothing rather than borrowing a default's
        /// declarations. It changes no verdict either way — enforcement is
        /// git-native and host-independent.
        harness: Option<Harness>,
    },
    /// Set this clone's repo-local git identity when it is unset or denied.
    Identity,
}

/// Subcommands of `capture` (CLOUD-121).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureCommand {
    /// Read a frozen capture, with no second run of the command that made it.
    Show {
        /// The `<stream>:<digest>` handle to read.
        handle: String,
        /// A 1-indexed inclusive `FROM:TO` window, clamped to the capture.
        lines: Option<String>,
        /// A case-sensitive literal substring; only lines containing it.
        grep: Option<String>,
        /// Write the selected bytes to stdout verbatim, with no decode.
        raw: bool,
        /// A 0-indexed half-open `FROM:TO` byte range, clamped to the capture.
        bytes: Option<String>,
        /// Emit the selection as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// List this repository's captures as handles.
    List {
        /// Only captures of this stream.
        stream: Option<String>,
        /// List recorded calls instead of stored captures.
        calls: bool,
        /// Emit the listing as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Remove this repository's captures. The one removal path.
    Prune {
        /// The global `-y --yes`, which this verb requires: it never prompts.
        yes: bool,
        /// Report what would be removed and remove nothing.
        dry_run: bool,
    },
    /// Resolve a stored tool response by the key it carries (CLOUD-1121).
    ///
    /// APPENDED rather than placed beside `show`, where the surface groups it,
    /// for the reason `Command::Init` states one level up: this enum carries no
    /// `repr`, so a variant inserted in the middle shifts every later
    /// discriminant and `mise run semver` reads that as a break the crate would
    /// have to declare. Measured — it did, as
    /// `enum_no_repr_variant_discriminant_changed`. Declaration order here is a
    /// contract with nothing: dispatch is an exhaustive match and the verb order
    /// a reader sees is `surface.rs`'s.
    Find {
        /// The key the response must carry.
        key: String,
        /// Tool selectors; a response matching any of them is eligible.
        tools: Vec<String>,
        /// The dotted path the key sits at. `None` means the default, `id`.
        key_at: Option<String>,
        /// Write the resolved bytes to stdout verbatim, with no decode.
        raw: bool,
        /// Emit the pointer as byte-stable JSON instead of a pointer line.
        json: bool,
    },
}

/// Subcommands of `mcp` (CLOUD-1260).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum McpCommand {
    /// Dispatch one declared method and print a pointer plus the reduction.
    Call {
        /// The server to dispatch to, as a `[[mcp.source]]` names it.
        server: String,
        /// The method to call.
        method: String,
        /// The method's arguments as a JSON object. `None` is an empty object.
        params: Option<String>,
    },
}

/// Subcommands of `target` (CLOUD-1030).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetCommand {
    /// Reclaim superseded artifacts, then judge the floor the next build needs.
    Prune {
        /// The global `-y --yes`, which this verb requires: it never prompts.
        yes: bool,
        /// Report what would be removed and remove nothing.
        dry_run: bool,
        /// The build directory to prune, instead of the configured one.
        root: Option<String>,
    },
}

/// Subcommands of `commit`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitCommand {
    /// Judge commit subjects against the `[commit]` convention.
    Check {
        /// Emit the findings as byte-stable JSON instead of pointer lines.
        json: bool,
        /// The commit range to judge. Mutually exclusive with `message`;
        /// exactly one must be given, and neither is a usage error rather than
        /// a vacuous pass over nothing.
        range: Option<String>,
        /// The pending commit-message file to judge.
        message: Option<String>,
    },
}

/// Subcommands of `state`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateCommand {
    /// Bind this checkout to its findings store.
    Adopt {
        /// The store id to bind. `None` binds whatever resolution found, which
        /// is the ordinary case; naming one is how an operator overrides a
        /// resolution that refused to decide for itself.
        store: Option<String>,
    },
    /// Record this ref's findings into the store.
    Record,
    /// Upgrade the store's record version. The only upgrade path.
    Migrate,
    /// List stored findings.
    List {
        /// Emit the listing as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `record` (CLOUD-1265).
///
/// Two leaves rather than one verb with a mode flag: the two stores share the
/// record's line shape and nothing else, and a flag deciding which KEY gets
/// composed would be a second authority over one byte format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordCommand {
    /// Record a declared tool row's verdict.
    Tool {
        /// The `[[rule.tools]]` id whose verdict is being recorded.
        ///
        /// The only argument, and that is the anti-staleness property: the tool,
        /// its pin and the input path all come from the committed config, so no
        /// caller can hand over a digest at all.
        id: String,
    },
    /// Record the forge's check verdicts for one commit.
    Forge {
        /// The ref or sha the verdict was taken against.
        reference: String,
    },
}

/// Subcommands of `receipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptCommand {
    /// Record that the named check concluded pass against the current HEAD.
    Record {
        /// The check whose conclusion is being recorded.
        check: String,
    },
    /// Judge the named check's recorded receipt against HEAD and origin/main.
    Status {
        /// The check whose receipt is judged.
        check: String,
        /// Which git fact the receipt is judged against (CLOUD-741).
        ///
        /// Defaults to [`ReceiptKey::Head`], the only keying this verb had
        /// before, so every caller predating the flag is unchanged.
        key: ReceiptKey,
        /// Emit the verdict as byte-stable JSON instead of a pointer line.
        json: bool,
    },
}

/// Subcommands of `config`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigCommand {
    /// Print the effective configuration.
    Show {
        /// Emit the full `{value, source}` document instead of pointer lines.
        json: bool,
    },
    /// Report policy smells in `batten.toml`.
    Lint {
        /// Emit the smells as byte-stable JSON instead of pointer lines.
        json: bool,
        /// Where to read the host ruleset payload from, when the caller asked
        /// for the drift comparison. `-` is stdin.
        host_rules: Option<String>,
    },
    /// Report schema keys removed since a published release with no window.
    Deprecations {
        /// Emit the findings as byte-stable JSON instead of pointer lines.
        json: bool,
        /// The git ref whose published schema is the baseline.
        against: String,
    },
    /// Print the content hash of the governing config surface.
    Epoch {
        /// Emit the epoch and the surface it covers as byte-stable JSON.
        json: bool,
        /// Ignore the cached value and rehash the tracked files' bytes.
        no_cache: bool,
    },
}

/// Diagnoses of `doctor` (house style §2: the verb nests focused
/// sub-diagnostics).
///
/// [`DoctorCommand::Diagnose`] is what a bare `batten doctor` selects, so adding
/// a sub-verb did not turn the parent into a noun that refuses to answer — house
/// style §8 promises bare `doctor` validates the resolved config, and
/// `surface::is_noun` is what keeps that promise structural.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DoctorCommand {
    /// The bare report: config, git repository, command programs.
    Diagnose {
        /// Emit the diagnosis as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Whether batten is wired on every hook surface of every harness.
    Hooks {
        /// Emit the per-harness diagnosis as byte-stable JSON.
        json: bool,
    },
}

/// Subcommands of `generate`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenerateCommand {
    /// Emit the completion script for one shell.
    Completions {
        /// The shell whose completion script to emit.
        shell: clap_complete::Shell,
    },
    /// Emit the JSON Schema for a config surface.
    Schema {
        /// Which surface to describe: a config surface (the committed authority
        /// or the raise-only override layer), or a policy-input document.
        surface: SchemaSurface,
    },
    // APPENDED, never inserted (CLOUD-69). A variant's implicit discriminant is
    // its position, so adding one above `Schema` renumbers it — which
    // `cargo-semver-checks` reports as `enum_no_repr_variant_discriminant_changed`,
    // a break this change has no reason to be. `#[non_exhaustive]` permits the
    // addition; it does not permit the renumbering.
    /// Emit the roff man page for one command.
    Man {
        /// The root-relative path of the command to document (`config show`),
        /// or `None` for the root page. Optional rather than required because
        /// the root page is the one a caller asks for by default.
        command: Option<String>,
    },
    /// Emit the whole surface as one markdown reference.
    Markdown,
    /// Emit one harness's hook registrations (CLOUD-62).
    Hooks {
        /// The harness whose wiring to emit.
        harness: crate::hook::Harness,
    },
}

/// The formats `batten spec` can emit.
///
/// One, deliberately. House-style §2 and §11 advertised `kdl|json`; KDL was
/// never implemented and never had a consumer, and JSON is the agent-facing
/// contract (§6). The document is corrected rather than the binary, and
/// `spec::tests::the_spec_emits_exactly_the_committed_formats` pins the list so
/// a second format is added to both at once (CLOUD-244).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SpecFormat {
    /// Byte-stable JSON — the agent-facing contract (§6).
    Json,
}

/// The surfaces a schema can describe (CLOUD-239, CLOUD-879).
///
/// Two config surfaces, two derivations. `batten.toml` is the committed
/// authority; `batten.local.toml` is the raise-only override, which accepts a
/// strict subset and refuses the rest. One schema describing both is what let a
/// validator green-light keys the loader drops.
///
/// **And two POLICY-INPUT surfaces, which is why this is no longer
/// `ConfigSurface`.** CLOUD-879 derives the documents a Rego module reads as
/// `input` — one per scope — from the fact model, and neither is a config
/// surface: naming them under the old type would have made the type's name a lie
/// about half its variants. Renaming is the smaller lie to fix, and the two
/// existing flag values are untouched.
///
/// A flag on the existing emitter rather than a second sub-verb: CLOUD-244
/// records that §2 and the landed surface already disagree about where schema
/// emission lives, and adding a verb would deepen that before it is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SchemaSurface {
    /// The committed authority: `batten.toml`.
    Authority,
    /// The raise-only override layer: `batten.local.toml`.
    Override,
    /// The `input` document a `scope = "tree"` Rego module reads.
    PolicyInput,
    /// The `input` document a `scope = "mediated_call"` Rego module reads.
    PolicyCall,
}

/// Parse the process arguments into a [`Cli`].
///
/// # Errors
///
/// Returns `clap`'s error for a malformed invocation, and for `--help` and
/// `--version`, which `clap` reports through the same channel. The binary
/// distinguishes them with [`clap::Error::use_stderr`] so a help request is not
/// charged as a usage error.
pub fn try_parse() -> Result<Cli, clap::Error> {
    Ok(from_matches(&surface::command().try_get_matches()?))
}

/// Give the parsed matches their typed shape.
///
/// Total by construction: an unrecognised subcommand yields `None`, which `run`
/// treats as the bare invocation. `clap` has already refused anything the
/// surface does not declare, so `None` here is unreachable for a declared verb —
/// and [`tests::every_leaf_verb_dispatches`] is what keeps that true as the
/// surface grows.
fn from_matches(matches: &ArgMatches) -> Cli {
    Cli {
        // `--strictness` is global, so `clap` records it on the root regardless
        // of where on the command line it appeared.
        strictness: matches.get_one::<Strictness>("strictness").copied(),
        fail_on_warning: matches.get_flag("fail_on_warning"),
        config_from: matches.get_one::<String>("config_from").cloned(),
        config_in: matches.get_one::<String>("config_in").cloned(),
        command: matches.subcommand().and_then(command_of),
    }
}

/// Read a boolean flag that `clap` records on the subcommand it was passed to.
fn flag(matches: &ArgMatches, id: &str) -> bool {
    matches.try_get_one::<bool>(id).ok().flatten() == Some(&true)
}

/// A value the caller actually typed, as distinct from one `clap` filled in.
///
/// [`FlagDecl::defaulted_enum`] hands `clap` a default, so `get_one` answers on
/// every call and cannot tell "the caller chose `human`" from "nobody chose".
/// Where a committed `[exec]` table sets the default, that difference is the
/// whole §8 precedence chain — a flag nobody typed must not outrank the file.
///
/// [`FlagDecl::defaulted_enum`]: crate::surface::FlagDecl
fn supplied<'a, T>(matches: &'a ArgMatches, id: &str) -> Option<&'a T>
where
    T: Clone + Send + Sync + 'static,
{
    match matches.value_source(id) {
        Some(clap::parser::ValueSource::CommandLine) => matches.get_one::<T>(id),
        _ => None,
    }
}

/// The nesting nouns, each mapping its own sub-verb.
///
/// Split out of [`command_of`] one function per noun rather than inlined as
/// closures: the flat match grew past `clippy::too_many_lines` when `provision`
/// landed, and a noun's sub-verbs are the natural seam. Each stays total —
/// an unrecognised sub-verb is `None`, which `clap` has already made
/// unreachable for a declared surface.
fn config_of(matches: &ArgMatches) -> Option<ConfigCommand> {
    match matches.subcommand()? {
        ("show", matches) => Some(ConfigCommand::Show {
            json: flag(matches, "json"),
        }),
        ("lint", matches) => Some(ConfigCommand::Lint {
            json: flag(matches, "json"),
            host_rules: matches
                .get_one::<String>("host_rules")
                .map(ToOwned::to_owned),
        }),
        ("deprecations", matches) => Some(ConfigCommand::Deprecations {
            json: flag(matches, "json"),
            // `--against` is declared `required`, so clap has already refused an
            // invocation without it; the default is unreachable and exists only
            // because `get_one` is total.
            against: matches
                .get_one::<String>("against")
                .cloned()
                .unwrap_or_default(),
        }),
        ("epoch", matches) => Some(ConfigCommand::Epoch {
            json: flag(matches, "json"),
            no_cache: flag(matches, "no_cache"),
        }),
        _ => None,
    }
}

/// The positional is optional and belongs to one kind, so it is read inside the
/// arm — the shape [`state_of`] uses for `state adopt`.
fn lint_of(matches: &ArgMatches) -> Option<LintCommand> {
    match matches.subcommand()? {
        ("brief", matches) => Some(LintCommand::Brief {
            path: matches.get_one::<String>("brief").cloned(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn policy_of(matches: &ArgMatches) -> Option<PolicyCommand> {
    match matches.subcommand()? {
        ("budget", matches) => Some(PolicyCommand::Budget {
            json: flag(matches, "json"),
        }),
        ("test", matches) => Some(PolicyCommand::Test {
            json: flag(matches, "json"),
        }),
        ("tools", matches) => Some(PolicyCommand::Tools {
            json: flag(matches, "json"),
        }),
        ("explain", matches) => Some(PolicyCommand::Explain {
            // `clap` already refuses the absent case — the declaration is
            // `required` — so this default is unreachable rather than a silent
            // empty query.
            token: matches
                .get_one::<String>("token")
                .cloned()
                .unwrap_or_default(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn attribution_of(matches: &ArgMatches) -> Option<AttributionCommand> {
    match matches.subcommand()? {
        ("check", matches) => Some(AttributionCommand::Check {
            json: flag(matches, "json"),
            range: matches.get_one::<String>("range").cloned(),
            message: matches.get_one::<String>("message").cloned(),
            harness: matches.get_one::<Harness>("harness").copied(),
        }),
        ("identity", _) => Some(AttributionCommand::Identity),
        _ => None,
    }
}

fn commit_of(matches: &ArgMatches) -> Option<CommitCommand> {
    match matches.subcommand()? {
        ("check", matches) => Some(CommitCommand::Check {
            json: flag(matches, "json"),
            range: matches.get_one::<String>("range").cloned(),
            message: matches.get_one::<String>("message").cloned(),
        }),
        _ => None,
    }
}

fn semver_of(matches: &ArgMatches) -> Option<SemverCommand> {
    match matches.subcommand()? {
        ("check", matches) => Some(SemverCommand::Check {
            baseline: matches.get_one::<String>("baseline").cloned(),
            release_type: matches.get_one::<String>("release_type").cloned(),
            package: matches.get_one::<String>("package").cloned(),
        }),
        _ => None,
    }
}

fn mutate_of(matches: &ArgMatches) -> Option<MutateCommand> {
    match matches.subcommand()? {
        ("sweep", _) => Some(MutateCommand::Sweep),
        ("census", _) => Some(MutateCommand::Census),
        _ => None,
    }
}

fn perf_of(matches: &ArgMatches) -> Option<PerfCommand> {
    match matches.subcommand()? {
        ("pair", matches) => Some(PerfCommand::Pair {
            null: flag(matches, "null"),
        }),
        _ => None,
    }
}

fn provision_of(matches: &ArgMatches) -> Option<ProvisionCommand> {
    match matches.subcommand()? {
        ("status", matches) => Some(ProvisionCommand::Status {
            json: flag(matches, "json"),
        }),
        ("apply", matches) => Some(ProvisionCommand::Apply {
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn wiring_of(matches: &ArgMatches) -> Option<WiringCommand> {
    match matches.subcommand()? {
        ("reclaim", matches) => Some(WiringCommand::Reclaim {
            yes: flag(matches, "yes"),
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn defects_of(matches: &ArgMatches) -> Option<DefectsCommand> {
    match matches.subcommand()? {
        ("query", matches) => Some(DefectsCommand::Query {
            json: flag(matches, "json"),
            class: matches.get_one::<String>("class").cloned(),
            id: matches.get_one::<String>("id").cloned(),
            ungated: flag(matches, "ungated"),
        }),
        ("add", matches) => Some(DefectsCommand::Add {
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn design_of(matches: &ArgMatches) -> Option<DesignCommand> {
    match matches.subcommand()? {
        ("audit", matches) => Some(DesignCommand::Audit {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

/// **Infallible, unlike every other `*_of`**, and that is the whole difference
/// between a verb that nests and a noun. The others return `None` for an absent
/// subcommand because clap has already refused it (`subcommand_required`); here
/// an absent one is the ordinary bare invocation and selects the report.
fn doctor_of(matches: &ArgMatches) -> DoctorCommand {
    match matches.subcommand() {
        Some(("hooks", matches)) => DoctorCommand::Hooks {
            json: flag(matches, "json"),
        },
        // The bare verb reads `-J` from its OWN matches, which is where clap put
        // it when no subcommand was given.
        _ => DoctorCommand::Diagnose {
            json: flag(matches, "json"),
        },
    }
}

fn worktree_of(matches: &ArgMatches) -> Option<WorktreeCommand> {
    match matches.subcommand()? {
        ("status", matches) => Some(WorktreeCommand::Status {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

/// `lease`'s nine arms (CLOUD-1274).
///
/// Every positional here is `required` on its surface row, so `clap` refuses an
/// absent one before this runs and the defaults below are unreachable rather than
/// a silent empty binding — which for `authorises` would be the difference between
/// a verb that says it cannot answer and one that answers about the empty branch.
fn lease_of(matches: &ArgMatches) -> Option<LeaseCommand> {
    let branch_of = |matches: &ArgMatches| {
        matches
            .get_one::<String>("branch")
            .cloned()
            .unwrap_or_default()
    };
    match matches.subcommand()? {
        ("authorises", matches) => Some(LeaseCommand::Authorises {
            branch: branch_of(matches),
        }),
        ("status", matches) => Some(LeaseCommand::Status {
            json: matches.get_flag("json"),
        }),
        ("peek", matches) => Some(LeaseCommand::Peek {
            field: matches
                .get_one::<String>("field")
                .cloned()
                .unwrap_or_default(),
        }),
        ("held", _) => Some(LeaseCommand::Held),
        ("acquire", matches) => Some(LeaseCommand::Acquire {
            branch: branch_of(matches),
        }),
        ("renew", _) => Some(LeaseCommand::Renew),
        ("hold", _) => Some(LeaseCommand::Hold),
        ("release", _) => Some(LeaseCommand::Release),
        ("reserve", matches) => Some(LeaseCommand::Reserve {
            branch: branch_of(matches),
        }),
        _ => None,
    }
}

/// `override request`'s three binding fields (CLOUD-1051).
///
/// The answers are NOT here: they arrive on stdin, for the reason `surface.rs`
/// records on the row — argv reaches every mediated hook's input document, and
/// the answers are the one payload this surface deliberately carries.
///
/// `clap` already refuses each absent case (all three are `required`), so the
/// defaults below are unreachable rather than a silent empty binding.
fn override_of(matches: &ArgMatches) -> Option<OverrideCommand> {
    match matches.subcommand()? {
        ("request", matches) => Some(OverrideCommand::Request {
            rule: matches
                .get_one::<String>("rule")
                .cloned()
                .unwrap_or_default(),
            verdict: matches
                .get_one::<String>("verdict")
                .cloned()
                .unwrap_or_default(),
            subject: matches
                .get_one::<String>("subject")
                .cloned()
                .unwrap_or_default(),
        }),
        ("spend", matches) => Some(OverrideCommand::Spend {
            admission: matches
                .get_one::<String>("admission")
                .cloned()
                .unwrap_or_default(),
            rule: matches
                .get_one::<String>("rule")
                .cloned()
                .unwrap_or_default(),
            verdict: matches
                .get_one::<String>("verdict")
                .cloned()
                .unwrap_or_default(),
            subject: matches
                .get_one::<String>("subject")
                .cloned()
                .unwrap_or_default(),
        }),
        _ => None,
    }
}

fn generate_of(matches: &ArgMatches) -> Option<GenerateCommand> {
    match matches.subcommand()? {
        ("completions", matches) => matches
            .get_one::<clap_complete::Shell>("shell")
            .map(|shell| GenerateCommand::Completions { shell: *shell }),
        ("man", matches) => Some(GenerateCommand::Man {
            command: matches.get_one::<String>("command").cloned(),
        }),
        ("markdown", _) => Some(GenerateCommand::Markdown),
        ("hooks", matches) => matches
            .get_one::<crate::hook::Harness>("harness")
            .map(|harness| GenerateCommand::Hooks { harness: *harness }),
        ("schema", matches) => Some(GenerateCommand::Schema {
            surface: matches
                .get_one::<SchemaSurface>("surface")
                .copied()
                .unwrap_or(SchemaSurface::Authority),
        }),
        _ => None,
    }
}

fn receipt_of(matches: &ArgMatches) -> Option<ReceiptCommand> {
    let (name, matches) = matches.subcommand()?;
    let check = matches.get_one::<String>("check")?.clone();
    match name {
        "record" => Some(ReceiptCommand::Record { check }),
        // `unwrap_or_default` rather than `?`: the flag is declared with a
        // default, so an absent value is the ordinary case, not a parse failure.
        "status" => Some(ReceiptCommand::Status {
            check,
            key: matches
                .get_one::<ReceiptKey>("key")
                .copied()
                .unwrap_or_default(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

/// The positionals and selectors differ per sub-verb, so each is read inside its
/// own arm — the shape [`state_of`] uses.
fn ready_of(matches: &ArgMatches) -> Option<ReadyCommand> {
    match matches.subcommand()? {
        ("lint", matches) => Some(ReadyCommand::Lint {
            issue: matches.get_one::<String>("issue").cloned(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn claim_of(matches: &ArgMatches) -> Option<ClaimCommand> {
    match matches.subcommand()? {
        ("check", matches) => Some(ClaimCommand::Check {
            takeover: flag(matches, "takeover"),
            bypass_sequence: flag(matches, "bypass_sequence"),
            // `--adopt-from` implies `--adopt`: naming the orphan is a stronger
            // statement than asking for one, and requiring both would make the
            // longer spelling silently do nothing.
            adopt: flag(matches, "adopt") || matches.get_one::<String>("adopt_from").is_some(),
            adopt_from: matches.get_one::<String>("adopt_from").cloned(),
            issue: matches.get_one::<String>("issue").cloned(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn checks_of(matches: &ArgMatches) -> Option<ChecksCommand> {
    match matches.subcommand()? {
        ("green", matches) => Some(ChecksCommand::Green {
            // Both are required by the surface, so clap has already refused an
            // argv without them; `None` here is unreachable and maps to a
            // refusal rather than to an empty set, which would make every check
            // unrequired — the false green this verb exists to stop.
            required: matches.get_one::<String>("required").cloned()?,
            absent_ok: matches.get_one::<String>("absent_ok").cloned(),
            answered: matches.get_one::<String>("answered").cloned()?,
            fanin: matches.get_one::<String>("fanin").cloned(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn pr_of(matches: &ArgMatches) -> Option<PrCommand> {
    match matches.subcommand()? {
        ("watch", matches) => Some(PrCommand::Watch {
            // Required by the surface, so clap has already refused an argv
            // without them; `None` is unreachable and maps to a refusal rather
            // than to a default, which for the roster would make every check
            // unrequired and for the sha would poll a commit nobody named.
            sha: matches.get_one::<String>("sha").cloned()?,
            repo: matches.get_one::<String>("repo").cloned(),
            interval: matches.get_one::<String>("interval").cloned(),
            progress: matches.get_one::<String>("progress").cloned(),
            progress_id: matches.get_one::<String>("progress_id").cloned(),
            required: matches.get_one::<String>("required").cloned()?,
            absent_ok: matches.get_one::<String>("absent_ok").cloned(),
            answered: matches.get_one::<String>("answered").cloned()?,
            fanin: matches.get_one::<String>("fanin").cloned(),
        }),
        _ => None,
    }
}

fn capture_of(matches: &ArgMatches) -> Option<CaptureCommand> {
    match matches.subcommand()? {
        ("show", matches) => Some(CaptureCommand::Show {
            // Required by the surface, so clap has already refused an argv
            // without it; `None` here would be unreachable and is mapped to a
            // refusal rather than a default handle nobody named.
            handle: matches.get_one::<String>("handle").cloned()?,
            lines: matches.get_one::<String>("lines").cloned(),
            grep: matches.get_one::<String>("grep").cloned(),
            raw: flag(matches, "raw"),
            bytes: matches.get_one::<String>("bytes").cloned(),
            json: flag(matches, "json"),
        }),
        ("find", matches) => Some(CaptureCommand::Find {
            // Both are required by the surface, so clap has refused an argv
            // without them before this runs; `None` is unreachable and maps to a
            // refusal rather than a selector nobody named.
            key: matches.get_one::<String>("key").cloned()?,
            tools: matches
                .get_many::<String>("tool")
                .map(|values| values.cloned().collect())?,
            key_at: matches.get_one::<String>("key_at").cloned(),
            raw: flag(matches, "raw"),
            json: flag(matches, "json"),
        }),
        ("list", matches) => Some(CaptureCommand::List {
            stream: matches.get_one::<String>("stream").cloned(),
            calls: flag(matches, "calls"),
            json: flag(matches, "json"),
        }),
        ("prune", matches) => Some(CaptureCommand::Prune {
            yes: flag(matches, "yes"),
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

/// The `mcp` sub-verb a parse resolved to.
fn mcp_of(matches: &ArgMatches) -> Option<McpCommand> {
    match matches.subcommand()? {
        ("call", matches) => Some(McpCommand::Call {
            // Both are required by the surface, so clap has refused an argv
            // without them before this runs; `None` is unreachable and maps to a
            // refusal rather than a call nobody named.
            server: matches.get_one::<String>("server").cloned()?,
            method: matches.get_one::<String>("method").cloned()?,
            params: matches.get_one::<String>("params").cloned(),
        }),
        _ => None,
    }
}

/// The `target` sub-verb a parse resolved to.
fn target_of(matches: &ArgMatches) -> Option<TargetCommand> {
    match matches.subcommand()? {
        ("prune", matches) => Some(TargetCommand::Prune {
            yes: flag(matches, "yes"),
            dry_run: flag(matches, "dry_run"),
            root: matches.get_one::<String>("root").cloned(),
        }),
        _ => None,
    }
}

/// Unlike [`receipt_of`], the positional is optional and belongs to one
/// sub-verb, so it is read inside the arm rather than ahead of the match.
fn state_of(matches: &ArgMatches) -> Option<StateCommand> {
    match matches.subcommand()? {
        ("adopt", matches) => Some(StateCommand::Adopt {
            store: matches.get_one::<String>("store").cloned(),
        }),
        ("record", _) => Some(StateCommand::Record),
        ("migrate", _) => Some(StateCommand::Migrate),
        ("list", matches) => Some(StateCommand::List {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

/// Each sub-verb owns its own positional under a different name, so both are read
/// inside their arms — [`state_of`]'s shape rather than [`receipt_of`]'s.
fn record_of(matches: &ArgMatches) -> Option<RecordCommand> {
    match matches.subcommand()? {
        ("tool", matches) => Some(RecordCommand::Tool {
            id: matches.get_one::<String>("id")?.clone(),
        }),
        ("forge", matches) => Some(RecordCommand::Forge {
            reference: matches.get_one::<String>("ref")?.clone(),
        }),
        _ => None,
    }
}

fn command_of((name, matches): (&str, &ArgMatches)) -> Option<Command> {
    match name {
        "check" => Some(Command::Check(CheckFlags {
            json: flag(matches, "json"),
            rule: matches.get_one::<String>("rule").cloned(),
            staged: flag(matches, "staged"),
            since: matches.get_one::<String>("since").cloned(),
        })),
        "enforce" => Some(Command::Enforce {
            json: flag(matches, "json"),
        }),
        "config" => config_of(matches).map(|command| Command::Config { command }),
        "lint" => lint_of(matches).map(|command| Command::Lint { command }),
        "spec" => matches
            .get_one::<SpecFormat>("format")
            .map(|format| Command::Spec { format: *format }),
        // The one parent that still ACTS bare (house style §2 nests
        // sub-diagnostics under `doctor`, §8 promises what bare `doctor` does),
        // so an absent subcommand is the diagnosis rather than a usage error.
        // `surface::is_noun` is the other half of that decision.
        "doctor" => Some(Command::Doctor {
            command: doctor_of(matches),
        }),
        "init" => Some(Command::Init {
            dry_run: flag(matches, "dry_run"),
        }),
        "baseline" => Some(Command::Baseline {
            prune: flag(matches, "prune"),
            dry_run: flag(matches, "dry_run"),
        }),
        "policy" => policy_of(matches).map(|command| Command::Policy { command }),
        "provision" => provision_of(matches).map(|command| Command::Provision { command }),
        "defects" => defects_of(matches).map(|command| Command::Defects { command }),
        "design" => design_of(matches).map(|command| Command::Design { command }),
        "attribution" => attribution_of(matches).map(|command| Command::Attribution { command }),
        "commit" => commit_of(matches).map(|command| Command::Commit { command }),
        "semver" => semver_of(matches).map(|command| Command::Semver { command }),
        "perf" => perf_of(matches).map(|command| Command::Perf { command }),
        "mutate" => mutate_of(matches).map(|command| Command::Mutate { command }),
        "ready" => ready_of(matches).map(|command| Command::Ready { command }),
        "claim" => claim_of(matches).map(|command| Command::Claim { command }),
        "checks" => checks_of(matches).map(|command| Command::Checks { command }),
        "pr" => pr_of(matches).map(|command| Command::Pr { command }),
        "worktree" => worktree_of(matches).map(|command| Command::Worktree { command }),
        "lease" => lease_of(matches).map(|command| Command::Lease { command }),
        "override" => override_of(matches).map(|command| Command::Override { command }),
        "wiring" => wiring_of(matches).map(|command| Command::Wiring { command }),
        "generate" => generate_of(matches).map(|command| Command::Generate { command }),
        // `get_many`, not `get_one`: the tail is an `Append` action, so every
        // token after `--` is a separate value and the child's argv is the whole
        // list. An empty list is unreachable — clap enforces `num_args(1..)` —
        // and is mapped to `None` rather than an empty exec.
        "exec" => {
            let command: Vec<String> = matches
                .get_many::<String>("command")
                .map(|values| values.cloned().collect())
                .unwrap_or_default();
            if command.is_empty() {
                None
            } else {
                Some(Command::Exec(ExecRequest {
                    command,
                    capture_only: flag(matches, "capture_only"),
                    tee: matches.get_flag("tee"),
                    // Read through the VALUE SOURCE, not the value: clap fills
                    // `defaulted_enum`'s default in, so `get_one` always answers
                    // and a config-set default would be overwritten on every
                    // call by a flag nobody typed.
                    format: supplied(matches, "format").copied(),
                    style: supplied(matches, "style").copied(),
                    jobs: matches.get_one::<String>("jobs").cloned(),
                    continue_on_error: matches.get_flag("continue_on_error"),
                }))
            }
        }
        "capture" => capture_of(matches).map(|command| Command::Capture { command }),
        "mcp" => mcp_of(matches).map(|command| Command::Mcp { command }),
        "target" => target_of(matches).map(|command| Command::Target { command }),
        "hook" => matches
            .get_one::<Harness>("harness")
            .map(|harness| Command::Hook { harness: *harness }),
        "payload" => match matches.subcommand()? {
            ("field", inner) => Some(Command::HookField {
                harness: *inner.get_one::<Harness>("harness")?,
                field: *inner.get_one::<HookFieldName>("name")?,
            }),
            _ => None,
        },
        "receipt" => receipt_of(matches).map(|command| Command::Receipt { command }),
        "state" => state_of(matches).map(|command| Command::State { command }),
        "record" => record_of(matches).map(|command| Command::Record { command }),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::surface::{SURFACE, ValueDecl};

    /// Parse an argv the way the binary does, through the built tree.
    fn parse(argv: &[&str]) -> Cli {
        let matches = surface::command()
            .try_get_matches_from(std::iter::once("batten").chain(argv.iter().copied()))
            .expect("argv parses");
        from_matches(&matches)
    }

    /// The smallest argv that satisfies a declared command's required arguments.
    ///
    /// Values come from the declaration itself — a `ValueEnum` flag is given its
    /// first accepted token — so a new required flag needs no edit here.
    fn argv_for(path: &str) -> Vec<String> {
        let mut argv: Vec<String> = path.split(' ').map(ToOwned::to_owned).collect();
        let decl = SURFACE
            .iter()
            .find(|decl| decl.path == path)
            .expect("path is declared");
        for flag in decl.flags {
            let value = match flag.value {
                // A counted flag consumes nothing, so it never contributes a
                // token to the minimal argv — and it is never required.
                ValueDecl::Count => continue,
                // A trailing variadic is required and positional, so the minimal
                // argv needs `--` plus one token for the child.
                ValueDecl::Trailing => {
                    argv.push("--".to_owned());
                    argv.push("true".to_owned());
                    continue;
                }
                ValueDecl::Bool => {
                    if flag.required {
                        argv.push(format!("--{}", flag.long.expect("a bool flag has a long")));
                    }
                    continue;
                }
                ValueDecl::Str | ValueDecl::StrMany => "placeholder".to_owned(),
                ValueDecl::Enum { parser, default } => match default {
                    Some(_) => continue,
                    None => parser()
                        .possible_values()
                        .and_then(|mut values| values.next())
                        .map(|value| value.get_name().to_owned())
                        .expect("a ValueEnum flag offers at least one token"),
                },
            };
            if !flag.required {
                continue;
            }
            if let Some(long) = flag.long {
                argv.push(format!("--{long}"));
            }
            argv.push(value);
        }
        argv
    }

    #[test]
    fn every_leaf_verb_dispatches() {
        // The other half of the derivation gate. `surface.rs` pins that every
        // declared path reaches the parser; this pins that every *leaf* path
        // reaches a typed arm. Without it a new row parses fine and then falls
        // through `command_of` to `None`, which `run` reads as a bare
        // invocation — a declared verb silently exiting 0 having done nothing.
        for decl in SURFACE {
            if SURFACE
                .iter()
                .any(|other| other.path.starts_with(&format!("{} ", decl.path)))
            {
                continue; // a noun; its leaves carry the dispatch
            }
            let argv = argv_for(decl.path);
            let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
            assert!(
                parse(&borrowed).command.is_some(),
                "{} parses but does not dispatch",
                decl.path
            );
        }
    }

    #[test]
    fn a_bare_invocation_chooses_no_command() {
        let matches = surface::command()
            .try_get_matches_from(["batten"].iter())
            .expect_err("a bare invocation is clap's help path");
        assert!(matches.use_stderr(), "the listing is a usage error, exit 1");
    }

    #[test]
    fn the_global_flag_is_read_after_a_subcommand() {
        // `--strictness` is global, so it must resolve identically whether it
        // precedes or follows the verb — otherwise a flag would apply to one
        // verb and not another, which §8's precedence chain forbids.
        let before = parse(&["--strictness", "strict", "check"]);
        let after = parse(&["check", "--strictness", "strict"]);
        assert_eq!(before, after);
        assert_eq!(before.strictness, Some(Strictness::Strict));
    }

    #[test]
    fn spec_format_defaults_to_json() {
        assert_eq!(
            parse(&["spec"]).command,
            Some(Command::Spec {
                format: SpecFormat::Json
            })
        );
    }

    #[test]
    fn a_positional_reaches_its_typed_arm() {
        assert_eq!(
            parse(&["receipt", "status", "verify"]).command,
            Some(Command::Receipt {
                command: ReceiptCommand::Status {
                    check: "verify".to_owned(),
                    key: ReceiptKey::Head,
                    json: false,
                }
            })
        );
    }

    /// The default is the contract, not a convenience (CLOUD-741). `--key` was
    /// added to an existing verb, so every caller predating it supplies nothing
    /// — and any default but `head` would silently re-point them at a receipt
    /// they never asked about. Asserted rather than left to `ReceiptKey`'s
    /// `#[default]`, which a future variant could move without failing anything
    /// here.
    #[test]
    fn an_absent_key_is_the_sha_keying_every_earlier_caller_meant() {
        let Some(Command::Receipt {
            command: ReceiptCommand::Status { key, .. },
        }) = parse(&["receipt", "status", "verify"]).command
        else {
            panic!("receipt status parses to its own arm")
        };
        assert_eq!(key, ReceiptKey::Head);
    }

    #[test]
    fn the_branch_keying_is_selectable() {
        assert_eq!(
            parse(&["receipt", "status", "claim", "--key", "branch"]).command,
            Some(Command::Receipt {
                command: ReceiptCommand::Status {
                    check: "claim".to_owned(),
                    key: ReceiptKey::Branch,
                    json: false,
                }
            })
        );
    }

    /// The spelling the config uses, byte for byte. A `[[rule]]`'s `key` column
    /// deserializes `head`/`branch`, and `ReceiptKey` carries an explicit
    /// `clap(rename_all)` so the two cannot drift — a variant accepted here under
    /// a spelling the config rejects would mean the surfaces disagree about what
    /// was asked for.
    ///
    /// Asserted at the clap layer rather than through `parse`, which panics on a
    /// rejected argv by design: the refusal *is* the behaviour under test.
    #[test]
    fn the_cli_and_the_config_name_the_keying_alike() {
        for token in ["Branch", "BRANCH", "branches"] {
            assert!(
                surface::command()
                    .try_get_matches_from(["batten", "receipt", "status", "claim", "--key", token])
                    .is_err(),
                "`--key {token}` is not a spelling the config would accept"
            );
        }
        for token in ["head", "branch"] {
            assert!(
                surface::command()
                    .try_get_matches_from(["batten", "receipt", "status", "claim", "--key", token])
                    .is_ok(),
                "`--key {token}` is the config's own spelling"
            );
        }
    }
}
