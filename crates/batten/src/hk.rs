//! The adopted gate runner's surface contract, as a committed projection
//! (CLOUD-947).
//!
//! The adopted runner decides what a repository's gate actually runs — which
//! steps, in what order, under which profiles, in which parallel group. Nothing
//! compared that live plan against a reviewed one, so a step added, removed,
//! renamed, reordered or regrouped changed what the gate enforces with no diff
//! for anyone to read. This module makes the plan an artifact and drift a diff.
//!
//! # Two halves, two effects, one canonicaliser
//!
//! The generator is a [`crate::effect::Effect::Write`] verb: it runs the pinned
//! binary and rewrites the committed projection. The gate is
//! [`crate::effect::Effect::Read`]: it runs the same binary and compares. Both
//! reach the artifact through [`project`], which is the ONLY path from the
//! runner's JSON to a [`Surface`] — so the two sides cannot disagree about what
//! the plan is, which is the disagreement class `.claude/rules/rust.md` records
//! for every second authority in this crate.
//!
//! # Volatile fields are excluded BY CONSTRUCTION, never filtered at compare
//!
//! The runner stamps every plan with the instant it was generated, and reports a
//! matched-file count and a human `detail` string per step. All three move
//! between two runs over one unchanged tree — measured, `generatedAt` is the
//! only difference between two back-to-back plans here.
//!
//! [`project`] never reads them, so they cannot enter the artifact and cannot
//! make it flap. A filter at compare time would be the same behaviour spelled
//! where it can rot: the artifact would carry a value nothing compares, and the
//! next author would have to know not to trust it. A field that never enters
//! cannot be trusted by mistake.
//!
//! # An unknown step is drift, never consent
//!
//! A step name in the live plan that the committed projection does not carry is
//! [`Drift::StepAdded`] — a finding a reader acts on. It is deliberately NOT an
//! append the gate performs on its own: appearing in the plan is what the
//! runner's own config caused, and a gate that absorbed it would report green
//! over a step nobody reviewed. Regenerating the artifact is a decision a human
//! makes by running the write verb, and the diff is what they are deciding on.
//!
//! # Three answers, and the third is most of this module
//!
//! [`crate::facts::Look::CouldNotLook`] is every way the plan did not yield a
//! trustworthy answer: the binary is absent or unspawnable, its version cannot
//! be read, its output is not JSON this build can read, the exit status and the
//! parse disagree, or **the plan is empty**. That last one is this repository's
//! anti-vacuity rule: a generator that found nothing looks exactly like a gate
//! that passed, and the two must not be one exit code.
//!
//! [`crate::facts::Look::IsNot`] is never produced. A plan that ran and carries
//! steps is a fact; there is no arm in which the question is answerable and the
//! answer is "no plan".
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! A [`Drift`] carries the hook, the run type and a step NAME. It never carries
//! a step's command, its glob, its matched files, or a dump of either plan. The
//! report is what a reader follows to the two files; it is not a copy of them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::facts::Look;

/// The program this module adopts.
///
/// A bare program rather than a path: it resolves through the project's own
/// pin, which is what makes the plan the PINNED binary's rather than whichever
/// build happens to be ambient. A version mismatch between the committed
/// artifact and the running binary is could-not-look for that reason — see
/// [`Contract::agrees_with`].
pub const TOOL: &str = "hk";

/// Where the committed projection lives, relative to the repository root.
///
/// Batten's own derived artifact, in the same class as the config file name:
/// the engine writes it and the engine reads it, so the location is the
/// engine's to state. It names no consumer (non-negotiable rule 1).
pub const ARTIFACT: &str = "contracts/hk.json";

/// The projection's own version, bumped when the SHAPE changes.
///
/// Separate from the tool's version because the two move for different reasons:
/// a tool bump changes what is projected, a shape bump changes how. A reader of
/// an artifact carrying an unknown shape version is told so rather than being
/// handed fields it cannot interpret.
pub const SHAPE: u32 = 1;

/// The id a reader greps for when this gate refuses.
///
/// A declared constant rather than a `[[rule]]` row's id, because the subject is
/// the engine's own artifact: a consumer cannot name the class, so a consumer
/// row could only restate it. Same shape as `init`'s own refusal id.
pub const DRIFT_RULE: &str = "hk-contract-drift";

/// The three surfaces the contract covers, and the argv each is asked through.
///
/// **The third is not spelled like the other two, and that is the runner's, not
/// a typo.** `check` and `fix` are subcommands; a git hook is reached through
/// `run <hook>`. Asking for `pre-commit` directly exits non-zero as an unknown
/// subcommand, which would make the whole contract could-not-look for a reason
/// that has nothing to do with the tree.
///
/// The hook and the run type are recorded separately because they genuinely
/// differ: the pre-commit hook reports a `check` run type, so a projection
/// keyed on either alone would collapse two surfaces into one.
pub const SURFACES: &[&[&str]] = &[&["check"], &["fix"], &["run", "pre-commit"]];

/// The flags that ask for a plan rather than a run.
///
/// `--all` rather than a path list: a plan taken over changed paths is a
/// property of the working tree, and the contract is a property of the runner's
/// config. Recording the former would produce an artifact that drifts whenever
/// anyone edits anything.
pub const PLAN_FLAGS: &[&str] = &["--all", "--plan", "--json"];

/// One step, reduced to what the contract is about.
///
/// Four fields and no fifth: the name is the step's identity, the status is
/// whether the gate would run it, and the order and group are the topology. A
/// step's command, glob and matched files are what it DOES; this artifact is
/// about what the gate IS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Step {
    /// The step's declared name — its identity across plans.
    pub name: String,
    /// Whether the runner would execute it, as the runner words it.
    pub status: String,
    /// Position in the plan, 0-indexed as the runner reports it.
    pub order_index: u64,
    /// The parallel group it belongs to.
    pub parallel_group_id: String,
}

/// One parallel group: an id and the steps in it, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Group {
    /// The group's id, as the steps reference it.
    pub id: String,
    /// The steps in it, in the runner's own order.
    pub step_ids: Vec<String>,
}

/// One surface's plan, projected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Surface {
    /// The hook this plan is for.
    pub hook: String,
    /// The run type it resolves to, which is not always the hook's name.
    pub run_type: String,
    /// The profiles enabled for it, in the runner's order.
    pub profiles: Vec<String>,
    /// The parallel-group topology.
    pub groups: Vec<Group>,
    /// Every step, in plan order.
    pub steps: Vec<Step>,
}

/// The committed contract: a shape version, the tool version it was taken at,
/// and one entry per surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Contract {
    /// [`SHAPE`] at the time of writing.
    pub version: u32,
    /// The tool's self-reported version, so a plan taken at another pin stops
    /// answering rather than answering wrongly.
    pub tool_version: String,
    /// One per [`SURFACES`] entry, in that order.
    pub surfaces: Vec<Surface>,
}

/// What moved, as a pointer.
///
/// Every variant names the surface and, where there is one, a step by NAME.
/// None carries a command, a glob, a file list or a count of matched files —
/// the report points at the two artifacts, it does not quote them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Drift {
    /// The committed projection covers a surface the live plan does not, or the
    /// other way round.
    SurfaceSet {
        /// The hook that is on one side only.
        hook: String,
        /// Which side carries it.
        committed: bool,
    },
    /// The run type a hook resolves to moved.
    RunType {
        /// The hook whose run type moved.
        hook: String,
    },
    /// The enabled profile set moved.
    Profiles {
        /// The hook whose profiles moved.
        hook: String,
    },
    /// A step is in the live plan and not the committed projection.
    StepAdded {
        /// The hook it appears under.
        hook: String,
        /// The step's name.
        step: String,
    },
    /// A step is in the committed projection and not the live plan.
    StepRemoved {
        /// The hook it was declared under.
        hook: String,
        /// The step's name.
        step: String,
    },
    /// A step's position in the plan moved.
    StepMoved {
        /// The hook it runs under.
        hook: String,
        /// The step's name.
        step: String,
    },
    /// A step's parallel group moved.
    StepRegrouped {
        /// The hook it runs under.
        hook: String,
        /// The step's name.
        step: String,
    },
    /// A step's status moved — the gate would run it where it did not, or the
    /// reverse.
    StepStatus {
        /// The hook it runs under.
        hook: String,
        /// The step's name.
        step: String,
    },
    /// The group topology moved in a way no step's own membership records.
    Groups {
        /// The hook whose topology moved.
        hook: String,
    },
}

impl Drift {
    /// The stable one-line rendering, byte-identical for one input (§6).
    ///
    /// `<class> <hook>` or `<class> <hook> <step>`, in that order, so a reader
    /// and a `sort` see the same thing. The class token is a fixed literal
    /// rather than prose about the difference.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Drift::SurfaceSet { hook, committed } => {
                let side = if *committed { "committed" } else { "live" };
                format!("surface-only-{side} {hook}")
            }
            Drift::RunType { hook } => format!("run-type {hook}"),
            Drift::Profiles { hook } => format!("profiles {hook}"),
            Drift::StepAdded { hook, step } => format!("step-added {hook} {step}"),
            Drift::StepRemoved { hook, step } => format!("step-removed {hook} {step}"),
            Drift::StepMoved { hook, step } => format!("step-moved {hook} {step}"),
            Drift::StepRegrouped { hook, step } => format!("step-regrouped {hook} {step}"),
            Drift::StepStatus { hook, step } => format!("step-status {hook} {step}"),
            Drift::Groups { hook } => format!("groups {hook}"),
        }
    }
}

/// Project one plan document into the surface the contract records.
///
/// Separated from the spawn for `symbols.rs`'s `sites_in` reason and
/// `.claude/rules/rust.md`'s: the failing condition is a DOCUMENT SHAPE rather
/// than a repository state, so the decision is extracted and tested directly
/// rather than through a fixture that has to make a real runner misbehave.
///
/// [`Look::CouldNotLook`] where a required key is absent or the wrong type, and
/// where the step list is EMPTY — a plan with no steps is a runner that answered
/// nothing, and projecting it would commit an artifact against which every later
/// comparison passes.
#[must_use]
pub fn project(value: &serde_json::Value) -> Look<Surface> {
    let (Some(hook), Some(run_type)) = (
        value.get("hook").and_then(serde_json::Value::as_str),
        value.get("runType").and_then(serde_json::Value::as_str),
    ) else {
        return Look::CouldNotLook;
    };
    let Some(profiles) = string_list(value.get("profiles")) else {
        return Look::CouldNotLook;
    };
    let Some(groups) = groups_in(value.get("groups")) else {
        return Look::CouldNotLook;
    };
    let Some(steps) = steps_in(value.get("steps")) else {
        return Look::CouldNotLook;
    };
    // ANTI-VACUITY, and it is the whole reason this returns three answers rather
    // than a `Result` with an empty happy path. An empty plan is not a plan.
    if steps.is_empty() {
        return Look::CouldNotLook;
    }
    Look::Is(Surface {
        hook: hook.to_owned(),
        run_type: run_type.to_owned(),
        profiles,
        groups,
        steps,
    })
}

/// A JSON array of strings, or `None` for anything else.
///
/// An absent key is `None` rather than an empty list: the two are different
/// answers, and a projection that read a missing `profiles` as "no profiles"
/// would commit a claim it never read.
fn string_list(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

fn groups_in(value: Option<&serde_json::Value>) -> Option<Vec<Group>> {
    value?
        .as_array()?
        .iter()
        .map(|entry| {
            Some(Group {
                id: entry.get("id")?.as_str()?.to_owned(),
                step_ids: string_list(entry.get("stepIds"))?,
            })
        })
        .collect()
}

fn steps_in(value: Option<&serde_json::Value>) -> Option<Vec<Step>> {
    value?
        .as_array()?
        .iter()
        .map(|entry| {
            Some(Step {
                name: entry.get("name")?.as_str()?.to_owned(),
                status: entry.get("status")?.as_str()?.to_owned(),
                order_index: entry.get("orderIndex")?.as_u64()?,
                parallel_group_id: entry.get("parallelGroupId")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

impl Contract {
    /// Render the artifact's bytes: two-space JSON in declaration order, with a
    /// trailing newline.
    ///
    /// Declaration order rather than sorted keys, because the struct IS the
    /// order — a reader of the type knows what the file looks like. Byte-stable
    /// by construction: nothing here reads a clock, a path or an environment.
    ///
    /// # Errors
    ///
    /// [`crate::UsageError`] only if the value cannot be serialised, which the
    /// types above make unreachable; it is propagated rather than unwrapped
    /// because library code here does not panic.
    pub fn render(&self) -> anyhow::Result<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|error| crate::UsageError::raise(error.to_string()))?;
        text.push('\n');
        Ok(text)
    }

    /// Read a committed artifact's bytes.
    ///
    /// # Errors
    ///
    /// [`crate::UsageError`] when the bytes are not this shape — a malformed
    /// committed artifact is an invalid input the caller can fix, which is `1`
    /// on the one exit table, not the `3` a failure to LOOK earns.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        serde_json::from_str(text).map_err(|error| crate::UsageError::raise(error.to_string()))
    }

    /// Whether a live contract was taken at the same tool version.
    ///
    /// A differently-pinned binary does not answer this artifact's question at
    /// all: its plan may differ because the runner changed rather than because
    /// the config did, and reporting that as drift would send a reader looking
    /// for a config change nobody made. Same reason a tool-verdict record is
    /// keyed by the pinned version.
    #[must_use]
    pub fn agrees_with(&self, other: &Self) -> bool {
        self.version == other.version && self.tool_version == other.tool_version
    }
}

/// Every way the committed projection and the live one differ.
///
/// Ordered by surface and then by the order a reader would walk the plan, so
/// the output is byte-stable for one pair of inputs.
///
/// A step present on both sides is compared field by field, and each difference
/// is its own finding: a step that moved AND changed group says both, because
/// they are two different changes to what the gate does.
#[must_use]
pub fn compare(committed: &Contract, current: &Contract) -> Vec<Drift> {
    let mut drifts = Vec::new();
    for surface in &committed.surfaces {
        let Some(live) = current
            .surfaces
            .iter()
            .find(|other| other.hook == surface.hook)
        else {
            drifts.push(Drift::SurfaceSet {
                hook: surface.hook.clone(),
                committed: true,
            });
            continue;
        };
        drifts.extend(compare_surface(surface, live));
    }
    for surface in &current.surfaces {
        if !committed
            .surfaces
            .iter()
            .any(|other| other.hook == surface.hook)
        {
            drifts.push(Drift::SurfaceSet {
                hook: surface.hook.clone(),
                committed: false,
            });
        }
    }
    drifts
}

fn compare_surface(committed: &Surface, current: &Surface) -> Vec<Drift> {
    let mut drifts = Vec::new();
    let hook = committed.hook.clone();
    if committed.run_type != current.run_type {
        drifts.push(Drift::RunType { hook: hook.clone() });
    }
    if committed.profiles != current.profiles {
        drifts.push(Drift::Profiles { hook: hook.clone() });
    }
    for step in &committed.steps {
        let Some(live) = current.steps.iter().find(|other| other.name == step.name) else {
            drifts.push(Drift::StepRemoved {
                hook: hook.clone(),
                step: step.name.clone(),
            });
            continue;
        };
        if step.order_index != live.order_index {
            drifts.push(Drift::StepMoved {
                hook: hook.clone(),
                step: step.name.clone(),
            });
        }
        if step.parallel_group_id != live.parallel_group_id {
            drifts.push(Drift::StepRegrouped {
                hook: hook.clone(),
                step: step.name.clone(),
            });
        }
        if step.status != live.status {
            drifts.push(Drift::StepStatus {
                hook: hook.clone(),
                step: step.name.clone(),
            });
        }
    }
    for step in &current.steps {
        if !committed.steps.iter().any(|other| other.name == step.name) {
            drifts.push(Drift::StepAdded {
                hook: hook.clone(),
                step: step.name.clone(),
            });
        }
    }
    // The group topology, after the per-step findings, and ONLY where no step
    // already accounts for it. A step added, removed, moved or regrouped changes
    // the membership lists by construction, so reporting both would name one
    // change twice and send a reader looking for a second one. What survives is
    // the difference no step's own fields record: a group that appeared or
    // vanished, or one whose members were reordered with every step unmoved. A
    // moved run type or profile set does NOT suppress it — those say nothing
    // about membership, and reading them as an account of it would drop a real
    // topology change.
    let step_level = drifts.iter().any(|drift| {
        matches!(
            drift,
            Drift::StepAdded { .. }
                | Drift::StepRemoved { .. }
                | Drift::StepMoved { .. }
                | Drift::StepRegrouped { .. }
        )
    });
    if committed.groups != current.groups && !step_level {
        drifts.push(Drift::Groups { hook });
    }
    drifts
}

/// The tool's self-reported version, as provenance.
///
/// Its own spawn rather than a field read out of the plan, because the plan
/// carries no version at all — and inferring one from its shape would be
/// exactly the unrecorded dependency [`Contract::agrees_with`] guards against.
fn version(root: &Path) -> Look<String> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the contract IS the pinned binary's own answer, so acquiring it runs that binary — the classification, not an accident of it (CLOUD-947)"
    )]
    let spawned = std::process::Command::new(TOOL)
        .arg("--version")
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let Ok(output) = spawned else {
        return Look::CouldNotLook;
    };
    if !output.status.success() {
        return Look::CouldNotLook;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(text)
    }
}

/// Ask the pinned binary for one surface's plan.
fn plan(root: &Path, surface: &[&str]) -> Look<serde_json::Value> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the contract IS the pinned binary's own answer, so acquiring it runs that binary — the classification, not an accident of it (CLOUD-947)"
    )]
    let spawned = std::process::Command::new(TOOL)
        .args(surface)
        .args(PLAN_FLAGS)
        .current_dir(root)
        // Both streams captured, NEITHER forwarded: the runner narrates its file
        // walk on stderr, and echoing a child's stream would put output Batten
        // never shaped onto Batten's own.
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let Ok(output) = spawned else {
        return Look::CouldNotLook;
    };
    // THE CROSS-CHECK, in `secrets.rs`'s direction: a plan parsed out of a failed
    // run describes a resolution that did not finish. Clean is never inferred
    // from a stream that failed to parse, and a contract is never taken from a
    // run that failed.
    if !output.status.success() {
        return Look::CouldNotLook;
    }
    match serde_json::from_slice(&output.stdout) {
        Ok(value) => Look::Is(value),
        Err(_) => Look::CouldNotLook,
    }
}

/// Resolve the whole contract by running the pinned binary once per surface.
///
/// [`Look::CouldNotLook`] if ANY surface fails, rather than a partial contract:
/// a projection missing a surface is one against which that surface's drift can
/// never be found, and it would commit clean.
#[must_use]
pub fn resolve(root: &Path) -> Look<Contract> {
    let Look::Is(tool_version) = version(root) else {
        return Look::CouldNotLook;
    };
    let mut surfaces = Vec::with_capacity(SURFACES.len());
    for argv in SURFACES {
        let Look::Is(value) = plan(root, argv) else {
            return Look::CouldNotLook;
        };
        let Look::Is(surface) = project(&value) else {
            return Look::CouldNotLook;
        };
        surfaces.push(surface);
    }
    Look::Is(Contract {
        version: SHAPE,
        tool_version,
        surfaces,
    })
}

// ─── CLOUD-949: the effective plan as a pre-admission fact ───────────────────
//
// The section above answers what the plan IS, against a reviewed projection. This
// one answers what the plan is FOR A PROPOSED INVOCATION, and hands the answer to
// a policy module as a typed fact.
//
// **The two do not share a type, and the difference is the whole row.** The
// contract deliberately drops `fileCount` and the reason `kind`, because a
// reviewed artifact that carried them would flap on every edit. The fact
// deliberately carries them, because whether a step was excluded by a PROFILE or
// by a glob MISS is exactly what a policy-required step's absence turns on. One
// type with both readings would be a projection that is wrong for one of its two
// consumers.
//
// **Nothing here parses the runner's own config.** hk owns its selector; this
// asks the binary and stores what it answered. Re-deriving the selection would
// make the engine a second authority on which files a step runs over — the
// disagreement class `.claude/rules/rust.md` records, in the one place where the
// other authority is a program somebody else maintains.

/// One declared plan query: which surface to ask about, and what a module needs
/// to decide over the answer.
///
/// **`required` and `prohibited_profiles` are CONSUMER facts** and live in the
/// row rather than in this crate (non-negotiable rule 1). They are projected
/// alongside the acquired plan so the module compares two halves of one document
/// rather than reaching for a second source — the same shape a `[[rule.tools]]`
/// row's `id` gives its module.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PlanQuery {
    /// The key this plan is projected under in `input.tree.plan`.
    pub id: String,
    /// Which surface to ask about: a hook name the contract also covers.
    pub hook: String,
    /// The steps this consumer requires the plan to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Profiles whose presence makes the plan unusable for this consumer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibited_profiles: Vec<String>,
}

impl PlanQuery {
    /// Whether this row names a surface the contract does not cover.
    ///
    /// Refused at LOAD rather than answered at adjudication: a row asking about a
    /// hook nothing can plan would resolve to could-not-look forever, which reads
    /// as an unreachable gate rather than as a misconfigured one.
    #[must_use]
    pub fn unknown_hook(&self) -> bool {
        !SURFACES.iter().any(|argv| hook_of(argv) == self.hook)
    }
}

/// The hook a declared argv asks about — its last word.
///
/// `check` and `fix` name themselves; `run pre-commit` names the hook second,
/// which is the runner's grammar rather than a special case here.
#[must_use]
fn hook_of(argv: &[&str]) -> String {
    argv.last()
        .map_or_else(String::new, |word| (*word).to_owned())
}

/// One step as the FACT carries it — the projection's four fields plus the two
/// a decision about a required step turns on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PlannedStep {
    /// The step's declared name.
    pub name: String,
    /// Whether the runner would execute it.
    pub status: String,
    /// Why, as the runner's own KIND token — never its prose. A step excluded
    /// for a missing profile and one excluded by a glob miss are different
    /// findings, and the kind is the only field that separates them.
    pub reason_kind: Option<String>,
    /// Position in the plan.
    pub order_index: u64,
    /// The parallel group it belongs to.
    pub parallel_group_id: String,
    /// How many files it matched. A COUNT, never the paths (rule 4).
    pub file_count: u64,
}

/// What one acquisition resolved, bound to the invocation and the tree it was
/// taken over.
///
/// **`input_fingerprint` is why this is not keyed on HEAD.** Dirty and index
/// state change the selection without moving HEAD, so a fact bound to HEAD alone
/// answers about a tree that is not the one being judged — the discriminator
/// CLOUD-949 names, and the one an implementation keyed on HEAD passes every
/// other case and fails.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Planned {
    /// The hook asked about.
    pub hook: String,
    /// The run type it resolved to.
    pub run_type: String,
    /// The profiles enabled for it.
    pub profiles: Vec<String>,
    /// The exact argv, so a reader can tell which question was asked.
    pub invocation: Vec<String>,
    /// The tool's self-reported version.
    pub tool_version: String,
    /// The digest of the committed surface contract this was taken beside, or
    /// `None` where no contract is committed.
    pub contract_digest: Option<String>,
    /// A digest over HEAD and every path that differs from it, content and all.
    pub input_fingerprint: String,
    /// The steps this consumer requires, carried from the row.
    pub required: Vec<String>,
    /// The profiles this consumer refuses, carried from the row.
    pub prohibited_profiles: Vec<String>,
    /// Every step, in plan order.
    pub steps: Vec<PlannedStep>,
}

/// Project one plan document into the fact, keeping the two fields the contract
/// drops.
///
/// [`Look::CouldNotLook`] on an EMPTY plan, for [`project`]'s reason: a plan that
/// selected nothing looks exactly like a gate that passed.
#[must_use]
pub fn planned_steps(value: &serde_json::Value) -> Look<Vec<PlannedStep>> {
    let Some(entries) = value.get("steps").and_then(serde_json::Value::as_array) else {
        return Look::CouldNotLook;
    };
    let mut steps = Vec::with_capacity(entries.len());
    for entry in entries {
        let (Some(name), Some(status)) = (
            entry.get("name").and_then(serde_json::Value::as_str),
            entry.get("status").and_then(serde_json::Value::as_str),
        ) else {
            return Look::CouldNotLook;
        };
        let (Some(order_index), Some(parallel_group_id)) = (
            entry.get("orderIndex").and_then(serde_json::Value::as_u64),
            entry
                .get("parallelGroupId")
                .and_then(serde_json::Value::as_str),
        ) else {
            return Look::CouldNotLook;
        };
        steps.push(PlannedStep {
            name: name.to_owned(),
            status: status.to_owned(),
            // The FIRST reason's kind. A step carries reasons in the runner's own
            // order and the first is the one it acted on; the rest are context a
            // pointer does not need.
            reason_kind: entry
                .get("reasons")
                .and_then(serde_json::Value::as_array)
                .and_then(|reasons| reasons.first())
                .and_then(|reason| reason.get("kind"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            order_index,
            parallel_group_id: parallel_group_id.to_owned(),
            // Absent is zero here rather than could-not-look: the runner omits
            // the key for a step it never filtered, which is a real count.
            file_count: entry
                .get("fileCount")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        });
    }
    if steps.is_empty() {
        return Look::CouldNotLook;
    }
    Look::Is(steps)
}

/// The digest binding a plan to the tree it was taken over.
///
/// HEAD, then every differing path with the digest of its CURRENT bytes — so a
/// file edited while already dirty moves the fingerprint, which a changed-path
/// SET alone would not. A path that will not read contributes a `-`, because a
/// file the engine could not open is a state the fingerprint must distinguish
/// rather than skip.
///
/// Pointer-only in the value it produces: the digest carries no path and no byte
/// to any reader (rule 4). The paths are inputs to a hash, never output.
#[must_use]
pub fn fingerprint(root: &Path) -> Look<String> {
    let Ok(head) = crate::git::head_fact(root) else {
        return Look::CouldNotLook;
    };
    let Ok(status) = crate::git::status_fact(root) else {
        return Look::CouldNotLook;
    };
    let mut material = String::new();
    material.push_str(head.commit.as_deref().unwrap_or("-"));
    material.push('\n');
    let mut changed = status.changed.clone();
    changed.sort();
    for path in &changed {
        material.push_str(path);
        material.push(' ');
        match std::fs::read(root.join(path)) {
            Ok(bytes) => material.push_str(&crate::tools::digest(&bytes)),
            Err(_) => material.push('-'),
        }
        material.push('\n');
    }
    Look::Is(crate::tools::digest(material.as_bytes()))
}

/// Acquire the effective plan for one declared query.
///
/// Fresh, every time, from the exact invocation the query names — never read back
/// from a store. A stored plan would need every binding field compared before it
/// could be trusted, and a comparison a caller can forget is the staleness class
/// `[[rule.tools]]`'s keying exists to remove. Here the fact simply cannot be
/// stale, because it is taken now.
#[must_use]
pub fn acquire(root: &Path, query: &PlanQuery) -> Look<Planned> {
    let Some(argv) = SURFACES.iter().find(|argv| hook_of(argv) == query.hook) else {
        return Look::CouldNotLook;
    };
    let Look::Is(tool_version) = version(root) else {
        return Look::CouldNotLook;
    };
    let Look::Is(fingerprint) = fingerprint(root) else {
        return Look::CouldNotLook;
    };
    let Look::Is(value) = plan(root, argv) else {
        return Look::CouldNotLook;
    };
    let (Some(hook), Some(run_type)) = (
        value.get("hook").and_then(serde_json::Value::as_str),
        value.get("runType").and_then(serde_json::Value::as_str),
    ) else {
        return Look::CouldNotLook;
    };
    let Some(profiles) = string_list(value.get("profiles")) else {
        return Look::CouldNotLook;
    };
    let Look::Is(steps) = planned_steps(&value) else {
        return Look::CouldNotLook;
    };
    Look::Is(Planned {
        hook: hook.to_owned(),
        run_type: run_type.to_owned(),
        profiles,
        invocation: argv
            .iter()
            .chain(PLAN_FLAGS.iter())
            .map(|word| (*word).to_owned())
            .collect(),
        tool_version,
        // ABSENT rather than could-not-look: a repository that has not committed
        // a contract can still ask what its gate would run, and refusing the whole
        // fact would make this row depend on the other one being adopted first.
        contract_digest: std::fs::read(root.join(ARTIFACT))
            .ok()
            .map(|bytes| crate::tools::digest(&bytes)),
        input_fingerprint: fingerprint,
        required: query.required.clone(),
        prohibited_profiles: query.prohibited_profiles.clone(),
        steps,
    })
}

// ─── CLOUD-948: the runtime-observation receipt ──────────────────────────────
//
// The two sections above answer what the gate INTENDS to run and what it WOULD
// run for a proposed invocation. Neither says anything about what a given agent
// session actually resolved: a different runner on PATH, a stale contract, or a
// plan that will not resolve at all are invisible to a contract that describes
// intent.
//
// **This is a separate authority and is deliberately not merged into the
// verification receipt.** One receipt answers one question. A merged one would
// answer neither, because a mismatch could then mean the contract is wrong OR
// the runtime is, and nothing in the record would separate them.
//
// **IT DECIDES NOTHING.** No gate reads it, no call is denied by it, and it
// proves no hook is installed and no run occurred. It is evidence, and the whole
// of its contribution is that a later reader can tell an environment fault from
// a repository one.

/// The receipt predicate, versioned in its own name.
///
/// A version in the TYPE rather than a field, so a reader that does not know
/// this shape fails to match rather than misreading a field it does not have.
pub const OBSERVATION_PREDICATE: &str = "hk-session-capability/v1";

/// Where observations live, under the git directory.
///
/// Beside the other per-checkout stores and for their reason: it is state that
/// must never be committed, and the git directory is the one place this crate
/// already treats that way.
const OBSERVATION_DIR: &str = "batten-hk-observations";

/// What a session resolved, as three states.
///
/// **The third is the could-not-look channel rather than a failure.** Reading
/// `Unknown` as `Drifted` would turn a verdict about the ENVIRONMENT into one
/// about the REPOSITORY, which is exactly the confusion a three-valued read
/// exists to prevent — and it is the discriminator an implementation that
/// collapsed them would fail while passing every other case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Capability {
    /// The runtime version and the normalised surfaces both match the contract.
    Available,
    /// Readable runtime data disagrees with the contract.
    Drifted,
    /// The runner, the contract, or plan resolution was unavailable or
    /// malformed. An answer, not an error.
    Unknown,
}

impl Capability {
    /// The stable token this state is recorded and rendered under (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Available => "available",
            Capability::Drifted => "drifted",
            Capability::Unknown => "unknown",
        }
    }
}

/// One recorded observation.
///
/// **Every field is a digest, a version or a token.** No raw session identifier,
/// no command, no path, no result byte and no environment value is stored — the
/// exclusion list is this receipt's substance rather than a caveat, because an
/// observation is written on a host whose session id may itself be sensitive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Observation {
    /// [`OBSERVATION_PREDICATE`], written into the record so a reader matches on
    /// the shape rather than on where the file was found.
    pub predicate_type: String,
    /// The session identifier, HASHED. The raw token never reaches the disk.
    pub session: String,
    /// The digest of the committed surface contract this was taken against.
    pub contract_digest: String,
    /// The config epoch at the time of observation.
    pub config_epoch: String,
    /// The runner's self-reported version, or `None` where it could not be read.
    pub tool_version: Option<String>,
    /// What was resolved.
    pub state: Capability,
}

/// The hashed form of a host's session token.
///
/// `contract.rs`'s spelling, and deliberately the same one: a second hashing of
/// one concept would be a second authority over what "this session" means.
#[must_use]
fn hashed(session: &str) -> String {
    crate::tools::digest(session.as_bytes())
}

/// Where one session's observation of one contract digest lives.
///
/// **Both components are in the name, which is what makes the once-per rule
/// structural.** A second event in the same session against the same digest
/// finds the file and does not probe; a changed digest is a different name, so
/// it is a new observation rather than an overwrite. CLOUD-725's failure — a
/// cached receipt answering a question it never observed — is unreachable when
/// the cache key carries everything the answer depends on.
#[must_use]
pub fn observation_path(git_dir: &Path, session: &str, contract_digest: &str) -> PathBuf {
    git_dir
        .join(OBSERVATION_DIR)
        .join(format!("{}.{contract_digest}.json", hashed(session)))
}

/// Read back one observation, if this session already made it.
#[must_use]
pub fn observed(git_dir: &Path, session: &str, contract_digest: &str) -> Look<Observation> {
    let path = observation_path(git_dir, session, contract_digest);
    let Ok(text) = std::fs::read_to_string(path) else {
        return Look::CouldNotLook;
    };
    match serde_json::from_str::<Observation>(&text) {
        // A record whose predicate type is not this one does not answer this
        // question, so it is could-not-look rather than a value to reinterpret.
        Ok(record) if record.predicate_type == OBSERVATION_PREDICATE => Look::Is(record),
        _ => Look::CouldNotLook,
    }
}

/// Compare a live contract against the committed one, as a state.
///
/// Pure, and separated from the probe for `.claude/rules/rust.md`'s reason: the
/// failing condition is a PAIR OF CONTRACTS, which a test can create, rather
/// than a runner a test would have to make misbehave.
#[must_use]
pub fn capability(committed: Option<&Contract>, current: Option<&Contract>) -> Capability {
    let (Some(committed), Some(current)) = (committed, current) else {
        // Either side absent is could-not-look: with nothing to compare, a
        // `drifted` here would be a claim about the repository made on the
        // strength of an environment fault.
        return Capability::Unknown;
    };
    if committed.tool_version != current.tool_version {
        return Capability::Drifted;
    }
    if compare(committed, current).is_empty() {
        Capability::Available
    } else {
        Capability::Drifted
    }
}

/// Observe what this session resolved, recording it once per contract digest.
///
/// [`Look::IsNot`] where the host supplies no session identifier: a receipt
/// about "this session" cannot be written by a host that cannot name one, and
/// writing it under a shared key would let two sessions answer for each other.
/// That is a real answer rather than a failure, which is why it is `IsNot` and
/// not `CouldNotLook`.
///
/// **The existing record short-circuits the probe**, which is the once-per rule
/// working rather than being remembered: a second event in the same session
/// against the same digest returns the record and runs no program.
///
/// # Errors
///
/// Propagates an I/O failure creating the directory or writing the record.
pub fn observe(
    root: &Path,
    git_dir: &Path,
    session: Option<&str>,
) -> anyhow::Result<Look<Observation>> {
    let Some(session) = session.filter(|token| !token.is_empty()) else {
        return Ok(Look::IsNot);
    };
    // The digest is the cache key, so it is read BEFORE anything is probed. An
    // absent contract still has a key -- a stable literal -- because a session
    // that observed "there is no contract" has observed something.
    let contract_digest = std::fs::read(root.join(ARTIFACT)).map_or_else(
        |_| "no-contract".to_owned(),
        |bytes| crate::tools::digest(&bytes),
    );
    if let Look::Is(already) = observed(git_dir, session, &contract_digest) {
        return Ok(Look::Is(already));
    }

    let committed = std::fs::read_to_string(root.join(ARTIFACT))
        .ok()
        .and_then(|text| Contract::parse(&text).ok());
    let current = match resolve(root) {
        Look::Is(contract) => Some(contract),
        _ => None,
    };
    let record = Observation {
        predicate_type: OBSERVATION_PREDICATE.to_owned(),
        session: hashed(session),
        contract_digest: contract_digest.clone(),
        config_epoch: crate::epoch::compute(root, None).unwrap_or_else(|_| "unknown".to_owned()),
        tool_version: current
            .as_ref()
            .map(|contract| contract.tool_version.clone()),
        state: capability(committed.as_ref(), current.as_ref()),
    };
    let path = observation_path(git_dir, session, &contract_digest);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = serde_json::to_string_pretty(&record)
        .map_err(|error| crate::UsageError::raise(error.to_string()))?;
    text.push('\n');
    std::fs::write(&path, text)?;
    Ok(Look::Is(record))
}

// ─── CLOUD-950: what a run can be evidenced to have done ─────────────────────
//
// The runner provides machine-readable PLANNING and no trustworthy structured
// per-step LIFECYCLE stream. That absence was undocumented, which is the
// dangerous state: nothing stopped a step-level execution receipt inferred from
// a process exit, and such a receipt reads exactly like one backed by evidence.
//
// **The absence is committed data now, not a comment**, and it is the one
// authority on what the pinned runner can evidence. `attest` reads it, so a
// step attestation under `ExecutionEvents::None` is unwritable rather than
// merely discouraged — which is the half that makes this a gate.
//
// THE THREE ROUTES THAT WOULD MANUFACTURE THE EVIDENCE ARE EXCLUDED BY NAME:
// scraping stderr, wrapping steps individually, and inferring execution from a
// process exit. Each produces a claim about a step nobody watched, and each is
// exactly what the fixture exists to say does not exist.

/// Where the committed capability fixture lives.
pub const EVIDENCE: &str = "contracts/hk-evidence.json";

/// What the pinned runner emits about a run's steps.
///
/// **A two-valued enum rather than a boolean**, because the fixture must be able
/// to express the state that does NOT hold today: a format that could only say
/// "none" would be a comment with a schema, and nothing would prove it able to
/// carry the answer that arrives when the runner gains a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ExecutionEvents {
    /// No structured per-step lifecycle stream exists.
    None,
    /// A structured stream exists and binds to a plan and a run.
    Structured,
}

/// The committed capability fixture: what can be evidenced, per surface of the
/// question, at one pinned version.
///
/// **Seven flags rather than a summary, and the lint is expected rather than
/// obeyed.** CLOUD-950 names each row separately because they move separately: a
/// runner could gain step terminals without run identity, or skipped-step
/// announcements without a final exit, and a fixture that carried only the
/// summary could not say which. Collapsing them into an enum would delete the
/// granularity the row exists to record, and `execution_events` is already the
/// summary a gate reads.
#[expect(
    clippy::struct_excessive_bools,
    reason = "stays: each flag is a separately-moving capability CLOUD-950 names, and `execution_events` is the summary a gate reads"
)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Evidence {
    /// The fixture's own shape version.
    pub version: u32,
    /// The runner version this was established against. A capability is a
    /// property of a BUILD, so a fixture that named no version would answer for
    /// a runner nobody measured.
    pub tool_version: String,
    /// Whether the plan is machine-readable. It is, which is why the other rows
    /// are worth stating: the contrast is the finding.
    pub plan_schema: bool,
    /// Whether a run carries an identity events could bind to.
    pub run_identity: bool,
    /// Whether events bind to the digest of the plan they ran.
    pub plan_digest_binding: bool,
    /// Whether a step's start is observable.
    pub step_start_events: bool,
    /// Whether a step's terminal outcome is observable.
    pub step_terminal_events: bool,
    /// Whether a skipped step is announced.
    pub skipped_step_events: bool,
    /// Whether the run's final exit is observable as an event.
    pub final_exit_events: bool,
    /// The summary the gate reads.
    pub execution_events: ExecutionEvents,
}

/// Why a step attestation is not available.
///
/// Pointer-shaped: a kind token and, where there is one, a step NAME. Never a
/// byte of the runner's output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Incomplete {
    /// The declared capability says no such stream exists.
    ///
    /// **The arm that is true today**, and the one an implementation that only
    /// validated event streams would never reach — it would accept a perfect
    /// fixture stream and emit a receipt for a step nobody watched.
    Uncapable,
    /// The events name a plan that is not the one asked about.
    PlanMismatch,
    /// The events name a run that is not the one asked about.
    RunMismatch,
    /// A planned step has no terminal event.
    Missing {
        /// The step's name.
        step: String,
    },
    /// A step carries more than one terminal event.
    Duplicated {
        /// The step's name.
        step: String,
    },
    /// A step terminated before it started.
    OutOfOrder {
        /// The step's name.
        step: String,
    },
    /// The stream has no final exit, so it may have been cut off.
    Truncated,
    /// A step ran that the plan does not contain.
    Unplanned {
        /// The step's name.
        step: String,
    },
}

impl Incomplete {
    /// The stable token this kind is reported under (§6).
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Incomplete::Uncapable => "uncapable".to_owned(),
            Incomplete::PlanMismatch => "plan-mismatch".to_owned(),
            Incomplete::RunMismatch => "run-mismatch".to_owned(),
            Incomplete::Missing { step } => format!("missing {step}"),
            Incomplete::Duplicated { step } => format!("duplicated {step}"),
            Incomplete::OutOfOrder { step } => format!("out-of-order {step}"),
            Incomplete::Truncated => "truncated".to_owned(),
            Incomplete::Unplanned { step } => format!("unplanned {step}"),
        }
    }
}

/// One lifecycle event, as a capable runner would emit it.
///
/// Defined even though nothing emits it, which is the point: the fixture format
/// is proven able to express the capable shape rather than only the state that
/// happens to hold today.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Event {
    /// The run this belongs to.
    pub run: String,
    /// The digest of the plan it ran.
    pub plan_digest: String,
    /// The step, or `None` for the run's own final exit.
    pub step: Option<String>,
    /// `start`, `terminal`, `skipped`, or `exit`.
    pub kind: String,
    /// Position in the stream, as the emitter ordered it.
    pub sequence: u64,
}

/// Whether a step-level attestation may be made for one run.
///
/// **`Err` is the only answer available today, and that is the row's whole
/// claim.** The capability fixture is read FIRST, so no stream — however
/// well-formed — can produce a pass while the pinned runner declares no
/// lifecycle events. An implementation that reached for the stream first would
/// accept a fabricated one, which is exactly the misleading receipt this exists
/// to prevent.
///
/// # Errors
///
/// Never returns `Err` in the `Result` sense; the refusals are values. This
/// returns `Result<(), Incomplete>` because a caller must handle the refusal to
/// obtain the pass, which is what keeps the pass from being the default.
pub fn attest(
    evidence: &Evidence,
    plan: &Planned,
    run: &str,
    plan_digest: &str,
    events: &[Event],
) -> Result<(), Incomplete> {
    // THE CAPABILITY GATE, FIRST AND UNCONDITIONALLY.
    if evidence.execution_events == ExecutionEvents::None {
        return Err(Incomplete::Uncapable);
    }
    if events.iter().any(|event| event.run != run) {
        return Err(Incomplete::RunMismatch);
    }
    if events.iter().any(|event| event.plan_digest != plan_digest) {
        return Err(Incomplete::PlanMismatch);
    }
    if !events.iter().any(|event| event.kind == "exit") {
        return Err(Incomplete::Truncated);
    }
    for event in events {
        let Some(step) = event.step.as_deref() else {
            continue;
        };
        if !plan.steps.iter().any(|planned| planned.name == step) {
            return Err(Incomplete::Unplanned {
                step: step.to_owned(),
            });
        }
    }
    for planned in &plan.steps {
        if planned.status != "included" {
            continue;
        }
        let terminals: Vec<&Event> = events
            .iter()
            .filter(|event| {
                event.step.as_deref() == Some(planned.name.as_str()) && event.kind == "terminal"
            })
            .collect();
        let start = events.iter().find(|event| {
            event.step.as_deref() == Some(planned.name.as_str()) && event.kind == "start"
        });
        match (start, terminals.len()) {
            (_, 0) => {
                return Err(Incomplete::Missing {
                    step: planned.name.clone(),
                });
            }
            (_, count) if count > 1 => {
                return Err(Incomplete::Duplicated {
                    step: planned.name.clone(),
                });
            }
            (None, _) => {
                return Err(Incomplete::OutOfOrder {
                    step: planned.name.clone(),
                });
            }
            (Some(start), _) => {
                if terminals
                    .iter()
                    .any(|terminal| terminal.sequence < start.sequence)
                {
                    return Err(Incomplete::OutOfOrder {
                        step: planned.name.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

impl Evidence {
    /// Read the committed fixture.
    ///
    /// # Errors
    ///
    /// [`crate::UsageError`] when the bytes are not this shape — a malformed
    /// fixture is an invalid input the caller can fix, and it must never read as
    /// a capability nobody declared.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        serde_json::from_str(text).map_err(|error| crate::UsageError::raise(error.to_string()))
    }

    /// Render the fixture's bytes, in the artifact's own shape.
    ///
    /// # Errors
    ///
    /// [`crate::UsageError`] only if the value cannot be serialised, which the
    /// types make unreachable.
    pub fn render(&self) -> anyhow::Result<String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|error| crate::UsageError::raise(error.to_string()))?;
        text.push('\n');
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(name: &str, status: &str, order: u64, group: &str) -> Step {
        Step {
            name: name.to_owned(),
            status: status.to_owned(),
            order_index: order,
            parallel_group_id: group.to_owned(),
        }
    }

    fn surface(steps: Vec<Step>) -> Surface {
        Surface {
            hook: "check".to_owned(),
            run_type: "check".to_owned(),
            profiles: vec!["slow".to_owned()],
            groups: vec![Group {
                id: "group_0".to_owned(),
                step_ids: steps.iter().map(|entry| entry.name.clone()).collect(),
            }],
            steps,
        }
    }

    fn contract(surface: Surface) -> Contract {
        Contract {
            version: SHAPE,
            tool_version: "hk 1.56.1".to_owned(),
            surfaces: vec![surface],
        }
    }

    fn plan_document() -> serde_json::Value {
        serde_json::json!({
            "hook": "check",
            "runType": "check",
            "profiles": ["slow"],
            "generatedAt": "2026-09-05T08:18:23.012156283+00:00",
            "groups": [{"id": "group_0", "stepIds": ["one", "two"]}],
            "steps": [
                {
                    "name": "one",
                    "status": "included",
                    "orderIndex": 0,
                    "parallelGroupId": "group_0",
                    "fileCount": 2,
                    "reasons": [{"kind": "filter_match", "detail": "2 files matched"}]
                },
                {
                    "name": "two",
                    "status": "included",
                    "orderIndex": 1,
                    "parallelGroupId": "group_0",
                    "fileCount": 970,
                    "reasons": [{"kind": "filter_match", "detail": "970 files matched"}]
                }
            ]
        })
    }

    /// The discriminator. A filter-at-compare-time implementation passes every
    /// other case here and fails this one, because the volatile value would be
    /// IN the artifact and the two renderings would differ.
    #[test]
    fn a_volatile_field_moving_does_not_reach_the_projection() {
        let mut later = plan_document();
        later["generatedAt"] = serde_json::json!("2026-09-05T09:99:00.000000000+00:00");
        later["steps"][0]["fileCount"] = serde_json::json!(3);
        later["steps"][1]["reasons"][0]["detail"] = serde_json::json!("971 files matched");

        let (Look::Is(first), Look::Is(second)) = (project(&plan_document()), project(&later))
        else {
            panic!("both plans project")
        };
        assert_eq!(first, second);
        assert!(compare(&contract(first), &contract(second)).is_empty());
    }

    #[test]
    fn repeat_rendering_is_byte_identical() {
        let contract = contract(surface(vec![step("one", "included", 0, "group_0")]));
        let (Ok(first), Ok(second)) = (contract.render(), contract.render()) else {
            panic!("the artifact renders")
        };
        assert_eq!(first, second);
        assert!(first.ends_with('\n'), "the artifact ends in a newline");
    }

    #[test]
    fn a_rendered_contract_reads_back_as_itself() {
        let contract = contract(surface(vec![step("one", "included", 0, "group_0")]));
        let Ok(text) = contract.render() else {
            panic!("the artifact renders")
        };
        let Ok(read) = Contract::parse(&text) else {
            panic!("the artifact reads back")
        };
        assert_eq!(read, contract);
    }

    /// An empty plan is could-not-look, never a clean projection. A generator
    /// that found nothing looks exactly like a gate that passed.
    #[test]
    fn an_empty_plan_is_could_not_look() {
        let mut empty = plan_document();
        empty["steps"] = serde_json::json!([]);
        assert_eq!(project(&empty), Look::CouldNotLook);
    }

    #[test]
    fn a_plan_missing_a_key_is_could_not_look() {
        for key in ["hook", "runType", "profiles", "groups", "steps"] {
            let mut broken = plan_document();
            let Some(object) = broken.as_object_mut() else {
                panic!("the fixture is an object")
            };
            object.remove(key);
            assert_eq!(
                project(&broken),
                Look::CouldNotLook,
                "a plan with no `{key}` cannot be projected"
            );
        }
    }

    #[test]
    fn a_step_added_is_drift_and_never_absorbed() {
        let committed = contract(surface(vec![step("one", "included", 0, "group_0")]));
        let current = contract(surface(vec![
            step("one", "included", 0, "group_0"),
            step("two", "included", 1, "group_0"),
        ]));
        assert_eq!(
            compare(&committed, &current)
                .iter()
                .map(Drift::render)
                .collect::<Vec<_>>(),
            vec!["step-added check two".to_owned()]
        );
    }

    #[test]
    fn a_step_removed_renamed_reordered_regrouped_or_restatused_each_drift() {
        let base = surface(vec![
            step("one", "included", 0, "group_0"),
            step("two", "included", 1, "group_0"),
        ]);
        let committed = contract(base.clone());

        let removed = surface(vec![step("one", "included", 0, "group_0")]);
        assert!(
            compare(&committed, &contract(removed))
                .iter()
                .any(|drift| drift.render() == "step-removed check two")
        );

        let renamed = surface(vec![
            step("one", "included", 0, "group_0"),
            step("owt", "included", 1, "group_0"),
        ]);
        let renderings: Vec<String> = compare(&committed, &contract(renamed))
            .iter()
            .map(Drift::render)
            .collect();
        assert!(renderings.contains(&"step-removed check two".to_owned()));
        assert!(renderings.contains(&"step-added check owt".to_owned()));

        let reordered = surface(vec![
            step("one", "included", 1, "group_0"),
            step("two", "included", 0, "group_0"),
        ]);
        assert!(
            compare(&committed, &contract(reordered))
                .iter()
                .any(|drift| drift.render() == "step-moved check one")
        );

        let mut regrouped = base.clone();
        regrouped.steps[1].parallel_group_id = "group_1".to_owned();
        assert!(
            compare(&committed, &contract(regrouped))
                .iter()
                .any(|drift| drift.render() == "step-regrouped check two")
        );

        let mut restatused = base;
        restatused.steps[1].status = "skipped".to_owned();
        assert!(
            compare(&committed, &contract(restatused))
                .iter()
                .any(|drift| drift.render() == "step-status check two")
        );
    }

    #[test]
    fn a_moved_profile_set_and_run_type_each_drift() {
        let committed = contract(surface(vec![step("one", "included", 0, "group_0")]));

        let mut retyped = surface(vec![step("one", "included", 0, "group_0")]);
        retyped.run_type = "fix".to_owned();
        assert!(
            compare(&committed, &contract(retyped))
                .iter()
                .any(|drift| drift.render() == "run-type check")
        );

        let mut reprofiled = surface(vec![step("one", "included", 0, "group_0")]);
        reprofiled.profiles = Vec::new();
        assert!(
            compare(&committed, &contract(reprofiled))
                .iter()
                .any(|drift| drift.render() == "profiles check")
        );
    }

    #[test]
    fn a_surface_on_one_side_only_is_named_with_the_side_it_is_on() {
        let one = contract(surface(vec![step("one", "included", 0, "group_0")]));
        let mut other = one.clone();
        let Some(only) = other.surfaces.first_mut() else {
            panic!("the fixture carries a surface")
        };
        only.hook = "fix".to_owned();

        assert_eq!(
            compare(&one, &other)
                .iter()
                .map(Drift::render)
                .collect::<Vec<_>>(),
            vec![
                "surface-only-committed check".to_owned(),
                "surface-only-live fix".to_owned(),
            ]
        );
    }

    #[test]
    fn a_group_that_moved_with_no_step_saying_so_is_named() {
        let committed = contract(surface(vec![
            step("one", "included", 0, "group_0"),
            step("two", "included", 1, "group_0"),
        ]));
        let mut regrouped = surface(vec![
            step("one", "included", 0, "group_0"),
            step("two", "included", 1, "group_0"),
        ]);
        let Some(group) = regrouped.groups.first_mut() else {
            panic!("the fixture carries a group")
        };
        group.step_ids.reverse();
        assert_eq!(
            compare(&committed, &contract(regrouped))
                .iter()
                .map(Drift::render)
                .collect::<Vec<_>>(),
            vec!["groups check".to_owned()]
        );
    }

    /// A contract taken at another pin does not answer this artifact's question,
    /// so the comparison is refused before it is made.
    #[test]
    fn a_contract_at_another_pin_does_not_agree() {
        let committed = contract(surface(vec![step("one", "included", 0, "group_0")]));
        let mut bumped = committed.clone();
        bumped.tool_version = "hk 1.57.0".to_owned();
        assert!(committed.agrees_with(&committed));
        assert!(!committed.agrees_with(&bumped));

        let mut reshaped = committed.clone();
        reshaped.version = SHAPE + 1;
        assert!(!committed.agrees_with(&reshaped));
    }

    /// Rule 4, asserted rather than assumed: the report names the step and
    /// nothing the plan said about it.
    #[test]
    fn a_finding_carries_no_payload() {
        let rendered = Drift::StepAdded {
            hook: "check".to_owned(),
            step: "one".to_owned(),
        }
        .render();
        assert_eq!(rendered, "step-added check one");
        for payload in ["files matched", "mise run", "glob", "{"] {
            assert!(
                !rendered.contains(payload),
                "a pointer carries no `{payload}`"
            );
        }
    }

    /// The third surface is spelled through `run`, which is the runner's own
    /// grammar. Asserted because a plausible-looking `["pre-commit"]` exits
    /// non-zero and would make the whole contract could-not-look.
    #[test]
    fn the_hook_surface_is_asked_for_through_the_run_verb() {
        assert_eq!(SURFACES.len(), 3);
        assert_eq!(SURFACES[2], &["run", "pre-commit"]);
        assert!(SURFACES.iter().all(|argv| !argv.is_empty()));
    }
}
