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

use std::path::Path;

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
