//! The `[[step]]` row and its load-time validator (CLOUD-843).
//!
//! **A LEAF, split from [`crate::step`] so the loader can name the row without
//! reaching the cache.** `config` owns the table's field and refuses a bad row
//! at load; `step` reads the committed table back through `resolve`. With the
//! type in `step`, `config -> step -> resolve -> config` was a module cycle —
//! the `config -> resolve` edge the layering table forbids, routed around in
//! one hop. Here the row's OWN edges are `error` and `git`'s pathspec
//! predicate, and neither is a module that loads a config.
//!
//! **What that does not claim.** The layering table decides over direct edges,
//! and `git` reaches `rules` (for its tree walker and glob selector), which
//! reaches `config`. So this module reaches the loader transitively — through
//! the `config <-> rules` cycle that already exists and that this split neither
//! adds to nor removes. What the split removed is the edge that was the row's
//! own: `step -> resolve`, with the loader naming `step`.

use std::collections::BTreeSet;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// One declared step: what its verdict depends on, and where it runs in a graph.
///
/// A KEYED ROW declares both `inputs` and `tools`; a SCHEDULE-ONLY NODE declares
/// neither (CLOUD-2785): it is in a `batten step graph run` group, always runs,
/// and never keys or takes a receipt. Absent and empty are different answers,
/// which is why both lists are optional and an empty one is still refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The step's name, as its caller passes it to `batten step`.
    pub id: String,
    /// Git pathspecs (no `:` magic) whose INDEX entries are key material. `.`
    /// is the whole tracked tree.
    ///
    /// The index rather than the worktree, and the worktree must agree with it
    /// over the set: a diverged or untracked path under a spec is no key at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<String>>,
    /// Programs, as argv, whose stdout is key material: a tool's version, or
    /// the declaration of the step's own command. Each must exit 0 and print
    /// something, or there is no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Vec<String>>>,
    /// The argv `batten step graph run` starts this row with. Never key
    /// material: the command a receipt covers is the one after `step run --`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<Vec<String>>,
    /// The graph this row is a node of, as `step graph run <group>` names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Grouped rows, of this group or an earlier one, that must exit 0 before
    /// this one starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// How the step's verdict is read. One variant on purpose: it is where a
    /// structured verdict is added, and a text pattern has none to be spelled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// The per-case journal a miss runs under, chosen by the row and never by
    /// sniffing the command's argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<Journal>,
}

/// How a step's verdict is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The command's exit code, house-style §7.
    Exit,
}

/// A per-case journal a step's miss runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Journal {
    /// `cargo nextest run` under the case-by-case journal (CLOUD-2772).
    Nextest,
}

impl Step {
    /// The declared pathspecs, empty for a schedule-only node.
    #[must_use]
    pub fn inputs(&self) -> &[String] {
        self.inputs.as_deref().unwrap_or_default()
    }

    /// The declared tools, empty for a schedule-only node.
    #[must_use]
    pub fn tools(&self) -> &[Vec<String>] {
        self.tools.as_deref().unwrap_or_default()
    }

    /// Whether this row keys a receipt: it declares inputs and tools.
    #[must_use]
    pub const fn is_keyed(&self) -> bool {
        self.inputs.is_some() && self.tools.is_some()
    }
}

/// Refuse a row the cache or the graph cannot act on, at LOAD rather than at
/// the first run.
///
/// Each refusal is a row that would otherwise answer the wrong thing silently:
/// empty inputs would key a receipt to no file at all; empty tools would let a
/// receipt outlive the toolchain that earned it; a `:`-magic pathspec would
/// select nothing; one list without the other is neither a keyed row nor a
/// schedule-only node; a grouped row with nothing to run, a dependency on no
/// grouped row, or a cycle is a graph that cannot be scheduled.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row's id.
pub fn validate(rows: &[Step]) -> Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for row in rows {
        validate_row(row)?;
        if !seen.insert(row.id.as_str()) {
            return Err(refuse(row, "declared twice — one id, one key"));
        }
    }
    validate_graph(rows)
}

fn refuse(row: &Step, why: &str) -> anyhow::Error {
    UsageError::raise(format!("[[step]] {}: {why}", row.id))
}

fn validate_row(row: &Step) -> Result<()> {
    if row.id.trim().is_empty() {
        return Err(UsageError::raise(String::from(
            "[[step]]: `id` is empty, so no caller could name the row",
        )));
    }
    match (&row.inputs, &row.tools) {
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(refuse(
                row,
                "declares one of `inputs` and `tools` without the other — a keyed row \
                 declares both, a schedule-only node neither",
            ));
        }
        (Some(inputs), Some(tools)) => {
            if inputs.is_empty() {
                return Err(refuse(
                    row,
                    "`inputs` is empty, so a receipt would answer for any tree — declare `.` \
                     for the whole tracked tree",
                ));
            }
            if let Some(spec) = inputs
                .iter()
                .find(|spec| !crate::git::pathspec_is_supported(spec))
            {
                return Err(refuse(
                    row,
                    &format!(
                        "`{spec}` is not a pathspec this build reads (empty, or `:` magic), so \
                         it would select nothing and read as a clean set"
                    ),
                ));
            }
            if tools.is_empty() {
                return Err(refuse(
                    row,
                    "`tools` is empty, so a receipt would outlive the toolchain that earned it",
                ));
            }
            if tools.iter().any(Vec::is_empty) {
                return Err(refuse(
                    row,
                    "a `tools` entry is an empty argv, which runs nothing",
                ));
            }
        }
    }
    if row.run.as_ref().is_some_and(Vec::is_empty) {
        return Err(refuse(row, "`run` is an empty argv, which runs nothing"));
    }
    if row.group.is_some() && row.run.is_none() {
        return Err(refuse(
            row,
            "is in a `group` with no `run`, so the graph has nothing to start",
        ));
    }
    if row.group.is_none() && !row.depends_on.is_empty() {
        return Err(refuse(row, "declares `depends_on` outside any `group`"));
    }
    Ok(())
}

/// Every dependency names a grouped row, and no group has a cycle.
///
/// A DEPENDENCY MAY CROSS GROUPS (CLOUD-2904): groups are tiers that run in
/// order, and a later tier's row may consume what an earlier tier's row
/// produces. That edge is what skips it when the producer is red; an edge-less
/// later tier runs whatever an earlier one decided.
fn validate_graph(rows: &[Step]) -> Result<()> {
    let by_id: std::collections::BTreeMap<&str, &Step> =
        rows.iter().map(|row| (row.id.as_str(), row)).collect();
    for row in rows {
        for dependency in &row.depends_on {
            let grouped = by_id
                .get(dependency.as_str())
                .is_some_and(|other| other.group.is_some());
            if !grouped {
                return Err(refuse(
                    row,
                    &format!("depends on `{dependency}`, which is not a row of any group"),
                ));
            }
        }
    }
    // Kahn's algorithm over the dependency edges: whatever never reaches
    // in-degree zero sits on a cycle.
    let mut waiting: std::collections::BTreeMap<&str, usize> = rows
        .iter()
        .map(|row| (row.id.as_str(), row.depends_on.len()))
        .collect();
    let mut ready: Vec<&str> = waiting
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| *id)
        .collect();
    while let Some(done) = ready.pop() {
        waiting.remove(done);
        for row in rows {
            if row.depends_on.iter().any(|dependency| dependency == done)
                && let Some(count) = waiting.get_mut(row.id.as_str())
            {
                *count -= 1;
                if *count == 0 {
                    ready.push(row.id.as_str());
                }
            }
        }
    }
    if let Some((id, _)) = waiting.iter().next() {
        let row = by_id[id];
        return Err(refuse(
            row,
            "is on a `depends_on` cycle, so no order can start it",
        ));
    }
    Ok(())
}

// The validator's mutation rows, one per refusal. Each clause is a row that
// would otherwise load and answer the wrong thing in silence, so dropping any
// one of them must turn the unit case that feeds it that row red.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(inputs: &[&str], tools: &[&[&str]]) -> Step {
        Step {
            id: String::from("a-step"),
            inputs: Some(inputs.iter().map(|spec| (*spec).to_owned()).collect()),
            tools: Some(
                tools
                    .iter()
                    .map(|argv| argv.iter().map(|word| (*word).to_owned()).collect())
                    .collect(),
            ),
            run: None,
            group: None,
            depends_on: Vec::new(),
            verdict: None,
            journal: None,
        }
    }

    /// Fails by: a row declaring only one of inputs and tools read as keyed,
    /// which keys a receipt to half its material.
    #[test]
    fn only_a_row_with_inputs_and_tools_is_keyed() {
        assert!(row(&["."], &[&["rustc", "-V"]]).is_keyed());
        let mut no_tools = row(&["."], &[]);
        no_tools.tools = None;
        assert!(!no_tools.is_keyed());
        let mut no_inputs = row(&["."], &[&["rustc", "-V"]]);
        no_inputs.inputs = None;
        assert!(!no_inputs.is_keyed());
        assert!(!node("n", &[]).is_keyed());
    }

    /// A schedule-only node of group `g`, running `true`, after `after`.
    fn node(id: &str, after: &[&str]) -> Step {
        Step {
            id: id.to_owned(),
            inputs: None,
            tools: None,
            run: Some(vec![String::from("true")]),
            group: Some(String::from("g")),
            depends_on: after.iter().map(|id| (*id).to_owned()).collect(),
            verdict: None,
            journal: None,
        }
    }

    /// Fails by: a row declaring inputs and tools read as unkeyed, or a
    /// schedule-only node read as keyed.
    #[test]
    fn a_row_with_inputs_and_tools_is_keyed() {
        assert!(row(&["."], &[&["cargo", "--version"]]).is_keyed());
        assert!(!node("n", &[]).is_keyed());
    }

    /// The load error a `[[step]]` table parsed from `toml` gives, if any.
    fn loaded(toml: &str) -> Result<Vec<Step>, String> {
        #[derive(serde::Deserialize)]
        struct Table {
            step: Vec<Step>,
        }
        let table: Table = toml::from_str(toml).map_err(|error| error.to_string())?;
        validate(&table.step).map_err(|error| error.to_string())?;
        Ok(table.step)
    }

    /// Fails by: `tools` answering anything but the declared lists, or a row
    /// with one list and not the other read as keyed.
    #[test]
    fn a_row_is_keyed_by_both_lists_and_answers_its_own_tools() {
        let keyed = row(&["crates"], &[&["rustc", "--version"]]);
        assert!(keyed.is_keyed());
        assert_eq!(
            keyed.tools(),
            [vec![String::from("rustc"), String::from("--version")]]
        );
        let mut inputs_only = keyed.clone();
        inputs_only.tools = None;
        assert!(!inputs_only.is_keyed());
        assert!(inputs_only.tools().is_empty());
        let mut tools_only = keyed;
        tools_only.inputs = None;
        assert!(!tools_only.is_keyed());
        assert!(!node("n", &[]).is_keyed());
    }

    #[test]
    fn a_well_formed_row_loads() {
        validate(&[row(&["crates", "."], &[&["rustc", "--version"]])]).unwrap();
    }

    #[test]
    fn a_row_that_would_answer_the_wrong_thing_is_refused_at_load() {
        // Each of these parses and would decide wrongly in silence: no inputs key
        // nothing, no tools outlive the toolchain, a magic spec selects nothing,
        // and an empty argv runs nothing.
        for (bad, why) in [
            (row(&[], &[&["t"]]), "inputs"),
            (row(&[":(exclude)x"], &[&["t"]]), "pathspec"),
            (row(&[""], &[&["t"]]), "pathspec"),
            (row(&["a"], &[]), "tools"),
            (row(&["a"], &[&[]]), "empty argv"),
        ] {
            let refused = validate(&[bad]).unwrap_err().to_string();
            assert!(refused.contains(why), "{why}: {refused}");
        }
    }

    #[test]
    fn an_empty_id_is_refused() {
        let mut blank = row(&["a"], &[&["t"]]);
        blank.id = String::from("  ");
        let refused = validate(&[blank]).unwrap_err().to_string();
        assert!(refused.contains("`id` is empty"), "{refused}");
    }

    #[test]
    fn a_step_declared_twice_is_refused() {
        let refused = validate(&[row(&["a"], &[&["t"]]), row(&["b"], &[&["t"]])])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("declared twice"), "{refused}");
    }

    // THE CI MAPPING IS NOT A ROW KEY (CLOUD-2788): `step cover` reads it from
    // `CI_LOCAL_PROOF` beside the roster, so a `ci` list on a row would load and
    // be read by nothing. It is refused, as every unknown key is.
    #[test]
    fn a_ci_key_on_a_row_is_refused() {
        let base = "[[step]]\nid = \"s\"\ninputs = [\"a\"]\ntools = [[\"t\"]]\n";
        assert!(loaded(base).is_ok());
        let refused = loaded(&format!("{base}ci = [\"check\"]\n")).unwrap_err();
        assert!(refused.contains("unknown field `ci`"), "{refused}");
    }

    // A VERDICT HAS NO TEXT FORM (CLOUD-2785): the only value is `exit`, so a
    // pattern over a log has nothing to be spelled in.
    #[test]
    fn a_text_verdict_is_refused_at_load() {
        let base = "[[step]]\nid = \"s\"\ninputs = [\"a\"]\ntools = [[\"t\"]]\n";
        assert!(loaded(&format!("{base}verdict = \"exit\"\n")).is_ok());
        for bad in ["verdict = \"stdout\"\n", "verdict = { pattern = \"ok\" }\n"] {
            assert!(loaded(&format!("{base}{bad}")).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_schedule_only_row_loads() {
        validate(&[node("a", &[]), node("b", &["a"])]).unwrap();
    }

    #[test]
    fn inputs_without_tools_is_refused() {
        let mut half = row(&["a"], &[&["t"]]);
        half.tools = None;
        let refused = validate(&[half]).unwrap_err().to_string();
        assert!(refused.contains("without the other"), "{refused}");
        let mut other = row(&["a"], &[&["t"]]);
        other.inputs = None;
        let refused = validate(&[other]).unwrap_err().to_string();
        assert!(refused.contains("without the other"), "{refused}");
    }

    #[test]
    fn a_grouped_row_without_run_is_refused() {
        let mut bare = node("a", &[]);
        bare.run = None;
        let refused = validate(&[bare]).unwrap_err().to_string();
        assert!(refused.contains("no `run`"), "{refused}");
    }

    #[test]
    fn a_dependency_on_an_ungrouped_or_missing_row_is_refused() {
        let mut loose = node("b", &[]);
        loose.group = None;
        let refused = validate(&[node("a", &["b"]), loose])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not a row of any group"), "{refused}");
        let refused = validate(&[node("a", &["missing"])])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not a row of any group"), "{refused}");
    }

    #[test]
    fn a_dependency_on_another_groups_row_loads() {
        let mut earlier = node("b", &[]);
        earlier.group = Some(String::from("h"));
        assert!(validate(&[node("a", &["b"]), earlier]).is_ok());
    }

    #[test]
    fn a_dependency_cycle_is_refused() {
        let refused = validate(&[node("a", &["c"]), node("b", &["a"]), node("c", &["b"])])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("cycle"), "{refused}");
        // A diamond is not a cycle.
        validate(&[
            node("a", &[]),
            node("b", &["a"]),
            node("c", &["a"]),
            node("d", &["b", "c"]),
        ])
        .unwrap();
    }

    /// Fails by: a keyed row's declared tools read as none, or a
    /// schedule-only node read as keyed.
    #[test]
    fn a_keyed_row_carries_its_tools_and_a_node_keys_nothing() {
        let keyed = row(&["."], &[&["rustc", "--version"]]);
        assert_eq!(
            keyed.tools(),
            [vec![String::from("rustc"), String::from("--version")]]
        );
        assert!(keyed.is_keyed());
        let node = node("n", &[]);
        assert!(node.tools().is_empty());
        assert!(!node.is_keyed());
    }
}
