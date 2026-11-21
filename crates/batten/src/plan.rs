//! `batten plan lint` and `batten plan path` (CLOUD-2766): the front of the plan
//! chain `plan cover partial` already closes at landing.
//!
//! **A COMMAND AND AN EXIT CODE OVER AN OBJECT, NOT A MINT ON A SKILL.** A
//! `[[mint]]` on a `Skill` call fires when the skill is LOADED, so it would lift a
//! hold before any of the skill had run. The receipt here is written by a verb
//! that decided something about the plan, the way `claim check` writes the claim
//! receipt (AGENTS.md rule 3).
//!
//! **WHAT IT DOES NOT CLAIM.** The verdict line is written by the session, so the
//! lint proves the line is there, not that an isolated reader produced it. The
//! `requires` receipt proves the skill was loaded on this branch before the lint
//! passed. Together: the skill was asked for, and the plan it left has the shape a
//! checked plan has — the grade of the review receipts, one notch stronger
//! because the shape is decided.
//!
//! **THE PLAN'S STEPS ARE THE RECORDED PLAN.** `batten record plan` already
//! stores this branch's entries under its claim, and `plan cover partial` holds
//! each to its end at landing. The lint requires the document's steps and that
//! record to agree, so the gate that runs at the end judges what was planned at
//! the start, and a plan cannot be recorded after the work as one line.
//!
//! Pointer-only (rule 4): every finding is the plan file, a line and a clause.
//! Nothing the plan says is echoed.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::config_model::PLAN_RECEIPT as RECEIPT;
use crate::config_model::PlanTable;
use crate::error::UsageError;

/// One finding: the plan's line and a fixed clause, never the plan's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The 1-based line in the plan file.
    pub line: usize,
    /// The clause, from the fixed set this module names.
    pub clause: String,
}

impl Finding {
    fn at(line: usize, clause: &str) -> Self {
        Self {
            line,
            clause: clause.to_owned(),
        }
    }
}

/// The plan file a branch keeps: `<git dir>/batten-plans/<branch>.md`, with the
/// branch spelled as a branch-keyed receipt spells it and no claim suffix.
#[must_use]
pub fn path(git_dir: &Path, branch: &str) -> PathBuf {
    git_dir
        .join("batten-plans")
        .join(format!("{}.md", branch.replace('/', "-")))
}

/// The lines of `text` a reader looks at: 1-based, with every line inside a
/// fenced code block — and the fences themselves — dropped.
fn unfenced(text: &str) -> Vec<(usize, &str)> {
    let mut fenced = false;
    let mut kept = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            kept.push((index + 1, line));
        }
    }
    kept
}

/// An ATX heading's level and text.
fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line.bytes().take_while(|byte| *byte == b'#').count();
    let rest = line.get(level..)?;
    ((1..=6).contains(&level) && rest.starts_with(' ')).then(|| (level, rest[1..].trim_end()))
}

/// Whether `line` is the heading of the declared section `name`.
fn is_named(line: &str, name: &str) -> bool {
    heading(line).is_some_and(|(_, text)| text == name)
}

/// A list line's text, when `line` begins one at column 0.
fn list_text(line: &str) -> Option<&str> {
    if let Some(rest) = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))
    {
        return Some(rest);
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    let rest = line.get(digits..)?;
    (digits > 0)
        .then(|| rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")))
        .flatten()
}

/// Whether `token` is an id of the form `<prefix><digits>`.
fn is_id(token: &str, prefix: char) -> bool {
    token.strip_prefix(prefix).is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// The id a list text begins with, when it is of the `prefix` form. An id ends at
/// the first character that is not an ASCII letter or digit.
fn leading_id(text: &str, prefix: char) -> Option<&str> {
    let end = text
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(text.len());
    let token = &text[..end];
    is_id(token, prefix).then_some(token)
}

/// Every whole id of the item form in `text`.
fn cited(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| is_id(token, 'A'))
}

/// Every pointer on `line` that names a file that is not there, or a line past
/// its end.
fn dead_pointers(line: &str, root: &Path) -> usize {
    let mut dead = 0;
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        if after.starts_with('`') {
            rest = after.trim_start_matches('`');
            continue;
        }
        let Some(close) = after.find('`') else {
            break;
        };
        if pointer_is_dead(&after[..close], root) {
            dead += 1;
        }
        rest = &after[close + 1..];
    }
    dead
}

/// Whether a single-backticked token is a `<path>:<digits>` pointer that does not
/// resolve. A token of any other shape — a bare path above all — is not judged:
/// a plan names files it will create.
fn pointer_is_dead(token: &str, root: &Path) -> bool {
    let Some((path, number)) = token.rsplit_once(':') else {
        return false;
    };
    if path.is_empty() || path.contains(' ') || number.is_empty() {
        return false;
    }
    let Ok(line) = number.parse::<usize>() else {
        return false;
    };
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| part == std::path::Component::ParentDir)
    {
        return true;
    }
    std::fs::read_to_string(root.join(relative))
        .map_or(true, |text| line == 0 || line > text.lines().count())
}

/// A located section: its heading's line and level, and its body's lines.
struct Section<'a> {
    heading: usize,
    body: Vec<(usize, &'a str)>,
}

impl Section<'_> {
    fn is_empty(&self) -> bool {
        self.body.iter().all(|(_, line)| line.trim().is_empty())
    }

    /// Whether the body is the single line `none`: the trivial form.
    fn is_none(&self) -> bool {
        let lines: Vec<&str> = self
            .body
            .iter()
            .map(|(_, line)| line.trim())
            .filter(|line| !line.is_empty())
            .collect();
        lines == ["none"]
    }
}

/// Find each declared section after the one before it; the last runs to the
/// end of the file whatever headings it holds.
fn sections<'a>(
    lines: &[(usize, &'a str)],
    declared: &[String],
) -> Vec<std::result::Result<Section<'a>, usize>> {
    let mut found = Vec::new();
    let mut cursor = 0;
    let mut previous = 1;
    for (index, name) in declared.iter().enumerate() {
        let last = index + 1 == declared.len();
        let Some(at) = lines[cursor..]
            .iter()
            .position(|(_, line)| is_named(line, name))
        else {
            found.push(Err(previous));
            continue;
        };
        let at = cursor + at;
        let (number, line) = lines[at];
        let level = heading(line).map_or(1, |(level, _)| level);
        let body: Vec<(usize, &str)> = lines[at + 1..]
            .iter()
            .take_while(|(_, line)| last || heading(line).is_none_or(|(other, _)| other > level))
            .copied()
            .collect();
        cursor = at + 1;
        previous = number;
        found.push(Ok(Section {
            heading: number,
            body,
        }));
    }
    found
}

/// What the lint is given besides the plan's text.
#[derive(Debug)]
pub struct Inputs<'a> {
    /// The declared table.
    pub table: &'a PlanTable,
    /// The worktree root pointers resolve against.
    pub root: &'a Path,
    /// The ids of the plan record for this claim, or `None` when there is none.
    pub record: Option<Vec<String>>,
    /// Whether the `requires` receipt exists, when one is declared.
    pub prerequisite: bool,
}

/// Judge a plan's text. Empty when it passes.
#[must_use]
pub fn lint(text: &str, inputs: &Inputs<'_>) -> Vec<Finding> {
    if text.trim().is_empty() {
        return vec![Finding::at(1, "file-missing")];
    }
    let lines = unfenced(text);
    let declared = &inputs.table.sections;
    let located = sections(&lines, declared);
    let mut findings = Vec::new();
    for (index, section) in located.iter().enumerate() {
        match section {
            Err(previous) => findings.push(Finding::at(
                *previous,
                &format!("section-missing {}", index + 1),
            )),
            Ok(section) if section.is_empty() => findings.push(Finding::at(
                section.heading,
                &format!("section-missing {}", index + 1),
            )),
            Ok(_) => {}
        }
    }
    let (items_section, steps_section) = match (located.first(), located.get(1)) {
        (Some(Ok(items)), Some(Ok(steps))) => (Some(items), Some(steps)),
        (items, steps) => (
            items.and_then(|section| section.as_ref().ok()),
            steps.and_then(|section| section.as_ref().ok()),
        ),
    };
    let trivial =
        items_section.is_some_and(Section::is_none) && steps_section.is_some_and(Section::is_none);
    plan_body(&mut findings, items_section, steps_section, trivial, inputs);
    pointers(&mut findings, &lines, located.last(), inputs.root);
    verdict(&mut findings, located.last(), &inputs.table.verdict);
    if inputs.table.requires.is_some() && !inputs.prerequisite {
        findings.push(Finding::at(1, "check-unasked"));
    }
    findings.sort_by_key(|finding| finding.line);
    findings
}

/// Items, steps, the record and coverage.
fn plan_body(
    findings: &mut Vec<Finding>,
    items_section: Option<&Section<'_>>,
    steps_section: Option<&Section<'_>>,
    trivial: bool,
    inputs: &Inputs<'_>,
) {
    let items: Vec<(usize, &str)> = items_section.map_or_else(Vec::new, |section| {
        section
            .body
            .iter()
            .filter_map(|(number, line)| {
                list_text(line)
                    .and_then(|text| leading_id(text, 'A'))
                    .map(|id| (*number, id))
            })
            .collect()
    });
    let steps = steps_of(steps_section);
    let steps_heading = steps_section.map_or(1, |section| section.heading);
    for (section, held, index) in [
        (items_section, items.is_empty(), 1),
        (steps_section, steps.is_empty(), 2),
    ] {
        if let Some(section) =
            section.filter(|section| held && !section.is_empty() && !section.is_none())
        {
            findings.push(Finding::at(
                section.heading,
                &format!("section-missing {index}"),
            ));
        }
    }
    let Some(record) = &inputs.record else {
        findings.push(Finding::at(steps_heading, "record-missing"));
        return;
    };
    if trivial && record.is_empty() {
        return;
    }
    let step_ids: BTreeSet<&str> = steps.iter().map(|step| step.id).collect();
    for step in &steps {
        if !record.iter().any(|entry| entry == step.id) {
            findings.push(Finding::at(step.line, "step-unrecorded"));
        }
    }
    for entry in record {
        if !is_id(entry, 'S') {
            findings.push(Finding::at(steps_heading, "entry-misnamed"));
        } else if !step_ids.contains(entry.as_str()) {
            findings.push(Finding::at(steps_heading, "entry-unplanned"));
        }
    }
    coverage(findings, &items, &steps);
}

/// Requirement-to-task coverage, in both directions, decided by matching ids.
fn coverage(findings: &mut Vec<Finding>, items: &[(usize, &str)], steps: &[Step<'_>]) {
    let item_ids: BTreeSet<&str> = items.iter().map(|(_, id)| *id).collect();
    let reached: BTreeSet<&str> = steps
        .iter()
        .flat_map(|step| step.cites.iter().copied())
        .collect();
    for (number, id) in items {
        if !reached.contains(id) {
            findings.push(Finding::at(*number, "item-unreached"));
        }
    }
    for step in steps {
        if step.cites.is_empty() || step.cites.iter().any(|id| !item_ids.contains(id)) {
            findings.push(Finding::at(step.line, "step-unasked"));
        }
    }
}

/// One step: its line, its id and the item ids its lines cite.
struct Step<'a> {
    line: usize,
    id: &'a str,
    cites: Vec<&'a str>,
}

/// The steps of the second section, each with the lines that follow it.
fn steps_of<'a>(section: Option<&Section<'a>>) -> Vec<Step<'a>> {
    let mut steps: Vec<Step<'a>> = Vec::new();
    for (number, line) in section.map_or(&[][..], |section| section.body.as_slice()) {
        if let Some(id) = list_text(line).and_then(|text| leading_id(text, 'S')) {
            steps.push(Step {
                line: *number,
                id,
                cites: cited(line).collect(),
            });
        } else if let Some(step) = steps.last_mut() {
            step.cites.extend(cited(line));
        }
    }
    steps
}

/// Every dead pointer outside the last section.
fn pointers(
    findings: &mut Vec<Finding>,
    lines: &[(usize, &str)],
    last: Option<&std::result::Result<Section<'_>, usize>>,
    root: &Path,
) {
    let last = last
        .and_then(|section| section.as_ref().ok())
        .map(|section| section.heading);
    for (number, line) in lines
        .iter()
        .take_while(|(number, _)| last.is_none_or(|last| *number < last))
    {
        let dead = dead_pointers(line, root);
        for _ in 0..dead {
            findings.push(Finding::at(*number, "pointer-dead"));
        }
    }
}

/// The last section must hold the declared verdict line.
fn verdict(
    findings: &mut Vec<Finding>,
    last: Option<&std::result::Result<Section<'_>, usize>>,
    wanted: &str,
) {
    let Some(Ok(section)) = last else {
        return;
    };
    if !section
        .body
        .iter()
        .any(|(_, line)| line.trim_end() == wanted)
    {
        findings.push(Finding::at(section.heading, "verdict-absent"));
    }
}

/// What one `plan lint` run decided.
#[derive(Debug)]
pub struct Ran {
    /// The plan file judged.
    pub plan: PathBuf,
    /// What failed, in line order. Empty when the lint passed and wrote.
    pub findings: Vec<Finding>,
}

/// The branch `plan` verbs key on, and the repository's git directory.
///
/// # Errors
///
/// A [`UsageError`] outside a repository or on a detached HEAD, which has no
/// branch to key a plan on.
pub fn keyed(root: &Path) -> Result<(PathBuf, String)> {
    let git_dir = crate::git::git_dir(root).map_err(|_| {
        UsageError::raise("plan: not a git repository, so there is nothing to key a plan on")
    })?;
    let Ok(Some(branch)) = crate::git::current_branch(root) else {
        return Err(UsageError::raise(
            "plan: a detached HEAD has no branch to key a plan on",
        ));
    };
    Ok((git_dir, branch))
}

/// Run `plan lint` from `root`: judge the branch's plan and, on zero findings,
/// append the receipt and consume the prerequisite.
///
/// # Errors
///
/// A [`UsageError`] when no `[plan]` table is declared, outside a repository or
/// on a detached HEAD; an internal error when the receipt cannot be written.
pub fn run_lint(root: &Path, table: Option<&PlanTable>) -> Result<Ran> {
    let Some(table) = table else {
        return Err(undeclared());
    };
    let (git_dir, branch) = keyed(root)?;
    let plan = path(&git_dir, &branch);
    let text = std::fs::read_to_string(&plan).unwrap_or_default();
    let receipts = git_dir.join("batten-receipts");
    let claim = crate::claim::claimed_token(&receipts, &branch);
    let record = std::fs::read_to_string(crate::recorder::record_path(
        &git_dir,
        "plan",
        &branch,
        claim.as_deref(),
    ))
    .ok()
    .map(|text| record_ids(&text));
    let prerequisite = table
        .requires
        .as_ref()
        .map(|name| receipts.join(crate::receipt::branch_receipt_name(name, &branch)));
    let worktree = crate::git::worktree_root(root).unwrap_or_else(|_| root.to_path_buf());
    let findings = lint(
        &text,
        &Inputs {
            table,
            root: &worktree,
            record,
            prerequisite: prerequisite.as_ref().is_some_and(|path| path.is_file()),
        },
    );
    if !findings.is_empty() {
        return Ok(Ran { plan, findings });
    }
    let head = crate::git::head_commit(root)?;
    append_receipt(&receipts, &branch, &head, &text)?;
    if let Some(prerequisite) = &prerequisite {
        std::fs::remove_file(prerequisite)?;
    }
    Ok(Ran { plan, findings })
}

/// Append `base <head>` and `plan <sha256>` to the branch's `plan-check`
/// receipt.
///
/// **APPENDED, NOT REPLACED**: the store is append-only on purpose and the
/// reader takes the newest `base`. The `base` line is required, not decoration:
/// a branch-keyed receipt rule treats a receipt without one as void.
fn append_receipt(receipts: &Path, branch: &str, head: &str, text: &str) -> Result<()> {
    std::fs::create_dir_all(receipts)?;
    let dest = receipts.join(crate::receipt::branch_receipt_name(RECEIPT, branch));
    let digest = crate::digest::sha256_hex(text.as_bytes());
    let lines = format!("base {head}\nplan {digest}\n");
    crate::durable::append(&dest, &lines)?;
    Ok(())
}

/// The usage error `plan lint` gives with no `[plan]` table.
fn undeclared() -> anyhow::Error {
    UsageError::raise(
        "plan lint: no [plan] table is declared, so there is nothing to judge a plan against",
    )
}

/// The entry ids of a plan record's text, in order.
#[must_use]
pub fn record_ids(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! The grammar's boundaries, each decided here rather than through the
    //! binary: the `plan_lint` suite reaches them only where a whole plan
    //! happens to sit on one.
    use super::*;

    fn table(sections: &[&str]) -> PlanTable {
        PlanTable {
            sections: sections.iter().map(|name| (*name).to_owned()).collect(),
            verdict: String::from("verdict: executable"),
            requires: None,
        }
    }

    /// A directory of its own under the temp dir, emptied first.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("batten-plan-tests-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn clauses(text: &str, record: &[&str]) -> Vec<String> {
        let root = scratch("clauses");
        lint(
            text,
            &Inputs {
                table: &table(&["Acceptance", "Steps", "Validation"]),
                root: &root,
                record: Some(record.iter().map(|id| (*id).to_owned()).collect()),
                prerequisite: true,
            },
        )
        .into_iter()
        .map(|finding| finding.clause)
        .collect()
    }

    #[test]
    fn three_or_more_distinct_sections_are_a_table() {
        assert!(crate::config_model::plan_partial(&table(&["A", "B"])));
        assert!(!crate::config_model::plan_partial(&table(&["A", "B", "C"])));
        assert!(!crate::config_model::plan_partial(&table(&[
            "A", "B", "C", "D"
        ])));
        assert!(crate::config_model::plan_partial(&table(&["A", "C", "C"])));
    }

    #[test]
    fn either_fence_spelling_hides_its_block() {
        for fence in ["```", "~~~"] {
            let text = format!("a\n{fence}\nb\n{fence}\nc");
            assert_eq!(unfenced(&text), vec![(1, "a"), (5, "c")], "{fence}");
        }
    }

    #[test]
    fn a_heading_needs_its_space() {
        assert_eq!(heading("## Steps"), Some((2, "Steps")));
        assert_eq!(heading("#Steps"), None);
        assert_eq!(heading("####### Steps"), None);
    }

    #[test]
    fn a_numbered_list_line_needs_its_number() {
        assert_eq!(list_text("1. a"), Some("a"));
        assert_eq!(list_text("12) b"), Some("b"));
        assert_eq!(list_text(". c"), None);
        assert_eq!(list_text("- d"), Some("d"));
    }

    #[test]
    fn an_id_is_its_prefix_and_digits_only() {
        assert!(is_id("S1", 'S'));
        assert!(!is_id("S", 'S'));
        assert!(!is_id("S1a", 'S'));
        assert!(!is_id("A1", 'S'));
    }

    #[test]
    fn every_pointer_on_a_line_is_counted() {
        let root = scratch("every-pointer");
        assert_eq!(dead_pointers("see `a.rs:1` and `b.rs:2` too", &root), 2);
        assert_eq!(dead_pointers("`a.rs:1`", &root), 1);
        // A closing backtick is never the next opening one: the text between two
        // pointers is prose, even when it has a pointer's shape.
        assert_eq!(dead_pointers("`a.rs:1`b.rs:2`c.rs:3`", &root), 2);
    }

    #[test]
    fn only_a_path_and_a_line_is_a_pointer() {
        let root = scratch("pointer-shape");
        std::fs::write(root.join("here.rs"), "one\ntwo\n").unwrap();
        assert!(!pointer_is_dead(":5", &root), "no path");
        assert!(!pointer_is_dead("a b:5", &root), "a path with a space");
        assert!(!pointer_is_dead("here.rs:", &root), "no line");
        assert!(!pointer_is_dead("here.rs:2", &root));
        assert!(pointer_is_dead("here.rs:3", &root), "past the end");
        assert!(pointer_is_dead("here.rs:0", &root), "line zero");
    }

    #[test]
    fn a_pointer_out_of_the_tree_is_dead_even_when_it_resolves() {
        let root = scratch("escape");
        let inner = root.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(root.join("outside.rs"), "one\n").unwrap();
        assert!(pointer_is_dead("../outside.rs:1", &inner), "a parent hop");
        let absolute = root.join("outside.rs");
        assert!(
            pointer_is_dead(&format!("{}:1", absolute.display()), &inner),
            "an absolute path"
        );
    }

    #[test]
    fn none_is_the_single_line_none() {
        let none = Section {
            heading: 1,
            body: vec![(2, ""), (3, "none"), (4, " ")],
        };
        let other = Section {
            heading: 1,
            body: vec![(2, "none"), (3, "more")],
        };
        assert!(none.is_none());
        assert!(!other.is_none());
    }

    #[test]
    fn a_section_ends_at_a_heading_no_deeper_than_its_own() {
        let text = "## A\n- x\n### deeper\n## Extra\n- y\n## B\nb\n## C\nc\n";
        let lines = unfenced(text);
        let located = sections(&lines, &table(&["A", "B", "C"]).sections);
        let Some(Ok(first)) = located.first() else {
            panic!("A is found");
        };
        assert_eq!(first.body, vec![(2, "- x"), (3, "### deeper")]);
    }

    #[test]
    fn a_heading_answers_one_declared_section() {
        let text = "## X\nbody\n## V\nverdict: executable\n";
        let lines = unfenced(text);
        let located = sections(&lines, &table(&["X", "X", "V"]).sections);
        assert!(located[0].is_ok());
        assert!(
            located[1].is_err(),
            "the second X is not the first one again"
        );
    }

    #[test]
    fn a_section_found_out_of_order_is_missing() {
        let text = "## B\nb\n## A\na\n## C\nc\n";
        let lines = unfenced(text);
        let located = sections(&lines, &table(&["A", "B", "C"]).sections);
        assert!(located[0].is_ok());
        assert!(located[1].is_err(), "B before A reads as missing");
    }

    #[test]
    fn the_trivial_form_needs_both_sections_none() {
        let text =
            "## Acceptance\nnone\n## Steps\n- S1 do it (A1)\n## Validation\nverdict: executable\n";
        assert!(clauses(text, &[]).contains(&String::from("step-unrecorded")));
    }

    #[test]
    fn an_items_section_with_no_item_is_missing() {
        let text =
            "## Acceptance\n- no id here\n## Steps\nnone\n## Validation\nverdict: executable\n";
        assert!(clauses(text, &[]).contains(&String::from("section-missing 1")));
    }

    #[test]
    fn a_step_is_recorded_when_its_id_is_in_the_record() {
        let text = "## Acceptance\n- A1 one\n## Steps\n- S1 do it (A1)\n## Validation\nverdict: executable\n";
        assert_eq!(clauses(text, &["S1"]), Vec::<String>::new());
    }

    #[test]
    fn the_validation_heading_itself_is_not_judged() {
        let root = scratch("validation-heading");
        let named = "V `gone.rs:1`";
        let text =
            format!("## A\n- A1 one\n## S\n- S1 do it (A1)\n## {named}\nverdict: executable\n");
        let findings = lint(
            &text,
            &Inputs {
                table: &table(&["A", "S", named]),
                root: &root,
                record: Some(vec![String::from("S1")]),
                prerequisite: true,
            },
        );
        assert_eq!(findings, Vec::new());
    }
}
