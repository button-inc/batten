//! The shipped skills stay inside their line budget and describe only the surface
//! the binary actually ships (CLOUD-213), over the compiled binary.
//!
//! # Why these properties
//!
//! The skill is the dispositional third of the interaction model: hooks bind, the
//! CLI consults, the skill teaches when to consult and what a deny means. Two of
//! its properties are specification rather than taste, and a specification without
//! a mechanism is prose (non-negotiable rule 2).
//!
//! **The budget is evidence, not style.** In head-to-head evaluation a 341-line
//! skill outscored a 2,187-line one: terse beats comprehensive, because a skill
//! competes for the same context the task needs. So [`MAX_LINES`] is a ceiling
//! somebody measured, and the number lives here and nowhere else.
//!
//! **The expensive failure is fiction.** A skill that teaches a verb the binary
//! does not have is worse than no skill: it sends an agent to build a command line
//! that cannot work, and the failure surfaces as a confusing usage error rather
//! than as a documentation bug. Nothing else in the tree would notice — the skill
//! is markdown, so no compiler reads it.
//!
//! So the verb reading comes from `batten spec`, the shipped spec-as-data surface
//! (house style §11), and the exit reading from the binary's own `--help`. Both
//! are acquired from the compiled binary rather than from a second copy of the
//! command tree, which is the whole reason this tier exists rather than a
//! fixture-fed one.
//!
//! **And one set of bytes.** A skill is authored at `skills/` and reached through
//! a vendor path by symlink, the `CLAUDE.md` -> `AGENTS.md` shape already in the
//! tree. If that ever becomes a copy, the checks judge one file while agents load
//! the other, which is the worst of both.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use common::{at_root, batten, scratch};

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Two paths die, so two arms:
// a program and its suite are separate subjects, and one arm covering both would
// claim a conservation nobody checked. The suite's arm names its declared
// `# subject:` too (CLOUD-1130), which this same delta retires.
//
// carried: mise-tasks/skill-check.sh crates/batten/src/surface.rs crates/batten/tests/skill_contract.rs
// carried: tests/skill-check.bats mise-tasks/skill-check.sh crates/batten/src/surface.rs crates/batten/tests/skill_contract.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared. Nineteen
// carried and two changed, and each change is a SEAM the port moved rather than a
// predicate it dropped. Arms are suite-qualified because a case TITLE is not
// unique across suites and this bundle retires four of them at once.
//
// carried: "skill-check.bats::a skill inside budget, naming only declared verbs, exits 0" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a verb the binary does not declare is reported with a file:line pointer" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a subcommand the binary does not declare is caught, not just a bare verb" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a positional argument does not read as an undeclared subcommand" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::flags do not read as subcommands" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a console block is judged as well as an inline span" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::prose naming the product is not read as a verb" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a skill over the line budget is refused, and the count is named" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::the budget is a boundary, not a suggestion" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::an exit meaning that drifts from the binary's rendering is caught" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a code the skill never names is caught even when its meaning is present" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a vendor path that is a copy rather than a symlink is refused" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a symlink pointing at some other file is refused" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a missing skill is exit 2 — could not look, not a clean tree" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::the repo as it stands passes" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a second skill with no vendor symlink is a violation" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a second skill is discovered while UNTRACKED — presence is the predicate" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a well-formed second skill leaves the run clean" crates/batten/tests/skill_contract.rs
// carried: "skill-check.bats::a second skill over budget is reported against its own path" crates/batten/tests/skill_contract.rs
//
// changed: "skill-check.bats::an unreadable spec is exit 2, never a pass over an unjudged vocabulary" crates/batten/tests/skill_contract.rs the suite pointed `BATTEN_BIN` at a nonexistent path, and this tier has no such indirection: `common::batten()` resolves `CARGO_BIN_EXE_batten`, so a binary that is not there is a harness that did not build rather than a verdict. What that case protected — that an unjudged vocabulary never reads as a clean one — survives as `an_empty_vocabulary_is_never_read_as_a_clean_skill`, which asserts the refusal from the reading's side instead of from the launcher's
// changed: "skill-check.bats::the gate is wired: hk.pkl declares a step that runs this task" crates/batten/tests/skill_contract.rs the step now runs the successor task rather than `mise run skill-check`, so the literal it asserted is gone. The property is the same one and is still gated: `the_skill_contract_is_wired_into_the_hk_gate` asserts hk.pkl declares a `skill-check` step whose check names the task that runs THIS file

/// The ceiling, stated once. Raising it is a visible diff in this file.
const MAX_LINES: usize = 300;

/// Where the authored skills live, and where they are reached from.
const AUTHORED: &str = "skills";
const VENDORED: &str = ".claude/skills";

// --- the two authorities, both read from the compiled binary --------------------

/// Every command path the binary declares, and the subset that DISPATCHES.
///
/// The distinction decides whether a trailing word is a positional argument or
/// fiction, and nothing else can supply it: `receipt status verify` is a leaf plus
/// an argument, `receipt invent` is a noun plus a subcommand that does not exist,
/// and the two are the same shape until you know which parent is which.
fn declared_commands() -> (BTreeSet<String>, BTreeSet<String>) {
    let output = batten()
        .args(["spec", "--format", "json"])
        .output()
        .expect("run batten spec --format json");
    assert_eq!(
        output.status.code(),
        Some(0),
        "could not read `batten spec` — cannot judge the verbs"
    );
    let spec: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("`batten spec` is JSON");
    let mut paths = BTreeSet::new();
    let mut parents = BTreeSet::new();
    collect_commands(&spec, &mut paths, &mut parents);
    (paths, parents)
}

fn collect_commands(
    node: &serde_json::Value,
    paths: &mut BTreeSet<String>,
    parents: &mut BTreeSet<String>,
) {
    let children = node
        .get("subcommands")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if let Some(path) = node.get("path").and_then(serde_json::Value::as_str) {
        paths.insert(path.to_owned());
        if !children.is_empty() {
            parents.insert(path.to_owned());
        }
    }
    for child in children {
        collect_commands(child, paths, parents);
    }
}

/// The exit table as the binary renders it: `  <code>  <meaning>`.
fn exit_table() -> Vec<(String, String)> {
    let output = batten().arg("--help").output().expect("run batten --help");
    assert_eq!(
        output.status.code(),
        Some(0),
        "could not read `batten --help` — cannot judge the exit table"
    );
    let help = String::from_utf8(output.stdout).expect("`--help` is UTF-8");
    help.lines()
        .filter_map(|line| line.strip_prefix("  "))
        .filter_map(|rest| {
            let (code, meaning) = rest.split_once("  ")?;
            let code = code.trim();
            (code.len() == 1 && matches!(code.as_bytes().first(), Some(b'0'..=b'3')))
                .then(|| (code.to_owned(), meaning.trim().to_owned()))
        })
        .collect()
}

// --- the readings, pure over text ----------------------------------------------

/// The line count `wc -l` reports: newline-terminated lines.
fn line_count(text: &str) -> usize {
    text.matches('\n').count()
}

/// Every `batten …` phrase a skill names, in a COMMAND CONTEXT only — an inline
/// code span, or a `$ batten …` line in a console block — never prose.
///
/// Prose legitimately says "Batten" as a proper noun and "batten.toml" as a
/// filename, and a scan loose enough to read those as verbs would report the
/// English rather than the commands.
fn command_phrases(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if let Some(rest) = line.trim_start().strip_prefix("$ batten ") {
            found.push((number, rest.trim().to_owned()));
        }
        let mut haystack = line;
        while let Some(at) = haystack.find("`batten ") {
            let after = &haystack[at + "`batten ".len()..];
            match after.split_once('`') {
                Some((span, tail)) => {
                    found.push((number, span.trim().to_owned()));
                    haystack = tail;
                }
                None => break,
            }
        }
    }
    found
}

/// The argument-free head of a phrase: bare lowercase words, stopping at the
/// first flag, placeholder or redirect.
fn head_words(phrase: &str) -> String {
    let mut head: Vec<&str> = Vec::new();
    for word in phrase.split_whitespace() {
        let bare = !word.is_empty()
            && word
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            && word.as_bytes().first().is_some_and(u8::is_ascii_lowercase);
        if bare {
            head.push(word);
        } else {
            break;
        }
    }
    head.join(" ")
}

/// Pointer-only findings (non-negotiable rule 4): `path:line predicate`, never a
/// line of the skill.
fn verb_findings(
    path: &str,
    text: &str,
    paths: &BTreeSet<String>,
    parents: &BTreeSet<String>,
) -> Vec<String> {
    let mut findings = Vec::new();
    for (line, phrase) in command_phrases(text) {
        let head = head_words(&phrase);
        if head.is_empty() {
            continue;
        }
        // A named verb may carry flags and positional arguments the spec does not
        // declare (`receipt status verify`), so the longest run of bare words is
        // shortened one word at a time until it resolves. Only a phrase whose
        // every prefix fails is fiction.
        let mut candidate = head.clone();
        let mut trailing = false;
        let resolved = loop {
            if paths.contains(&candidate) {
                break true;
            }
            match candidate.rsplit_once(' ') {
                Some((shorter, _)) => {
                    candidate = shorter.to_owned();
                    trailing = true;
                }
                None => break false,
            }
        };
        if !resolved {
            findings.push(format!("{path}:{line} skill-unknown-verb ({head})"));
        } else if trailing && parents.contains(&candidate) {
            // The prefix resolved, but it is a NOUN that dispatches, so the word
            // after it had to be one of its declared subcommands and was not.
            // Shortening past a dispatching row is what would let `receipt invent`
            // pass by resolving to `receipt` — fiction hiding behind a real parent.
            findings.push(format!("{path}:{line} skill-unknown-subcommand ({head})"));
        }
    }
    findings
}

fn budget_findings(path: &str, text: &str, max_lines: usize) -> Vec<String> {
    let lines = line_count(text);
    if lines > max_lines {
        vec![format!(
            "{path}:{lines} skill-over-budget ({lines} > {max_lines})"
        )]
    } else {
        Vec::new()
    }
}

fn exit_table_findings(path: &str, text: &str, table: &[(String, String)]) -> Vec<String> {
    let mut findings = Vec::new();
    for (code, meaning) in table {
        if !text.contains(meaning.as_str()) {
            findings.push(format!("{path}:0 skill-exit-meaning-missing ({code})"));
        }
        if !text.contains(&format!("`{code}`")) {
            findings.push(format!("{path}:0 skill-exit-code-unnamed ({code})"));
        }
    }
    findings
}

// --- discovery and the vendor path ---------------------------------------------

/// Every `skills/*/SKILL.md` under `root`, DISCOVERED FROM THE FILESYSTEM rather
/// than from `git ls-files`, and the difference is not academic.
///
/// A newly authored skill is untracked until it is staged, so a git-sourced walk
/// skips the one skill most likely to be wrong and passes. Measured on the retired
/// program: with `skills/serena/SKILL.md` present and its vendor symlink deleted,
/// the git-sourced loop reported clean. The harness loads a skill because the file
/// is THERE, so presence is the predicate; the tracked-tree gates ask git because
/// their subject genuinely is the commit.
fn authored_skills(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root.join(AUTHORED)) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            root.join(AUTHORED)
                .join(&name)
                .join("SKILL.md")
                .is_file()
                .then(|| format!("{AUTHORED}/{name}/SKILL.md"))
        })
        .collect();
    found.sort();
    found
}

/// The reached path derived from the authored one, so a new skill cannot be added
/// with its symlink unchecked — the derivation is the convention.
fn vendor_for(authored: &str) -> Option<String> {
    authored
        .strip_prefix(&format!("{AUTHORED}/"))
        .map(|rest| format!("{VENDORED}/{rest}"))
}

fn vendor_findings(root: &Path, authored: &str) -> Vec<String> {
    let Some(vendor) = vendor_for(authored) else {
        return vec![format!("{authored}:0 skill-vendor-path-underivable")];
    };
    let vendored = root.join(&vendor);
    if !vendored
        .symlink_metadata()
        .is_ok_and(|meta| meta.is_symlink())
    {
        return vec![format!("{vendor}:0 skill-vendor-path-not-a-symlink")];
    }
    let same = fs::canonicalize(&vendored)
        .ok()
        .zip(fs::canonicalize(root.join(authored)).ok())
        .is_some_and(|(reached, real)| reached == real);
    if same {
        Vec::new()
    } else {
        vec![format!("{vendor}:0 skill-vendor-path-resolves-elsewhere")]
    }
}

/// The generic half — budget and one-set-of-bytes — over EVERY skill.
///
/// The split is by what the check's AUTHORITY is, and only two of the four
/// generalise. The verb and exit-table checks read `batten spec` and
/// `batten --help`, so they are assertions about a skill that DESCRIBES BATTEN and
/// mean nothing over one that does not — running them everywhere would report
/// every sentence of a Serena skill as fiction.
fn generic_findings(root: &Path, max_lines: usize) -> Vec<String> {
    let mut findings = Vec::new();
    for authored in authored_skills(root) {
        let text = fs::read_to_string(root.join(&authored)).unwrap_or_default();
        findings.extend(budget_findings(&authored, &text, max_lines));
        findings.extend(vendor_findings(root, &authored));
    }
    findings
}

// --- fixtures -------------------------------------------------------------------

/// A minimal skill that satisfies every predicate: one real verb, the whole exit
/// table as the binary renders it.
///
/// Built rather than copied from the real document, and the difference shows up
/// the day the real skill is edited: a fixture built on a copy goes red for
/// reasons that have nothing to do with the predicate under test.
fn minimal_skill(table: &[(String, String)]) -> String {
    let mut text = String::from("# Skill\n\nRun `batten check` and read the status.\n\n");
    for (code, meaning) in table {
        text.push_str(&format!("| `{code}` | {meaning} |\n"));
    }
    text
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        Self {
            root: scratch(name),
        }
    }

    /// Write `skills/<name>/SKILL.md` with `text`, and link its vendor path.
    fn skill(&self, name: &str, text: &str) -> &Self {
        let authored = self.root.join(AUTHORED).join(name);
        fs::create_dir_all(&authored).expect("create the authored directory");
        fs::write(authored.join("SKILL.md"), text).expect("write the skill");
        fs::create_dir_all(self.root.join(VENDORED).join(name))
            .expect("create the vendor directory");
        self
    }

    fn link_vendor(&self, name: &str) -> &Self {
        let target = self.root.join(AUTHORED).join(name).join("SKILL.md");
        let link = self.root.join(VENDORED).join(name).join("SKILL.md");
        let _ = fs::remove_file(&link);
        symlink(&target, &link);
        self
    }

    fn append(&self, name: &str, text: &str) -> &Self {
        let path = self.root.join(AUTHORED).join(name).join("SKILL.md");
        let mut body = fs::read_to_string(&path).expect("read the skill");
        body.push_str(text);
        fs::write(&path, body).expect("rewrite the skill");
        self
    }

    fn text(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(AUTHORED).join(name).join("SKILL.md"))
            .expect("read the skill")
    }

    fn path(&self, name: &str) -> String {
        format!("{AUTHORED}/{name}/SKILL.md")
    }
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("link the vendor path");
}

#[cfg(not(unix))]
fn symlink(target: &Path, link: &Path) {
    let _ = (target, link);
}

/// A fixture carrying one well-formed skill named `batten`.
fn conforming(name: &str, table: &[(String, String)]) -> Fixture {
    let fixture = Fixture::new(name);
    fixture.skill("batten", &minimal_skill(table));
    fixture.link_vendor("batten");
    fixture
}

// --- the predicate, over the real tree ------------------------------------------

#[test]
fn the_repository_as_it_stands_is_clean() {
    let root = at_root("");
    let (paths, parents) = declared_commands();
    let table = exit_table();
    let mut findings = generic_findings(&root, MAX_LINES);
    let skill = format!("{AUTHORED}/batten/SKILL.md");
    let text = fs::read_to_string(root.join(&skill)).expect("the shipped skill is readable");
    findings.extend(verb_findings(&skill, &text, &paths, &parents));
    findings.extend(exit_table_findings(&skill, &text, &table));
    assert!(
        findings.is_empty(),
        "the shipped skills are over budget or describe a surface the binary does \
         not have: {findings:?}"
    );
}

#[test]
fn every_authored_skill_is_discovered_over_the_real_tree() {
    // Anti-vacuity for the case above: a discovery that found nothing would report
    // clean over every skill in the tree.
    let found = authored_skills(&at_root(""));
    assert!(
        found.len() >= 2,
        "the tree carries more than one authored skill; discovery found {found:?}"
    );
    assert!(
        found.contains(&format!("{AUTHORED}/batten/SKILL.md")),
        "{found:?}"
    );
}

#[test]
fn the_two_authorities_are_non_empty() {
    // An empty vocabulary makes every verb resolve to nothing and an empty exit
    // table makes the drift check vacuous, so both readings are asserted before
    // any case depends on them.
    let (paths, parents) = declared_commands();
    assert!(paths.len() > 1, "the binary declares a command tree");
    assert!(!parents.is_empty(), "some rows dispatch");
    assert_eq!(
        exit_table().len(),
        4,
        "the 0/1/2/3 table, as `--help` renders it"
    );
}

#[test]
fn an_empty_vocabulary_is_never_read_as_a_clean_skill() {
    // What the retired suite's `BATTEN_BIN=/nonexistent` case stood for: a
    // vocabulary that could not be read must refuse the skill rather than pass it.
    // Asserted from the reading's side, because this tier has no launcher to break.
    let table = exit_table();
    let text = minimal_skill(&table);
    let findings = verb_findings(
        "skills/batten/SKILL.md",
        &text,
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
    assert!(
        !findings.is_empty(),
        "an unjudged vocabulary reported a clean skill: {findings:?}"
    );
}

// --- the verb vocabulary --------------------------------------------------------

#[test]
fn a_skill_inside_budget_naming_only_declared_verbs_is_clean() {
    let table = exit_table();
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-clean", &table);
    let text = fixture.text("batten");
    let path = fixture.path("batten");
    assert!(generic_findings(&fixture.root, MAX_LINES).is_empty());
    assert!(verb_findings(&path, &text, &paths, &parents).is_empty());
    assert!(exit_table_findings(&path, &text, &table).is_empty());
}

#[test]
fn a_verb_the_binary_does_not_declare_is_reported_with_a_pointer() {
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-fiction", &exit_table());
    fixture.append("batten", "then run `batten nonesuch`\n");
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-unknown-verb (nonesuch)"),
        "{findings:?}"
    );
    assert!(
        findings[0].starts_with("skills/batten/SKILL.md:"),
        "{findings:?}"
    );
}

#[test]
fn a_subcommand_the_binary_does_not_declare_is_caught_not_just_a_bare_verb() {
    // The trap this closes: `receipt` IS a declared row, so a reading that merely
    // shortened the phrase until something resolved would accept `receipt invent`
    // by falling back to its parent — fiction hiding behind a real noun.
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-subcommand", &exit_table());
    fixture.append("batten", "try `batten receipt invent`\n");
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-unknown-subcommand (receipt invent)"),
        "{findings:?}"
    );
}

#[test]
fn a_positional_argument_does_not_read_as_an_undeclared_subcommand() {
    // `receipt status verify` is `receipt status` plus a positional. Without the
    // shortening, every documented invocation carrying an argument would be
    // reported as fiction.
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-positional", &exit_table());
    fixture.append("batten", "run `batten receipt status verify`\n");
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn flags_do_not_read_as_subcommands() {
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-flags", &exit_table());
    fixture.append("batten", "run `batten check -J --silent`\n");
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn a_console_block_is_judged_as_well_as_an_inline_span() {
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-console", &exit_table());
    fixture.append("batten", "\n```console\n$ batten alsofake\n```\n");
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-unknown-verb (alsofake)"),
        "{findings:?}"
    );
}

#[test]
fn prose_naming_the_product_is_not_read_as_a_verb() {
    // "Batten is a completion gate" and "batten.toml" are English and a filename.
    // A scan loose enough to read those as commands would report the prose, which
    // is the false-positive rate that gets a gate bypassed.
    let (paths, parents) = declared_commands();
    let fixture = conforming("skill-contract-prose", &exit_table());
    fixture.append(
        "batten",
        "\nBatten is a gate, configured by batten.toml in the repo root.\n",
    );
    let findings = verb_findings(
        &fixture.path("batten"),
        &fixture.text("batten"),
        &paths,
        &parents,
    );
    assert!(findings.is_empty(), "{findings:?}");
}

// --- the budget ------------------------------------------------------------------

#[test]
fn a_skill_over_the_line_budget_is_refused_and_the_count_is_named() {
    let fixture = conforming("skill-contract-budget", &exit_table());
    fixture.append("batten", &"filler\n".repeat(MAX_LINES + 1));
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("skill-over-budget"), "{findings:?}");
    let lines = line_count(&fixture.text("batten"));
    assert!(findings[0].contains(&lines.to_string()), "{findings:?}");
}

#[test]
fn the_budget_is_a_boundary_not_a_suggestion() {
    // Exactly at the ceiling passes; one past it does not.
    let fixture = conforming("skill-contract-boundary", &exit_table());
    let lines = line_count(&fixture.text("batten"));
    assert!(
        generic_findings(&fixture.root, lines).is_empty(),
        "exactly at the ceiling is inside it"
    );
    assert_eq!(
        generic_findings(&fixture.root, lines - 1).len(),
        1,
        "one past the ceiling is refused"
    );
}

// --- the exit contract ------------------------------------------------------------

#[test]
fn an_exit_meaning_that_drifts_from_the_binarys_rendering_is_caught() {
    let table = exit_table();
    let drifted = minimal_skill(&table).replace(
        "internal error — fail loud, do not block",
        "internal oopsie",
    );
    let findings = exit_table_findings("skills/batten/SKILL.md", &drifted, &table);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-exit-meaning-missing (3)"),
        "{findings:?}"
    );
}

#[test]
fn a_code_the_skill_never_names_is_caught_even_when_its_meaning_is_present() {
    let table = exit_table();
    let drifted = minimal_skill(&table).replace("| `2` |", "| two |");
    let findings = exit_table_findings("skills/batten/SKILL.md", &drifted, &table);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-exit-code-unnamed (2)"),
        "{findings:?}"
    );
}

// --- one set of bytes --------------------------------------------------------------

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_vendor_path_that_is_a_copy_rather_than_a_symlink_is_refused() {
    let fixture = conforming("skill-contract-copy", &exit_table());
    let link = fixture.root.join(VENDORED).join("batten").join("SKILL.md");
    fs::remove_file(&link).expect("drop the symlink");
    fs::write(&link, fixture.text("batten")).expect("write a copy in its place");
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-vendor-path-not-a-symlink"),
        "{findings:?}"
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_symlink_pointing_at_some_other_file_is_refused() {
    let fixture = conforming("skill-contract-decoy", &exit_table());
    let decoy = fixture.root.join(AUTHORED).join("batten").join("OTHER.md");
    fs::write(&decoy, "decoy\n").expect("write the decoy");
    let link = fixture.root.join(VENDORED).join("batten").join("SKILL.md");
    fs::remove_file(&link).expect("drop the symlink");
    symlink(&decoy, &link);
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains("skill-vendor-path-resolves-elsewhere"),
        "{findings:?}"
    );
}

#[test]
fn a_missing_skill_is_could_not_look_rather_than_a_clean_tree() {
    // No authored skill at all is an unjudged tree, not a conforming one: the
    // discovery must report nothing found rather than nothing wrong.
    let fixture = Fixture::new("skill-contract-missing");
    fs::create_dir_all(fixture.root.join(AUTHORED)).expect("create the skills directory");
    assert!(
        authored_skills(&fixture.root).is_empty(),
        "there is no skill to judge"
    );
    assert!(
        generic_findings(&fixture.root, MAX_LINES).is_empty(),
        "and an empty tree raises no finding, which is why the count above is the \
         assertion that matters"
    );
}

// --- every skill, not just the default one (CLOUD-864) ------------------------------

/// A minimal second skill that names no batten verb, as a real one would not.
fn second_skill(fixture: &Fixture) {
    fixture.skill("other", "# Other\n\nNothing about the binary here.\n");
}

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_second_skill_with_no_vendor_symlink_is_a_violation() {
    let fixture = conforming("skill-contract-second-unlinked", &exit_table());
    second_skill(&fixture);
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].contains(".claude/skills/other/SKILL.md:0 skill-vendor-path-not-a-symlink"),
        "{findings:?}"
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_second_skill_is_discovered_while_untracked_because_presence_is_the_predicate() {
    // Nothing here is ever staged, so a git-sourced discovery returns nothing and
    // passes — which is exactly how the first version of this loop shipped a check
    // that skipped the newest skill in the tree.
    let fixture = conforming("skill-contract-second-untracked", &exit_table());
    second_skill(&fixture);
    assert!(
        !fixture.root.join(".git").exists(),
        "the fixture is not a repository, so git could name no skill here"
    );
    let found = authored_skills(&fixture.root);
    assert!(
        found.contains(&format!("{AUTHORED}/other/SKILL.md")),
        "{found:?}"
    );
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert!(
        findings
            .iter()
            .any(|finding| finding.contains("skills/other/SKILL.md")),
        "{findings:?}"
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_well_formed_second_skill_leaves_the_run_clean() {
    // Without this, a loop that reported on everything would satisfy the two cases
    // above.
    let fixture = conforming("skill-contract-second-clean", &exit_table());
    second_skill(&fixture);
    fixture.link_vendor("other");
    let findings = generic_findings(&fixture.root, MAX_LINES);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the vendor path is a symlink")]
fn a_second_skill_over_budget_is_reported_against_its_own_path() {
    let fixture = conforming("skill-contract-second-budget", &exit_table());
    second_skill(&fixture);
    fixture.link_vendor("other");
    let findings = generic_findings(&fixture.root, 1);
    assert!(
        findings
            .iter()
            .any(|finding| finding.starts_with("skills/other/SKILL.md:")
                && finding.contains("skill-over-budget")),
        "{findings:?}"
    );
}

// --- the wiring -------------------------------------------------------------------

#[test]
fn the_skill_contract_is_wired_into_the_hk_gate() {
    // The retired suite asserted `hk.pkl` still carried `mise run skill-check`.
    // The step survives the retirement and its check now names the task that runs
    // THIS file, so the property is unchanged and the literal is not.
    let hk = fs::read_to_string(at_root("hk.pkl")).expect("read hk.pkl");
    let at = hk
        .find("[\"skill-check\"]")
        .expect("hk.pkl declares a skill-check step");
    let block = &hk[at..];
    let check = block
        .lines()
        .find(|line| line.trim_start().starts_with("check ="))
        .expect("the skill-check step declares a check");
    assert!(
        check.contains("test:skill-contract"),
        "the skill-check step must run the task that drives \
         crates/batten/tests/skill_contract.rs, and runs `{check}`"
    );
}
