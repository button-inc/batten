//! `batten mutate` over the compiled binary (CLOUD-418, CLOUD-1267).
//!
//! # What this file is the successor to
//!
//! `tests/mutant.bats` and `tests/mutant-census.bats`, whose subjects —
//! `mise-tasks/mutant.sh` and `mise-tasks/mutant-census.sh` — this change
//! deletes. Every case below builds a throwaway repository with one toy gate and
//! one toy suite, because the subject here is the HARNESS, not any real gate's
//! coverage: running it against the live enforced set would make this file's
//! verdict a function of whichever gate someone edited last, which is the
//! opposite of a decision table.
//!
//! # The case the port exists for
//!
//! `a_declared_rust_suite_is_reddened_by_a_mutation_on_the_module` is
//! CLOUD-1267 in one assertion. The predecessor resolved a gate's suite as
//! `tests/<gate>.bats` unconditionally, so a mutation on a `.rego` module had
//! nothing that could turn red and the runner answered `no-suite`. That fixture
//! is a policy module, a `#MUTANT-SUITE` naming a Rust tier, and a mutation the
//! tier catches — the shape 29 exemptions said was unreachable.
//!
//! Its mirror is `a_module_whose_tier_cannot_see_it_reports_a_survivor`, and the
//! pair is what makes either evidence: a runner that reported `caught` for
//! everything would pass the first and fail the second.
//!
//! # Why `git` and `bats` and `cargo` are real here
//!
//! The repository is local and instant, and stubbing any of the three would test
//! the stub. The Rust-tier fixture is a single package with no dependencies, so
//! its `cargo test` compiles in seconds against a target directory of its own.

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Their grammar is disjoint
// from CLOUD-908's case arms below by construction: a case arm's first field
// after the marker is a QUOTED case name, and a file arm's is a path.
//
// carried: mise-tasks/mutant.sh crates/batten/src/mutate.rs kind:verb crates/batten/tests/mutate.rs
// carried: tests/mutant.bats crates/batten/src/mutate.rs kind:verb crates/batten/tests/mutate.rs
// carried: mise-tasks/mutant-census.sh crates/batten/src/mutate.rs kind:verb crates/batten/tests/mutate.rs
// carried: tests/mutant-census.bats crates/batten/src/mutate.rs kind:verb crates/batten/tests/mutate.rs

// THE CASE ARMS (CLOUD-908). One per `@test` the two dying suites declared.
//
// carried: "mutant.bats::a mutation its suite catches is a pass" crates/batten/tests/mutate.rs
// carried: "mutant.bats::THE DEFECT: a mutation the suite does NOT catch fails" crates/batten/tests/mutate.rs
// carried: "mutant.bats::A ROW IS EXACTLY THREE FIELDS, and a fourth is refused before the split" crates/batten/tests/mutate.rs
// carried: "mutant.bats::A FILTER THAT SELECTS THE WHOLE SUITE names no case, like one that selects none" crates/batten/tests/mutate.rs
// carried: "mutant.bats::a filter selecting one case of a single-case suite is not read as too wide" crates/batten/tests/mutate.rs
// carried: "mutant.bats::THE TREE IS RESTORED BETWEEN ROWS, so a gate is judged against a pristine sibling" crates/batten/tests/mutate.rs
// carried: "mutant.bats::A ROW THAT MUTATES ITS OWN DECLARATION is refused, not reported as a survivor" crates/batten/tests/mutate.rs
// carried: "mutant.bats::THE COPY IS A REPOSITORY, so a suite that resolves its own root answers about it" crates/batten/tests/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a listed gate with NO declaration fails, rather than being skipped" crates/batten/tests/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a filter naming no case is not a pass" crates/batten/tests/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a mutation that changes nothing is not a pass" crates/batten/tests/mutate.rs
// carried: "mutant.bats::an unset enforced set is fatal rather than an empty one" crates/batten/tests/mutate.rs
// changed: "mutant.bats::a gate named with no suite is reported, not silently passed" crates/batten/tests/mutate.rs the verdict is unchanged and its EXIT CODE is not: could-not-look is exit 3 where the predecessor answered 1, which is the acceptance CLOUD-1267 states
// carried: "mutant.bats::POINTER, NEVER PAYLOAD: the report carries no line of the mutated source" crates/batten/tests/mutate.rs
// carried: "mutant.bats::the tracked file is never mutated in place" crates/batten/tests/mutate.rs
// carried: "mutant.bats::an UNCOMMITTED case is still covered — the working tree is the subject" crates/batten/tests/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a case that is red BEFORE the mutation is not evidence" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::a gate named in the set is a closed census" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::THE DEFECT: a gate the set omits is uncovered, and named" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::a task that does not describe itself as a gate owes no mutation" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::a hook body is a gate too — it decides by emitting a deny" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::a policy module is censused unconditionally, so a migration cannot shrink the set" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::a filed exemption is a closed census, not a gap" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::an exemption naming no issue is unfiled — the whole difference from a TODO" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::an exemption with no reason is unfiled as well" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::declared AND exempt is refused — the reason would be a dead letter" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::THE REVERSE DIRECTION: a name in the set resolving to no gate is refused" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::an unset set is could-not-look, never a closed census" crates/batten/tests/mutate.rs
// changed: "mutant-census.bats::ANTI-VACUITY: a tree resolving no gate at all is exit 2, not perfect coverage" crates/batten/tests/mutate.rs an empty subject set is no longer a separate refusal: the census reports the reverse direction instead, so a set naming gates over a tree holding none is `names-no-subject` per name rather than one unreadable verdict about the tree
// carried: "mutant-census.bats::output is pointer-only — the exemption's reason never reaches the log" crates/batten/tests/mutate.rs
// carried: "mutant-census.bats::this repository's own census is closed — the gate on the real tree" crates/batten/tests/mutate.rs

// THE FIXTURE CASES. The dying suites wrote a toy suite inside a heredoc, so
// these `@test` lines are the SUBJECT a case exercised rather than a case of the
// suite itself — and the counter cannot tell the two apart, which is right: a
// fixture case deleted with nothing carrying it is coverage lost either way.
// They travel into `TOY_SUITE` and `RUST_SUITE` here, exercised by every case
// that builds a toy repository.
//
// carried: "mutant.bats::over the limit is refused" crates/batten/tests/mutate.rs
// carried: "mutant.bats::under the limit passes" crates/batten/tests/mutate.rs
// carried: "mutant.bats::the sibling answers strict" crates/batten/tests/mutate.rs
// carried: "mutant.bats::the composer refuses under a strict sibling" crates/batten/tests/mutate.rs
// carried: "mutant.bats::over the limit is refused, from a root the suite resolves itself" crates/batten/tests/mutate.rs
// carried: "mutant.bats::an uncommitted case is exercised" crates/batten/tests/mutate.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{stderr, stdout};

// ---------------------------------------------------------------------------
// The fixtures.
// ---------------------------------------------------------------------------

/// A toy gate with one real decision. `LIMIT` is what a mutation moves.
const TOY_GATE: &str = r#"#!/usr/bin/env bash
#MISE description="Gate: the toy"
set -uo pipefail
LIMIT=10
[ "${1:-0}" -le "$LIMIT" ] || exit 1
exit 0
"#;

/// Two cases, so a filter can name one of them and `total > 1` holds.
const TOY_SUITE: &str = r#"#!/usr/bin/env bats
@test "over the limit is refused" {
	run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 99
	[ "$status" -eq 1 ]
}
@test "under the limit passes" {
	run "$BATS_TEST_DIRNAME/../mise-tasks/toy.sh" 1
	[ "$status" -eq 0 ]
}
"#;

/// The mutation the toy suite catches: the gate stops refusing anything.
const CAUGHT: &str = "#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|over the limit";

/// A wiped scratch repository.
fn toy(name: &str) -> PathBuf {
    let root = common::scratch(&format!("mutate-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    root
}

fn write(root: &Path, path: &str, body: &str) {
    common::write(root, path, body);
}

/// Write an executable program.
fn write_program(root: &Path, path: &str, body: &str) {
    common::write(root, path, body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o755))
            .expect("make the toy gate executable");
    }
}

/// Track everything written so far. The staged tree is the TRACKED set, so a
/// fixture that skipped this would be staging nothing.
fn track(root: &Path) {
    common::git_in(root, &["add", "-A"]);
}

/// Borrow this repository's vendored bats submodule rather than checking out a
/// second copy: it is the same binary either way.
fn lend_bats(root: &Path) {
    fs::create_dir_all(root.join("tests")).expect("scratch tests dir");
    let link = root.join("tests/bats");
    // A stale lend is a directory on one path and a symlink on the other, and
    // `remove_dir_all` refuses the second — so clear both spellings.
    let _ = fs::remove_dir_all(&link);
    let _ = fs::remove_file(&link);
    // The resolved source is read only where a symlink can be made, or it is a
    // binding no arm consumes and `-D warnings` is right to refuse it.
    #[cfg(unix)]
    {
        let real = common::at_root("tests/bats")
            .canonicalize()
            .expect("the vendored runner is where the manifest says it is");
        std::os::unix::fs::symlink(real, link).expect("lend the runner");
    }
}

/// A toy repository carrying one gate, one suite and the declared rows.
fn toy_repo(name: &str, rows: &[&str]) -> PathBuf {
    let root = toy(name);
    let mut gate = String::from(TOY_GATE);
    for row in rows {
        gate.push_str(row);
        gate.push('\n');
    }
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(&root, "tests/toy.bats", TOY_SUITE);
    track(&root);
    lend_bats(&root);
    root
}

/// Run a verb of `mutate` in `root` with the enforced set `gates`.
fn run(root: &Path, verb: &str, gates: &str) -> (i32, String, String) {
    let answer = common::batten()
        .args(["mutate", verb])
        .current_dir(root)
        .env("MUTANT_GATES", gates)
        .output()
        .expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

fn sweep(root: &Path, gates: &str) -> (i32, String, String) {
    run(root, "sweep", gates)
}

fn census(root: &Path, gates: &str) -> (i32, String, String) {
    run(root, "census", gates)
}

// ---------------------------------------------------------------------------
// The sweep's decision table.
// ---------------------------------------------------------------------------

#[test]
fn a_mutation_its_suite_catches_is_a_pass() {
    let root = toy_repo("caught", &[CAUGHT]);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[test]
fn the_defect_a_mutation_the_suite_does_not_catch_fails() {
    // The mutation moves a line no case exercises, so the suite stays green.
    let root = toy_repo(
        "survivor",
        &["#MUTANT unwatched|s/^exit 0$/exit 0 # unwatched/|over the limit"],
    );
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
}

#[test]
fn a_row_is_exactly_three_fields_and_a_fourth_is_refused_before_the_split() {
    let root = toy_repo("malformed", &["#MUTANT five|s/a|b/|and|the case", CAUGHT]);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("malformed-row"), "{out}");
    assert!(out.contains("5 fields, want 3"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

#[test]
fn a_filter_that_selects_the_whole_suite_names_no_case_like_one_that_selects_none() {
    // `the limit` is a substring of BOTH case names, so the row stops naming a
    // case and redness under mutation could come from anywhere in the suite.
    let root = toy_repo(
        "wide-filter",
        &["#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|the limit"],
    );
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("filter-names-every-case"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

#[test]
fn a_filter_selecting_one_case_of_a_single_case_suite_is_not_read_as_too_wide() {
    // The guard on the false positive above: with one case, selecting it is the
    // only thing a filter can do.
    let root = toy("single-case");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.bats",
        "#!/usr/bin/env bats\n@test \"over the limit is refused\" {\n\trun \
         \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 99\n\t[ \"$status\" -eq 1 ]\n}\n",
    );
    track(&root);
    lend_bats(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[test]
fn the_tree_is_restored_between_rows_so_a_gate_is_judged_against_a_pristine_sibling() {
    // A composer whose verdict depends on a sibling's answer. Without the
    // restore the sibling's mutant is still in place when the composer is
    // judged, and the survivor reported changes with the sweep ORDER.
    let root = toy("restore");
    write_program(&root, "mise-tasks/sibling.sh", TOY_GATE);
    write(
        &root,
        "tests/sibling.bats",
        &TOY_SUITE.replace("toy.sh", "sibling.sh"),
    );
    let mut sibling = String::from(TOY_GATE);
    sibling.push_str("#MUTANT sibling-limit|s/^LIMIT=10$/LIMIT=999/|over the limit\n");
    write_program(&root, "mise-tasks/sibling.sh", &sibling);

    // The mutation is `|`-free and anchored on a line carrying no `$`, so the
    // three-field rule and sed's own metacharacters both stay out of the way.
    let composer = r#"#!/usr/bin/env bash
#MISE description="Gate: the composer"
set -uo pipefail
DELEGATE=1
if [ "${DELEGATE}" = 1 ]; then
	"$(dirname "$0")/sibling.sh" "${1:-0}" || exit 1
fi
exit 0
#MUTANT composer-delegates|s@^DELEGATE=1$@DELEGATE=0@|over the limit
"#;
    write_program(&root, "mise-tasks/composer.sh", composer);
    write(
        &root,
        "tests/composer.bats",
        &TOY_SUITE.replace("toy.sh", "composer.sh"),
    );
    track(&root);
    lend_bats(&root);

    let (code, out, err) = sweep(&root, "sibling,composer");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[test]
fn a_row_that_mutates_its_own_declaration_is_refused_not_reported_as_a_survivor() {
    // A pattern spelled literally matches its own declaration line, so the file
    // changes, the gate's behaviour does not, and the mutation survives every
    // run while reading as enforced coverage.
    let root = toy_repo(
        "self-mutating",
        &["#MUTANT self|s/MUTANT self/MUTANT other/|over the limit"],
    );
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("self-mutating-row"), "{out}");
    assert!(!out.contains("SURVIVED"), "{out}");
}

#[test]
fn the_copy_is_a_repository_so_a_suite_that_resolves_its_own_root_answers_about_it() {
    let root = toy("is-a-repo");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.bats",
        "#!/usr/bin/env bats\n@test \"over the limit is refused\" {\n\trun git rev-parse \
         --show-toplevel\n\t[ \"$status\" -eq 0 ]\n\trun \
         \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 99\n\t[ \"$status\" -eq 1 ]\n}\n@test \"under \
         the limit passes\" {\n\trun \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 1\n\t[ \"$status\" \
         -eq 0 ]\n}\n",
    );
    track(&root);
    lend_bats(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert!(!out.contains("case-already-red"), "{out}");
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn anti_vacuity_a_listed_gate_with_no_declaration_fails_rather_than_being_skipped() {
    let root = toy_repo("no-declaration", &[]);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("no-mutant-declared"), "{out}");
}

#[test]
fn anti_vacuity_a_filter_naming_no_case_is_not_a_pass() {
    let root = toy_repo(
        "no-case",
        &["#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|no case is named this"],
    );
    let (code, out, _) = sweep(&root, "toy");
    // Could-not-look, and it is exit 3 rather than the verdict class.
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("names-no-case"), "{out}");
}

#[test]
fn anti_vacuity_a_mutation_that_changes_nothing_is_not_a_pass() {
    let root = toy_repo(
        "inert",
        &["#MUTANT inert|s/^NOTHING_MATCHES_THIS$/x/|over the limit"],
    );
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("inert-mutation"), "{out}");
}

#[test]
fn an_unset_enforced_set_is_fatal_rather_than_an_empty_one() {
    let root = toy_repo("unset", &[CAUGHT]);
    let (code, _, err) = sweep(&root, "");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("MUTANT_GATES is unset"), "{err}");
}

#[test]
fn a_gate_named_with_no_suite_is_reported_and_is_could_not_look() {
    // CHANGED FROM THE PREDECESSOR, deliberately: the verdict is the same and
    // its exit code is not. `no-suite` says the runner could not look, which
    // CLOUD-1267 requires to stay distinguishable from "every mutation caught"
    // — and from a survivor, which is a verdict about the tree.
    let root = toy("no-suite");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    track(&root);
    lend_bats(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("no-suite"), "{out}");
}

#[test]
fn a_name_resolving_to_nothing_is_no_such_gate() {
    let root = toy_repo("ghost", &[CAUGHT]);
    let (code, out, _) = sweep(&root, "ghost");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("no-such-gate"), "{out}");
}

#[test]
fn pointer_never_payload_the_report_carries_no_line_of_the_mutated_source() {
    let root = toy_repo(
        "pointer",
        &["#MUTANT leak|s/^exit 0$/SECRETMARKER=1/|over the limit"],
    );
    let (_, out, err) = sweep(&root, "toy");
    assert!(!out.contains("SECRETMARKER"), "{out}");
    assert!(!err.contains("SECRETMARKER"), "{err}");
}

#[test]
fn the_tracked_file_is_never_mutated_in_place() {
    let root = toy_repo("in-place", &[CAUGHT]);
    let before = common::git_in(&root, &["hash-object", "mise-tasks/toy.sh"]);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    let after = common::git_in(&root, &["hash-object", "mise-tasks/toy.sh"]);
    assert_eq!(before, after, "the tracked gate must not be corrupted");
}

#[test]
fn an_uncommitted_case_is_still_covered_because_the_working_tree_is_the_subject() {
    let root = toy_repo("uncommitted", &[CAUGHT]);
    common::git_in(&root, &["commit", "-m", "base"]);
    // A case added and staged but never committed. `git archive HEAD` would not
    // see it, and every mutation naming it would report `names-no-case`.
    write(
        &root,
        "tests/toy.bats",
        &format!(
            "{TOY_SUITE}@test \"a third case, uncommitted\" {{\n\trun \
             \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 0\n\t[ \"$status\" -eq 0 ]\n}}\n"
        ),
    );
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
}

#[test]
fn anti_vacuity_a_case_that_is_red_before_the_mutation_is_not_evidence() {
    let root = toy("already-red");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.bats",
        "#!/usr/bin/env bats\n@test \"over the limit is refused\" {\n\trun \
         \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 99\n\t[ \"$status\" -eq 99 ]\n}\n@test \"under \
         the limit passes\" {\n\trun \"$BATS_TEST_DIRNAME/../mise-tasks/toy.sh\" 1\n\t[ \"$status\" \
         -eq 0 ]\n}\n",
    );
    track(&root);
    lend_bats(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("case-already-red"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

// ---------------------------------------------------------------------------
// The declared suite, which is the whole of CLOUD-1267.
// ---------------------------------------------------------------------------

/// A single-package repository whose gate is a policy module and whose suite is
/// a compiled-binary tier that reads it.
///
/// No dependencies, so the compile is seconds and the target directory is its
/// own — which is also what proves the sweep runs `cargo` inside the STAGED
/// tree: a run against the source tree would read the unmutated module.
fn rust_tier_repo(name: &str, limit_in_tier: &str) -> PathBuf {
    let root = toy(name);
    write(
        &root,
        "Cargo.toml",
        // `[workspace]` is load-bearing: the scratch root lives under this
        // crate's own `target/`, so without it cargo resolves the enclosing
        // workspace and refuses the package as an unlisted member.
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lib]\npath = \
         \"src/lib.rs\"\n\n[workspace]\n",
    );
    write(&root, "src/lib.rs", "");
    write(
        &root,
        "policy/toy.rego",
        "#MUTANT-SUITE tests/tier.rs\n#MUTANT limit-moved|s@^limit := 10$@limit := 999@|the_limit_is_ten\nlimit := 10\n",
    );
    write(
        &root,
        "tests/tier.rs",
        // THE DECLARATION LINES ARE STRIPPED BEFORE THE ASSERT, and that is the
        // fixture's own version of a real tier's behaviour rather than a
        // convenience: a `#MUTANT` row carries its own sed script, so its text
        // contains the very bytes the mutation removes elsewhere — and a tier
        // that read the whole file would stay green over a mutated module for
        // the same reason `self-mutating-row` exists.
        &format!(
            "#[test]\nfn the_limit_is_ten() {{\n    let text = \
             std::fs::read_to_string(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\"\
             )).join(\"policy/toy.rego\")).unwrap();\n    let live: String = \
             text.lines().filter(|line| \
             !line.starts_with(\"#MUTANT\")).collect::<Vec<_>>().join(\"\\n\");\n    \
             assert!(live.contains(\"{limit_in_tier}\"), \"{{live}}\");\n}}\n\n#[test]\nfn \
             a_second_case_keeps_the_filter_honest() {{\n    assert!(!\"\".is_empty() || \
             true);\n}}\n"
        ),
    );
    track(&root);
    root
}

#[test]
fn a_declared_rust_suite_is_reddened_by_a_mutation_on_the_module() {
    // CLOUD-1267 IN ONE ASSERTION. The predecessor resolved this gate's suite as
    // `tests/toy.bats`, found none, and answered `no-suite` — so the module was
    // exempt and 141 compiled-binary tiers were unreachable. The declared
    // mapping is what makes the mutation reach a case that can turn red.
    let root = rust_tier_repo("rust-tier", "limit := 10");
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[test]
fn a_module_whose_tier_cannot_see_it_reports_a_survivor() {
    // THE DISCRIMINATING MIRROR, and without it the case above is satisfied by a
    // runner that answers `caught` unconditionally. This tier asserts something
    // the mutation cannot move, which is exactly the shape of a dead predicate:
    // the mutation runs, the tier stays green, and the row SURVIVES.
    let root = rust_tier_repo("rust-tier-dead", "limit");
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
}

#[test]
fn an_owner_is_echoed_on_a_survivor_and_clears_nothing() {
    // `#MUTANT-OWNER` exists so a predicate already known to be dead is reported
    // with the row that owns it. It must not become an exemption: the finding
    // stands and the exit code is unmoved.
    let root = rust_tier_repo("owner", "limit");
    let module = fs::read_to_string(root.join("policy/toy.rego")).unwrap();
    write(
        &root,
        "policy/toy.rego",
        &format!("#MUTANT-OWNER CLOUD-1265|nothing writes the record this reads\n{module}"),
    );
    track(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
    assert!(out.contains("CLOUD-1265"), "{out}");
}

// ---------------------------------------------------------------------------
// The census.
// ---------------------------------------------------------------------------

/// A repository carrying named tasks with the descriptions the classifier reads.
fn census_repo(name: &str, tasks: &[(&str, &str)]) -> PathBuf {
    let root = toy(name);
    for (task, description) in tasks {
        write_program(
            &root,
            &format!("mise-tasks/{task}.sh"),
            &format!("#!/usr/bin/env bash\n#MISE description=\"{description}\"\nexit 0\n"),
        );
    }
    track(&root);
    root
}

#[test]
fn a_gate_named_in_the_set_is_a_closed_census() {
    let root = census_repo("census-closed", &[("alpha-check", "Gate: something")]);
    let (code, out, err) = census(&root, "alpha-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("1 gate(s)"), "{out}");
}

#[test]
fn the_defect_a_gate_the_set_omits_is_uncovered_and_named() {
    let root = census_repo(
        "census-uncovered",
        &[
            ("alpha-check", "Gate: something"),
            ("beta-check", "Gate: something else"),
        ],
    );
    let (code, out, _) = census(&root, "alpha-check");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("mise-tasks/beta-check.sh uncovered"), "{out}");
    assert!(!out.contains("alpha-check.sh uncovered"), "{out}");
}

#[test]
fn a_task_that_does_not_describe_itself_as_a_gate_owes_no_mutation() {
    let root = census_repo(
        "census-not-a-gate",
        &[
            ("alpha-check", "Gate: something"),
            ("measure", "Measure: something"),
            ("effect", "Effect: something"),
        ],
    );
    let (code, out, err) = census(&root, "alpha-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("1 gate(s)"), "{out}");
}

#[test]
fn a_hook_body_is_a_gate_too_because_it_decides_by_emitting_a_deny() {
    let root = census_repo("census-hook", &[("some-guard", "PreToolUse hook body")]);
    let (code, out, _) = census(&root, "");
    // An unset set is could-not-look before anything else is decided.
    assert_eq!(code, 1, "{out}");
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("mise-tasks/some-guard.sh uncovered"), "{out}");
}

#[test]
fn a_policy_module_is_censused_unconditionally_so_a_migration_cannot_shrink_the_set() {
    let root = toy("census-module");
    write(&root, "policy/some-rule.rego", "package batten.some_rule\n");
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("policy/some-rule.rego uncovered"), "{out}");
}

#[test]
fn a_preset_is_censused_too_so_the_one_class_a_pattern_row_cannot_reach_is_visible() {
    // CLOUD-1267's widening, and it is the census half of the same hole: a
    // preset ships to every consumer, and a runner blind to that directory is
    // blind to CLOUD-934's dead-predicate class.
    let root = toy("census-preset");
    write(
        &root,
        "crates/batten/src/policy/presets/some-preset/rule.rego",
        "package batten.some_preset\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("some-preset uncovered"), "{out}");
}

#[test]
fn a_filed_exemption_is_a_closed_census_not_a_gap() {
    let root = toy("census-exempt");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT CLOUD-931|its \
         suite runs no arm that can go red\nexit 0\n",
    );
    write_program(
        &root,
        "mise-tasks/beta-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something else\"\nexit 0\n",
    );
    track(&root);
    let (code, out, err) = census(&root, "beta-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("2 gate(s)"), "{out}");
}

#[test]
fn an_exemption_naming_no_issue_is_unfiled_which_is_the_whole_difference_from_a_todo() {
    let root = toy("census-unfiled-key");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT later|a \
         reason\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("mise-tasks/alpha-check.sh exempt-unfiled"),
        "{out}"
    );
}

#[test]
fn an_exemption_with_no_reason_is_unfiled_as_well() {
    let root = toy("census-unfiled-reason");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT \
         CLOUD-931\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("exempt-unfiled"), "{out}");
}

#[test]
fn declared_and_exempt_is_refused_because_the_reason_would_be_a_dead_letter() {
    let root = toy("census-both");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT CLOUD-931|a \
         reason\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "alpha-check");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("mise-tasks/alpha-check.sh declared-and-exempt"),
        "{out}"
    );
}

#[test]
fn the_reverse_direction_a_name_in_the_set_resolving_to_no_gate_is_refused() {
    let root = census_repo("census-ghost", &[("alpha-check", "Gate: something")]);
    let (code, out, _) = census(&root, "alpha-check,ghost-check");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("ghost-check names-no-subject"), "{out}");
}

#[test]
fn an_unset_set_is_could_not_look_never_a_closed_census() {
    let root = census_repo("census-unset", &[("alpha-check", "Gate: something")]);
    let (code, _, err) = census(&root, "");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("MUTANT_GATES is unset"), "{err}");
}

#[test]
fn output_is_pointer_only_so_the_exemptions_reason_never_reaches_the_log() {
    let root = toy("census-pointer");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT \
         CLOUD-931|SECRETPROSE\nexit 0\n",
    );
    track(&root);
    let (_, out, err) = census(&root, "alpha-check");
    assert!(!out.contains("SECRETPROSE"), "{out}");
    assert!(!err.contains("SECRETPROSE"), "{err}");
}

// ---------------------------------------------------------------------------
// The gate on the real tree.
// ---------------------------------------------------------------------------

#[test]
fn this_repositorys_own_census_is_closed() {
    // What makes every fixture above evidence about THIS repository. A tree
    // whose census is open is a gate covered by nothing stronger than "its suite
    // is green", which CLOUD-418 measured as insufficient four times.
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let set = fs::read_to_string(root.join("mise.toml")).expect("the manifest reads");
    let declared = set
        .lines()
        .find_map(|line| line.strip_prefix("MUTANT_GATES = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("the manifest declares the enforced set");
    let (code, out, err) = census(&root, declared);
    assert_eq!(code, 0, "{out}{err}");
}
