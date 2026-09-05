//! End-to-end tests over the compiled binary for `batten config lint`
//! (CLOUD-87).
//!
//! The lint answers a question neither schema validation nor `--config-from`
//! does: this config parses fine and is judged against a trusted base — but does
//! it *gate anything*? A set declared and empty, a rule switched off, a severity
//! quietly rated down all survive both of those checks.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.
//!
//! # The retirement ledger for `mise-tasks/config-lint.sh` (CLOUD-1162, unit 15)
//!
//! The program was a WRAPPER: it spawned `batten config lint` — the successor —
//! and then adjudicated the answer against a claim receipt and a commit trailer.
//! Both halves are the verb's now, so the wrapper collapses into the thing it
//! already called. The 23.5s it cost was almost entirely `cargo run` start-up
//! paid once per bats case, which is why the port IS the performance fix.
//!
//! Two deleted paths, two file arms. The successor is engine source that widens
//! no command surface — `config lint` already shipped — so both are
//! `kind:mechanism` rather than `kind:verb`.
//!
// carried: mise-tasks/config-lint.sh crates/batten/src/lint.rs kind:mechanism crates/batten/tests/it/config_lint.rs
// carried: tests/config-lint.bats crates/batten/src/lint.rs kind:mechanism crates/batten/tests/it/config_lint.rs
//!
//! ## CARRIED — the smell half, which this file already covered
//!
// carried: "a clean config exits 0 and states its count" crates/batten/tests/it/config_lint.rs
// carried: "an empty protected set fails the gate with a pointer" crates/batten/tests/it/config_lint.rs
// carried: "a rule switched off fails the gate" crates/batten/tests/it/config_lint.rs
// carried: "output is pointer-only — no config body echoed" crates/batten/tests/it/config_lint.rs
// carried: "a malformed config is a usage error, not a verdict" crates/batten/tests/it/config_lint.rs
// carried: "the gate leaves the config it judges unmodified" crates/batten/tests/it/config_lint.rs
// carried: "with no base ref the base-ref class does not run at all" crates/batten/tests/it/config_lint.rs
// carried: "with a base ref supplied a weakening fails the gate" crates/batten/tests/it/config_lint.rs
// carried: "with a base ref supplied an unweakened tree still exits 0" crates/batten/tests/it/config_lint.rs
// carried: "a base ref that does not resolve is a usage error, never a silent pass" crates/batten/tests/it/config_lint.rs
//!
//! ## CARRIED — the admission half, now decided in `lint::admissions`
//!
// carried: "a groomed clause plus a matching commit trailer admits the weakening" crates/batten/tests/it/config_lint.rs
// carried: "a commit trailer the groom does not name is refused" crates/batten/src/lint.rs
// carried: "a groomed clause with no commit trailer is refused" crates/batten/src/lint.rs
// carried: "an admission is keyed to the smell AND the key, not to either alone" crates/batten/src/lint.rs
// carried: "one unadmitted smell keeps the whole run a verdict" crates/batten/src/lint.rs
// carried: "the admission reports a pointer, never the clause's prose" crates/batten/tests/it/config_lint.rs
//!
//! ## CHANGED — one case asserted the defect, so it could not be carried
//!
//! CLOUD-841: a receipt that EXISTS and names no weakening read as no receipt at
//! all, so the trailer alone admitted. The bats case pinned that behaviour as
//! correct. The successor refuses it, and
//! `lint::tests::a_groom_that_looked_and_named_nothing_refuses_the_trailer` is
//! the case in the direction the decision actually goes.
//!
// changed: "with no claim receipt the trailer alone admits, which is CI's shape" crates/batten/src/lint.rs the case still holds for a receipt that is ABSENT, which is what it names, but the shell reached that arm for a receipt that was merely SILENT too; the successor tells the two apart and only the first admits
//!
//! ## WITHDRAWN — three cases whose subject the retirement deletes
//!
//! Each named a property of the SHELL rather than of the decision, and there is
//! nothing left for them to be about. Recorded rather than dropped, because a
//! case that vanishes without a reason is indistinguishable from one forgotten.
//!
// withdrawn: "the task carries no bypass branch at all" the case greps the program's own bytes for a BYPASS branch, and the program is deleted; the property it protected is now structural, since `config lint` reads no environment variable on this path and `lint::admissions` takes its two sources as arguments
// withdrawn: "the refusal points at grooming, not at a flag to set" the shell composed that refusal text and no longer exists; the verb emits a pointer plus a verdict token, and the remedy prose it used to print is `config weakens unnamed`'s registry row rather than a string in a gate
// withdrawn: "the rationale claims no caller that grep cannot find" the case gated the deleted program's own header against the workflow tree, and a header that no longer exists cannot make a claim to reconcile
//!
//! # The retirement ledger for `mise-tasks/ci-drift.sh` (CLOUD-843, CLOUD-54)
//!
//! The second program to retire onto this same verb, and for the same reason: its
//! last line was `config lint --host-rules -`, so the ADJUDICATION was already
//! here. What the shell owned was a credentialed fetch — `gh repo view` plus
//! `gh api repos/<repo>/rules/branches/<branch>` — which the engine may not
//! perform at all (house-style §5, `evaluator-io-check`).
//!
//! So the fetch moved OUT rather than in, which is CLOUD-1277's own formulation
//! for this family: *"the polling stays outside; only the decision moves in."* It
//! is a step in `.github/workflows/ci-drift.yml` now, where the job token already
//! is, and a `gh api` that fails reds the job before the gate runs.
//!
//! **CLOUD-1277 asked for a channel this did not need.** That row proposes a
//! producer-written document under `$GIT_DIR` declared by `[[rule.external]]`,
//! because `input.tree.forge` is a `name -> token` map and cannot carry a nested
//! ruleset. Both halves are true and neither applies: that shape is what a
//! tree-scoped MODULE would need, and the successor here is a VERB reading an
//! argument. `--host-rules` has taken a path since it shipped.
//!
//! Two deleted paths, two file arms. The successor is engine source that widens
//! no command surface — `config lint --host-rules` already shipped — so both are
//! `kind:mechanism`.
//!
// carried: mise-tasks/ci-drift.sh crates/batten/src/ci.rs kind:mechanism crates/batten/tests/it/config_lint.rs
// carried: tests/ci-drift.bats crates/batten/src/ci.rs kind:mechanism crates/batten/tests/it/config_lint.rs
//!
//! ## CARRIED — the decision half, which this file already covered
//!
// carried: "THE DEFECT: a fetch that could not look is exit 1, never a green verdict" crates/batten/tests/it/config_lint.rs
// carried: "the decision's verdict passes through, so drift fails the gate" crates/batten/tests/it/config_lint.rs
// carried: "the decision is the offline one, over stdin — the gate spawns no second fetch" crates/batten/tests/it/config_lint.rs
//!
//! ## CHANGED — one case, because the payload arrives by a different route
//!
// changed: "the fetched bytes reach the decision on stdin, unaltered" crates/batten/tests/it/config_lint.rs the bytes now arrive as a declared PATH rather than on stdin; `--host-rules` has always taken both, and the path arm is what lets the fetch live in the workflow instead of in a program that must pipe
//!
//! ## WITHDRAWN — two cases whose subject the retirement deletes
//!
//! Both were about the shell's own plumbing rather than about the decision. A
//! failed fetch no longer has a program to hand nothing to — the workflow step
//! fails and the gate never runs — and the branch is an argument the workflow
//! supplies rather than a variable a program defaults.
//!
// withdrawn: "a failed fetch hands nothing to the decision" the program that did the fetching and the piping is deleted; the workflow step fails first, so there is no in-between state left to assert
// withdrawn: "the branch is the one CI_DRIFT_BRANCH names, and main is the default" the default moved into the workflow's own expansion, which is ungoverned and not this tier's subject
//!
//! ## SUBSUMED — the four wiring cases, which `ci-local-parity` already owns
//!
//! They assert that `verify` and CI arm the same task, that CI arms it with the
//! PR's own base ref rather than a hardcoded trunk, that the fetch and the
//! `CONFIG_LINT_BASE` value agree on the `origin/` namespace, and that the job is
//! not shallow. **The task name survives this retirement**, so every one of those
//! call sites is byte-identical and every assertion still holds — they are about
//! `mise.toml` and `ci.yml`, which this change does not move.
//!
// subsumed: "verify arms the same task CI arms" crates/batten/tests/it/ci_parity.rs
// subsumed: "the armed caller names the PR's own base ref, not a hardcoded one" crates/batten/tests/it/ci_parity.rs
// subsumed: "the armed caller and the fetch agree on the ref namespace" crates/batten/tests/it/ci_parity.rs
// subsumed: "the job that arms the gate clones the history the trailer read needs" crates/batten/tests/it/ci_parity.rs
// subsumed: "this repo's own config is clean — the gate on the real tree" crates/batten/tests/it/checks_green.rs
// subsumed: "no environment variable waives a base-ref weakening" crates/batten/tests/it/guardrail_bypass.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, scratch, stderr, stdout};

/// Create a temp repo containing a `batten.toml` with `contents`.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    Fixture::new(name).config(contents).build()
}

/// A pull-request-shaped fixture: `base` pinned as `origin/main`, `working` in
/// the tree on top.
fn pr_fixture(name: &str, base: &str, working: &str) -> PathBuf {
    Fixture::new(name)
        .config(base)
        .git()
        .base_commit()
        .config(working)
        .work_commit()
        .build()
}

fn lint(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["config", "lint"];
    args.extend_from_slice(extra);
    common::run(dir, &args)
}

/// A pull request that WEAKENS policy, whose work commit carries `trailer` as a
/// `Weakens:` line when one is given.
///
/// The trailer goes on through git's own commit path rather than being written
/// into a message file by hand, so what the verb parses is what git produced.
fn weakening_pr(name: &str, trailer: Option<&str>) -> PathBuf {
    let base = "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\nseverity = \"deny\"\n";
    let working = base.replace("\"deny\"", "\"warn\"");
    let dir = Fixture::new(name)
        .config(base)
        .git()
        .base_commit()
        .config(&working)
        .build();
    common::git_in(&dir, &["add", "-A"]);
    let message = match trailer {
        Some(pair) => format!("the pull request\n\nWeakens: {pair}"),
        None => "the pull request".to_owned(),
    };
    common::git_in(&dir, &["commit", "-q", "--allow-empty", "-m", &message]);
    dir
}

/// Mint a claim receipt for the fixture's current branch, admitting `pairs`.
///
/// Written through `claim::receipt_name` rather than a literal, because the
/// filename is the contract between the minter and this reader and two spellings
/// of it mean the gate reports a missing receipt for one that exists.
fn groom(dir: &Path, pairs: &[&str]) {
    let branch = common::git_in(dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let branch = branch.trim();
    let store = dir.join(".git").join("batten-receipts");
    fs::create_dir_all(&store).unwrap();
    let mut body = String::from("CLOUD-1\nready-lint pass\n");
    for pair in pairs {
        use std::fmt::Write as _;
        writeln!(body, "weakens CLOUD-1 {pair}").unwrap();
    }
    fs::write(store.join(batten::claim::receipt_name(branch)), body).unwrap();
}

/// THE PAIR THE WHOLE ADMISSION TURNS ON, over the compiled binary rather than
/// over `lint::admissions` directly (CLOUD-841, CLOUD-418).
///
/// The unit tier pins the decision; this one pins that the ENGINE can build the
/// two inputs it decides over — a receipt read off disk under the branch's own
/// name, and a trailer read out of a real commit. A `with input as` equivalent
/// would pass over a reader that finds neither, which is the class this whole
/// campaign keeps meeting.
#[test]
fn a_silent_groom_refuses_where_an_absent_one_admits() {
    // ABSENT: no receipt at all — CI's shape, and the trailer alone admits.
    let absent = weakening_pr(
        "lint-admit-absent",
        Some("severity-lowered rule[no-todo].severity"),
    );
    let out = lint(&absent, &["--config-from", "origin/main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("trailer-alone"),
        "an absent receipt admits on the trailer and says so: {}",
        stdout(&out)
    );

    // SILENT: a receipt that EXISTS and admits nothing. Byte-identical trailer,
    // byte-identical config, opposite verdict — which is the whole of CLOUD-841
    // and the case the shell got backwards.
    let silent = weakening_pr(
        "lint-admit-silent",
        Some("severity-lowered rule[no-todo].severity"),
    );
    groom(&silent, &[]);
    let out = lint(&silent, &["--config-from", "origin/main"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a groom that looked and named nothing must refuse: {}",
        stdout(&out)
    );

    // NAMING IT: the same receipt, now admitting the pair. The third state, and
    // without it the two above are satisfied by a gate that never admits.
    let named = weakening_pr(
        "lint-admit-named",
        Some("severity-lowered rule[no-todo].severity"),
    );
    groom(&named, &["severity-lowered rule[no-todo].severity"]);
    let out = lint(&named, &["--config-from", "origin/main"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("groomed"), "{}", stdout(&out));
}

#[test]
fn a_weakening_no_trailer_names_is_refused_whatever_the_groom_said() {
    // The other direction of "they AGREE", end to end: a groomed clause that no
    // commit names is a plan rather than a declaration.
    let dir = weakening_pr("lint-admit-no-trailer", None);
    groom(&dir, &["severity-lowered rule[no-todo].severity"]);
    let out = lint(&dir, &["--config-from", "origin/main"]);
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(!stdout(&out).contains("admitted"), "{}", stdout(&out));
}

#[test]
fn an_admission_carries_a_pointer_and_never_the_clause_prose() {
    // Non-negotiable rule 4 at the one place this family is most likely to breach
    // it: the groomed body is a consumer's prose, and the receipt is the only
    // thing that has ever seen it. Neither the reason nor the issue key reaches
    // the report — the key is provenance for a human reading the RECEIPT, not a
    // field of the pair being matched.
    let dir = weakening_pr(
        "lint-admit-pointer",
        Some("severity-lowered rule[no-todo].severity"),
    );
    groom(&dir, &["severity-lowered rule[no-todo].severity"]);
    let out = lint(&dir, &["--config-from", "origin/main"]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("severity-lowered"), "{text}");
    assert!(
        !text.contains("CLOUD-1"),
        "the issue key is not part of the report: {text}"
    );
    assert!(
        !text.contains("ready-lint"),
        "no receipt line is echoed: {text}"
    );
}

#[test]
fn an_unarmed_run_decides_no_admission_at_all() {
    // The arm runs only under a base ref, which is the same condition that
    // produces a base-ref smell — so an unarmed run is byte-identical to what it
    // was before the admission half existed. Measured rather than assumed,
    // because reading an unarmed `0 smell(s)` as a pass over the base-ref class
    // is exactly the error that let two smells reach `verify` on this campaign's
    // own branch.
    let dir = weakening_pr(
        "lint-admit-unarmed",
        Some("severity-lowered rule[no-todo].severity"),
    );
    groom(&dir, &[]);
    let out = lint(&dir, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(!stdout(&out).contains("admitted"), "{}", stdout(&out));
}

/// A `forbid` rule at the given severity.
fn rule(id: &str, severity: &str) -> String {
    format!(
        "\n[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"{severity}\"\n"
    )
}

// --- single-tree smells ------------------------------------------------------

#[test]
fn a_clean_config_exits_zero_and_still_states_its_count() {
    // Stating zero matters: silence would be indistinguishable from "the lint
    // did not run", which is how a skipped gate reads as a passing one.
    let dir = repo_with_config(
        "lint-clean",
        &format!("version = 1\nprotected = [\"a\"]\n{}", rule("r", "deny")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn an_empty_protected_set_is_a_violation_with_a_pointer() {
    // CLOUD-87's headline acceptance. Exit 2 — a smell is a verdict about the
    // config, the same class as a rule finding.
    let dir = repo_with_config("lint-empty-protected", "version = 1\nprotected = []\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:2 empty-protected-set\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn the_pointer_names_the_line_the_key_is_written_on() {
    let dir = repo_with_config(
        "lint-line-number",
        "version = 1\n\n# a comment\n\nprotected = []\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).starts_with("batten.toml:5 empty-protected-set\n"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_absent_set_is_not_a_smell() {
    // Absent means "this repository does not use the feature"; flagging it would
    // fire on every minimal config, which is how a lint teaches people to
    // ignore it. Deletion of a populated set is caught by the base-ref class.
    let dir = repo_with_config("lint-absent-set", "version = 1\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn a_rule_switched_off_is_a_smell() {
    // `severity = "allow"` reads as a gate in the file and is not one.
    let dir = repo_with_config(
        "lint-rule-disabled",
        &format!("version = 1\n{}", rule("no-todo", "allow")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("rule-disabled"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn every_empty_set_is_reported_and_the_output_is_byte_stable() {
    let dir = repo_with_config(
        "lint-all-empty",
        "version = 1\nunlanded = []\nscope = []\nprotected = []\n",
    );
    let first = lint(&dir, &[]);
    assert_eq!(first.status.code(), Some(2));
    assert_eq!(
        stdout(&first),
        "batten.toml:2 empty-unlanded-set\n\
         batten.toml:3 empty-scope-set\n\
         batten.toml:4 empty-protected-set\n\
         config-lint: 3 smell(s)\n"
    );
    let second = lint(&dir, &[]);
    assert_eq!(
        first.stdout, second.stdout,
        "the report must be byte-stable"
    );
}

#[test]
fn the_output_never_carries_the_config_bytes() {
    // Non-negotiable rule 4: a location and a stable id, never the content.
    let dir = repo_with_config(
        "lint-pointer-only",
        "version = 1\n# a very distinctive comment\nprotected = []\n",
    );
    let text = stdout(&lint(&dir, &[]));
    assert!(!text.contains("very distinctive comment"), "got: {text}");
    assert!(!text.contains("version = 1"), "got: {text}");
}

// --- a waiver that cannot reach its rule (CLOUD-293) -------------------------

/// A config with one `shape` rule — the mediated-call kind, which reads no
/// `glob` — plus whatever waiver rows the case needs.
fn shape_config(waivers: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"no-merge\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\npattern = \"gh pr merge\"\n\
         reason = \"land by fast-forward\"\nseverity = \"deny\"\n{waivers}"
    )
}

fn waiver_row(rule: &str) -> String {
    format!(
        "\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked in CLOUD-1\"\nexpires = \"2099-01-01\"\n"
    )
}

/// A config declaring one `judge` RULE — the one kind left outside
/// `waiver::reaches` after CLOUD-610 — plus whatever waiver rows follow.
///
/// Not to be confused with `judge_config` further down, which builds a `[judge]`
/// TABLE: that is the payload-boundary knob, this is a `[[rule]]` row of kind
/// `judge`. Two different config surfaces that share a word.
fn judge_rule_config(waivers: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"intentional\"\nkind = \"judge\"\n\
         glob = \"**/*.rs\"\ncriteria = \"does this read as intentional\"\n\
         tier = \"advisory\"\nno_fix_reason = \"answered by a person\"\n{waivers}"
    )
}

#[test]
fn a_waiver_over_an_unreachable_kind_is_a_violation_naming_the_kind() {
    // CLOUD-293's headline acceptance, over the compiled binary — now on the one
    // kind that stayed unreachable. A judge row is refused the `severity` column,
    // so it mints no finding for `waiver::apply` and renders no `Decision` for
    // `hook::adjudicate`, and a waiver over it suppresses nothing either way.
    let dir = repo_with_config(
        "lint-waiver-judge",
        &judge_rule_config(&waiver_row("intentional")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:waiver[intentional] judge waiver-unreachable-kind\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn a_waiver_over_a_reachable_kind_exits_zero() {
    // The half that keeps the smell worth reading: it must not fire on every
    // waiver in the file. `forbid` mints findings, so its waiver is live.
    let dir = repo_with_config(
        "lint-waiver-forbid",
        &format!("version = 1\n{}{}", rule("r", "deny"), waiver_row("r")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn a_waiver_over_a_mediated_kind_exits_zero_since_the_hook_honours_it() {
    // CLOUD-610's retirement over the compiled binary, and the pairing is the
    // point: the same `shape` row that produced the smell above now produces
    // none, because `hook::adjudicate` consults the waiver table this file
    // declares. A `judge` waiver still smells (above), which is what proves the
    // set was read from `waiver::reaches` rather than restated in the lint.
    let dir = repo_with_config("lint-waiver-shape", &shape_config(&waiver_row("no-merge")));
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn the_unreachable_smell_reaches_the_machine_channel_unchanged() {
    // No new field: the pointer splits into the same `at`/`id` pair every other
    // smell uses, so a consumer needs no second convention for this one.
    let dir = repo_with_config(
        "lint-waiver-json",
        &judge_rule_config(&waiver_row("intentional")),
    );
    let output = lint(&dir, &["-J"]);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        text.contains("\"at\": \"waiver[intentional] judge\""),
        "got: {text}"
    );
    assert!(
        text.contains("\"id\": \"waiver-unreachable-kind\""),
        "got: {text}"
    );
    // Pointer-only: never the justification, never the criteria the rule judges by.
    assert!(!text.contains("tracked in CLOUD-1"), "got: {text}");
    assert!(
        !text.contains("does this read as intentional"),
        "got: {text}"
    );
}

// --- base-ref comparison smells ----------------------------------------------

#[test]
fn a_severity_lowered_against_the_base_ref_is_a_smell() {
    // CLOUD-87's second acceptance, and the one that needs CLOUD-31's loader.
    // Without a base ref this config is entirely clean — a `warn` rule is legal.
    let repo = pr_fixture(
        "lint-severity-lowered",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        &format!("version = 1\n{}", rule("no-todo", "warn")),
    );
    assert_eq!(
        lint(&repo, &[]).status.code(),
        Some(0),
        "the single-tree view cannot see the lowering"
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        // The key path, not `:0`. `trust` located this weakening precisely and
        // the conversion now keeps that location, so the pointer names the key
        // that was lowered and matches what `check --config-from` prints for the
        // same finding (CLOUD-233).
        "batten.toml:rule[no-todo].severity severity-lowered\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn a_deleted_protected_entry_is_a_smell_against_the_base_ref() {
    // The deletion the single-tree class deliberately does not flag: absent is
    // not empty, but absent-having-been-present is a weakening.
    let repo = pr_fixture(
        "lint-protected-deleted",
        "version = 1\nprotected = [\"crates/**\"]\n",
        "version = 1\n",
    );
    assert_eq!(lint(&repo, &[]).status.code(), Some(0));
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("protected-removed"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn tightening_against_the_base_ref_is_not_a_smell() {
    let repo = pr_fixture(
        "lint-tightened",
        "version = 1\nprotected = [\"a\"]\n",
        "version = 1\nprotected = [\"a\", \"b\"]\nstrictness = \"strict\"\n",
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn the_smell_ids_are_the_same_names_the_check_delta_uses() {
    // One definition of "weakened", shared: the lint's base-ref ids come off the
    // same `WeakeningKind` the `check` delta is built from, so the two can never
    // disagree about what happened.
    let repo = pr_fixture(
        "lint-shared-vocabulary",
        "version = 1\nprotected = [\"a\"]\nstrictness = \"strict\"\n",
        "version = 1\n",
    );
    let linted = stdout(&lint(&repo, &["--config-from", "origin/main"]));
    assert!(linted.contains("protected-removed"), "got: {linted}");
    assert!(linted.contains("strictness-lowered"), "got: {linted}");

    // The same run through `check` names the same two keys.
    let checked = batten()
        .args(["check", "--config-from", "origin/main"])
        .current_dir(&repo)
        .output()
        .expect("run batten check");
    let checked = String::from_utf8_lossy(&checked.stdout);
    assert!(
        checked.contains("batten.toml:protected[a]"),
        "got: {checked}"
    );
    assert!(checked.contains("batten.toml:strictness"), "got: {checked}");
}

#[test]
fn the_keys_cloud_721_added_reach_the_lint_with_their_own_pointers() {
    // The two cases CLOUD-721 named were reported CLEAN by a comparison that
    // claimed to cover their key, and a third — the verb table — was not
    // compared at all. All three arrive through the one definition of
    // "weakened", so this asserts the whole path rather than the module's own
    // view of it.
    let base = concat!(
        "version = 1\n",
        "\n[[verb]]\nverb = \"rm\"\neffect = \"destructive\"\n",
        "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n",
        "pattern = \"TODO\"\nseverity = \"deny\"\n",
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"tracked\"\nexpires = \"2020-01-01\"\n",
    );
    // Same rule, same severity, same waiver key: the glob is narrowed to match
    // nothing, the lapsed waiver is extended past the decade, and the mutating
    // verb row is deleted.
    let working = concat!(
        "version = 1\n",
        "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"nothing/here/**\"\n",
        "pattern = \"TODO\"\nseverity = \"deny\"\n",
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"tracked\"\nexpires = \"2099-01-01\"\n",
    );
    let repo = pr_fixture("lint-cloud-721-keys", base, working);

    // Single-tree, all three are invisible: every one of them is a statement
    // about the pair of files.
    assert_eq!(lint(&repo, &[]).status.code(), Some(0));

    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:rule[no-todo].glob rule-predicate-changed\n\
         batten.toml:verb[rm] verb-removed\n\
         batten.toml:waiver[no-todo].expires waiver-expiry-extended\n\
         config-lint: 3 smell(s)\n",
        "each key carries its own pointer, so none of the three can collapse \
         into another (CLOUD-233)"
    );

    // Byte-stable across two runs over the same tree (§6), which the digest
    // token in the rule pointer is the newest way to get wrong.
    assert_eq!(
        stdout(&lint(&repo, &["--config-from", "origin/main"])),
        stdout(&output)
    );

    // Pointer-only: the narrowed glob is config content and never reaches the
    // output (non-negotiable rule 4).
    assert!(
        !stdout(&output).contains("nothing/here"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_arriving_narrowing_key_is_clean_while_the_same_row_widened_is_not() {
    // CLOUD-1394, over the compiled binary against a REAL base ref, because the
    // acceptance turns on the engine building the comparison rather than on the
    // module's own view of it. Both arms live in one case on purpose: an
    // assertion that the narrowing is clean passes trivially under a gate that
    // stopped firing at all, which is the failure this replaces rather than a
    // variant of it.
    let row = |extra: &str| {
        format!(
            "version = 1\n\n[[rule]]\nid = \"ready-receipt\"\nkind = \"receipt\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr ready\"\n\
             checks = [\"verify\"]\nkey = \"head\"\nreason = \"run verify\"\n{extra}"
        )
    };

    // The narrowing: a bound arrives where the base declared none, so a receipt
    // this row already accepted can only stop qualifying by aging out.
    let narrowed = pr_fixture("lint-1394-narrowed", &row(""), &row("max_age = 3600\n"));
    let output = lint(&narrowed, &["--config-from", "origin/main"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an arriving `max_age` is not a weakening; got: {}",
        stdout(&output)
    );
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");

    // The mirror, same row and same column: raising the bound admits receipts
    // the base refused, and nothing here ranks that.
    let widened = pr_fixture(
        "lint-1394-widened",
        &row("max_age = 3600\n"),
        &row("max_age = 86400\n"),
    );
    let output = lint(&widened, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:rule[ready-receipt].max_age rule-predicate-changed\n\
         config-lint: 1 smell(s)\n"
    );

    // And the counterexample the ranking is DECLARED rather than inferred for:
    // `bypass_env` is optional, absent before and absence-preserving, and it
    // makes the row suppressible (`batten.toml:415-430`).
    let suppressible = pr_fixture(
        "lint-1394-bypass",
        &row(""),
        &row("bypass_env = \"BATTEN_READY_BYPASS\"\n"),
    );
    let output = lint(&suppressible, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:rule[ready-receipt].bypass_env rule-predicate-changed\n\
         config-lint: 1 smell(s)\n"
    );
}

#[test]
fn the_reverse_edit_of_those_keys_is_clean() {
    // The direction half, at the same boundary the verdict is taken: a widened
    // glob, an expiry pulled in, and a verb row ADDED lower no bar.
    let tight = concat!(
        "version = 1\n",
        "\n[[verb]]\nverb = \"rm\"\neffect = \"destructive\"\n",
        "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n",
        "pattern = \"TODO\"\nseverity = \"deny\"\n",
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"tracked\"\nexpires = \"2020-01-01\"\n",
    );
    let loose = concat!(
        "version = 1\n",
        "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"nothing/here/**\"\n",
        "pattern = \"TODO\"\nseverity = \"deny\"\n",
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"tracked\"\nexpires = \"2099-01-01\"\n",
    );
    let repo = pr_fixture("lint-cloud-721-reverse", loose, tight);
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(
        stdout(&output),
        // The lapsed waiver in the WORKING tree is a single-tree smell of its
        // own, and it is there either way — it is what makes the pair honest:
        // the base-ref class contributes exactly one line, the predicate change,
        // reported as a CHANGE in both directions because ranking two globs
        // would be a judgement.
        "batten.toml:15 waiver-expired\n\
         batten.toml:rule[no-todo].glob rule-predicate-changed\n\
         config-lint: 2 smell(s)\n"
    );
    assert!(
        !stdout(&output).contains("verb-removed"),
        "adding a mediated verb row raises the bar: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("waiver-expiry-extended"),
        "pulling an expiry IN raises the bar: {}",
        stdout(&output)
    );
}

// --- errors are usage errors, never verdicts ---------------------------------

#[test]
fn a_malformed_config_is_a_usage_error() {
    // Exit 1, not 2: "I cannot read this" is a statement about the invocation.
    // A harness reading 2 would report a policy denial that never happened (§7).
    let dir = repo_with_config("lint-malformed", "version = 1\nthis is not toml\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
}

#[test]
fn a_missing_config_is_a_usage_error() {
    let dir = scratch("lint-missing-config");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");
    assert_eq!(lint(&dir, &[]).status.code(), Some(1));
}

#[test]
fn an_unknown_base_ref_is_a_usage_error() {
    let repo = pr_fixture("lint-unknown-ref", "version = 1\n", "version = 1\n");
    let output = lint(&repo, &["--config-from", "origin/nonexistent"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

// --- the surface ------------------------------------------------------------

#[test]
fn config_lint_is_declared_read_in_the_spec() {
    // §5: the derived agent allowlist is `filter(effect == read)`, so a lint that
    // only inspects must say so or it is needlessly excluded.
    let output = batten().arg("spec").output().expect("run batten spec");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let config = spec["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config")
        .expect("config is in the spec");
    let lint = config["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config lint")
        .expect("config lint is in the spec");
    assert_eq!(lint["effect"], "read");
}

#[test]
fn this_repositorys_own_config_is_clean() {
    // Consumer #1: the lint Batten ships runs against the config Batten is
    // gated by, which is also what `mise run config-lint` asserts in the gate.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = batten()
        .args(["config", "lint"])
        .current_dir(&repo)
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config lint");
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's batten.toml has a smell: {}",
        stdout(&output)
    );
}

// --- one weakening, one pointer, whichever verb reports it --------------------
//
// CLOUD-233. `config lint` and `check --config-from` reuse one comparison, so
// they must agree on where a weakening *is*. They did not: this verb substituted
// `:0` for the key `trust` had already computed, which pointed nowhere and — since
// a smell's identity was `(line, id)` — made two weakenings of one kind compare
// equal, so `dedup` silently dropped all but the first.

#[test]
fn two_rules_lowered_in_one_edit_are_both_reported() {
    // The count is the sharp end: under-reporting a weakening is worse than
    // mislocating it, and no test asserted cardinality before this one.
    let repo = pr_fixture(
        "lint-two-lowerings",
        &format!("version = 1{}{}", rule("one", "deny"), rule("two", "deny")),
        &format!("version = 1{}{}", rule("one", "warn"), rule("two", "warn")),
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:rule[one].severity severity-lowered\n\
         batten.toml:rule[two].severity severity-lowered\n\
         config-lint: 2 smell(s)\n",
        "both lowerings, each under its own key"
    );
}

#[test]
fn the_two_verbs_agree_on_where_a_weakening_is() {
    // The assertion that would have caught this, and which neither verb's own
    // suite can express alone: the pointer half of each line must match, so a
    // caller can join a smell to the weakening it came from.
    let repo = pr_fixture(
        "lint-pointer-joinable",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &format!("version = 1{}", rule("no-todo", "warn")),
    );
    let lint_out = stdout(&lint(&repo, &["--config-from", "origin/main"]));

    let check = batten()
        .args(["check", "--config-from", "origin/main"])
        .current_dir(&repo)
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten check");
    let check_out = String::from_utf8_lossy(&check.stdout).into_owned();

    // The pointer is everything up to the first space; the trailing token differs
    // by verb on purpose — one names the smell, the other the verdict transition.
    let pointer = |text: &str| -> String {
        text.lines()
            .find(|line| line.starts_with("batten.toml:"))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(
        pointer(&lint_out),
        pointer(&check_out),
        "lint: {lint_out}check: {check_out}"
    );
    assert_eq!(pointer(&lint_out), "batten.toml:rule[no-todo].severity");
}

// --- the judge payload boundary (CLOUD-135) ----------------------------------

/// A config with a protected set and a `[judge]` table, with `extra` appended
/// inside that table.
fn judge_config(extra: &str) -> String {
    format!("version = 1\nprotected = [\"secrets/**\"]\n\n[judge]\nraw = [\"span_text\"]\n{extra}")
}

#[test]
fn a_judge_over_a_protected_set_needs_no_answer_because_the_engine_gives_one() {
    // `judge-over-protected-unstated` used to fire here. It is gone with the key
    // it asked about: protected content now refuses the whole invocation, so
    // there is no question for a config to leave unanswered, and a smell over a
    // decision the engine makes structurally could never fire.
    let dir = repo_with_config("judge-unstated", &judge_config(""));
    let output = lint(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an unanswerable question is not a smell: {}",
        stdout(&output)
    );
}

#[test]
fn the_removed_protected_egress_key_is_refused_rather_than_ignored() {
    // The key was the issue's own rejected alternative — "a committed opt-in key
    // for protected egress … not a latent key". A config still carrying it must
    // hear that it no longer does anything, rather than parsing green and
    // leaving its author believing protected content still crosses.
    for answer in ["pointer", "raw"] {
        let dir = repo_with_config(
            &format!("judge-removed-{answer}"),
            &judge_config(&format!("over_protected = \"{answer}\"\n")),
        );
        let output = lint(&dir, &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "an unknown key is a usage error, never a silent ignore"
        );
        assert!(
            stderr(&output).contains("over_protected"),
            "the refusal names the key that is gone"
        );
    }
}

#[test]
fn a_judge_with_no_protected_set_owes_no_answer() {
    // Absent is not empty, the rule this whole module runs on: a config with
    // nothing marked protected has no protected content to decide about, and
    // firing there would make the smell noise on every minimal config.
    let dir = repo_with_config(
        "judge-no-protected",
        "version = 1\n\n[judge]\nraw = [\"span_text\"]\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_protected_set_with_no_judge_owes_no_answer_either() {
    let dir = repo_with_config(
        "judge-absent",
        "version = 1\nprotected = [\"secrets/**\"]\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

// --- the merge-contract drift gate (CLOUD-54) --------------------------------
//
// The host ruleset is the authority; `[ci]` is a projection a gate polices. The
// payload arrives from the caller — agents fetch, gates decide — so every case
// below is a pure comparison over bytes on disk or stdin, with no network.

/// A config declaring `[ci]`, with `extra` appended inside the table.
fn ci_config(extra: &str) -> String {
    format!("version = 1\n\n[ci]\nrequired_checks = [\"final\"]\n{extra}")
}

/// One of the committed rules-API fixtures, by file stem.
fn rules_fixture(stem: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ci")
        .join(format!("{stem}.json"))
}

/// `config lint --host-rules <fixture>` in `dir`.
fn lint_against(dir: &Path, stem: &str) -> Output {
    lint(
        dir,
        &[
            "--host-rules",
            rules_fixture(stem).to_str().expect("fixture path is UTF-8"),
        ],
    )
}

#[test]
fn a_projection_matching_the_host_is_silent_and_clean() {
    let dir = repo_with_config("ci-agrees", &ci_config(""));
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("0 smell(s)"),
        "agreement is the count stated at zero, never silence that could be a \
         lint which did not run"
    );
}

#[test]
fn a_check_the_host_requires_and_the_config_lacks_is_drift() {
    let dir = repo_with_config(
        "ci-missing-check",
        "version = 1\n\n[ci]\nrequired_checks = [\"other\"]\n",
    );
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(2), "drift is a policy verdict");
    let text = stdout(&output);
    assert!(
        text.contains("ci-required-checks-drift"),
        "the smell names itself: {text:?}"
    );
    assert!(
        text.contains("ci.required_checks"),
        "and the key to edit: {text:?}"
    );
    assert!(
        text.contains("+final") && text.contains("-other"),
        "signed by which side has each token — `+` host, `-` config: {text:?}"
    );
}

#[test]
fn a_check_the_config_claims_and_the_host_does_not_require_is_drift_too() {
    // Not harmless: a stale name in the projection is exactly what a downstream
    // reader would wait on forever.
    let dir = repo_with_config(
        "ci-stale-check",
        "version = 1\n\n[ci]\nrequired_checks = [\"final\", \"ghost\"]\n",
    );
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("-ghost"));
}

#[test]
fn a_host_ruleset_that_cannot_be_read_is_could_not_look_never_agreement() {
    // `ci-drift.sh`'s ONE `#MUTANT` row, re-homed rather than assumed
    // (CLOUD-843). Its predicate was `could-not-look-is-a-pass`, over the
    // program's `exit 1` on a failed fetch, and its own header said why: "a drift
    // check that could not look has not found agreement, and reporting green
    // there is the false-green shape this engine exists to catch."
    //
    // WRITTEN BECAUSE THE LEDGER ARM ABOVE WAS FALSE WITHOUT IT. That arm records
    // the case as `carried:` to this file, and this file had no case over an
    // unreadable payload — only over rulesets it could read. That is CLOUD-908's
    // exact class, `retires_with` conserving files rather than logic, and it was
    // caught by re-reading the arm rather than by any gate: nothing checks that a
    // named successor actually covers what it claims.
    let dir = repo_with_config("ci-unreadable-rules", &ci_config(""));
    let output = lint(&dir, &["--host-rules", "/nonexistent-ruleset.json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a payload that cannot be read is a usage error, never agreement"
    );
    assert!(
        !stdout(&output).contains("0 smell"),
        "could-not-look reported as a clean comparison: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_payload_that_is_not_a_ruleset_is_could_not_look_too() {
    // The sibling arm, and the one that discriminates: an unreadable path and a
    // readable file that is not a rules-API response are different failures with
    // the same obligation. Without this, the case above passes over a verb that
    // refuses only on `open()` and would happily compare against `{}`.
    //
    // Unchanged by CLOUD-380: `{}` carries none of the repository keys, so it is
    // not routed to the `[host]` arm and gets this arm's refusal exactly as
    // before. Routing on a recognised KEY rather than on being an object is what
    // preserves that.
    let dir = repo_with_config("ci-not-a-ruleset", &ci_config(""));
    let payload = dir.join("not-a-ruleset.json");
    std::fs::write(&payload, "{}").expect("write payload");
    let output = lint(&dir, &["--host-rules", payload.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a payload that is not a rules-API array is a usage error"
    );
}

/// CLOUD-759's anti-vacuity pair, and both halves are required or this ships as
/// a sensor.
///
/// A deferral names the condition for its own reversal; the condition is later
/// satisfied; nothing re-fires. Both instances this row was opened for were found
/// by accident while looking for something else, which is the point — nothing was
/// watching one fact that three issue bodies reasoned from.
#[test]
fn a_deferral_whose_condition_now_holds_is_reported_and_one_still_waiting_is_silent() {
    let manifest = "[workspace.package]\nrust-version = \"1.98\"\n";
    let row = |issue: &str, reaches: &str| {
        format!(
            "version = 1\n\n[[deferral]]\nissue = \"{issue}\"\nfact = \"rust-version\"\n\
             reaches = \"{reaches}\"\nreason = \"why it waits\"\n"
        )
    };

    // CLOUD-647's measured instance: deferred on `rust-version = 1.88.0` against
    // a 1.85.0 pin, and the pin is now 1.98 — fully discharged and still carried.
    let reached = repo_with_config("deferral-reached", &row("CLOUD-647", "1.88.0"));
    std::fs::write(reached.join("Cargo.toml"), manifest).expect("write manifest");
    let output = lint(&reached, &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("deferral[CLOUD-647].reaches deferral-reversible"),
        "the pointer names the row that owns the decision: {}",
        stdout(&output)
    );
    // POINTER, NEVER THE PROSE (rule 4): the reason is config content and the
    // finding carries none of it.
    assert!(
        !stdout(&output).contains("why it waits"),
        "{}",
        stdout(&output)
    );

    // The half that makes the first one mean something: a condition the tree
    // cannot yet show is silent, not reported.
    let waiting = repo_with_config("deferral-waiting", &row("CLOUD-999", "1.99.0"));
    std::fs::write(waiting.join("Cargo.toml"), manifest).expect("write manifest");
    let output = lint(&waiting, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a deferral still waiting is not a finding: {}",
        stdout(&output)
    );
}

/// A manifest this cannot read reports nothing, rather than every deferral.
///
/// The could-not-look direction for a gate that ADDS refusals: a deferral is
/// raised only when the tree can SHOW its condition holds. The opposite reading
/// would refuse every deferral on a checkout whose manifest moved.
#[test]
fn a_deferral_over_an_unreadable_manifest_is_silent_rather_than_reported() {
    let dir = repo_with_config(
        "deferral-no-manifest",
        "version = 1\n\n[[deferral]]\nissue = \"CLOUD-647\"\nfact = \"rust-version\"\n\
         reaches = \"1.0.0\"\nreason = \"why it waits\"\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "no manifest is could-not-look, never a blanket refusal: {}",
        stdout(&output)
    );
}

/// A failed fetch must never read as agreement (CLOUD-380).
///
/// The forge answers an error as a JSON OBJECT, and the repository response is an
/// object too. Routing on shape alone would compare an all-absent projection
/// against a declared `[host]` and find nothing to report — exit `0` over a fetch
/// that never happened, which is the one answer this comparison must not give.
#[test]
fn a_forge_error_object_is_refused_rather_than_compared_as_agreement() {
    let dir = repo_with_config(
        "host-error-payload",
        "version = 1\n\n[host]\ndelete_branch_on_merge = true\n",
    );
    let path = dir.join("error.json");
    fs::write(&path, r#"{"message":"Not Found","status":"404"}"#).expect("write payload");

    let output = lint(&dir, &["--host-rules", path.to_str().unwrap()]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "an error payload is never a clean comparison: {}",
        stdout(&output)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "and it is could-not-look rather than drift: {}",
        stderr(&output)
    );
}

/// CLOUD-380's discriminating pair, over the compiled binary with the payload on
/// disk so the suite stays offline.
///
/// The load-bearing half is that the refusal NAMES THE KEY. A comparison that
/// exits non-zero on any non-200 looks identical from outside until you read what
/// it said, and naming the key is what separates the two.
#[test]
fn a_host_setting_the_tree_disagrees_with_is_refused_and_names_the_key() {
    let dir = repo_with_config(
        "host-drift",
        "version = 1

[host]
delete_branch_on_merge = true
",
    );
    let payload = dir.join("repo.json");
    std::fs::write(&payload, r#"{"delete_branch_on_merge": false}"#).expect("write payload");

    let output = lint(&dir, &["--host-rules", payload.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "drift is a policy verdict");
    assert!(
        stdout(&output).contains("host.delete_branch_on_merge"),
        "the refusal names the key an author must edit: {}",
        stdout(&output)
    );
    // POINTER, NEVER PAYLOAD: which side claims what, never a byte of the
    // host's response.
    assert!(
        stdout(&output).contains("-true,+false"),
        "{}",
        stdout(&output)
    );
}

/// The agreement half, plus the arm that keeps this from over-reporting.
///
/// A key the tree does not claim is silent: a consumer projecting one setting
/// must not be told it disagrees about two it never mentioned. Without this the
/// case above passes over a comparison that reports every absent key as drift.
#[test]
fn a_host_setting_the_tree_agrees_with_is_clean_and_an_unclaimed_one_is_silent() {
    let dir = repo_with_config(
        "host-agree",
        "version = 1

[host]
delete_branch_on_merge = true
",
    );
    let payload = dir.join("repo.json");
    std::fs::write(
        &payload,
        r#"{"delete_branch_on_merge": true, "web_commit_signoff_required": false,
            "security_and_analysis": {"secret_scanning_push_protection": {"status": "disabled"}}}"#,
    )
    .expect("write payload");

    let output = lint(&dir, &["--host-rules", payload.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "two unclaimed keys the host reports are not drift: {}",
        stdout(&output)
    );
}

#[test]
fn a_host_that_constrains_merge_methods_while_the_config_omits_them_is_drift() {
    // The dangerous direction: the projection silently claims freedom the host
    // does not grant.
    let dir = repo_with_config("ci-omits-methods", &ci_config(""));
    let output = lint_against(&dir, "rules-merge-methods");
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(text.contains("ci-allowed-merge-methods-drift"), "{text:?}");
    assert!(text.contains("+squash"), "{text:?}");
}

#[test]
fn a_config_claiming_a_method_the_host_does_not_allow_is_drift() {
    let dir = repo_with_config(
        "ci-extra-method",
        &ci_config("allowed_merge_methods = [\"merge\", \"squash\"]\n"),
    );
    let output = lint_against(&dir, "rules-merge-methods");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("-merge"));
}

#[test]
fn a_legacy_payload_is_clean_on_the_method_half_and_still_compares_checks() {
    // No `pull_request` rule at all — the shape legacy branch protection
    // produces. A config that omits the key agrees with it.
    let dir = repo_with_config(
        "ci-legacy",
        "version = 1\n\n[ci]\nrequired_checks = [\"build\", \"test\"]\n",
    );
    assert_eq!(
        lint_against(&dir, "rules-legacy").status.code(),
        Some(0),
        "omitting the key agrees with a host that constrains no method"
    );

    // The check half is still compared, so a legacy payload is not a free pass.
    let wrong = repo_with_config(
        "ci-legacy-wrong",
        "version = 1\n\n[ci]\nrequired_checks = [\"build\"]\n",
    );
    let output = lint_against(&wrong, "rules-legacy");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("+test"));
}

#[test]
fn a_payload_that_is_not_a_rules_array_is_a_usage_error() {
    let dir = repo_with_config("ci-bad-payload", &ci_config(""));
    let path = dir.join("not-rules.json");
    fs::write(&path, "{\"message\":\"Not Found\"}").expect("write payload");
    let output = lint(&dir, &["--host-rules", path.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a gate handed the wrong document says so rather than deriving an empty \
         contract from it"
    );
    assert!(stderr(&output).contains("rules-API array"));
}

#[test]
fn asking_for_a_comparison_the_config_cannot_join_is_a_usage_error() {
    // `--host-rules` with no committed `[ci]`: the caller asked for a comparison
    // one side cannot participate in, and answering "no drift" would be a pass
    // over nothing.
    let dir = repo_with_config("ci-absent", "version = 1\n");
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("[ci]"));
}

#[test]
fn a_malformed_ci_table_is_refused_at_parse() {
    for (name, table) in [
        (
            "ci-unknown-key",
            "[ci]\nrequired_checks = [\"a\"]\nbogus = 1\n",
        ),
        ("ci-empty", "[ci]\nrequired_checks = []\n"),
        ("ci-duplicate", "[ci]\nrequired_checks = [\"a\", \"a\"]\n"),
        (
            "ci-bad-method",
            "[ci]\nrequired_checks = [\"a\"]\nallowed_merge_methods = [\"fast-forward\"]\n",
        ),
    ] {
        let dir = repo_with_config(name, &format!("version = 1\n\n{table}"));
        let output = lint(&dir, &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: a malformed table is refused, never ignored"
        );
    }
}

#[test]
fn the_drift_report_is_byte_stable_and_reads_stdin() {
    let dir = repo_with_config(
        "ci-stable",
        "version = 1\n\n[ci]\nrequired_checks = [\"other\"]\n",
    );
    let payload = fs::read_to_string(rules_fixture("rules-required-checks")).expect("fixture");

    // `-` is stdin, which is how the CI task pipes a live fetch in.
    let piped = |args: &[&str]| -> Output {
        let mut command = batten();
        command
            .current_dir(&dir)
            .args(["config", "lint", "--host-rules", "-"])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn batten");
        std::io::Write::write_all(
            &mut child.stdin.take().expect("piped stdin"),
            payload.as_bytes(),
        )
        .expect("write payload");
        child.wait_with_output().expect("run batten")
    };

    let first = piped(&["-J"]);
    let second = piped(&["-J"]);
    assert_eq!(first.status.code(), Some(2));
    assert_eq!(
        first.stdout, second.stdout,
        "identical input must produce identical bytes"
    );
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("ci-required-checks-drift"),
        "the machine channel carries the smell too"
    );
}

#[test]
fn lint_without_the_flag_is_unchanged() {
    // The drift half is additive: a run that does not ask for it must behave
    // exactly as it did before this landed.
    let dir = repo_with_config("ci-no-flag", &ci_config(""));
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!stdout(&output).contains("ci-"), "no drift smell appears");
}

// --- the pair a CI job's pass/fail reduces to (CLOUD-236) --------------------

#[test]
fn the_armed_comparison_is_a_two_sided_verdict_over_one_tree() {
    // CLOUD-236 arms `--config-from` in CI against the PR's own base ref, and a
    // CI job is a boolean: it fails or it does not. So the behavioural claim the
    // workflow rests on is a PAIR, asserted here rather than inferred from the
    // two halves living in separate cases — a gate that only ever fails is
    // indistinguishable from one that is stuck, and it is the passing half that
    // says the arming has not simply broken every PR.
    //
    // Same base, same rule, one variable: whether the working tree lowered it.
    let base = format!("version = 1\n{}", rule("no-todo", "deny"));

    let weakened = pr_fixture(
        "armed-weakened",
        &base,
        &format!("version = 1\n{}", rule("no-todo", "warn")),
    );
    let refused = lint(&weakened, &["--config-from", "origin/main"]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "a branch that lowers the bar it is judged by must be the policy verdict"
    );
    assert!(
        stdout(&refused).contains("severity-lowered"),
        "got: {}",
        stdout(&refused)
    );

    let unchanged = pr_fixture("armed-unchanged", &base, &base);
    let allowed = lint(&unchanged, &["--config-from", "origin/main"]);
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "arming the flag must not fail a branch that changed no policy"
    );
    assert_eq!(stdout(&allowed), "config-lint: 0 smell(s)\n");
}

#[test]
fn the_armed_comparison_still_reports_a_single_tree_smell() {
    // The two classes compose rather than replace each other. This is what the
    // task-level bypass is bounded against: armed, one invocation can report a
    // base-ref weakening AND a property of the commit, and a hatch for the first
    // must not quietly cover the second (`mise-tasks/config-lint.sh`).
    let repo = pr_fixture(
        "armed-both-classes",
        &format!(
            "version = 1\nprotected = [\"a\"]\n{}",
            rule("no-todo", "deny")
        ),
        &format!("version = 1\nprotected = []\n{}", rule("no-todo", "warn")),
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    let seen = stdout(&output);
    assert!(seen.contains("empty-protected-set"), "got: {seen}");
    assert!(seen.contains("severity-lowered"), "got: {seen}");
}
