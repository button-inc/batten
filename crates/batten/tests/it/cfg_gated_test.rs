//! `policy/cfg-gated-test.rego` over the COMPILED engine (CLOUD-1148).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads, and this module reads two
//! facts that a `with input as` case fabricates for free and the engine has to
//! earn: `input.tree.lines[path]` for the working tree, and
//! `input.tree["base-delta"]["base-lines"][path]` for the same path's committed
//! bytes. The second is the one worth a tier of its own — it is the whole
//! difference between this rule and a state rule, and a module reading a
//! `base-lines` key the engine never filled would report clean over every branch
//! while its own suite stayed green.
//!
//! `rules/policy-modules.md` records that class twice: a module copied from
//! `policy.rs`'s own doc iterated a tree key the engine never built, and
//! OpenTelemetry's `weaver` printed "No policy violation", exit 0, over a
//! knowingly-broken registry because its module read a key the v1 schema does
//! not build. Both live instances in this tree were found by adding this tier.
//!
//! # What the rule is for
//!
//! A `#[cfg(<platform>)]` on a `#[test]` takes the case out of the build on
//! every other target, so `cross-check` type-checks only the arm the local host
//! admits. `cfg!` inside the body keeps both compiled and states the
//! off-platform contract where a reader can see it. The rule is a RATCHET rather
//! than a state check: this tree carries ~40 legitimate `#[cfg(unix)]` `#[test]`
//! pairs whose subject genuinely does not exist off unix, and a gate refusing
//! those on its first run is one an author switches off.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::config_model::Rule;
use batten::rules;

/// The predicate id the module declares — NOT the `[[rule]]` id, which is
/// `test cover missing`. The two differ, and the difference is load-bearing: an
/// admission resolves its anchor by the FINDING's rule, so minting against the
/// config id silently produces a `call:<head>` anchor that suppresses nothing.
const GATED_ADDED: &str = "test cover unseen";

/// A fixture repository whose base commit carries `before` at
/// `crates/batten/src/subject.rs` and whose working tree carries `after`.
///
/// The pair is the point: the engine has to resolve the committed side from git
/// as `base-lines` and read the working side as `lines`, and a rule that got
/// either from a harness would pass over a branch it never compared.
///
/// `origin/main` is a local ref pointed at the base commit, for `test_targets.rs`
/// and `filed_here.rs`'s reason: `base_delta` resolves a rev, and configuring a
/// remote would make an entirely local question depend on the network. It is
/// written by [`common::pin_origin_main`] rather than by `git update-ref`, which
/// is all that verb does on a repository this young.
///
/// NO HAND-ROLLED `git init` — [`common::init_repo`] copies the one template the
/// whole suite shares. CLOUD-1419 measured 79 forked inits producing 1,819 git
/// processes over one traced run, and `test fix duplicate` refused this helper's first
/// spelling at the line that wrote it.
fn repo(name: &str, before: &[&str], after: &[&str]) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);

    let subject = root.join("crates/batten/src/subject.rs");
    fs::create_dir_all(subject.parent().expect("a parent")).expect("scratch parent");
    fs::write(&subject, join(before)).expect("seed the committed side");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    common::pin_origin_main(&root);

    fs::write(&subject, join(after)).expect("write the working side");

    install_module(&root);
    root
}

fn join(lines: &[&str]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/cfg-gated-test.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/cfg-gated-test.rego")).expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here — including the `line_sources` glob, without which the module reads
/// no lines and refuses nothing.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "test cover missing",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "line_sources": ["crates/**/*.rs"],
        "module": "policy/cfg-gated-test.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            registers: &[],
            traversals: &[],
            records: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

fn classes(root: &Path) -> Vec<String> {
    let scanned = scan(root);
    scanned
        .findings
        .iter()
        .filter_map(|finding| {
            scanned
                .classes
                .get(&finding.identity.fingerprint.to_hex())
                .cloned()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_that_adds_no_attribute_passes_untouched() {
    let root = repo(
        "cfg-gated-clean",
        &["#[test]", "fn a() {}"],
        &["#[test]", "fn a() {}", "// a new comment"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "an edit that narrows no case is not this rule's business"
    );
}

/// THE REFUSAL, over the engine's own `base-lines` rather than a harness's.
///
/// `#MUTANT direction-may-invert` and `#MUTANT reach-may-be-empty` both redden
/// here: the first flips `after > base`, the second empties the offset set so no
/// `cfg` reaches any `#[test]`.
#[test]
fn a_branch_that_adds_a_platform_gated_test_is_refused() {
    let root = repo(
        "cfg-gated-added",
        &["#[test]", "fn a() {}"],
        &["#[cfg(unix)]", "#[test]", "fn a() {}"],
    );
    assert_eq!(
        verdicts(&root),
        vec![GATED_ADDED.to_owned()],
        "the attribute is new against the committed side, and the engine's own \
         base-lines is what has to surface that"
    );
    assert_eq!(
        classes(&root),
        vec!["test cover partial".to_owned()],
        "the finding carries the declared class, which is what an admission \
         binds against"
    );
}

/// THE CASE THAT MAKES THE RULE SURVIVABLE, and the one an implementer would
/// skip. This tree's ~40 pre-existing pairs are legitimate — their subject does
/// not exist off unix — so an edit to a file carrying one must pass, or the gate
/// fires on ordinary work and gets switched off.
///
/// `#MUTANT base-may-read-as-empty` reddens exactly here: replacing the base
/// count with `0` makes every pre-existing pair read as newly added.
#[test]
fn a_pre_existing_platform_gated_test_survives_an_edit() {
    let root = repo(
        "cfg-gated-preexisting",
        &["#[cfg(unix)]", "#[test]", "fn a() {}"],
        &[
            "#[cfg(unix)]",
            "#[test]",
            "fn a() {}",
            "",
            "// an unrelated edit to the same file",
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the count did not go up, and a ratchet only ever asks the direction"
    );
}

/// THE DISCRIMINATING PARTNER for `#MUTANT block-may-span-code`. Code between
/// the `cfg` and the `#[test]` means the attribute gates the CODE, not the case —
/// which is how every legitimate unix-only helper in this tree is written, sitting
/// directly above the cases it serves.
///
/// With `attribute_or_doc` neutered to `true` the two ends join across the `use`
/// line and this passes-side case turns red, which is the kill.
#[test]
fn a_cfg_far_from_the_test_with_code_between_is_not_a_gated_test() {
    let root = repo(
        "cfg-gated-spanning",
        &["#[test]", "fn a() {}"],
        &[
            "#[cfg(unix)]",
            "use std::os::unix::fs::MetadataExt as _;",
            "",
            "#[test]",
            "fn a() {}",
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a cfg over an import is not a cfg over the case below it, and reading \
         one as the other refuses every unix-only helper in the tree"
    );
}

/// THE ONE-KEYSTROKE EVASION, which is why the reach is three rather than one.
/// An `#[allow]` written between the two lines must not buy a bypass.
#[test]
fn an_interleaved_attribute_does_not_buy_a_bypass() {
    let root = repo(
        "cfg-gated-interleaved",
        &["#[test]", "fn a() {}"],
        &[
            "#[cfg(target_os = \"linux\")]",
            "#[allow(clippy::unwrap_used)]",
            "/// what it does",
            "#[test]",
            "fn a() {}",
        ],
    );
    assert_eq!(
        verdicts(&root),
        vec![GATED_ADDED.to_owned()],
        "two attributes and a doc line between the cfg and the #[test] are still \
         one attribute run"
    );
}

/// `#[cfg(test)]` IS THE MODULE GATE and varies with no target, so it can leave
/// no arm uncompiled. Refusing it would refuse every unit-test module in the
/// crate — a first firing that is a false positive on ~every file.
#[test]
fn the_test_module_gate_is_not_a_platform_gate() {
    let root = repo(
        "cfg-gated-module-gate",
        &["fn a() {}"],
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    #[test]",
            "    fn a() {}",
            "}",
        ],
    );
    assert!(verdicts(&root).is_empty(), "cfg(test) names no platform");
}

/// `cfg!` IS THE REMEDY, so the shape the doctrine asks for has to pass — over
/// the compiled engine and not only in the module's own tier. A rule that
/// refused its own remedy would have no route out.
#[test]
fn the_cfg_macro_inside_the_body_is_the_remedy() {
    let root = repo(
        "cfg-gated-remedy",
        &["#[test]", "fn a() {}"],
        &[
            "#[test]",
            "fn a() {",
            "    if cfg!(unix) {",
            "        assert!(true);",
            "    } else {",
            "        assert!(true);",
            "    }",
            "}",
        ],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the whole point of the rule is that this spelling lands"
    );
}

/// AN ADDED FILE HAS NO BASE SIDE, and its count is zero rather than
/// unreadable: the same defect arriving in one commit instead of two.
#[test]
fn an_added_file_carrying_a_gated_test_is_refused() {
    let root = repo("cfg-gated-new-file", &["fn a() {}"], &["fn a() {}"]);
    let added = root.join("crates/batten/src/fresh.rs");
    fs::write(&added, join(&["#[cfg(windows)]", "#[test]", "fn b() {}"]))
        .expect("write an added file");
    assert_eq!(
        verdicts(&root),
        vec![GATED_ADDED.to_owned()],
        "a path with no committed side compares against zero, not against \
         could-not-look"
    );
}

/// The rule run over a CHANGE-SET, as `batten check --staged` narrows it: the
/// verdict classes a run scoped to `changed` reaches.
fn verdicts_scoped(root: &Path, changed: &[&str]) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    let scope = rules::Scope::Changed(changed.iter().map(|path| (*path).to_owned()).collect());
    rules::run_static_over(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            registers: &[],
            traversals: &[],
            records: &[],
        },
        root,
        rules::RunOptions {
            checks: batten::policy::ModuleChecks::Run,
            scope: &scope,
            surface: batten::facts::Surface::Check,
            now: None,
            half: None,
            keyed_bases: &[],
        },
    )
    .expect("the read surface runs a policy row over a change-set")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

/// A COMMIT IS JUDGED ON WHAT IT STAGES, never on an unstaged file beside it
/// (CLOUD-2789). The pre-commit step runs `check --staged`, and the module read
/// `lines` for every tracked `.rs` file whatever the scope said: 4.4 s p50 at
/// every commit, and a refusal of this commit for a gated test that is not in it.
///
/// Fails by: a scoped run reading an unstaged file's lines (the first assertion
/// refuses `subject.rs`, which is not in the change-set), or the narrowing
/// dropping the staged file itself (the second sees nothing).
#[test]
fn a_staged_run_reads_only_the_staged_files_lines() {
    let root = repo(
        "cfg-gated-staged-only",
        &["#[test]", "fn a() {}"],
        &["#[cfg(unix)]", "#[test]", "fn a() {}"],
    );
    let staged = root.join("crates/batten/src/staged.rs");
    fs::write(&staged, join(&["fn b() {}"])).expect("write the staged file");
    assert_eq!(
        verdicts_scoped(&root, &["crates/batten/src/staged.rs"]),
        Vec::<String>::new(),
        "the unstaged gated test in subject.rs is not this commit's"
    );
    assert_eq!(
        verdicts_scoped(&root, &["crates/batten/src/subject.rs"]),
        vec![GATED_ADDED.to_owned()],
        "the same edit, staged, is refused as the unnarrowed run refuses it"
    );
}

/// A STAGED MOVE IS STILL A MOVE (CLOUD-2789). The staged change-set names the
/// file's new home and never its old one, since a deletion leaves no index
/// entry; the narrowed delta keeps the whole branch's deletions so the new home
/// is paired with its base lines. Without that, moving a pre-existing
/// platform-gated test between crates is refused at the commit as an addition.
///
/// Fails by: the narrowed delta dropping deletions (the move reads as an added
/// file carrying one gated test, and is refused).
#[test]
fn a_staged_move_of_a_gated_test_is_not_an_addition() {
    let gated = ["#[cfg(unix)]", "#[test]", "fn a() {}"];
    let root = repo("cfg-gated-staged-move", &gated, &gated);
    fs::remove_file(root.join("crates/batten/src/subject.rs")).expect("move: delete");
    let moved = root.join("crates/batten-base/src/subject.rs");
    fs::create_dir_all(moved.parent().expect("a parent")).expect("move: new home");
    fs::write(&moved, join(&gated)).expect("move: write");
    assert_eq!(
        verdicts_scoped(&root, &["crates/batten-base/src/subject.rs"]),
        Vec::<String>::new(),
        "the moved file carries its base lines, so nothing grew"
    );
}

/// COULD NOT LOOK IS REPORTED, NEVER PASSED. With no `origin/main` the engine
/// resolves no delta, and a rule that refused nothing there would be
/// byte-identical to a clean tree on the decision surface — over a branch it
/// never read.
///
/// The class is `diff read absent`, reused from the registry rather than
/// restated: one concept, one spelling.
#[test]
fn an_unresolvable_base_reports_rather_than_passing() {
    let root = repo(
        "cfg-gated-no-base",
        &["#[test]", "fn a() {}"],
        &["#[cfg(unix)]", "#[test]", "fn a() {}"],
    );
    // The inverse of `pin_origin_main`'s loose-ref write, and a fork cheaper
    // than `update-ref -d` for the same effect on a repository this young.
    fs::remove_file(root.join(".git/refs/remotes/origin/main")).expect("unpin the base ref");
    assert_eq!(
        classes(&root),
        vec!["diff read absent".to_owned()],
        "an unresolvable base is a read failure, and the rule says so instead of \
         reporting the branch clean"
    );
}
