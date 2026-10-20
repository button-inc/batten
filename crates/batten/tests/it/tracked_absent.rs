//! Three task-body gates retired onto policy modules over the compiled engine
//! (CLOUD-1991): `hk-version` onto `policy/hk-pin-agreement.rego`, `no-docs-tree`
//! onto `policy/docs-tree-absent.rego`, and `no-armed-ripcord` onto
//! `policy/ripcord-untracked.rego`.
//!
//! # Why this tier and not only the modules' own `test_` rules
//!
//! A `with input as` case writes the shape it then reads, so it is green over a
//! key the engine never fills (CLOUD-845). Every case here goes in through
//! `batten check` over a fixture repository, so what it pins is that the engine
//! FILLS `input.tree.documents["mise.toml"]`, `input.tree.lines["hk.pkl"]` and
//! `input.tree["git-index"][<spec>]` for the rows as `batten.toml` declares them,
//! and that `data.batten.patterns` reaches the module from a `[[pattern]]` row.
//!
//! # RETIREMENT LEDGER — the three `mise.toml` bodies
//!
//! The bodies were inline task shell, not governed paths, so they owe no
//! file-granularity arm; the properties each asserted are carried case by case.
//!
// carried: "hk-version: mise.toml and hk.pkl agree on the hk version" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// carried: "hk-version: a drift between the two pins is refused" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// carried: "hk-version: a pin neither file names refuses rather than passes (`:?`)" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// changed: "hk-version: only the first `hk@` in hk.pkl is compared" policy/hk-pin-agreement.rego the module compares every `hk@<version>` the file names, so a second amends line naming another version is refused rather than shadowed by `head -n1`
// carried: "no-docs-tree: a tracked path under docs/ is refused, naming one" policy/docs-tree-absent.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-docs-tree: a tree with no docs/ passes" policy/docs-tree-absent.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-armed-ripcord: a tracked sentinel is refused" policy/ripcord-untracked.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-armed-ripcord: an armed but untracked sentinel passes" policy/ripcord-untracked.rego crates/batten/tests/it/tracked_absent.rs
// changed: "the three gates run in the pre-commit tier" hk.pkl their hk steps are `slow` now, because the task is `batten check` over a module and a commit may not pay a compile (CLOUD-1397); `batten-check`'s `enforce` also judges all three rows at `verify` and in CI, so what moves is WHEN a violation is caught, from the commit to the landing path

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The rows and classes a fixture carries, hand-built rather than copied from
/// the committed authority for `mise_pin_agreement.rs`'s reason: the whole
/// authority drags every other row's module into a tree that does not have one.
const AUTHORITY: &str = r#"version = 1

[[pattern]]
id = "hk-amends-version"
regex = 'hk@([0-9]+\.[0-9]+\.[0-9]+)'

[[pattern]]
id = "hk-download-tag"
regex = '/v([0-9]+\.[0-9]+\.[0-9]+)/hk@'

[[rule]]
id = "tool pin other"
kind = "policy"
scope = "tree"
documents = ["mise.toml"]
line_sources = ["hk.pkl"]
module = "policy/hk-pin-agreement.rego"
severity = "deny"
reason = "set both pins to one version."

[[rule]]
id = "prose place refused"
kind = "policy"
scope = "tree"
index = ["docs"]
module = "policy/docs-tree-absent.rego"
severity = "deny"
reason = "research belongs on the tracker row."

[[rule]]
id = "path ship refused"
kind = "policy"
scope = "tree"
index = [".batten-ripcord"]
module = "policy/ripcord-untracked.rego"
severity = "deny"
reason = "remove the sentinel from the index."

[[verdict]]
id = "tool pin other"
gloss = "hk.pkl names a different hk than mise.toml pins"
class = """
Set both to one version.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/hk-pin-agreement.rego"

[[verdict]]
id = "prose place refused"
gloss = "a path under docs/ is tracked"
class = """
Move it onto the tracker row.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/docs-tree-absent.rego"

[[verdict]]
id = "path ship refused"
gloss = "the break-glass sentinel is tracked"
class = """
Remove it from the index.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/ripcord-untracked.rego"
"#;

const MODULES: [&str; 3] = [
    "policy/hk-pin-agreement.rego",
    "policy/docs-tree-absent.rego",
    "policy/ripcord-untracked.rego",
];

/// An `amends` line with each half of the URL named separately — the release
/// tag and the `hk@` fragment. Which half drifts is then the only thing a case
/// states, instead of a reader spotting it inside a 90-character literal.
fn amends_halves(tag: &str, fragment: &str) -> String {
    format!(
        "amends \"package://github.com/jdx/hk/releases/download/v{tag}/hk@{fragment}#/Config.pkl\"\n"
    )
}

/// An `amends` line in the shape `hk.pkl` really spells it: both halves agree.
fn amends(version: &str) -> String {
    amends_halves(version, version)
}

/// The `pkl-package` task with each half of its URL named separately — the
/// release tag and the `hk@` fragment. Which half drifts is then the only thing
/// a case states, which is `amends_halves`'s reason on the other surface.
///
/// Carries the whole task table, not just the URL, so a package case naming
/// drifting halves is one `format!` over `[tools]` plus this. A case whose `run`
/// names no version at all goes through `package_manifest` instead, since this
/// always writes a `/v<semver>/` segment.
fn package_task_halves(tag: &str, fragment: &str) -> String {
    format!(
        "[tasks.pkl-package]\nrun = \"pkl download-package package://github.com/jdx/hk/releases/download/v{tag}/hk@{fragment}\"\n"
    )
}

/// The `pkl-package` task as `mise.toml` really spells it: both halves agree.
fn package_task(version: &str) -> String {
    package_task_halves(version, version)
}

/// A whole `mise.toml` — the agreeing `[tools]` pin plus a `[tasks.pkl-package]`
/// whose `run` is spelled exactly as the case gives it, TOML and all.
///
/// `package_task_halves`'s reason, for the family `package_task_halves` cannot
/// serve: the cases whose `run` names no version at all — whether by carrying no
/// URL or by carrying a `latest` one. They differ from each other by as little
/// as three spaces, and inline those sat at column 85 of an escaped one-liner.
/// Here the difference is the argument.
fn package_manifest(run: &str) -> String {
    format!("[tools]\nhk = \"1.56.1\"\n\n[tasks.pkl-package]\nrun = {run}\n")
}

/// A committed fixture repository carrying the three committed modules, the
/// authority above, agreeing hk pins, and whatever else the case adds.
///
/// COMMITTED, because `line_sources` and the index projection read tracked
/// paths: an uncommitted fixture would be invisible and every refusal below
/// would pass vacuously.
fn fixture(name: &str, files: &[(&str, &str)], force_add: &[&str]) -> PathBuf {
    let root = common::scratch(&format!("tracked-absent-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    for module in MODULES {
        let source = common::at_root(module)
            .canonicalize()
            .expect("the committed module is where the row says it is");
        fs::copy(source, root.join(module)).expect("install committed module");
    }
    fs::write(root.join("batten.toml"), AUTHORITY).expect("write the fixture authority");
    fs::write(root.join("mise.toml"), "[tools]\nhk = \"1.56.1\"\n").expect("mise.toml");
    fs::write(root.join("hk.pkl"), amends("1.56.1")).expect("hk.pkl");
    for (path, body) in files {
        if let Some(parent) = root.join(path).parent() {
            fs::create_dir_all(parent).expect("fixture parent");
        }
        fs::write(root.join(path), body).expect("write a fixture file");
    }
    common::init_repo(&root);
    common::git_in(&root, &["add", "-A"]);
    for path in force_add {
        common::git_in(&root, &["add", "-f", path]);
    }
    common::git_in(&root, &["commit", "-q", "-m", "fixture"]);
    root
}

/// `batten check` over the fixture: its exit code and everything it said.
fn check(root: &Path) -> (Option<i32>, String) {
    let output = common::run(root, &["check"]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code(), said)
}

fn denied(root: &Path, rule: &str, pointer: &str) {
    let (code, said) = check(root);
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Violation.code()),
        "expected the policy verdict: {said}"
    );
    assert!(said.contains(rule), "the finding names `{rule}`: {said}");
    assert!(
        said.contains(pointer),
        "the finding points at `{pointer}`: {said}"
    );
}

fn clean(root: &Path) {
    let (code, said) = check(root);
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Success.code()),
        "expected a clean tree: {said}"
    );
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by modules
// that refuse everything.
// ---------------------------------------------------------------------------

#[test]
fn agreeing_pins_no_docs_and_no_sentinel_are_clean() {
    let root = fixture("clean", &[], &[]);
    clean(&root);
}

// ---------------------------------------------------------------------------
// hk-version.
// ---------------------------------------------------------------------------

/// Both halves of the URL disagree with the pin — the fixture moves `[tools]`,
/// not the URL — so arms A and A2 both fire on one line and collapse to one
/// finding.
///
/// It does NOT carry `#MUTANT hk-pin-disagreement-passes` any more, and that is
/// the point: `amends()` writes one version into both halves, so A2 masks A
/// here and neutering arm A changes nothing this case can see. The mutant names
/// `an_amends_fragment_naming_another_version_is_refused` instead, where only
/// the fragment drifts.
#[test]
fn a_version_the_amends_url_names_differently_is_refused() {
    let root = fixture(
        "hk-drift",
        &[("mise.toml", "[tools]\nhk = \"1.57.0\"\n")],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

/// `#MUTANT hk-package-disagreement-passes` reddens here.
///
/// The third spelling of the pin (CLOUD-2311): `[tasks.pkl-package]` fetches the
/// package `hk.pkl` amends, so its URL names a version too. Here the amends line
/// and the `[tools]` pin agree at 1.56.1 and only the fetch drifts — so arm D is
/// the only arm that can see it, and a pass means the fetch is ungoverned.
#[test]
fn a_package_task_naming_another_version_is_refused() {
    let manifest = format!("[tools]\nhk = \"1.56.1\"\n\n{}", package_task("1.57.0"));
    let root = fixture("hk-package-drift", &[("mise.toml", &manifest)], &[]);
    denied(&root, "tool pin other", "mise.toml");
}

/// The same fixture with the fetch agreeing: the arm refuses the disagreement
/// and not the task's presence, so declaring it cannot itself be a violation.
#[test]
fn a_package_task_naming_the_pin_is_clean() {
    let manifest = format!("[tools]\nhk = \"1.56.1\"\n\n{}", package_task("1.56.1"));
    let root = fixture("hk-package-agreed", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-pin-disagreement-passes` reddens here — and NOT on
/// `a_version_the_amends_url_names_differently_is_refused`, which it used to
/// name. `amends()` writes one version into both halves of the URL, so arm A2
/// also fires there and emits a byte-identical finding: neutering arm A changes
/// nothing a case can see. The module header carries the measurement.
///
/// Here only the FRAGMENT drifts. The tag segment equals the pin, so A2 is
/// silent and arm A is the one arm that can refuse this.
#[test]
fn an_amends_fragment_naming_another_version_is_refused() {
    let root = fixture(
        "hk-fragment-drift",
        &[("hk.pkl", &amends_halves("1.56.1", "1.57.0"))],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

/// `#MUTANT hk-amends-merge-narrows-arm-b` reddens here.
///
/// A floating FRAGMENT over an agreeing tag. Arm A is silent (nothing to bind),
/// arm A2 is silent (the tag equals the pin), and only arm B's
/// `count(amends) == 0` can refuse it — which is true only while `amends` holds
/// fragment matches alone. Merge the two sets and this goes clean, which is the
/// defect this branch made on both surfaces before the mutation was declared.
#[test]
fn an_amends_fragment_floating_over_an_agreeing_tag_is_refused() {
    let root = fixture(
        "hk-fragment-floats",
        &[("hk.pkl", &amends_halves("1.56.1", "latest"))],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

/// `#MUTANT hk-package-merge-narrows-arm-e` reddens here — the same defect on
/// the fetch URL, where it would let the fetch float to `latest` while `hk.pkl`
/// amends a fixed version.
#[test]
fn a_package_fragment_floating_over_an_agreeing_tag_is_refused() {
    let manifest = format!(
        "[tools]\nhk = \"1.56.1\"\n\n{}",
        package_task_halves("1.56.1", "latest")
    );
    let root = fixture("hk-package-floats", &[("mise.toml", &manifest)], &[]);
    denied(&root, "tool pin other", "mise.toml");
}

/// `#MUTANT hk-package-unnamed-passes` reddens here: arm E, which is arm B's
/// claim for the fetch URL. `hk@latest` over a path with no `/v<semver>/`
/// segment matches neither pattern, so `packages` is empty and arm D has
/// nothing to compare — the fetch would warm a package `hk.pkl` does not amend.
#[test]
fn a_package_task_naming_no_version_is_refused() {
    let manifest = package_manifest(
        r#""pkl download-package package://github.com/jdx/hk/releases/download/latest/hk@latest""#,
    );
    let root = fixture("hk-package-unnamed", &[("mise.toml", &manifest)], &[]);
    denied(&root, "tool pin other", "mise.toml");
}

/// `#MUTANT hk-package-stepless-run-fires` reddens here. An empty `run` array
/// binds `package_run` while yielding no step, so `packages` is empty for a
/// manifest that names no fetch URL at all — and arm E without its step guard
/// reports a pin disagreement against a tree with nothing to disagree with.
#[test]
fn a_package_task_with_an_empty_run_is_clean() {
    let manifest = package_manifest("[]");
    let root = fixture("hk-package-stepless", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-package-empty-run-string-counted` reddens here: the string
/// spelling of the same empty task, which `run = []` cannot reach because an
/// empty array binds `package_run` without yielding an entry to test.
#[test]
fn a_package_task_with_an_empty_run_string_is_clean() {
    let manifest = package_manifest(r#""""#);
    let root = fixture("hk-package-empty-run", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-package-empty-step-counted` reddens here: the array spelling,
/// which reaches the other `is_step` call. One element, a string, naming no
/// version.
#[test]
fn a_package_task_whose_only_step_is_empty_is_clean() {
    let manifest = package_manifest(r#"[""]"#);
    let root = fixture("hk-package-empty-step", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-package-blank-step-counted` reddens here. Whitespace is not a
/// command, and this is the shape that cleared the string body's emptiness test
/// — the measurement that folded three guards into `is_step`: the array body's
/// `is_string` and both `!= ""` tests.
#[test]
fn a_package_task_whose_run_is_blank_is_clean() {
    let manifest = package_manifest(r#""   ""#);
    let root = fixture("hk-package-blank", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-package-array-blank-reinlined` reddens here, and only here: the
/// array half's guard re-inlined as a bare `!= ""`, which is the shape `is_step`
/// was extracted to retire. `[""]` stays clean under it and `"   "` never
/// reaches the array half, so this corner is the one that can show it.
#[test]
fn a_package_task_whose_only_step_is_blank_is_clean() {
    let manifest = package_manifest(r#"["   "]"#);
    let root = fixture("hk-package-blank-step", &[("mise.toml", &manifest)], &[]);
    clean(&root);
}

/// `#MUTANT hk-amends-tag-disagreement-passes` reddens here.
///
/// The other half of `hk.pkl`'s own URL (CLOUD-2311): it names the version in
/// the release tag as well as the `hk@` fragment. Here the fragment agrees with
/// the pin and only the tag drifts, so arm A sees nothing and only arm A2 can
/// refuse it — a pass means half the string the module claims to govern is
/// ungoverned.
#[test]
fn an_amends_tag_segment_naming_another_version_is_refused() {
    let root = fixture(
        "hk-tag-drift",
        &[("hk.pkl", &amends_halves("1.57.0", "1.56.1"))],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

/// `#MUTANT hk-amends-unnamed-passes` reddens here: the shell's `:?` on an
/// `hk.pkl` whose `amends` names no version.
#[test]
fn an_hk_pkl_naming_no_version_is_refused() {
    let root = fixture(
        "hk-unnamed",
        &[(
            "hk.pkl",
            "amends \"package://example.invalid/Config.pkl\"\n",
        )],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

// ---------------------------------------------------------------------------
// no-docs-tree.
// ---------------------------------------------------------------------------

/// `#MUTANT docs-tree-admitted` reddens here.
#[test]
fn a_tracked_docs_file_is_refused() {
    let root = fixture("docs", &[("docs/notes.md", "# notes\n")], &[]);
    denied(&root, "prose place refused", "docs/notes.md");
}

/// A path that merely STARTS with `docs` is not under the tree.
#[test]
fn a_sibling_named_like_docs_is_not_the_docs_tree() {
    let root = fixture("docs-sibling", &[("docsite/index.md", "# site\n")], &[]);
    clean(&root);
}

// ---------------------------------------------------------------------------
// no-armed-ripcord.
// ---------------------------------------------------------------------------

/// `#MUTANT ripcord-admitted` reddens here. The sentinel is ignored by name, as
/// it is in this repository, so reaching the index takes `git add -f` — the
/// case the gate exists for.
#[test]
fn a_force_added_sentinel_is_refused() {
    let root = fixture(
        "ripcord-tracked",
        &[(".gitignore", ".batten-ripcord\n"), (".batten-ripcord", "")],
        &[".batten-ripcord"],
    );
    denied(&root, "path ship refused", ".batten-ripcord");
}

/// ARMED is not SHIPPED: an ignored sentinel in the working tree is one
/// operator's break-glass and reaches no clone.
#[test]
fn an_armed_but_ignored_sentinel_is_clean() {
    let root = fixture(
        "ripcord-armed",
        &[(".gitignore", ".batten-ripcord\n"), (".batten-ripcord", "")],
        &[],
    );
    clean(&root);
}
