//! `input.tree.staged` and `input.tree.state`, over the compiled binary
//! (CLOUD-1203).
//!
//! **The discriminating case is `the_index_answers_not_the_worktree`**, and the
//! row says why: without it the suite is satisfied by a fact that reads the
//! checkout, which is the exact trap `Fact::Tracked`'s own doc names — *"this is
//! how a module author writes a predicate about the index and gets an answer
//! about the checkout."* So the fixture stages one value, leaves a DIFFERENT
//! value in the working tree, and asserts the module sees the staged one.
//!
//! That matters beyond tidiness. `lock-complete` is the pure "committed bytes
//! only" gate — it judges THE COMMIT, not the developer's working copy — so a
//! successor reading the worktree would answer a different question and pass
//! over a staged-but-unsaved edit. A silent wrong answer, not a missing feature.
//!
//! `tracked_still_means_the_working_tree` is the other half of that pair: the
//! row refuses widening `tracked` to mean the index, because that would change
//! every existing consumer's answer without any of them asking.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// Reads the staged value of a declared path, and reports which one it saw.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
staged = ["pinned.toml"]

[[verdict]]
id = "staged is index"
gloss = "the probe read the value that was staged"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe index probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "staged is worktree"
gloss = "the probe read the value left in the working tree"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe worktree probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "tracked sees thepath"
gloss = "the working-tree walk still yields the path, unchanged by the staged read"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe tracked probe"
kind = "document"
target = "probe.rego"
"#;

/// The same probe declaring NO staged path — the acquires-nothing arm.
const UNDECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["batten.toml"]

[[verdict]]
id = "staged is index"
gloss = "the probe read the value that was staged"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe index probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "staged is worktree"
gloss = "the probe read the value left in the working tree"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe worktree probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "tracked sees thepath"
gloss = "the working-tree walk still yields the path, unchanged by the staged read"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe tracked probe"
kind = "document"
target = "probe.rego"
"#;

/// Two predicates over one key, plus one over `tracked`.
///
/// The pair is what discriminates: a single "did I read something" rule would be
/// green whether the engine handed back the index or the checkout, which is the
/// whole failure this family exists to prevent.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "staged-is-index"

rules contains "staged-is-worktree"

rules contains "tracked-sees-the-path"

violation contains {
	"rule": "staged-is-index",
	"verdict": "staged is index",
} if {
	input.tree.staged["pinned.toml"].pin == "staged"
}

violation contains {
	"rule": "staged-is-worktree",
	"verdict": "staged is worktree",
} if {
	input.tree.staged["pinned.toml"].pin == "worktree"
}

violation contains {
	"rule": "tracked-sees-the-path",
	"verdict": "tracked sees thepath",
} if {
	some path in input.tree.tracked
	path == "pinned.toml"
}

test_a_staged_value_fires_the_index_class if {
	some v in violation with input as {"tree": {"staged": {"pinned.toml": {"pin": "staged"}}, "tracked": []}}
	v.rule == "staged-is-index"
}

test_a_worktree_value_fires_the_other_class if {
	some v in violation with input as {"tree": {"staged": {"pinned.toml": {"pin": "worktree"}}, "tracked": []}}
	v.rule == "staged-is-worktree"
}

test_an_absent_key_fires_neither if {
	count({v | some v in violation; startswith(v.rule, "staged-")}) == 0 with input as {"tree": {"staged": {}, "tracked": []}}
}
"#;

/// A repository whose index and working tree DISAGREE about one path.
///
/// That disagreement is the whole fixture: `pinned.toml` is committed saying
/// `staged`, and then overwritten in the checkout saying `worktree` without
/// being re-staged.
fn fixture(name: &str, config: &str, diverge: bool) -> PathBuf {
    let dir = scratch(&format!("staged-facts-{name}"));
    write(&dir, "batten.toml", config);
    write(&dir, "probe.rego", PROBE);
    write(&dir, "pinned.toml", "pin = \"staged\"\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    if diverge {
        // THE DIVERGENCE, and it is left unstaged on purpose: the index still
        // says `staged` and the checkout now says `worktree`, so the two facts
        // give different answers and the suite can tell which one was read.
        write(&dir, "pinned.toml", "pin = \"worktree\"\n");
    }
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn the_index_answers_not_the_worktree() {
    // THE CASE THE ROW SAYS MATTERS. Stage one value, leave a different one in
    // the working tree, assert the fact returns the STAGED one. Without it the
    // suite is satisfied by a fact that reads the checkout — the exact trap
    // `Fact::Tracked`'s doc names.
    let dir = fixture("index", CONFIG, true);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("staged-is-index"),
        "the fact must return the STAGED bytes\n{answer}{cause}"
    );
    assert!(
        !answer.contains("staged-is-worktree"),
        "reading the working tree here is the defect this family exists to prevent\n{answer}{cause}"
    );
}

#[test]
fn tracked_still_means_the_working_tree() {
    // `tracked` IS NOT WIDENED, asserted rather than assumed. The row refuses it
    // outright, because widening would change every existing consumer's answer
    // without any of them asking — and this suite is the one place both facts
    // are read over the same tree, so it is the place that can tell.
    let dir = fixture("tracked", CONFIG, true);
    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert!(
        answer.contains("tracked-sees-the-path"),
        "the working-tree walk must be unchanged by the staged read\n{answer}"
    );
}

#[test]
fn an_undeclared_path_is_not_staged_read() {
    // THE BOUND. Same repository, same divergence, and the row declares no
    // staged path: the key resolves nothing and both predicates are silent.
    // Without it the family reads whatever the index holds rather than what a
    // row asked for, and `Cost::Read` stops being an honest classification.
    let dir = fixture("undeclared", UNDECLARED, true);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(!answer.contains("staged-is-index"), "{answer}{cause}");
    assert!(!answer.contains("staged-is-worktree"), "{answer}{cause}");
}

#[test]
fn an_unstaged_path_is_could_not_look_never_an_empty_node() {
    // COULD-NOT-LOOK. The declared path is not in the index at all, so the row
    // is skipped rather than run against an empty node — a module handed one
    // would decide over a file that is not there, which is CLOUD-845's dead gate
    // arriving as a clean tree.
    let dir = scratch("staged-facts-unstaged");
    write(&dir, "batten.toml", CONFIG);
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    // `pinned.toml` is never written and never staged.
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an unstaged path must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("staged-is-index"), "{answer}{cause}");
    assert!(!answer.contains("staged-is-worktree"), "{answer}{cause}");
}

/// The same probe, over a path whose extension no [`Format`] owns.
///
/// `mise.lock` is TOML by content and `.lock` by name, and `Format::for_path`
/// decides on the NAME — so this config is the whole of `lock-complete`'s
/// blocker expressed as a fixture.
const LOCK: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "lock.rego"
severity = "deny"
staged = ["pinned.lock"]

[[verdict]]
id = "lock staged read"
gloss = "the probe resolved a node for the declared .lock path"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "lock read probe"
kind = "document"
target = "lock.rego"

[[verdict]]
id = "lock could notlook"
gloss = "the declared .lock path reached the could-not-look channel"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "lock missing probe"
kind = "document"
target = "lock.rego"
"#;

/// One predicate per direction, so the case cannot pass by both being silent.
///
/// The `missing` arm is the half that discriminates: without it a `.lock` that
/// resolved nothing and a `.lock` that was never declared are the same green.
/// The same row, DECLARING the format its extension cannot supply.
///
/// One line different from `LOCK` above, and that line is the whole of
/// CLOUD-1049's second half: `format` is consulted only where
/// `Format::for_path` returns nothing, so this resolves `pinned.lock` as TOML
/// without teaching the engine that every `.lock` anywhere is one.
const LOCK_DECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "lock.rego"
severity = "deny"
staged = ["pinned.lock"]
format = "toml"

[[verdict]]
id = "V-LOCK-STAGED-READ"
gloss = "the probe resolved a node for the declared .lock path"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-LOCK-READ"
kind = "document"
target = "lock.rego"

[[verdict]]
id = "V-LOCK-COULD-NOT-LOOK"
gloss = "the declared .lock path reached the could-not-look channel"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-LOCK-MISSING"
kind = "document"
target = "lock.rego"
"#;

const LOCK_PROBE: &str = r#"package batten.lockprobe

import rego.v1

rules contains "lock-staged-read"

rules contains "lock-could-not-look"

violation contains {
	"rule": "lock-staged-read",
	"verdict": "lock staged read",
	"subjects": [{"path": "pinned.lock"}],
} if {
	input.tree.staged["pinned.lock"].pin == "staged"
}

violation contains {
	"rule": "lock-could-not-look",
	"verdict": "lock could notlook",
	"subjects": [{"path": name}],
} if {
	some name in input.tree.missing
}

test_a_resolved_node_fires_the_read_class if {
	some v in violation with input as {"tree": {"staged": {"pinned.lock": {"pin": "staged"}}, "missing": []}}
	v.rule == "lock-staged-read"
}

test_an_unresolved_path_fires_the_could_not_look_class if {
	some v in violation with input as {"tree": {"staged": {}, "missing": ["pinned.lock"]}}
	v.rule == "lock-could-not-look"
}

test_a_clean_read_fires_neither_could_not_look if {
	count({v | some v in violation; v.rule == "lock-could-not-look"}) == 0 with input as {"tree": {"staged": {"pinned.lock": {"pin": "staged"}}, "missing": []}}
}
"#;

#[test]
fn a_declared_lock_path_is_could_not_look_rather_than_a_silent_pass() {
    // `Format::for_path` splits on the last dot and searches `Format::extensions()`;
    // no variant owns `lock`, so a declared `.lock` is `NotAcquired::UnknownFormat`
    // before a byte is parsed — even though the staged bytes here are valid TOML
    // and `staged_facts` read them fine. That much is unchanged and is still the
    // reason `input.tree.staged["mise.lock"]` resolves nothing.
    //
    // WHAT CHANGED IS THE SECOND HALF, and it is the one that made this a DEAD
    // gate rather than a narrow one. This case used to assert total silence —
    // exit 0, no finding, no cause — as MEASURED-not-desired, and it recorded
    // that `rules.rs` pushes the path into `out.missing` with an explicit
    // `UnknownFormat` cause which then "does not arrive", concluding that "the
    // loss is DOWNSTREAM of the push". That reading was right, and CLOUD-1049's
    // fix is exactly there: `policy_rule` was discarding the built document
    // whenever anything failed to acquire, so the cause never reached the module.
    //
    // So an unparseable extension is now a REFUSAL naming the path, which is what
    // a could-not-look channel is for. The gate is still narrow — nothing here
    // teaches the engine that a `.lock` is TOML — but a consumer is now told it
    // could not be read instead of being handed a clean tree.
    let dir = scratch("staged-facts-lock");
    write(&dir, "batten.toml", LOCK);
    write(&dir, "lock.rego", LOCK_PROBE);
    // Valid TOML, and identical in content to the `pinned.toml` fixture above
    // that DOES resolve. Only the extension differs, which is the whole finding.
    write(&dir, "pinned.lock", "pin = \"staged\"\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        !answer.contains("lock-staged-read"),
        "the extension is still unknown, so no staged node resolves — if this \
         fires, the engine learned `.lock` and the arm below is the wrong \
         assertion\n{answer}{cause}"
    );
    assert!(
        answer.contains("lock-could-not-look"),
        "but it must SAY so: an extension this build cannot parse belongs in \
         `input.tree.missing` with its cause, not in a clean tree\n{answer}{cause}"
    );
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "and it is a verdict rather than an abstention\n{answer}{cause}"
    );
}

#[test]
fn a_declared_format_resolves_a_staged_path_the_extension_cannot() {
    // THE ESCAPE, and the case that turns `lock-entry-complete` from a
    // registered row deciding nothing into a live gate. Byte-identical fixture
    // to the case above — same probe, same bytes, same extension — with one line
    // added to the row: `format = "toml"`.
    //
    // Above, the extension names no format and the path is could-not-look.
    // Here the row says what to read it as and the node resolves, so the pair is
    // what proves the column is doing the work rather than the file changing.
    let dir = scratch("staged-facts-lock-declared");
    write(&dir, "batten.toml", LOCK_DECLARED);
    write(&dir, "lock.rego", LOCK_PROBE);
    write(&dir, "pinned.lock", "pin = \"staged\"\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("lock-staged-read"),
        "a declared format resolves the staged node the extension could not\n{answer}{cause}"
    );
    assert!(
        !answer.contains("lock-could-not-look"),
        "and the path is no longer in the could-not-look channel, because it was \
         read\n{answer}{cause}"
    );
}

#[test]
fn a_declared_format_does_not_override_an_extension_that_names_one() {
    // THE BOUND, and it is what keeps `facts.rs`'s "the extension is the honest
    // default there" true. A row declaring `format` must not be able to re-label
    // a path whose extension already names a format — otherwise an author could
    // declare `.json` as TOML and the parse failure would be blamed on the file.
    //
    // `pinned.toml` here holds TOML and the row declares `json5`. If the column
    // were an override the read would fail; because it is a FALLBACK consulted
    // only where the extension names nothing, the file is read as TOML and the
    // index predicate fires exactly as it does in `the_index_answers_not_the_worktree`.
    let dir = fixture(
        "staged-facts-format-ignored",
        &CONFIG.replace(
            "staged = [\"pinned.toml\"]",
            "staged = [\"pinned.toml\"]\nformat = \"json5\"",
        ),
        true,
    );
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("staged-is-index"),
        "a known extension decides, and the declared format is not consulted\n{answer}{cause}"
    );
}

/// A lockfile locking every platform this repository installs on, complete.
///
/// The base the two cases below vary, and it has to be complete rather than
/// minimal: `lock-complete` decides eight predicates over one file, so a fixture
/// carrying a single platform would be refused for a reason neither case is
/// about and the anti-vacuity mirror could never be green.
const COMPLETE_LOCK: &str = r#"[[tools."aqua:example/tool"]]
version = "1.0.0"
backend = "aqua:example/tool"

[tools."aqua:example/tool"."platforms.linux-x64"]
checksum = "sha256:abc"
url = "https://example.invalid/tool.tar.gz"

[tools."aqua:example/tool"."platforms.linux-arm64"]
checksum = "sha256:abc"
url = "https://example.invalid/tool.tar.gz"

[tools."aqua:example/tool"."platforms.macos-arm64"]
checksum = "sha256:abc"
url = "https://example.invalid/tool.tar.gz"
"#;

/// The partial shape: locked, and nothing to fetch.
const PARTIAL_ENTRY: &str = r#"
[tools."aqua:example/tool"."platforms.linux-x64-musl"]
checksum = "sha256:abc"
"#;

/// Materialize a repository carrying the committed `lock-complete` module.
fn lock_fixture(name: &str, lock: &str) -> PathBuf {
    let module = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy/lock-complete.rego"),
    )
    .expect("the committed module");
    let dir = scratch(name);
    write(&dir, "batten.toml", crate::lock_complete::CONFIG);
    write(&dir, "policy/lock-complete.rego", &module);
    write(&dir, "mise.lock", lock);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    dir
}

#[test]
fn the_committed_lock_rule_refuses_a_partial_entry_over_the_binary() {
    // THE PROOF THAT A REGISTERED ROW STOPPED BEING DEAD, and it needs the real
    // module rather than a probe: the row deciding this predicate was in
    // `batten.toml` deciding NOTHING on every run, because `mise.lock` carries an
    // extension no `Format` owns, so it resolved no staged node and Rego reads
    // undefined as *does not hold*. Its `test_` rules passed throughout on `with
    // input as`, which fabricates the shape the engine could not produce.
    //
    // So the case drives the committed module, over the compiled binary, against
    // the exact defect the row exists for: a platform entry carrying a checksum
    // and nothing to fetch. `mise lock` never repairs an existing entry, so a
    // stably wrong lockfile passes a regenerate-and-diff gate forever — and one
    // did, which is why the row was written.
    let dir = lock_fixture(
        "staged-facts-lock-entry",
        &format!("{COMPLETE_LOCK}{PARTIAL_ENTRY}"),
    );
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "the committed rule must refuse a partial entry — if this is 0 the row is \
         registered and deciding nothing again\n{answer}{cause}"
    );
    // THE PREDICATE ID, NOT THE ROW ID. A module's finding carries the `rule` id
    // the `violation` object declares — `lock-complete` is what `--rule` selects
    // and `lock-platform-uninstallable` is what decided — so asserting the row
    // name here would pass over any module that raised anything at all.
    assert!(
        answer.contains("lock-platform-uninstallable"),
        "and the finding names the predicate that decided it\n{answer}{cause}"
    );
}

#[test]
fn the_committed_lock_rule_passes_a_complete_entry() {
    // THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by a rule
    // that refuses every lockfile, which is the failure mode a newly-live gate is
    // most likely to have: the predicate was never exercised against the engine,
    // so nothing has ever shown it discriminating.
    let dir = lock_fixture("staged-facts-lock-entry-clean", COMPLETE_LOCK);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a checksum WITH a url is complete, and the rule must say so\n{answer}{cause}"
    );
}
