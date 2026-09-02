//! `policy/harness-wiring.rego` over the compiled binary (CLOUD-1160).
//!
//! **A `with input as` case cannot answer what this file asks.** The module's own
//! `test_` rules pin the PREDICATE; this pins that the ENGINE builds the input the
//! predicate reads — committed wiring documents under `input.tree.documents`, and
//! a merged surface under `input.tree.external` resolved beneath a root variable. CLOUD-845 measured a module fabricating an input key the engine
//! cannot produce and CLOUD-857 the same thing with an input shape; both were
//! green over a gate that decided nothing, and this family is where that risk is
//! highest because every other fact in the model is repo-rooted by construction.
//!
//! # The retirement ledger for `mise-tasks/hooks-wiring-check.sh` (CLOUD-1160)
//!
//! The program was a TRANSLATOR with a table. It spawned `batten doctor hooks -J`
//! — which already decides the whole derivation half, one unit case per finding —
//! and then answered one further question the engine structurally cannot: which
//! of the commands registered beside batten's are legitimate HERE.
//! `crates/batten/src/doctor.rs` says so at both `siblings` and `merged`: a
//! command line carries a path (rule 4), and whether a hook beside batten's is
//! legitimate is a consumer's judgement (rule 1). So the derivation half needed no
//! porting at all, and the consumer half needed a module that can read the wiring
//! documents itself — which `input.tree.external` (CLOUD-1167) made expressible.
//!
//! The 51.4s it cost was overwhelmingly `setup()` dispatching `cargo run` five
//! times before each of 36 cases, which is why the port IS the performance fix.
//!
//! Two deleted paths, two file arms. The successor is a consumer module, so
//! neither arm declares a `kind:` — the path already decides it. Both surface
//! classes live in ONE module: they were briefly split on CLOUD-1307, a row since
//! measured false (it used the released binary, not the built one), and
//! `the_committed_half_survives_an_absent_merged_surface` below is the case that
//! keeps the correction from being re-broken.
//!
// carried: mise-tasks/hooks-wiring-check.sh policy/harness-wiring.rego crates/batten/tests/it/harness_wiring.rs
// carried: tests/hooks-wiring-check.bats policy/harness-wiring.rego crates/batten/tests/it/harness_wiring.rs
//!
//! ## SUBSUMED — the derivation half, which `doctor hooks` already decided
//!
//! Fifteen cases, and not one of them was ever about the shell: the program read
//! `doctor hooks -J` and re-rendered its findings as pointer lines. Every one has
//! a one-for-one unit case in `crates/batten/src/doctor.rs`'s own tier, which is
//! where the decision has always lived. The replacement task runs
//! `batten doctor hooks` beside `batten check`, so the call site survives too.
//!
// subsumed: "the derived command itself is accepted, so a consumer without a launcher still passes" crates/batten/src/doctor.rs
// subsumed: "a command that reaches nothing is DRIFT, not silence" crates/batten/src/doctor.rs
// subsumed: "the pointer names the file and the event, never the entry body" crates/batten/src/doctor.rs
// subsumed: "an event the derivation does not register is refused" crates/batten/src/doctor.rs
// subsumed: "A MATCHER ON BATTEN'S OWN ENTRY IS A SECOND NARROWING, and is refused" crates/batten/src/doctor.rs
// subsumed: "A SECOND COMMAND ON ONE EVENT is a second authority for one decision" crates/batten/src/doctor.rs
// subsumed: "A DERIVED EVENT WITH NO REGISTRATION is refused — this is CLOUD-312's cutover" crates/batten/src/doctor.rs
// subsumed: "a wiring carrying no batten entry is now RED, on every event it omits" crates/batten/src/doctor.rs
// subsumed: "a wiring with no hooks key at all is red rather than green" crates/batten/src/doctor.rs
// subsumed: "an ABSENT wiring file is a FINDING now, which is stronger than exit 2" crates/batten/src/doctor.rs
// subsumed: "an unparseable wiring file is named distinctly from an absent one" crates/batten/src/doctor.rs
// subsumed: "every registration is judged, so one run names them all" crates/batten/src/doctor.rs
// subsumed: "A HARNESS THE CORE DIAGNOSES AND THE TABLE OMITS is refused" crates/batten/src/doctor.rs
// subsumed: "A HARNESS THE TABLE NAMES AND THE CORE DOES NOT KNOW is refused too" crates/batten/src/doctor.rs
// subsumed: "exit-code is absent from the diagnosis: it has no hook-config surface" crates/batten/src/doctor.rs
//!
//! ## CARRIED — the consumer half, which is what this change actually ports
//!
// carried: "a PreToolUse command that does not reach the engine is a violation" crates/batten/tests/it/harness_wiring.rs
// carried: "a declared sibling passes, and the declaration names who retires it" policy/harness-wiring.rego
// carried: "a declaration naming no issue is itself a violation, so the hatch is never silent" policy/harness-wiring.rego
// carried: "a declaration whose key is not a CLOUD row is unowned, not merely present" policy/harness-wiring.rego
// carried: "a declaration matching nothing wired is stale, so the list cannot rot" policy/harness-wiring.rego
// carried: "CLOUD-525 (a): an UNDECLARED registration on a merged surface is a violation" crates/batten/tests/it/harness_wiring.rs
// carried: "CLOUD-525 (b): the same registration declared with an owner passes" policy/harness-wiring.rego
// carried: "CLOUD-525 (c3): a COMMITTED row is stale with no merged surface, as before" policy/harness-wiring.rego
// carried: "CLOUD-525: an ABSENT merged surface is the ordinary case, not a finding" crates/batten/tests/it/harness_wiring.rs
// carried: "THE SCOPE IS EVERY EVENT NOW: a Stop sibling is a violation too" crates/batten/tests/it/harness_wiring.rs
//!
//! ## CHANGED — one case, and the successor goes the other way on purpose
//!
//! The shell reported a committed sibling by naming the COMMAND. That command
//! carries the host's own `$CLAUDE_PROJECT_DIR` prefix and this consumer's
//! directory layout, which non-negotiable rule 4 keeps out of a gate's output —
//! and the same program's merged half already reduced its commands to a basename
//! for exactly that reason. The successor points at the FILE, which is a tracked
//! path this repository owns and which a reader can open to see the entry.
//!
// changed: "the sibling IS named by its path, unlike a drifted batten command" policy/harness-wiring.rego the case pinned the command travelling in the finding, and the successor emits the containing file plus a count instead; `the_finding_points_at_the_file_and_never_at_the_command` below is the case in the direction the decision goes
//!
//! ## WITHDRAWN — ten cases whose subject the retirement deletes
//!
//! Three are the LAUNCHER COLUMN. Every row of it has been `-` since CLOUD-824
//! made all five harnesses run the derived command directly, and the affordance
//! only ever existed so a consumer fronting the engine with its own script could
//! declare it. The successor does not carry it: an argument for keeping an unused
//! column is an argument for keeping a gate nothing can fail, and a consumer that
//! needs one again writes it into the module rather than into a table with no rows.
//!
// withdrawn: "a declared launcher stands in for the derived command — that indirection is the point" the column has been empty since CLOUD-824 and the successor drops it; the case drove a fixture table that no longer has anywhere to be declared
// withdrawn: "an UNDECLARED launcher is drift — the column is a declaration, not a wildcard" the same empty column read from the other side, and with no column there is no wildcard to refuse
// withdrawn: "no harness declares a launcher, so no shell fronts the engine here" it asserted the column was empty, which a deleted column satisfies vacuously rather than meaningfully
//!
//! Two are the DIAGNOSIS DOCUMENT's own could-not-look arm. They asserted that a
//! `doctor hooks -J` answer the shell could not parse was exit 2 rather than a
//! pass. The successor spawns nothing — `doctor hooks` is its own process with its
//! own exit code — so there is no second-hand document left to fail to read.
//!
// withdrawn: "a diagnosis that cannot be READ is exit 2 — could not look is not a verdict" the shell parsed a spawned process's stdout and the successor spawns nothing; `doctor hooks` reports its own verdict through its own exit code
// withdrawn: "a diagnosis that is not the DOCUMENT is exit 2 too, not a pass" the same second-hand document, and the property it protected is now structural rather than checked
//!
//! Three are the CLOSED-OWNER rule, and this one is a real loss rather than a
//! vacuous one. It refused a declared row whose owning issue had been closed —
//! the permanent-exemption shape the table exists to prevent — and it decided
//! that from `get_issue` payloads the caller piped in. A tree-scoped module has
//! no stdin and no fact carries a tracker row's status: `input.tree.records` is
//! the recorder channel and reaches `input.facts` on the MEDIATED surface, which
//! a `scope = "tree"` rule never sees. Filed rather than dropped silently, and
//! the two directions that survive — `unowned` and `stale` — still keep the table
//! from growing without an owner or rotting after a retirement.
//!
// withdrawn: "CLOUD-525 (e): a declared row whose owner is a CLOSED issue is a violation" no tree-scoped fact carries a tracker row's status, so the predicate is unspellable in the successor; the class is filed rather than dropped
// withdrawn: "CLOUD-525: an OPEN owner keeps the same declared row green" the positive control for the class above, and it goes with it
// withdrawn: "CLOUD-525: with no board piped in, the owner rule is unenforced rather than assumed" the could-not-look arm for a stdin channel the successor does not have
//!
//! Two more are the MERGED half's STALE direction, and they go for a reason that
//! is filed rather than inherent. `CLOUD-1307`: an absent `[[rule.external]]`
//! source skips its whole rule, so the merged surfaces cannot share one row and
//! the engine binds one module to one rule — which leaves a merged evaluation
//! holding ONE surface. Staleness needs the UNION of the surfaces that were read,
//! because a command registered on the launcher would read as stale to a module
//! that opened the settings file. The committed half keeps its own stale
//! direction, where the subject is a tracked file and always readable.
//!
// withdrawn: "CLOUD-525 (c): a declared row matching nothing on a surface that WAS read is stale" one rule holds one surface under CLOUD-1307, so a union over the surfaces read is unspellable; restored there
// withdrawn: "CLOUD-525 (c2): NO MERGED SURFACE READ IS COULD-NOT-LOOK, never a stale row" the guard for the predicate above, and it goes with it — the engine now skips the merged rule outright when its surface is absent, which is the same posture one level up

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, batten, git_in, scratch, scratch_outside_tree, stderr, stdout, write};

/// The variable the fixture's merged row resolves under.
///
/// The committed row names `HOME`, and a fixture must not: setting `HOME` for a
/// child changes where git looks for its own configuration, which turns an
/// unrelated failure into this suite's. The engine expands whatever variable a
/// row NAMES, so a fixture declaring its own is also the arm proving the root
/// comes from config rather than from a constant.
const ROOT_VAR: &str = "BATTEN_FIXTURE_WIRING_ROOT";

/// The verdict rows both modules raise, copied because a registry is per-config.
///
/// Their prose is trimmed; what has to match the committed config is the ID,
/// which is what a module raises and what these cases assert on.
///
/// THE KEY PATTERN IS DELIBERATELY NOT THE COMMITTED ONE. `batten.toml`'s
/// `ready-issue-key` row spells this consumer's tracker prefix, and reproducing
/// that expression here would put a specific consumer's vocabulary inside
/// `crates/` — non-negotiable rule 1, which `no-tracker-key-in-core` refuses.
/// A generic key shape matches the module's declared owners without naming any
/// tracker, which is all the fixture needs.
///
/// Twice, and the second time was this comment. The first violation was the
/// expression itself; the fix then EXPLAINED itself by quoting the prefix it had
/// just removed, and the gate refused that too — correctly, since a grep for a
/// consumer's names does not care which side of a `///` the name is on.
const VERDICTS: &str = r#"
[[pattern]]
id = "ready-issue-key"
regex = '[A-Z]+-[0-9]+'

[[pattern]]
id = "closed-issue-status"
regex = '^(done|canceled|duplicate)$'

[[verdict]]
id = "hook wire duplicate"
gloss = "a registration on a merged surface outside this repository does not reach the mediator"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "harness-wiring.rego"

[[verdict]]
id = "hook wire unread"
gloss = "a declared hook surface exists and will not parse, so the wiring could not be judged"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "harness-wiring.rego"

[[verdict]]
id = "hook wire loose"
gloss = "a committed hook surface registers a command that is neither the mediator nor declared"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "config read first"
kind = "document"
target = "harness-wiring.rego"

[[verdict]]
id = "hook declare unnamed"
gloss = "a declared hook sibling names no issue, so it records a decision and nobody to ask"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "harness-wiring.rego"

[[verdict]]
id = "hook declare stale"
gloss = "a declared hook sibling matches nothing wired, so it is a licence with no subject"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "harness-wiring.rego"

[[verdict]]
id = "hook declare spent"
gloss = "a declared hook sibling names an issue that has closed, so its licence outlived its owner"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "harness-wiring.rego"
"#;

/// The fixture config: one rule over both surface classes.
///
/// The launcher external is ALWAYS declared, present or not. It used to be a
/// second rule guarded by a flag, on CLOUD-1307's claim that an absent source
/// skips its whole rule — measured against the released binary rather than the
/// built one, and false of the shipping engine.
/// `the_committed_half_survives_an_absent_merged_surface` is the case that keeps
/// that correction from being re-broken.
fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "harness-wiring"
kind = "policy"
scope = "tree"
documents = [".claude/settings.json"]
module = "harness-wiring.rego"
severity = "deny"

[[rule.external]]
id = "harness-launcher-settings"
root = "BATTEN_FIXTURE_WIRING_ROOT"
path = ".claude/launcher-settings.json"

[[rule.minted]]
id = "issue-status"
mint = "issue-read"
field = 4
recency = 2
max_age_days = 7
{VERDICTS}"#
    )
}

/// One wiring document over `PreToolUse` and `Stop`, from the commands given.
///
/// The shape is the host's: an event maps to a list of entries, each with its own
/// `hooks` array. Building it here keeps every case about the command set it
/// names rather than about JSON.
fn wiring(pre_tool: &[&str], stop: &[&str]) -> String {
    let entries = |commands: &[&str]| {
        commands
            .iter()
            .map(|command| {
                format!(r#"{{"hooks": [{{"type": "command", "command": "{command}"}}]}}"#)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        r#"{{"hooks": {{"PreToolUse": [{}], "Stop": [{}]}}}}"#,
        entries(pre_tool),
        entries(stop)
    )
}

/// The committed registration every fixture starts from.
const MEDIATOR: &str = "batten hook --harness claude-code";

/// The one committed sibling the module's table declares, spelled as the host
/// spells it — with the variable prefix, so the substring match is exercised
/// rather than assumed.
const DECLARED_SIBLING: &str = "$CLAUDE_PROJECT_DIR/mise-tasks/run-shape-guard.sh";

/// Both merged commands the merged module declares, spelled as the launcher
/// writes them — with a directory, so the basename reduction is exercised.
const DECLARED_MERGED: [&str; 2] = [
    "~/.claude/session-start-git-identity.sh",
    "~/.claude/stop-hook-git-check.sh",
];

/// A repository fixture carrying both real modules, plus the out-of-root
/// directory the merged row points at.
///
/// One of each per case: these run in parallel and `git init` races on a shared
/// directory.
fn fixture(name: &str, committed: &str, merged: Option<&str>) -> (PathBuf, PathBuf) {
    let repo = scratch(&format!("harness-wiring-{name}"));
    write(&repo, "batten.toml", &config());

    // THE REAL MODULES, read off the tree rather than restated. A fixture copy
    // would drift from the thing that ships, which is the whole failure this
    // second tier exists to catch one level up.
    let module = std::fs::read_to_string(at_root("policy/harness-wiring.rego")).unwrap();
    write(&repo, "harness-wiring.rego", &module);
    write(&repo, ".claude/settings.json", committed);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);
    git_in(&repo, &["add", "-A"]);

    // OUTSIDE the repository, which is the point of the merged half: a path under
    // the checkout would be reachable through `documents` and would prove nothing
    // about this family.
    let outside = scratch_outside_tree("harness-wiring-root", name);
    if let Some(body) = merged {
        std::fs::create_dir_all(outside.join(".claude")).expect("out-of-root dir");
        std::fs::write(outside.join(".claude/launcher-settings.json"), body).expect("write merged");
    }
    (repo, outside)
}

/// `batten check` in `repo`, with the root variable set or removed.
fn check(repo: &Path, root: Option<&Path>) -> Output {
    let mut command = batten();
    command.current_dir(repo).arg("check");
    match root {
        Some(dir) => command.env(ROOT_VAR, dir),
        // REMOVED, not set to empty: this is the case where the host simply has
        // no such root, which is the permanent state of a CI runner.
        None => command.env_remove(ROOT_VAR),
    };
    command.output().expect("run batten check")
}

/// The finding lines a run rendered.
///
/// STDOUT, AND THE VERDICT TOKEN IS NOT IN IT. `batten check` renders
/// `<pointer> <rule>` per finding — a path where the finding has one, a count
/// where it does not — and the `-J` channel carries the same two fields. The
/// token a module raises is `policy explain`'s surface, not this one, so these
/// cases discriminate by the shape the pointer takes: a sibling names its file,
/// and a table finding is a bare count. Which CLASS produced a count is the
/// load-time tier's question, and it is pinned there.
fn findings(output: &Output) -> String {
    stdout(output)
}

/// A wiring with every declared registration present and nothing else.
fn clean_committed() -> String {
    wiring(&[MEDIATOR, DECLARED_SIBLING], &[MEDIATOR])
}

fn clean_merged() -> String {
    wiring(&[], &DECLARED_MERGED)
}

#[test]
fn a_correctly_wired_tree_is_clean() {
    // ANTI-VACUITY, and the case every other one rests on: without it they would
    // all pass just as well over a module that refuses everything.
    let (repo, outside) = fixture("clean", &clean_committed(), Some(&clean_merged()));
    let output = check(&repo, Some(&outside));
    assert!(
        output.status.success(),
        "a correctly wired tree reported: {}",
        stderr(&output)
    );
}

#[test]
fn a_committed_sibling_the_table_does_not_declare_is_refused() {
    // THE POSITIVE the whole consumer half exists for: the engine counts this
    // command and structurally will not name it, so nothing but a consumer's own
    // module can turn the count into a verdict.
    let (repo, outside) = fixture(
        "committed-sibling",
        &wiring(
            &[
                MEDIATOR,
                DECLARED_SIBLING,
                "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh",
            ],
            &[MEDIATOR],
        ),
        Some(&clean_merged()),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "an undeclared sibling passed");
    assert!(
        findings(&output).contains(".claude/settings.json harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
}

#[test]
fn the_finding_points_at_the_file_and_never_at_the_command() {
    // The CHANGED arm's own case. A hook command carries the host's variable
    // prefix and this consumer's layout; the file is a tracked path, so the
    // pointer is honest and opening it shows the entry.
    let (repo, outside) = fixture(
        "pointer",
        &wiring(
            &[
                MEDIATOR,
                DECLARED_SIBLING,
                "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh",
            ],
            &[MEDIATOR],
        ),
        Some(&clean_merged()),
    );
    let reported = findings(&check(&repo, Some(&outside)));
    assert!(
        reported.contains(".claude/settings.json"),
        "the finding does not name the file: {reported}"
    );
    assert!(
        !reported.contains("other-guard.sh"),
        "the finding carries the command: {reported}"
    );
    assert!(
        !reported.contains("CLAUDE_PROJECT_DIR"),
        "the finding carries the host's own prefix: {reported}"
    );
}

#[test]
fn a_stop_sibling_is_refused_too_so_the_scope_is_every_event() {
    // CLOUD-777 widened the predicate from `PreToolUse` to every event, and a
    // module iterating one event key would pass this while looking correct.
    let (repo, outside) = fixture(
        "stop-sibling",
        &wiring(
            &[MEDIATOR, DECLARED_SIBLING],
            &[MEDIATOR, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"],
        ),
        Some(&clean_merged()),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "a Stop sibling passed");
    assert!(
        findings(&output).contains(".claude/settings.json harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
}

#[test]
fn a_committed_row_matching_nothing_is_stale() {
    // The table's other direction, and the one that keeps a landed retirement
    // from leaving a licence behind for the next command with a similar path.
    let (repo, outside) = fixture(
        "stale",
        &wiring(&[MEDIATOR], &[MEDIATOR]),
        Some(&clean_merged()),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "a spent declaration survived");
    // A COUNT AND NO PATH, which is how this is told from the sibling finding
    // above on a surface that renders no token: the table's own two directions
    // point at nothing openable, so they render as a bare count.
    assert!(
        findings(&output).contains("1 harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
    assert!(
        !findings(&output).contains(".claude/settings.json harness-wiring"),
        "a stale declaration reported as a sibling: {}",
        findings(&output)
    );
}

#[test]
fn a_tree_with_no_wiring_surface_is_not_stale() {
    // THE COULD-NOT-LOOK GUARD, and this case exists because its absence shipped.
    // Without `committed_read > 0`, a declaration matches nothing in a tree that
    // carries no wiring surface at all, and the module reports a spent licence
    // over a tree it never looked at. Measured 2026-09-01: `cli.rs`'s fixture
    // repos have no `.claude/settings.json`, and four of its cases went red with
    // `1 harness-wiring` on the line above their own expected finding.
    //
    // In the compiled tier rather than only in the module's own `test_` rules,
    // because that is what makes the mutation on the guard land somewhere a
    // declared `#MUTANT-SUITE` case can turn red (CLOUD-1267).
    let repo = scratch("harness-wiring-no-surface");
    write(&repo, "batten.toml", &config());
    let module = std::fs::read_to_string(at_root("policy/harness-wiring.rego")).unwrap();
    write(&repo, "harness-wiring.rego", &module);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);
    git_in(&repo, &["add", "-A"]);
    let output = check(&repo, None);
    assert!(
        output.status.success(),
        "a tree with no wiring surface reported: {}",
        findings(&output)
    );
}

/// Write one `issue-read` receipt into the fixture's own receipt store.
///
/// The store is under the GIT DIRECTORY, never in the tree, which is what makes
/// this fact per-checkout and empty on any runner. The body is `[[mint]]
/// issue-read`'s: `{id} {updatedAt} {now} {digest} {status} {ready}`, so field 4
/// is the status and field 2 is when the reading was taken.
fn receipt(repo: &Path, key: &str, status: &str, taken: u64) {
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("receipt store");
    std::fs::write(
        store.join(format!("issue-read.{key}")),
        format!("{key} 2026-01-01 {taken} abcd1234 {status} ready\n"),
    )
    .expect("write receipt");
}

/// Seconds since the epoch, for a receipt written "just now".
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[test]
fn the_engine_reads_a_closed_owner_off_a_minted_receipt() {
    // CLOUD-1310'S WHOLE POINT, and it is only decidable over the compiled binary:
    // a `with input as` case fabricates `input.tree.minted` and so passes over an
    // engine that never builds it. This writes a real receipt into a real store and
    // asks the shipped `check` to find it.
    //
    // The tree is otherwise CLEAN — every declared row matches something wired —
    // so the only thing that can redden this run is the owner's status.
    let (repo, outside) = fixture("owner-closed", &clean_committed(), Some(&clean_merged()));
    receipt(&repo, "CLOUD-1314", "done", now());
    let output = check(&repo, Some(&outside));
    assert!(
        !output.status.success(),
        "a row whose owner has closed was allowed: {}",
        findings(&output)
    );
    // A COUNT, never the key: the table's directions point at nothing openable.
    //
    // TWO, from ONE reading, and that is a property worth pinning rather than an
    // off-by-one to paper over: `spent` is keyed by the ROW, and both merged rows
    // name this same owner. A single receipt therefore closes both, which is what
    // an owner-shaped licence looks like when it expires — a `1` here would mean
    // the predicate had stopped at the first row it matched.
    assert!(
        findings(&output).contains("2 harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
    assert!(
        !findings(&output).contains(".claude/settings.json harness-wiring"),
        "a spent declaration reported as a sibling: {}",
        findings(&output)
    );
}

#[test]
fn an_open_owner_is_not_spent() {
    // The other direction, and without it the case above passes over a module that
    // fires on any reading at all.
    let (repo, outside) = fixture("owner-open", &clean_committed(), Some(&clean_merged()));
    receipt(&repo, "CLOUD-1314", "in-progress", now());
    let output = check(&repo, Some(&outside));
    assert!(
        output.status.success(),
        "an open owner was reported spent: {}",
        findings(&output)
    );
}

#[test]
fn a_reading_older_than_the_declared_bound_does_not_answer() {
    // THE AGE BOUND, over the compiled binary, which is the one thing the module's
    // own tier cannot reach: it fabricates the projection, so it cannot show that
    // the ENGINE dropped a stale reading before the module ever saw it.
    //
    // This is why the fact is not a `captured` reduction. That store is keyed by
    // content and carries no clock, so a mutable field answers from whichever read
    // sorts first by digest — here, a status read eight days ago would still say
    // `done` forever.
    let (repo, outside) = fixture("owner-stale", &clean_committed(), Some(&clean_merged()));
    receipt(&repo, "CLOUD-1314", "done", now() - 8 * 86_400);
    let output = check(&repo, Some(&outside));
    assert!(
        output.status.success(),
        "a reading past the declared bound still answered: {}",
        findings(&output)
    );
}

#[test]
fn no_receipt_store_at_all_is_not_spent() {
    // COULD-NOT-LOOK, and it is the ORDINARY state: the store is per-checkout, so
    // every CI runner and every fresh clone has none. A module reading that absence
    // as a closed owner would redden everywhere for a state nobody can fix — and an
    // engine returning an empty MAP rather than nothing would make that the module's
    // problem to guard rather than the fact's.
    let (repo, outside) = fixture("owner-unread", &clean_committed(), Some(&clean_merged()));
    let output = check(&repo, Some(&outside));
    assert!(
        output.status.success(),
        "a tree whose receipt store does not exist reported: {}",
        findings(&output)
    );
}

#[test]
fn a_merged_registration_the_table_does_not_declare_is_refused() {
    // The out-of-root half of the positive: this file is outside the checkout, so
    // no in-tree gate can see it and `input.tree.external` is the only route.
    let (repo, outside) = fixture(
        "merged-sibling",
        &clean_committed(),
        Some(&wiring(&[], &["~/.claude/some-other-hook.sh"])),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "an undeclared merged hook passed");
    assert!(
        findings(&output).contains("harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
}

#[test]
fn the_merged_finding_carries_no_path_at_all() {
    // §5, and the reason the merged half counts where the committed half points:
    // a merged path is under somebody's home directory, so it differs per machine
    // and would defeat byte-stability as well as rule 4.
    let (repo, outside) = fixture(
        "merged-pointer",
        &clean_committed(),
        Some(&wiring(&[], &["~/.claude/some-other-hook.sh"])),
    );
    let reported = findings(&check(&repo, Some(&outside)));
    assert!(
        !reported.contains("some-other-hook.sh"),
        "the merged finding names the command: {reported}"
    );
    assert!(
        !reported.contains(outside.to_string_lossy().as_ref()),
        "the merged finding names the resolved path: {reported}"
    );
}

#[test]
fn the_committed_half_survives_an_absent_merged_surface() {
    // THE REGRESSION GUARD FOR CLOUD-1307, and the reason the two halves are two
    // modules rather than one. An absent `[[rule.external]]` source skips its
    // whole rule — measured, with an unconditional arm silent — so a single row
    // carrying both would be off on every machine with no launcher file, which is
    // every CI runner. Here the merged row is not declared at all and the
    // committed half must still decide.
    let (repo, _outside) = fixture(
        "absent-merged",
        &wiring(
            &[
                MEDIATOR,
                DECLARED_SIBLING,
                "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh",
            ],
            &[MEDIATOR],
        ),
        None,
    );
    let output = check(&repo, None);
    assert!(
        !output.status.success(),
        "the committed half went silent with no merged surface — CLOUD-1307 has          been reintroduced by recombining the two rows"
    );
    assert!(
        findings(&output).contains(".claude/settings.json harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
}

#[test]
fn an_absent_merged_surface_is_not_itself_a_finding() {
    // The other side of the same coin: most machines carry no launcher file, and
    // a run red for its absence would be red on every developer's box for a state
    // nobody can fix.
    let (repo, _outside) = fixture("absent-clean", &clean_committed(), None);
    let output = check(&repo, None);
    assert!(
        output.status.success(),
        "an absent merged surface reported: {}",
        stderr(&output)
    );
}

#[test]
fn a_wrapper_that_reaches_the_mediator_is_not_a_second_decider() {
    // The predicate is a SECOND decider, not a spelling. CLOUD-824 records what
    // demanding an exact string bought last time, which was a launcher script
    // resolving the repo root through a second authority and allowing every
    // mediated call silently.
    let (repo, outside) = fixture(
        "wrapper",
        &clean_committed(),
        Some(&wiring(
            &[],
            &[
                "mise exec -- batten hook --harness claude-code",
                DECLARED_MERGED[0],
                DECLARED_MERGED[1],
            ],
        )),
    );
    let output = check(&repo, Some(&outside));
    assert!(
        output.status.success(),
        "a wrapper around the mediator was refused: {}",
        stderr(&output)
    );
}

#[test]
fn this_repository_is_wired_correctly() {
    // The gate on the real tree, which is the only place the committed tables and
    // the real documents meet. It is also what would catch a `[[rule.external]]`
    // row a module reads and the config stops declaring.
    let output = batten()
        .current_dir(at_root("."))
        .args(["check", "--rule", "harness-wiring"])
        .output()
        .expect("run batten check");
    assert!(
        output.status.success(),
        "this repository's own wiring reported: {}",
        stderr(&output)
    );
}
