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
// carried: "CLOUD-525 (a): an UNDECLARED registration on a merged surface is a violation" crates/batten/tests/it/harness_wiring.rs
// carried: "CLOUD-525: an ABSENT merged surface is the ordinary case, not a finding" crates/batten/tests/it/harness_wiring.rs
// carried: "THE SCOPE IS EVERY EVENT NOW: a Stop sibling is a violation too" crates/batten/tests/it/harness_wiring.rs
//!
//! ## WITHDRAWN AGAIN — the exemption table, and this time the whole of it
//!
//! CLOUD-1383. Five of the rows above were about `policy/harness-declared.json`:
//! a tolerated registration, a row naming no issue, a row matching nothing wired.
//! They ported cleanly to the module and were live and correct there. What was
//! wrong was one layer down — the table existed only because nothing in the
//! container ever said whose home directory it was, so batten had to negotiate
//! per registration and then police its own negotiation. It also drifted from the
//! session-start repair inside a day, in the direction that reads healthy on both
//! instruments (CLOUD-1377).
//!
//! `BATTEN_ENVIRONMENT=disposable` states the fact, so there is nothing to
//! tolerate and nothing to police. A sibling is refused on either surface class,
//! and the environment decides whether the repair may remove it.
//!
// withdrawn: "a declared sibling passes, and the declaration names who retires it" CLOUD-1383 deleted the exemption table; a sibling is refused rather than declared, and `a_committed_sibling_beside_the_mediator_is_refused` is the same fixture in the direction the decision now goes
// withdrawn: "a declaration naming no issue is itself a violation, so the hatch is never silent" there is no declaration to name an issue; the hatch it guarded does not exist
// withdrawn: "a declaration whose key is not a CLOUD row is unowned, not merely present" the same table read from its key side, and it goes with the table
// withdrawn: "a declaration matching nothing wired is stale, so the list cannot rot" there is no list to rot; a retirement leaves no licence behind when there is nowhere to leave one
// withdrawn: "CLOUD-525 (b): the same registration declared with an owner passes" the merged half of the tolerated-registration case, withdrawn with it
// withdrawn: "CLOUD-525 (c3): a COMMITTED row is stale with no merged surface, as before" the per-surface-class guard for a direction that no longer exists
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
//!
//! # The retirement ledger for `mise-tasks/hook-matcher-check.sh` (CLOUD-1192)
//!
//! **The program asked a question the engine had already closed more strictly.**
//! It read `.claude/settings.json`'s `PreToolUse` matchers and decided whether
//! each `[[verb]]` row in `batten.toml` was DELIVERED by one of them — a
//! coverage question over an enumeration. `crates/batten/src/doctor.rs` refuses
//! the enumeration itself: `MATCHER_NARROWS` fires on a batten registration
//! carrying ANY matcher, because the derivation emits none deliberately so that
//! `batten.toml`'s `mediated_call` rows are the only narrowing. The dying
//! program's own header states the consequence — "AN EMPTY OR ABSENT `matcher`
//! IS COVERAGE, NOT A GAP … broader than any enumeration" — so under the
//! engine's rule every declared verb is delivered unconditionally and the
//! coverage question has no reachable negative case left.
//!
//! That is what makes this a subsumption rather than a port: the successor is
//! not a translation of the predicate, it is the reason the predicate stopped
//! being askable. `a_matcher_on_battens_own_entry_is_refused` below is the
//! compiled-binary tier for it — the shell suite drove a fixture settings file
//! and so does this, in the direction the decision now goes.
//!
//! CLOUD-1192 is what forced the choice. The gate selected engine entries with
//! a literal `batten-hook\.sh|batten hook`, so renaming the mediation verb to
//! `adjudicate` left it matching zero entries and reporting every declared verb
//! uncovered. `shell edit refused` declares one route with no override, and a
//! §1 that says "this row edits `foo.sh`" is a row written in the wrong shape.
//!
// subsumed: mise-tasks/hook-matcher-check.sh crates/batten/src/doctor.rs kind:mechanism crates/batten/tests/it/harness_wiring.rs
// subsumed: tests/hook-matcher-check.bats crates/batten/src/doctor.rs kind:mechanism crates/batten/tests/it/harness_wiring.rs
//!
//! ## SUBSUMED — the arms `doctor hooks` reaches, at equal or greater strength
//!
// subsumed: "the committed tree is covered" crates/batten/src/doctor.rs
// subsumed: "a tool-name verb outside the matcher is caught, and named with the token it needed" crates/batten/src/doctor.rs
// subsumed: "a shell-program verb with no Bash in the matcher is uncovered too" crates/batten/src/doctor.rs
// subsumed: "an absent matcher is coverage, not a gap" crates/batten/src/doctor.rs
// subsumed: "an empty matcher is coverage, and so is a literal star" crates/batten/src/doctor.rs
// subsumed: "an entry that does not invoke the engine lends no coverage" crates/batten/src/doctor.rs
// subsumed: "a direct 'batten hook' registration counts, not only the launcher" crates/batten/src/doctor.rs
// subsumed: "a settings file that cannot be read fails open, loudly, and never as a verdict" crates/batten/src/doctor.rs
// subsumed: "a settings file that does not exist fails open, loudly" crates/batten/src/doctor.rs
//!
//! ## WITHDRAWN — the enumeration's own machinery, which has no question left
//!
//! Nine cases, and not one of them is a coverage loss: each pins how the SHELL
//! parsed a matcher, a `[[verb]]` table or `write_tools()`'s Rust source with
//! `awk`. The engine loads its own config and knows its own harness enum, so
//! there is no second parser to get wrong — and with a matcher refused outright
//! there is no regex to compile, no route to choose and no token to require.
//!
// withdrawn: "a shell-program verb is satisfied by Bash alone — the route decides the token" the route/token model existed only to decide which token an ENUMERATED matcher had to carry; with no matcher permitted there is no token to require and nothing to route
// withdrawn: "the matcher is read as a regex, so an alternation covers each of its arms" a matcher is refused rather than compiled, so the successor never evaluates one and there is no regex dialect to pin
// withdrawn: "coverage is unanchored, matching the host — Edit delivers MultiEdit" the same reading in its subtlest direction, and it goes with the matcher it read
// withdrawn: "a config declaring no verbs is nothing to cover, and says so" the empty-table arm of a coverage predicate that no longer exists; the engine reports on the wiring, never on the size of the verb table
// withdrawn: "a [[verb]] table this gate cannot parse is could-not-look, never a pass" the awk parse is gone: the engine loads `batten.toml` through its own parser, so an unparseable config is a config error before any wiring question is asked
// withdrawn: "an engine source with no readable write_tools arm is could-not-look" the successor READS the `Harness` enum rather than scraping `hook.rs`, so the arm cannot be unreadable and the could-not-look class is unreachable
// withdrawn: "a neighbouring harness arm is not read as this host's tool set" the same scrape from its cross-contamination side; a typed enum cannot bleed one variant into another
// withdrawn: "a matcher that is not a compilable regex is could-not-look" the could-not-look arm for a compilation the successor never performs
// withdrawn: "one front-end declared under two subcommands is one coverage question" a de-duplication of verb rows that only mattered to a per-verb coverage loop; the successor decides per REGISTRATION, so a verb table's shape does not reach it

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, batten, git_in, scratch, scratch_outside_tree, stderr, stdout, write};

/// The finding id `doctor.rs` raises for a matcher on batten's own entry.
///
/// A literal here rather than a re-export: the constant is private to `doctor`,
/// and a test asserting the RENDERED token is asserting what a reader actually
/// sees. `doctor.rs`'s own tier pins the constant.
const MATCHER_NARROWS: &str = "hook-wiring-matcher-narrows";

/// The variable the fixture's merged row resolves under.
///
/// The committed row names `HOME`, and a fixture must not: setting `HOME` for a
/// child changes where git looks for its own configuration, which turns an
/// unrelated failure into this suite's. The engine expands whatever variable a
/// row NAMES, so a fixture declaring its own is also the arm proving the root
/// comes from config rather than from a constant.
const ROOT_VAR: &str = "BATTEN_FIXTURE_WIRING_ROOT";

/// The verdict rows the module raises, copied because a registry is per-config.
///
/// Their prose is trimmed; what has to match the committed config is the ID,
/// which is what a module raises and what these cases assert on.
///
/// NO `[[pattern]]` ROWS ANY MORE (CLOUD-1383). The fixture declared two — a
/// generic key shape and a closed-status expression — for the three exemption
/// directions this module no longer has. What survives them is worth keeping: the
/// committed `ready-issue-key` row spells this consumer's tracker prefix, and
/// reproducing that expression here would put a specific consumer's vocabulary
/// inside `crates/`, which `no-tracker-key-in-core` refuses. It refused it twice —
/// the second time was the comment explaining the first fix, which quoted the
/// prefix it had just removed, and the gate was right: a grep for a consumer's
/// names does not care which side of a `///` the name is on.
const VERDICTS: &str = r#"
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
const MEDIATOR: &str = "batten adjudicate --harness claude-code";

/// A sibling command a case registers beside the mediator, spelled as the host
/// spells it — with the variable prefix, so the substring match is exercised
/// rather than assumed.
///
/// It was `DECLARED_SIBLING` until CLOUD-1383: the module read an exemption table
/// and this was the row that excused it. There is no table now, so the same
/// command is simply a second decider and is refused.
const SIBLING: &str = "$CLAUDE_PROJECT_DIR/mise-tasks/some-guard.sh";

/// The two launcher hooks, spelled as the launcher wrote them — with a directory,
/// so the basename reduction is still exercised.
///
/// They were the exemption table's last two rows, tolerated because the launcher
/// rewrites them at every session start and no commit here could clear them.
/// CLOUD-1383 moved that from a licence to a fact about the environment, so they
/// are refused here like any other second decider.
const RETIRED_MERGED: [&str; 2] = [
    "~/.claude/session-start-git-identity.sh",
    "~/.claude/stop-hook-git-check.sh",
];

/// A repository fixture carrying the real module, plus the out-of-root
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

/// A wiring carrying the mediator and nothing else, on both events.
fn clean_committed() -> String {
    wiring(&[MEDIATOR], &[MEDIATOR])
}

fn clean_merged() -> String {
    // THE MEDIATOR ALONE, which is what a clean surface is on either class now
    // that nothing may be tolerated beside it.
    wiring(&[], &[MEDIATOR])
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
fn a_committed_sibling_beside_the_mediator_is_refused() {
    // THE POSITIVE the whole consumer half exists for: the engine counts this
    // command and structurally will not name it, so nothing but a consumer's own
    // module can turn the count into a verdict.
    //
    // `SIBLING` was declared in the exemption table until CLOUD-1383 and passed
    // here on that row. It is refused now, which is the change read from its own
    // side: the same command, the same surface, and no table to excuse it.
    let (repo, outside) = fixture(
        "committed-sibling",
        &wiring(&[MEDIATOR, SIBLING], &[MEDIATOR]),
        Some(&clean_merged()),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "a sibling passed");
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
            &[MEDIATOR, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"],
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
            &[MEDIATOR],
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
fn a_tree_with_no_wiring_surface_is_clean() {
    // COULD-NOT-LOOK IS NOT A FINDING, and this case exists because the opposite
    // shipped once. Measured 2026-09-01, before CLOUD-1383 deleted the exemption
    // table: a declared row matched nothing in a tree carrying no wiring surface
    // at all, so the module reported a spent licence over a tree it never looked
    // at — `cli.rs`'s fixture repos have no `.claude/settings.json` and four of
    // its cases went red with `1 harness-wiring` above their own expected finding.
    //
    // The table is gone and with it the direction that could fire here, so the
    // property is now structural rather than guarded. The case stays because it
    // is what a fixture repository looks like, and a module reporting anything
    // over one is a finding about a tree nobody judged.
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

// THE FOUR `input.tree.minted` CASES MOVED RATHER THAN WENT (CLOUD-1383).
//
// They drove CLOUD-1310's `spent` direction — a declared row whose owning issue
// had closed — over a real receipt in a real store, which is the only tier that
// can show the ENGINE builds `input.tree.minted` at all. This module no longer
// reads that fact, so the cases have no predicate here to be about.
//
// The fact is unmoved and so is its coverage: `crates/batten/tests/it/minted_facts.rs`
// carries all four over a fixture module whose whole subject is the projection.
// Deleting them with the predicate would have been the coverage loss dressed as
// cleanup this repository refuses, on the engine half of a row that landed a day
// earlier.

#[test]
fn a_merged_registration_beside_the_mediator_is_refused() {
    // The out-of-root half of the positive: this file is outside the checkout, so
    // no in-tree gate can see it and `input.tree.external` is the only route.
    let (repo, outside) = fixture(
        "merged-sibling",
        &clean_committed(),
        Some(&wiring(&[], &["~/.claude/some-other-hook.sh"])),
    );
    let output = check(&repo, Some(&outside));
    assert!(!output.status.success(), "a merged sibling passed");
    assert!(
        findings(&output).contains("harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
}

#[test]
fn the_launcher_hooks_are_refused_rather_than_tolerated() {
    // CLOUD-1383'S ACCEPTANCE, over the compiled binary rather than only in the
    // module's own tier.
    //
    // These two were the exemption table's last rows. They were tolerated because
    // the launcher rewrites them at every session start, so no commit in this
    // repository could clear them and refusing them would have meant a gate red on
    // a condition nobody in the container could fix.
    //
    // The fact is what moved, not the subject: a container states its home
    // directory is disposable and the session-start repair removes them before
    // this gate reads the surface; a developer machine states nothing, keeps them,
    // and is TOLD. So the module refuses them, which is the difference between a
    // report and a licence.
    let (repo, outside) = fixture(
        "retired-return",
        &clean_committed(),
        Some(&wiring(&[], &RETIRED_MERGED)),
    );
    let output = check(&repo, Some(&outside));
    assert!(
        !output.status.success(),
        "a retired launcher hook came back and was allowed: {}",
        findings(&output)
    );
    // A COUNT AND NO PATH: a merged path is under somebody's home directory and
    // differs per machine, so rule 4 and §6 byte-stability both forbid it travelling.
    assert!(
        findings(&output).contains("2 harness-wiring"),
        "wrong finding: {}",
        findings(&output)
    );
    assert!(
        !findings(&output).contains(".claude"),
        "a merged path travelled into the finding: {}",
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
            &[MEDIATOR, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"],
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
        // The wrapper ALONE. It used to carry the two launcher hooks beside it,
        // which was fine while the exemption table declared them; there is no
        // table since CLOUD-1383, so including them here would test the stray
        // predicate instead of the wrapper one.
        Some(&wiring(
            &[],
            &["mise exec -- batten adjudicate --harness claude-code"],
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

/// `doctor hooks` in `repo`, as one string over both channels.
///
/// The EXIT STATUS is deliberately not what the two cases below read. A fixture
/// declares one harness's wiring, so the other four are `file-missing` and the
/// two events this repository's derivation emits beyond `PreToolUse`/`Stop` are
/// `event-unregistered` — `doctor hooks` is non-zero there whatever the matcher
/// does. Keying on the status would have let the positive case pass over a
/// diagnosis that never looked at a matcher at all, which is exactly what
/// `the_same_wiring_without_a_matcher_is_clean` caught when it was written.
fn diagnosis(repo: &Path) -> String {
    let output = batten()
        .current_dir(repo)
        .args(["doctor", "hooks"])
        .output()
        .expect("run batten doctor hooks");
    format!("{}{}", stdout(&output), stderr(&output))
}

/// One wiring, with and without a matcher on batten's own `PreToolUse` entry.
fn matcher_fixture(name: &str, matcher: Option<&str>) -> PathBuf {
    let entry = match matcher {
        Some(value) => format!(
            r#"{{"matcher": "{value}", "hooks": [{{"type": "command", "command": "{MEDIATOR}"}}]}}"#
        ),
        None => format!(r#"{{"hooks": [{{"type": "command", "command": "{MEDIATOR}"}}]}}"#),
    };
    let committed = format!(
        r#"{{"hooks": {{"PreToolUse": [{entry}], "Stop": [{{"hooks": [{{"type": "command", "command": "{MEDIATOR}"}}]}}]}}}}"#
    );
    fixture(name, &committed, None).0
}

/// The subsumption CLOUD-1192's retirement rests on, over the compiled binary.
///
/// `mise-tasks/hook-matcher-check.sh` asked whether an enumerated matcher
/// DELIVERED every declared `[[verb]]`. `doctor hooks` refuses the enumeration:
/// a matcher on batten's own registration is a second narrowing, so the coverage
/// question has no reachable negative case. Asserted here rather than only in
/// `doctor.rs`'s unit tier because the retired suite drove a fixture settings
/// file through a process, and a subsumption is only real at the strength the
/// BINARY actually reaches.
#[test]
fn a_matcher_on_battens_own_entry_is_refused() {
    let repo = matcher_fixture("matcher-narrows", Some("Bash"));
    assert!(
        diagnosis(&repo).contains(MATCHER_NARROWS),
        "a matcher on batten's own entry was not reported: {}",
        diagnosis(&repo)
    );
}

/// The anti-vacuity half, and it is what makes the case above mean anything.
///
/// The SAME wiring with the matcher removed must not raise that finding. Without
/// this, the positive case passes over any `doctor hooks` that reports something
/// — which it does here for four absent harnesses and two unregistered events,
/// none of which is about a matcher.
#[test]
fn the_same_wiring_without_a_matcher_is_clean() {
    let repo = matcher_fixture("matcher-absent", None);
    assert!(
        !diagnosis(&repo).contains(MATCHER_NARROWS),
        "an unmatched wiring was reported as narrowing: {}",
        diagnosis(&repo)
    );
}
