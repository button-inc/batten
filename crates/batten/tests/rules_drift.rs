//! A restated value still agrees with the mechanism that owns it, over the
//! compiled binary (CLOUD-506/770/932's predicates, CLOUD-1150's retirement).
//!
//! **This is the tier `policy/rules-drift.rego`'s own `test_` rules cannot be.**
//! A `with input as` block writes the shape it then reads, so it is green over a
//! key the engine never fills. Three of this gate's four predicates read an
//! AUTHORITY that is not prose — a shell string, a generated JSON schema, a Rust
//! constant — and each arrives through a different acquisition path. Whether the
//! engine hands any of them over is decidable only here:
//!
//! * `${VAR:-N}` is read from `mise-tasks/*.sh` as LINES, and a `.sh` file is not
//!   a format the parser knows. Only a real run says the line surface reaches it.
//! * The schema keys are read with `walk` over a PARSED document, which is a
//!   different acquisition from the line one beside it in the same row.
//! * `policy.rs`'s constants are read as lines from a `.rs` path — the third
//!   surface, in a row whose other members are markdown and JSON.
//!
//! A module reaching for any of those and getting undefined denies nothing and
//! loads clean, which is the class `.claude/rules/policy-modules.md` opens with.
//!
//! **The anti-inversion mirror is the case this gate cannot ship without.**
//! `.claude/rules/toolchain.md`'s own rule is that a value should NOT be
//! restated, so a gate pushing toward completeness would invert the discipline
//! it enforces. `a_knob_named_without_a_value_is_untouched` is that assertion
//! over the real boundary.
//!
//! The ledger for this member: two deleted paths and thirty deleted `@test`
//! cases. The successor is a consumer module, so no `kind:` field is owed.
//
// carried: mise-tasks/rules-drift.sh policy/rules-drift.rego crates/batten/tests/rules_drift.rs
// carried: tests/rules-drift.bats policy/rules-drift.rego crates/batten/tests/rules_drift.rs
//
// carried: "a restated default that disagrees with the mechanism fails, and names both values" policy/rules-drift.rego
// carried: "the same claim with the right value passes" policy/rules-drift.rego
// carried: "PROSE THAT NAMES A KNOB WITHOUT QUOTING A VALUE PASSES" policy/rules-drift.rego
// carried: "a variable no mechanism defaults is not judged" policy/rules-drift.rego
// carried: "a paragraph claiming a task runs on an unwired event fails, and names the event" policy/rules-drift.rego
// carried: "the pointer names the line the event is on, not the paragraph's first line" policy/rules-drift.rego
// carried: "the same paragraph naming only wired events passes" policy/rules-drift.rego
// carried: "A PARAGRAPH SAYING AN EVENT IS ABSENT IS NOT A CLAIM THAT IT RUNS" policy/rules-drift.rego
// carried: "an event named outside any runs-on paragraph is not judged" policy/rules-drift.rego
// carried: "a backticked word that is not an event is left alone" policy/rules-drift.rego
// carried: "a rules file with no restated value does not stop the walk at the drifted one" policy/rules-drift.rego
// carried: "output is pointer-only — the sentence is never echoed" policy/rules-drift.rego
// carried: "A DRIFTED VALUE IN A MEMORY FAILS — the second prose surface is walked" policy/rules-drift.rego
// carried: "A MEMORY IN A SUBDIRECTORY IS REACHED — proven, not assumed from the glob" policy/rules-drift.rego
// carried: "a memory naming a knob without quoting a value passes" policy/rules-drift.rego
// carried: "AN ABSENT MEMORY TREE IS NOT A FAILURE, unlike an absent rules directory" policy/rules-drift.rego
// carried: "this repository's own rules files agree with their mechanisms" policy/rules-drift.rego
// carried: "A NAMED TREE KEY THE SCHEMA DOES NOT CARRY FAILS, and names the key and the schema" policy/rules-drift.rego
// carried: "the same prose naming only emittable keys passes" policy/rules-drift.rego
// carried: "THE TWO SURFACES ARE JUDGED SEPARATELY — a call key is not a tree key" policy/rules-drift.rego
// carried: "a call key on the call surface passes" policy/rules-drift.rego
// carried: "prose about documents without the qualified form is not judged" policy/rules-drift.rego
// carried: "A NAMED FIXED RULE THE EVALUATOR DOES NOT QUERY FAILS" policy/rules-drift.rego
// carried: "the three real rule names pass" policy/rules-drift.rego
// carried: "A SUBSCRIPTED PATTERN REFERENCE IS NOT A RULE NAME — the bracket is the tell" policy/rules-drift.rego
//
// THE FOUR ANTI-VACUITY GUARDS CHANGE SHAPE, and they change together for one
// reason: the predecessor was a TASK with a call site, and a `[[rule]]` has
// none. It runs wherever `batten check` runs, so an unconditional startup
// refusal would speak in every fixture repository that inherits this config —
// the scoping defect CLOUD-1164 records for `tree-clean`. Each guard is now
// conditioned on there being a claim that depends on the authority, and raises
// `V-DRIFT-AUTHORITY-UNREADABLE` rather than exiting before any predicate runs.
//
// changed: "an empty rules directory is refused rather than silently green" policy/rules-drift.rego a glob that selects nothing is silent here rather than exit 1: `line_sources` is a glob and a repository with no rules tree is an ordinary consumer, which is exactly what the predecessor already said about an ABSENT MEMORY TREE one case below. The refusal it does keep is the one that has a subject — an authority some prose claims against
// changed: "unreadable wiring is refused rather than reporting every event unwired" policy/rules-drift.rego conditioned on a wiring claim existing: an unreadable `.claude/settings.json` is `V-DRIFT-AUTHORITY-UNREADABLE` when some sentence claims a wiring, and silent when none does
// changed: "unreadable schemas are refused rather than reporting every key unemittable" policy/rules-drift.rego same conditioning, plus a READ-BUT-EMPTY arm the predecessor did not need: this build of regorus has no `walk`, so the recursive descent became one fixed path, and a schema whose shape moved parses fine and yields nothing — invisible to `input.tree.missing`, so `schema_vacuous` covers it
// changed: "unreadable policy source is refused rather than reporting every name unqueried" policy/rules-drift.rego same conditioning, on a named fixed rule existing
// changed: "the gate is wired into the hk gate, so a drift reddens a commit" policy/rules-drift.rego the assertion moves from the suite to the wiring itself: hk's `rules-drift` step now runs `mise run rules-drift`, which is an inline `batten check --rule rules-drift`, so the step name and the rule id are one object rather than two that a grep held together
//
// ONE PREDICATE NARROWED, and it is recorded here rather than absorbed into the
// carried arm above it. The predecessor took `head -n1` of grep order when a
// variable is read with a default in more than one program; an object
// comprehension over the same pairs raises on the duplicate key, so this asks
// whether the claim matches ANY observed default. That is strictly the more
// conservative direction — it can only report fewer drifts, never more — and no
// variable in the tree today is read with two different defaults.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{git_in, run, scratch, stdout, write};

/// The rule's own id, which is also what `--rule` selects.
const RULE: &str = "rules-drift";

/// Materialize a repository carrying the committed module and this row.
///
/// **The module is COPIED from the tree rather than restated inline**, on
/// `crates/batten/tests/memories.rs`' precedent: a fixture that re-typed the
/// predicate would be a second implementation, and it would pass over a module
/// the engine can no longer load.
///
/// The `[[pattern]]` rows and every `[[verdict]]` row are restated, because they
/// are CONSUMER config — the engine refuses at load a module raising a token no
/// row declares, and a fixture missing one fails with a config error that looks
/// nothing like the predicate being wrong.
fn fixture(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = scratch(name);
    let module = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy/rules-drift.rego"),
    )
    .expect("the committed module");
    write(&dir, "policy/rules-drift.rego", &module);
    write(
        &dir,
        "batten.toml",
        &format!(
            r#"version = 1

[[pattern]]
id = "restated-default"
regex = '`[A-Z][A-Z0-9_]+` \([0-9]+\)'

[[pattern]]
id = "shell-default"
regex = '\$\{{[A-Z][A-Z0-9_]*:-[^}}]*\}}'

[[pattern]]
id = "policy-input-key"
regex = '`input\.(tree|call)\.[a-z][a-z0-9_-]*'

[[pattern]]
id = "fixed-rule-ref"
regex = '`data\.batten\.[a-z_]+`'

[[pattern]]
id = "policy-rule-const"
regex = '^const [A-Z_]+_RULE: &str = "[a-z_]+";'

[[rule]]
id = "{RULE}"
kind = "policy"
scope = "tree"
line_sources = [
  "*.md",
  ".claude/rules/*.md",
  ".serena/memories/*.md",
  ".serena/memories/**/*.md",
  "mise-tasks/*.sh",
  "crates/batten/src/policy.rs",
]
sources = [
  ".claude/settings.json",
  "schema/policy-input.schema.json",
  "schema/policy-call.schema.json",
]
module = "policy/rules-drift.rego"
severity = "deny"

[[verdict]]
id = "V-RESTATED-DEFAULT-DRIFTS"
gloss = "a restated env default disagrees with the mechanism"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-DEFAULT"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-NAMED-EVENT-UNWIRED"
gloss = "a sentence claims a wiring nothing wires"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-EVENT"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-NAMED-INPUT-KEY-UNEMITTABLE"
gloss = "a named policy input key the schema does not carry"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-KEY"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-NAMED-FIXED-RULE-UNQUERIED"
gloss = "a named fixed rule the evaluator does not query"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-RULE"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-DRIFT-AUTHORITY-UNREADABLE"
gloss = "an authority some prose claims against could not be read"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-UNREADABLE"
kind = "document"
target = "policy/rules-drift.rego"
"#
        ),
    );
    for (path, body) in files {
        write(&dir, path, body);
    }
    git_in(&dir, &["init", "--initial-branch=main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-m", "fixture"]);
    dir
}

/// Judge the fixture on this one rule, and return what it said.
///
/// Findings are on STDOUT, which is where the pointer contract puts them.
fn judge(dir: &Path) -> (Option<i32>, String) {
    let out = run(dir, &["check", "--rule", RULE]);
    (out.status.code(), stdout(&out))
}

/// The four authorities, each spelled the way the real tree spells it.
fn authorities() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "mise-tasks/land.sh",
            "#!/usr/bin/env bash\nlaps=\"${LAND_MAX_LAPS:-2}\"\n",
        ),
        (
            ".claude/settings.json",
            r#"{"hooks": {"PreToolUse": [], "Stop": []}}"#,
        ),
        (
            "schema/policy-input.schema.json",
            r#"{"properties": {"tree": {"properties": {"documents": {}, "lines": {}}}}}"#,
        ),
        (
            "schema/policy-call.schema.json",
            r#"{"properties": {"call": {"properties": {"command": {}, "segments": {}}}}}"#,
        ),
        (
            "crates/batten/src/policy.rs",
            "const DENY_RULE: &str = \"deny\";\nconst RULES_RULE: &str = \"rules\";\n",
        ),
    ]
}

/// The authorities plus one prose file, which every case below varies.
fn tree(prose: &str) -> Vec<(&'static str, String)> {
    let mut files: Vec<(&'static str, String)> = authorities()
        .into_iter()
        .map(|(path, body)| (path, body.to_owned()))
        .collect();
    files.push((".claude/rules/toolchain.md", prose.to_owned()));
    files
}

fn judge_prose(name: &str, prose: &str) -> (Option<i32>, String) {
    let owned = tree(prose);
    let files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, body)| (*path, body.as_str()))
        .collect();
    judge(&fixture(name, &files))
}

#[test]
fn prose_that_agrees_with_every_mechanism_is_clean() {
    // THE ANTI-VACUITY MIRROR for every case below. Without it, a rule that
    // refused everything would satisfy each of them — and this file's whole
    // reason for existing is that the opposite failure is invisible.
    let (code, said) = judge_prose(
        "rules-drift-clean",
        "The backstop is `LAND_MAX_LAPS` (2) laps. The guard runs on `PreToolUse`.\n\
         A module iterates `input.tree.documents` and publishes `data.batten.deny`.\n",
    );
    assert_eq!(code, Some(0), "prose that agrees is clean\n{said}");
}

#[test]
fn a_restated_default_that_disagrees_is_reported_with_its_pointer() {
    // PREDICATE 1, and the engine-side property that matters: the `${VAR:-N}`
    // was read out of a `.sh` path as LINES. A `.sh` file is no format the
    // parser knows, so if the line surface did not reach it the authority would
    // be empty, `observed` would be false, and this case would pass for the
    // wrong reason — silently, which is why the clean mirror above is paired
    // with `a_variable_no_program_defaults_is_untouched` below.
    let (code, said) = judge_prose(
        "rules-drift-default",
        "The runaway backstop is `LAND_MAX_LAPS` (8) laps.\n",
    );
    assert_eq!(
        code,
        Some(2),
        "a disagreeing restatement is a finding\n{said}"
    );
    assert!(
        said.contains("restated-default-drifts"),
        "the finding names its rule\n{said}"
    );
    assert!(
        said.contains(".claude/rules/toolchain.md:1"),
        "pointer-only, and it must name the line to edit\n{said}"
    );
}

#[test]
fn a_knob_named_without_a_value_is_untouched() {
    // THE ANTI-INVERSION MIRROR, and it is the case this gate cannot ship
    // without. `toolchain.md`'s own rule is that a value should NOT be restated,
    // so a gate that pushed toward completeness would invert the discipline it
    // exists to enforce. Prose stays free to name a knob and point at it.
    let (code, said) = judge_prose(
        "rules-drift-named-only",
        "The runaway backstop is `LAND_MAX_LAPS`; read the value in the task.\n",
    );
    assert_eq!(
        code,
        Some(0),
        "naming a knob without asserting a value must never be a finding\n{said}"
    );
}

#[test]
fn a_variable_no_program_defaults_is_untouched() {
    // THE OTHER HALF OF THE SAME BOUND. A variable no task reads with a default
    // has nothing to disagree with, and inventing a disagreement there is the
    // same completeness pressure one step over.
    let (code, said) = judge_prose(
        "rules-drift-undefaulted",
        "The cap is `SOME_UNREAD_KNOB` (8) laps.\n",
    );
    assert_eq!(code, Some(0), "nothing to disagree with\n{said}");
}

#[test]
fn a_sentence_claiming_an_unwired_event_is_reported() {
    // PREDICATE 2. The authority is `.claude/settings.json`'s `hooks` keys,
    // reached as a PARSED document in the same row that reads markdown as lines
    // — two acquisitions, one row, and only a real run says both happened.
    let (code, said) = judge_prose(
        "rules-drift-event",
        "The contract-drift guard runs on `PostToolBatch` today.\n",
    );
    assert_eq!(code, Some(2), "an unwired claim is a finding\n{said}");
    assert!(
        said.contains("named-event-unwired"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_gap_recorded_beside_a_wiring_is_untouched() {
    // THE ROOM TO RECORD A GAP, over the real boundary. This is what makes the
    // scope a SENTENCE rather than a paragraph: a paragraph stating a wiring
    // often states an accepted gap in the same breath, and a paragraph-wide
    // check would forbid the repo from writing its own gaps down. CLOUD-461 was
    // the motivating instance, and its closing changed nothing — the next
    // accepted gap needs the same room.
    let (code, said) = judge_prose(
        "rules-drift-gap",
        "The guard runs on `PreToolUse`. The `PostToolBatch` entry stays absent,\n\
         and CLOUD-461 is why.\n",
    );
    assert_eq!(
        code,
        Some(0),
        "prose must stay able to say an event is NOT wired\n{said}"
    );
}

#[test]
fn a_named_input_key_the_schema_does_not_carry_is_reported() {
    // PREDICATE 3, and the acquisition it turns on is `walk` over a parsed JSON
    // document — `jq`'s recursive descent, which is why this row declares the
    // schemas as `documents` and not as lines.
    let (code, said) = judge_prose(
        "rules-drift-key",
        "A module iterates `input.tree.invented` for this.\n",
    );
    assert_eq!(code, Some(2), "an unemittable key is a finding\n{said}");
    assert!(
        said.contains("named-input-key-unemittable"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn the_two_schema_surfaces_are_judged_separately() {
    // THE SURFACE SPLIT, which is the half a single-schema fixture cannot show.
    // `command` is a real key — on the CALL document. Naming it under `tree` is
    // exactly the silent dead gate wearing a plausible name, so it must be a
    // finding rather than pass because the token exists somewhere.
    let (code, said) = judge_prose(
        "rules-drift-surface",
        "A module reads `input.tree.command` for this.\n",
    );
    assert_eq!(
        code,
        Some(2),
        "a key from the wrong surface is the defect, not a synonym\n{said}"
    );
    let (clean, also) = judge_prose(
        "rules-drift-surface-ok",
        "A module reads `input.call.command` for this.\n",
    );
    assert_eq!(
        clean,
        Some(0),
        "the same key on its own surface is fine\n{also}"
    );
}

#[test]
fn a_named_fixed_rule_the_evaluator_does_not_query_is_reported() {
    // PREDICATE 4. The authority is `policy.rs`'s own constants, read as lines
    // from a `.rs` path — the third acquisition surface in this one row.
    let (code, said) = judge_prose(
        "rules-drift-fixed",
        "Publish `data.batten.denies` to contribute to the set.\n",
    );
    assert_eq!(code, Some(2), "an unqueried name is a finding\n{said}");
    assert!(
        said.contains("named-fixed-rule-unqueried"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn the_subscripted_pattern_table_is_not_read_as_a_rule_name() {
    // THE ANCHOR THAT KEEPS `patterns` OUT, asserted rather than assumed. The
    // pattern table is always written subscripted, so it carries a bracket
    // before the closing backtick and is not a bare rule reference. Without this
    // case the gate would report every correct mention of the pattern table.
    let (code, said) = judge_prose(
        "rules-drift-subscripted",
        "Read the row as `data.batten.patterns[\"mem-reference\"]` instead.\n",
    );
    assert_eq!(
        code,
        Some(0),
        "a subscripted pattern reference is not a fixed rule name\n{said}"
    );
}

/// Build the standard tree with one authority replaced or dropped.
fn judge_without_settings(
    name: &str,
    prose: &str,
    settings: Option<&str>,
) -> (Option<i32>, String) {
    let owned = tree(prose);
    let mut files: Vec<(&str, &str)> = owned
        .iter()
        .filter(|(path, _)| *path != ".claude/settings.json")
        .map(|(path, body)| (*path, body.as_str()))
        .collect();
    if let Some(body) = settings {
        files.push((".claude/settings.json", body));
    }
    judge(&fixture(name, &files))
}

#[test]
fn an_absent_authority_a_claim_depends_on_is_refused() {
    // COULD-NOT-LOOK, and it is the arm the whole bundle turns on. A declared
    // authority the engine cannot read must not be silent: a module that
    // iterates only what it CAN read reports green over a file nobody looked at,
    // which is a dead gate arriving as a clean tree.
    //
    // Only the compiled tier can say this. A `with input as` case fabricates the
    // very shape it then reads, and the shape it would fabricate here is the one
    // the engine turned out not to build — see the next case.
    let (code, said) = judge_without_settings(
        "rules-drift-absent-authority",
        "The guard runs on `PreToolUse` today.\n",
        None,
    );
    assert_eq!(
        code,
        Some(2),
        "an absent authority a claim depends on must not be silent\n{said}"
    );
    assert!(
        said.contains("drift-authority-unreadable"),
        "and it must be its OWN class, distinguishable from a clean pass and \
         from a wiring that is merely absent\n{said}"
    );
}

#[test]
fn an_unparseable_authority_is_silent_today_and_that_is_an_engine_gap() {
    // THE MEASUREMENT THAT SHAPED THIS ROW, asserted as CURRENT BEHAVIOUR rather
    // than as a property anybody wants — the same shape `memories.rs` uses for
    // CLOUD-1276, and for the same reason: a test asserting the behaviour we WISH
    // for would be red on a defect that is not this member's to fix, and a test
    // asserting nothing would let the defect change silently under us.
    //
    // Measured over the compiled binary, a declared source the engine cannot READ
    // does not reach `input.tree.missing`. It stops the WHOLE RULE from
    // evaluating — an unconditional predicate that read nothing at all went quiet
    // with it, and the run exited 0 with no output. Three-way, one tree, one
    // module:
    //
    //   valid            -> the rule evaluates, the predicate fires, exit 2
    //   absent           -> `sources` keeps the rule alive; the arm above fires
    //   present, invalid -> NOTHING evaluates, exit 0, silent
    //
    // The `documents` (named-path) channel loses the middle row too, which is why
    // this row declares `sources`. The last row is what no spelling recovers.
    //
    // THE COST, STATED RATHER THAN ABSORBED: the predecessor caught both — `jq`
    // on an unparseable `.claude/settings.json` exited non-zero and the guard
    // refused. This successor catches the absent case and not the malformed one.
    // That is a narrow fidelity loss on a defect every `[[rule]]` in this
    // repository already has, not one this member introduces.
    let (code, said) = judge_without_settings(
        "rules-drift-unparseable-authority",
        "The guard runs on `PreToolUse` today.\n",
        Some("{ this is not json ,,,"),
    );
    assert_eq!(
        code,
        Some(0),
        "MEASURED, NOT DESIRED. If this goes red the engine learned to route an \
         unreadable source to `input.tree.missing` instead of silencing the rule \
         — delete this case and assert the refusal in the one above\n{said}"
    );
}

#[test]
fn an_authority_no_prose_claims_against_is_silent() {
    // THE SCOPE MIRROR, and it is the difference from the predecessor worth
    // measuring. `rules-drift.sh` exited 1 at startup when it could not read an
    // authority. A `[[rule]]` has NO CALL SITE — it runs wherever `batten check`
    // runs, including every fixture repository that inherits this config — so an
    // unconditional guard would make the row speak everywhere. That is the
    // scoping defect CLOUD-1164 records for `tree-clean`, and conditioning the
    // arm on there being a claim to judge is how this member avoids it.
    let (code, said) = judge_without_settings(
        "rules-drift-no-claim",
        "Ordinary prose that asserts nothing about any mechanism.\n",
        None,
    );
    assert_eq!(
        code,
        Some(0),
        "an authority nothing claims against must be silent, or this row speaks \
         in every fixture tree that inherits the config\n{said}"
    );
}

#[test]
fn the_memory_surface_is_walked_too() {
    // CLOUD-770's SURFACE, and the property is the one `memories.rs` names for
    // its own globs: `line_sources` is a union of includes with
    // `literal_separator(true)`, so a nesting depth nobody spelled is silently
    // outside the judged set — and a rule that selects nothing reports green
    // exactly like a clean tree. Its coverage on the real repo is PROSPECTIVE
    // (measured 2026-08-20, no memory uses the anchor), which makes this the
    // only place the surface is shown to be reachable at all.
    let owned = tree("Ordinary prose.\n");
    let mut files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, body)| (*path, body.as_str()))
        .collect();
    files.push((
        ".serena/memories/workflow/landing-loop.md",
        "The backstop is `LAND_MAX_LAPS` (8) laps.\n",
    ));
    let (code, said) = judge(&fixture("rules-drift-memory", &files));
    assert_eq!(
        code,
        Some(2),
        "a nested memory is judged, or CLOUD-770's surface is decorative\n{said}"
    );
    assert!(
        said.contains(".serena/memories/workflow/landing-loop.md"),
        "and the pointer names the memory rather than the rules file\n{said}"
    );
}
