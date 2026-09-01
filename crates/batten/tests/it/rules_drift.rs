//! A restated value still agrees with the mechanism that owns it, over the
//! compiled binary (CLOUD-506/770/932's predicates, CLOUD-1150's retirement).
//!
//! **This is the tier `policy/rules-drift.rego`'s own `test_` rules cannot be.**
//! A `with input as` block writes the shape it then reads, so it is green over a
//! key the engine never fills. Every predicate here but one reads an
//! AUTHORITY that is not prose — a shell string, a generated JSON schema, a Rust
//! constant, a Rego module — and each arrives through a different acquisition
//! path. Whether the engine hands any of them over is decidable only here:
//!
//! * `${VAR:-N}` is read from `mise-tasks/*.sh` as LINES, and a `.sh` file is not
//!   a format the parser knows. Only a real run says the line surface reaches it.
//! * The schema keys are read over a PARSED document, which is a
//!   different acquisition from the line one beside it in the same row.
//! * `policy.rs`'s constants are read as lines from a `.rs` path — a third
//!   surface, in a row whose other members are markdown and JSON.
//! * A module's own rule HEADS are read as lines from a `policy/*.rego` path
//!   (CLOUD-1150 §2), which is a fourth. The count they yield is the authority a
//!   restated `(N arms)` is held to, so a hand-written table of the arms would be
//!   the third authority this whole gate exists to refuse.
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
// `drift read unread` rather than exiting before any predicate runs.
//
// changed: "an empty rules directory is refused rather than silently green" policy/rules-drift.rego a glob that selects nothing is silent here rather than exit 1: `line_sources` is a glob and a repository with no rules tree is an ordinary consumer, which is exactly what the predecessor already said about an ABSENT MEMORY TREE one case below. The refusal it does keep is the one that has a subject — an authority some prose claims against
// changed: "unreadable wiring is refused rather than reporting every event unwired" policy/rules-drift.rego conditioned on a wiring claim existing: an unreadable `.claude/settings.json` is `drift read unread` when some sentence claims a wiring, and silent when none does
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

use crate::common;

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
id = "module read first"
regex = '^const [A-Z_]+_RULE: &str = "[a-z_]+";'

[[pattern]]
id = "restated-arm-count"
regex = '`[a-z][a-z0-9_]+` \([0-9]+ arms\)'

[[pattern]]
id = "rego-rule-head"
regex = '^[a-z][a-z0-9_]*[(\[ ]'

[[pattern]]
id = "policy-input-key-subscripted"
regex = '`input\.(tree|call)\["[a-z][a-z0-9-]+"\]'

[[pattern]]
id = "schema-authority-claim"
regex = 'holds the lists above to those two files'

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
  "policy/*.rego",
]
sources = [
  ".claude/settings.json",
  "schema/policy-input.schema.json",
  "schema/policy-call.schema.json",
]
module = "policy/rules-drift.rego"
severity = "deny"

[[verdict]]
id = "default state other"
gloss = "a restated env default disagrees with the mechanism"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-DEFAULT"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "event wire missing"
gloss = "a sentence claims a wiring nothing wires"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-EVENT"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "input key dead"
gloss = "a named policy input key the schema does not carry"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-KEY"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "rule ask missing"
gloss = "a named fixed rule the evaluator does not query"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-RULE"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-RESTATED-ARM-COUNT-DRIFTS"
gloss = "a restated arm count disagrees with the module"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-ARM-COUNT"
kind = "document"
target = "policy/rules-drift.rego"

[[verdict]]
id = "V-SCHEMA-KEY-UNDOCUMENTED"
gloss = "a claiming file does not name a key the engine emits"
class = "fixture"

[[verdict.route]]
id = "R-FIXTURE-UNDOCUMENTED"
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
fn an_unparseable_authority_a_claim_depends_on_is_refused() {
    // THE OTHER HALF OF THE CLASS, and it used to be this file's standing record
    // of a defect. It asserted exit 0 as MEASURED-not-desired and carried its own
    // instruction: "If this goes red the engine learned to route an unreadable
    // source to `input.tree.missing` instead of silencing the rule — delete this
    // case and assert the refusal in the one above." CLOUD-1049's fix is what
    // made it go red, so this is that instruction carried out.
    //
    // The two cases are kept SEPARATE rather than folded together, because the
    // engine reaches them by different routes and a single case would stop
    // discriminating: `an_absent_authority_...` above is a path that never
    // entered the acquisition set, this one is a path that was read and would not
    // parse. `NotAcquired` keeps `Absent` and `Unparsed` distinct precisely so a
    // policy cannot mistake one for the other, and this pair is what proves the
    // distinction survives the projection.
    //
    // THE FIDELITY LOSS THIS FILE RECORDED IS NOW REPAID. Six `changed:` arms
    // above say the successor caught an absent authority and not a malformed one,
    // "a narrow fidelity loss on a defect every `[[rule]]` in this repository
    // already has". The defect is fixed and the loss is gone: the predecessor's
    // `jq` refused a malformed `.claude/settings.json` loudly, and so does this.
    let (code, said) = judge_without_settings(
        "rules-drift-unparseable-authority",
        "The guard runs on `PreToolUse` today.\n",
        Some("{ this is not json ,,,"),
    );
    assert_eq!(
        code,
        Some(2),
        "an authority that will not parse is could-not-look, not a clean tree\n{said}"
    );
    assert!(
        said.contains("drift-authority-unreadable"),
        "and it reaches the same class as the absent case — one channel, two \
         causes, neither of them silence\n{said}"
    );
}

#[test]
fn an_unparseable_authority_no_prose_claims_against_is_still_silent() {
    // THE ANTI-VACUITY MIRROR FOR THE ARM CLOUD-1049 BROUGHT TO LIFE, and it is
    // the case that keeps the fix from over-reaching. Now that an unreadable
    // source reaches the module, the danger inverts: a row could refuse in every
    // tree that happens not to carry one of its authorities, which is the
    // fixture-wide noise `tree-clean` was backed out for.
    //
    // The conditioning is what prevents it — this arm fires only where some prose
    // actually claims against the authority — and that conditioning is invisible
    // unless a case drives the same malformed file past prose that claims
    // nothing. Without this, `an_unparseable_authority_a_claim_depends_on_is_refused`
    // is satisfied by a rule that refuses unconditionally.
    let (code, said) = judge_without_settings(
        "rules-drift-unparseable-no-claim",
        "Ordinary prose that asserts nothing about any mechanism.\n",
        Some("{ this is not json ,,,"),
    );
    assert_eq!(
        code,
        Some(0),
        "an authority nothing claims against is not this row's business, however \
         unreadable it is\n{said}"
    );
    assert!(
        !said.contains("drift-authority-unreadable"),
        "and the could-not-look class must not fire on a tree that asked no \
         question of the file\n{said}"
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

/// The authorities plus one prose file AND extra files the case supplies.
///
/// Split from [`judge_prose`] rather than widening it: the two predicates below
/// read a surface the other five do not — a `.rego` module's own rule heads — and
/// threading an empty slice through every existing call site would say those
/// cases had something to do with it.
fn judge_prose_with(name: &str, prose: &str, extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let owned = tree(prose);
    let mut files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, body)| (*path, body.as_str()))
        .collect();
    files.extend_from_slice(extra);
    judge(&fixture(name, &files))
}

/// A module with `n` heads for `probe_arm`, plus one INDENTED occurrence that
/// must not count.
///
/// The indented line is what makes the anchor observable rather than assumed: a
/// pattern without `^` would count it, so every case below would be off by one in
/// the same direction and the pair would still look consistent.
const PROBE: &str = "package batten.probe\n\
                     \n\
                     import rego.v1\n\
                     \n\
                     probe_arm(a) if a == 1\n\
                     probe_arm(a) if a == 2\n\
                     probe_arm(a) if a == 3\n\
                     \tprobe_arm(a) if a == 4\n";

#[test]
fn a_restated_arm_count_that_disagrees_with_the_module_is_reported() {
    // CLOUD-1150 §2, and the acquisition it turns on is a SIXTH surface in this
    // one row: a `policy/*.rego` path read as LINES. The predicate counts rule
    // heads out of the modules themselves, so a hand-written table of the arms
    // would be the third authority this whole gate exists to refuse — and if the
    // line surface did not reach `.rego`, `arm_count` would be undefined, the
    // body would not hold, and this case would pass for the wrong reason.
    let (code, said) = judge_prose_with(
        "rules-drift-arms",
        "The admission is `probe_arm` (2 arms) today.\n",
        &[("policy/probe.rego", PROBE)],
    );
    assert_eq!(code, Some(2), "a wrong arm count is a finding\n{said}");
    assert!(
        said.contains("restated-arm-count-drifts"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn an_arm_count_that_agrees_with_the_module_is_untouched() {
    // THE ANTI-VACUITY MIRROR, and it doubles as the anchor's own assertion: the
    // module carries FOUR `probe_arm` lines and one of them is indented, so three
    // is the agreeing answer. A predicate that counted the indented line would be
    // red here and green above, which is the only way round that discriminates.
    let (code, said) = judge_prose_with(
        "rules-drift-arms-ok",
        "The admission is `probe_arm` (3 arms) today.\n",
        &[("policy/probe.rego", PROBE)],
    );
    assert_eq!(code, Some(0), "the right count is clean\n{said}");
}

#[test]
fn an_arm_named_without_a_count_is_untouched() {
    // THE ANTI-INVERSION MIRROR, predicate 1's one shape up. This file's own rule
    // is that a value should be read at its authority rather than restated, so a
    // gate demanding that every mention of a mechanism enumerate it would invert
    // the discipline it enforces.
    let (code, said) = judge_prose_with(
        "rules-drift-arms-unclaimed",
        "`probe_arm` is the authority; read the module rather than this line.\n",
        &[("policy/probe.rego", PROBE)],
    );
    assert_eq!(
        code,
        Some(0),
        "naming without counting is not a claim\n{said}"
    );
}

/// The sentence `.claude/rules/policy-modules.md` closes its key lists with, and
/// the anchor `schema-key-undocumented` keys on.
const CLAIM: &str = "`rules-drift` holds the lists above to those two files.\n";

#[test]
fn a_schema_key_the_claiming_file_omits_is_reported() {
    // CLOUD-1206, and it is predicate 3 RUN BACKWARDS over the same acquisition.
    // The fixture schema declares `documents` and `lines`; the prose claims to
    // enumerate them and names only the first. That is the live defect measured
    // 2026-08-30 in miniature — `base-delta` and `symbols` were emittable and
    // unnamed under exactly this sentence.
    let (code, said) = judge_prose_with(
        "rules-drift-undocumented",
        &format!(
            "A module iterates `input.tree.documents`, `input.call.command` and \
             `input.call.segments`.\n{CLAIM}"
        ),
        &[],
    );
    assert_eq!(
        code,
        Some(2),
        "an omitted emittable key is a finding\n{said}"
    );
    assert!(
        said.contains("schema-key-undocumented"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn the_claiming_file_naming_every_key_is_clean() {
    // THE ANTI-VACUITY MIRROR, and the case that would go red if the predicate
    // reported every key rather than the missing ones.
    let (code, said) = judge_prose_with(
        "rules-drift-documented",
        &format!(
            "A module iterates `input.tree.documents`, `input.tree.lines`, \
             `input.call.command` and `input.call.segments`.\n{CLAIM}"
        ),
        &[],
    );
    assert_eq!(code, Some(0), "naming every key is clean\n{said}");
}

#[test]
fn a_file_making_no_authority_claim_is_untouched() {
    // THE SCOPE MIRROR, and it is what keeps this inside the anti-restatement
    // bound: without it the gate would demand that every prose surface in the
    // repository enumerate all 24 tree keys. The prose here is byte-identical to
    // the reported case minus the claiming sentence.
    let (code, said) = judge_prose_with(
        "rules-drift-unclaimed",
        "A module iterates `input.tree.documents`, `input.call.command` and \
         `input.call.segments`.\n",
        &[],
    );
    assert_eq!(
        code,
        Some(0),
        "a file promising nothing is untouched\n{said}"
    );
}

#[test]
fn the_subscripted_spelling_counts_as_naming_a_key() {
    // Eight of the engine's keys carry a hyphen, which is not a legal Rego
    // selector, so they are only ever written `input.tree["git-history"]` — and
    // `policy-input-key`'s `\.` cannot match a `[`. Left unread, this predicate's
    // first run over the real tree would have been eight false findings, which is
    // a gate nobody keeps. Asserted over the boundary rather than in the module,
    // because it is the ENGINE handing the line over that makes it decidable.
    // NAMED APART FROM `the_subscripted_pattern_table_is_not_read_as_a_rule_name`'s
    // fixture, which was `rules-drift-subscripted` first. `scratch` keys the
    // directory on the name, so two cases sharing one wrote each other's prose and
    // whichever ran second judged the other's tree — green or red by scheduling
    // order, which is the worst way for a suite to be wrong.
    let (code, said) = judge_prose_with(
        "rules-drift-subscripted-key",
        &format!(
            "A module iterates `input.tree[\"documents\"]`, `input.tree.lines`, \
             `input.call[\"command\"]` and `input.call.segments`.\n{CLAIM}"
        ),
        &[],
    );
    assert_eq!(
        code,
        Some(0),
        "the subscripted spelling names the key too\n{said}"
    );
}

#[test]
fn the_two_anchors_this_gate_keys_on_are_still_one_line_in_the_committed_files() {
    // THE ANTI-DEAD-GATE ASSERTION, and it exists because both new predicates are
    // LINE-ORIENTED over prose a formatter owns. `prettier` reflows Markdown, so a
    // future edit that pushes `` `admitted_addition` (4 arms) `` or the schema
    // authority sentence across a line break leaves the pattern matching nothing —
    // and a dead gate and a clean tree are byte-identical on the decision surface,
    // which is the class this whole file opens with, arriving through the gate's
    // own anchor rather than through its input.
    //
    // Asserted over the COMMITTED files rather than a fixture: a fixture would
    // pass over a repository whose anchors had already been reflowed away, which
    // is precisely the state that must be red.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let toolchain = std::fs::read_to_string(root.join(".claude/rules/toolchain.md"))
        .expect("the committed toolchain rules");
    assert!(
        toolchain
            .lines()
            .any(|line| line.contains("`admitted_addition` (4 arms)")),
        "the arm-count claim must survive on one line or `restated-arm-count` \
         silently stops judging it"
    );
    let modules = std::fs::read_to_string(root.join(".claude/rules/policy-modules.md"))
        .expect("the committed module rules");
    assert!(
        modules
            .lines()
            .any(|line| line.contains("holds the lists above to those two files")),
        "the schema authority claim must survive on one line or \
         `schema-key-undocumented` silently stops judging it"
    );
}
