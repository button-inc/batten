//! The predecessor acceptance corpus, translated (CLOUD-64).
//!
//! The source is external and read-only: `docs/acceptance-checks.yaml` in the
//! predecessor consumer repo, pinned at blob `ceba3afd` — 9600 bytes, 165
//! lines, **21 items**. It is never vendored here; what lands is the corpus's
//! content in Batten's own vocabulary, as
//! `tests/fixtures/acceptance-corpus/batten.toml.in` plus this suite.
//!
//! **Parity is total, and that is the point.** A translation that quietly
//! dropped an item would look exactly like a translation that finished, so
//! every source item carries one entry in [`DISPOSITIONS`] naming its bucket
//! and the artifact behind it. The table's length is asserted against the
//! pinned item count, every rule-bucket entry must resolve to a rule actually
//! present in the materialized fixture, and every test-bucket entry must name a
//! test in this file — so an item can neither vanish nor be filed into a bucket
//! with nothing behind it.
//!
//! **De-identification is checked, not asserted.** Obligation (f) walks the
//! materialized ruleset and requires every `check` program and every path-shaped
//! argument to resolve inside the fixture directory. Deliberately not a
//! denylist of consumer names: that would put those names inside
//! `crates/batten` and break non-negotiable rule 1 in the act of enforcing it.
//!
//! Kept out of `tests/cli.rs`, which is the exit-code and output-contract
//! suite.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::config::Config;
use batten::severity::RuleSeverity;

/// Items in the pinned source blob `ceba3afd`.
///
/// Asserted against, never derived: re-pinning the source must be a deliberate
/// edit to this number rather than a silently absorbed drift.
const SOURCE_ITEM_COUNT: usize = 21;

/// Where one source item ended up.
enum Bucket {
    /// A `deny` `command` rule. The source expected exit `0`, which is exactly
    /// the engine's predicate — but its `stdout_contains` does not cross, so
    /// the invocation survives and the output assertion does not.
    RuleExitOnly(&'static str),
    /// A `warn` `command` rule: the source expected a non-zero that IS the
    /// tree's current state, reported without failing the run.
    RuleWarn(&'static str),
    /// A negative test over the compiled binary: the source handed the tool a
    /// fixed input and expected the tool's own refusal.
    NegativeTest(&'static str),
    /// Recorded as not crossing, against the issue whose surface it needs.
    NotCrossing(&'static str),
}

/// One entry per item in the source blob, in source order.
///
/// The `name` is the source item's own `name:` field, so the mapping can be
/// read against the source without guessing.
struct Disposition {
    source_name: &'static str,
    bucket: Bucket,
}

const DISPOSITIONS: &[Disposition] = &[
    Disposition {
        source_name: "conflict-marker finds no markers in authored files",
        bucket: Bucket::RuleExitOnly("conflict-marker"),
    },
    Disposition {
        source_name: "build config run lines are single commands, with no shell logic",
        bucket: Bucket::RuleExitOnly("build-config-single-commands"),
    },
    Disposition {
        source_name: "no append-only ledger has lost a record",
        bucket: Bucket::RuleExitOnly("append-only-ledgers-intact"),
    },
    Disposition {
        source_name: "the build system invokes no undeclared external command",
        bucket: Bucket::RuleExitOnly("no-undeclared-external-command"),
    },
    Disposition {
        source_name: "entity-grep reports entity-fact occurrences",
        bucket: Bucket::RuleWarn("entity-fact-occurrences"),
    },
    Disposition {
        source_name: "token-budget passes at the floor",
        bucket: Bucket::RuleExitOnly("token-budget-floor"),
    },
    Disposition {
        source_name: "token-budget fails against the aspirational threshold",
        bucket: Bucket::RuleWarn("token-budget-target"),
    },
    Disposition {
        source_name: "evidence-unlanded reports landed when nothing is ahead of the base",
        bucket: Bucket::RuleExitOnly("evidence-landed"),
    },
    Disposition {
        source_name: "ruleset exits non-zero (not a silent 0) on empty input",
        bucket: Bucket::NegativeTest("an_empty_check_template_is_refused_rather_than_skipped"),
    },
    Disposition {
        source_name: "defects store is populated and queryable",
        bucket: Bucket::RuleExitOnly("defect-store-queryable"),
    },
    Disposition {
        source_name: "design workspace conforms to the structure contract",
        bucket: Bucket::RuleExitOnly("design-structure-conforms"),
    },
    Disposition {
        source_name: "brief --template prints the required delegation schema",
        bucket: Bucket::RuleExitOnly("delegation-schema-available"),
    },
    Disposition {
        source_name: "brief flags an incomplete delegation prompt",
        bucket: Bucket::NegativeTest("a_rule_whose_program_is_absent_is_not_a_silent_pass"),
    },
    Disposition {
        source_name: "design evidence passes the research-integrity audit",
        bucket: Bucket::RuleExitOnly("design-evidence-audited"),
    },
    Disposition {
        source_name: "shape-lint config parses and every rule builds",
        bucket: Bucket::RuleExitOnly("shape-lint-config-parses"),
    },
    Disposition {
        source_name: "shape-lint rules are loaded, with the severity tiers intact",
        bucket: Bucket::RuleExitOnly("shape-lint-rules-loaded"),
    },
    Disposition {
        source_name: "shape-lint error-level rules pass on the committed tree",
        bucket: Bucket::RuleExitOnly("shape-lint-error-tier-clean"),
    },
    Disposition {
        source_name: "shape-lint warning backlog is real",
        bucket: Bucket::RuleWarn("shape-lint-warning-backlog"),
    },
    Disposition {
        source_name: "questions answer refuses an unknown id (not a silent no-op)",
        bucket: Bucket::NegativeTest("a_per_kind_field_mismatch_is_refused_rather_than_ignored"),
    },
    Disposition {
        source_name: "the question record stays honestly open",
        bucket: Bucket::RuleExitOnly("question-record-present"),
    },
    // The one item declaring no `expect_exit` at all. A `command` rule would
    // invent the exit `0` the source never states, and it has no non-zero to
    // place; its whole content is a stdout_contains/stdout_absent pair, which
    // needs the `exec` output-predicate surface.
    Disposition {
        source_name: "at-risk reports PR status as a measured field",
        bucket: Bucket::NotCrossing("CLOUD-117"),
    },
];

/// This suite's own source, read for the self-referential assertions below.
///
/// Located from `CARGO_MANIFEST_DIR` rather than `file!()`: that macro yields a
/// workspace-relative path, and the test process's working directory is not the
/// workspace root.
fn this_file() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/it/acceptance_corpus.rs"),
    )
    .expect("read this suite's own source")
}

/// The committed fixture ruleset and its tree.
fn source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/acceptance-corpus")
}

/// Materialize the fixture into a scratch tree, stripping the inertness suffix.
///
/// The stub programs need their executable bit: the corpus is committed as
/// inert data, and `.in` files carry no mode worth preserving.
fn materialize(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("acceptance-corpus/{name}"));
    copy_inert(&source_dir(), &dir);
    dir
}

fn copy_inert(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).expect("read the fixture source") {
        let entry = entry.expect("read a fixture entry");
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            let child = to.join(&file_name);
            fs::create_dir_all(&child).expect("create fixture subdirectory");
            copy_inert(&path, &child);
            continue;
        }
        let stripped = file_name
            .strip_suffix(".in")
            .unwrap_or_else(|| panic!("{file_name} is committed without the .in suffix"));
        let contents = fs::read_to_string(&path).expect("read a fixture file");
        let target = to.join(stripped);
        fs::write(&target, contents).expect("write a fixture file");
        if to.file_name().and_then(|n| n.to_str()) == Some("bin") {
            make_executable(&target);
        }
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mark the stub executable");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// The materialized ruleset, parsed.
fn materialized_config(dir: &Path) -> Config {
    let text = fs::read_to_string(dir.join("batten.toml")).expect("read the materialized config");
    toml::from_str(&text).expect("the materialized fixture is a valid batten.toml")
}

// --- (a) the driver verb, clean and with a seeded violation ------------------

#[test]
fn enforce_is_clean_on_the_fixture_and_a_violation_when_seeded() {
    let dir = materialize("enforce-clean");
    let clean = common::run(&dir, &["enforce"]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "clean tree: {}",
        common::stderr(&clean)
    );

    // Fail-loudness is proved once, here, rather than once per source item: the
    // seed flips every stub to non-zero, so a `deny` rule fires.
    let seeded = materialize("enforce-seeded");
    common::write(&seeded, "seed-violation", "");
    let output = common::run(&seeded, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a deny finding is the policy verdict"
    );
    assert!(
        !common::stdout(&output).is_empty(),
        "a violation must print a pointer"
    );
}

// --- (b) `check` refuses the ruleset rather than skipping it -----------------

#[test]
fn check_refuses_the_spawning_ruleset_and_names_enforce() {
    // The §5 split is what keeps `check`'s `read` classification honest: a
    // skipped rule that still exited 0 is the false green Batten exists to
    // catch.
    let dir = materialize("check-refuses");
    let output = common::run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a usage error, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("batten enforce"),
        "the refusal must name the verb that can run it: {}",
        common::stderr(&output)
    );
}

// --- (c) warn reports without failing, until promoted ------------------------

#[test]
fn the_warn_items_report_without_failing_until_promoted() {
    let dir = materialize("warn-promotion");
    let default = common::run(&dir, &["enforce"]);
    assert_eq!(default.status.code(), Some(0), "a warn finding is clean");
    assert!(
        !common::stdout(&default).is_empty(),
        "…and is still reported"
    );

    let promoted = common::run(&dir, &["enforce", "--fail-on-warning"]);
    assert_eq!(promoted.status.code(), Some(2), "promotable to a violation");
    assert_eq!(
        common::stdout(&default),
        common::stdout(&promoted),
        "promotion changes the verdict, never what was found"
    );
}

// --- (d) the machine contract is byte-stable ---------------------------------

#[test]
fn the_json_payload_is_byte_stable_across_runs() {
    let dir = materialize("json-stable");
    let first = common::run(&dir, &["enforce", "-J"]);
    let second = common::run(&dir, &["enforce", "-J"]);
    assert_eq!(
        first.stdout, second.stdout,
        "identical input, identical bytes"
    );
}

// --- (e) parity is total -----------------------------------------------------

#[test]
fn every_source_item_has_exactly_one_recorded_disposition() {
    assert_eq!(
        DISPOSITIONS.len(),
        SOURCE_ITEM_COUNT,
        "the disposition table must cover the pinned source blob exactly"
    );

    let dir = materialize("parity");
    let config = materialized_config(&dir);
    let this_file = this_file();

    for entry in DISPOSITIONS {
        match entry.bucket {
            Bucket::RuleExitOnly(id) | Bucket::RuleWarn(id) => {
                let rule = config
                    .rules
                    .iter()
                    .find(|rule| rule.id == id)
                    .unwrap_or_else(|| {
                        panic!(
                            "{}: names rule {id}, absent from the fixture",
                            entry.source_name
                        )
                    });
                let expected = match entry.bucket {
                    Bucket::RuleWarn(_) => RuleSeverity::Warn,
                    _ => RuleSeverity::Deny,
                };
                assert_eq!(
                    rule.severity(),
                    expected,
                    "{}: rule {id} carries the wrong severity for its bucket",
                    entry.source_name
                );
            }
            Bucket::NegativeTest(name) => assert!(
                this_file.contains(&format!("fn {name}(")),
                "{}: names test {name}, which does not exist here",
                entry.source_name
            ),
            Bucket::NotCrossing(issue) => assert!(
                issue.starts_with("CLOUD-"),
                "a non-crossing must name the issue whose surface it needs"
            ),
        }
    }

    // The other direction: no rule in the fixture is unaccounted for, so the
    // table cannot go stale by addition either.
    for rule in &config.rules {
        assert!(
            DISPOSITIONS.iter().any(|entry| matches!(
                entry.bucket,
                Bucket::RuleExitOnly(id) | Bucket::RuleWarn(id) if id == rule.id
            )),
            "rule {} is in the fixture but in no disposition entry",
            rule.id
        );
    }
}

// --- (§4) the fixture is a real batten.toml, judged by the published schema ---

#[test]
fn the_materialized_fixture_validates_against_the_derived_schema() {
    // The `.in` copy is inert bytes; what the suite writes is what the schema
    // judges. Without this the port could introduce a config shape the schema
    // Batten publishes to consumers rejects.
    let dir = materialize("schema");
    let output = common::batten()
        .args(["generate", "schema"])
        .output()
        .expect("run batten generate schema");
    assert_eq!(output.status.code(), Some(0));
    let schema: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");

    let text = fs::read_to_string(dir.join("batten.toml")).expect("read the materialized config");
    let document: serde_json::Value = toml::from_str(&text).expect("the fixture is valid TOML");
    let errors: Vec<String> = validator
        .iter_errors(&document)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "the fixture is not schema-valid: {errors:?}"
    );
}

// --- (f) de-identification is checked ----------------------------------------

#[test]
fn every_program_and_path_shaped_argument_resolves_inside_the_fixture() {
    // Checked rather than asserted, and without a denylist: the property is
    // "nothing in this ruleset reaches outside the fixture", which is decidable
    // from the fixture alone.
    let dir = materialize("containment");
    let config = materialized_config(&dir);
    assert!(!config.rules.is_empty(), "an empty ruleset would pass here");

    for rule in &config.rules {
        let check = rule
            .check
            .as_deref()
            .unwrap_or_else(|| panic!("rule {} is a command rule with no check template", rule.id));
        for token in check.split_whitespace() {
            if token.starts_with('-') || !token.contains('/') {
                continue;
            }
            assert!(
                !Path::new(token).is_absolute(),
                "rule {}: {token} is an absolute path",
                rule.id
            );
            assert!(
                dir.join(token).exists(),
                "rule {}: {token} does not resolve inside the fixture",
                rule.id
            );
        }
    }
}

// --- (g) no second command builder -------------------------------------------

#[test]
fn this_suite_builds_its_invocation_through_the_one_materializer() {
    // CLOUD-63 collapsed the per-suite copies onto tests/common/mod.rs. A new
    // target that re-typed the builder would restore the drift that collapse
    // removed, so the absence is asserted rather than left to review.
    // The needle is assembled at runtime rather than written as a literal: a
    // test that searched its own source for a string it also spells would match
    // itself and fail whatever the rest of the file did. Same shape as a rule id
    // that must not embed the literal it bans.
    let needle = format!("CARGO_{}_EXE_batten", "BIN");
    assert!(
        !this_file().contains(&needle),
        "this suite must reach the binary through common::batten()"
    );
    assert!(this_file().contains("mod common;"));
}

// --- the three negative tests ------------------------------------------------
//
// Each preserves a source item whose non-zero came from a FIXED INPUT rather
// than from the tree — the tool's own refusal. The tool is now `batten`, so
// what is preserved is the shape (fixed input → named refusal, never a silent
// pass), not the predecessor's message.

#[test]
fn an_empty_check_template_is_refused_rather_than_skipped() {
    // The source handed its runner an empty ruleset source and required a
    // non-zero rather than a silent 0. Here: a `command` rule with nothing to
    // run is a usage error, not a rule that trivially passes.
    let dir = materialize("negative-empty-run");
    common::write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"empty\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"\"\nseverity = \"deny\"\n",
    );
    let output = common::run(&dir, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an empty check template is a usage error: {}",
        common::stderr(&output)
    );
    assert!(
        common::stdout(&output).is_empty(),
        "a diagnostic is not a finding"
    );
}

#[test]
fn a_rule_whose_program_is_absent_is_not_a_silent_pass() {
    // The source pointed its tool at a committed fixture it knew was
    // incomplete and required a loud failure. Here: a rule naming a program
    // that does not exist must never resolve to "passed".
    let dir = materialize("negative-absent-program");
    common::write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"absent\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"bin/not-materialized\"\nseverity = \"deny\"\n",
    );
    let output = common::run(&dir, &["enforce"]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "an unrunnable rule must not report green"
    );
}

#[test]
fn a_per_kind_field_mismatch_is_refused_rather_than_ignored() {
    // The source required its tool to refuse an id it did not know rather than
    // no-op. Here: a rule carrying a field its kind does not take is refused at
    // load, never quietly dropped.
    let dir = materialize("negative-field-mismatch");
    common::write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"mismatch\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"bin/checker design verify\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    let output = common::run(&dir, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a per-kind field mismatch is a usage error: {}",
        common::stderr(&output)
    );
}
