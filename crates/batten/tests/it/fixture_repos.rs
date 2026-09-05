//! The discovered fixture-repository corpus (CLOUD-63).
//!
//! Every fixture is a directory under `tests/fixtures/repos/`, and this file
//! carries **zero fixture facts**: no fixture list, no expected bytes, no
//! per-fixture branch. It enumerates the corpus root, materializes each
//! directory into a scratch repository, runs the argv the fixture pins, and
//! compares against the fixture's own committed `expected`.
//!
//! There is deliberately **no accept/bless mode**. An `expected` file rewritten
//! from observed output would agree with any behaviour at all, which is a
//! harness that gates nothing.
//!
//! The corpus is self-referential — a driver that discovered zero fixtures, or
//! silently skipped a malformed one, would be green — so the obligations that
//! keep it from passing vacuously are asserted here rather than argued:
//! discovery is exact rather than merely non-empty, a missing `expected` is an
//! error rather than a skip, the comparison is negatively self-tested, every
//! `RuleKind` variant is covered, and every fixture is run twice.
//!
//! **Inertness.** Corpus files are committed with a trailing `.in` and
//! materialization strips it, so a fixture may carry a shape this repository's
//! own gates refuse (a conflict marker, an invalid config, unformatted TOML)
//! without tripping them over the same tree. `expected.in` is the one file that
//! is *not* materialized: it is the specification, not payload, and writing it
//! into the fixture tree would put a file in front of the globs under test.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::config::Config;
use batten::rules::RuleKind;

/// The committed corpus root.
///
/// A named subdirectory of `tests/fixtures/` rather than that directory itself,
/// so a suite-driven fixture tree can share the parent without either suite
/// enumerating the other's contents.
fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repos")
}

/// The suffix every committed corpus file carries, stripped on materialization.
const INERT_SUFFIX: &str = ".in";

/// The committed expectation, before its suffix is stripped.
const EXPECTED_FILE: &str = "expected.in";

/// What a fixture pins: the invocation, the exit code, the exact stdout, and any
/// stderr substrings.
struct Expectation {
    argv: Vec<String>,
    exit: i32,
    stdout: String,
    /// Substrings, not byte-equality: a diagnostic interpolates the config's own
    /// path, which is the per-run scratch directory.
    stderr_contains: Vec<String>,
}

/// Parse a committed `expected` file.
///
/// Strict on purpose — an unrecognised key or a missing required one is an
/// error, never a default. A parser that shrugged at a typo would silently drop
/// the assertion the typo was in.
fn parse_expectation(text: &str, fixture: &str) -> Expectation {
    let mut argv = None;
    let mut exit = None;
    let mut stderr_contains = Vec::new();
    let mut stdout = None;

    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line == "stdout:" {
            // Everything after this marker is the expected stdout, verbatim.
            let rest: Vec<&str> = lines.by_ref().collect();
            stdout = Some(if rest.is_empty() {
                String::new()
            } else {
                format!("{}\n", rest.join("\n"))
            });
            break;
        }
        let Some((key, value)) = line.split_once(": ") else {
            panic!("{fixture}: unparseable expectation line: {line:?}");
        };
        match key {
            "argv" => argv = Some(value.split_whitespace().map(str::to_owned).collect()),
            "exit" => exit = Some(value.parse().expect("exit code is an integer")),
            "stderr-contains" => stderr_contains.push(value.to_owned()),
            other => panic!("{fixture}: unknown expectation key {other:?}"),
        }
    }

    Expectation {
        argv: argv.unwrap_or_else(|| panic!("{fixture}: expectation names no argv")),
        exit: exit.unwrap_or_else(|| panic!("{fixture}: expectation names no exit code")),
        stdout: stdout.unwrap_or_else(|| panic!("{fixture}: expectation has no stdout: marker")),
        stderr_contains,
    }
}

/// Every fixture directory directly under the corpus root, sorted.
fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(corpus_root())
        .expect("read the corpus root")
        .map(|entry| entry.expect("read a corpus entry"))
        .filter(|entry| entry.file_type().expect("entry type").is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Materialize `name` into a scratch repository and return its path.
///
/// Every committed file has its `.in` stripped; `expected.in` is the
/// specification and is not written into the tree.
fn materialize(name: &str) -> PathBuf {
    materialize_into(name, "run")
}

/// The same, into a caller-named slot.
///
/// **The slot exists because the scratch path is shared state and the runner now
/// has three consumers** (CLOUD-313). It had one, so `fixture-repos/<name>` was
/// unambiguous; a second test materializing the same fixture concurrently reads
/// a tree the first is still writing, and scores the rule as `missing` over a
/// file that is not there yet. Measured while landing the scoring runner: green
/// alone, red beside its sibling. Process-per-test does not fix it — nextest
/// isolates processes and they still share a filesystem path — so the slot is
/// part of the address rather than something a runner setting can paper over.
fn materialize_into(name: &str, slot: &str) -> PathBuf {
    let source = corpus_root().join(name);
    let dir = common::scratch(&format!("fixture-repos/{slot}/{name}"));
    for entry in fs::read_dir(&source).expect("read a fixture directory") {
        let entry = entry.expect("read a fixture entry");
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name == EXPECTED_FILE {
            continue;
        }
        let stripped = file_name.strip_suffix(INERT_SUFFIX).unwrap_or_else(|| {
            panic!("{name}: corpus file {file_name} is missing the {INERT_SUFFIX} suffix")
        });
        let contents = fs::read_to_string(entry.path()).expect("read a fixture file");
        common::write(&dir, stripped, &contents);
    }
    dir
}

/// The expectation `name` commits.
fn expectation(name: &str) -> Expectation {
    let path = corpus_root().join(name).join(EXPECTED_FILE);
    let text = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("{name}: no {EXPECTED_FILE} — a fixture without one is an error, never a skip")
    });
    parse_expectation(&text, name)
}

/// The comparison, as a pure function so it can be negatively self-tested.
///
/// Returns the mismatches it found; empty means the run matched.
fn mismatches(
    expected: &Expectation,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    if code != Some(expected.exit) {
        problems.push(format!("exit {code:?}, expected {}", expected.exit));
    }
    if stdout != expected.stdout {
        problems.push(format!("stdout {stdout:?}, expected {:?}", expected.stdout));
    }
    for needle in &expected.stderr_contains {
        if !stderr.contains(needle.as_str()) {
            problems.push(format!("stderr does not contain {needle:?}"));
        }
    }
    problems
}

/// Run one fixture's pinned argv against its materialized tree.
fn run_fixture(dir: &Path, expected: &Expectation) -> (Option<i32>, String, String) {
    let args: Vec<&str> = expected.argv.iter().map(String::as_str).collect();
    let output = common::run(dir, &args);
    (
        output.status.code(),
        common::stdout(&output),
        common::stderr(&output),
    )
}

// --- rule-case scoring (CLOUD-313) -------------------------------------------
//
// A `[[rule]]` row is a classifier with TWO failure modes and `expected.in`
// observes one. It pins the whole of stdout, so a rule that stops firing changes
// those bytes and the fixture fails — but it fails as a stdout diff, which names
// the fixture and not the rule, and it says nothing at all about a rule that
// fires on a line nobody meant it to. The four instances in `batten.toml`'s own
// history are all that untested half: a comment narrating a banned command,
// literals dropped because they fired on ordinary prose, a leading quote carried
// purely to suppress a false positive, and a self-match hazard nothing pins.
// Measured (CLOUD-310): of 40 lines a literal row reported across `mise-tasks/`,
// 8 were comments — 20% noise the suite could not see.
//
// So a case says what it expects, IN the case file, and scores into one of four
// outcomes. The marker declares the line that FOLLOWS it, which is `#MUTANT`'s
// shape for the same reason: one authority, adjacent to its subject, with no
// second file to keep in agreement.

/// The marker a case file carries, declaring what the next line expects.
///
/// Naming a rule id is safe by the convention already in force — a rule id does
/// not name its own literals, precisely because a finding's `path:line rule-id`
/// output lands in a fixture inside the rule's own glob. That convention had
/// nothing pinning it until `a_marker_naming_a_rule_does_not_trip_it` below.
const CASE_MARKER: &str = "batten-case: ";

/// What a marked line claims about one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polarity {
    /// The line violates the rule, so the rule must report it.
    Violating,
    /// The line is clean, so the rule must ignore it.
    Clean,
}

/// How a case turned out. Two of the four are failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A violating case was flagged.
    Reported,
    /// A clean case was ignored.
    Validated,
    /// A clean case was flagged — a false positive.
    Noisy,
    /// A violating case was not flagged — a false negative.
    Missing,
}

impl Outcome {
    /// The token the runner prints, and the name a failure is reported under.
    const fn as_str(self) -> &'static str {
        match self {
            Outcome::Reported => "reported",
            Outcome::Validated => "validated",
            Outcome::Noisy => "noisy",
            Outcome::Missing => "missing",
        }
    }

    /// Whether this outcome fails the suite.
    const fn is_failure(self) -> bool {
        matches!(self, Outcome::Noisy | Outcome::Missing)
    }
}

/// One declared case: a rule, a pointer, and what the pointer claims.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Case {
    rule: String,
    path: String,
    line: usize,
    polarity: Polarity,
}

impl Case {
    /// The pointer a failure is reported under — `path:line rule-id`, the same
    /// shape a finding takes, and never the matched bytes (rule 4).
    fn pointer(&self) -> String {
        format!("{}:{} {}", self.path, self.line, self.rule)
    }
}

/// Every case a fixture's committed files declare.
///
/// Read from the CORPUS rather than the materialized tree, so the marker's line
/// numbering is the one a reader sees in the committed file — materialization
/// only strips a suffix from the name, never a line from the body, so the two
/// agree, and reading the source keeps that assumption visible.
fn cases_in(name: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut files: Vec<PathBuf> = fs::read_dir(corpus_root().join(name))
        .expect("read a fixture directory")
        .map(|entry| entry.expect("read a fixture entry").path())
        .collect();
    files.sort();
    for file in files {
        let file_name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if file_name == EXPECTED_FILE {
            continue;
        }
        let Some(stripped) = file_name.strip_suffix(INERT_SUFFIX) else {
            continue;
        };
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let Some((_, declared)) = line.split_once(CASE_MARKER) else {
                continue;
            };
            let mut fields = declared.split_whitespace();
            let rule = fields
                .next()
                .unwrap_or_else(|| panic!("{name}/{file_name}: a case marker names no rule"));
            let polarity = match fields.next() {
                Some("violating") => Polarity::Violating,
                Some("clean") => Polarity::Clean,
                other => panic!(
                    "{name}/{file_name}: a case marker's outcome is `violating` or `clean`, got {other:?}"
                ),
            };
            cases.push(Case {
                rule: rule.to_owned(),
                path: stripped.to_owned(),
                // The marker declares the line that FOLLOWS it. `enumerate` is
                // 0-based and findings are 1-based, so the next line is
                // `index + 2`.
                line: index + 2,
                polarity,
            });
        }
    }
    cases
}

/// The `path:line rule-id` pointers a run reported.
///
/// Parsed rather than matched as a substring: a case is scored on whether the
/// rule fired at THAT pointer, and a `contains` check would let a finding on one
/// line satisfy a case about another.
fn reported_pointers(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.trim().to_owned())
        .collect()
}

/// Score one case against what the run reported.
///
/// A pure function so it can be negatively self-tested, exactly as `mismatches`
/// is: a scorer nothing exercises in both directions is the status quo with more
/// code.
fn score(case: &Case, reported: &[String]) -> Outcome {
    let flagged = reported.iter().any(|line| line == &case.pointer());
    match (case.polarity, flagged) {
        (Polarity::Violating, true) => Outcome::Reported,
        (Polarity::Violating, false) => Outcome::Missing,
        (Polarity::Clean, false) => Outcome::Validated,
        (Polarity::Clean, true) => Outcome::Noisy,
    }
}

#[test]
fn every_declared_case_scores_reported_or_validated() {
    // The runner CLOUD-313 asks for. `expected.in` keeps pinning the whole of
    // stdout; this says, per line, which rule was meant to fire there and which
    // was meant to stay quiet — so a false positive fails by name as `noisy` and
    // a false negative as `missing`, rather than as a diff a reader has to
    // interpret.
    let mut failures: Vec<String> = Vec::new();
    let mut scored = 0usize;
    for name in fixture_names() {
        let cases = cases_in(&name);
        if cases.is_empty() {
            continue;
        }
        let expected = expectation(&name);
        let dir = materialize_into(&name, "cases");
        let (_, stdout, _) = run_fixture(&dir, &expected);
        let reported = reported_pointers(&stdout);
        for case in cases {
            scored += 1;
            let outcome = score(&case, &reported);
            if outcome.is_failure() {
                // Pointer-only: the case's own `path:line rule-id` and the
                // outcome token. Never the matched bytes — a false-positive
                // report whose subject is a matched literal is exactly where a
                // checker leaks what it was scanning.
                failures.push(format!("{name}/{} {}", case.pointer(), outcome.as_str()));
            }
        }
    }
    assert!(
        scored > 0,
        "no fixture declares a case — this test would pass vacuously"
    );
    assert!(
        failures.is_empty(),
        "{} of {scored} case(s) failed: {}",
        failures.len(),
        failures.join("; ")
    );
}

#[test]
fn the_scorer_names_a_false_positive_and_a_false_negative() {
    // The negative self-test, in both directions, because a scorer that only
    // ever returned the two passing outcomes would satisfy the case above over
    // any behaviour at all.
    let clean = Case {
        rule: "no-timeout".to_owned(),
        path: "run.sh".to_owned(),
        line: 1,
        polarity: Polarity::Clean,
    };
    let violating = Case {
        polarity: Polarity::Violating,
        ..clean.clone()
    };
    let flagged = vec![clean.pointer()];

    assert_eq!(score(&clean, &[]), Outcome::Validated);
    assert_eq!(score(&violating, &flagged), Outcome::Reported);
    assert_eq!(
        score(&clean, &flagged),
        Outcome::Noisy,
        "a clean line the rule flagged is a false positive"
    );
    assert_eq!(
        score(&violating, &[]),
        Outcome::Missing,
        "a violating line the rule missed is a false negative"
    );
    assert!(Outcome::Noisy.is_failure() && Outcome::Missing.is_failure());
    assert!(!Outcome::Reported.is_failure() && !Outcome::Validated.is_failure());

    // A finding on a DIFFERENT line must not satisfy a case: the pointer is
    // compared whole, so a rule firing one line off reads as both `missing` here
    // and `noisy` there rather than as a pass.
    let elsewhere = Case { line: 2, ..clean };
    assert_eq!(score(&elsewhere, &flagged), Outcome::Validated);
}

#[test]
fn a_marker_naming_a_rule_does_not_trip_it() {
    // The self-match hazard, which was a convention with nothing behind it: rule
    // ids deliberately do not name their own literals, because a finding's
    // pointer output lands in a fixture inside the rule's own glob. A marker
    // names a rule id, so if a later id reintroduced the self-match, every case
    // file carrying that marker would start reporting itself.
    //
    // Asserted over the corpus rather than argued: no declared case's own marker
    // line is reported by the rule it names.
    for name in fixture_names() {
        let cases = cases_in(&name);
        if cases.is_empty() {
            continue;
        }
        let expected = expectation(&name);
        let dir = materialize_into(&name, "self-match");
        let (_, stdout, _) = run_fixture(&dir, &expected);
        let reported = reported_pointers(&stdout);
        for case in cases {
            let marker_line = case.line - 1;
            let marker_pointer = format!("{}:{marker_line} {}", case.path, case.rule);
            assert!(
                !reported.contains(&marker_pointer),
                "{name}: the marker declaring {} is reported by the rule it names",
                case.pointer()
            );
        }
    }
}

// --- (a) discovery is non-empty AND exact ------------------------------------

#[test]
fn every_fixture_directory_is_a_fixture() {
    // Exactness, not merely non-emptiness: the count of *drivable* fixtures must
    // equal the count of directories under the root, so a fixture whose
    // `expected` is missing or misnamed fails here rather than vanishing from
    // the run. A driver that skipped it would be green over a corpus it never
    // exercised.
    let names = fixture_names();
    assert!(
        !names.is_empty(),
        "the corpus is empty — this suite would pass vacuously"
    );
    for name in &names {
        // Panics with the fixture's name if the expectation is absent.
        let _ = expectation(name);
    }
}

// --- (b) the comparison is negatively self-tested ----------------------------

#[test]
fn a_wrong_expectation_is_reported_as_a_mismatch() {
    // Held in memory rather than committed: proving the comparator discriminates
    // must not require a permanently red fixture on disk.
    let expected = Expectation {
        argv: vec!["check".to_owned()],
        exit: 0,
        stdout: "nothing\n".to_owned(),
        stderr_contains: vec!["absent".to_owned()],
    };
    assert_eq!(
        mismatches(&expected, Some(0), "nothing\n", "absent").len(),
        0,
        "a matching run must report no mismatch"
    );
    assert_eq!(
        mismatches(&expected, Some(2), "something else\n", "").len(),
        3,
        "a wrong exit code, wrong stdout and missing stderr must each be reported"
    );
}

// --- (c) one fixture per rule kind -------------------------------------------

#[test]
fn the_corpus_covers_every_rule_kind() {
    // A presence predicate over the engine's own table, which `forbid` cannot
    // express: the domain is `RuleKind::ALL`, not the repository's files. Same
    // discipline as `rules.rs`'s `all_covers_every_kind`.
    let mut covered: Vec<RuleKind> = Vec::new();
    for name in fixture_names() {
        let text = fs::read_to_string(corpus_root().join(&name).join("batten.toml.in"))
            .unwrap_or_else(|_| panic!("{name}: no batten.toml.in"));
        // A fixture may deliberately carry a config the loader refuses (the
        // exit-1 case); it contributes no kind rather than failing here.
        let Ok(config) = toml::from_str::<Config>(&text) else {
            continue;
        };
        for rule in &config.rules {
            if !covered.contains(&rule.kind) {
                covered.push(rule.kind);
            }
            if rule.kind.carries_ambient_authority() {
                // §3: a spawning kind runs under `enforce`; `check` refuses it.
                assert_eq!(
                    expectation(&name).argv.first().map(String::as_str),
                    Some("enforce"),
                    "{name}: a spawning rule kind must be driven by enforce"
                );
            }
        }
    }
    for kind in RuleKind::ALL {
        assert!(
            covered.contains(kind),
            "no fixture exercises the {kind:?} rule kind"
        );
    }
}

// --- (d) every fixture matches, twice ----------------------------------------

#[test]
fn every_fixture_matches_its_expectation_and_is_byte_stable() {
    for name in fixture_names() {
        let expected = expectation(&name);
        let dir = materialize(&name);

        let (code, stdout, stderr) = run_fixture(&dir, &expected);
        let problems = mismatches(&expected, code, &stdout, &stderr);
        assert!(problems.is_empty(), "{name}: {}", problems.join("; "));

        // Byte-stability over the whole corpus, generalizing the single case
        // `cli.rs` pins: identical input, identical bytes (§6).
        let (_, again, _) = run_fixture(&dir, &expected);
        assert_eq!(stdout, again, "{name}: stdout was not byte-stable");
    }
}

// --- (e) inertness -----------------------------------------------------------

#[test]
fn every_committed_corpus_file_is_inert() {
    // The `.in` suffix is what lets a fixture carry a shape this repo's own
    // gates refuse. A file committed without it would be linted, formatted, or
    // scanned as if it were source.
    for name in fixture_names() {
        for entry in fs::read_dir(corpus_root().join(&name)).expect("read a fixture directory") {
            let file_name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(
                file_name.ends_with(INERT_SUFFIX),
                "{name}/{file_name} is committed without the {INERT_SUFFIX} suffix"
            );
        }
    }
}
