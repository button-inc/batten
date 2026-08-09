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

mod common;

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
    let source = corpus_root().join(name);
    let dir = common::scratch(&format!("fixture-repos/{name}"));
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
            if rule.kind.spawns_processes() {
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
