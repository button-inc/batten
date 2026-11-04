//! Replay each modified test's BASE form against HEAD (CLOUD-2090).
//!
//! # Why config lint is not enough
//!
//! `config lint --config-from <base>` sees a weakening only where it is
//! configuration. A test whose expectation was loosened is code: measured in
//! #1056, `this_repository_is_healthy` came to exclude a check while GAINING
//! assertions, so a count of asserts reads it as a strengthening. The base test
//! run against HEAD's code does not: it asserts what the base asserted, and a
//! HEAD that no longer satisfies it has changed what "passing" means.
//!
//! # What this decides, and what it does not
//!
//! - A `#[test]` fn present at both revisions whose body changed (whitespace
//!   aside) is **modified**; its base body is spliced into HEAD's tree and run.
//!   A base body that fails, or a spliced tree that will not build, is
//!   `test-expectation-changed`. A replay that could not run at all is
//!   could-not-look, never a finding.
//! - A `#[test]` fn present at base and gone at HEAD is `test-removed`, with no
//!   replay: there is nothing at HEAD to run it beside.
//! - An ADDED test is never replayed — it has no base expectation to hold HEAD to.
//!
//! **The bound, stated:** only `#[test]` bodies are compared. A helper whose body
//! changed under an unchanged test is not replayed; the test's own run at HEAD
//! is what covers it.
//!
//! Each finding is a pointer (rule 4): the test's key and a token. It is admitted
//! only through the `asked` ledger, the one route `config lint` uses, so one
//! landing puts every changed expectation to the owner in one recorded question.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::exit::ExitCode;
// THE IDS ARE THE ENGINE'S ONE SMELL VOCABULARY, never literals here
// (CLOUD-2379). Two `&'static str` constants used to live in this module, and
// `policy explain` could resolve neither — so a refused lap named a finding
// nothing explained. `SmellId::definition` is exhaustive, which is what makes
// that unreachable rather than merely fixed.
use crate::lint::SmellId;

/// One `#[test]` fn: where it is, and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFn {
    /// `<module path inside the file>::<name>`, e.g. `tests::a_case`.
    pub inner: String,
    /// The 1-based line of the fn's name.
    pub line: usize,
    /// The body's byte range in its file, braces included.
    pub body: (usize, usize),
}

/// One modified test: its base body, and where its head body sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modified {
    /// `<module path inside the file>::<name>`.
    pub inner: String,
    /// The base revision's body text, braces included.
    pub base_body: String,
    /// The head body's byte range in the head file.
    pub head_body: (usize, usize),
    /// The 1-based line of the fn's name at head.
    pub line: usize,
}

/// What a diff did to the tests of one file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changed {
    /// Present at both revisions with a different body.
    pub modified: Vec<Modified>,
    /// Present at base, absent at head: `(inner, base line)`.
    pub removed: Vec<(String, usize)>,
}

/// Every `#[test]` fn in `source`, or `None` when it is not Rust.
#[must_use]
pub fn tests_in(source: &str) -> Option<Vec<TestFn>> {
    let file = crate::source::rust(source).ok()?;
    let starts = line_starts(source);
    let mut found = Vec::new();
    collect(&file.items, &mut Vec::new(), source, &starts, &mut found);
    Some(found)
}

fn collect(
    items: &[syn::Item],
    path: &mut Vec<String>,
    source: &str,
    starts: &[usize],
    found: &mut Vec<TestFn>,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) if is_test(&function.attrs) => {
                let open = function.block.brace_token.span.open().start();
                let close = function.block.brace_token.span.close().end();
                if let (Some(from), Some(to)) =
                    (offset(source, starts, open), offset(source, starts, close))
                {
                    let mut inner = path.clone();
                    inner.push(function.sig.ident.to_string());
                    found.push(TestFn {
                        inner: inner.join("::"),
                        line: function.sig.ident.span().start().line,
                        body: (from, to),
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    path.push(module.ident.to_string());
                    collect(nested, path, source, starts, found);
                    path.pop();
                }
            }
            _ => {}
        }
    }
}

/// `#[test]`, or a test macro spelled with a path ending in `test`
/// (`#[tokio::test]`).
fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

/// The byte offset of each line's first byte.
fn line_starts(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(source.match_indices('\n').map(|(at, _)| at + 1))
        .collect()
}

/// A `proc-macro2` position (1-based line, 0-based char column) as a byte offset.
fn offset(source: &str, starts: &[usize], at: proc_macro2::LineColumn) -> Option<usize> {
    let start = *starts.get(at.line.checked_sub(1)?)?;
    let rest = source.get(start..)?;
    Some(
        start
            + rest
                .char_indices()
                .nth(at.column)
                .map_or(rest.len(), |(byte, _)| byte),
    )
}

/// The body text with every whitespace character removed, so a reformat is not a
/// modification.
fn shape(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether a body changed beyond its whitespace.
fn differs(base: &str, head: &str) -> bool {
    shape(base) != shape(head)
}

/// What changed between a file's base and head text.
#[must_use]
//MUTANT-SUITE crates/batten/src/replay.rs
//MUTANT modified-unseen|s@^    shape(base) != shape(head)$@    false@|a_changed_body_is_modified_and_formatting_is_not
pub fn compare(base: &str, head: &str) -> Changed {
    let index = |source: &str| -> BTreeMap<String, TestFn> {
        tests_in(source)
            .unwrap_or_default()
            .into_iter()
            .map(|test| (test.inner.clone(), test))
            .collect()
    };
    let (before, after) = (index(base), index(head));
    let mut changed = Changed::default();
    for (inner, old) in &before {
        let base_body = &base[old.body.0..old.body.1];
        match after.get(inner) {
            Some(new) if differs(base_body, &head[new.body.0..new.body.1]) => {
                changed.modified.push(Modified {
                    inner: inner.clone(),
                    base_body: base_body.to_owned(),
                    head_body: new.body,
                    line: new.line,
                });
            }
            Some(_) => {}
            None => changed.removed.push((inner.clone(), old.line)),
        }
    }
    changed
}

/// `head` with each modified test's base body spliced in, applied from the last
/// range back so earlier offsets stay valid.
#[must_use]
pub fn splice(head: &str, modified: &[Modified]) -> String {
    let mut edits: Vec<&Modified> = modified.iter().collect();
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.head_body.0));
    let mut out = head.to_owned();
    for edit in edits {
        out.replace_range(edit.head_body.0..edit.head_body.1, &edit.base_body);
    }
    out
}

/// Where each spliced base body sits in [`splice`]'s output, as 1-indexed
/// inclusive line ranges, so a rustc location can be charged to the body that
/// holds it. A body's start moves by what every earlier splice added or removed.
#[must_use]
pub fn spliced_lines<'a>(head: &str, modified: &'a [Modified]) -> Vec<(&'a str, usize, usize)> {
    let mut ordered: Vec<&Modified> = modified.iter().collect();
    ordered.sort_by_key(|edit| edit.head_body.0);
    let spliced = splice(head, modified);
    let mut shift: isize = 0;
    let mut spans = Vec::new();
    for edit in ordered {
        let start = edit.head_body.0.saturating_add_signed(shift);
        let first = spliced
            .get(..start)
            .map_or(1, |before| before.matches('\n').count() + 1);
        let last = first + edit.base_body.matches('\n').count();
        spans.push((edit.inner.as_str(), first, last));
        let head_len = edit.head_body.1 - edit.head_body.0;
        shift += isize::try_from(edit.base_body.len()).unwrap_or(isize::MAX)
            - isize::try_from(head_len).unwrap_or(isize::MAX);
    }
    spans
}

/// The `path:line` locations rustc printed (`--> path:line:col`), relative to
/// the tree it built in.
fn compile_errors(output: &str) -> Vec<(String, usize)> {
    output
        .lines()
        .filter_map(|line| {
            let at = line.trim_start().strip_prefix("--> ")?;
            let mut parts = at.rsplitn(3, ':');
            let _column = parts.next()?;
            let line_no = parts.next()?.parse().ok()?;
            Some((parts.next()?.to_owned(), line_no))
        })
        .collect()
}

/// Every `.rs` blob at `rev`, by path.
fn rust_files(root: &Path, rev: &str) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    crate::git::for_each_blob_at_rev(root, rev, "**/*.rs", |path, text| {
        files.insert(path.to_owned(), text.to_owned());
    })?;
    Ok(files)
}

/// One finding: the test's `<path>::<inner>` key, its line, and the token.
#[derive(serde::Serialize)]
struct Finding {
    key: String,
    path: String,
    line: usize,
    id: SmellId,
}

/// One rendered finding: the finding and how the `asked` ledger answered it.
#[derive(serde::Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    admission: &'static str,
}

/// `batten test replay --base <ref>`: run each modified test's base form against
/// HEAD, and admit what changed only through the `asked` ledger.
///
/// Exit 0 when every finding is admitted (or there is none), 2 when one is not.
/// With `json`, the findings are one document, emitted even when it is empty.
///
/// # Errors
///
/// A base that does not resolve, a tree that cannot be materialised, or a
/// ledger that cannot be read — each could-not-look rather than a pass.
pub fn run(root: &Path, base: &str, json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let fork = crate::git::merge_base(root, base)?.unwrap_or_else(|| base.to_owned());
    let before = rust_files(root, &fork)?;
    let after = rust_files(root, "HEAD")?;

    let mut findings = Vec::new();
    // The head text each modified file is spliced from, by path.
    let mut splices: BTreeMap<String, (String, Vec<Modified>)> = BTreeMap::new();
    for (path, base_text) in &before {
        let Some(head_text) = after.get(path) else {
            continue;
        };
        if head_text == base_text {
            continue;
        }
        let changed = compare(base_text, head_text);
        for (inner, line) in changed.removed {
            findings.push(Finding {
                key: format!("{path}::{inner}"),
                path: path.clone(),
                line,
                id: SmellId::TestRemoved,
            });
        }
        if !changed.modified.is_empty() {
            splices.insert(path.clone(), (head_text.clone(), changed.modified));
        }
    }

    if !splices.is_empty() {
        findings.extend(replay(root, &splices)?);
    }

    let smells: Vec<crate::lint::Smell> = findings
        .iter()
        .map(|finding| crate::lint::Smell {
            at: crate::lint::Where::Key(finding.key.clone()),
            id: finding.id,
        })
        .collect();
    let ledger = crate::asked::added_since(root, base)?;
    let admitted = crate::lint::admissions(&smells, &ledger);
    let rows: Vec<Row<'_>> = findings
        .iter()
        .zip(&admitted)
        .map(|(finding, (_, admission))| Row {
            finding,
            admission: admission.as_str(),
        })
        .collect();
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)?;
    } else {
        for row in &rows {
            let Finding {
                path,
                line,
                id,
                key,
            } = row.finding;
            writeln!(out, "{path}:{line} {id} {key} ({})", row.admission)?;
        }
    }
    let refused = admitted
        .iter()
        .filter(|(_, admission)| admission.is_refused())
        .count();
    Ok(if refused == 0 {
        ExitCode::Success
    } else {
        ExitCode::Violation
    })
}

//MUTANT replay-target-outside-the-checkout|s@^    let target = root.join("target").join("replay");$@    let target = state.join("target");@|a_replay_builds_where_the_prune_can_reach_it
/// Materialise HEAD under the repository's state directory, splice each base
/// body in, and run each modified test there. A test that fails, or a tree that
/// will not build, is `test-expectation-changed`.
///
/// **Outside the checkout**, CLOUD-2096's lesson: a tree or a build cache inside
/// the repository is walked by its own scans. The target directory persists, so a
/// later lap builds warm.
fn replay(
    root: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
) -> Result<Vec<Finding>> {
    let state = crate::state::repo_state_dir(root)?.join("replay");
    let tree = state.join("tree");
    if tree.exists() {
        std::fs::remove_dir_all(&tree)
            .with_context(|| format!("test replay: clear {}", tree.display()))?;
    }
    crate::git::materialize_rev(root, "HEAD", &tree)?;
    // THE BUILD LIVES UNDER THE CHECKOUT'S `target/`, THE TREE OUTSIDE IT (CLOUD-2196).
    // CLOUD-2096 moved the tree out because a checkout's scans walk it; the build
    // cache went with it, and there no reclaim could reach it: measured on #1132,
    // 5308 MB under the state directory while every lap closed below the warm
    // floor and ran the volume out. `target/replay` is a nested build tree the
    // prune derives, exactly as `mutate`'s `target/mutate` is.
    let target = root.join("target").join("replay");
    let retired = state.join("target");
    if retired.exists() {
        std::fs::remove_dir_all(&retired)
            .with_context(|| format!("test replay: retire {}", retired.display()))?;
    }
    let published = [(
        String::from("CARGO_TARGET_DIR"),
        Some(target.to_string_lossy().into_owned()),
    )];
    // THE TOOL IS PROBED BEFORE ANY ANSWER IS READ. `cargo` exits 101 both for a
    // build that failed and for a subcommand it cannot find, so without this a
    // missing `nextest` reads as every base expectation broken — measured on the
    // musl lane, where the refusing cases passed while running nothing.
    let probe = ["cargo", "nextest", "--version"].map(String::from);
    match crate::exec::piped_argv(
        &tree,
        &probe,
        "",
        crate::exec::Diagnostics::Keep,
        &published,
    ) {
        Some((0, _)) => {}
        outcome => bail!(
            "test replay: could not run `cargo nextest` in {}: {}",
            tree.display(),
            said(outcome.as_ref())
        ),
    }
    // ONE RUN, EVERY MODIFIED TEST (CLOUD-2090). A call per test rebuilt the
    // spliced tree before each one, because a replayed case that spawns cargo
    // leaves the shared target dir's fingerprints moved; measured 2026-10-10,
    // 159 modified tests ran past a two-hour bound. One union filter builds once
    // and each test is judged off its own result lines, so the verdicts are the
    // ones the per-test calls gave.
    //
    // A BODY THAT WILL NOT COMPILE IS CHARGED TO ITSELF, NEVER TO THE UNION.
    // One base body HEAD's code cannot compile used to fail the shared build and
    // so every modified test with it: measured on #1132, a body that only GAINED
    // an assertion read as an expectation change because another file's base
    // body named a removed helper. rustc's `--> path:line` locations are charged
    // to the spliced bodies that hold them; those alone are findings, and the
    // rest are rebuilt without them. An error no body holds keeps the old,
    // conservative answer: every remaining test is a finding.
    judge(&tree, splices, &|still| run_union(&tree, still, &published))
}

/// One union run over the splices still standing: its exit code and output.
type UnionRun<'a> = &'a dyn Fn(&BTreeMap<String, (String, Vec<Modified>)>) -> Option<(i32, String)>;

/// Splice, run and charge until every modified test in `splices` is judged,
/// each union run asked of `run` ([`run_union`] in every caller but the suite).
///
/// **THE SEAM THE CHARGING LOOP IS TESTED THROUGH.** A body that will not compile
/// is charged to itself and the rest rebuilt without it — a sequence of runs a
/// real `nextest` produces only over a real broken body, and a run handed in
/// produces on demand.
fn judge(
    tree: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    run: UnionRun<'_>,
) -> Result<Vec<Finding>> {
    let mut splices = splices.clone();
    let mut findings = Vec::new();
    loop {
        for (path, (head_text, modified)) in &splices {
            crate::durable::replace(tree.join(path), splice(head_text, modified))
                .with_context(|| format!("test replay: splice {path}"))?;
        }
        if splices.values().all(|(_, modified)| modified.is_empty()) {
            return Ok(findings);
        }
        let outcome = run(&splices);
        if let Some((code, output)) = outcome.as_ref()
            && *code == BUILD_FAILED
            && output.contains(COMPILE_FAILED)
        {
            let charged = charge(&splices, &compile_errors(output));
            if !charged.is_empty() {
                for (path, inner) in charged {
                    if let Some((_, modified)) = splices.get_mut(&path)
                        && let Some(at) = modified.iter().position(|test| test.inner == inner)
                    {
                        let test = modified.remove(at);
                        findings.push(Finding {
                            key: format!("{path}::{}", test.inner),
                            path: path.clone(),
                            line: test.line,
                            id: SmellId::TestExpectationChanged,
                        });
                    }
                }
                continue;
            }
        }
        for (path, (_, modified)) in &splices {
            for test in modified {
                if !passes(outcome.as_ref(), &test.inner)? {
                    findings.push(Finding {
                        key: format!("{path}::{}", test.inner),
                        path: path.clone(),
                        line: test.line,
                        id: SmellId::TestExpectationChanged,
                    });
                }
            }
        }
        return Ok(findings);
    }
}

/// Run every still-spliced test in one `nextest` call: its outcome, or `None`
/// when it could not be spawned.
fn run_union(
    tree: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    published: &[(String, Option<String>)],
) -> Option<(i32, String)> {
    let tests: Vec<&str> = splices
        .values()
        .flat_map(|(_, modified)| modified.iter().map(|test| test.inner.as_str()))
        .collect();
    let filter = tests
        .iter()
        .map(|inner| format!("test(/(^|::){inner}$/)"))
        .collect::<Vec<_>>()
        .join(" | ");
    let argv: Vec<String> = [
        "cargo",
        "nextest",
        "run",
        "--workspace",
        "--no-fail-fast",
        "--no-tests=fail",
        "--color",
        "never",
        "-E",
        &filter,
    ]
    .iter()
    .map(|word| (*word).to_owned())
    .collect();
    // `piped_argv` because it runs the child IN `tree`: `run_in_env`'s root
    // names only where a capture is stored, and the child inherits this
    // process's directory — the checkout, whose HEAD test passes.
    crate::exec::piped_argv(tree, &argv, "", crate::exec::Diagnostics::Keep, published)
}

/// The spliced bodies that hold a compile error's location, as `(path, inner)`.
fn charge(
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    errors: &[(String, usize)],
) -> std::collections::BTreeSet<(String, String)> {
    let mut charged = std::collections::BTreeSet::new();
    for (path, (head_text, modified)) in splices {
        for (inner, first, last) in spliced_lines(head_text, modified) {
            if errors
                .iter()
                .any(|(at, line)| at == path && (first..=last).contains(line))
            {
                charged.insert((path.clone(), inner.to_owned()));
            }
        }
    }
    charged
}

/// `nextest`'s exit when a test it ran failed.
const TEST_RUN_FAILED: i32 = 100;
/// `nextest`'s exit when the build failed. `cargo` uses it for its own setup
/// failures too, so it is a finding only beside [`COMPILE_FAILED`].
const BUILD_FAILED: i32 = 101;
/// The result words `nextest` ends a test's first attempt with: exactly what
/// cargo-nextest 0.9.104's `nextest-runner/src/reporter/displayer/imp.rs`
/// `status_str` returns, the `SIG` names being `helpers.rs` `signal_str`'s.
/// A signal `signal_str` cannot name prints `ABORT SIG <n>` ([`unnamed`]), and
/// `ABORT` alone is Windows'. `SLOW`, `START`, `SKIP`, `TERMINATING` and `SETUP …`
/// lines name a case or a script too and decide nothing, so are not here.
const TERMINAL: &[&str] = &[
    "PASS",
    "LEAK",
    "FAIL",
    "FAIL + LEAK",
    "XFAIL",
    "LEAK-FAIL",
    "TIMEOUT",
    "ABORT",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGFPE",
    "SIGKILL",
    "SIGSEGV",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
];
/// The words after a `TRY <n> ` prefix: exactly what the same file's
/// `short_status_str` returns, a signal by its bare `signal_str` name and an
/// unnamed one as `SIG <n>`.
const RETRIED: &[&str] = &[
    "PASS", "LEAK", "FAIL", "XFAIL", "LKFAIL", "TMT", "ABORT", "HUP", "INT", "QUIT", "ILL", "TRAP",
    "ABRT", "FPE", "KILL", "SEGV", "PIPE", "ALRM", "TERM",
];
/// The result words that are a pass: `LEAK` is one that leaked handles.
const PASSED: &[&str] = &["PASS", "LEAK"];

/// Whether `word` is `prefix` then a signal number.
fn unnamed(word: &str, prefix: &str) -> bool {
    word.strip_prefix(prefix)
        .is_some_and(|number| number.parse::<i32>().is_ok())
}

/// One attempt's result line as `(result, case)`: a result word, bare or after
/// a `TRY <n> ` retry prefix (which `result` drops), then the bracketed duration
/// and the case. Anchored on the whole text before the first `[`, so only a
/// word nextest prints, in the place it prints it, reads as a result.
pub(crate) fn attempt(line: &str) -> Option<(&str, &str)> {
    let (word, rest) = line.split_once('[')?;
    let (_, case) = rest.split_once(']')?;
    let (word, case) = (word.trim(), case.trim());
    let result = match word.strip_prefix("TRY ") {
        Some(retried) => {
            let (number, result) = retried.split_once(' ')?;
            number.parse::<u32>().ok()?;
            (RETRIED.contains(&result) || unnamed(result, "SIG ")).then_some(result)?
        }
        None => (TERMINAL.contains(&word) || unnamed(word, "ABORT SIG ")).then_some(word)?,
    };
    (!case.is_empty()).then_some((result, case))
}

/// Whether `line` is nextest's run summary. Past it nextest repeats each
/// failure, so no attempt is read after it; a run printed it when it ran at all.
pub(crate) fn summary(line: &str) -> bool {
    line.trim_start().starts_with("Summary [")
}

/// Every attempt a nextest run reported, up to its summary.
pub(crate) fn attempts(output: &str) -> impl Iterator<Item = (&str, &str)> {
    output
        .lines()
        .take_while(|line| !summary(line))
        .filter_map(attempt)
}
/// What `cargo` prints when rustc refused the crate: a base body HEAD's code
/// cannot compile, as opposed to a build that never reached rustc.
const COMPILE_FAILED: &str = "could not compile";

/// Whether one test passed in the shared run.
///
/// Judged from the test's OWN attempts ([`attempts`]), so one failing case
/// never reads as another failing. Every attempt naming the test must pass, a
/// retried one included, whatever nextest's exit says of a retry that passed:
/// the repository refuses retries so that a flake never reads as a pass. A
/// rustc refusal fails
/// every test, as it failed every per-test build of the one spliced tree. A run
/// that named the test nowhere and did not fail to compile is could-not-look,
/// never a finding: a refusal the replay never measured would read as one it did.
//MUTANT-SUITE crates/batten/tests/it/test_replay.rs
//MUTANT expectation-unchecked|s@^    let failed = results.iter().any(\x7cresult\x7c !PASSED.contains(result));$@    let failed = false;@|a_narrowed_expectation_is_refused_by_name
fn passes(outcome: Option<&(i32, String)>, test: &str) -> Result<bool> {
    let Some((code, output)) = outcome else {
        bail!("test replay: could not replay {test}: {}", said(outcome));
    };
    if *code == BUILD_FAILED && output.contains(COMPILE_FAILED) {
        return Ok(false);
    }
    let suffix = format!("::{test}");
    let results: Vec<&str> = attempts(output)
        .filter(|(_, case)| {
            case.split_whitespace()
                .last()
                .is_some_and(|name| name == test || name.ends_with(&suffix))
        })
        .map(|(result, _)| result)
        .collect();
    if results.is_empty() {
        bail!("test replay: could not replay {test}: {}", said(outcome));
    }
    let failed = results.iter().any(|result| !PASSED.contains(result));
    if failed && *code != TEST_RUN_FAILED && *code != 0 {
        bail!("test replay: could not replay {test}: {}", said(outcome));
    }
    Ok(!failed)
}

fn said(outcome: Option<&(i32, String)>) -> String {
    let Some((code, output)) = outcome else {
        return String::from("it could not be spawned");
    };
    let lines: Vec<&str> = output.lines().collect();
    let tail = lines[lines.len().saturating_sub(8)..].join("\n");
    format!("exit {code}\n{tail}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const BASE: &str = "\
fn helper() -> u8 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn kept() {
        assert_eq!(1, 1);
    }

    #[test]
    fn narrowed() {
        assert_eq!(super::helper(), 1);
    }

    #[test]
    fn dropped() {
        assert!(true);
    }
}
";

    #[test]
    fn a_changed_body_is_modified_and_formatting_is_not() {
        let head = BASE
            .replace("assert_eq!(1, 1);", "assert_eq!( 1,1 );")
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(BASE, &head);
        let names: Vec<&str> = changed.modified.iter().map(|m| m.inner.as_str()).collect();
        assert_eq!(
            names,
            ["tests::narrowed"],
            "a reformat is not a modification"
        );
        assert!(
            changed.modified[0]
                .base_body
                .contains("assert_eq!(super::helper(), 1);")
        );
    }

    #[test]
    fn a_base_test_gone_at_head_is_removed() {
        let head = BASE.replace(
            "    #[test]\n    fn dropped() {\n        assert!(true);\n    }\n",
            "",
        );
        let changed = compare(BASE, &head);
        assert_eq!(changed.removed, vec![(String::from("tests::dropped"), 16)]);
        assert!(changed.modified.is_empty());
    }

    #[test]
    fn an_added_test_is_never_replayed() {
        let head = BASE.replace(
            "mod tests {\n",
            "mod tests {\n    #[test]\n    fn added() { assert!(false); }\n",
        );
        assert_eq!(compare(BASE, &head), Changed::default());
    }

    #[test]
    fn a_base_body_is_spliced_into_exactly_its_fn() {
        let head = BASE.replace(
            "assert_eq!(super::helper(), 1);",
            "let _ = super::helper();",
        );
        let changed = compare(BASE, &head);
        assert_eq!(splice(&head, &changed.modified), BASE);
    }

    /// A COMPILE ERROR IS CHARGED TO THE BODY THAT HOLDS IT. Two bodies change,
    /// the earlier one's splice adds lines, and an error inside the later one is
    /// charged to it alone: the span accounts for the earlier body's growth.
    #[test]
    fn a_compile_error_is_charged_to_the_spliced_body_that_holds_it() {
        let base = BASE.replace(
            "assert_eq!(1, 1);",
            "assert_eq!(1, 1);\n        assert_eq!(2, 2);\n        assert_eq!(3, 3);",
        );
        let head = base
            .replace(
                "assert_eq!(1, 1);\n        assert_eq!(2, 2);\n        assert_eq!(3, 3);",
                "assert_eq!(9, 9);",
            )
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(&base, &head);
        assert_eq!(changed.modified.len(), 2, "both bodies changed");
        let rendered = splice(&head, &changed.modified);
        let helper_line = rendered
            .lines()
            .position(|line| line.contains("super::helper(), 1"))
            .expect("the base body is spliced")
            + 1;
        let output = format!(
            "error[E0425]: cannot find function `helper`\n   --> src/x.rs:{helper_line}:24\n"
        );
        assert_eq!(
            compile_errors(&output),
            [(String::from("src/x.rs"), helper_line)]
        );
        let mut by_path = BTreeMap::new();
        by_path.insert(String::from("src/x.rs"), (head, changed.modified));
        let blamed = charge(&by_path, &compile_errors(&output));
        assert_eq!(
            blamed.into_iter().collect::<Vec<_>>(),
            [(String::from("src/x.rs"), String::from("tests::narrowed"))],
            "only the body holding the error is charged"
        );
    }

    #[test]
    fn only_a_measured_failure_is_a_finding() {
        let said = |code: i32, text: &str| Some((code, text.to_owned()));
        let pass = "        PASS [   0.010s] batten::it m::t\n";
        let fail = "        FAIL [   0.010s] batten::it m::t\n";
        assert!(passes(said(0, pass).as_ref(), "t").unwrap());
        assert!(!passes(said(100, fail).as_ref(), "t").unwrap());
        // A failure line under a clean exit is still measured, never could-not-look.
        assert!(!passes(said(0, fail).as_ref(), "t").unwrap());
        // ONE RUN JUDGES EVERY TEST: another case failing in the same run is
        // not this one failing, and a SLOW line is not a result.
        let shared = "        SLOW [> 60s] batten::it m::t\n        PASS [  61.0s] batten::it m::t\n        FAIL [   0.010s] batten::it m::other\n";
        assert!(passes(said(100, shared).as_ref(), "t").unwrap());
        assert!(!passes(said(100, shared).as_ref(), "other").unwrap());
        // A run that names the test nowhere measured nothing about it.
        assert!(passes(said(0, pass).as_ref(), "absent").is_err());
        assert!(
            !passes(
                said(101, "error: could not compile `replayed`").as_ref(),
                "t"
            )
            .unwrap()
        );
        // A build that never reached rustc, a refused filter, and a child that
        // never ran each measured nothing, so none of them is a refusal.
        assert!(passes(said(101, "error: no such command: `nextest`").as_ref(), "t").is_err());
        assert!(passes(said(4, "").as_ref(), "t").is_err());
        assert!(passes(None, "t").is_err());
    }

    /// Fails by: a word nextest's `status_str` / `short_status_str` print read
    /// as no result, a word they never print (or one in the wrong place) read
    /// as one, a `TRY` prefix kept in the result, or a line naming no case read.
    #[test]
    fn only_the_words_nextest_prints_are_results() {
        fn read(line: &str) -> Option<&str> {
            attempt(line).map(|(result, _)| result)
        }
        assert_eq!(
            attempt("        LEAK [   0.120s] batten::it m::t"),
            Some(("LEAK", "batten::it m::t"))
        );
        assert_eq!(read(" FAIL + LEAK [   0.010s] b t"), Some("FAIL + LEAK"));
        assert_eq!(read("      SIGILL [   0.010s] b t"), Some("SIGILL"));
        assert_eq!(read(" ABORT SIG 7 [   0.010s] b t"), Some("ABORT SIG 7"));
        assert_eq!(read("   TRY 2 TMT [  60.000s] b t"), Some("TMT"));
        assert_eq!(read(" TRY 3 SIG 7 [   0.010s] b t"), Some("SIG 7"));
        assert_eq!(read("  TRY 2 SEGV [   0.010s] b t"), Some("SEGV"));
        for refused in [
            "        SLOW [> 60.000s] b t",
            "  SETUP PASS [   0.010s] db-setup",
            "      SIGBUS [   0.010s] b t",
            "         TMT [   0.010s] b t",
            "TRY 2 SIGILL [   0.010s] b t",
            " TRY x FAIL [   0.010s] b t",
            " TRY 2 SIG x [   0.010s] b t",
            " ABORT SIG x [   0.010s] b t",
            "    log PASS [   0.010s] b t",
            "        PASS [   0.004s]",
            "        PASS   0.004s  b t",
        ] {
            assert_eq!(read(refused), None, "{refused}");
        }
    }

    /// Fails by: a retried attempt or a `LEAK` pass left unjudged, any failed
    /// attempt not failing the test, or a failure nextest repeats after its
    /// summary read as another attempt.
    #[test]
    fn every_attempt_up_to_the_summary_is_judged() {
        let said = |text: &str| Some((100, text.to_owned()));
        let flaked =
            "  TRY 1 FAIL [   0.010s] batten::it m::t\n  TRY 2 PASS [   0.010s] batten::it m::t\n";
        assert!(
            !passes(said(flaked).as_ref(), "t").unwrap(),
            "a flake is not a pass"
        );
        let leaked = "        LEAK [   0.120s] batten::it m::t\n";
        assert!(passes(said(leaked).as_ref(), "t").unwrap());
        let repeated = "        PASS [   0.010s] batten::it m::t\n     \
                        Summary [   0.020s] 1 test run: 1 passed\n        \
                        FAIL [   0.010s] batten::it m::t\n";
        assert!(passes(said(repeated).as_ref(), "t").unwrap());
        assert!(summary("     Summary [   0.020s] 1 test run: 1 passed"));
        assert!(!summary("        PASS [   0.010s] batten::it Summary"));
    }

    /// Fails by: a compile failure not charged, the charged body not the one
    /// removed, or the rebuild not run without it — each leaves the passing
    /// body charged too, or the charged one unjudged.
    #[test]
    fn a_body_that_will_not_compile_is_charged_and_the_rest_rebuilt_without_it() {
        let base = BASE.replace(
            "assert_eq!(1, 1);",
            "assert_eq!(1, 1);\n        assert_eq!(2, 2);",
        );
        let head = base
            .replace(
                "assert_eq!(1, 1);\n        assert_eq!(2, 2);",
                "assert_eq!(9, 9);",
            )
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(&base, &head);
        let helper_line = splice(&head, &changed.modified)
            .lines()
            .position(|line| line.contains("super::helper(), 1"))
            .expect("the base body is spliced")
            + 1;
        let tree = crate::scratch::scratch("replay-judge");
        std::fs::create_dir_all(tree.join("src")).unwrap();
        let mut splices = BTreeMap::new();
        splices.insert(String::from("src/x.rs"), (head, changed.modified));
        let runs = std::cell::Cell::new(0);
        let run = |still: &BTreeMap<String, (String, Vec<Modified>)>| {
            runs.set(runs.get() + 1);
            if runs.get() == 1 {
                return Some((
                    BUILD_FAILED,
                    format!(
                        "error[E0425]: cannot find function `helper`\n   --> src/x.rs:{helper_line}:24\n\
                         error: could not compile `x`\n"
                    ),
                ));
            }
            let left: Vec<&str> = still
                .values()
                .flat_map(|(_, modified)| modified.iter().map(|test| test.inner.as_str()))
                .collect();
            assert_eq!(
                left,
                ["tests::kept"],
                "the rebuild runs without the charged body"
            );
            Some((
                0,
                String::from("        PASS [   0.010s] batten::it tests::kept\n"),
            ))
        };
        let findings = judge(&tree, &splices, &run).unwrap();
        assert_eq!(
            findings.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(),
            ["src/x.rs::tests::narrowed"]
        );
        assert_eq!(runs.get(), 2);
    }

    #[test]
    fn a_line_starts_one_byte_past_each_newline() {
        assert_eq!(line_starts("a\nbc\n"), vec![0, 2, 5]);
    }

    /// Fails by: a spliced body's span shifted by the splices before it, or
    /// counted from zero, so a compile error is charged to the wrong body.
    #[test]
    fn each_spliced_body_spans_exactly_the_lines_it_occupies() {
        let base = BASE.replace(
            "assert_eq!(1, 1);",
            "assert_eq!(1, 1);\n        assert_eq!(2, 2);\n        assert_eq!(3, 3);",
        );
        let head = base
            .replace(
                "assert_eq!(1, 1);\n        assert_eq!(2, 2);\n        assert_eq!(3, 3);",
                "assert_eq!(9, 9);",
            )
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(&base, &head);
        let rendered = splice(&head, &changed.modified);
        let spans = spliced_lines(&head, &changed.modified);
        assert_eq!(spans.len(), 2);
        for (inner, first, last) in spans {
            let body = &changed
                .modified
                .iter()
                .find(|edit| edit.inner == inner)
                .expect("a span names a modified body")
                .base_body;
            let at = rendered.find(body.as_str()).expect("the body is spliced");
            let expected = rendered[..at].matches('\n').count() + 1;
            assert_eq!(
                (first, last),
                (expected, expected + body.matches('\n').count()),
                "{inner}"
            );
        }
    }

    #[test]
    fn what_a_run_said_is_its_exit_and_its_tail() {
        assert_eq!(said(None), "it could not be spawned");
        let long = (1..=10)
            .map(|n| format!("line {n}\n"))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(
            said(Some(&(3, long))),
            "exit 3\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10"
        );
    }
}
