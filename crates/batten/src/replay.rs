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
//!
//! # Crash-only, test by test
//!
//! The replay used to be all-or-nothing: it rematerialised HEAD on every run and
//! judged every modified test in one union run with no per-test record, so a
//! stopped lap kept nothing. Now each modified test's verdict — passed,
//! expectation changed, or charged as not compiling — is journaled durably under
//! `replay/journal/` the moment it is read, keyed on what decides it: the spliced
//! base body, the test's dependency key at HEAD (the one `test:cargo` selects by,
//! [`crate::mutate::resume::held_cases`]; HEAD's tree id where that is unknown),
//! the build's inputs and the base content. A rerun reads the journal first and
//! runs the union only over what it does not hold, and `replay/tree` is kept
//! while HEAD's tree id is the one it was materialised from.
//!
//! Inside the union run, each case is kept too: the run goes under the same
//! nextest run-wrapper `test:cargo` uses ([`crate::mutate::resume::wrap`]),
//! journaled under a key over the base content, HEAD's tree, every spliced
//! body and the build ([`union_key`]), so a lap stopped mid-run keeps every
//! case it passed and the next one reads those back as passes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

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
pub fn compare(base: &str, head: &str) -> Changed {
    compare_moved(base, head, &|body| body.to_owned(), &|_| false)
}

/// [`compare`], with the branch's file moves taken out of the question
/// (CLOUD-2789).
///
/// THE GATE ASKS WHETHER A BASE ASSERTION STILL HOLDS AT HEAD (#1056), and a
/// move changes no assertion. Two things a move did change are taken back out
/// here, and nothing else is:
///
/// - `translate` rewrites each moved file's path inside a base body to where
///   it lives now. A base body that differs from its head body only by such a
///   path is UNCHANGED, and a modified one is spliced in translated, so its
///   own assertions run against HEAD's files rather than failing on a path
///   that no longer exists.
/// - `elsewhere` answers whether a body (translated, whitespace aside) is a
///   test at HEAD in some other file. A base test gone from its file but
///   present there MOVED; it is not removed.
///
/// Every other difference is judged exactly as before: an assertion whose text
/// changed is still modified and replayed, and a body found nowhere is still
/// `test-removed`.
#[must_use]
pub fn compare_moved(
    base: &str,
    head: &str,
    translate: &dyn Fn(&str) -> String,
    elsewhere: &dyn Fn(&str) -> bool,
) -> Changed {
    let same = |body: &str| body.to_owned();
    compare_canonical(base, head, translate, elsewhere, &same, &same)
}

/// [`compare_moved`], with each body also read by the ITEMS it names rather
/// than how it spells them (CLOUD-2789): `canon_base` and `canon_head` replace
/// every path they resolve with the site defining it ([`crate::item_index`]),
/// so `crate::rules::Rule` at base and `crate::config_model::Rule` at head are
/// one item when `Rule` moved, or `rules` re-exported it. A respelled path is
/// then no change; every other token is still compared, so a changed assertion
/// is still modified. `elsewhere` receives the canonical base shape.
#[must_use]
pub fn compare_canonical(
    base: &str,
    head: &str,
    translate: &dyn Fn(&str) -> String,
    elsewhere: &dyn Fn(&str) -> bool,
    canon_base: &dyn Fn(&str) -> String,
    canon_head: &dyn Fn(&str) -> String,
) -> Changed {
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
        let base_body = translate(&base[old.body.0..old.body.1]);
        match after.get(inner) {
            Some(new)
                if differs(
                    &canon_base(&base_body),
                    &canon_head(&head[new.body.0..new.body.1]),
                ) =>
            {
                changed.modified.push(Modified {
                    inner: inner.clone(),
                    base_body,
                    head_body: new.body,
                    line: new.line,
                });
            }
            Some(_) => {}
            None if elsewhere(&shape(&canon_base(&base_body))) => {}
            None => changed.removed.push((inner.clone(), old.line)),
        }
    }
    changed
}

/// Each moved file's path rewritten to where it lives now, in every spelling a
/// test in `test_path` can use for it: repository-relative, and relative to the
/// test's own crate (`../batten-base/src/x.rs` from `crates/batten`), which is
/// how `CARGO_MANIFEST_DIR`-based reads spell a sibling crate.
///
/// One left-to-right pass, longest spelling first at each position, so a
/// rewritten path is never rewritten again (`src/x.rs` sits inside
/// `crates/a/src/x.rs`).
#[must_use]
pub fn translate(body: &str, test_path: &str, moves: &BTreeMap<String, String>) -> String {
    let crate_dir = test_path
        .strip_prefix("crates/")
        .and_then(|rest| rest.split_once('/'))
        .map(|(name, _)| format!("crates/{name}/"));
    let relative = |path: &str| -> Option<String> {
        let dir = crate_dir.as_deref()?;
        Some(match path.strip_prefix(dir) {
            Some(inside) => inside.to_owned(),
            None => format!("../{}", path.strip_prefix("crates/")?),
        })
    };
    let mut spellings: Vec<(String, String)> = Vec::new();
    for (old, new) in moves {
        spellings.push((old.clone(), new.clone()));
        if let (Some(old), Some(new)) = (relative(old), relative(new)) {
            spellings.push((old, new));
        }
    }
    spellings.sort_by_key(|(old, _)| std::cmp::Reverse(old.len()));
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    'scan: while let Some(next) = rest.chars().next() {
        for (old, new) in &spellings {
            if let Some(after) = rest.strip_prefix(old.as_str()) {
                out.push_str(new);
                rest = after;
                continue 'scan;
            }
        }
        out.push(next);
        rest = &rest[next.len_utf8()..];
    }
    out
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

/// Where each base Rust file is at HEAD: its own path, the one path it MOVED
/// to, or `None` when it is gone (CLOUD-2789).
///
/// A file that moved between crates (`crates/a/src/x.rs` to `crates/b/src/x.rs`)
/// is paired with the one HEAD file that is new since base and ends in the same
/// path below its last `src/`. The pairing used to be by path alone, and a base
/// path missing at HEAD was skipped: every test in a moved or deleted file
/// escaped the replay, so a test could be weakened by moving its file. Now a
/// moved file is compared at its new path, and a file with no successor (gone,
/// or ambiguous between two) has every base test `test-removed`.
#[must_use]
pub fn successors(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> BTreeMap<String, Option<String>> {
    let moves = crate::git::pair_moves(
        before.keys().filter(|path| !after.contains_key(*path)),
        after.keys().filter(|path| !before.contains_key(*path)),
    );
    before
        .keys()
        .map(|path| {
            let at_head = if after.contains_key(path) {
                Some(path.clone())
            } else {
                moves.get(path).cloned()
            };
            (path.clone(), at_head)
        })
        .collect()
}

/// The base half of the journal key (CLOUD-2787): one `base <path> <id>` line
/// per Rust file read at the merge base, `<id>` its content's digest — `step
/// base`'s line shape over exactly what the replay reads there. NO COMMIT ID:
/// a trunk commit touching no Rust file moves the merge base, never this.
fn base_lines(before: &BTreeMap<String, String>) -> String {
    before
        .iter()
        .map(|(path, text)| format!("base {path} {}", blake3::hash(text.as_bytes()).to_hex()))
        .collect::<Vec<_>>()
        .join("\n")
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
///
/// A REFUSAL CARRIES ITS CAUSE (CLOUD-2505), as `config lint`'s does: a bare
/// `refused` read as never asked, so an admission already recorded under a
/// mistyped pair was only found by asking again.
#[derive(serde::Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    admission: &'static str,
    cause: Option<&'static str>,
}

/// Write each finding with its admission, then the repair line for any cause
/// that is a repair rather than a question (CLOUD-2505). Text or one JSON
/// document; the document is emitted even when it is empty.
fn write_rows(
    findings: &[Finding],
    admissions: &[crate::lint::Admission],
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let rows: Vec<Row<'_>> = findings
        .iter()
        .zip(admissions)
        .map(|(finding, admission)| Row {
            finding,
            admission: admission.as_str(),
            cause: admission.is_refused().then(|| admission.token()),
        })
        .collect();
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)?;
        return Ok(());
    }
    for row in &rows {
        let Finding {
            path,
            line,
            id,
            key,
        } = row.finding;
        let token = match row.cause {
            Some(cause) => format!("{} {cause}", row.admission),
            None => row.admission.to_owned(),
        };
        writeln!(out, "{path}:{line} {id} {key} ({token})")?;
    }
    for line in crate::lint::remedy_lines("test-replay", admissions) {
        writeln!(out, "{line}")?;
    }
    Ok(())
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
pub fn run(
    root: &Path,
    base: &str,
    json: bool,
    structural: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let fork = crate::git::merge_base(root, base)?.unwrap_or_else(|| base.to_owned());
    let before = rust_files(root, &fork)?;
    let after = rust_files(root, "HEAD")?;

    let mut findings = Vec::new();
    // The head text each modified file is spliced from, by path.
    let mut splices: BTreeMap<String, (String, Vec<Modified>)> = BTreeMap::new();
    let moved = successors(&before, &after);
    // Every file the branch moved, old path to new (CLOUD-2789): what a base
    // body is translated through before it is judged.
    let moves: BTreeMap<String, String> = moved
        .iter()
        .filter_map(|(old, new)| Some((old.clone(), new.clone()?)))
        .filter(|(old, new)| old != new)
        .collect();
    // Which item each path names, at base and at HEAD, and the items the
    // branch moved between files (CLOUD-2789): a body is judged by what it
    // names, so a path respelled at an item's new home is no change.
    let base_index = crate::item_index::Index::new(&before);
    let head_index = crate::item_index::Index::new(&after);
    let item_moves = crate::item_index::moved_items(&base_index, &head_index);
    let no_moves = BTreeMap::new();
    // `crate::` names the file's own crate only for a file under a crate's
    // `src/`; in an integration test it is the test crate, which is not
    // indexed, so only its `batten::` paths resolve.
    let krate_of = |path: &str| -> String {
        if path.contains("/src/") {
            crate::item_index::crate_of(path).unwrap_or_default()
        } else {
            String::new()
        }
    };
    // Every test body at HEAD, by canonical shape, read only if some base test
    // left its file: what tells a test that moved from one that is gone.
    let head_shapes: std::cell::OnceCell<BTreeSet<String>> = std::cell::OnceCell::new();
    let shapes_at_head = || {
        head_shapes.get_or_init(|| {
            after
                .iter()
                .flat_map(|(path, text)| {
                    let krate = krate_of(path);
                    tests_in(text)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|test| {
                            shape(&crate::item_index::canonical(
                                &text[test.body.0..test.body.1],
                                &krate,
                                &head_index,
                                &no_moves,
                            ))
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        })
    };
    for (path, base_text) in &before {
        // A file gone at HEAD is compared against nothing, so each of its base
        // tests is removed; a moved one is compared at the path it moved to.
        let head_path = moved.get(path).cloned().flatten();
        let head_text = head_path
            .as_ref()
            .and_then(|head_path| after.get(head_path))
            .map_or("", String::as_str);
        if head_text == base_text {
            continue;
        }
        let test_path = head_path.as_deref().unwrap_or(path);
        let (base_krate, head_krate) = (krate_of(path), krate_of(test_path));
        let changed = compare_canonical(
            base_text,
            head_text,
            &|body| translate(body, test_path, &moves),
            &|body| shapes_at_head().contains(body),
            &|body| crate::item_index::canonical(body, &base_krate, &base_index, &item_moves),
            &|body| crate::item_index::canonical(body, &head_krate, &head_index, &no_moves),
        );
        for (inner, line) in changed.removed {
            findings.push(Finding {
                key: format!("{path}::{inner}"),
                path: path.clone(),
                line,
                id: SmellId::TestRemoved,
            });
        }
        if let Some(head_path) = head_path
            && !changed.modified.is_empty()
        {
            splices.insert(head_path, (head_text.to_owned(), changed.modified));
        }
    }

    // `--structural` STOPS HERE (CLOUD-2789): a removed test is decided by the
    // two trees alone, so the lap judges it in its first, seconds-long tier, and
    // only a modified test's run waits for the build.
    if !structural && !splices.is_empty() {
        findings.extend(replay(root, &base_lines(&before), &after, &splices)?);
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
    let verdicts: Vec<crate::lint::Admission> = admitted.iter().map(|(_, a)| *a).collect();
    write_rows(&findings, &verdicts, json, out)?;
    let kept = crate::state::repo_state_dir(root)?
        .join("replay")
        .join(BUILD_LOG);
    if !json && !structural && kept.is_file() {
        writeln!(
            out,
            "test replay: a union build failed; its compiler output is at {}",
            kept.display()
        )?;
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

/// Materialise HEAD under the repository's state directory, splice each base
/// body in, and run each modified test there. A test that fails, or a tree that
/// will not build, is `test-expectation-changed`.
///
/// **Outside the checkout**, CLOUD-2096's lesson: a tree or a build cache inside
/// the repository is walked by its own scans. The target directory persists, so a
/// later lap builds warm.
///
/// **Journaled first** ([`Journal`]): a test whose verdict the journal holds is
/// read back, never rerun, and when it holds every one no tree is placed and
/// nothing is built. `base` is the merge base's content ([`base_lines`]) and
/// `after` HEAD's Rust by path.
fn replay(
    root: &Path,
    base: &str,
    after: &BTreeMap<String, String>,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
) -> Result<Vec<Finding>> {
    let state = crate::state::repo_state_dir(root)?.join("replay");
    let tree = state.join("tree");
    let head =
        crate::git::resolve_ref(root, "HEAD^{tree}")?.context("test replay: HEAD names no tree")?;
    // THE BASE BY CONTENT (CLOUD-2787), never by a name that can move under the
    // journal nor by a commit id that moves with an unrelated trunk commit.
    let journal = Journal::open(root, &state, base, &head, splices);
    if !journal.lacks_any(splices) {
        return resume(&tree, splices, &journal, &|_| None, &|_| None);
    }
    place_tree(root, &state, &tree, &head, after)?;
    // A REPLAYED BODY RUNS IN A REPOSITORY, AS ITS HEAD FORM DOES. A bare file
    // tree failed every test that asks git anything — `batten exec` refused "not
    // inside a git repository" — so the base body's failure measured the tree,
    // not the expectation: measured on #1276, fifteen refusals, each one's HEAD
    // body failing there identically.
    crate::gitwrite::borrow_repository(root, &tree)?;
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
    //
    // EACH CASE IS KEPT THE MOMENT IT PASSES (step 17), under `test:cargo`'s
    // own run-wrapper, so a lap stopped mid-run loses only the cases still
    // running. Keyed over every spliced body rather than the ones still
    // standing, so a resumed run filtered to the rest reads its passes back.
    let wrapped = journal
        .union(splices)
        .map(|key| (state.join("test-run"), key));
    // A BUILD THAT FAILED KEEPS ITS COMPILER OUTPUT (#1276). The charging loop
    // reads rustc's locations and dropped the rest, so 375 bodies were charged
    // as non-compiling with no error anyone could read. Every failed union
    // build is appended here, and `run` names the file.
    let kept = state.join(BUILD_LOG);
    let _ = std::fs::remove_file(&kept);
    resume(
        &tree,
        splices,
        &journal,
        &|still| {
            let outcome = run_union(&tree, still, &published, wrapped.as_ref());
            if let Some((code, output)) = outcome.as_ref()
                && *code == BUILD_FAILED
            {
                let _ = crate::durable::append(&kept, output);
            }
            outcome
        },
        &|failed| {
            // UNWRAPPED: the run-wrapper journals passes under a key over the
            // SPLICED bodies, and a HEAD body's pass is not one of them.
            run_union(&tree, failed, &published, None)
        },
    )
}

/// Where a run's failed union builds keep their output, under `replay/`.
const BUILD_LOG: &str = "build-failed.log";

/// The file beside `replay/tree` naming the HEAD tree id it was materialised
/// from; absent while no whole tree stands there.
const TREE_ID: &str = "tree.id";

/// HEAD at `tree`: kept when [`TREE_ID`] names `head`, HEAD's tree id, with its
/// Rust put back to HEAD's text (`after`) wherever an earlier run's splice was
/// left; materialised afresh otherwise.
///
/// THE ID GOES FIRST AND COMES BACK LAST, so a run stopped mid-materialise
/// leaves no tree that claims a HEAD it does not wholly hold.
fn place_tree(
    root: &Path,
    state: &Path,
    tree: &Path,
    head: &str,
    after: &BTreeMap<String, String>,
) -> Result<()> {
    let marker = state.join(TREE_ID);
    let recorded = crate::fsio::read_to_string(&marker).ok();
    if tree.is_dir() && recorded.as_deref().map(str::trim_end) == Some(head) {
        return restore(tree, after);
    }
    if marker.exists() {
        std::fs::remove_file(&marker)
            .with_context(|| format!("test replay: clear {}", marker.display()))?;
    }
    if tree.exists() {
        std::fs::remove_dir_all(tree)
            .with_context(|| format!("test replay: clear {}", tree.display()))?;
    }
    crate::git::materialize_rev(root, "HEAD", tree)?;
    crate::durable::replace(&marker, head)
        .with_context(|| format!("test replay: record {}", marker.display()))
}

/// Rewrite every Rust file of a kept `tree` whose text is not HEAD's (`after`):
/// the splices a stopped run left, and any a test wrote into its own tree.
fn restore(tree: &Path, after: &BTreeMap<String, String>) -> Result<()> {
    for (path, text) in after {
        let at = tree.join(path);
        if crate::fsio::read_to_string(&at).ok().as_deref() != Some(text.as_str()) {
            crate::durable::replace(&at, text)
                .with_context(|| format!("test replay: restore {path}"))?;
        }
    }
    Ok(())
}

/// What one modified test's base body was judged against HEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// It ran and passed.
    Passed,
    /// It ran and failed: its expectation changed.
    Changed,
    /// HEAD's code would not compile it, and the refusal was charged to it.
    Charged,
}

impl Verdict {
    /// Every verdict, in the order [`Verdict::read`] tries them.
    const ALL: [Self; 3] = [Self::Passed, Self::Changed, Self::Charged];

    /// The word the journal holds for it.
    fn word(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Changed => "expectation-changed",
            Self::Charged => "charged-non-compiling",
        }
    }

    /// The verdict a journal entry holds, or `None` for one it does not name.
    fn read(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|verdict| verdict.word() == text.trim_end())
    }
}

/// Where each modified test's verdict is kept the moment it is read, and what
/// each entry's key is taken over besides the test and its base body.
///
/// UNKNOWN NEVER HITS ACROSS HEADS: a test with no dependency key keys on
/// HEAD's whole tree id, and a build whose inputs cannot be read journals
/// nothing at all, so every test reruns rather than one being read back wrong.
struct Journal {
    /// `replay/journal` under the repository's state directory.
    dir: PathBuf,
    /// The merge base's content the bodies were read at ([`base_lines`]).
    base: String,
    /// The build's inputs ([`crate::mutate::resume::build_digest`]), `None`
    /// where they cannot be read.
    build: Option<String>,
    /// HEAD's tree id: the dependency half of a test with none of its own.
    tree: String,
    /// Each test's dependency key at HEAD, by `<path>::<inner>`, where one is
    /// known ([`dependency_keys`]).
    deps: BTreeMap<String, String>,
}

impl Journal {
    /// The journal under `state` for the base content `base` and HEAD's tree id
    /// `tree`, with each test of `splices` whose dependency key is known.
    fn open(
        root: &Path,
        state: &Path,
        base: &str,
        tree: &str,
        splices: &BTreeMap<String, (String, Vec<Modified>)>,
    ) -> Self {
        let resources = crate::mutate::schema::resource_ids(root).ok();
        let build = resources
            .as_ref()
            .and_then(|ids| crate::mutate::resume::build_digest(root, ids));
        let deps = resources
            .map(|ids| dependency_keys(root, &ids, splices))
            .unwrap_or_default();
        Self {
            dir: state.join("journal"),
            base: base.to_owned(),
            build,
            tree: tree.to_owned(),
            deps,
        }
    }

    /// The entry name of `test` in `path`, or `None` when nothing is journaled.
    fn key(&self, path: &str, test: &Modified) -> Option<String> {
        let build = self.build.as_deref()?;
        let id = format!("{path}::{}", test.inner);
        let body = blake3::hash(test.base_body.as_bytes()).to_hex().to_string();
        let dependency = self.deps.get(&id).map_or_else(
            || format!("tree\x1e{}", self.tree),
            |key| format!("dep\x1e{key}"),
        );
        let mut hasher = blake3::Hasher::new();
        for part in [
            "rj1",
            id.as_str(),
            body.as_str(),
            dependency.as_str(),
            build,
            self.base.as_str(),
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\x1f");
        }
        Some(hasher.finalize().to_hex().to_string())
    }

    /// The verdict journaled for `test` in `path`, if any.
    fn read(&self, path: &str, test: &Modified) -> Option<Verdict> {
        let word = crate::fsio::read_to_string(self.dir.join(self.key(path, test)?)).ok()?;
        Verdict::read(&word)
    }

    /// Journal `verdict` for `test` in `path`, durably. An economy: an entry
    /// that cannot be written costs the next run a rerun, never this run its
    /// verdict.
    fn record(&self, path: &str, test: &Modified, verdict: Verdict) {
        let Some(key) = self.key(path, test) else {
            return;
        };
        if std::fs::create_dir_all(&self.dir).is_ok() {
            let _ = crate::durable::replace(self.dir.join(key), verdict.word());
        }
    }

    /// Whether any test of `splices` has no journaled verdict.
    fn lacks_any(&self, splices: &BTreeMap<String, (String, Vec<Modified>)>) -> bool {
        splices.iter().any(|(path, (_, modified))| {
            modified.iter().any(|test| self.read(path, test).is_none())
        })
    }

    /// The key the union run's per-case journal is kept under for `splices`
    /// ([`union_key`]), under this process's build variables; `None` where the
    /// build cannot be read, which runs the union unwrapped.
    fn union(&self, splices: &BTreeMap<String, (String, Vec<Modified>)>) -> Option<String> {
        let build = self.build.as_deref()?;
        let flags = crate::mutate::resume::flags_digest(&crate::mutate::schema::build_flags());
        Some(union_key(&self.base, &self.tree, build, &flags, splices))
    }
}

/// The key of the union run's per-case journal: the base content `base`
/// ([`base_lines`]), HEAD's tree id `tree`, the build's inputs `build`
/// ([`crate::mutate::resume::build_digest`]), the code-generation variables
/// `flags`, and every spliced body of `splices` by path and test.
///
/// HEAD'S TREE ID STANDS FOR THE CHECKOUT'S CONTENT IDS: the union builds HEAD
/// as materialised, never the working tree, so the tree id names every byte a
/// case's build reads besides the splices.
///
/// THE WHOLE SPLICE SET, NOT THE BODIES STILL STANDING: a resumed run splices
/// only the tests the verdict journal lacks, and keyed on those it would read
/// back none of the passes the stopped run kept. The bound, stated: a pass is
/// read back across runs that spliced different subsets of the same set, so
/// one test's base body is taken never to be code another test runs, the
/// bound the module doc already states for helpers.
fn union_key(
    base: &str,
    tree: &str,
    build: &str,
    flags: &str,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in ["ru1", base, tree, build, flags] {
        hasher.update(part.as_bytes());
        hasher.update(b"\x1f");
    }
    for (path, (_, modified)) in splices {
        for test in modified {
            for part in [path.as_str(), test.inner.as_str(), test.base_body.as_str()] {
                hasher.update(part.as_bytes());
                hasher.update(b"\x1f");
            }
            hasher.update(b"\x1e");
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// Each modified test's dependency key at HEAD, by `<path>::<inner>`: the key
/// `test:cargo` selects its case by ([`crate::mutate::resume::held_cases`]),
/// where the reach store holds one for it on this tree. Every other test is
/// left out, and keys on HEAD's tree id.
///
/// THE KEY TRACED HEAD'S BODY, NOT THE BASE BODY THAT RUNS, so it stands only
/// where the base body names nothing the head body does not ([`names`]): what
/// the base body can reach by name or read by path is then in the head body's
/// key. A working tree that is not HEAD keys nothing: the store is read off
/// the checkout, and the replay runs HEAD.
fn dependency_keys(
    root: &Path,
    resources: &BTreeMap<String, String>,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
) -> BTreeMap<String, String> {
    let mut deps = BTreeMap::new();
    if !crate::git::changed_paths(root).is_ok_and(|changed| changed.is_empty()) {
        return deps;
    }
    let env = crate::mutate::resume::env_digest(
        std::env::vars_os(),
        &crate::mutate::resume::journal_env(root),
    );
    let Ok(held) = crate::mutate::resume::held_cases(root, resources, &env) else {
        return deps;
    };
    for (path, (head_text, modified)) in splices {
        let Some((module, binary)) = case_of(root, path) else {
            continue;
        };
        for test in modified {
            let head_body = head_text.get(test.head_body.0..test.head_body.1);
            let covered = names(&test.base_body)
                .zip(head_body.and_then(names))
                .is_some_and(|(base, head)| base.is_subset(&head));
            if !covered {
                continue;
            }
            let name = if module.is_empty() {
                test.inner.clone()
            } else {
                format!("{module}::{}", test.inner)
            };
            if let Some(key) = held.get(&(name, binary.clone())) {
                deps.insert(format!("{path}::{}", test.inner), key.clone());
            }
        }
    }
    deps
}

/// The libtest module prefix and nextest binary id a `#[test]` in `path` runs
/// under, where the file's place in its innermost package names them: the
/// library's modules, or an integration-test target and its modules. `None`
/// where it cannot (a binary's or example's file), which keys on the tree; a
/// `#[path]`ed module names a case no record holds, which does too.
fn case_of(root: &Path, path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split('/').collect();
    let (at, package) = (0..parts.len()).rev().find_map(|depth| {
        let manifest = root.join(parts[..depth].join("/")).join("Cargo.toml");
        let table = crate::fsio::read_to_string(manifest)
            .ok()?
            .parse::<toml::Table>()
            .ok()?;
        let name = table.get("package")?.get("name")?.as_str()?.to_owned();
        Some((depth, name))
    })?;
    match &parts[at..] {
        ["src", "main.rs"] | ["src", "bin", ..] => None,
        ["src", rest @ ..] => Some((module_of(rest, "lib")?, package)),
        ["tests", file] => {
            let target = file.strip_suffix(".rs")?.replace('-', "_");
            Some((String::new(), format!("{package}::{target}")))
        }
        ["tests", target, rest @ ..] => Some((
            module_of(rest, "main")?,
            format!("{package}::{}", target.replace('-', "_")),
        )),
        _ => None,
    }
}

/// The module path of a target's file from its parts under the target's
/// directory, `crate_root` (`lib`, `main`) being the file that is the crate.
fn module_of(rest: &[&str], crate_root: &str) -> Option<String> {
    let (last, dirs) = rest.split_last()?;
    let stem = last.strip_suffix(".rs")?;
    let mut segments: Vec<&str> = dirs.to_vec();
    if !(stem == "mod" || (dirs.is_empty() && stem == crate_root)) {
        segments.push(stem);
    }
    Some(segments.join("::"))
}

/// Every identifier and every non-numeric literal `body` holds: what it can
/// reach by name or read by path. `None` when it does not lex.
fn names(body: &str) -> Option<BTreeSet<String>> {
    /// Add every name in `stream`, groups descended into, to `out`.
    fn gather(stream: proc_macro2::TokenStream, out: &mut BTreeSet<String>) {
        for token in stream {
            match token {
                proc_macro2::TokenTree::Group(group) => gather(group.stream(), out),
                proc_macro2::TokenTree::Ident(ident) => {
                    out.insert(ident.to_string());
                }
                proc_macro2::TokenTree::Literal(literal) => {
                    let text = literal.to_string();
                    if !text.starts_with(|c: char| c.is_ascii_digit()) {
                        out.insert(text);
                    }
                }
                proc_macro2::TokenTree::Punct(_) => {}
            }
        }
    }
    let stream: proc_macro2::TokenStream = body.parse().ok()?;
    let mut out = BTreeSet::new();
    gather(stream, &mut out);
    Some(out)
}

/// Every modified test's finding: each the journal holds read back, the rest
/// judged through `run` ([`judge`]), which journals each verdict as it reads
/// it. Sorted, so a verdict read back prints where a judged one would.
fn resume(
    tree: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    journal: &Journal,
    run: UnionRun<'_>,
    control: UnionRun<'_>,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut rest: BTreeMap<String, (String, Vec<Modified>)> = BTreeMap::new();
    for (path, (head_text, modified)) in splices {
        let mut left = Vec::new();
        for test in modified {
            match journal.read(path, test) {
                Some(Verdict::Passed) => {}
                Some(Verdict::Changed | Verdict::Charged) => findings.push(changed(path, test)),
                None => left.push(test.clone()),
            }
        }
        if !left.is_empty() {
            rest.insert(path.clone(), (head_text.clone(), left));
        }
    }
    if !rest.is_empty() {
        findings.extend(judge(tree, &rest, journal, run, control)?);
    }
    findings.sort_by(|a, b| (&a.path, a.line, &a.key).cmp(&(&b.path, b.line, &b.key)));
    Ok(findings)
}

/// `test`'s `test-expectation-changed` finding in `path`.
fn changed(path: &str, test: &Modified) -> Finding {
    Finding {
        key: format!("{path}::{}", test.inner),
        path: path.to_owned(),
        line: test.line,
        id: SmellId::TestExpectationChanged,
    }
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
///
/// **EACH VERDICT IS JOURNALED THE MOMENT IT IS DECIDED** ([`Journal::record`]):
/// a charged body as it is charged, each other test as its result is read. The
/// verdicts themselves are exactly what this loop decided before the journal.
fn judge(
    tree: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    journal: &Journal,
    run: UnionRun<'_>,
    control: UnionRun<'_>,
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
                        journal.record(&path, &test, Verdict::Charged);
                        findings.push(changed(&path, &test));
                    }
                }
                continue;
            }
        }
        // A REFUSAL NO BODY HOLDS IS THE UNION'S, NEVER ONE TEST'S: it fails
        // every test still standing, and journaled it would outlive the body
        // that caused it. So it is reported as before and journaled not at all.
        let unattributed = outcome
            .as_ref()
            .is_some_and(|(code, output)| *code == BUILD_FAILED && output.contains(COMPILE_FAILED));
        let mut failed: BTreeMap<String, (String, Vec<Modified>)> = BTreeMap::new();
        for (path, (head_text, modified)) in &splices {
            for test in modified {
                if passes(outcome.as_ref(), &test.inner)? {
                    if !unattributed {
                        journal.record(path, test, Verdict::Passed);
                    }
                } else if unattributed {
                    findings.push(changed(path, test));
                } else {
                    failed
                        .entry(path.clone())
                        .or_insert_with(|| (head_text.clone(), Vec::new()))
                        .1
                        .push(test.clone());
                }
            }
        }
        findings.extend(controlled(tree, &failed, journal, control)?);
        return Ok(findings);
    }
}

/// The failed base bodies whose HEAD body passes in the same tree: only those
/// are expectation changes (#1276).
///
/// **A FAILURE HEAD'S OWN BODY SHARES MEASURES THE TREE, NOT THE EXPECTATION.**
/// The replay tree is not a checkout: its build sits under the checkout's
/// `target/`, its task-runner config is untrusted, and its fixtures fall through to the
/// checkout holding the build. Measured on #1276, three base bodies failed for
/// those reasons alone — and so does HEAD's form of each, there. So each failed
/// test's HEAD body is run in the same tree, and one that fails too is no
/// finding and is not journaled: the next tree may differ. A control that could
/// not run answers nothing, so every failure stands.
fn controlled(
    tree: &Path,
    failed: &BTreeMap<String, (String, Vec<Modified>)>,
    journal: &Journal,
    control: UnionRun<'_>,
) -> Result<Vec<Finding>> {
    if failed.is_empty() {
        return Ok(Vec::new());
    }
    for (path, (head_text, _)) in failed {
        crate::durable::replace(tree.join(path), head_text)
            .with_context(|| format!("test replay: restore {path} for its control"))?;
    }
    let held = control(failed);
    let mut findings = Vec::new();
    for (path, (_, tests)) in failed {
        for test in tests {
            let head_passes = held.is_none() || passes(held.as_ref(), &test.inner).unwrap_or(true);
            if head_passes {
                journal.record(path, test, Verdict::Changed);
                findings.push(changed(path, test));
            }
        }
    }
    Ok(findings)
}

/// Run every still-spliced test in one `nextest` call: its outcome, or `None`
/// when it could not be spawned. With `wrapped` — the journal's state
/// directory and key ([`Journal::union`]) — each case runs under the
/// journaling run-wrapper, so a case passed by an earlier run over the same
/// key reports its pass without running; a wrapper that cannot be set up runs
/// the union as before, since the journal is an economy.
fn run_union(
    tree: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
    published: &[(String, Option<String>)],
    wrapped: Option<&(PathBuf, String)>,
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
    let argv = match wrapped {
        Some((state, key)) => crate::mutate::resume::wrap(tree, state, key, &argv).unwrap_or(argv),
        None => argv,
    };
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

    /// A REFUSAL NAMES ITS CAUSE, AND A REPAIR IS SAID ONCE (CLOUD-2505).
    #[test]
    fn a_refused_row_names_its_cause_and_a_repair_is_said_once() {
        use crate::lint::{Admission, Cause};
        let finding = |test: &str| Finding {
            key: format!("src/x.rs::tests::{test}"),
            path: String::from("src/x.rs"),
            line: 3,
            id: SmellId::TestRemoved,
        };
        let findings = [finding("a"), finding("b"), finding("c")];
        let admissions = [
            Admission::Refused(Cause::NotAsked),
            Admission::Asked,
            Admission::Refused(Cause::LedgerRewritten),
        ];
        let mut text = Vec::new();
        write_rows(&findings, &admissions, false, &mut text).unwrap();
        let remedy = Cause::LedgerRewritten.remedy().unwrap();
        assert_eq!(
            String::from_utf8(text).unwrap(),
            format!(
                "src/x.rs:3 test-removed src/x.rs::tests::a (refused not-asked)\n\
                 src/x.rs:3 test-removed src/x.rs::tests::b (asked)\n\
                 src/x.rs:3 test-removed src/x.rs::tests::c (refused ledger-rewritten)\n\
                 test-replay: {remedy}\n"
            )
        );

        let mut json = Vec::new();
        write_rows(&findings[..2], &admissions[..2], true, &mut json).unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(rows[0]["admission"], "refused");
        assert_eq!(rows[0]["cause"], "not-asked");
        assert_eq!(rows[1]["admission"], "asked");
        assert!(rows[1]["cause"].is_null());
    }

    /// Fails by: the journal's base half keyed on anything but the Rust read
    /// at the merge base (CLOUD-2787) — a commit id would move with a trunk
    /// commit touching none of it, and a key blind to a body would hold
    /// across a changed one.
    #[test]
    fn the_journal_base_is_the_content_read_at_the_merge_base() {
        let at = |text: &str| {
            BTreeMap::from([
                (String::from("src/a.rs"), String::from("fn a() {}\n")),
                (String::from("src/b.rs"), text.to_owned()),
            ])
        };
        let one = base_lines(&at("fn b() {}\n"));
        assert_eq!(
            one,
            base_lines(&at("fn b() {}\n")),
            "same content, same base"
        );
        assert_ne!(one, base_lines(&at("fn b() { 1; }\n")), "a moved body");
        assert_eq!(one.lines().count(), 2);
        assert!(one.starts_with("base src/a.rs "), "{one}");
    }

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

    fn files(paths: &[&str]) -> BTreeMap<String, String> {
        paths
            .iter()
            .map(|path| ((*path).to_owned(), String::new()))
            .collect()
    }

    /// Fails by: a base path missing at HEAD skipped rather than followed, the
    /// hole that let every test in a moved file escape the replay.
    #[test]
    fn a_file_moved_between_crates_is_compared_at_its_new_path() {
        let before = files(&["crates/a/src/x.rs", "crates/a/src/kept.rs"]);
        let after = files(&["crates/b/src/x.rs", "crates/a/src/kept.rs"]);
        let moved = successors(&before, &after);
        assert_eq!(
            moved["crates/a/src/x.rs"].as_deref(),
            Some("crates/b/src/x.rs")
        );
        assert_eq!(
            moved["crates/a/src/kept.rs"].as_deref(),
            Some("crates/a/src/kept.rs")
        );
    }

    /// Fails by: a deleted file, or one whose move two new files could explain,
    /// paired with something rather than having its tests removed.
    #[test]
    fn a_gone_or_ambiguous_file_has_no_successor() {
        let before = files(&["crates/a/src/gone.rs", "crates/a/src/twice.rs"]);
        let after = files(&["crates/b/src/twice.rs", "crates/c/src/twice.rs"]);
        let moved = successors(&before, &after);
        assert_eq!(moved["crates/a/src/gone.rs"], None);
        assert_eq!(moved["crates/a/src/twice.rs"], None);
        assert_eq!(
            compare(BASE, "").removed.len(),
            compare(BASE, BASE).removed.len() + tests_in(BASE).unwrap().len(),
            "a file with no successor is compared against nothing: every test removed"
        );
    }

    /// Fails by: a moved file's path left untranslated in either spelling, or a
    /// rewritten path rewritten again by the shorter spelling inside it.
    #[test]
    fn a_moved_path_is_translated_in_both_spellings_once() {
        let moves = BTreeMap::from([(
            "crates/batten/src/facts.rs".to_owned(),
            "crates/batten-facts/src/facts.rs".to_owned(),
        )]);
        let body = r#"{ read("crates/batten/src/facts.rs"); read(dir.join("src/facts.rs")); }"#;
        assert_eq!(
            translate(body, "crates/batten/tests/it/x.rs", &moves),
            r#"{ read("crates/batten-facts/src/facts.rs"); read(dir.join("../batten-facts/src/facts.rs")); }"#
        );
        assert_eq!(translate(body, "README.md", &BTreeMap::new()), body);
    }

    /// Fails by: a body that differs only by a moved path judged modified, a
    /// test that moved to another file judged removed, or a REAL change to an
    /// assertion hidden by either.
    #[test]
    fn a_move_is_not_a_change_and_a_changed_assertion_still_is() {
        let base = "#[test]\nfn a() { read(\"old/x.rs\"); assert_eq!(n, 1); }\n\
                    #[test]\nfn b() { assert!(gone); }\n";
        let moved = |body: &str| body.replace("old/x.rs", "new/x.rs");
        let elsewhere = |body: &str| body == shape("{ assert!(gone); }");
        let head = "#[test]\nfn a() { read(\"new/x.rs\"); assert_eq!(n, 1); }\n";
        assert_eq!(
            compare_moved(base, head, &moved, &elsewhere),
            Changed::default()
        );
        let weakened = "#[test]\nfn a() { read(\"new/x.rs\"); assert_eq!(n, 2); }\n";
        let changed = compare_moved(base, weakened, &moved, &elsewhere);
        assert_eq!(
            changed.modified.len(),
            1,
            "a changed assertion is still replayed"
        );
        assert!(
            changed.modified[0].base_body.contains("new/x.rs"),
            "and spliced translated, so it fails on its assertion, not its path"
        );
        let removed = compare_moved(base, head, &moved, &|_| false);
        assert_eq!(removed.removed, vec![(String::from("b"), 4)]);
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
        let findings = judge(
            &tree,
            &splices,
            &journal("replay-judge-journal"),
            &run,
            &|_| None,
        )
        .unwrap();
        assert_eq!(
            findings.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(),
            ["src/x.rs::tests::narrowed"]
        );
        assert_eq!(runs.get(), 2);
    }

    /// Fails by: a base failure HEAD's own body shares in the tree counted as
    /// an expectation change, or the control run with no failure to check, or
    /// a failure HEAD's body passes past dropped (#1276).
    #[test]
    fn a_failure_head_s_own_body_shares_is_the_tree_s_not_the_expectation_s() {
        let head = BASE
            .replace("assert_eq!(1, 1);", "assert_eq!(2, 2);")
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(BASE, &head);
        let tree = judged_tree("replay-control");
        let mut splices = BTreeMap::new();
        splices.insert(String::from("src/x.rs"), (head.clone(), changed.modified));
        let failing = |names: &[&str]| {
            names
                .iter()
                .map(|name| format!("        FAIL [   0.010s] batten::it tests::{name}\n"))
                .collect::<Vec<_>>()
                .concat()
        };
        let run = |_: &Splices| Some((TEST_RUN_FAILED, failing(&["kept", "narrowed"])));
        let controlled = std::cell::RefCell::new(Vec::new());
        let control = |failed: &Splices| {
            controlled.borrow_mut().extend(
                failed
                    .values()
                    .flat_map(|(_, tests)| tests.iter().map(|test| test.inner.clone())),
            );
            assert_eq!(
                crate::fsio::read_to_string(tree.join("src/x.rs"))
                    .ok()
                    .as_deref(),
                Some(head.as_str()),
                "the control runs HEAD's own bodies"
            );
            Some((
                TEST_RUN_FAILED,
                format!(
                    "        PASS [   0.010s] batten::it tests::narrowed\n{}",
                    failing(&["kept"])
                ),
            ))
        };
        let findings = judge(
            &tree,
            &splices,
            &journal("replay-control-journal"),
            &run,
            &control,
        )
        .unwrap();
        assert_eq!(keys(&findings), ["src/x.rs::tests::narrowed"]);
        assert_eq!(
            controlled.into_inner(),
            ["tests::kept", "tests::narrowed"],
            "only the failures are controlled"
        );
        let none = |_: &Splices| None;
        let unchecked = judge(
            &tree,
            &splices,
            &journal("replay-control-unchecked"),
            &run,
            &none,
        )
        .unwrap();
        assert_eq!(
            keys(&unchecked).len(),
            2,
            "a control that could not run leaves every failure standing"
        );
    }

    /// The splices a test of the journal judges through.
    type Splices = BTreeMap<String, (String, Vec<Modified>)>;

    /// `kept`'s base body at the start of the journal's fixtures.
    const KEPT_BASE: &str = "assert_eq!(1, 1);\n        assert_eq!(2, 2);";

    /// Two modified tests in `src/x.rs`: `kept`, whose base body is `kept_base`
    /// and passes, and `narrowed`, whose base body names a helper HEAD's code
    /// will not compile it against. With the line that refusal points at.
    fn two_modified(kept_base: &str) -> (Splices, usize) {
        let base = BASE.replace("assert_eq!(1, 1);", kept_base);
        let head = BASE
            .replace("assert_eq!(1, 1);", "assert_eq!(9, 9);")
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(&base, &head);
        assert_eq!(changed.modified.len(), 2, "both bodies changed");
        let helper_line = splice(&head, &changed.modified)
            .lines()
            .position(|line| line.contains("super::helper(), 1"))
            .expect("the base body is spliced")
            + 1;
        let mut splices = BTreeMap::new();
        splices.insert(String::from("src/x.rs"), (head, changed.modified));
        (splices, helper_line)
    }

    /// The refusal rustc gives `narrowed`'s base body, at `helper_line`.
    fn refusal(helper_line: usize) -> (i32, String) {
        (
            BUILD_FAILED,
            format!(
                "error[E0425]: cannot find function `helper`\n   --> src/x.rs:{helper_line}:24\n\
                 error: could not compile `x`\n"
            ),
        )
    }

    /// A run in which `kept` passed.
    fn kept_passes() -> (i32, String) {
        (
            0,
            String::from("        PASS [   0.010s] batten::it tests::kept\n"),
        )
    }

    /// The tests a union run was asked to run.
    fn standing(still: &Splices) -> Vec<&str> {
        still
            .values()
            .flat_map(|(_, modified)| modified.iter().map(|test| test.inner.as_str()))
            .collect()
    }

    /// Each finding's key.
    fn keys(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.key.as_str())
            .collect()
    }

    /// A journal at `name`'s scratch directory, its base, build and tree fixed.
    fn journal(name: &str) -> Journal {
        Journal {
            dir: crate::scratch::scratch(name).join("journal"),
            base: String::from("base"),
            build: Some(String::from("build")),
            tree: String::from("tree"),
            deps: BTreeMap::new(),
        }
    }

    /// A tree for the judge seam to splice into.
    fn judged_tree(name: &str) -> PathBuf {
        let tree = crate::scratch::scratch(name);
        std::fs::create_dir_all(tree.join("src")).unwrap();
        tree
    }

    /// Judge both fixtures to the end into `journal`: `narrowed` charged,
    /// `kept` passed, in the two runs that takes.
    fn judge_all(tree: &Path, journal: &Journal) {
        let (splices, helper_line) = two_modified(KEPT_BASE);
        let runs = std::cell::Cell::new(0);
        let run = |_: &Splices| {
            runs.set(runs.get() + 1);
            Some(if runs.get() == 1 {
                refusal(helper_line)
            } else {
                kept_passes()
            })
        };
        let findings = resume(tree, &splices, journal, &run, &|_| None).unwrap();
        assert_eq!(keys(&findings), ["src/x.rs::tests::narrowed"]);
        assert_eq!(runs.get(), 2, "a charge, then the rebuild without it");
    }

    /// Fails by: a verdict journaled only at the end of a run (a stopped run
    /// keeps nothing, and the resume charges `narrowed` again), or a journaled
    /// test run again.
    #[test]
    fn a_stopped_replay_resumes_by_running_only_the_rest() {
        let (splices, helper_line) = two_modified(KEPT_BASE);
        let tree = judged_tree("replay-stopped");
        let journal = journal("replay-stopped-journal");
        let runs = std::cell::Cell::new(0);
        // THE LAP STOPS AFTER THE CHARGE: the rebuild never reports.
        let stopped = |_: &Splices| {
            runs.set(runs.get() + 1);
            (runs.get() == 1).then(|| refusal(helper_line))
        };
        assert!(
            resume(&tree, &splices, &journal, &stopped, &|_| None).is_err(),
            "a rebuild that never reported measured nothing"
        );
        assert_eq!(runs.get(), 2);
        let resumed = std::cell::Cell::new(0);
        let rest = |still: &Splices| {
            resumed.set(resumed.get() + 1);
            assert_eq!(
                standing(still),
                ["tests::kept"],
                "only the unjudged test runs"
            );
            Some(kept_passes())
        };
        let findings = resume(&tree, &splices, &journal, &rest, &|_| None).unwrap();
        assert_eq!(
            keys(&findings),
            ["src/x.rs::tests::narrowed"],
            "the charge is read back"
        );
        assert_eq!(resumed.get(), 1);
    }

    /// Fails by: a verdict not journaled, or one journaled under a key that
    /// moves between two runs over the same HEAD and base.
    #[test]
    fn an_unchanged_head_and_base_rerun_nothing() {
        let tree = judged_tree("replay-unchanged");
        let journal = journal("replay-unchanged-journal");
        judge_all(&tree, &journal);
        let (splices, _) = two_modified(KEPT_BASE);
        let runs = std::cell::Cell::new(0);
        let none = |_: &Splices| {
            runs.set(runs.get() + 1);
            None::<(i32, String)>
        };
        let findings = resume(&tree, &splices, &journal, &none, &|_| None).unwrap();
        assert_eq!(keys(&findings), ["src/x.rs::tests::narrowed"]);
        assert_eq!(runs.get(), 0, "every verdict is read back");
        assert!(!journal.lacks_any(&splices));
    }

    /// Fails by: a key that does not see the base body (the stale pass read
    /// back), or one that moves every test's key with one body.
    #[test]
    fn a_changed_base_body_reruns_only_its_test() {
        let tree = judged_tree("replay-moved-body");
        let journal = journal("replay-moved-body-journal");
        judge_all(&tree, &journal);
        let (splices, _) = two_modified("assert_eq!(1, 1);\n        assert_eq!(4, 4);");
        let runs = std::cell::Cell::new(0);
        let run = |still: &Splices| {
            runs.set(runs.get() + 1);
            assert_eq!(standing(still), ["tests::kept"], "only the moved body runs");
            Some(kept_passes())
        };
        let findings = resume(&tree, &splices, &journal, &run, &|_| None).unwrap();
        assert_eq!(keys(&findings), ["src/x.rs::tests::narrowed"]);
        assert_eq!(runs.get(), 1);
    }

    /// Fails by: a journal key that holds across a moved base commit, build,
    /// body, test or (for a test with no dependency key) HEAD tree; one that a
    /// tree move its dependency key does not see moves; or an entry kept
    /// where the build cannot be read.
    #[test]
    fn a_journal_key_moves_with_what_decides_the_verdict() {
        let (splices, _) = two_modified(KEPT_BASE);
        let (path, (_, modified)) = splices.iter().next().unwrap();
        let with = |base: &str, build: Option<&str>, tree: &str, dep: bool| Journal {
            dir: PathBuf::from("journal"),
            base: base.to_owned(),
            build: build.map(str::to_owned),
            tree: tree.to_owned(),
            deps: dep
                .then(|| (format!("{path}::{}", modified[0].inner), String::from("d")))
                .into_iter()
                .collect(),
        };
        let key = |journal: &Journal, test: &Modified| journal.key(path, test);
        let one = key(&with("b", Some("c"), "t", false), &modified[0]);
        assert!(one.is_some());
        assert_eq!(one, key(&with("b", Some("c"), "t", false), &modified[0]));
        for moved in [
            key(&with("b2", Some("c"), "t", false), &modified[0]),
            key(&with("b", Some("c2"), "t", false), &modified[0]),
            key(&with("b", Some("c"), "t2", false), &modified[0]),
            key(&with("b", Some("c"), "t", false), &modified[1]),
            key(&with("b", Some("c"), "t", true), &modified[0]),
        ] {
            assert_ne!(one, moved);
        }
        let mut rebased = modified[0].clone();
        rebased.base_body.push(' ');
        assert_ne!(one, key(&with("b", Some("c"), "t", false), &rebased));
        assert_eq!(
            key(&with("b", Some("c"), "t", true), &modified[0]),
            key(&with("b", Some("c"), "t2", true), &modified[0]),
            "a tree move the dependency key does not see reruns nothing"
        );
        assert_eq!(key(&with("b", None, "t", false), &modified[0]), None);
    }

    /// Fails by: a union journal key that holds across a moved base commit,
    /// HEAD tree, build, build variable or spliced body (a pass of another
    /// spliced tree read back), or one that moves between two runs over the
    /// same of all of them.
    #[test]
    fn a_union_journal_key_moves_with_what_the_union_builds() {
        let (splices, _) = two_modified(KEPT_BASE);
        let (moved, _) = two_modified("assert_eq!(1, 1);\n        assert_eq!(4, 4);");
        let one = union_key("b", "t", "c", "f", &splices);
        assert_eq!(one, union_key("b", "t", "c", "f", &splices));
        for other in [
            union_key("b2", "t", "c", "f", &splices),
            union_key("b", "t2", "c", "f", &splices),
            union_key("b", "t", "c2", "f", &splices),
            union_key("b", "t", "c", "f2", &splices),
            union_key("b", "t", "c", "f", &moved),
        ] {
            assert_ne!(one, other);
        }
        assert!(
            journal("replay-union-key").union(&splices).is_some(),
            "a readable build keys the union"
        );
        let unbuilt = Journal {
            build: None,
            ..journal("replay-union-unbuilt")
        };
        assert_eq!(unbuilt.union(&splices), None, "no build, no journal");
    }

    /// Fails by: a base body that names something its head body does not read
    /// as covered by the head body's key, or a file's module path misread.
    #[test]
    fn a_base_body_is_covered_only_where_it_names_nothing_new() {
        let head = names("{ let four = super::add(2, 2); assert_eq!(four, 4); }").unwrap();
        let covered = |body: &str| names(body).unwrap().is_subset(&head);
        assert!(covered("{ assert_eq!(super::add(2, 2), 5); }"));
        assert!(!covered("{ assert_eq!(super::sub(2, 2), 0); }"));
        assert!(!covered("{ let _ = include_str!(\"other.json\"); }"));
        assert_eq!(module_of(&["lib.rs"], "lib").as_deref(), Some(""));
        assert_eq!(module_of(&["a", "mod.rs"], "lib").as_deref(), Some("a"));
        assert_eq!(module_of(&["a", "b.rs"], "lib").as_deref(), Some("a::b"));
        assert_eq!(module_of(&["main.rs"], "main").as_deref(), Some(""));
        assert_eq!(module_of(&["step.rs"], "main").as_deref(), Some("step"));
        assert_eq!(module_of(&["notes.txt"], "lib"), None);
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

    /// Fails by: a file's case placed in the wrong target or module, a
    /// binary's file given a case no record holds, or a nested package's file
    /// read against the outer package.
    #[test]
    fn a_tests_case_is_its_targets_module_path() {
        let root = crate::scratch::scratch("replay-case-of");
        for (manifest, name) in [("Cargo.toml", "pkg"), ("crates/c/Cargo.toml", "c")] {
            let at = root.join(manifest);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(at, format!("[package]\nname = \"{name}\"\n")).unwrap();
        }
        let case = |path: &str| case_of(&root, path);
        let some = |module: &str, binary: &str| Some((module.to_owned(), binary.to_owned()));
        assert_eq!(case("src/lib.rs"), some("", "pkg"));
        assert_eq!(case("src/a/b.rs"), some("a::b", "pkg"));
        assert_eq!(case("src/a/mod.rs"), some("a", "pkg"));
        assert_eq!(case("src/main.rs"), None);
        assert_eq!(case("src/bin/x.rs"), None);
        assert_eq!(case("tests/it-x.rs"), some("", "pkg::it_x"));
        assert_eq!(case("tests/it/main.rs"), some("", "pkg::it"));
        assert_eq!(case("tests/it/a.rs"), some("a", "pkg::it"));
        assert_eq!(case("crates/c/src/x.rs"), some("x", "c"));
        assert_eq!(case("examples/e.rs"), None);
    }

    /// Fails by: a tree materialised for another HEAD kept (a replay of the
    /// wrong code), or the tree of this HEAD materialised again.
    #[test]
    fn a_tree_is_kept_only_for_the_head_it_was_made_from() {
        let base = crate::scratch::scratch("replay-place-tree");
        let (root, state, tree) = (base.join("root"), base.join("state"), base.join("tree"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::write(root.join("a.txt"), "one").unwrap();
        crate::gitwrite::commit_paths(&root, &[String::from("a.txt")], "init").unwrap();
        let after = BTreeMap::new();
        place_tree(&root, &state, &tree, "head-1", &after).unwrap();
        assert!(tree.join("a.txt").is_file(), "materialised");
        std::fs::write(tree.join("sentinel"), "").unwrap();
        place_tree(&root, &state, &tree, "head-1", &after).unwrap();
        assert!(
            tree.join("sentinel").is_file(),
            "the same head's tree is kept"
        );
        place_tree(&root, &state, &tree, "head-2", &after).unwrap();
        assert!(
            !tree.join("sentinel").exists(),
            "another head's is made afresh"
        );
        assert_eq!(
            crate::fsio::read_to_string(state.join(TREE_ID)).unwrap(),
            "head-2"
        );
    }

    /// Fails by: a refusal no body holds journaled against a test (it would
    /// outlive the body that caused it) or sent to the control run, or a
    /// passing union build that failed to link left unjournaled.
    #[test]
    fn only_a_compile_refusal_no_body_holds_is_the_unions() {
        let (splices, _) = two_modified(KEPT_BASE);
        let tree = judged_tree("replay-unattributed");
        let unplaced_journal = journal("replay-unattributed-journal");
        let passed_journal = journal("replay-unattributed-passed");
        let controlled = std::cell::Cell::new(false);
        let control = |_: &Splices| {
            controlled.set(true);
            None
        };
        let unplaced =
            |_: &Splices| Some((BUILD_FAILED, String::from("error: could not compile `x`\n")));
        let findings = judge(&tree, &splices, &unplaced_journal, &unplaced, &control).unwrap();
        assert_eq!(keys(&findings).len(), 2, "every test still standing fails");
        assert!(!controlled.get(), "the union's refusal is not controlled");
        for (path, (_, tests)) in &splices {
            for test in tests {
                assert_eq!(unplaced_journal.read(path, test), None, "nor journaled");
            }
        }
        let passed = |_: &Splices| {
            Some((
                BUILD_FAILED,
                String::from(
                    "        PASS [   0.010s] batten::it tests::kept\n        \
                     PASS [   0.010s] batten::it tests::narrowed\n",
                ),
            ))
        };
        assert!(
            judge(&tree, &splices, &passed_journal, &passed, &control)
                .unwrap()
                .is_empty()
        );
        for (path, (_, tests)) in &splices {
            for test in tests {
                assert_eq!(passed_journal.read(path, test), Some(Verdict::Passed));
            }
        }
    }
}

/// The replay's dependency keys over a sealed reach record (#1276).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod dependency_key_tests {
    use super::{compare, dependency_keys};
    use crate::mutate::schema;
    use std::collections::{BTreeMap, BTreeSet};

    /// The base body, then HEAD's: HEAD's names every name the base body does.
    const BASE: &str = "pub fn helper() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn kept() {\n        assert_eq!(super::helper(), 1);\n    }\n}\n";
    const HEAD: &str = "pub fn helper() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn kept() {\n        let one = super::helper();\n        assert_eq!(one, 1);\n    }\n}\n";

    /// A committed crate at HEAD, with one sealed reach record for its case
    /// in the state the replay reads.
    fn sealed(name: &str) -> std::path::PathBuf {
        let scratch = crate::scratch::scratch(name);
        crate::testing::contain_state(&scratch.join("data"));
        let root = scratch.join("repo");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fix\"\n").unwrap();
        std::fs::write(root.join("src/lib.rs"), HEAD).unwrap();
        crate::gitwrite::init_on_main(&root).unwrap();
        crate::gitwrite::commit_paths(
            &root,
            &[String::from("Cargo.toml"), String::from("src/lib.rs")],
            "head",
        )
        .unwrap();
        let resources = schema::resource_ids(&root).unwrap();
        let format = schema::Format {
            dirs: [(String::from("fix"), String::new())].into(),
            probed: [String::from("src/lib.rs")].into(),
            flags: schema::build_flags(),
            ..schema::Format::default()
        };
        let base = crate::state::repo_state_dir(&root)
            .unwrap()
            .join("mutate")
            .join("schema")
            .join("reach");
        let record = base.join("c1");
        std::fs::create_dir_all(&record).unwrap();
        std::fs::write(
            base.join(format!("format-{}.json", format.key())),
            serde_json::to_string(&format).unwrap(),
        )
        .unwrap();
        let index = schema::dependency_index(&root, &format).unwrap();
        let functions: BTreeSet<String> = ["kept", "helper"]
            .iter()
            .flat_map(|name| index.digests_of(name))
            .collect();
        let case = (String::from("tests::kept"), String::from("fix"));
        let cases = [(case.clone(), (functions.clone(), None))].into();
        let tested = schema::test_digests(&root, &index, &format.dirs, &cases, &resources)
            .remove(&case)
            .flatten()
            .expect("the case's selection digest");
        let depends: String = std::iter::once(String::from("Dd\n"))
            .chain(functions.iter().map(|function| format!("F{function}\n")))
            .collect();
        for (file, text) in [
            ("tested", format!("{}\t{tested}", format.key())),
            ("depends", depends),
            ("case", String::from("tests::kept\tfix")),
            ("done", String::from("0")),
        ] {
            std::fs::write(record.join(file), text).unwrap();
        }
        root
    }

    /// The splices of `base` against the committed HEAD.
    fn splices(base: &str) -> BTreeMap<String, (String, Vec<super::Modified>)> {
        [(
            String::from("src/lib.rs"),
            (HEAD.to_owned(), compare(base, HEAD).modified),
        )]
        .into()
    }

    /// Fails by: a modified test the reach store holds keyed on the tree (every
    /// unrelated edit judges it again), a working tree that is not HEAD keyed
    /// (the store was read off the checkout, and the replay runs HEAD), or a
    /// base body naming what HEAD's does not keyed on HEAD's trace.
    #[test]
    fn a_held_cases_test_keys_on_its_dependencies() {
        let root = sealed("replay-dependency-keys");
        let resources = schema::resource_ids(&root).unwrap();
        let keys = dependency_keys(&root, &resources, &splices(BASE));
        assert_eq!(
            keys.keys().map(String::as_str).collect::<Vec<_>>(),
            ["src/lib.rs::tests::kept"],
            "the held case keys its test"
        );
        let wider = BASE.replace("super::helper(), 1", "super::helper(), other()");
        assert!(
            dependency_keys(&root, &resources, &splices(&wider)).is_empty(),
            "a base body naming more than HEAD's"
        );
        std::fs::write(root.join("src/lib.rs"), format!("{HEAD}// edited\n")).unwrap();
        assert!(
            dependency_keys(&root, &resources, &splices(BASE)).is_empty(),
            "a working tree that is not HEAD"
        );
    }
}
