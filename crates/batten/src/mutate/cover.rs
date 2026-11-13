//! Per-test coverage, so each cargo-mutants mutant runs only the tests that
//! execute the function it mutates (CLOUD-2253).
//!
//! # Why
//!
//! cargo-mutants selects tests by PACKAGE and never by coverage (mutants.rs,
//! "workspaces"), so every mutant ran the crate's whole suite until its first
//! failure. Measured on #1276: in 46 caught mutants every catching test took
//! under a second (one took 15s), yet nextest ran a median of ~6,000 unrelated
//! tests, ~80s, before reaching it. Running only covering tests is the
//! literature's and PIT's practice: Reales Mateo et al. (STVR 2014) execute a
//! mutant only against tests covering its statement; PIT collects per-test line
//! coverage and runs only the tests that execute the mutated line.
//!
//! # How
//!
//! 1. `batten mutate cover` runs the suite once, instrumented
//!    (`-C instrument-coverage`), under a nextest `run-wrapper` that is this
//!    binary ([`recorded`]). Each test, and every process it spawns, writes its
//!    profiles to that test's own directory; the wrapper reduces them to the
//!    workspace functions that executed ([`keys_of`]) and deletes them, so disk
//!    holds one test's profiles at a time. [`Map`] inverts the per-test lists.
//! 2. cargo-mutants runs `$CARGO` for every build and test step, from inside the
//!    mutant's copy. `mutate cargo` points `$CARGO` at this binary with
//!    [`SHIM`] naming the real cargo. On a test step [`cargo_shimmed`] finds the
//!    mutated line ([`mutated_line`]), the function cargo-mutants recorded for
//!    it, and adds `-E` naming exactly the tests that cover it.
//! 3. A mutant the narrowed run misses is not reported from it: `mutate cargo`
//!    re-runs every missed mutant against the whole suite (`--iterate` skips the
//!    caught ones), so the verdict is the full suite's. Selection only makes a
//!    CAUGHT verdict cheaper; it can never manufacture one.
//!
//! The map is never rebuilt by `mutate cargo`: a stale map only selects worse,
//! and step 3 makes worse selection slower, never wrong.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// Names the real cargo when this binary stands in for it (step 2). Removed
/// before cargo runs, so no test process inherits the stand-in.
pub const SHIM: &str = "BATTEN_CARGO_SHIM";
/// The map file the stand-in selects from.
pub const MAP: &str = "BATTEN_COVER_MAP";
/// cargo-mutants' `mutants.json` for the run, which names each mutant's function.
pub const MUTANTS: &str = "BATTEN_COVER_MUTANTS";
/// The checkout the mutant's copy was taken from, for the unmutated bytes.
pub const ROOT: &str = "BATTEN_COVER_ROOT";
/// Where the recording wrapper writes each test's function list.
pub const DIR: &str = "BATTEN_COVER_DIR";
/// The `llvm-profdata` matching rustc's LLVM.
pub const PROFDATA: &str = "BATTEN_COVER_PROFDATA";
/// The workspace crate names (`-` as `_`) whose functions a record keeps.
pub const CRATES: &str = "BATTEN_COVER_CRATES";
/// The first argument that makes this binary the recording wrapper.
pub const RECORD_ARG: &str = "__cover-record";

const HEADER: &str = "batten-cover 1";

/// Identifier segments of a v0-mangled symbol, from the first workspace crate
/// root onward, or `None` when no workspace crate roots it.
///
/// Not a demangler: a backreference (`B<base62>_`) and a disambiguator
/// (`s<base62>_`) are skipped rather than resolved, and the segments of a
/// foreign type argument are kept. Both only widen a key, so a lookup selects
/// more tests than it needs, never fewer.
#[must_use]
pub fn segments(symbol: &str, crates: &BTreeSet<String>) -> Option<Vec<String>> {
    let bytes = symbol.as_bytes();
    let mut at = 0;
    let mut kept: Option<Vec<String>> = None;
    while at < bytes.len() {
        let byte = bytes[at];
        if (byte == b's' || byte == b'B')
            && bytes.get(at + 1).is_some_and(u8::is_ascii_alphanumeric)
        {
            // `s<base62>_` / `B<base62>_`: skip to the closing underscore.
            match bytes[at + 1..].iter().position(|&b| b == b'_') {
                Some(end) => at += end + 2,
                None => break,
            }
            continue;
        }
        if !byte.is_ascii_digit() {
            at += 1;
            continue;
        }
        let digits = bytes[at..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        let Ok(length) = symbol[at..at + digits].parse::<usize>() else {
            break;
        };
        at += digits;
        if bytes.get(at) == Some(&b'_') {
            at += 1;
        }
        let Some(ident) = symbol.get(at..at + length) else {
            break;
        };
        at += length;
        if ident.is_empty()
            || !ident
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            continue;
        }
        match kept.as_mut() {
            Some(kept) => kept.push(ident.to_owned()),
            None if crates.contains(ident) => kept = Some(Vec::new()),
            None => {}
        }
    }
    kept.filter(|kept| !kept.is_empty())
}

/// The keys of a `llvm-profdata show --covered` listing: one per executed
/// workspace function, its segments joined by `::`.
#[must_use]
pub fn keys_of(listing: &str, crates: &BTreeSet<String>) -> BTreeSet<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("_R"))
        .filter_map(|symbol| segments(symbol, crates))
        .map(|segments| segments.join("::"))
        .collect()
}

/// The module segments a source file's functions sit under: `src/a/b.rs` is
/// `a::b`, a `mod.rs` is its directory, and a crate root (`lib.rs`, `main.rs`)
/// has none.
#[must_use]
pub fn module_of(file: &str) -> Vec<String> {
    let Some((_, inside)) = file.rsplit_once("src/") else {
        return Vec::new();
    };
    let mut parts: Vec<String> = inside
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_owned)
        .collect();
    if parts.last().is_some_and(|last| last == "mod") {
        parts.pop();
    }
    if parts.len() == 1 && matches!(parts[0].as_str(), "lib" | "main") {
        parts.clear();
    }
    parts
}

/// The identifier segments of cargo-mutants' `function_name`: `Type::method`
/// is both, `<impl Trait for Type>::method` keeps the identifiers it names.
#[must_use]
pub fn function_segments(name: &str) -> Vec<String> {
    name.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|part| !part.is_empty() && !matches!(*part, "impl" | "for" | "dyn" | "mut"))
        .map(str::to_owned)
        .collect()
}

/// Whether `key` (a covered function's segments) can be the function named by
/// `module` and `function`: every module segment in order, then the function's
/// last segment after them.
fn key_matches(key: &[&str], module: &[String], function: &str) -> bool {
    let mut rest = key;
    for part in module {
        match rest.iter().position(|seg| seg == part) {
            Some(at) => rest = &rest[at + 1..],
            None => return false,
        }
    }
    rest.contains(&function)
}

/// Every test's covered functions, inverted: which tests cover each key.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Map {
    /// Test names, indexed by id.
    pub tests: Vec<String>,
    /// Each test's nextest binary id (`batten`, `batten::it`), by the same id;
    /// empty where the record did not say.
    pub binaries: Vec<String>,
    /// Covered function key → the ids of the tests that executed it.
    pub keys: BTreeMap<String, BTreeSet<usize>>,
}

impl Map {
    /// Add one test's record: its name and the keys it covered.
    pub fn add(&mut self, test: &str, keys: impl IntoIterator<Item = String>) {
        self.add_in("", test, keys);
    }

    /// Add one test's record with the binary it lives in.
    pub fn add_in(&mut self, binary: &str, test: &str, keys: impl IntoIterator<Item = String>) {
        let id = self.tests.len();
        self.tests.push(test.to_owned());
        self.binaries.push(binary.to_owned());
        for key in keys {
            self.keys.entry(key).or_default().insert(id);
        }
    }

    /// The binaries `tests` live in, or `None` if any of them is unknown, so
    /// a build is narrowed only when every covering case's binary is known.
    #[must_use]
    pub fn binaries_of(&self, tests: &BTreeSet<&str>) -> Option<BTreeSet<&str>> {
        let mut found = BTreeSet::new();
        for (test, binary) in self.tests.iter().zip(&self.binaries) {
            if tests.contains(test.as_str()) {
                if binary.is_empty() {
                    return None;
                }
                found.insert(binary.as_str());
            }
        }
        Some(found)
    }

    /// The tests that cover the function cargo-mutants named, in `file`.
    #[must_use]
    pub fn select(&self, file: &str, function_name: &str) -> BTreeSet<&str> {
        let module = module_of(file);
        let segments = function_segments(function_name);
        let Some(function) = segments.last() else {
            return BTreeSet::new();
        };
        let mut ids = BTreeSet::new();
        for (key, tests) in &self.keys {
            let key: Vec<&str> = key.split("::").collect();
            if key_matches(&key, &module, function) {
                ids.extend(tests.iter().copied());
            }
        }
        ids.into_iter()
            .filter_map(|id| self.tests.get(id).map(String::as_str))
            .collect()
    }

    /// The map as its file holds it.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = format!("{HEADER}\n");
        for (id, (test, binary)) in self.tests.iter().zip(&self.binaries).enumerate() {
            if binary.is_empty() {
                let _ = writeln!(text, "T {id} {test}");
            } else {
                let _ = writeln!(text, "T {id} {test} {binary}");
            }
        }
        for (key, ids) in &self.keys {
            let ids: Vec<String> = ids.iter().map(usize::to_string).collect();
            let _ = writeln!(text, "K {key} {}", ids.join(","));
        }
        text
    }

    /// A map read back from [`Map::render`]'s form; `None` for any other text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != HEADER {
            return None;
        }
        let mut map = Self::default();
        for line in lines {
            let (kind, rest) = line.split_once(' ')?;
            let (first, second) = rest.split_once(' ')?;
            match kind {
                "T" => {
                    if first.parse::<usize>().ok()? != map.tests.len() {
                        return None;
                    }
                    // `name` or `name binary`: neither holds a space.
                    let (case, binary) = second.split_once(' ').unwrap_or((second, ""));
                    map.tests.push(case.to_owned());
                    map.binaries.push(binary.to_owned());
                }
                "K" => {
                    let ids = second
                        .split(',')
                        .map(str::parse::<usize>)
                        .collect::<Result<BTreeSet<_>, _>>()
                        .ok()?;
                    map.keys.insert(first.to_owned(), ids);
                }
                _ => return None,
            }
        }
        Some(map)
    }
}

/// The nextest filterset naming exactly `tests`; `none()` when there are none,
/// so a mutant nothing covers runs nothing and is re-judged by the full pass.
#[must_use]
pub fn filterset(tests: &BTreeSet<&str>) -> String {
    if tests.is_empty() {
        return String::from("none()");
    }
    tests
        .iter()
        .map(|test| format!("test(={test})"))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The first line (1-based) at which `mutated` differs from `original`.
#[must_use]
pub fn first_difference(original: &str, mutated: &str) -> Option<usize> {
    let mut before = original.lines();
    let mut after = mutated.lines();
    let mut line = 1;
    loop {
        match (before.next(), after.next()) {
            (None, None) => return None,
            (left, right) if left != right => return Some(line),
            _ => line += 1,
        }
    }
}

/// One mutant's file, function and span, as cargo-mutants' `mutants.json` holds.
#[derive(Debug, serde::Deserialize)]
struct Mutant {
    file: String,
    function: Option<Function>,
}

#[derive(Debug, serde::Deserialize)]
struct Function {
    function_name: String,
    span: Span,
}

#[derive(Debug, serde::Deserialize)]
struct Span {
    start: Position,
    end: Position,
}

#[derive(Debug, serde::Deserialize)]
struct Position {
    line: usize,
}

/// The function cargo-mutants recorded around `line` of `file`, from the run's
/// `mutants.json` text.
#[must_use]
pub fn function_at(mutants_json: &str, file: &str, line: usize) -> Option<String> {
    let mutants: Vec<Mutant> = serde_json::from_str(mutants_json).ok()?;
    mutants
        .into_iter()
        .filter(|mutant| mutant.file == file)
        .filter_map(|mutant| mutant.function)
        .filter(|function| function.span.start.line <= line && line <= function.span.end.line)
        // The innermost: a closure's span sits inside its function's.
        .min_by_key(|function| function.span.end.line - function.span.start.line)
        .map(|function| function.function_name)
}

/// The mutated file and line in the copy at `copy`, against the checkout at
/// `root` it was copied from.
///
/// # Errors
///
/// The copy is not a repository git can read.
pub fn mutated_line(copy: &Path, root: &Path) -> Result<Option<(String, usize)>> {
    for path in crate::git::changed_paths(copy)? {
        if Path::new(&path)
            .extension()
            .is_none_or(|ext| !ext.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        let mutated = crate::fsio::read_to_string(copy.join(&path)).unwrap_or_default();
        let original = crate::fsio::read_to_string(root.join(&path)).unwrap_or_default();
        if let Some(line) = first_difference(&original, &mutated) {
            return Ok(Some((path, line)));
        }
    }
    Ok(None)
}

/// The cargo target flags that build exactly `binaries` (nextest binary ids:
/// `pkg` is a library's unit tests, `pkg::bin/name`, `pkg::example/name`,
/// `pkg::bench/name`, and `pkg::name` an integration test).
///
/// No covering binary still builds `--lib`, the cheapest build that decides
/// whether the mutant compiles. A mutant in a binary's own source adds
/// `--bins`, since no library target compiles that file.
#[must_use]
pub fn target_args(binaries: &BTreeSet<&str>, mutated_file: &str) -> Vec<String> {
    let mut targets: BTreeSet<Vec<String>> = BTreeSet::new();
    for binary in binaries {
        let target = match binary.split_once("::") {
            None => vec![String::from("--lib")],
            Some((_, rest)) => match rest.split_once('/') {
                Some(("bin", name)) => vec![String::from("--bin"), name.to_owned()],
                Some(("example", name)) => vec![String::from("--example"), name.to_owned()],
                Some(("bench", name)) => vec![String::from("--bench"), name.to_owned()],
                _ => vec![String::from("--test"), rest.to_owned()],
            },
        };
        targets.insert(target);
    }
    if targets.is_empty() {
        targets.insert(vec![String::from("--lib")]);
    }
    if mutated_file.ends_with("src/main.rs") || mutated_file.contains("src/bin/") {
        targets.insert(vec![String::from("--bins")]);
    }
    targets.into_iter().flatten().collect()
}

/// Whether `args` (cargo's, after the program) is a nextest run, the build
/// step (`--no-run`) or the test step alike.
#[must_use]
pub fn is_nextest_run(args: &[std::ffi::OsString]) -> bool {
    args.first().is_some_and(|arg| arg == "nextest") && args.get(1).is_some_and(|arg| arg == "run")
}

/// Whether `args` (cargo's, after the program) is a nextest test run, as
/// opposed to the build step cargo-mutants runs first with `--no-run`.
#[must_use]
pub fn is_test_step(args: &[std::ffi::OsString]) -> bool {
    args.first().is_some_and(|arg| arg == "nextest")
        && args.get(1).is_some_and(|arg| arg == "run")
        && !args.iter().any(|arg| arg == "--no-run")
}

/// The checkout's Rust sources as they stand, copied under `dest`: what each
/// cargo-mutants copy is compared against to find its mutated line.
///
/// NOT THE LIVE CHECKOUT, which a sweep running for hours does not freeze:
/// measured on #1276, one edit to `lib.rs` mid-sweep made its line the "first
/// difference" of every later mutant below it, so each was handed another
/// function's cases, survived them, and fell to the whole-suite pass.
///
/// # Errors
///
/// The checkout cannot be listed, or a source cannot be copied.
pub fn pristine(root: &Path, dest: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dest);
    let mut paths = crate::git::tracked_paths(root)?;
    paths.extend(crate::git::changed_paths(root)?);
    for path in &paths {
        if Path::new(path)
            .extension()
            .is_none_or(|ext| !ext.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        let from = root.join(path);
        if !from.is_file() {
            continue;
        }
        let to = dest.join(path);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&from, &to).with_context(|| format!("copy {path}"))?;
    }
    Ok(())
}

/// What the stand-in adds for the mutant in the working directory: the
/// filterset naming its covering cases, and the target flags building only
/// their binaries (empty when a covering case's binary is unknown). `None` to
/// run cargo's command unchanged: the baseline, or anything the map cannot
/// place.
fn selection() -> Option<(String, Vec<String>)> {
    let map = Map::parse(&crate::fsio::read_to_string(std::env::var_os(MAP)?).ok()?)?;
    let mutants = crate::fsio::read_to_string(std::env::var_os(MUTANTS)?).ok()?;
    let root = PathBuf::from(std::env::var_os(ROOT)?);
    let copy = std::env::current_dir().ok()?;
    let (file, line) = mutated_line(&copy, &root).ok()??;
    let function = function_at(&mutants, &file, line)?;
    let tests = map.select(&file, &function);
    let targets = map
        .binaries_of(&tests)
        .map(|binaries| target_args(&binaries, &file))
        .unwrap_or_default();
    Some((filterset(&tests), targets))
}

/// As cargo-mutants' `$CARGO`: when [`SHIM`] names the real cargo, become it,
/// narrowing the build and test steps alike to the covering tests' binaries,
/// and the test step to the covering tests. `None` when this process is not
/// the stand-in.
pub fn cargo_shimmed(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Option<std::process::ExitCode> {
    let cargo = std::env::var_os(SHIM)?;
    let mut launch: Vec<std::ffi::OsString> = vec![cargo];
    let rest: Vec<std::ffi::OsString> = args.skip(1).collect();
    let narrowed = if is_nextest_run(&rest) {
        selection()
    } else {
        None
    };
    let test_step = is_test_step(&rest);
    launch.extend(rest);
    if let Some((filter, targets)) = narrowed {
        // THE SAME TARGETS FOR BOTH STEPS: a test step naming other targets
        // than its build would compile the rest there instead.
        launch.extend(targets.into_iter().map(std::ffi::OsString::from));
        if test_step {
            launch.extend(["-E".into(), filter.into(), "--no-tests=pass".into()]);
        }
    }
    match crate::exec::become_argv_without(&launch, &[SHIM]) {
        Ok(never) => match never {},
        Err(why) => {
            let _ =
                std::io::Write::write_fmt(&mut std::io::stderr(), format_args!("batten: {why}\n"));
            Some(std::process::ExitCode::from(101))
        }
    }
}

/// The test name in the argv nextest hands a wrapper: `<binary> --exact <name>`.
#[must_use]
pub fn test_name(args: &[String]) -> Option<&str> {
    let at = args.iter().position(|arg| arg == "--exact")?;
    args.get(at + 1).map(String::as_str)
}

/// As nextest's `run-wrapper` under `mutate cover`: run the test with its own
/// profile directory, reduce what executed to keys, and exit as the test did.
/// `None` when this process is not the recorder.
pub fn recorded(args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<String> = args
        .skip(1)
        .filter_map(|arg| arg.into_string().ok())
        .collect();
    if args.first().map(String::as_str) != Some(RECORD_ARG) {
        return None;
    }
    let test: Vec<String> = args[1..].to_vec();
    let code = match record(&test) {
        Ok(code) => code,
        Err(why) => {
            let _ = std::io::Write::write_fmt(
                &mut std::io::stderr(),
                format_args!("batten: cover record: {why:#}\n"),
            );
            101
        }
    };
    Some(std::process::ExitCode::from(code))
}

fn record(test: &[String]) -> Result<u8> {
    let dir = PathBuf::from(std::env::var_os(DIR).context("no cover directory")?);
    let profdata = std::env::var(PROFDATA).context("no llvm-profdata")?;
    let crates: BTreeSet<String> = std::env::var(CRATES)
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    let (program, rest) = test.split_first().context("no test to run")?;
    let name = test_name(test).unwrap_or(program).to_owned();
    let id = blake3::hash(test.join("\u{1f}").as_bytes()).to_hex()[..16].to_owned();
    // RESUMED, NOT REPEATED: a build cut short (a container restart, on
    // #1276, 8,754 cases in) keeps its records, and a case already recorded
    // passes without running again.
    if dir.join("tests").join(&id).is_file() {
        return Ok(0);
    }
    let work = dir.join("work").join(&id);
    std::fs::create_dir_all(&work).with_context(|| format!("create {}", work.display()))?;
    // `%m` WITHOUT `%p`: LLVM merges every process of one binary into one
    // file online. Per-process files (`%p-%m`) are ~12 MB each, and a case
    // that spawns the engine hundreds of times filled the disk mid-map on
    // #1276, so the cover run stopped reporting 513 cases short.
    let pattern = work.join("%m.profraw").to_string_lossy().into_owned();
    let cwd = std::env::current_dir()?;
    let ran = super::spawn_as(
        &cwd,
        super::Program::Test(program),
        rest,
        &[(String::from("LLVM_PROFILE_FILE"), pattern)],
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    let code = match ran.outcome {
        super::Outcome::Passed => 0,
        super::Outcome::Failed(Some(code)) => u8::try_from(code).unwrap_or(101),
        super::Outcome::Failed(None) | super::Outcome::TimedOut => 101,
    };
    let profiles: Vec<String> = std::fs::read_dir(&work)?
        .filter_map(Result::ok)
        .map(|entry| entry.path().to_string_lossy().into_owned())
        .filter(|path| path.ends_with(".profraw"))
        .collect();
    let mut keys = BTreeSet::new();
    if !profiles.is_empty() {
        let merged = work.join("merged.profdata").to_string_lossy().into_owned();
        let mut merge = vec![String::from("merge"), String::from("-sparse")];
        merge.extend(profiles);
        merge.extend([String::from("-o"), merged.clone()]);
        let bound = super::runner_bound();
        let merging = super::spawn(
            &cwd,
            super::Program::Profdata(&profdata),
            &merge,
            &[],
            bound,
        )?;
        if merging.passed() {
            let show = [
                String::from("show"),
                String::from("--all-functions"),
                String::from("--covered"),
                merged,
            ];
            let shown = super::spawn(&cwd, super::Program::Profdata(&profdata), &show, &[], bound)?;
            keys = keys_of(&shown.stdout, &crates);
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    // THE BINARY IT LIVES IN, as nextest names it to the process it runs, so
    // the stand-in can build only that binary for a mutant it covers.
    let binary = std::env::var("NEXTEST_BINARY_ID").unwrap_or_default();
    let mut body = format!("{name}\t{binary}\n");
    for key in keys {
        let _ = writeln!(body, "{key}");
    }
    let tests = dir.join("tests");
    std::fs::create_dir_all(&tests)?;
    crate::durable::replace(tests.join(&id), body)?;
    Ok(code)
}

/// The first argument that makes this binary build the map.
pub const BUILD_ARG: &str = "__cover-build";

/// Where `mutate cargo` reads the map, under the checkout at `root`.
#[must_use]
pub fn map_path(root: &Path) -> PathBuf {
    root.join("target").join("mutants").join("cover.map")
}

/// `batten __cover-build`: run the workspace suite once, instrumented, and write
/// the map `mutate cargo` selects from. `None` when this is not that call.
pub fn built(args: impl Iterator<Item = std::ffi::OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<std::ffi::OsString> = args.skip(1).collect();
    if args.first().is_none_or(|arg| arg != BUILD_ARG) {
        return None;
    }
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let code = match build(&mut out) {
        Ok(()) => 0,
        Err(why) => {
            let _ = std::io::Write::write_fmt(
                &mut err,
                format_args!("::error:: mutate cover: {why:#}\n"),
            );
            3
        }
    };
    Some(std::process::ExitCode::from(code))
}

/// The `llvm-profdata` the toolchain ships for its own LLVM, from its sysroot.
fn profdata(root: &Path) -> Result<PathBuf> {
    let bound = super::runner_bound();
    let args = [String::from("--print"), String::from("sysroot")];
    let sysroot = super::spawn(root, super::Program::Rustc, &args, &[], bound)?;
    let host = super::spawn(
        root,
        super::Program::Rustc,
        &[String::from("-vV")],
        &[],
        bound,
    )?;
    let host = host
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc -vV names no host")?
        .to_owned();
    let tool = PathBuf::from(sysroot.stdout.trim())
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("llvm-profdata");
    anyhow::ensure!(
        tool.is_file(),
        "no {}: run `rustup component add llvm-tools`",
        tool.display()
    );
    Ok(tool)
}

/// The workspace's crate names as symbols spell them (`-` as `_`).
fn workspace_crates(root: &Path) -> Result<BTreeSet<String>> {
    let args = ["metadata", "--no-deps", "--format-version", "1"].map(String::from);
    let ran = super::spawn(
        root,
        super::Program::Cargo,
        &args,
        &[],
        super::runner_bound(),
    )?;
    anyhow::ensure!(ran.passed(), "cargo metadata failed");
    let metadata: serde_json::Value = serde_json::from_str(&ran.stdout)?;
    Ok(metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|package| package["targets"].as_array().into_iter().flatten())
        .filter_map(|target| target["name"].as_str())
        .map(|name| name.replace('-', "_"))
        .collect())
}

/// The repository's nextest config with the recording wrapper and its profile
/// added, so every case keeps the setup scripts and settings it runs under.
///
/// APPENDED AS TEXT, the experimental list alone edited in place: an edited
/// `profile.batten-cover` came out as an INLINE table, which cannot hold the
/// `[[...scripts]]` array, so the wrapper was dropped without an error and the
/// suite ran unrecorded.
fn wrapped_config(root: &Path, recorder: &Path, store: &Path) -> Result<String> {
    let path = root.join(".config").join("nextest.toml");
    let text = crate::fsio::read_to_string(&path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text.parse().context("parse nextest.toml")?;
    let mut experimental = doc
        .get("experimental")
        .and_then(toml_edit::Item::as_array)
        .cloned()
        .unwrap_or_default();
    if !experimental
        .iter()
        .any(|value| value.as_str() == Some("wrapper-scripts"))
    {
        experimental.push("wrapper-scripts");
    }
    doc["experimental"] = toml_edit::value(experimental);
    let recorder = toml_edit::Value::from(recorder.to_string_lossy().into_owned());
    // THE STORE IS NAMED, so the report is where the build reads it: left to
    // nextest, it went under the checkout's `target/`, not the build's.
    let store = toml_edit::Value::from(store.to_string_lossy().into_owned());
    let mut config = doc.to_string();
    let _ = write!(
        config,
        "\n[store]\ndir = {store}\n\n[scripts.wrapper.batten-cover]\ncommand = [{recorder}, \"{RECORD_ARG}\"]\n\n\
         [profile.batten-cover]\nfail-fast = false\nretries = 0\n\n\
         [profile.batten-cover.junit]\npath = \"{JUNIT}\"\n\n\
         [[profile.batten-cover.scripts]]\nfilter = \"all()\"\nrun-wrapper = \"batten-cover\"\n"
    );
    Ok(config)
}

/// The report the cover profile writes, under `<target>/nextest/batten-cover/`.
/// nextest writes it only when the run finishes.
const JUNIT: &str = "cover.xml";

/// How many cases a nextest `JUnit` report says ran: the `tests` of every
/// suite but a setup script's (`@setup-script:…`), which nextest reports as a
/// suite of one and is no case. `None` for a report with no case suite.
#[must_use]
pub fn junit_count(report: &str) -> Option<usize> {
    let mut total = None;
    for suite in report.split("<testsuite ").skip(1) {
        let head = &suite[..suite.find('>')?];
        if head.contains("name=\"@") {
            continue;
        }
        let at = head.find(" tests=\"")? + " tests=\"".len();
        let digits = &head[at..];
        let count: usize = digits[..digits.find('"')?].parse().ok()?;
        total = Some(total.unwrap_or(0) + count);
    }
    total
}

/// A map is complete when every case the run reports recorded what it ran.
/// A run cut short, or a recorder that failed, would leave whole modules out,
/// and every mutant only they reach would go to the whole-suite pass: measured
/// on #1276, a map missing the suite's alphabetical tail (527 of 9,855 cases).
///
/// # Errors
///
/// No report (the run did not finish), or fewer records than cases.
pub fn complete(report: Option<&str>, recorded: usize) -> Result<()> {
    let ran = report
        .and_then(junit_count)
        .context("the cover run wrote no report, so it did not finish")?;
    anyhow::ensure!(
        recorded >= ran,
        "only {recorded} of {ran} case(s) recorded what they executed"
    );
    Ok(())
}

/// Where the instrumented build goes: OUTSIDE `target/`, which the disk
/// collector ranks, because it reclaimed the instrumented test binaries in the
/// middle of the run executing them (6.6 GB, on #1276). Keyed by the checkout,
/// and removed once the map is written.
fn build_dir(root: &Path) -> PathBuf {
    let key = blake3::hash(root.to_string_lossy().as_bytes()).to_hex();
    std::env::temp_dir().join(format!("batten-cover-{}", &key[..12]))
}

fn build(out: &mut dyn std::io::Write) -> Result<()> {
    let root = crate::git::repo_root(Path::new("."))?;
    let tool = profdata(&root)?;
    let crates = workspace_crates(&root)?;
    let work = root.join("target").join("mutants").join("cover-work");
    // Only the in-flight profiles go: the records of a build cut short are
    // kept, and `record` skips every case they already hold.
    let _ = std::fs::remove_dir_all(work.join("work"));
    std::fs::create_dir_all(&work)?;
    let recorder = std::env::current_exe()?;
    let config = work.join("nextest.toml");
    let store = work.join("nextest");
    crate::durable::replace(&config, wrapped_config(&root, &recorder, &store)?)?;
    let crates_list = crates.iter().cloned().collect::<Vec<_>>().join(",");
    let env = [
        (String::from("CARGO_TARGET_DIR"), build_dir(&root)),
        (String::from(DIR), work.clone()),
        (String::from(PROFDATA), tool),
        // THE BUILD'S OWN PROFILES go here, not into the tree: an instrumented
        // build script or proc macro runs while compiling, from the crate's
        // directory, and wrote hundreds of `default_*.profraw` beside the
        // sources. The wrapper overrides this for each case it records.
        (
            String::from("LLVM_PROFILE_FILE"),
            work.join("build").join("%m.profraw"),
        ),
    ]
    .map(|(key, value)| (key, value.to_string_lossy().into_owned()));
    let mut env = env.to_vec();
    env.push((String::from(CRATES), crates_list));
    env.push((
        String::from("RUSTFLAGS"),
        String::from("-C instrument-coverage"),
    ));
    let args = [
        "nextest",
        "run",
        "--workspace",
        "--cargo-profile",
        "mutants",
        "--profile",
        "batten-cover",
        "--no-fail-fast",
        "--config-file",
    ]
    .map(String::from)
    .into_iter()
    .chain([config.to_string_lossy().into_owned()])
    .collect::<Vec<_>>();
    // A FAILING CASE STILL RECORDS what it executed, so the run's own verdict is
    // not this verb's: the map is what it reports.
    let _ = super::spawn_as(
        &root,
        super::Program::Cargo,
        &args,
        &env,
        super::runner_bound(),
        super::Said::Streamed,
    )?;
    let map = collect(&work)?;
    let report = store.join("batten-cover").join(JUNIT);
    let whole = complete(
        crate::fsio::read_to_string(&report).ok().as_deref(),
        map.tests.len(),
    );
    if whole.is_err() {
        let _ = std::fs::remove_dir_all(build_dir(&root));
    }
    whole?;
    let target = map_path(&root);
    crate::durable::replace(&target, map.render())?;
    let _ = std::fs::remove_dir_all(&work);
    let _ = std::fs::remove_dir_all(build_dir(&root));
    writeln!(
        out,
        "mutate cover: {} case(s), {} function(s) at {}",
        map.tests.len(),
        map.keys.len(),
        target.display()
    )?;
    Ok(())
}

/// The map from every record under `dir/tests`.
///
/// # Errors
///
/// The directory cannot be read.
pub fn collect(dir: &Path) -> Result<Map> {
    let mut map = Map::default();
    let mut records: Vec<PathBuf> = std::fs::read_dir(dir.join("tests"))
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    records.sort();
    for file in records {
        let body = crate::fsio::read_to_string(&file).unwrap_or_default();
        let mut lines = body.lines();
        let Some(head) = lines.next() else { continue };
        let (test, binary) = head.split_once('\t').unwrap_or((head, ""));
        map.add_in(binary, test, lines.map(str::to_owned));
    }
    Ok(map)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ours() -> BTreeSet<String> {
        BTreeSet::from([String::from("batten")])
    }

    #[test]
    fn a_symbol_keeps_its_segments_from_the_workspace_crate_on() {
        let free = "_RNvNtCsdzwT5X3ccBr_6batten5rules13validate_rows";
        assert_eq!(segments(free, &ours()).unwrap(), ["rules", "validate_rows"]);
        let closure = "_RNCNvNtCsdzwT5X3ccBr_6batten5rules13validate_rows0B5_";
        assert_eq!(
            segments(closure, &ours()).unwrap(),
            ["rules", "validate_rows"]
        );
        let method = "_RNvMNtCsdzwT5X3ccBr_6batten7collectNtB2_7Request11live_window";
        assert_eq!(
            segments(method, &ours()).unwrap(),
            ["collect", "Request", "live_window"]
        );
        let foreign = "_RNvMNtCs5Ccj3K7tdyC_6rustls12common_stateNtB2_11CommonState5check";
        assert_eq!(segments(foreign, &ours()), None);
    }

    #[test]
    fn a_listing_keeps_only_workspace_functions() {
        let listing = "_RNvNtCsdzwT5X3ccBr_6batten5rules13validate_rows\n\
                       _RNvMNtCs5Ccj3K7tdyC_6rustls12common_stateNtB2_11CommonState5check\n\
                       Functions shown: 2\n";
        assert_eq!(
            keys_of(listing, &ours()),
            BTreeSet::from([String::from("rules::validate_rows")])
        );
    }

    #[test]
    fn a_file_names_its_module_and_a_root_names_none() {
        assert_eq!(module_of("crates/batten/src/collect.rs"), ["collect"]);
        assert_eq!(
            module_of("crates/batten/src/policy/presets.rs"),
            ["policy", "presets"]
        );
        assert_eq!(module_of("crates/batten/src/policy/mod.rs"), ["policy"]);
        assert!(module_of("crates/batten/src/lib.rs").is_empty());
        assert!(module_of("crates/batten/src/main.rs").is_empty());
    }

    #[test]
    fn a_function_name_keeps_its_identifiers() {
        assert_eq!(
            function_segments("Request::live_window"),
            ["Request", "live_window"]
        );
        assert_eq!(
            function_segments("<impl Display for Verdict>::fmt"),
            ["Display", "Verdict", "fmt"]
        );
    }

    #[test]
    fn selection_is_the_tests_covering_that_function_in_that_module() {
        let mut map = Map::default();
        map.add("a", [String::from("collect::Request::live_window")]);
        map.add("b", [String::from("collect::trees")]);
        map.add("c", [String::from("prune::Request::live_window")]);
        map.add("d", [String::from("run_forge_poll")]);
        let file = "crates/batten/src/collect.rs";
        assert_eq!(
            map.select(file, "Request::live_window"),
            BTreeSet::from(["a"])
        );
        assert_eq!(map.select(file, "trees"), BTreeSet::from(["b"]));
        assert!(map.select(file, "absent").is_empty());
        let root = "crates/batten/src/lib.rs";
        assert_eq!(map.select(root, "run_forge_poll"), BTreeSet::from(["d"]));
    }

    #[test]
    fn a_map_survives_its_own_file() {
        let mut map = Map::default();
        map.add("x::one", [String::from("a::f"), String::from("b::g")]);
        map.add("x::two", [String::from("a::f")]);
        assert_eq!(Map::parse(&map.render()), Some(map));
        assert_eq!(Map::parse("not a map"), None);
    }

    #[test]
    fn nothing_covering_selects_nothing_rather_than_everything() {
        assert_eq!(filterset(&BTreeSet::new()), "none()");
        assert_eq!(
            filterset(&BTreeSet::from(["a", "b"])),
            "test(=a) | test(=b)"
        );
    }

    #[test]
    fn the_first_difference_is_the_mutated_line() {
        assert_eq!(first_difference("a\nb\nc\n", "a\nX\nc\n"), Some(2));
        assert_eq!(first_difference("a\nb\n", "a\nb\nc\n"), Some(3));
        assert_eq!(first_difference("a\n", "a\n"), None);
    }

    #[test]
    fn the_innermost_recorded_function_owns_the_line() {
        let json = r#"[
          {"file":"src/a.rs","function":{"function_name":"outer","span":{"start":{"line":1},"end":{"line":20}}}},
          {"file":"src/a.rs","function":{"function_name":"inner","span":{"start":{"line":5},"end":{"line":9}}}},
          {"file":"src/b.rs","function":{"function_name":"other","span":{"start":{"line":1},"end":{"line":99}}}}
        ]"#;
        assert_eq!(function_at(json, "src/a.rs", 6).as_deref(), Some("inner"));
        assert_eq!(function_at(json, "src/a.rs", 15).as_deref(), Some("outer"));
        assert_eq!(function_at(json, "src/a.rs", 40), None);
    }

    #[test]
    fn only_a_test_run_is_narrowed() {
        let args = |words: &[&str]| -> Vec<std::ffi::OsString> {
            words.iter().map(std::ffi::OsString::from).collect()
        };
        assert!(is_test_step(&args(&["nextest", "run", "--package=batten"])));
        assert!(!is_test_step(&args(&["nextest", "run", "--no-run"])));
        assert!(!is_test_step(&args(&["build", "--tests"])));
        assert!(is_nextest_run(&args(&["nextest", "run", "--no-run"])));
        assert!(is_nextest_run(&args(&["nextest", "run"])));
        assert!(!is_nextest_run(&args(&["nextest", "list"])));
        assert!(!is_nextest_run(&args(&["build", "run"])));
    }

    #[test]
    fn the_wrapped_test_is_named_by_its_exact_argument() {
        let args: Vec<String> = ["/t/deps/it-1", "--exact", "engine_pin::init", "--nocapture"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(test_name(&args), Some("engine_pin::init"));
    }

    /// Each binary id names its own target; nothing covering still builds the
    /// library; a binary's own source adds `--bins`.
    ///
    /// Fails by: an id read as the wrong target kind, the empty case building
    /// nothing, or a binary source left unbuilt.
    #[test]
    fn each_binary_names_the_target_that_builds_it() {
        let set = |ids: &[&'static str]| ids.iter().copied().collect::<BTreeSet<&str>>();
        let lib = "crates/batten/src/lib.rs";
        assert_eq!(target_args(&set(&["batten"]), lib), ["--lib"]);
        assert_eq!(target_args(&set(&["batten::it"]), lib), ["--test", "it"]);
        assert_eq!(
            target_args(&set(&["batten::bin/batten"]), lib),
            ["--bin", "batten"]
        );
        assert_eq!(
            target_args(&set(&["batten::example/window-census"]), lib),
            ["--example", "window-census"]
        );
        assert_eq!(
            target_args(&set(&["batten::bench/b"]), lib),
            ["--bench", "b"]
        );
        assert_eq!(
            target_args(&set(&["batten", "batten::it", "batten-fsio"]), lib),
            ["--lib", "--test", "it"],
            "two libraries are one `--lib`"
        );
        assert_eq!(target_args(&set(&[]), lib), ["--lib"]);
        assert_eq!(
            target_args(&set(&["batten::it"]), "crates/batten/src/main.rs"),
            ["--bins", "--test", "it"]
        );
    }

    /// A map narrows only when it knows every covering case's binary, and
    /// keeps the binaries through its own file.
    ///
    /// Fails by: an unknown binary read as known, or the binary dropped by
    /// `render` or `parse`.
    #[test]
    fn binaries_narrow_only_when_every_case_has_one() {
        let mut map = Map::default();
        map.add_in("batten", "a", [String::from("f")]);
        map.add_in("batten::it", "b", [String::from("f")]);
        map.add("c", [String::from("g")]);
        let ab: BTreeSet<&str> = ["a", "b"].into_iter().collect();
        assert_eq!(
            map.binaries_of(&ab),
            Some(["batten", "batten::it"].into_iter().collect())
        );
        let ac: BTreeSet<&str> = ["a", "c"].into_iter().collect();
        assert_eq!(map.binaries_of(&ac), None, "c's binary is unknown");
        assert_eq!(Map::parse(&map.render()), Some(map));
    }

    /// The snapshot holds the tree's Rust sources, tracked or not, and no
    /// other file; a later edit to the checkout leaves it alone, so the
    /// mutated line is found against what the sweep started from.
    ///
    /// Fails by: an untracked source left out, a non-source copied, or the
    /// comparison reading the live checkout.
    #[test]
    fn a_snapshot_is_the_sources_as_the_sweep_found_them() {
        let dir = crate::scratch::scratch("cover-pristine");
        let repo = dir.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(repo.join("notes.txt"), "n\n").unwrap();
        crate::gitwrite::commit_paths(
            &repo,
            &[String::from("src/a.rs"), String::from("notes.txt")],
            "fixture",
        )
        .unwrap();
        std::fs::write(repo.join("src/new.rs"), "fn n() {}\n").unwrap();
        let dest = dir.join("pristine");
        pristine(&repo, &dest).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("src/a.rs")).unwrap(),
            "fn a() {}\n"
        );
        assert!(dest.join("src/new.rs").is_file(), "an untracked source");
        assert!(!dest.join("notes.txt").exists(), "a non-source");
        std::fs::write(repo.join("src/a.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("src/a.rs")).unwrap(),
            "fn a() {}\n",
            "the snapshot does not follow the checkout"
        );
        assert_eq!(
            mutated_line(&repo, &dest).unwrap(),
            Some((String::from("src/a.rs"), 2))
        );
    }

    #[test]
    fn the_report_names_how_many_cases_ran() {
        let report = "<testsuites name=\"nextest-run\" tests=\"9856\">\
                      <testsuite name=\"@setup-script:clear-scratch\" tests=\"1\" disabled=\"0\">\
                      </testsuite><testsuite name=\"batten\" tests=\"3923\" disabled=\"0\">\
                      </testsuite><testsuite name=\"batten::it\" tests=\"5912\" disabled=\"0\">\
                      </testsuite></testsuites>";
        assert_eq!(junit_count(report), Some(9835), "a setup script is no case");
        assert_eq!(
            junit_count("<testsuites tests=\"1\"><testsuite name=\"@setup-script:x\" tests=\"1\">"),
            None
        );
        assert_eq!(junit_count(""), None);
    }

    /// A short or missing record set refuses the map; a whole one passes.
    ///
    /// Fails by: the report's absence read as complete, or `>=` loosened.
    #[test]
    fn a_map_missing_cases_is_refused() {
        let report = "<testsuites tests=\"3\"><testsuite name=\"b\" tests=\"3\">";
        assert!(complete(Some(report), 3).is_ok());
        assert!(complete(Some(report), 4).is_ok());
        assert!(complete(Some(report), 2).is_err());
        assert!(complete(None, 3).is_err());
    }
}
