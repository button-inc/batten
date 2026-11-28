//! No hand-rolled version reader outside the one parser (CLOUD-2906).
//!
//! Every version string batten decides over is semver, and every reader parses
//! it through `crates/batten-base/src/version.rs`. A reader that strips a `v` by
//! hand, splits a dotted version into numbers, or matches one with a digit-run
//! regex reads a pre-release or a build-metadata version wrong, so this census
//! refuses each of those SHAPES.
//!
//! # Why a shape predicate over the syntax, and over every file a crate builds
//!
//! The first census matched eight literal spellings and read only `src/` and
//! `tests/`. The readers this row removed most often were none of them — a
//! split on `.`, `-` or `+` feeding a numeric `parse` — and a build script's
//! module sat outside the files it read (the review of #1293, finding 2). So the
//! Rust half is three predicates over `syn`'s tree (`rules/scanning.md` row
//! two), per function, across every `.rs` file under each workspace member
//! (`build.rs` and `build/` included):
//!
//! - **v-trimmed**: a `trim_start_matches`, `strip_prefix`, `trim_matches`,
//!   `trim_left_matches` or `starts_with` whose argument is the literal `v`;
//! - **dotted-split**: a function that splits on a `.` character (alone or in
//!   an array) AND parses (`parse` as a method or as a path) — a version's
//!   components read by hand;
//! - **version-regex**: a string literal carrying a digit run followed by a
//!   literal dot, the shape of a version pattern.
//!
//! The non-Rust half (task file, task programs, workflows, bootstraps) keeps the
//! shell needles: git's and coreutils' version sorts, `describe` over tags, and a
//! `#v` parameter strip. Needles are assembled from parts so this file never
//! finds itself.
//!
//! `KNOWN` names each remainder with why it stays; each entry must still be
//! found, so the list only shrinks.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// A shape the Rust predicate refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    VTrimmed,
    DottedSplit,
    VersionRegex,
}

impl Shape {
    const fn name(self) -> &'static str {
        match self {
            Self::VTrimmed => "v-trimmed",
            Self::DottedSplit => "dotted-split",
            Self::VersionRegex => "version-regex",
        }
    }
}

/// One function's evidence, folded when the function closes.
#[derive(Default)]
struct Scope {
    splits: Vec<usize>,
    parses: bool,
}

/// Every hit in one file, as `(shape, line)`.
#[derive(Default)]
struct Census {
    hits: Vec<(Shape, usize)>,
    scopes: Vec<Scope>,
}

const SPLITTERS: &[&str] = &[
    "split",
    "splitn",
    "rsplit",
    "rsplitn",
    "split_once",
    "rsplit_once",
    "split_terminator",
];

const V_READERS: &[&str] = &[
    "trim_start_matches",
    "trim_left_matches",
    "trim_matches",
    "strip_prefix",
    "starts_with",
];

/// Whether `expr` is the char or str literal `v`.
fn is_v(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Char(c) => c.value() == 'v',
            syn::Lit::Str(s) => s.value() == "v",
            _ => false,
        },
        _ => false,
    }
}

/// Whether `expr` names the version component separator `'.'`, alone or in an
/// array or a reference to one. A split on `-` or `+` alone is an issue key or a
/// range far more often than a version, and a version's components are only
/// reached by a split on `.`, so the dot is the shape.
fn is_separator(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Lit(lit) => matches!(&lit.lit, syn::Lit::Char(c) if c.value() == '.'),
        syn::Expr::Array(array) => array.elems.iter().any(is_separator),
        syn::Expr::Reference(reference) => is_separator(&reference.expr),
        _ => false,
    }
}

/// Whether a string literal's value is a version-shaped pattern: a digit run
/// (`[0-9]+`, `\d+`) followed by a literal dot.
fn is_version_pattern(value: &str) -> bool {
    // Assembled, so this function's own literals are not the shape it finds.
    let runs = ["[0-9]+", "\\d+"];
    let dots = ["\\.", "[.]"];
    runs.iter().any(|run| {
        dots.iter()
            .any(|dot| value.contains(&format!("{run}{dot}")))
    })
}

impl Census {
    fn open(&mut self) {
        self.scopes.push(Scope::default());
    }

    fn close(&mut self) {
        if let Some(scope) = self.scopes.pop()
            && scope.parses
        {
            self.hits
                .extend(scope.splits.iter().map(|&line| (Shape::DottedSplit, line)));
        }
    }
}

impl<'ast> Visit<'ast> for Census {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.open();
        syn::visit::visit_item_fn(self, node);
        self.close();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.open();
        syn::visit::visit_impl_item_fn(self, node);
        self.close();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.open();
        syn::visit::visit_trait_item_fn(self, node);
        self.close();
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let line = node.method.span().start().line;
        if V_READERS.contains(&method.as_str()) && node.args.iter().any(is_v) {
            self.hits.push((Shape::VTrimmed, line));
        }
        if let Some(scope) = self.scopes.last_mut() {
            if SPLITTERS.contains(&method.as_str()) && node.args.iter().any(is_separator) {
                scope.splits.push(line);
            }
            if method == "parse" {
                scope.parses = true;
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let segments: Vec<String> = node
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if segments.last().is_some_and(|last| last == "parse")
            && let Some(scope) = self.scopes.last_mut()
        {
            scope.parses = true;
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        if is_version_pattern(&node.value()) {
            self.hits
                .push((Shape::VersionRegex, node.span().start().line));
        }
    }
}

/// The Rust shapes `source` carries.
fn rust_hits(source: &str) -> Vec<(Shape, usize)> {
    let file = syn::parse_file(source).expect("every crate source parses");
    let mut census = Census::default();
    census.visit_file(&file);
    census
        .hits
        .sort_by_key(|&(shape, line)| (line, shape.name()));
    census.hits
}

/// The retired shell shapes, each assembled from two parts so the literal never
/// appears whole in this file.
fn needles() -> Vec<String> {
    [
        ["--sort=", "-v:refname"],
        ["sort ", "-V"],
        ["describe ", "--tags"],
        ["#v", "}"],
    ]
    .iter()
    .map(|parts| parts.concat())
    .collect()
}

/// `text` with whole-line `#` comments removed.
fn shell_code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The needles a non-Rust file's code contains.
fn shell_hits(code: &str) -> Vec<String> {
    needles()
        .into_iter()
        .filter(|needle| code.contains(needle.as_str()))
        .collect()
}

/// The remainders that stay, as `(path, shape, why)`.
const KNOWN: &[(&str, &str, &str)] = &[
    (
        "action.yml",
        "#v}",
        "the bootstrap that installs batten: no verb exists yet to call, and it moves an \
         already-parsed pin without ordering or classifying it (row S7, kept)",
    ),
    (
        "crates/batten-facts/src/facts.rs",
        "dotted-split",
        "not a version: a document path `a.b.0.c`, whose numeric segments are list indices",
    ),
    (
        "crates/batten/src/epoch.rs",
        "dotted-split",
        "not a version: a written instant's `secs.nanos`",
    ),
    (
        "crates/batten/src/lib.rs",
        "dotted-split",
        "not a version: a lease token's progress stamp, whose first field is a second",
    ),
    (
        "crates/batten/src/land/receipts.rs",
        "dotted-split",
        "not a version: a receipt file name's `<sealed>.<archive>.<part>` hex halves and an \
         `.at` stamp's integer seconds",
    ),
    (
        "crates/batten/tests/it/step_receipt.rs",
        "dotted-split",
        "not a version: a `stage` line's decimal seconds read as milliseconds",
    ),
    (
        "crates/batten/src/wiring.rs",
        "dotted-split",
        "a real hand-rolled release triple in a test helper, landed on the bundle beside \
         this census; `wiring.rs` is held by another session, so its move to \
         `batten_base::version` is owed there, not done here",
    ),
    (
        "crates/batten/src/wiring.rs",
        "v-trimmed",
        "the same test helper's `strip_prefix('v')`, owed with its dotted-split",
    ),
    (
        "crates/batten-base/src/deferral.rs",
        "dotted-split",
        "Cargo's `rust-version` is a PARTIAL version (`1.98`), not semver, so the semver \
         parser would refuse every valid value (row R30, kept)",
    ),
];

/// The file the parser lives in: the one place a version is read.
const PARSER: &str = "crates/batten-base/src/version.rs";

/// Every `.rs` file under `dir`, `target/` excluded.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn relative(path: &Path) -> String {
    let root = common::at_root("").canonicalize().unwrap();
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    path.strip_prefix(&root)
        .map_or_else(|_| path.clone(), Path::to_path_buf)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every Rust file a workspace member builds: its whole directory, so a build
/// script and anything it includes by `#[path]` are read with `src/`.
fn rust_corpus() -> Vec<String> {
    let mut found = Vec::new();
    for member in common::workspace_members() {
        rust_files(&member, &mut found);
    }
    let mut files: Vec<String> = found.iter().map(|path| relative(path)).collect();
    files.sort();
    files
}

/// Every non-Rust file the census reads.
fn shell_corpus() -> Vec<String> {
    let mut files = Vec::new();
    for dir in [".github/workflows", "mise-tasks"] {
        for entry in std::fs::read_dir(common::at_root(dir)).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            if path.is_file() {
                files.push(relative(&path));
            }
        }
    }
    for file in ["mise.toml", "hk.pkl", "install.sh", "action.yml"] {
        files.push(file.to_owned());
    }
    files.sort();
    files
}

#[test]
fn no_hand_rolled_version_reading_outside_the_parser() {
    let mut found = Vec::new();
    let mut known_seen = vec![false; KNOWN.len()];
    let mut note = |file: &str, shape: &str, at: String| match KNOWN
        .iter()
        .position(|(path, known, _)| *path == file && *known == shape)
    {
        Some(index) => known_seen[index] = true,
        None => found.push(format!("{file}:{at} {shape}")),
    };

    let rust = rust_corpus();
    // ANTI-VACUITY: the corpus is the whole workspace, build scripts included.
    assert!(
        rust.len() > 300,
        "the census read {} Rust files",
        rust.len()
    );
    assert!(
        rust.iter().any(|file| file.ends_with("/build.rs")),
        "the census reads no build script: {rust:?}"
    );
    for file in &rust {
        if file == PARSER {
            continue;
        }
        let source = std::fs::read_to_string(common::at_root(file)).unwrap();
        for (shape, line) in rust_hits(&source) {
            note(file, shape.name(), line.to_string());
        }
    }
    for file in &shell_corpus() {
        let Ok(text) = std::fs::read_to_string(common::at_root(file)) else {
            continue;
        };
        for needle in shell_hits(&shell_code(&text)) {
            note(file, &needle, String::new());
        }
    }
    assert!(
        found.is_empty(),
        "{} hand-rolled version reader(s); parse through `batten_base::version` \
         instead: {found:#?}",
        found.len()
    );
    let stale: Vec<&str> = KNOWN
        .iter()
        .zip(&known_seen)
        .filter(|(_, seen)| !**seen)
        .map(|((path, _, _), _)| *path)
        .collect();
    assert!(
        stale.is_empty(),
        "a KNOWN remainder is gone, so its entry goes too: {stale:?}"
    );
}

/// The census can fail: each shape, seeded into a function, is found; the same
/// text in a comment is not; and the near misses (a split on `,` that parses, a
/// dotted split that never parses, a `w` trimmed) are not.
#[test]
fn every_shape_is_found_and_its_near_misses_are_not() {
    let shapes = |source: &str| -> Vec<&'static str> {
        rust_hits(source)
            .into_iter()
            .map(|(shape, _)| shape.name())
            .collect()
    };
    assert_eq!(
        shapes("fn f(t: &str) { let _ = t.trim_start_matches('v'); }"),
        ["v-trimmed"]
    );
    assert_eq!(
        shapes("fn f(t: &str) { let _ = t.strip_prefix(\"v\"); }"),
        ["v-trimmed"]
    );
    assert_eq!(
        shapes(
            "fn f(t: &str) -> Vec<u64> { t.split(['-', '+']).next().unwrap().split('.')\
             .map(str::parse).collect::<Result<_, _>>().unwrap() }"
        ),
        ["dotted-split"]
    );
    assert_eq!(
        shapes("fn f(t: &str) { let _ = t.split_once('.').map(|(a, _)| a.parse::<u64>()); }"),
        ["dotted-split"]
    );
    assert_eq!(
        shapes(r#"fn f() { let _ = regex::Regex::new(r"^v[0-9]+\.[0-9]+$"); }"#),
        ["version-regex"]
    );
    // Near misses.
    assert!(shapes("fn f(t: &str) { let _ = t.split(',').map(str::parse::<u64>); }").is_empty());
    assert!(shapes("fn f(t: &str) { let _ = t.split('.').count(); }").is_empty());
    assert!(
        shapes("fn f(t: &str) { let _ = t.split_once('-').map(|(_, n)| n.parse::<u64>()); }")
            .is_empty()
    );
    assert!(shapes("fn f(t: &str) { let _ = t.trim_start_matches('w'); }").is_empty());
    assert!(shapes("// t.trim_start_matches('v')\nfn f() {}").is_empty());
    // The shell half.
    for needle in needles() {
        assert_eq!(
            shell_hits(&shell_code(&format!("x {needle}\n"))),
            std::slice::from_ref(&needle)
        );
        assert!(shell_hits(&shell_code(&format!("# {needle}\n"))).is_empty());
    }
}
