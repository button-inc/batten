//! Run one saved codemod recipe ([`batten_codemods`]) over a tree.
//!
//! `cargo run --release -q -p batten-codemods --example codemod -- <recipe> [root]`, `root`
//! defaulting to `crates/batten`. Files under a crate's `src/` name it `crate`;
//! tests, examples and benches name it `batten`. Prints counts only, never the
//! diff. With no recipe named, lists them. A file that cannot be read, parsed
//! or written is counted as refused, never skipped silently.

use std::io::Write as _;

use batten_codemods as recipe;

fn main() -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    let mut args = std::env::args().skip(1);
    let asked = args.next().unwrap_or_default();
    // `impl-plan <src>`: one pointer per impl `move-impl-home` would weigh,
    // written nowhere. The evidence for choosing a remedy per impl.
    if asked == "impl-plan" {
        let src = args
            .next()
            .unwrap_or_else(|| String::from("crates/batten/src"));
        let root = std::path::Path::new(".");
        let files: std::collections::BTreeMap<String, String> = walk(&root.join(&src))
            .into_iter()
            .filter_map(|path| {
                let text = batten::fsio::read_to_string(&path).ok()?;
                let key = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                Some((key, text))
            })
            .collect();
        for line in batten::module_graph::impl_plan(&src, &files) {
            writeln!(out, "{line}")?;
        }
        return Ok(());
    }
    // `fix [cargo args…]`: apply rustc's machine-applicable suggestions to a
    // fixpoint, imports decided per build (`batten_codemods::fix`).
    if asked == "fix" {
        let scope: Vec<String> = args.collect();
        return run_fix(&mut out, &scope);
    }
    if let Some(chosen) = recipe::named_tree(&asked) {
        let root = args.next().unwrap_or_else(|| String::from("."));
        return run_tree(&mut out, chosen, std::path::Path::new(&root));
    }
    let Some(chosen) = recipe::named(&asked) else {
        for known in recipe::RECIPES {
            writeln!(out, "{}\t{}", known.name, known.summary)?;
        }
        for known in recipe::TREE_RECIPES {
            writeln!(out, "{}\t{}", known.name, known.summary)?;
        }
        return Ok(());
    };
    let root = args.next().unwrap_or_else(|| String::from("crates/batten"));
    let (mut read, mut rewritten, mut refused) = (0_usize, 0_usize, 0_usize);
    for path in walk(std::path::Path::new(&root)) {
        let spelled = path.to_string_lossy();
        if chosen.skip.iter().any(|suffix| spelled.ends_with(suffix)) {
            continue;
        }
        let Ok(text) = batten::fsio::read_to_string(&path) else {
            refused += 1;
            continue;
        };
        read += 1;
        let base = if spelled.contains("/src/") {
            "crate"
        } else {
            "batten"
        };
        match (chosen.apply)(&text, base) {
            Ok(edited) if edited != text => {
                if batten::durable::replace(&path, edited).is_ok() {
                    rewritten += 1;
                } else {
                    refused += 1;
                }
            }
            Ok(_) => {}
            Err(_) => refused += 1,
        }
    }
    writeln!(
        out,
        "{}: files read {read}, rewritten {rewritten}, refused {refused}",
        chosen.name
    )
}

/// A tree recipe over `root`: every `.rs` file and every `Cargo.toml` read
/// once, keyed by their path relative to `root`, then each changed file
/// written. A file that cannot be read is refused and the run writes nothing,
/// since a resolver missing a file could respell a path to the wrong home.
fn run_tree(
    out: &mut impl std::io::Write,
    chosen: &recipe::TreeRecipe,
    root: &std::path::Path,
) -> std::io::Result<()> {
    let (mut files, mut manifests) = (
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::new(),
    );
    let mut refused = 0_usize;
    for path in walk_matching(root, &|path| {
        path.extension().is_some_and(|ext| ext == "rs")
            || path.file_name().is_some_and(|name| name == "Cargo.toml")
    }) {
        let Ok(text) = batten::fsio::read_to_string(&path) else {
            refused += 1;
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if relative.ends_with("Cargo.toml") {
            manifests.insert(relative, text);
        } else {
            files.insert(relative, text);
        }
    }
    if refused > 0 {
        return writeln!(
            out,
            "{}: files read {}, rewritten 0, refused {refused}",
            chosen.name,
            files.len()
        );
    }
    let mut rewritten = 0_usize;
    for (relative, edited) in (chosen.apply)(&files, &manifests) {
        if chosen.skip.iter().any(|suffix| relative.ends_with(suffix)) {
            continue;
        }
        // A recipe may create a file (a split module), whose directory may
        // not exist yet.
        let target = root.join(&relative);
        let parent_ready = target
            .parent()
            .is_none_or(|parent| std::fs::create_dir_all(parent).is_ok());
        if parent_ready && batten::durable::replace(&target, edited).is_ok() {
            rewritten += 1;
        } else {
            refused += 1;
        }
    }
    writeln!(
        out,
        "{}: files read {}, rewritten {rewritten}, refused {refused}",
        chosen.name,
        files.len()
    )
}

/// The most passes `fix` runs: each pass is two `cargo check`s, and a
/// suggestion that keeps reappearing must not loop forever.
const FIX_PASSES: usize = 8;

/// `cargo check` over `units` (`--lib --bins` or `--tests --examples
/// --benches`) plus the caller's `scope`, as cargo's JSON stream.
fn check_stream(units: &[&str], scope: &[String]) -> std::io::Result<String> {
    use batten::capture::Streamed as _;
    #[expect(
        clippy::disallowed_types,
        reason = "stays: asking the compiler for its diagnostics is this mode's whole input; the codemods crate is never released"
    )]
    let mut command = std::process::Command::new("cargo");
    let output = command
        .args(["check", "--message-format", "json"])
        .args(units)
        .args(scope)
        .streamed_output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Plan and apply passes until one changes nothing; one count line per pass.
fn run_fix(out: &mut impl std::io::Write, scope: &[String]) -> std::io::Result<()> {
    let read = |path: &str| batten::fsio::read_to_string(path).ok();
    for pass in 1..=FIX_PASSES {
        let non_test = check_stream(&["--lib", "--bins"], scope)?;
        let test = check_stream(&["--tests", "--examples", "--benches"], scope)?;
        let plan = recipe::fix::plan(&non_test, &test, &read);
        let (mut applied, mut refused) = (0_usize, 0_usize);
        for (path, suggestions) in &plan.edits {
            let written = read(path)
                .and_then(|text| recipe::fix::apply(&text, suggestions).ok())
                .is_some_and(|text| {
                    batten::durable::replace(std::path::Path::new(path), text).is_ok()
                });
            if written {
                applied += suggestions.len();
            } else {
                refused += 1;
            }
        }
        writeln!(
            out,
            "fix pass {pass}: applied {applied}, gated {}, left {}, refused {refused}, errors {}",
            plan.gated, plan.left, plan.errors
        )?;
        if applied == 0 {
            return Ok(());
        }
    }
    writeln!(out, "fix: stopped after {FIX_PASSES} passes")
}

/// Every `.rs` file under `dir`, fixtures and build output excluded: a fixture
/// is input data some case reads byte for byte, never code to migrate.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    walk_matching(dir, &|path| path.extension().is_some_and(|ext| ext == "rs"))
}

/// Every file under `dir` that `keep` accepts, skipping fixtures, build
/// output and hidden directories.
fn walk_matching(
    dir: &std::path::Path,
    keep: &dyn Fn(&std::path::Path) -> bool,
) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !path.file_name().is_some_and(|name| {
                name == "fixtures" || name == "target" || name.to_string_lossy().starts_with('.')
            }) {
                found.extend(walk_matching(&path, keep));
            }
        } else if keep(&path) {
            found.push(path);
        }
    }
    found
}
