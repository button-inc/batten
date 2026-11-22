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
    // `fix <package>…`: apply rustc's machine-applicable suggestions to a
    // fixpoint, imports decided per build and per package
    // (`batten_codemods::fix`).
    if asked == "fix" {
        let scope: Vec<String> = args.collect();
        return run_fix(&mut out, &scope);
    }
    // `levels [src]` and `suggest [src] [n]`: the module graph's structure,
    // as counts and module names (Lakos levels, propagation cost, and the
    // edges whose cut shrinks the largest cycle).
    if asked == "levels" || asked == "suggest" {
        let src = args
            .next()
            .unwrap_or_else(|| String::from("crates/batten/src"));
        let graph = batten::module_graph::read(std::path::Path::new(&src))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if asked == "levels" {
            let levels = graph.levels();
            let top = levels.values().max().copied().unwrap_or(0);
            writeln!(
                out,
                "levels: {} module(s), {top} level(s), largest component {}, propagation cost {:.1}%",
                levels.len(),
                graph.largest_component(),
                graph.propagation_cost()
            )?;
            for level in 1..=top {
                let count = levels.values().filter(|at| **at == level).count();
                writeln!(out, "level {level}: {count}")?;
            }
            return Ok(());
        }
        let shown: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(20);
        let largest = graph.largest_component();
        for (from, to, left) in graph.cut_ranking().into_iter().take(shown) {
            writeln!(
                out,
                "{from} -> {to}: largest component {left} (now {largest})"
            )?;
        }
        return Ok(());
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
fn check_stream(verb: &[&str], units: &[&str], scope: &[String]) -> std::io::Result<String> {
    use batten::capture::Streamed as _;
    #[expect(
        clippy::disallowed_types,
        reason = "stays: asking the compiler for its diagnostics is this mode's whole input; the codemods crate is never released"
    )]
    let mut command = std::process::Command::new("cargo");
    let output = command
        .args(verb)
        .args(["--message-format", "json"])
        .args(units)
        .args(scope)
        .streamed_output()?;
    let stream = String::from_utf8_lossy(&output.stdout).into_owned();
    // Could-not-look, never "nothing to fix" (`recipe::fix::read_nothing`).
    if recipe::fix::read_nothing(output.status.success(), &stream) {
        return Err(std::io::Error::other(format!(
            "cargo {} exited {} with no compiler message; nothing was read, nothing applied",
            verb.join(" "),
            output.status
        )));
    }
    Ok(stream)
}

/// Plan and apply passes until one changes nothing; one count line per pass.
fn run_fix(out: &mut impl std::io::Write, scope: &[String]) -> std::io::Result<()> {
    let read = |path: &str| batten::fsio::read_to_string(path).ok();
    // No package named means no stream is read, which printed "applied 0" as if
    // the workspace had been judged clean.
    if scope.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fix needs at least one package: `fix <package>…`",
        ));
    }
    for pass in 1..=FIX_PASSES {
        // PER PACKAGE, EACH STREAM FILTERED TO THAT PACKAGE'S OWN MESSAGES.
        // `check --profile test` does not set `cfg(test)`; `test --no-run
        // --bins` and any `--workspace` build compile a library non-test as a
        // dependency, so its warnings repeat in the test stream. Measured on
        // the third real run: unit-test held 8 `unused_imports` to non-test's
        // 5, and `VerdictProgram` and `Applicability` were deleted again. In
        // `test --no-run --lib -p P` filtered to `P`, the only unit of `P` is
        // its library test unit.
        let (mut non_test, mut unit_test, mut other) =
            (String::new(), String::new(), String::new());
        for package in scope {
            let only = ["-p".to_owned(), package.clone()];
            let pick = |stream: String| recipe::fix::only_package(&stream, package);
            non_test.push_str(&pick(check_stream(&["check"], &["--lib"], &only)?));
            unit_test.push_str(&pick(check_stream(
                &["test", "--no-run"],
                &["--lib"],
                &only,
            )?));
            other.push_str(&pick(check_stream(
                &["check"],
                &["--bins", "--tests", "--examples", "--benches"],
                &only,
            )?));
        }
        let streams = recipe::fix::Streams {
            non_test: &non_test,
            unit_test: &unit_test,
            other: &other,
        };
        // Each stream's `unused_imports` count, so a stream that is empty or
        // carries another unit's warnings shows in the output, not in a
        // deleted import.
        let unused = |stream: &str| stream.matches("\"unused_imports\"").count();
        writeln!(
            out,
            "fix pass {pass} streams: non-test {}, unit-test {}, other {}",
            unused(&non_test),
            unused(&unit_test),
            unused(&other)
        )?;
        let plan = recipe::fix::plan(streams, &read);
        // A build that does not compile is not one to edit (`recipe::fix::may_apply`).
        if !recipe::fix::may_apply(&plan) {
            writeln!(
                out,
                "fix pass {pass}: applied 0, refused all, errors {}",
                plan.errors
            )?;
            return Err(std::io::Error::other(format!(
                "the build carries {} compile error(s); fix them first, nothing was applied",
                plan.errors
            )));
        }
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
