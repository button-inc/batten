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
    let Some(chosen) = args.next().and_then(|name| recipe::named(&name)) else {
        for known in recipe::RECIPES {
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

/// Every `.rs` file under `dir`, fixtures and build output excluded: a fixture
/// is input data some case reads byte for byte, never code to migrate.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !path
                .file_name()
                .is_some_and(|name| name == "fixtures" || name == "target")
            {
                found.extend(walk(&path));
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}
