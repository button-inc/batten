//! Build-time tables (CLOUD-2224).
//!
//! The `o200k_base` vocabulary as a static table in the binary's read-only
//! data, so counting tokens in a hook process never BUILDS the vocabulary:
//! measured, building it at runtime cost 120-165 ms and ~53 MiB per process
//! (tiktoken-rs) or 56-65 ms and ~70 MiB (bpe-openai), against a whole hook call
//! at p50 21-31 ms. Here it is built once, at compile time, from tiktoken-rs,
//! the one source of both the vocabulary and the pre-tokenizer pattern.
//!
//! `o200k.bin`, little-endian `u32`s then bytes:
//! `count`, `offsets[count + 1]` into the blob, `ranks[count]`, the blob — the
//! entries sorted by their bytes, so a rank is a binary search over the blob.
//!
//! No test target compiles this file; what it writes is judged where it is
//! read, by `o200k`'s parity case against tiktoken itself.
//!
//! It STAMPS THE BUILD'S IDENTITY (CLOUD-2903) as `BATTEN_BUILD_VERSION`, the
//! one value `config::VERSION` reads: the package version for the release
//! build `BATTEN_RELEASE_TAG` marks, a dev pre-release for every other build
//! (`src/build_identity.rs` decides; this script only gathers the facts).
//!
//! It also REFUSES TO BUILD a crate carrying a hand-written Rust mutation
//! marker or a second cargo-mutants argv ([`mutation_markers`], CLOUD-2253):
//! the Rust tier is cargo-mutants' alone, and a build is the one step nothing
//! skips.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[path = "src/mutation_markers.rs"]
mod mutation_markers;

// `pub` for the library, which declares the same file as `pub mod
// build_identity` so an integration case can render an identity; here it is
// a private module, where that visibility reaches nothing.
#[expect(
    unreachable_pub,
    reason = "the library exports these items; only this script's private copy cannot reach them (CLOUD-2903)"
)]
#[path = "src/build_identity.rs"]
mod identity;

/// The two special tokens: never produced by ordinary encoding, so never in
/// the merge table.
const SPECIAL_RANKS: [u32; 2] = [199_999, 200_018];

type Built = Result<(), Box<dyn std::error::Error>>;

fn main() -> Built {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or("cargo sets CARGO_MANIFEST_DIR")?,
    );
    // BEFORE the tables' early return below: a rerun that returned there first
    // would leave `env!("BATTEN_BUILD_VERSION")` unset.
    stamp_identity(&manifest)?;
    refuse_hand_rolled_mutation(&manifest)?;
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("cargo sets OUT_DIR")?);
    // THE TABLES ARE BUILT ONCE PER `OUT_DIR`, which cargo keys on this package
    // and its dependencies: the scan above reruns this script on every source
    // edit, and rebuilding a 200k-entry table each time would put seconds on
    // every build for bytes that cannot have changed.
    if ["o200k.bin", "o200k_dfa.bin", "o200k_pattern.rs"]
        .iter()
        .all(|file| out.join(file).is_file())
    {
        return Ok(());
    }
    let bpe = tiktoken_rs::o200k_base()?;
    let mut entries: Vec<(Vec<u8>, u32)> = (0..=200_018_u32)
        .filter(|rank| !SPECIAL_RANKS.contains(rank))
        .filter_map(|rank| bpe.decode_bytes(&[rank]).ok().map(|bytes| (bytes, rank)))
        .collect();
    entries.sort_unstable();
    let count = u32::try_from(entries.len())?;
    let mut offsets = Vec::with_capacity(entries.len() + 1);
    let mut blob = Vec::new();
    for (bytes, _) in &entries {
        offsets.push(u32::try_from(blob.len())?);
        blob.extend_from_slice(bytes);
    }
    offsets.push(u32::try_from(blob.len())?);
    let mut table = Vec::with_capacity(4 + offsets.len() * 4 + entries.len() * 4 + blob.len());
    table.extend_from_slice(&count.to_le_bytes());
    for offset in &offsets {
        table.extend_from_slice(&offset.to_le_bytes());
    }
    for (_, rank) in &entries {
        table.extend_from_slice(&rank.to_le_bytes());
    }
    table.extend_from_slice(&blob);
    std::fs::write(out.join("o200k.bin"), &table)?;
    // THE PRE-TOKENIZER AS A DFA, built here so no process compiles a regex
    // (measured at 4.7-6.7 ms per process with fancy-regex, against a 10 ms hook
    // target). o200k's one lookahead alternative, `\s+(?!\S)`, is not
    // DFA-expressible: it becomes `\s+`, and `o200k::pieces` trims a run that
    // the lookahead would have left one character short.
    let lookahead = r"|\s+(?!\S)|\s+";
    let source = tiktoken_rs::O200K_BASE_PAT_STR;
    if !source.ends_with(lookahead) {
        return Err(format!("o200k's pattern changed shape: {source}").into());
    }
    let plain = format!("{}|\\s+", source.trim_end_matches(lookahead));
    let dfa = regex_automata::dfa::dense::Builder::new()
        .configure(
            regex_automata::dfa::dense::Config::new()
                .start_kind(regex_automata::dfa::StartKind::Anchored),
        )
        .build(&plain)?
        .to_sparse()?;
    std::fs::write(out.join("o200k_dfa.bin"), dfa.to_bytes_little_endian())?;
    let mut pattern = std::fs::File::create(out.join("o200k_pattern.rs"))?;
    writeln!(
        pattern,
        "/// `o200k_base`'s pre-tokenizer, copied from tiktoken-rs at build time.\npub const PATTERN: &str = {:?};",
        tiktoken_rs::O200K_BASE_PAT_STR
    )?;
    Ok(())
}

/// Emit `BATTEN_BUILD_VERSION`, and the rerun triggers that keep it current.
///
/// The marked release build runs no git at all. Any other build gathers HEAD's
/// branch, committer second and source digest; where git answers nothing the
/// identity is `<next>-dev.unknown`, so no build fails for want of git, and a
/// tracked input that will not read drops only the digest, with one warning.
fn stamp_identity(manifest: &Path) -> Built {
    for name in [
        identity::RELEASE_MARKER,
        identity::BUILD_PR,
        identity::BUILD_COMMITTED,
        identity::BUILD_LINE,
        identity::BUILD_SOURCE_TRACKED,
        "GITHUB_REF",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let mut facts = identity::Facts {
        package: std::env::var("CARGO_PKG_VERSION")?,
        marker: std::env::var(identity::RELEASE_MARKER)
            .ok()
            .filter(|marker| !marker.is_empty()),
        line: None,
        committed: None,
        digest: None,
    };
    if facts.marker.is_none()
        && let Some(top) = git_text(manifest, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
    {
        watch(&top);
        let branch = git_text(&top, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
        facts.line = Some(identity::line(
            std::env::var(identity::BUILD_PR).ok().as_deref(),
            std::env::var("GITHUB_REF").ok().as_deref(),
            branch.as_deref(),
        )?);
        facts.committed =
            git_text(&top, &["show", "-s", "--format=%ct", "HEAD"]).and_then(|ct| ct.parse().ok());
        facts.digest = digest(&top);
    } else if facts.marker.is_none()
        && let Some(committed) = std::env::var(identity::BUILD_COMMITTED)
            .ok()
            .and_then(|committed| committed.parse().ok())
    {
        // A SOURCE BUILD WITH NO GIT (nix, CLOUD-2903): the builder names the
        // commit second and the line, and a builder whose source IS the tracked
        // tree lets the digest be folded from the directory. So a flake build
        // reports `<next>-dev.nix.<ts>+<digest>`, honest about being a source
        // build and naming its tree, rather than `dev.unknown`.
        facts.committed = Some(committed);
        facts.line = Some(identity::line(
            std::env::var(identity::BUILD_PR).ok().as_deref(),
            None,
            std::env::var(identity::BUILD_LINE).ok().as_deref(),
        )?);
        if std::env::var(identity::BUILD_SOURCE_TRACKED).is_ok_and(|tracked| tracked == "1") {
            facts.digest = manifest
                .parent()
                .and_then(Path::parent)
                .and_then(digest_of_directory);
        }
    }
    println!(
        "cargo:rustc-env=BATTEN_BUILD_VERSION={}",
        identity::identity(&facts)?
    );
    Ok(())
}

/// Watch every input the identity reads, ONLY WHERE IT EXISTS: cargo reads a
/// missing `rerun-if-changed` path as stale on every build. HEAD's ref file is
/// never named (it is missing exactly when the ref is packed): `refs/heads` is
/// watched as a directory, which cargo scans recursively, so a commit on any
/// branch is seen, and a detached commit rewrites `HEAD`.
fn watch(top: &Path) {
    let mut watched: Vec<PathBuf> = ["crates", "Cargo.toml", "Cargo.lock"]
        .iter()
        .map(|path| top.join(path))
        .collect();
    let named = ["HEAD", "index", "packed-refs", "refs/heads", "reftable"];
    let mut argv = vec!["rev-parse"];
    for path in named {
        argv.extend(["--git-path", path]);
    }
    if let Some(paths) = git_text(top, &argv) {
        watched.extend(paths.lines().map(|path| top.join(path)));
    }
    for path in watched.iter().filter(|path| path.exists()) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// The first [`identity::DIGEST_HEX`] hex of the source digest over the
/// INDEX's engine inputs, as `engine stamp` computes it: tracked membership,
/// the bytes on disk. `None` when git answers nothing, there is no input, or a
/// tracked input will not read (deleted but not yet `git rm`'d), which prints
/// one warning naming it.
fn digest(top: &Path) -> Option<String> {
    let listed = git(
        top,
        &["ls-files", "-z", "--", "crates", "Cargo.toml", "Cargo.lock"],
    )?;
    let mut inputs = BTreeMap::new();
    for raw in listed
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let Ok(path) = std::str::from_utf8(raw) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(top.join(path)) else {
            println!(
                "cargo:warning=batten's build identity carries no source digest: {path} is tracked and will not read"
            );
            return None;
        };
        inputs.insert(path.to_owned(), bytes);
    }
    identity::source_digest(&inputs).map(|digest| digest[..identity::DIGEST_HEX].to_owned())
}

/// [`digest`] over a source directory that IS the tracked tree (a flake's
/// `src = self`): every file under `crates/`, plus `Cargo.toml` and
/// `Cargo.lock`, by its `/`-joined relative path. `None` when one will not read.
fn digest_of_directory(top: &Path) -> Option<String> {
    let mut files = Vec::new();
    every_file(&top.join("crates"), &mut files);
    files.extend(["Cargo.toml", "Cargo.lock"].map(|name| top.join(name)));
    let mut inputs = BTreeMap::new();
    for path in files {
        let relative = path
            .strip_prefix(top)
            .ok()?
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        inputs.insert(relative, std::fs::read(&path).ok()?);
    }
    identity::source_digest(&inputs).map(|digest| digest[..identity::DIGEST_HEX].to_owned())
}

/// Every file under `dir`, recursively, `target/` excluded.
fn every_file(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "target") {
                every_file(&path, into);
            }
        } else {
            into.push(path);
        }
    }
}

/// `git -C dir args`'s stdout, trimmed, or `None` for a failure or nothing.
fn git_text(dir: &Path, args: &[&str]) -> Option<String> {
    let text = String::from_utf8(git(dir, args)?).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// `git -C dir args`'s stdout, or `None` when git will not run or fails.
fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: a build script reaches neither `crate::git` nor `batten::stream`, and `gix` as a build-dependency would compile a second copy for the host (CLOUD-2903)"
    )]
    let mut command = std::process::Command::new("git");
    command.arg("-C").arg(dir).args(args);
    #[expect(
        clippy::disallowed_methods,
        reason = "stays: the one spawn above, read to completion; the build script has no stream wrapper (CLOUD-2903)"
    )]
    let output = command.output().ok()?;
    output.status.success().then_some(output.stdout)
}

/// Refuse the build where the crate's Rust carries a mutation marker anywhere, or
/// builds a cargo-mutants argv outside its one site ([`mutation_markers`]).
/// Pointers only: `path:line`, never the line (rule 4).
fn refuse_hand_rolled_mutation(manifest: &Path) -> Built {
    let mut sources = Vec::new();
    for dir in ["src", "tests", "benches", "examples"] {
        let root = manifest.join(dir);
        // ONLY A DIRECTORY THAT EXISTS IS WATCHED: cargo reads a missing
        // `rerun-if-changed` path as stale on every build, which reran this
        // script and rebuilt the library on every mutation row (75s a row).
        if !root.is_dir() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", root.display());
        rust_files(&root, &mut sources);
    }
    sources.push(manifest.join("build.rs"));
    let mut markers = Vec::new();
    let mut argv_sites = Vec::new();
    for path in &sources {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        // `/`-joined on every host: `display()` renders `src\mutate.rs` on
        // Windows, which never equals `CARGO_MUTANTS_SITE` and failed the
        // one-site check on the file it names (x86_64-pc-windows-gnu dist).
        let relative = path
            .strip_prefix(manifest)
            .unwrap_or(path)
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        markers.extend(
            mutation_markers::marker_lines(&text)
                .into_iter()
                .map(|line| format!("{relative}:{line}")),
        );
        let argv = text.matches(mutation_markers::CARGO_MUTANTS_ARGV).count();
        if argv > 0 {
            argv_sites.push((relative, argv));
        }
    }
    if !markers.is_empty() {
        return Err(format!(
            "hand-written Rust mutation marker(s) at {}: cargo-mutants owns every Rust source and \
             reads none of them (CLOUD-2253); delete them",
            markers.join(", ")
        )
        .into());
    }
    let one_site = argv_sites.len() == 1
        && argv_sites[0] == (mutation_markers::CARGO_MUTANTS_SITE.to_owned(), 1);
    if !one_site {
        let sites: Vec<String> = argv_sites
            .iter()
            .map(|(path, count)| format!("{path} ({count})"))
            .collect();
        return Err(format!(
            "a cargo-mutants argv is built at [{}], not once in {}: cargo-mutants runs as \
             itself through `mutate::cargo_mutants_argv`, never a second harness (CLOUD-2253)",
            sites.join(", "),
            mutation_markers::CARGO_MUTANTS_SITE
        )
        .into());
    }
    Ok(())
}

/// Every `.rs` file under `dir`, recursively; a missing directory is none.
fn rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}
