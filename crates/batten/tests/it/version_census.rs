//! No hand-rolled version reader outside the one parser (CLOUD-2906).
//!
//! Every version string batten decides over is semver, and every reader parses
//! it through `crates/batten-base/src/version.rs`. A reader that strips a `v` by
//! hand, sorts tags by git's or coreutils' version order, describes over every
//! tag, or tests a version's text for a `0.0.` prefix reads a pre-release or a
//! build-metadata version wrong, so this census refuses each of those shapes in
//! code anywhere the tree runs it: every workspace crate's sources and tests,
//! the task file, the task programs, the workflows and the shell bootstraps.
//!
//! The needles are assembled from parts, and the shapes are paraphrased in this
//! prose, so the scanner never finds itself (`rules/scanning.md`). Comments are
//! stripped, because the property is about code that runs.
//!
//! `KNOWN` names each remainder this row could not move, with why; each entry
//! must still be found, so the list only shrinks.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// The retired shapes, each assembled from two parts so the literal never
/// appears whole in this file.
fn needles() -> Vec<String> {
    [
        ["trim_start_matches", "('v')"],
        ["strip_prefix", "('v')"],
        ["--sort=", "-v:refname"],
        ["sort ", "-V"],
        ["describe ", "--abbrev=0 --tags"],
        ["describe ", "--tags"],
        ["#v", "}"],
        ["starts_with(", "\"0.0.\")"],
    ]
    .iter()
    .map(|parts| parts.concat())
    .collect()
}

/// The remainders this row could not move, as `(path, needle index, why)`.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        ".github/workflows/linear-release-backfill.yml",
        4,
        "protected path: moves onto `batten release previous` with the workflow edit \
         CLOUD-2906 leaves open",
    ),
    (
        "crates/batten/tests/it/release_tracking.rs",
        4,
        "a fixture copy of the workflow line above; it moves with it",
    ),
    (
        "action.yml",
        6,
        "the bootstrap that installs batten: no verb exists yet to call, and it moves an \
         already-parsed pin without ordering or classifying it (row S7, kept)",
    ),
];

/// The file the parser lives in: the one place a `v` is handled.
const PARSER: &str = "crates/batten-base/src/version.rs";

/// `text` with its comments removed: `//` onward on a Rust line, a whole line
/// opening with `#` elsewhere.
fn code_of(text: &str, rust: bool) -> String {
    text.lines()
        .map(|line| {
            if rust {
                line.find("//").map_or(line, |at| &line[..at])
            } else if line.trim_start().starts_with('#') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The needle indices `code` contains.
fn hits(code: &str) -> Vec<usize> {
    needles()
        .iter()
        .enumerate()
        .filter(|(_, needle)| code.contains(needle.as_str()))
        .map(|(index, _)| index)
        .collect()
}

/// Every file the census reads, as a repo-relative path.
fn corpus() -> Vec<String> {
    let root = common::at_root("");
    let relative = |path: &Path| -> String {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let root = root.canonicalize().unwrap();
        path.strip_prefix(&root)
            .map_or_else(|_| path.clone(), Path::to_path_buf)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let mut files: Vec<String> = common::rust_sources()
        .iter()
        .map(|path| relative(path))
        .collect();
    for dir in [".github/workflows", "mise-tasks"] {
        let listed = std::fs::read_dir(common::at_root(dir)).unwrap();
        for entry in listed {
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
    files.dedup();
    files
}

#[test]
fn no_hand_rolled_version_reading_outside_the_parser() {
    let mut found = Vec::new();
    let mut known_seen = vec![false; KNOWN.len()];
    let files = corpus();
    assert!(files.len() > 100, "the census read {} files", files.len());
    for file in &files {
        if file == PARSER {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(common::at_root(file)) else {
            continue;
        };
        let rust = Path::new(file)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));
        for needle in hits(&code_of(&text, rust)) {
            match KNOWN
                .iter()
                .position(|(path, index, _)| *path == file && *index == needle)
            {
                Some(at) => known_seen[at] = true,
                None => found.push(format!("{file}: {}", needles()[needle])),
            }
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

/// The census can fail: each needle, seeded into code, is found, and the same
/// text inside a comment is not.
#[test]
fn every_needle_is_found_in_code_and_none_in_a_comment() {
    for (index, needle) in needles().iter().enumerate() {
        let seeded = format!("let x = {needle};\n");
        assert_eq!(hits(&code_of(&seeded, true)), vec![index], "{needle}");
        let commented = format!("// {needle}\n");
        assert!(hits(&code_of(&commented, true)).is_empty(), "{needle}");
        let shell = format!("# {needle}\n");
        assert!(hits(&code_of(&shell, false)).is_empty(), "{needle}");
    }
    assert_eq!(needles().len(), 8);
}
