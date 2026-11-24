//! No Rust file in `crates/` authors a shell program and makes it executable,
//! beyond the ones whose subject is shell and a residue that can only shrink
//! (CLOUD-2336).
//!
//! Tests used to write a `#!/bin/sh` stub, set its exec bit and run it. The
//! stand-in (`crates/batten/examples/stub.rs`) and real programs replaced that,
//! and nothing kept it from coming back: the tree regrew such files between
//! #1278's branch point and #1276's tip without any gate noticing.
//!
//! THE PREDICATE IS THE ROW'S OWN, and it is computable: a file is counted when
//! it holds a shell shebang inside a string literal AND reaches for an exec bit.
//! Either alone is innocent — a shebang is subject data for the shell-hygiene
//! suites, and a mode bit is how a stand-in symlink or a launcher is judged —
//! so only the intersection is a test that authors shell to run it.
//!
//! WHAT IT CANNOT SEE: a stub authored in one file and made executable in
//! another, or a shell argv run with `sh -c`. Both are narrower than what the
//! intersection catches, and the row's acceptance names only this one.
//!
//! THE NEEDLES ARE ASSEMBLED, NEVER SPELLED (`rules/scanning.md`): this file is
//! scanned by the censuses that scan the tree, and its last case holds it to
//! carrying no needle whole.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use crate::common;

/// The shebangs a shell stub opens with, each inside a string literal.
fn shebangs() -> [String; 2] {
    [
        ["\"#", "!/bin/sh"].concat(),
        ["\"#", "!/usr/bin/env bash"].concat(),
    ]
}

/// What reaches for an exec bit.
fn exec_bits() -> [String; 4] {
    [
        ["from_mode(", "0o7"].concat(),
        ["Permissions", "Ext"].concat(),
        ["set_", "permissions"].concat(),
        ["make_", "executable"].concat(),
    ]
}

/// Files whose subject is shell, so authoring an executable shebang is the
/// point: the shebang reader's own cases, and the disarm shim's old body.
const SUBJECT_IS_SHELL: [&str; 2] = [
    "crates/batten/src/rules.rs",
    "crates/batten/tests/it/wiring_disarm.rs",
];

/// Files #1276 added shell to after #1278 branched, which the replay did not
/// convert. Held exactly, so the list can only shrink: each is a conversion
/// owed to CLOUD-2336, never an allowance.
const RESIDUE: [&str; 6] = [
    "crates/batten/src/mutate.rs",
    "crates/batten/src/provision.rs",
    "crates/batten/tests/it/git_hook.rs",
    "crates/batten/tests/it/session_start.rs",
    "crates/batten/tests/it/step_graph.rs",
    "crates/batten/tests/it/step_receipt.rs",
];

/// Whether `text` holds a shell shebang literal and an exec-bit reach.
fn authors_executable_shell(text: &str) -> bool {
    shebangs()
        .iter()
        .any(|needle| text.contains(needle.as_str()))
        && exec_bits()
            .iter()
            .any(|needle| text.contains(needle.as_str()))
}

/// Every tracked Rust file under `crates/` that authors executable shell.
fn found() -> BTreeSet<String> {
    let root = common::at_root(".");
    common::git_in(&root, &["ls-files", "crates"])
        .lines()
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext == "rs")
        })
        .filter(|path| {
            std::fs::read_to_string(root.join(path))
                .is_ok_and(|text| authors_executable_shell(&text))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn no_test_authors_executable_shell_beyond_the_held_list() {
    let found = found();
    let allowed: BTreeSet<String> = SUBJECT_IS_SHELL
        .iter()
        .chain(RESIDUE.iter())
        .map(|path| (*path).to_owned())
        .collect();
    let grown: Vec<_> = found.difference(&allowed).collect();
    assert!(
        grown.is_empty(),
        "these author a shell program and make it executable; use the stand-in \
         (`common::stub_at`) or a real program: {grown:?}"
    );
    let stale: Vec<_> = allowed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these no longer author executable shell; drop them from the held list: {stale:?}"
    );
}

#[test]
fn a_shebang_alone_or_an_exec_bit_alone_is_not_counted() {
    let shebang = format!("let body = {}\\necho\\n\";", shebangs()[0]);
    let mode = format!("std::fs::{}(&path, mode);", exec_bits()[2]);
    assert!(
        !authors_executable_shell(&shebang),
        "a shebang is subject data"
    );
    assert!(!authors_executable_shell(&mode), "a mode bit is not shell");
    assert!(
        authors_executable_shell(&format!("{shebang}\n{mode}")),
        "the two together are an authored, executed stub"
    );
    let env_bash = format!("let body = {}\\n\";\n{}", shebangs()[1], exec_bits()[1]);
    assert!(authors_executable_shell(&env_bash), "env bash is shell too");
}

#[test]
fn the_census_does_not_match_itself() {
    let text = std::fs::read_to_string(common::at_root(
        "crates/batten/tests/it/stub_shell_census.rs",
    ))
    .expect("read this file");
    assert!(
        !authors_executable_shell(&text),
        "this file spells a needle whole"
    );
}
