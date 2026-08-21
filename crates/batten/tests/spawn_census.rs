//! The spawn census, as a gate rather than a table (CLOUD-743).
//!
//! CLOUD-320 asked for a written position on every shell-out and shipped no
//! mechanism, so three more spawn sites landed unremarked. The mechanism is
//! `clippy::disallowed_types` over `std::process::Command`, and the verdict for
//! each site lives in the `#[expect]` **on the line it describes**. There is no
//! census table — not in this file and not anywhere else — which is the point:
//! a table drifts from the code, and a count is a number that can be wrong.
//!
//! What this file holds is the gate's own shape, which clippy cannot check about
//! itself:
//!
//! * the lint is `deny` **in the manifest**, not `warn` promoted by
//!   `-D warnings` (§2, and CLOUD-822's measurement of what the difference
//!   costs);
//! * `clippy.toml` names the type and gives a reason;
//! * every annotation is an `#[expect]` carrying a **verdict**, never a bare
//!   `#[allow]` — `expect` is what makes a DELETED spawn with a stale
//!   annotation red too, so the census self-cleans in both directions;
//! * `surface.rs`'s bare `clap::Command` import needs no annotation at all,
//!   which is the discriminator a string scan cannot draw and the reason this
//!   gate is clippy.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::facts::{Format, Look, Node};
use common::at_root;

/// The one type the census is about.
const SPAWN_TYPE: &str = "std::process::Command";

/// The lint whose level carries the gate.
const LINT: &str = "clippy::disallowed_types";

/// The verdict a `reason` must open with.
///
/// Two values and no third, because the inventory question has two answers: the
/// spawn is the design (`stays`), or it has a named successor and this row exists
/// so the successor lands as a deletion (`GOES`). Free prose here would let an
/// annotation satisfy the gate while recording nothing — which is the failure
/// mode of the table this replaced.
const VERDICTS: &[&str] = &["stays", "GOES"];

/// Every Rust source file the gate runs over: the library and its test targets.
///
/// `--all-targets` is what `mise run lint:clippy` passes, so a test target's
/// spawn is as much an inventory row as the library's — and `git.rs`'s own
/// `#[cfg(test)]` fixture was a row in the census CLOUD-743 was filed with.
fn rust_sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for dir in ["crates/batten/src", "crates/batten/tests"] {
        collect(&at_root(dir), &mut found);
    }
    found.sort();
    assert!(
        found.len() > 40,
        "the source sweep found {} files, which is too few to be the crate",
        found.len()
    );
    found
}

fn collect(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The text of every attribute in `source` that mentions the census lint, with
/// the 1-based line it starts on.
///
/// A bounded scan rather than a parse: an attribute opens at `#[` or `#![` and
/// closes at the first `)]` before the NEXT opener. That bound is what makes it
/// safe over this file, which discusses `#[expect]` and `#[allow]` in prose and
/// names the lint in a `const` — an unbounded search would stitch a doc comment
/// to some later attribute's closer and report a finding about neither. Measured
/// here: the first version of this scan flagged line 25.
///
/// Enough to tell `expect` from `allow` and to find a `reason`, which is all
/// that is asked. The alternative is a proc-macro parse of the whole crate to
/// check a property clippy has already enforced the hard half of.
fn census_attributes(source: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = source[cursor..].find("#[") {
        // `#![` opens one character earlier; take the wider span so an inner
        // attribute is not read as a bare one.
        let mut open = cursor + offset;
        if open > 0 && source.as_bytes()[open - 1] == b'!' && open > 1 {
            open -= 1;
        }
        cursor = open + 2;
        let rest = &source[open..];
        let Some(close) = rest.find(")]") else {
            break;
        };
        // The next opener bounds this one. An attribute with no `(` — `#[test]`,
        // or the literal `#[expect]` in a doc comment — has no closer of its own,
        // so its "closer" belongs to something further down and it is skipped.
        let next = rest[2..].find("#[").map_or(rest.len(), |at| at + 2);
        if close + 2 > next {
            continue;
        }
        let attribute = &rest[..close + 2];
        if attribute.contains(LINT) {
            found.push((source[..open].lines().count() + 1, attribute.to_owned()));
        }
    }
    found
}

/// The workspace manifest as a parsed document, through the fact the engine
/// already owns (CLOUD-772) rather than a second TOML reader.
fn manifest() -> Node {
    let text = fs::read_to_string(at_root("Cargo.toml")).expect("the workspace manifest is here");
    match Format::Toml.read(&text) {
        Look::Is(node) => node,
        other => panic!("the workspace manifest did not parse: {other:?}"),
    }
}

#[test]
fn the_lint_is_denied_in_the_manifest_itself() {
    // §2, and the whole reason this row is not satisfied by adding an entry to
    // `clippy.toml` alone. Every other lint in this table is `warn`, promoted to
    // an error only by `mise run lint:clippy`'s `-D warnings`. CLOUD-822 measured
    // the consequence: `mise exec -- cargo clippy -p batten --all-targets` — the
    // escape `no-bare-cargo`'s own refusal text recommends — omits that flag and
    // missed 10 `expect_used` errors. A spawn gate at `warn` would report clean
    // over an unannotated spawn under a sanctioned command, and the agent would
    // then quote the clean run as verification.
    //
    // Relaxing the manifest line to `warn` turns THIS red, which is the §7(d)
    // obligation: the argument in §2 must not rest on a config line nothing
    // re-reads.
    let manifest = manifest();
    let level = manifest.at("workspace.lints.clippy.disallowed_types");
    let denied = Node::Text("deny".to_owned());
    assert_eq!(
        level,
        Look::Is(&denied),
        "[workspace.lints.clippy] must set `disallowed_types = \"deny\"`; found {level:?}. \
         A level only `-D warnings` promotes makes the verdict depend on which sanctioned \
         invocation ran (CLOUD-822), which is not a gate."
    );
}

#[test]
fn the_stale_annotation_arm_is_denied_too() {
    // `#[expect]` was chosen over `#[allow]` because it catches the OTHER
    // direction: a spawn deleted with its annotation left behind. That arm is
    // `unfulfilled_lint_expectations`, and it is warn-by-default — so until
    // CLOUD-743 it would have rested entirely on `mise run lint:clippy`'s
    // `-D warnings`, which is the same half-a-gate the clippy level above
    // refuses. Measured on a scratch crate in `tests/spawn-census.bats`: at the
    // default level, an `#[expect]` over code with no spawn is a warning and the
    // run exits 0.
    //
    // Two lints, two explicit denies, one gate. Relaxing either turns a test red.
    let manifest = manifest();
    let level = manifest.at("workspace.lints.rust.unfulfilled_lint_expectations");
    let denied = Node::Text("deny".to_owned());
    assert_eq!(
        level,
        Look::Is(&denied),
        "[workspace.lints.rust] must set `unfulfilled_lint_expectations = \"deny\"`; found \
         {level:?}. Without it the census only self-cleans in one direction, which is the \
         property a count table already had."
    );
}

#[test]
fn clippy_toml_names_the_spawn_type_and_says_why() {
    // The other half: the manifest carries the severity, this file carries the
    // subject. Split because they are different questions and clippy reads them
    // from different places — but neither alone is the gate, so both are asserted.
    let text = fs::read_to_string(at_root("clippy.toml")).expect("clippy.toml is committed");
    assert!(
        text.contains("disallowed-types"),
        "clippy.toml must carry a `disallowed-types` table"
    );
    assert!(
        text.contains(SPAWN_TYPE),
        "clippy.toml must name `{SPAWN_TYPE}` — the one type the census is about"
    );
    assert!(
        text.contains("reason ="),
        "the entry must carry a `reason`: clippy prints it at the deny site, and a deny that \
         does not say what to do is the CLOUD-437 defect"
    );
}

#[test]
fn every_annotation_is_an_expect_carrying_a_verdict() {
    // The property that replaces the table. Each site's verdict is on the site,
    // so there is nothing to keep in sync — and `#[expect]` rather than
    // `#[allow]` is load-bearing rather than stylistic: `allow` goes quiet when
    // the lint stops firing, so deleting a spawn and leaving its annotation
    // behind would be invisible. `expect` makes that red, which is §7(b) and the
    // direction a count table cannot see at all.
    //
    // Pointer-only per non-negotiable rule 4: a path and a line, never the
    // annotated source.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let shown = path.display().to_string();
        for (line, attribute) in census_attributes(&source) {
            if attribute.contains("allow(") {
                problems.push(format!("{shown}:{line} allow — must be expect"));
                continue;
            }
            if !attribute.contains("expect(") {
                problems.push(format!("{shown}:{line} not-an-expect"));
                continue;
            }
            let Some(reason) = attribute
                .split_once("reason = \"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(reason, _)| reason)
            else {
                problems.push(format!("{shown}:{line} no-reason"));
                continue;
            };
            if !VERDICTS.iter().any(|verdict| reason.starts_with(verdict)) {
                problems.push(format!("{shown}:{line} no-verdict"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "every spawn annotation is an inventory row and must open with a verdict \
         ({VERDICTS:?}):\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_census_is_not_empty() {
    // The anti-vacuity arm. Every assertion above is about the SHAPE of an
    // annotation, and each of them passes trivially over a crate that carries
    // none — which is what a `disallowed-types` entry silently scoped to nothing
    // would produce, and is exactly the reading the count table was there to
    // prevent. So the discriminator is that the sweep found some.
    //
    // A floor rather than a count: the number is clippy's to maintain, and a
    // pinned figure here would be the table this row deleted.
    let annotated = rust_sources()
        .into_iter()
        .filter(|path| {
            let source = fs::read_to_string(path).expect("read a crate source file");
            !census_attributes(&source).is_empty()
        })
        .count();
    assert!(
        annotated >= 5,
        "only {annotated} files carry a spawn verdict — the sweep is not reaching the crate"
    );
}

#[test]
fn claps_command_needs_no_annotation() {
    // THE DISCRIMINATOR, and it is load-bearing (§7(c)). `surface.rs` imports
    // clap's `Command` BARE, so the token names two different types in this
    // crate. That ambiguity is what made both of CLOUD-743's wrong turns: a text
    // scan counted 14 sites and a syntax-only matcher counts 11, because neither
    // resolves names. clippy matches the fully resolved path, so `clap::Command`
    // is never matched at all.
    //
    // Asserted over the real file rather than a fixture: the claim is that THIS
    // module's `Command` sites need no annotation, and `mise run lint:clippy`
    // being green over a `surface.rs` that carries none is the proof. A fixture
    // would prove it about a fixture.
    let source = fs::read_to_string(at_root("crates/batten/src/surface.rs")).expect("read surface");
    assert!(
        source.contains("use clap::{Arg, ArgAction, Command};"),
        "surface.rs must still import clap's `Command` bare — that bare import IS the case \
         this gate has to get right, and requalifying it would delete the discriminator \
         rather than satisfy it"
    );
    assert!(
        source.contains("Command::new("),
        "surface.rs must still build the clap tree through `Command::new`"
    );
    assert!(
        census_attributes(&source).is_empty(),
        "surface.rs must carry NO spawn annotation: every `Command` in it is clap's, and an \
         annotation here would mean the gate had reproduced the very defect it exists to fix"
    );
}
