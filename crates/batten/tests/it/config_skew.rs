//! A config key this build does not know names the rebuild (CLOUD-1449).
//!
//! # The defect
//!
//! Measured twice in one session, both times after a routine rebase brought
//! `main` forward under a live branch: `batten.toml` grew a key, the binary
//! built at session start predated it, and serde reported
//! `unknown field \`link\`` under the heading **invalid config**. The file was
//! exactly right. The whole config then failed to load, so EVERY rule stopped
//! evaluating at once — not the one row that reads the new key — and the agent
//! went hunting a defect in a file that had none. The remedy, a rebuild, was
//! named nowhere.
//!
//! # Why both directions are asserted, and why that is the whole file
//!
//! An unknown key is a stale binary or a typo, and the parser cannot tell them
//! apart. So the note states both readings. That makes the obvious wrong fix —
//! blaming skew for every parse failure — pass the first case and fail the
//! second, which is why `a_malformed_config_does_not_mention_a_rebuild` is not
//! a defensive extra. It is the half that keeps the message honest, and a
//! version of this fix that reported skew unconditionally would be CLOUD-1449
//! again wearing the other subject.
//!
//! # Over the compiled binary, not over `config::parse`
//!
//! What a consumer meets is a message on stderr and an exit code, and the unit
//! path cannot show that the boundary prints what the formatter built. Both
//! cases drive `batten check` in a scratch repository, which is the shape
//! `.claude/rules/rust.md` asks for anything a consumer depends on.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{batten, stderr};

/// A repository whose committed authority is `config`.
///
/// Built through `Fixture` rather than by hand, and that is `fixture-forks`
/// working rather than a style note: it refused the first draft of this file,
/// which ran its own `git init`. Every fixture copies the one template
/// `common/mod.rs` builds, so a suite cannot drift into its own repository
/// shape — and `Fixture::config` also writes the authority, which keeps a
/// protected path's literal name out of this file (`protected-mutation` reads
/// the committed text, not the write's destination).
fn scratch(name: &str, config: &str) -> PathBuf {
    common::Fixture::new(&format!("config-skew-{name}"))
        .config(config)
        .git()
        .build()
}

fn check(dir: &std::path::Path) -> std::process::Output {
    batten()
        .arg("check")
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten check")
}

/// The measured instance: a key this build has no field for.
///
/// `deny_unknown_fields` is what turns it into a hard parse error, which is
/// correct — the alternative is a silently discarded row — so the fix is the
/// message rather than the refusal.
///
/// Fails by: making the `UNKNOWN_KEY` guard unconditional in either direction.
/// `skew-reads-as-malformed` forces it to `true`, which drops the note.
#[test]
fn an_unknown_key_names_the_rebuild() {
    let dir = scratch(
        "unknown-key",
        "version = 1\n\n[[rule]]\nid = \"x\"\nkind = \"forbid\"\nseverity = \"deny\"\nglob = \"*\"\npattern = \"x\"\nnot_a_column_this_build_knows = 1\n",
    );

    let output = check(&dir);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "got: {said}");
    // The parse error still leads: it carries the line, and the note is an
    // addition rather than a replacement.
    assert!(said.contains("invalid config"), "got: {said}");
    // THE POINTER THE DEFECT WAS MISSING. Naming the task is the whole remedy;
    // an agent that reads only "invalid config" edits the wrong file.
    assert!(
        said.contains("mise run install:local"),
        "the rebuild must be named, or the reader edits a file that is correct: {said}"
    );
    // BOTH READINGS, because the parser cannot decide between them and a
    // message that asserted skew would be this defect with a new subject.
    assert!(
        said.contains("typo"),
        "the note must not assert skew over a typo it cannot rule out: {said}"
    );
}

/// And a genuinely malformed file says nothing about a rebuild.
///
/// THE DISCRIMINATING MIRROR. Without it the case above is satisfied by a fix
/// that appends the note to every parse failure — which would send a reader
/// with a real syntax error off to rebuild a binary that is already current.
///
/// Fails by: `every-parse-error-blames-skew`, which forces the guard to `false`
/// so the note is appended unconditionally.
#[test]
fn a_malformed_config_does_not_mention_a_rebuild() {
    let dir = scratch("malformed", "version = 1\n\n[[rule\nid = \"x\"\n");

    let output = check(&dir);
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "got: {said}");
    assert!(said.contains("invalid config"), "got: {said}");
    assert!(
        !said.contains("mise run install:local"),
        "a syntax error is not a version skew, and sending the reader to rebuild \
         a current binary is this defect with the subject swapped: {said}"
    );
}

/// The wording this predicate matches on is serde's, and nothing types it.
///
/// `config_error` discriminates on the rendered message because serde exposes no
/// typed discriminant for an unknown key. That is a real coupling to a
/// dependency's prose, and its failure direction is SILENT: a `toml` bump that
/// rewords either string leaves the parse error printing in full while the note
/// quietly stops appearing, which looks exactly like the defect never existing.
///
/// So the coupling is asserted rather than trusted. This case is what turns that
/// bump into a red suite instead of a regression nobody sees.
#[test]
fn the_parser_still_words_an_unknown_key_the_way_the_predicate_expects() {
    // `Debug` is `expect_err`'s requirement on the Ok type, not decoration.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Narrow {
        #[allow(dead_code)]
        known: u8,
    }

    let err = toml::from_str::<Narrow>("known = 1\nsurprise = 2\n")
        .expect_err("an unknown field must not parse");
    assert!(
        err.to_string().contains("unknown field"),
        "the predicate keys on this wording; a reword silently drops the note: {err}"
    );

    #[derive(Debug, serde::Deserialize)]
    enum Shape {
        #[allow(dead_code)]
        Known,
    }
    #[derive(Debug, serde::Deserialize)]
    struct Holder {
        #[allow(dead_code)]
        shape: Shape,
    }

    let err = toml::from_str::<Holder>("shape = \"surprise\"\n")
        .expect_err("an unknown variant must not parse");
    assert!(
        err.to_string().contains("unknown variant"),
        "the predicate keys on this wording too: {err}"
    );
}
