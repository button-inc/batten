//! A config key this build does not know names the rebuild (CLOUD-1449).
//!
//! # The defect
//!
//! Measured twice in one session, both times after a routine rebase brought
//! `main` forward under a live branch: `batten.toml` grew a key, the binary
//! built at session start predated it, and serde reported
//! ``unknown field `link` `` under the heading **invalid config**. The file was
//! exactly right. The whole config then failed to load, so EVERY rule stopped
//! evaluating at once — not the one row that reads the new key — and the agent
//! went hunting a defect in a file that had none. The remedy, a rebuild, was
//! named nowhere.
//!
//! # The subject moved when CLOUD-1428 landed, and the sentence above is why
//!
//! This module's own defect statement names it: the whole config failed to
//! load, so every rule stopped evaluating at once, *not the one row that reads
//! the new key*. CLOUD-1449 fixed the message half of that and left the
//! granularity; CLOUD-1428 fixed the granularity, so an unknown key inside a
//! `[[rule]]` row now costs that row and the file still loads —
//! `config_forward_compatible.rs` is the case that holds it.
//!
//! What still refuses, and is therefore what these cases now drive, is an
//! unknown key the prune cannot localise to a droppable row: one on the
//! top-level table, or inside a plain `[section]`. That is not a narrower
//! subject for the message — it is the one that still reaches a reader, and a
//! reader meeting it has exactly the wrong-file problem CLOUD-1449 measured.
//! The row case keeps the same remedy by another channel: the drop is reported
//! by id, and `doctor` refuses with `config-rows-dropped`.
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
/// Built through `Fixture` rather than by hand, and that is `test fix duplicate`
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

/// The measured instance: a key this build has no field for, on the TOP-LEVEL
/// table.
///
/// `deny_unknown_fields` still turns that into a hard parse error, and there it
/// is correct: a top-level key is not a droppable row, so the only granularities
/// available are the file or nothing. Inside a `[[rule]]` row the same key costs
/// the row instead (CLOUD-1428) — the position, not the key, is what decides.
///
/// Fails by: making the `UNKNOWN_KEY` guard unconditional in either direction.
/// `skew-reads-as-malformed` forces it to `true`, which drops the note.
#[test]
fn an_unknown_key_names_the_rebuild() {
    let dir = scratch(
        "unknown-key",
        "version = 1\nnot_a_column_this_build_knows = 1\n",
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

/// Two `[[hook.handler]]` rows, the second carrying a key no build has.
///
/// `[hook]` is never declared as a header of its own, which is the shape
/// `batten.toml` itself has: the only `hook` headers in the authority are the
/// sixteen `[[hook.handler]]` rows. That is what makes the section addressable
/// as a dotted path rather than as a nest inside some `[[hook]]` element.
const HANDLERS: &str = r#"version = 1

[[hook.handler]]
id = "readable-handler"
on = "user-prompt-submit"
run = ["true"]
owner = "CLOUD-1775"
expires = "2027-02-28"

[[hook.handler]]
id = "from-a-newer-schema"
on = "user-prompt-submit"
run = ["true"]
owner = "CLOUD-1775"
expires = "2027-02-28"
this_key_does_not_exist_in_any_version = true
"#;

/// THE CASE THE DEFECT FAILS (CLOUD-1775), and the one the bootstrap turns on.
///
/// `[[hook.handler]]` fell through BOTH prune granularities. `Header::is_row`
/// equated droppable with dotless, so `owning_row` declined and the row arm never
/// ran; `drop_key` then asked the top-level table for a key spelled
/// `hook.handler`, found `hook` instead, and declined too. The file was refused
/// whole.
///
/// That is the detector disabled by the staleness it detects: the skew handler is
/// declared in the artifact whose vocabulary it polices, so the first schema
/// addition a running binary predates unregisters it. Measured 2026-09-10 on
/// `command_matcher`, three hours after the same shape on `[wiring]`; between
/// them, eight `land` laps at ~900s of local `verify` failed for reasons that had
/// nothing to do with the branch.
///
/// Fails by: `dotted-row-not-droppable`, which restores the dotless requirement.
#[test]
fn an_unknown_key_in_a_dotted_row_costs_the_row_not_the_file() {
    let dir = scratch("dotted-row", HANDLERS);

    let output = check(&dir);
    let said = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the rows this build CAN read must still load, or the detector is \
         disabled by exactly the skew it exists to report: {said}"
    );
    assert!(
        !said.contains("invalid config"),
        "one unreadable row is not an unreadable file: {said}"
    );
}

/// THE ANTI-VACUITY HALF. A partial load must not become a silent one.
///
/// Without this, the case above is satisfied by a build that drops the key and
/// says nothing — which is the permissive fallback CLOUD-251 names, and would let
/// a typo switch a handler off with no reader ever learning of it. It is also the
/// second of the row's own Done criteria, stated in its words: *the unknown key
/// is still REPORTED*.
///
/// The good row is asserted present in the same breath, because a report naming
/// the dropped row would also be produced by a build that dropped both.
#[test]
fn the_dropped_handler_is_named_and_its_neighbour_survives() {
    let dir = scratch("dotted-row-named", HANDLERS);

    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config show");
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(
        said.contains("from-a-newer-schema"),
        "a dropped row is a handler that is NOT running, and must be reported by \
         id: {said}"
    );
    // THE SURVIVOR IS COUNTED, NOT NAMED, and the count is the whole assertion.
    // `config show` is pointer-only (rule 4), so it renders `hook <n>` rather
    // than each handler's id — which is what makes the number load-bearing here:
    // `2` is a build that dropped nothing, `0` is a prune that took the section
    // instead of the row, and only `1` is the repair.
    let counted = said
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("hook")).then(|| fields.next())?
        })
        .next();
    assert_eq!(
        counted,
        Some("1"),
        "exactly the readable handler survives — 2 is no prune at all and 0 is \
         the section taken rather than the row: {said}"
    );
    // POINTER, NEVER THE PAYLOAD (rule 4): the report names the row, never the
    // bytes that could not be read.
    assert!(
        !said.contains("this_key_does_not_exist_in_any_version"),
        "the report is a pointer, not the file's contents: {said}"
    );
}

/// A DOTTED ROW NESTED INSIDE AN ARRAY ELEMENT IS STILL NOT THE DROPPABLE UNIT.
///
/// `[[provision.env]]` is an array inside the last `[[provision]]` element, so
/// the row that owns a key under it is the `[[provision]]` row — dropping the
/// `env` block alone would leave a provision row provisioning something nobody
/// wrote. The discriminator is whether the dotted header's ROOT is itself an
/// array row in the same document; `hook` is not, `provision` is.
///
/// This is the mirror that keeps the fix from becoming "every dotted header is
/// droppable", which would pass the two cases above and silently change what a
/// `[[provision]]` row provisions.
#[test]
fn a_dotted_row_nested_in_an_array_element_still_charges_its_owner() {
    let dir = scratch(
        "dotted-row-nested",
        r#"version = 1

[[provision]]
id = "readable-provision"
run = ["true"]

[[provision.env]]
name = "SOME_VAR"
value = "x"
this_key_does_not_exist_in_any_version = true
"#,
    );

    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config show");
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(
        said.contains("readable-provision"),
        "the unit charged is the [[provision]] row that owns the nested block, \
         named by its own id: {said}"
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

    let err = toml::from_str::<Narrow>("known = 1\nsurprise = 2\n")
        .expect_err("an unknown field must not parse");
    assert!(
        err.to_string().contains("unknown field"),
        "the predicate keys on this wording; a reword silently drops the note: {err}"
    );

    let err = toml::from_str::<Holder>("shape = \"surprise\"\n")
        .expect_err("an unknown variant must not parse");
    assert!(
        err.to_string().contains("unknown variant"),
        "the predicate keys on this wording too: {err}"
    );
}
