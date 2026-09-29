//! The compiled Ready authority answers what the retired shell program answered
//! (CLOUD-1100, frozen by CLOUD-1221).
//!
//! CLOUD-909's obligation, applied to the one thing CLOUD-1100 changed about how a
//! verdict is reached. The GRAMMAR's fidelity is settled elsewhere —
//! `crates/batten/tests/it/ready.rs` carries every case of `tests/ready-lint.bats`
//! onto the compiled binary. What this file guards is a **presentation**: three
//! `[[recorder]]` columns that used to spawn `mise-tasks/ready-lint.sh` now ask
//! [`batten::ready::adjudicate`], and they kept their `read` tables byte for byte.
//!
//! # A replay while the program lived, a recording now that it does not
//!
//! Until CLOUD-1221 this file spawned the program over the corpus below and
//! compared the two producers live. Retiring the program ends the second arm, and
//! a stub in its place would compare the crate to a copy of itself. So the
//! program's answers over this exact corpus were RECORDED on the last tree that
//! carried it (2026-09-29), and [`recorded`] pins them. The comparison is the same
//! one, over the same axes, against the same producer's output — it simply no
//! longer needs the producer present to make it.
//!
//! The two DIVERGENCE inventories this file kept (CLOUD-1092's `bump` split and
//! CLOUD-1395's claims-object ratchet) were written to go red the day the program
//! retired, and they are deleted with it rather than left as exemptions against a
//! producer that no longer exists. Both divergences stand as the compiled
//! authority's own behaviour, asserted in `ready.rs`.
//!
//! # Why the comparison is the CONSUMED axes and not the whole stdout
//!
//! The shell program printed `ready-lint: <id> satisfies …` on a pass, and
//! `adjudicate` prints only the emissions — stdout is the data channel. No
//! consumer read that line: the switched columns read `status` and
//! `stdout-line = "cites-body "`, and `ready graph` reads `bump`, all compared here.
//!
//! # The status contract is INVERTED here, and that is the trap this file guards
//!
//! The program spelled `0` pass, `1` violation, `2` could-not-look; batten's own
//! `0/1/2/3` table spells `2` for the policy verdict. `adjudicate` answers in the
//! SHELL's codes precisely so the columns' `{ "0" = "ready", "1" = "unready" }`
//! tables keep their meaning, and every row below asserts the raw status so that
//! inversion cannot be quietly undone.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The repository root — where the workspace manifest and the committed config live.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root resolves")
}

/// The grammar this repository declares, resolved the way the engine resolves it.
///
/// **Read from the committed `[[pattern]]` rows, never re-typed**, AND with the
/// `[ready]` thresholds the CLI chains in `lib.rs`'s `board_grammar` (CLOUD-1395):
/// a grammar built from `resolve` alone is configured differently from the one
/// that ships, with every ratchet unset.
fn grammar() -> batten::ready::Grammar {
    let config =
        batten::config::load(&root().join("batten.toml")).expect("the committed config loads");
    batten::ready::Grammar::resolve(&config.patterns)
        .expect("the committed config declares the whole Ready grammar")
        .with_prose_threshold(
            config
                .ready
                .as_ref()
                .and_then(|ready| ready.prose_dialect_required_from.clone()),
        )
        .with_pressure_test_threshold(
            config
                .ready
                .as_ref()
                .and_then(|ready| ready.pressure_test_required_from.clone()),
        )
}

/// One payload for the corpus: an id, a body, optionally relations and a
/// creation instant.
fn payload(
    description: &str,
    relations: Option<serde_json::Value>,
    created: Option<&str>,
) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "id".to_owned(),
        serde_json::Value::String("CLOUD-1".to_owned()),
    );
    if let Some(created) = created {
        object.insert(
            "createdAt".to_owned(),
            serde_json::Value::String(created.to_owned()),
        );
    }
    object.insert(
        "description".to_owned(),
        serde_json::Value::String(description.to_owned()),
    );
    if let Some(relations) = relations {
        object.insert("relations".to_owned(), relations);
    }
    serde_json::Value::Object(object)
}

fn edge(direction: &str, id: &str) -> serde_json::Value {
    serde_json::json!({ direction: [ { "id": id } ] })
}

/// A Ready block opening over `rest`.
fn clause(rest: &str) -> String {
    format!("**Refinement — Ready**\n\n{rest}")
}

/// The corpus: one payload per verdict-bearing shape the grammar decides.
///
/// SYNTHETIC BODIES, never a real row's prose: a corpus lifted off the board would
/// put tracker content in `crates/**` (non-negotiable rule 1) and rot the moment
/// the row was groomed.
fn corpus() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "no ready block at all",
            payload("Just a description.\n", None, None),
        ),
        (
            "an opener with no clause under it",
            payload(&clause("Something soon."), None, None),
        ),
        (
            "a parent opener",
            payload(
                "**Refinement — Ready (parent)**\n\nThe children carry the clauses.",
                None,
                None,
            ),
        ),
        (
            "one canonical clause",
            payload(
                &clause("* **Authority boundary (§1).** The crate owns it."),
                None,
                None,
            ),
        ),
        (
            "an open-questions block inside a ready block",
            payload(
                &clause(
                    "* **Authority boundary (§1).** The crate.\n\n**Open questions**\n\n* Which one?",
                ),
                None,
                None,
            ),
        ),
        (
            "a §8 blocker cited with the relation present",
            payload(
                &clause("* **Blockers (§8).** `blockedBy` CLOUD-2."),
                Some(edge("blockedBy", "CLOUD-2")),
                None,
            ),
        ),
        (
            "a §8 blocker cited with no such relation",
            payload(
                &clause("* **Blockers (§8).** `blockedBy` CLOUD-3."),
                Some(edge("blockedBy", "CLOUD-2")),
                None,
            ),
        ),
        (
            "a §8 citation over a payload carrying no relations key",
            payload(&clause("* **Blockers (§8).** `blockedBy` CLOUD-3."), None, None),
        ),
        (
            "a deferral to a row nothing links",
            payload(
                &clause(
                    "* **Authority boundary (§1).** The crate.\n\nThe rest is deferred to CLOUD-9.",
                ),
                Some(edge("relatedTo", "CLOUD-2")),
                None,
            ),
        ),
        (
            "a deferral to a row that is linked",
            payload(
                &clause(
                    "* **Authority boundary (§1).** The crate.\n\nThe rest is deferred to CLOUD-9.",
                ),
                Some(edge("relatedTo", "CLOUD-9")),
                None,
            ),
        ),
    ]
    .into_iter()
    .chain(section_six())
    .collect()
}

/// The §6 shapes and the pre-cutover `createdAt`, present because an axis compared
/// over a corpus that cannot exercise it is vacuous (CLOUD-1092, CLOUD-1395).
fn section_six() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "§6 naming a releasing type",
            payload(
                &clause("* **Commit / bump (§6).** `fix` → **patch**."),
                None,
                None,
            ),
        ),
        (
            "§6 declaring no bump AND no type — the dispatch-record shape",
            payload(
                &clause("* **Commit / bump (§6).** **no bump** — this row lands no commit."),
                None,
                None,
            ),
        ),
        (
            "a row created BEFORE the claims-object cutover",
            payload(
                &clause("* **Commit / bump (§6).** `fix` → **patch**."),
                None,
                Some("2026-08-01T00:00:00.000Z"),
            ),
        ),
    ]
}

/// One recorded answer: status, then the `cites-body `, `cites-blockers ` and
/// `bump ` lines, each `None` where the program never printed that line.
type Answer = (
    i32,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

/// What `mise-tasks/ready-lint.sh` answered over [`corpus`], in the same order.
///
/// Recorded by running the program from the workspace root over each payload on
/// the last tree that carried it. Not re-derived from the crate: a table the crate
/// wrote would agree with the crate by construction.
fn recorded() -> Vec<Answer> {
    vec![
        (1, Some(""), None, None),
        (1, Some(""), Some(""), None),
        (1, Some(""), Some(""), None),
        (0, Some(""), Some(""), None),
        (0, Some(""), Some(""), None),
        (0, Some("CLOUD-2"), Some("CLOUD-2"), None),
        (1, Some("CLOUD-3"), Some("CLOUD-3"), None),
        (2, Some("CLOUD-3"), Some("CLOUD-3"), None),
        (1, Some("CLOUD-9"), Some(""), None),
        (0, Some("CLOUD-9"), Some(""), None),
        (0, Some(""), Some(""), Some("patch")),
        (0, Some(""), Some(""), Some("none")),
        (0, Some(""), Some(""), Some("patch")),
    ]
}

/// The line a column reads, by its prefix, or `None` where it was not printed.
fn line<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    out.lines().find_map(|line| line.strip_prefix(prefix))
}

#[test]
fn the_compiled_authority_answers_what_the_retired_program_answered() {
    let root = root();
    let grammar = grammar();
    let corpus = corpus();
    let recorded = recorded();
    assert_eq!(
        corpus.len(),
        recorded.len(),
        "every corpus shape carries exactly one recorded answer"
    );
    for ((shape, value), (status, body, blockers, bump)) in corpus.iter().zip(recorded) {
        let (compiled_status, out) = batten::ready::adjudicate(&grammar, value, &root)
            .unwrap_or_else(|| panic!("the compiled authority reads the corpus payload: {shape}"));
        assert_eq!(
            compiled_status, status,
            "the status the switched columns map must be the program's own, for {shape}"
        );
        assert_eq!(
            line(&out, "cites-body "),
            body,
            "the `cites-body` emission a column reads, for {shape}"
        );
        assert_eq!(
            line(&out, "cites-blockers "),
            blockers,
            "the `cites-blockers` emission, for {shape}"
        );
        assert_eq!(
            line(&out, "bump "),
            bump,
            "the `bump` emission `ready graph` reads, for {shape}"
        );
    }
}

/// The corpus discriminates. Without this the case above passes over a corpus
/// that happens to be all one verdict, which is CLOUD-418's class exactly.
#[test]
fn the_corpus_reaches_every_status_the_columns_map() {
    let root = root();
    let grammar = grammar();
    let mut seen: Vec<i32> = corpus()
        .into_iter()
        .filter_map(|(_, value)| batten::ready::adjudicate(&grammar, &value, &root))
        .map(|(status, _)| status)
        .collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        vec![0, 1, 2],
        "a corpus that never reaches a status is not evidence about the mapping of that \
         status: pass, violation and could-not-look must all appear"
    );
}
