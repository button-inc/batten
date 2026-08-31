//! The corpus the switched `[[recorder]]` columns are judged over (CLOUD-1100).
//!
//! # THIS FILE WAS A REPLAY, AND ITS SECOND ARM RETIRED WITH ITS SUBJECT
//!
//! It was `authority_replay.rs`, and it ran `mise-tasks/ready-lint.sh` and
//! [`batten::ready::adjudicate`] over one corpus, asserting they agreed on the
//! status and on the two emissions a column reads. That was CLOUD-909's
//! obligation over the one thing CLOUD-1100 changed: three `[[recorder]]`
//! columns stopped spawning the program and started asking the compiled
//! authority, keeping their `read` tables byte for byte — a column keeping its
//! reader while its producer changes is exactly where a silent divergence lives.
//!
//! The replay's own doc comment said what to do here: *"If the program is ever
//! retired, this file goes with it."* CLOUD-1221 retired it, and that sentence
//! is honoured for the arm it was written about — the comparison, its spawn and
//! its two emission readers are gone, and with them this crate's last spawn of
//! that program. **The file is renamed rather than deleted, because the sentence
//! was written when the comparison was all there was**, and what remains never
//! asked the program anything.
//!
//! # What survives, and why it is not a rump
//!
//! [`the_corpus_reaches_every_status_the_columns_map`] asserts that pass,
//! violation and could-not-look are each REACHABLE through `adjudicate` over
//! this corpus. It was the comparison's anti-vacuity half; standing alone it is
//! the assertion that the columns' `{ "0" = "ready", "1" = "unready" }` tables
//! map statuses the authority can actually produce. Nothing else in the tree
//! makes that claim, and a corpus that silently collapsed to one verdict would
//! leave two of those rows unreachable with every suite green.
//!
//! # The status contract is INVERTED here, and that is the trap this file guards
//!
//! The retired program spelled `0` pass, `1` violation, `2` could-not-look;
//! batten's own `0/1/2/3` table spells `2` for the policy verdict. `adjudicate`
//! answers in the SHELL's codes precisely so those column tables keep their
//! meaning — and a re-mapping there would be a wrong verdict wearing a right
//! verdict's shape, which reads as data rather than as a gap. The assertion
//! below pins the raw statuses, so that inversion cannot be quietly undone.
//!
//! `mise run ready-lint` still answers in those codes too, through the
//! `mise.toml` adapter CLOUD-1221 added for `mise-tasks/graph-check.sh`. This
//! file and that adapter are the two places the inversion is held.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The repository root — where the shell program and the workspace manifest live.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root resolves")
}

/// The grammar this repository declares, resolved the way the engine resolves it.
///
/// **Read from the committed `[[pattern]]` rows, never re-typed.** The Ready
/// vocabulary is the consumer's and lives in `batten.toml`; a replay that spelled
/// those expressions again would be comparing the shell program against a second
/// grammar rather than against the one that ships, which is exactly the drift a
/// fidelity replay exists to catch.
fn grammar() -> batten::ready::Grammar {
    let config =
        batten::config::load(&root().join("batten.toml")).expect("the committed config loads");
    batten::ready::Grammar::resolve(&config.patterns)
        .expect("the committed config declares the whole Ready grammar")
}

/// The corpus: one payload per verdict-bearing shape the grammar decides.
///
/// SYNTHETIC BODIES, never a real row's prose. A replay corpus lifted off the
/// board would put tracker content in `crates/**` — non-negotiable rule 1 — and
/// would also rot the moment somebody grooms the row it was copied from. Each
/// entry names the shape it exercises so a failure says which clause diverged.
fn corpus() -> Vec<(&'static str, serde_json::Value)> {
    let payload = |id: &str, description: &str, relations: Option<serde_json::Value>| {
        let mut object = serde_json::Map::new();
        object.insert("id".to_owned(), serde_json::Value::String(id.to_owned()));
        object.insert(
            "description".to_owned(),
            serde_json::Value::String(description.to_owned()),
        );
        if let Some(relations) = relations {
            object.insert("relations".to_owned(), relations);
        }
        serde_json::Value::Object(object)
    };
    let edge = |direction: &str, id: &str| serde_json::json!({ direction: [ { "id": id } ] });
    vec![
        (
            "no ready block at all",
            payload("CLOUD-1", "Just a description.\n", None),
        ),
        (
            "an opener with no clause under it",
            payload("CLOUD-1", "**Refinement — Ready**\n\nSomething soon.", None),
        ),
        (
            "a parent opener, which is exempt from the clause floor",
            payload(
                "CLOUD-1",
                "**Refinement — Ready (parent)**\n\nThe children carry the clauses.",
                None,
            ),
        ),
        (
            "one canonical clause",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Authority boundary (§1).** The crate owns it.",
                None,
            ),
        ),
        (
            "an open-questions block inside a ready block",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Authority boundary (§1).** The crate.\n\n**Open \
                 questions**\n\n* Which one?",
                None,
            ),
        ),
        (
            "a §8 blocker cited with the relation present",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Blockers (§8).** `blockedBy` CLOUD-2.",
                Some(edge("blockedBy", "CLOUD-2")),
            ),
        ),
        (
            "a §8 blocker cited with no such relation",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Blockers (§8).** `blockedBy` CLOUD-3.",
                Some(edge("blockedBy", "CLOUD-2")),
            ),
        ),
        (
            "a §8 citation over a payload carrying no relations key",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Blockers (§8).** `blockedBy` CLOUD-3.",
                None,
            ),
        ),
        (
            "a deferral to a row nothing links",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Authority boundary (§1).** The crate.\n\nThe rest \
                 is deferred to CLOUD-9.",
                Some(edge("relatedTo", "CLOUD-2")),
            ),
        ),
        (
            "a deferral to a row that is linked",
            payload(
                "CLOUD-1",
                "**Refinement — Ready**\n\n* **Authority boundary (§1).** The crate.\n\nThe rest \
                 is deferred to CLOUD-9.",
                Some(edge("relatedTo", "CLOUD-9")),
            ),
        ),
    ]
}

/// The corpus discriminates, and it is what is left once the replay's second arm
/// retired with its subject. It was written as the anti-vacuity half of the
/// comparison — without it that case passed over a corpus that happened to be
/// all one verdict, CLOUD-418's class exactly — and it outlives the comparison
/// because it never asked the program anything: it asserts that the three
/// `[[recorder]]` columns' status maps are each REACHABLE through the compiled
/// authority, which is a property of the crate.
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
        "a replay corpus that never reaches a status is not evidence about the mapping of \
         that status: pass, violation and could-not-look must all appear"
    );
}
