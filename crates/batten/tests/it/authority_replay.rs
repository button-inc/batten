//! The compiled Ready authority and the shell program agree (CLOUD-1100).
//!
//! CLOUD-909's obligation, applied to the one thing CLOUD-1100 actually changed
//! about how a verdict is reached. The GRAMMAR's fidelity is already settled —
//! `crates/batten/tests/it/ready.rs` carries all 82 cases of `tests/ready-lint.bats`
//! onto the compiled binary, and this file neither adds to that mapping nor
//! rewrites it. What is new is a **presentation**: three `[[recorder]]` columns
//! that used to spawn `mise-tasks/ready-lint.sh` now ask
//! [`batten::ready::adjudicate`], and they kept their `read` tables byte for byte.
//! A column keeping its reader while its producer changes is exactly the shape
//! where a silent divergence lives.
//!
//! # Why the comparison is the CONSUMED axes and not the whole stdout
//!
//! The two producers differ in stdout by one line, deliberately and permanently:
//! the shell program prints `ready-lint: <id> satisfies …` on a pass, and
//! `adjudicate` prints only the emissions. That is `run_ready_lint`'s own rule —
//! stdout is the data channel, and a human line appended to it makes the document
//! unparseable for the caller that asked for it — and no consumer reads it: the
//! switched columns read `status` and `stdout-line = "cites-body "`, both of which
//! this file compares in full.
//!
//! Stating the bound is the point rather than a caveat. A replay that compared
//! whole stdout would fail on a difference nothing consumes, and the next reader
//! would "fix" it by teaching the crate to print a human sentence into a data
//! channel.
//!
//! # The program is retired, so its half is a RECORDING (CLOUD-1221)
//!
//! This file used to spawn `mise-tasks/ready-lint.sh` on unix and compare. The
//! program retired with its last caller, so its answers over the corpus were
//! captured at the commit that deleted it and pinned as [`RECORDED`]; the
//! compiled authority is held to them on every platform now, and the two shapes
//! where it deliberately answers otherwise are pinned by their owning rows.
//!
//! # The status contract is INVERTED here, and that is the trap this file guards
//!
//! `ready-lint.sh` spells `0` pass, `1` violation, `2` could-not-look; batten's
//! own `0/1/2/3` table spells `2` for the policy verdict. `adjudicate` answers in
//! the SHELL's codes precisely so the columns' `{ "0" = "ready", "1" = "unready" }`
//! tables keep their meaning — and a re-mapping there would be a wrong verdict
//! wearing a right verdict's shape, which reads as data rather than as a gap.
//! Every case below asserts the raw status, so that inversion cannot be quietly
//! undone.

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
///
/// **AND THE `[ready]` THRESHOLDS ARE PART OF IT, which this omitted** (CLOUD-1395).
/// `Grammar::resolve` reads the `[[pattern]]` rows and nothing else; the CLI
/// builds the grammar it ships in `lib.rs`'s `board_grammar`, which chains
/// `with_prose_threshold` and `with_pressure_test_threshold` off `[ready]`. A
/// replay that called only `resolve` therefore compared the program against a
/// compiled producer **configured differently from the one that ships** — with
/// every ratchet unset, so no clause reading one could fire, on any payload.
///
/// That is the same class of defect as the corpus gaps this file already records,
/// one level up: `bump` was added over a corpus with no §6 clause, `createdAt` was
/// absent from every payload — and underneath both, the threshold those clauses
/// read was `None` regardless. A fidelity replay whose subject is not the shipped
/// configuration is not a fidelity replay, and it passes for that reason.
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
    .into_iter()
    .chain(section_six())
    .chain(claims_object())
    .collect()
}

/// The §6 shapes, lifted out because `corpus` crossed `too_many_lines` — and
/// worth their own name anyway.
///
/// §6 WAS ABSENT FROM THE CORPUS ENTIRELY, and that is the second half of why
/// CLOUD-1092's divergence survived a replay: adding the `bump` comparison alone
/// passed green over payloads that could not exercise it. That is CLOUD-418's
/// class inside the file written to prevent it, which is why the axis was added
/// WITH these rather than before them.
///
/// One discriminator and two controls, and the controls are what make the
/// discriminator mean anything. The third is pinned by
/// [`the_recorded_divergences_are_the_compiled_authoritys_decided_answers`].
fn section_six() -> Vec<(&'static str, serde_json::Value)> {
    let payload = |description: &str| {
        let mut object = serde_json::Map::new();
        object.insert(
            "id".to_owned(),
            serde_json::Value::String("CLOUD-1".to_owned()),
        );
        object.insert(
            "description".to_owned(),
            serde_json::Value::String(description.to_owned()),
        );
        serde_json::Value::Object(object)
    };
    vec![
        (
            "§6 naming a releasing type — both producers derive the same bump",
            payload("**Refinement — Ready**\n\n* **Commit / bump (§6).** `fix` → **patch**."),
        ),
        (
            "§6 declaring no bump AND no type — the dispatch-record shape, still `none`",
            payload(
                "**Refinement — Ready**\n\n* **Commit / bump (§6).** **no bump** — this row \
                 lands no commit.",
            ),
        ),
    ]
}

/// The shapes the CLAIMS-OBJECT RATCHET decides, which no payload here could
/// reach before (CLOUD-1395).
///
/// **The exit-code axis was already compared and had nothing to compare over.**
/// `the_compiled_authority_answers_exactly_what_the_program_answered` has
/// asserted `compiled_status == shell_status` all along, and it passed — because
/// every payload in the corpus omits `createdAt`, and
/// `[ready] prose_dialect_required_from` is read against exactly that field. A
/// row with no creation instant is never past the cutover, so `ready.rs`'s
/// `claims-object-absent` clause could not fire on any shape the replay ran, and
/// the one axis that would have caught the divergence was vacuous rather than
/// missing.
///
/// That is the same defect this file already records one axis over: CLOUD-1092's
/// `bump` comparison was added to a corpus carrying no §6 clause at all, so it
/// "had nothing to say". An assertion is only worth its line if some payload can
/// make it fail, and adding the payload is the work — not adding the assertion.
///
/// One discriminator and one control. The control is what proves the
/// discriminator is about the CUTOVER rather than about carrying a `createdAt` at
/// all.
fn claims_object() -> Vec<(&'static str, serde_json::Value)> {
    let payload = |created: &str, description: &str| {
        let mut object = serde_json::Map::new();
        object.insert(
            "id".to_owned(),
            serde_json::Value::String("CLOUD-1".to_owned()),
        );
        object.insert(
            "createdAt".to_owned(),
            serde_json::Value::String(created.to_owned()),
        );
        object.insert(
            "description".to_owned(),
            serde_json::Value::String(description.to_owned()),
        );
        serde_json::Value::Object(object)
    };
    vec![(
        "a row created BEFORE the cutover carrying no claims object — the ratchet does not          reach it, so both producers still read the prose",
        payload(
            "2026-08-01T00:00:00.000Z",
            "**Refinement — Ready**\n\n* **Commit / bump (§6).** `fix` → **patch**.",
        ),
    )]
}

/// What `mise-tasks/ready-lint.sh` answered over [`corpus`], RECORDED before the
/// program was retired (CLOUD-1221), in [`corpus`]'s order: the status, then the
/// `cites-body `, `cites-blockers ` and `bump ` lines a consumer reads (`None`
/// where the program never got that far).
///
/// **A recording, not a replay, and that is the honest shape once the program is
/// gone.** The replay ran both producers over one corpus; with one producer left,
/// the other's answers are fixed data captured from it — by piping each corpus
/// payload to the program at the commit that deleted it — and the compiled
/// authority is held to them. A shape added to the corpus later has no recording,
/// and the length assertion below says so rather than letting it pass unchecked.
/// One recorded answer: the exit code and the three captured fields.
type Recorded = (
    i32,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

const RECORDED: [Recorded; 13] = [
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
];

/// A line a consumer reads, by its prefix, or `None` where the producer never
/// got that far.
fn emitted<'a>(out: &'a str, prefix: &str) -> Option<&'a str> {
    out.lines().find_map(|line| line.strip_prefix(prefix))
}

#[test]
fn the_compiled_authority_answers_what_the_program_was_recorded_answering() {
    let root = root();
    let grammar = grammar();
    let corpus = corpus();
    assert_eq!(
        corpus.len(),
        RECORDED.len(),
        "a corpus shape with no recording is compared against nothing: the program is \
         retired, so a new shape asserts the compiled answer in a case of its own"
    );
    for ((shape, value), (status, body, blockers, bump)) in corpus.into_iter().zip(RECORDED) {
        let (compiled_status, out) = batten::ready::adjudicate(&grammar, &value, &root)
            .unwrap_or_else(|| panic!("the compiled authority reads the corpus payload: {shape}"));
        assert_eq!(
            compiled_status, status,
            "the status a column maps, for {shape}"
        );
        assert_eq!(
            emitted(&out, "cites-body "),
            body,
            "`cites-body`, for {shape}"
        );
        assert_eq!(
            emitted(&out, "cites-blockers "),
            blockers,
            "`cites-blockers`, for {shape}"
        );
        assert_eq!(emitted(&out, "bump "), bump, "`bump`, for {shape}");
    }
}

/// The two shapes where the compiled authority DELIBERATELY answers differently
/// from what the program was recorded answering — each owned by the row that
/// decided it, and each pinned so the difference stays a decision rather than a
/// drift.
///
/// CLOUD-1092: a row naming a NON-releasing type releases nothing and still lands
/// a commit, so the compiled authority emits `no-release` where the program
/// emitted `none` — the token the board check's In Review exemption reads.
/// CLOUD-1395: a row created after `[ready] prose_dialect_required_from` owes the
/// claims object, which the program had no clause for (recorded: exit `0`).
#[test]
fn the_recorded_divergences_are_the_compiled_authoritys_decided_answers() {
    let root = root();
    let grammar = grammar();
    let non_releasing = serde_json::json!({
        "id": "CLOUD-1",
        "description": "**Refinement — Ready**\n\n* **Commit / bump (§6).** `test` → **no bump**.",
    });
    let (_, out) = batten::ready::adjudicate(&grammar, &non_releasing, &root)
        .expect("the compiled authority reads the payload");
    assert_eq!(
        emitted(&out, "bump "),
        Some("no-release"),
        "recorded: `none`"
    );

    let after_cutover = serde_json::json!({
        "id": "CLOUD-1",
        "createdAt": "2026-09-03T00:00:00.000Z",
        "description": "**Refinement — Ready**\n\n* **Commit / bump (§6).** `fix` → **patch**.",
    });
    let (status, _) = batten::ready::adjudicate(&grammar, &after_cutover, &root)
        .expect("the compiled authority reads the payload");
    assert_eq!(
        status, 1,
        "recorded: exit 0, the program having no ratchet clause"
    );
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
        "a replay corpus that never reaches a status is not evidence about the mapping of \
         that status: pass, violation and could-not-look must all appear"
    );
}
