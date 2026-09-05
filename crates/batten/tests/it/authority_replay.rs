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
//! # The replay half is `#[cfg(unix)]`, and the corpus half is not
//!
//! `mise-tasks/ready-lint.sh` opens `#!/usr/bin/env bash`, so Windows cannot
//! execute it at all and the comparison has no second arm there — measured, as a
//! CI-only failure on a tree that was green locally. The gate is on the
//! COMPARISON alone: [`the_corpus_reaches_every_status_the_columns_map`] runs
//! everywhere, because it asks only what the compiled authority answers, and
//! that is a property of the crate rather than of the host. So the platform
//! that cannot run the program still proves the corpus discriminates; what it
//! cannot do is confirm the two producers agree, and no platform-independent
//! rewrite of that exists — a stub would compare the crate to a copy of itself.
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

#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;

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
/// discriminator mean anything. The third lives in [`divergent_corpus`].
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

/// The shapes where the two producers are KNOWN to disagree, each with the row
/// that owns the disagreement.
///
/// Kept as a declared list rather than dropped from the corpus, for the reason
/// `clippy.toml` uses `#[expect]` over `#[allow]` for a spawn: a divergence that
/// is merely absent from a corpus is indistinguishable from one nobody has found,
/// and that is exactly how this one survived. Listed, it is visible, and
/// [`the_producers_still_disagree_only_where_a_row_says_so`] goes RED the moment
/// it is repaired — which forces the entry to be deleted and the shape moved up
/// into [`corpus`], instead of leaving a stale exemption behind.
/// Unix only, for the reason the header gives about the comparison itself: the
/// program is a `#!/usr/bin/env bash` script, so a platform that cannot spawn it
/// cannot observe a divergence from it either. An inventory of disagreements is
/// meaningless where only one producer runs.
#[cfg(unix)]
fn divergent_corpus() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    let payload = |id: &str, description: &str| {
        let mut object = serde_json::Map::new();
        object.insert("id".to_owned(), serde_json::Value::String(id.to_owned()));
        object.insert(
            "description".to_owned(),
            serde_json::Value::String(description.to_owned()),
        );
        serde_json::Value::Object(object)
    };
    vec![(
        "§6 naming a NON-releasing type — releases nothing, still lands a commit",
        "CLOUD-1092",
        payload(
            "CLOUD-1",
            "**Refinement — Ready**\n\n* **Commit / bump (§6).** `test` → **no bump**.",
        ),
    )]
}

/// The shapes where the two producers return a different EXIT CODE, each with the
/// row that owns it.
///
/// Separate from [`divergent_corpus`] because that one inventories a divergence
/// in an EMISSION the columns read, and this one inventories a divergence in the
/// verdict itself. Collapsing them would let a shape that disagrees about `bump`
/// stand in for one that disagrees about whether the row is Ready at all, and
/// those are refused at different gates: `graph-check` reads the token, and
/// `claim-check` reads the verdict.
///
/// CLOUD-472's ratchet — `[ready] prose_dialect_required_from`, read at
/// `crates/batten/src/ready.rs` against the payload's `createdAt` — requires a row
/// created after the cutover to carry the fenced claims object. It landed in the
/// compiled producer only. `mise-tasks/ready-lint.sh` has no clause for it and
/// cannot acquire one: `shell edit refused` declares one route, `rule read
/// first`, with no override and no `bypass_env` — the same wall CLOUD-1221 records
/// for the `bump` split directly above.
///
/// So the gap WIDENS ON A CLOCK rather than on edits: every row created after the
/// cutover is a new disagreement. That is what makes listing it worth more than
/// the usual inventory entry — an unlisted divergence of this shape does not sit
/// still, it grows.
///
/// Measured on CLOUD-1384's own body, same bytes to both producers:
/// `mise run ready-lint` exit 0, `batten ready lint` exit 2 with
/// `claims-object-absent`.
#[cfg(unix)]
fn divergent_verdicts() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    let mut object = serde_json::Map::new();
    object.insert(
        "id".to_owned(),
        serde_json::Value::String("CLOUD-1".to_owned()),
    );
    object.insert(
        "createdAt".to_owned(),
        serde_json::Value::String("2026-09-03T00:00:00.000Z".to_owned()),
    );
    object.insert(
        "description".to_owned(),
        serde_json::Value::String(
            "**Refinement — Ready**\n\n* **Commit / bump (§6).** `fix` → **patch**.".to_owned(),
        ),
    );
    vec![(
        "a row created AFTER the cutover carrying no claims object — the compiled producer          raises `claims-object-absent` and the program has no clause for it",
        "CLOUD-1395",
        serde_json::Value::Object(object),
    )]
}

/// Run the shell program over one payload, and read back what a column reads.
///
/// Unix only: the program is a `#!/usr/bin/env bash` script, so there is nothing
/// for Windows to spawn.
///
/// The inventory row (CLOUD-320): **this spawn stays, and it stays here alone.**
/// A replay's whole value is that it runs the program it is being compared
/// against — routing it through `crate::exec` would compare the crate to a
/// harness rather than to `mise-tasks/ready-lint.sh`, and stubbing it would
/// compare the crate to a copy of itself. It is a test-only site: nothing in the
/// library spawns this program any more, which is what this row exists to
/// establish. If the program is ever retired, this file goes with it.
#[cfg(unix)]
#[expect(
    clippy::disallowed_types,
    reason = "stays: a replay must run the real program it is compared against, so routing \
              this through a harness or a stub would compare the crate to something other \
              than mise-tasks/ready-lint.sh. Test-only, and the library no longer spawns \
              that program at all — which is what this file exists to establish"
)]
fn spawn_the_program(payload: &str) -> (i32, String) {
    let root = root();
    let mut child = std::process::Command::new(root.join("mise-tasks/ready-lint.sh"))
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the shell program is executable from the workspace root");
    child
        .stdin
        .take()
        .expect("the child's stdin is piped")
        .write_all(payload.as_bytes())
        .expect("the payload is writable to the child");
    let output = child.wait_with_output().expect("the child terminates");
    (
        output.status.code().expect("the child was not signalled"),
        String::from_utf8(output.stdout).expect("the program's stdout is UTF-8"),
    )
}

/// The `cites-body ` line a switched column reads, or `None` where the producer
/// never got that far.
#[cfg(unix)]
fn cites_body(out: &str) -> Option<&str> {
    out.lines()
        .find_map(|line| line.strip_prefix("cites-body "))
}

/// The `cites-blockers ` line, the other emission both producers carry.
#[cfg(unix)]
fn cites_blockers(out: &str) -> Option<&str> {
    out.lines()
        .find_map(|line| line.strip_prefix("cites-blockers "))
}

/// The `bump ` line — the third emission, and the one with a consumer OUTSIDE
/// the switched columns.
///
/// It was missing from this replay, and its absence is why CLOUD-1092 could land
/// a fix and go unnoticed for a week. `mise-tasks/graph-check.sh:400-407` keys
/// `declares-no-commit-with-pr` on the literal token `none`, so this line decides
/// whether a row that lands a commit is refused at In Review — a heavier
/// consequence than either emission above, compared by nobody.
///
/// The header's rule is "the CONSUMED axes"; the defect was reading *consumed*
/// as *consumed by the three columns this row switched*. `graph-check` is a
/// consumer of the same producer, so this axis was always in scope.
#[cfg(unix)]
fn bump(out: &str) -> Option<&str> {
    out.lines().find_map(|line| line.strip_prefix("bump "))
}

#[cfg(unix)]
#[test]
fn the_compiled_authority_answers_exactly_what_the_program_answered() {
    let root = root();
    let grammar = grammar();
    for (shape, value) in corpus() {
        let text = serde_json::to_string(&value).expect("a corpus payload is encodable");
        let (shell_status, shell_out) = spawn_the_program(&text);
        let (compiled_status, compiled_out) = batten::ready::adjudicate(&grammar, &value, &root)
            .unwrap_or_else(|| panic!("the compiled authority reads the corpus payload: {shape}"));

        assert_eq!(
            compiled_status, shell_status,
            "the status the switched columns map must be the program's own, for {shape}: \
             compiled {compiled_status}, program {shell_status}"
        );
        assert_eq!(
            cites_body(&compiled_out),
            cites_body(&shell_out),
            "the `cites-body` emission a column reads must be identical, for {shape}"
        );
        assert_eq!(
            cites_blockers(&compiled_out),
            cites_blockers(&shell_out),
            "and so must `cites-blockers`, for {shape}"
        );
        assert_eq!(
            bump(&compiled_out),
            bump(&shell_out),
            "and so must `bump`, for {shape}: `graph-check` reads this token to decide \
             whether a row declaring no release also declares no commit, and the two \
             producers disagreeing there is a false refusal at In Review"
        );
    }
}

/// The declared divergences are still divergences, and there are no others.
///
/// This is the half that makes [`divergent_corpus`] an inventory rather than an
/// exemption. It asserts the disagreement is REAL — so a list entry cannot rot
/// into a note about something already fixed — and it names the row that owns
/// each one, so a reader meets the reason where they meet the fact.
///
/// CLOUD-1092 split the `bump` token so a `test`-typed row could declare "releases
/// nothing" without also declaring "lands no commit". That landed in
/// `crates/batten/src/ready.rs`; `mise-tasks/graph-check.sh:400-407` keys
/// `declares-no-commit-with-pr` on the literal `none` and reads the SHELL
/// producer, which still emits it. Measured live on 2026-08-31: `graph-check`
/// over CLOUD-1144 and its blocker reports `CLOUD-1177 declares-no-commit-with-pr`
/// — a `chore(lint)` row refused for landing the commit it exists to land.
///
/// It is not repaired here because `mise-tasks/ready-lint.sh` is a governed shell
/// rule: `shell edit refused` declares one route, `rule read first`, with no
/// override and no `bypass_env`. Retiring it reaches `graph-check.sh`, and through
/// it `released.sh` and `board-sweep.sh` — four programs and 214 `@test` cases,
/// which is CLOUD-1194's campaign rather than a line in this file. CLOUD-1221
/// carries the measurement.
#[cfg(unix)]
#[test]
fn the_producers_still_disagree_only_where_a_row_says_so() {
    let root = root();
    let grammar = grammar();
    for (shape, owner, value) in divergent_corpus() {
        let text = serde_json::to_string(&value).expect("a corpus payload is encodable");
        let (_, shell_out) = spawn_the_program(&text);
        let (_, compiled_out) = batten::ready::adjudicate(&grammar, &value, &root)
            .unwrap_or_else(|| panic!("the compiled authority reads the corpus payload: {shape}"));

        assert_ne!(
            bump(&compiled_out),
            bump(&shell_out),
            "{owner} records a divergence at {shape} and the two producers now AGREE. \
             If it was repaired, delete the entry from `divergent_corpus` and move the shape \
             into `corpus`, so the agreement is asserted rather than merely expected"
        );
    }
}

/// The declared VERDICT divergences are still divergences, and there are no
/// others.
///
/// [`the_producers_still_disagree_only_where_a_row_says_so`]'s discipline over
/// the other axis: it asserts the disagreement is REAL, so an entry cannot rot
/// into a note about something already repaired, and it goes RED the day
/// `ready-lint.sh` is retired — which is the event that should delete the entry
/// rather than leave a stale exemption behind.
#[cfg(unix)]
#[test]
fn the_producers_return_the_same_verdict_except_where_a_row_says_so() {
    let root = root();
    let grammar = grammar();
    for (shape, owner, value) in divergent_verdicts() {
        let text = serde_json::to_string(&value).expect("a corpus payload is encodable");
        let (shell_status, _) = spawn_the_program(&text);
        let (compiled_status, _) = batten::ready::adjudicate(&grammar, &value, &root)
            .unwrap_or_else(|| panic!("the compiled authority reads the corpus payload: {shape}"));

        assert_ne!(
            compiled_status, shell_status,
            "{owner} records a VERDICT divergence at {shape} and the two producers now AGREE \
             (both {compiled_status}). If it was repaired, delete the entry from \
             `divergent_verdicts` and move the shape into `corpus`, so the agreement is \
             asserted rather than merely expected"
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
        "a replay corpus that never reaches a status is not evidence about the mapping of \
         that status: pass, violation and could-not-look must all appear"
    );
}
