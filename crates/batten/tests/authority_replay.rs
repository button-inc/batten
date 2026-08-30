//! The compiled Ready authority and the shell program agree (CLOUD-1100).
//!
//! CLOUD-909's obligation, applied to the one thing CLOUD-1100 actually changed
//! about how a verdict is reached. The GRAMMAR's fidelity is already settled —
//! `crates/batten/tests/ready.rs` carries all 82 cases of `tests/ready-lint.bats`
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
