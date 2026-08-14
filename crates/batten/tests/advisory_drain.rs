//! The advisory drain over the compiled binary (CLOUD-79).
//!
//! The unit tests in `src/drain.rs` pin the state machine against an explicit
//! clock. These pin the half a unit test structurally cannot reach: that the
//! drain is wired to the **post-tool event of the `hook` surface**, that its
//! pacing comes from `batten.toml` rather than from a constant, and that every
//! path through it exits `0`.
//!
//! A separate target rather than more of `tests/cli.rs`: this needs the same
//! store-and-home fixture the ledger tests use, and `cli.rs` is four thousand
//! lines with several sessions editing it. The helpers below are local for the
//! same reason the module doc of `tests/common/mod.rs` gives for existing at all
//! — they are about *what is written*, not *how*.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, batten, scratch};

/// A `PostToolUse` payload in Claude Code's shape, for `session`.
fn post_tool(session: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PostToolUse","session_id":"{session}","cwd":"/w","tool_name":"Bash","tool_input":{{"command":"echo hi"}}}}"#
    )
}

/// Run `batten hook --harness claude-code` in `dir` with `payload` on stdin, in a
/// scrubbed environment pointing at the fixture's own state home.
fn hook(dir: &Path, home: &Path, payload: &str) -> Output {
    hook_at(dir, home, payload, &[])
}

/// [`hook`] with extra arguments ahead of the verb — the §3 ladder flags, which
/// are read from raw argument order and so cannot be appended.
fn hook_at(dir: &Path, home: &Path, payload: &str, leading: &[&str]) -> Output {
    let mut command = batten();
    command
        .args(leading)
        .args(["hook", "--harness", "claude-code"])
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        .expect("write the payload");
    child.wait_with_output().expect("run batten hook")
}

/// Run any `batten` subcommand against the fixture's state home.
fn state_cmd(dir: &Path, home: &Path, args: &[&str]) -> Output {
    batten()
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten")
}

/// A repository with one recorded finding whose file is **dirty**, plus an
/// isolated state home.
///
/// The dirty working tree is load-bearing rather than incidental: the finding is
/// code-anchored, so it surfaces only while its file is inside the changed
/// scope. A fixture with a clean tree would assert the filter, not the drain —
/// which `filters_a_code_finding_whose_file_is_not_in_the_changed_scope` does
/// deliberately, and this one must not do by accident.
fn drained_fixture(name: &str, drain_table: &str) -> (PathBuf, PathBuf) {
    marked_fixture(name, drain_table, "fn main() {}\n// TODO fix me\n")
}

/// [`drained_fixture`] over an arbitrary file body, so a test that needs a
/// different number of distinct identities states that number rather than
/// layering markers on top of this one's.
fn marked_fixture(name: &str, drain_table: &str, body: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let config = format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         severity = \"deny\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         no_fix_reason = \"delete the marker once the work behind it is done\"\n\
         {drain_table}"
    );
    let repo = Fixture::at(root.join("repo"))
        .config(&config)
        .file("src/a.rs", body)
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let recorded = state_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "state record failed: {}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    // Put the finding's file into the changed scope without re-recording, so the
    // stored instance still points at the path the filter is asked about.
    common::write(&repo, "src/a.rs", &format!("{body}// edited\n"));
    (repo, home)
}

/// [`hook`] for a session that declares a parent, which is what a warm fork is.
///
/// The two env vars are the host's contract (`session::SESSION_ENV` /
/// `PARENT_ENV`); the payload still carries the child's own id, because a fork is
/// a new session that inherited a lineage rather than a renamed one.
fn forked_hook(dir: &Path, home: &Path, payload: &str, parent: &str) -> Output {
    let mut command = batten();
    command
        .args(["hook", "--harness", "claude-code"])
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("BATTEN_SESSION_PARENT", parent)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        .expect("write the payload");
    child.wait_with_output().expect("run batten hook")
}

/// The `(scan, resultId)` watermark from the one session record under `home` that
/// carries one.
///
/// Read off disk rather than through a verb: the persistence clause is about what
/// survives the process, and a reader that went through the same binary could not
/// tell a written record from a remembered one. Searching for the record that has
/// a watermark rather than computing the lineage key keeps the assertion about the
/// fact — some record holds it — instead of restating the hashing this crate does.
fn watermark(home: &Path) -> Option<(u64, String)> {
    let sessions = std::fs::read_dir(home.join("data").join("batten"))
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("sessions"))
        .find(|path| path.is_dir())?;
    for entry in std::fs::read_dir(sessions).ok()?.flatten() {
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        let document: serde_json::Value = match serde_json::from_str(&text) {
            Ok(document) => document,
            Err(_) => continue,
        };
        if let Some(mark) = document.get("watermark") {
            let scan = mark.get("scan").and_then(serde_json::Value::as_u64)?;
            let id = mark.get("resultId").and_then(serde_json::Value::as_str)?;
            return Some((scan, id.to_owned()));
        }
    }
    None
}

/// The drain payload on stderr, with Batten's own `batten: ` notes removed —
/// those are messages *about* Batten and travel on a different channel by
/// construction (`output::message` vs `output::verdict`).
fn payload(output: &Output) -> Vec<String> {
    common::stderr(output)
        .lines()
        .filter(|line| !line.starts_with("batten: "))
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn a_post_tool_event_drains_the_store_as_pointer_lines() {
    // The wiring, end to end: findings recorded by one verb are surfaced by the
    // hook surface at the post-tool event, and what comes back is a pointer —
    // a fingerprint, a rule id, a `path:line` and a count (rule 4).
    let (repo, home) = drained_fixture("drain-emits", "");

    let first = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(first.status.code(), Some(0), "the drain never denies");
    let lines = payload(&first);
    assert_eq!(lines.len(), 1, "one finding, one line: {lines:?}");
    let fields: Vec<&str> = lines[0].split(' ').collect();
    assert_eq!(fields.len(), 4, "fingerprint, rule, path:line, count");
    assert_eq!(fields[0].len(), 64, "a fingerprint is 64 hex characters");
    assert_eq!(fields[1], "no-todo");
    assert_eq!(fields[2], "src/a.rs:2");
    assert_eq!(fields[3], "1");
    assert!(
        !lines[0].contains("TODO"),
        "a pointer, never the matched content"
    );

    // Nothing goes to stdout: on this host stdout is the decision channel, and a
    // stray byte there is a document the host would try to read as one.
    assert!(common::stdout(&first).is_empty());
}

#[test]
fn a_pre_tool_event_never_drains() {
    // The drain is keyed to the event, not to the surface. Pre-tool is the one
    // event that adjudicates, and mixing an advisory payload into it would put
    // findings on the path that can deny.
    let (repo, home) = drained_fixture("drain-pre-tool", "");
    let output = hook(
        &repo,
        &home,
        r#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/w","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty(), "no advisory payload here");
}

#[test]
fn a_batch_of_wakes_drains_once_and_the_interval_is_config() {
    // Acceptance (a) and (c) together, over the binary and with no fake clock:
    // one fixture coalesces and one does not, and the ONLY difference between
    // them is `interval_ms` in `batten.toml`. A hard-coded window could not
    // produce both columns.
    let (coalescing, home_c) =
        drained_fixture("drain-window-wide", "\n[drain]\ninterval_ms = 600000\n");
    let mut emitted = 0;
    for _ in 0..4 {
        if !payload(&hook(&coalescing, &home_c, &post_tool("batch"))).is_empty() {
            emitted += 1;
        }
    }
    assert_eq!(
        emitted, 1,
        "four verifier results inside one window are one drain"
    );

    let (open, home_o) = drained_fixture("drain-window-zero", "\n[drain]\ninterval_ms = 0\n");
    // A zero window drains every wake. The second and later ones are silent for
    // a DIFFERENT reason — the `resultId` short-circuit — so this asserts the
    // window is open by watching the give-up counter never reach a state a
    // coalescing window would have prevented: the first wake speaks, and a
    // change to the store is picked up on the very next one.
    assert_eq!(payload(&hook(&open, &home_o, &post_tool("batch"))).len(), 1);
    common::write(&open, "src/b.rs", "fn other() {}\n// TODO also fix me\n");
    let recorded = state_cmd(&open, &home_o, &["state", "record"]);
    assert_eq!(recorded.status.code(), Some(0));
    assert_eq!(
        payload(&hook(&open, &home_o, &post_tool("batch"))).len(),
        2,
        "with no window, the next wake reports the new finding immediately"
    );
}

#[test]
fn an_unchanged_finding_set_answers_with_the_marker_rather_than_the_listing() {
    // CLOUD-166 (a) over the binary. The second drain finds exactly what the
    // first did, and says so in one fixed token: re-listing spends context to
    // convey nothing, and SILENCE would be indistinguishable from a drain that
    // never ran — the false green this engine exists to catch.
    let (repo, home) = drained_fixture("drain-result-id", "\n[drain]\ninterval_ms = 0\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("s1"))).len(), 1);
    assert_eq!(
        payload(&hook(&repo, &home, &post_tool("s1"))),
        vec!["unchanged".to_owned()],
        "the same set again is repetition, and repetition has a name"
    );

    // Constant-size whatever the set: a fixture with four findings answers with
    // the same one token as a fixture with one.
    let (many, home_many) = spread_fixture(
        "drain-result-id-many",
        "\n[drain]\ninterval_ms = 0\ncardinality_cap = 100\n",
        4,
    );
    assert_eq!(payload(&hook(&many, &home_many, &post_tool("s1"))).len(), 4);
    assert_eq!(
        payload(&hook(&many, &home_many, &post_tool("s1"))),
        vec!["unchanged".to_owned()]
    );
}

#[test]
fn a_drain_with_nothing_to_say_stays_silent_rather_than_claiming_unchanged() {
    // The distinction the marker would lose if it were emitted unconditionally:
    // "nothing to report" and "the same as before" are different claims, and an
    // agent that cannot tell them apart learns nothing from either.
    let (repo, home) = drained_fixture("drain-nothing-unchanged", "\n[drain]\ninterval_ms = 0\n");
    common::git_in(&repo, &["checkout", "--", "src/a.rs"]);
    for _ in 0..2 {
        assert!(
            payload(&hook(&repo, &home, &post_tool("s1"))).is_empty(),
            "an empty payload is never the unchanged marker"
        );
    }
}

#[test]
fn every_cycle_advances_the_watermark_even_the_one_it_short_circuits() {
    // CLOUD-166's persistence clause: the short-circuit skips EMISSION only. The
    // ordinal is what makes that checkable — an id that moved only when the
    // payload moved could not tell a repeated cycle from one that never ran, and
    // the flap rate that divides by it would be measuring nothing.
    let (repo, home) = drained_fixture("drain-watermark", "\n[drain]\ninterval_ms = 0\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("s1"))).len(), 1);
    let first = watermark(&home).expect("the first drain leaves a watermark");
    assert_eq!(first.0, 1, "one cycle, ordinal one");

    assert_eq!(
        payload(&hook(&repo, &home, &post_tool("s1"))),
        vec!["unchanged".to_owned()]
    );
    let second = watermark(&home).expect("and so does the one that said nothing new");
    assert_eq!(
        second.0, 2,
        "the ordinal advances through the short-circuit"
    );
    assert_eq!(
        first.1, second.1,
        "the id does not, because the report did not change"
    );
}

#[test]
fn a_count_only_change_is_news_and_does_not_short_circuit() {
    // CLOUD-166 (b). The same identity observed more often is a state change, and
    // a bare set-hash would have skipped it. The count is in the rendered line, so
    // the digest moves — asserted over the binary because that is where a
    // regression would actually reach an agent.
    let (repo, home) = drained_fixture("drain-count-change", "\n[drain]\ninterval_ms = 0\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("s1"))).len(), 1);

    common::write(
        &repo,
        "src/a.rs",
        "fn main() {}\n// TODO fix me\n// TODO fix me\n",
    );
    let recorded = state_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(recorded.status.code(), Some(0));

    let again = payload(&hook(&repo, &home, &post_tool("s1")));
    assert_eq!(again.len(), 1, "one identity, one line: {again:?}");
    assert_ne!(again, vec!["unchanged".to_owned()], "a count is news");
    assert!(again[0].ends_with(" 1->2"));
}

#[test]
fn a_warm_fork_resumes_from_its_parents_watermark() {
    // CLOUD-166 (c), and the reason the watermark lives on the LINEAGE record
    // rather than beside the per-session wake state: a fork that re-listed its
    // parent's set would re-spend the context the short-circuit exists to save,
    // at the moment a restarted agent has least to spare.
    let (repo, home) = drained_fixture("drain-fork-watermark", "\n[drain]\ninterval_ms = 0\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("parent"))).len(), 1);

    // The fork edge is written by the verb that observes the session, which is
    // CLOUD-83's half and not this one's: the drain reads a lineage, it does not
    // mint one. Recording under the child's declared parentage is what a warm
    // restart does before any tool call reaches the hook.
    let observed = batten()
        .args(["state", "record"])
        .current_dir(&repo)
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("BATTEN_SESSION", "child")
        .env("BATTEN_SESSION_PARENT", "parent")
        .output()
        .expect("run batten state record");
    assert_eq!(observed.status.code(), Some(0));

    let forked = forked_hook(&repo, &home, &post_tool("child"), "parent");
    assert_eq!(forked.status.code(), Some(0));
    assert_eq!(
        payload(&forked),
        vec!["unchanged".to_owned()],
        "the child inherits what the parent was told, and does not repeat it"
    );
}

#[test]
fn two_sessions_hold_independent_windows() {
    // The window is per session, so a second session's first wake is a first
    // wake — it has seen nothing, and must not inherit another session's silence.
    let (repo, home) = drained_fixture("drain-per-session", "\n[drain]\ninterval_ms = 600000\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("alpha"))).len(), 1);
    assert!(
        payload(&hook(&repo, &home, &post_tool("alpha"))).is_empty(),
        "alpha is inside its own window"
    );
    assert_eq!(
        payload(&hook(&repo, &home, &post_tool("beta"))).len(),
        1,
        "beta has its own"
    );
}

#[test]
fn filters_a_code_finding_whose_file_is_not_in_the_changed_scope() {
    // The changed-scope filter, over the binary: same store, same event, clean
    // tree. The finding is real and stays in the store — it is simply not about
    // anything in front of the agent right now.
    let (repo, home) = drained_fixture("drain-scope-filter", "");
    common::git_in(&repo, &["checkout", "--", "src/a.rs"]);
    let output = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        payload(&output).is_empty(),
        "nothing to emit prints nothing"
    );

    // And it is recorded as withheld BY THE ENGINE — visible in the store
    // immediately, with no later verb needed to fold it, because the rate this
    // feeds reads records rather than shards.
    let shown = state_cmd(&repo, &home, &["state", "list", "-J"]);
    let document: serde_json::Value =
        serde_json::from_slice(&shown.stdout).expect("state list -J is JSON");
    assert_eq!(
        document[0]["presentation"]["not-shown"], "drain-suppressed",
        "the suppression is journalled, not merely skipped: {document}"
    );
}

#[test]
fn a_session_less_payload_degrades_without_draining_or_failing() {
    // CLOUD-43's contract: a missing session degrades to per-invocation
    // handling. Per-invocation is exactly the once-per-verifier behaviour the
    // window exists to prevent, so the honest degradation is to hold the wake —
    // loudly on the verbose rung, never as an error and never as a deny.
    const SESSIONLESS: &str = r#"{"hook_event_name":"PostToolUse","cwd":"/w","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#;

    let (repo, home) = drained_fixture("drain-no-session", "");
    let output = hook(&repo, &home, SESSIONLESS);
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
    assert!(
        !common::stderr(&output).contains("no session"),
        "and a default run is not told about it: on a host that never sends a \
         session this is the ordinary state, not news"
    );

    let loud = hook_at(&repo, &home, SESSIONLESS, &["-v"]);
    assert_eq!(loud.status.code(), Some(0));
    assert!(
        common::stderr(&loud).contains("no session"),
        "asking for detail produces it: {}",
        common::stderr(&loud)
    );
}

/// [`drained_fixture`] with `spans` distinct forbidden markers in one file, so
/// one rule surfaces that many distinct identities in a single drain.
///
/// Distinct spans rather than a repeated one deliberately: identical spans fold
/// into one identity with a count, which is the input the *re-raise* case wants
/// and the opposite of what the cardinality cap is about.
fn spread_fixture(name: &str, drain_table: &str, spans: usize) -> (PathBuf, PathBuf) {
    let mut body = String::from("fn main() {}\n");
    for index in 0..spans {
        body.push_str(&format!("// TODO number {index}\n"));
    }
    marked_fixture(name, drain_table, &body)
}

#[test]
fn a_rule_over_the_cardinality_cap_emits_one_summary_line_and_the_cap_is_config() {
    // CLOUD-82 (b) over the binary, and the half a renderer unit test cannot
    // reach: the cap that decides is the one in `batten.toml`. Same fixture,
    // same findings, two caps, two payloads — a hard-coded K could not produce
    // both columns, and a key that parsed but did nothing would produce neither.
    let (capped, home_c) = spread_fixture(
        "drain-cap-on",
        "\n[drain]\ninterval_ms = 0\ncardinality_cap = 2\n",
        4,
    );
    let lines = payload(&hook(&capped, &home_c, &post_tool("s1")));
    assert_eq!(
        lines,
        vec!["rule no-todo: 2+ findings".to_owned()],
        "one pointer-only summary line, never the four entries"
    );

    let (uncapped, home_u) = spread_fixture(
        "drain-cap-off",
        "\n[drain]\ninterval_ms = 0\ncardinality_cap = 10\n",
        4,
    );
    let lines = payload(&hook(&uncapped, &home_u, &post_tool("s1")));
    assert_eq!(
        lines.len(),
        4,
        "under the cap every identity speaks: {lines:?}"
    );

    // The withheld identities are recorded under the reason that feeds
    // rule-health telemetry — not as an ordinary drain suppression, which is
    // what a transient bound would be.
    let shown = state_cmd(&capped, &home_c, &["state", "list", "-J"]);
    let document: serde_json::Value =
        serde_json::from_slice(&shown.stdout).expect("state list -J is JSON");
    assert_eq!(
        document[0]["presentation"]["not-shown"], "over-cardinality-cap",
        "the cap is journalled as itself: {document}"
    );
}

#[test]
fn the_emitted_payload_stays_under_the_configured_token_budget() {
    // CLOUD-82 (a) over the binary. The budget is asserted against the bytes the
    // host actually receives, with the same estimator `[budget]` gates
    // instruction files with — a second estimator here could agree with nothing.
    const BUDGET: usize = 20;
    let (repo, home) = spread_fixture(
        "drain-budget",
        &format!("\n[drain]\ninterval_ms = 0\ncardinality_cap = 100\ntoken_budget = {BUDGET}\n"),
        12,
    );
    let lines = payload(&hook(&repo, &home, &post_tool("s1")));
    assert!(
        batten::budget::estimate_tokens(&lines.join("\n")) <= BUDGET,
        "over the configured budget: {lines:?}"
    );
    assert!(
        lines.last().is_some_and(
            |line| line.starts_with("budget: ") && line.ends_with(" findings withheld")
        ),
        "and the payload says how much it did not say: {lines:?}"
    );
}

#[test]
fn a_re_raised_group_reports_the_delta_rather_than_the_instance_list() {
    // CLOUD-82 (c) over the binary. The same identity observed more often is one
    // line carrying `old->new` — the identity did not change, the count did, and
    // the delta is the whole of the news.
    let (repo, home) = drained_fixture("drain-re-raise", "\n[drain]\ninterval_ms = 0\n");
    let first = payload(&hook(&repo, &home, &post_tool("s1")));
    assert_eq!(first.len(), 1);
    assert!(
        first[0].ends_with(" 1"),
        "the first sighting is a count: {first:?}"
    );

    // The SAME span again: identical spans fold into one identity with a count
    // of two, which is the multiset re-raise this asserts.
    common::write(
        &repo,
        "src/a.rs",
        "fn main() {}\n// TODO fix me\n// TODO fix me\n",
    );
    let recorded = state_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(recorded.status.code(), Some(0));

    let again = payload(&hook(&repo, &home, &post_tool("s1")));
    assert_eq!(again.len(), 1, "one identity, one line: {again:?}");
    assert!(
        again[0].ends_with(" 1->2"),
        "the count field carries the delta: {again:?}"
    );
    let fields: Vec<&str> = again[0].split(' ').collect();
    assert_eq!(fields.len(), 4, "still a pointer, not an instance list");
    assert_eq!(fields[2], "src/a.rs:2", "and one in-scope pointer");
}

#[test]
fn a_repository_with_no_store_drains_nothing_and_still_allows() {
    // `batten hook` is registered once and then mediates every call wherever the
    // agent happens to be. A repository that has never recorded anything is the
    // ordinary first-run state, not an error — and must not become the reason a
    // session cannot proceed.
    let repo = Fixture::new("drain-unbound")
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::new("drain-unbound-home").build();
    let output = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
}

#[test]
fn a_directory_that_is_not_a_batten_repository_drains_nothing() {
    // The cheapest refusal, and the one that runs most often: no committed
    // authority means there is nothing to pace against and nothing to read.
    let dir = common::scratch_outside_tree("batten-drain", "no-authority");
    let home = Fixture::at(dir.join("home")).build();
    let output = hook(&dir, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
}

// --- the emission policy: flap detection on this plane only (CLOUD-165) -------

/// A fixture whose forbid finding can be raised and cleared at will, driven
/// through the surface that journals evaluations.
///
/// `enforce` rather than `state record`, and the choice is the mechanism: the
/// evaluation journal the ratio is computed over is written by the enforce surface
/// (CLOUD-529), which is why these two issues land together. A `forbid` rule runs
/// on both surfaces, so nothing here needs a spawning kind.
fn flapping_fixture(name: &str, drain_table: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let config = format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         severity = \"deny\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         no_fix_reason = \"delete the marker once the work behind it is done\"\n\
         {drain_table}"
    );
    let repo = Fixture::at(root.join("repo"))
        .config(&config)
        .file("src/a.rs", "fn main() {}\n// TODO fix me\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let recorded = state_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "state record: {}",
        common::stderr(&recorded)
    );
    (repo, home)
}

/// Raise or clear the finding, then evaluate — one evaluation boundary.
///
/// The file is rewritten either way, so its path stays inside the changed scope
/// whichever state this leaves the finding in: a clear that also left the scope
/// would be asserting the scope filter rather than the policy.
fn evaluate(repo: &Path, home: &Path, raised: bool) {
    let body = if raised {
        "fn main() {}\n// TODO fix me\n"
    } else {
        "fn main() {}\n// fixed\n"
    };
    common::write(repo, "src/a.rs", body);
    let enforced = state_cmd(repo, home, &["enforce"]);
    assert_eq!(
        enforced.status.code(),
        Some(if raised { 2 } else { 0 }),
        "the verdict tracks the tree every evaluation: {}",
        common::stderr(&enforced)
    );
}

/// The one stored record, as `state list -J` reads it back.
fn stored(repo: &Path, home: &Path) -> serde_json::Value {
    let listed = state_cmd(repo, home, &["state", "list", "-J"]);
    assert_eq!(
        listed.status.code(),
        Some(0),
        "state list: {}",
        common::stderr(&listed)
    );
    let records: Vec<serde_json::Value> =
        serde_json::from_str(&common::stdout(&listed)).expect("state list -J is a document");
    assert_eq!(records.len(), 1, "{records:?}");
    records.into_iter().next().expect("one record")
}

/// The occurrence count the store holds for this ref, or `None` when the
/// observation is not a count at all.
fn occurrences(record: &serde_json::Value) -> Option<u64> {
    record["instances"][0]["occurrences"]["Observed"].as_u64()
}

// Acceptance (a), all four clauses over one alternating fixture.
#[test]
fn an_alternating_rule_tracks_state_truthfully_while_its_emissions_stop_at_the_cap() {
    // A window that a handful of evaluations fills, a threshold the alternation
    // clears, and a cap of one so the second emission is the suppressed one.
    let (repo, home) = flapping_fixture(
        "drain-flap",
        "\n[drain]\ninterval_ms = 0\nflap_window = 6\nflap_percent = 50\nemit_cap = 1\n",
    );

    let mut emissions = 0;
    let mut suppressed = false;
    for round in 0..6 {
        let raised = round % 2 == 0;
        evaluate(&repo, &home, raised);

        // THE STATE PLANE, asserted every single evaluation rather than at the end:
        // this is CLOUD-81's law, and the whole point of the plane split is that no
        // amount of emission policy may touch it.
        let record = stored(&repo, &home);
        assert_eq!(
            occurrences(&record),
            Some(u64::from(raised)),
            "round {round}: the store says what the last scan saw"
        );

        let woken = hook(&repo, &home, &post_tool("flap"));
        assert_eq!(woken.status.code(), Some(0), "the drain never denies");
        let lines = payload(&woken);
        if lines.iter().any(|line| line.contains("no-todo")) {
            emissions += 1;
        }
        if stored(&repo, &home)["presentation"]["not-shown"] == "flap-suppressed" {
            suppressed = true;
        }
    }

    assert!(
        suppressed,
        "the identity is annotated as withheld by the signal policy, journalled \
         under its own reason so the false-positive rate excludes it"
    );
    assert!(
        emissions <= 2,
        "emissions stop at the cap; got {emissions} over six evaluations"
    );

    // The rule-health counter, on the operator's channel: a rule id and a count,
    // never a finding's content.
    let told = common::stderr(&hook_at(&repo, &home, &post_tool("flap-verbose"), &["-v"]));
    assert!(
        told.contains("1 rule(s) with a flapping identity"),
        "the annotation feeds per-rule health: {told}"
    );
    assert!(!told.contains("TODO"), "pointer-only: {told}");

    // And the state plane is still truthful at the end: the last evaluation
    // cleared, and the finding cleared with it, cap or no cap.
    evaluate(&repo, &home, false);
    assert_eq!(occurrences(&stored(&repo, &home)), Some(0));
}

// Acceptance (b). The load-bearing case for the (identity × context) key: two
// worktrees at two refs, each monotone, interleaved in one shared journal.
#[test]
fn a_worktree_pair_at_different_refs_is_not_annotated_flapping() {
    let (repo, home) = flapping_fixture(
        "drain-flap-worktrees",
        "\n[drain]\ninterval_ms = 0\nflap_window = 6\nflap_percent = 50\nemit_cap = 1\n",
    );
    // A second checkout at its own ref. It shares the store — `git::repo_root`
    // routes a linked worktree to the main checkout — which is exactly why the
    // journal has to separate them by context rather than by store.
    let other = repo.parent().expect("a parent").join("other");
    common::git_in(
        &repo,
        &[
            "worktree",
            "add",
            "-b",
            "other",
            other.to_str().expect("a utf-8 path"),
        ],
    );

    // Each ref holds one state and keeps it. Interleaved, the log alternates.
    for _ in 0..3 {
        evaluate(&repo, &home, true);
        evaluate(&other, &home, false);
    }

    let woken = hook(&repo, &home, &post_tool("pair"));
    assert_eq!(woken.status.code(), Some(0));
    assert_ne!(
        stored(&repo, &home)["presentation"]["not-shown"],
        "flap-suppressed",
        "neither ref ever changed state; only the interleaving did"
    );
    let told = common::stderr(&hook_at(&repo, &home, &post_tool("pair-verbose"), &["-v"]));
    assert!(
        told.contains("0 rule(s) with a flapping identity"),
        "and nothing is annotated: {told}"
    );
}

// Acceptance (c). Clearing latency is a property of the state plane, so it must be
// identical with the policy on and off — the same fixture, two `[drain]` tables,
// one variable.
#[test]
fn clearing_latency_is_identical_with_the_policy_on_and_off() {
    let mut cleared_at = Vec::new();
    for (name, table) in [
        (
            "drain-flap-latency-on",
            "\n[drain]\ninterval_ms = 0\nflap_window = 6\nflap_percent = 50\nemit_cap = 0\n",
        ),
        (
            "drain-flap-latency-off",
            "\n[drain]\ninterval_ms = 0\nflap_window = 0\n",
        ),
    ] {
        let (repo, home) = flapping_fixture(name, table);
        // Flap it hard enough that the policy is certainly engaged in the first
        // column, then clear it and count the evaluations to zero.
        for round in 0..4 {
            evaluate(&repo, &home, round % 2 == 0);
            hook(&repo, &home, &post_tool("latency"));
        }
        evaluate(&repo, &home, false);
        let mut rounds = 0;
        while occurrences(&stored(&repo, &home)) != Some(0) {
            rounds += 1;
            assert!(rounds < 5, "{name}: the finding never cleared");
            evaluate(&repo, &home, false);
        }
        cleared_at.push(rounds);
    }
    assert_eq!(
        cleared_at[0], cleared_at[1],
        "hysteresis governs the emission channel and nothing else, so a suppressed \
         identity clears on exactly the evaluation an emitted one does"
    );
    assert_eq!(cleared_at[0], 0, "and it clears on the evaluation itself");
}
