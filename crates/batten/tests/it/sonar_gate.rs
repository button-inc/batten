//! `check grade other` — the external analyzer's verdict on one SHA (CLOUD-441)
//! — over the compiled binary, retiring `[tasks."sonar-gate"]`'s bash body under
//! CLOUD-843.
//!
//! The task is two argv steps now, and every case here runs exactly those two:
//! the `check-runs` `[[forge.query]]` row walked by `batten record query` against
//! `rest`'s `BATTEN_REST_FIXTURE` seam, then `batten check --rule 'check grade
//! other' --fail-on-warning` over what it recorded. Both argvs are read out of
//! the committed `mise.toml`, and the query row, the family, the rule and the
//! three verdicts out of the committed `batten.toml`, so a case asserts the
//! declared gate rather than a copy of it.
//!
//! # THE EXIT CONTRACT CHANGED, and the arms below say where
//!
//! The retired body answered `0` green / `1` red / `2` could-not-look / `3` no
//! answer yet. On the engine's one contract a finding is `2`, whichever finding it
//! is — the verdict token (`check grade red` or `check grade early`) carries the
//! distinction, as `checks green` already made red and not-yet share a code — and
//! could-not-look is the query's `3`, with any stale record removed.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/sonar-gate.sh policy/sonar-gate.rego crates/batten/tests/it/sonar_gate.rs
// carried: tests/sonar-gate.bats policy/sonar-gate.rego crates/batten/tests/it/sonar_gate.rs
// carried: "a green analysis passes" policy/sonar-gate.rego
// carried: "a failed analysis is red, and named" policy/sonar-gate.rego at exit 2 through `check`, where the body used 1; named by the conclusion and the `check grade red` token
// carried: "a neutral conclusion passes — the analyzer graded and did not object" policy/sonar-gate.rego
// carried: "timed_out is red like any other non-success conclusion" policy/sonar-gate.rego at exit 2, as above
// carried: "ABSENT IS NOT A VETO — an analyzer with no opinion cannot wedge a PR" policy/sonar-gate.rego
// changed: "an empty reading is absent, and takes no network to say so" policy/sonar-gate.rego there is no injected reading any more: the reading is the query's, so "empty" is a fetch that returned no check-runs, recorded as a closed window with no rows, and absent from there on. The property kept is that nothing is not a veto
// carried: "a pending analysis is not an answer" policy/sonar-gate.rego `check grade early` at exit 2, where the body used 3
// carried: "a skipped analysis is not an answer either" policy/sonar-gate.rego `check grade early` at exit 2
// carried: "a cancelled analysis is not an answer either — it judged nothing" policy/sonar-gate.rego `check grade early` at exit 2
// carried: "another check's failure is none of this gate's business" policy/sonar-gate.rego
// carried: "a skip superseded by a success passes — the residue does not veto" policy/sonar-gate.rego
// carried: "a success superseded by a FAILURE is red" policy/sonar-gate.rego at exit 2
// carried: "a success superseded by a re-run in flight is not an answer yet" policy/sonar-gate.rego
// "the id breaks a tie between two runs started in the same second" shares its title with a case already ledgered in `checks_green.rs`; a title owes exactly one arm, so that row answers for both suites.
// carried: "a reading with no ordering key fails closed — the least conclusive wins" policy/sonar-gate.rego
// changed: "output is a pointer — a conclusion and a name, never the analysis" policy/sonar-gate.rego the pointer is the conclusion and the verdict token; the check's name is the module's one constant rather than a column of the line, and the analysis never reaches the record because the query's `select` names six fields and no body
// carried: "the verdict is byte-identical across two runs on identical input" policy/sonar-gate.rego
// changed: "a SHA the remote has never seen is NO ANSWER YET, not a failed reading" mise.toml the forge's refusal is the query's could-not-look at exit 3, and it records nothing. The body told a missing commit from any other refusal by reading `gh`'s error text; the vendored client reports a status and never the body (non-negotiable rule 4), so the two are one answer now — never a pass either way, which is the half of the property that mattered
// carried: "any other fetch failure is COULD NOT LOOK — a reading we cannot take is not a pass" mise.toml the query's exit 3
// carried: "an auth failure is could not look too, never a pass" mise.toml the query's exit 3
// carried: "a successful fetch returning nothing is absent — the SHA exists and has no analysis" policy/sonar-gate.rego
// changed: "an AUTHENTICATED unpushed SHA is no answer yet — 422, not 404" mise.toml the same move as the 404 arm above: exit 3, nothing recorded
// carried: "a 422 that is NOT a missing commit stays could-not-look" mise.toml the query's exit 3

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, git_in, init_repo, scratch, write};
use serde_json::{Value, json};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// The commit every case asks about.
const SHA: &str = "deadbeef";

/// The one name the module judges.
const NAME: &str = "SonarCloud Code Analysis";

/// The family, the rule and the verdicts this tier installs, by id.
const FAMILY: &str = "check-runs";
const RULE: &str = "check grade other";
const VERDICTS: [&str; 3] = ["check grade red", "check grade early", "check read partial"];

/// The committed `batten.toml`, parsed.
fn committed() -> toml::Value {
    toml::from_str(&std::fs::read_to_string(at_root("batten.toml")).expect("the config"))
        .expect("batten.toml parses")
}

/// The rows of one array-of-tables whose `key` is one of `ids`.
fn rows(array: &toml::Value, key: &str, ids: &[&str]) -> Vec<toml::Value> {
    array
        .as_array()
        .expect("an array of tables")
        .iter()
        .filter(|row| {
            row.get(key)
                .and_then(toml::Value::as_str)
                .is_some_and(|id| ids.contains(&id))
        })
        .cloned()
        .collect()
}

/// The consumer config: THIS repository's query row, family, rule and verdicts,
/// lifted out of the committed authority and nothing else.
fn config() -> String {
    let real = committed();
    let query = rows(&real["forge"]["query"], "id", &[FAMILY]);
    assert_eq!(query.len(), 1, "one `{FAMILY}` query row is declared");
    let record = rows(&real["record"], "record", &[FAMILY]);
    assert_eq!(record.len(), 1, "the `{FAMILY}` family is declared");
    let rule = rows(&real["rule"], "id", &[RULE]);
    assert_eq!(rule.len(), 1, "the `{RULE}` rule is declared");
    let verdicts = rows(&real["verdict"], "id", &VERDICTS);
    assert_eq!(verdicts.len(), VERDICTS.len(), "every verdict is declared");

    let mut forge = toml::map::Map::new();
    forge.insert("query".to_owned(), toml::Value::Array(query));
    let mut table = toml::map::Map::new();
    table.insert("version".to_owned(), toml::Value::Integer(1));
    table.insert(
        "scope".to_owned(),
        toml::Value::Array(vec![toml::Value::String("**".to_owned())]),
    );
    table.insert("forge".to_owned(), toml::Value::Table(forge));
    table.insert("record".to_owned(), toml::Value::Array(record));
    table.insert("rule".to_owned(), toml::Value::Array(rule));
    table.insert("verdict".to_owned(), toml::Value::Array(verdicts));
    toml::to_string(&toml::Value::Table(table)).expect("re-serializes")
}

/// A committed consumer repository registering the real module, and an empty
/// fixture forge beside it.
fn consumer(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("sonar-gate-{name}"));
    let module = std::fs::read_to_string(at_root("policy/sonar-gate.rego")).expect("the module");
    write(&dir, "policy/sonar-gate.rego", &module);
    write(&dir, "batten.toml", &config());
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    let forge = scratch(&format!("sonar-gate-{name}-forge"));
    (dir, forge)
}

/// One canned response in the fixture's `-i` shape, answering the n-th request.
fn respond(forge: &Path, n: u32, status: u16, body: &str) {
    std::fs::write(
        forge.join(format!("resp.{n}")),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
}

/// What the fixture recorded about the requests that went out.
fn requests(forge: &Path) -> String {
    std::fs::read_to_string(forge.join("args")).unwrap_or_default()
}

/// The two argv steps of `[tasks."sonar-gate"]`, as the committed manifest spells
/// them: `run`'s entries, each with the `batten` invocation's arguments split on
/// spaces outside single quotes and the `sha` argument bound.
fn steps(sha: &str) -> Vec<Vec<String>> {
    let block = common::task_block("sonar-gate").expect("[tasks.\"sonar-gate\"] is declared");
    let parsed: toml::Value = toml::from_str(&block).expect("a task block is a TOML table");
    let run = parsed["tasks"]["sonar-gate"]["run"]
        .as_array()
        .expect("`run` is an argv list, not a shell body")
        .iter()
        .map(|step| step.as_str().expect("a command string").to_owned())
        .collect::<Vec<_>>();
    run.iter()
        .map(|step| {
            let (_, arguments) = step
                .split_once(" -- ")
                .expect("each step invokes the batten binary");
            split(&arguments.replace("{{usage.sha}}", sha))
        })
        .collect()
}

/// Split on spaces, keeping a single-quoted run as one argument.
fn split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// One step, run as the task runs it, against the fixture forge.
fn step(dir: &Path, forge: &Path, argv: &[String]) -> Output {
    common::batten()
        .args(argv)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The query step, then the decision step: the query's output, then the
/// decision's exit code and text.
fn gate(dir: &Path, forge: &Path) -> (Output, Option<i32>, String) {
    let [query, decide] = <[Vec<String>; 2]>::try_from(steps(SHA)).expect("two steps");
    let queried = step(dir, forge, &query);
    let decided = step(dir, forge, &decide);
    (queried, decided.status.code(), said(&decided))
}

/// One check-run as the endpoint returns it, with an analysis body the query
/// must never record.
fn run(
    status: &str,
    conclusion: Option<&str>,
    name: &str,
    started: Option<&str>,
    completed: Option<&str>,
    id: Option<u64>,
) -> Value {
    json!({
        "status": status,
        "conclusion": conclusion,
        "name": name,
        "started_at": started,
        "completed_at": completed,
        "id": id,
        "details_url": "https://sonar.example/dashboard?pullRequest=1",
        "output": {"summary": "THE ANALYSIS BODY"},
    })
}

/// A completed run of the analyzer, stamped.
fn single(conclusion: &str) -> Value {
    run(
        "completed",
        Some(conclusion),
        NAME,
        Some("2026-08-12T03:00:00Z"),
        Some("2026-08-12T03:01:00Z"),
        Some(1),
    )
}

/// One page of check-runs, reporting its own total.
fn page(runs: &[Value]) -> String {
    json!({"total_count": runs.len(), "check_runs": runs}).to_string()
}

/// A fresh consumer answering one page, gated: the decision's code and text,
/// after asserting the query recorded.
fn verdict(name: &str, runs: &[Value]) -> (Option<i32>, String) {
    let (dir, forge) = consumer(name);
    respond(&forge, 1, 200, &page(runs));
    let (queried, code, text) = gate(&dir, &forge);
    assert_eq!(
        queried.status.code(),
        Some(0),
        "{name}: the query records\n{}",
        said(&queried)
    );
    (code, text)
}

#[test]
fn the_task_is_the_query_then_the_rule() {
    let [query, decide] = <[Vec<String>; 2]>::try_from(steps(SHA)).expect("two steps");
    assert_eq!(
        query,
        [
            "record",
            "query",
            FAMILY,
            "--input",
            format!("sha={SHA}").as_str()
        ]
    );
    assert_eq!(decide, ["check", "--rule", RULE, "--fail-on-warning"]);
}

#[test]
fn green_and_neutral_pass() {
    for conclusion in ["success", "neutral"] {
        let (dir, forge) = consumer(&format!("green-{conclusion}"));
        respond(&forge, 1, 200, &page(&[single(conclusion)]));
        let (queried, code, text) = gate(&dir, &forge);
        assert_eq!(queried.status.code(), Some(0), "{}", said(&queried));
        assert_eq!(code, Some(0), "{conclusion}: {text}");
        // THE REQUEST IS THE ASSERTION: the slug and the SHA are bound.
        let asked = requests(&forge);
        assert!(
            asked.contains(&format!("repos/{REPO}/commits/{SHA}/check-runs?")),
            "the request names the bound endpoint: {asked}"
        );
        assert!(asked.contains("per_page=100"), "{asked}");
        assert!(
            !asked.contains('{'),
            "no placeholder reached the wire: {asked}"
        );
    }
}

#[test]
fn a_failed_or_timed_out_analysis_is_red_and_names_only_a_pointer() {
    for conclusion in ["failure", "timed_out"] {
        let (code, text) = verdict(&format!("red-{conclusion}"), &[single(conclusion)]);
        assert_eq!(code, Some(2), "{conclusion}: {text}");
        assert!(text.contains("check grade red"), "{text}");
        assert!(
            text.contains(conclusion),
            "the pointer is the conclusion: {text}"
        );
        assert!(
            !text.contains("THE ANALYSIS BODY") && !text.contains("sonar.example"),
            "rule 4: the analysis never reaches the report: {text}"
        );
    }
}

#[test]
fn absent_is_not_a_veto_and_an_empty_reading_is_absent() {
    let other = run(
        "completed",
        Some("success"),
        "ci",
        Some("2026-08-12T03:00:00Z"),
        Some("2026-08-12T03:01:00Z"),
        Some(1),
    );
    let (code, text) = verdict("absent-other", &[other]);
    assert_eq!(code, Some(0), "{text}");
    let (code, text) = verdict("absent-empty", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn pending_skipped_and_cancelled_are_not_an_answer() {
    for (name, runs) in [
        (
            "pending",
            run(
                "in_progress",
                None,
                NAME,
                Some("2026-08-12T03:00:00Z"),
                None,
                Some(1),
            ),
        ),
        ("skipped", single("skipped")),
        ("cancelled", single("cancelled")),
    ] {
        let (code, text) = verdict(&format!("unanswered-{name}"), &[runs]);
        assert_eq!(code, Some(2), "{name}: {text}");
        assert!(text.contains("check grade early"), "{name}: {text}");
        assert!(
            !text.contains("check grade red"),
            "no verdict is not a red one: {text}"
        );
    }
}

#[test]
fn every_declared_answer_is_an_answer() {
    // The module restates `[env] CI_ANSWERED_CONCLUSIONS`, because a module reads
    // no environment. Every member of the declaration must read as an answer —
    // never `check grade early` — so the restatement cannot drift into calling a
    // verdict "not yet".
    let declared = common::task_env("CI_ANSWERED_CONCLUSIONS");
    for conclusion in declared.split(',').filter(|c| !c.is_empty()) {
        let (_, text) = verdict(&format!("answered-{conclusion}"), &[single(conclusion)]);
        assert!(
            !text.contains("check grade early"),
            "{conclusion} is declared an answer: {text}"
        );
    }
    // And the mirror: a conclusion nobody has seen is not an answer.
    let (code, text) = verdict("answered-unseen", &[single("stale")]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check grade early"), "{text}");
}

#[test]
fn another_checks_failure_is_none_of_this_gates_business() {
    let failed = run(
        "completed",
        Some("failure"),
        "ci",
        Some("2026-08-12T03:00:00Z"),
        Some("2026-08-12T03:01:00Z"),
        Some(2),
    );
    let (code, text) = verdict("other", &[failed, single("success")]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_latest_run_decides() {
    let at = |status: &str, conclusion: Option<&str>, start: &str, end: Option<&str>, id: u64| {
        run(
            status,
            conclusion,
            NAME,
            Some(format!("2026-08-12T03:{start}Z").as_str()),
            end.map(|end| format!("2026-08-12T03:{end}Z")).as_deref(),
            Some(id),
        )
    };
    for (name, runs, want, token) in [
        (
            "skip-then-success",
            vec![
                at("completed", Some("skipped"), "18:10", Some("18:11"), 1),
                at("completed", Some("success"), "20:16", Some("25:00"), 2),
            ],
            Some(0),
            None,
        ),
        (
            "success-then-failure",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 1),
                at("completed", Some("failure"), "05:00", Some("06:00"), 2),
            ],
            Some(2),
            Some("check grade red"),
        ),
        (
            "success-then-rerun",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 1),
                at("in_progress", None, "05:00", None, 2),
            ],
            Some(2),
            Some("check grade early"),
        ),
        (
            "same-second-tie",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 10),
                at("completed", Some("failure"), "00:00", Some("01:00"), 11),
            ],
            Some(2),
            Some("check grade red"),
        ),
    ] {
        let (code, text) = verdict(&format!("latest-{name}"), &runs);
        assert_eq!(code, want, "{name}: {text}");
        if let Some(token) = token {
            assert!(text.contains(token), "{name}: {text}");
        }
    }
}

#[test]
fn a_concurrent_skip_does_not_bury_the_failure_it_raced() {
    // CLOUD-1662's measured shape: the failure STARTED first and CONCLUDED last,
    // so by the conclusion stamp it is the event's latest. Ordering by the start
    // alone would let the skipped twin read "not yet" over a red head.
    let failure = run(
        "completed",
        Some("failure"),
        NAME,
        Some("2026-08-12T04:05:37Z"),
        Some("2026-08-12T04:20:00Z"),
        Some(7),
    );
    let skipped = run(
        "completed",
        Some("skipped"),
        NAME,
        Some("2026-08-12T04:05:39Z"),
        Some("2026-08-12T04:05:40Z"),
        Some(8),
    );
    let (code, text) = verdict("concurrent-skip", &[failure, skipped]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check grade red"), "{text}");
}

#[test]
fn a_later_unstamped_skip_does_not_erase_a_verdict() {
    // A reading with no conclusion stamp falls back to the start, where the
    // path-filtered twin registers a second later and concludes `skipped`. It
    // judged nothing, so it never displaces the success before it.
    let success = run(
        "completed",
        Some("success"),
        NAME,
        Some("2026-08-12T02:34:02Z"),
        None,
        Some(1),
    );
    let skipped = run(
        "completed",
        Some("skipped"),
        NAME,
        Some("2026-08-12T02:34:03Z"),
        None,
        Some(2),
    );
    let (code, text) = verdict("unstamped-skip", &[success, skipped]);
    assert_eq!(code, Some(0), "{text}");
}

/// Two runs with no ordering key: the least conclusive wins, and the pointer
/// names the red conclusion rather than whichever row came last.
#[test]
fn an_unorderable_pair_fails_closed_and_points_at_the_red_one() {
    let bare = |conclusion: &str| run("completed", Some(conclusion), NAME, None, None, None);
    let (code, text) = verdict("unorderable", &[bare("failure"), bare("success")]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check grade red"), "{text}");
    assert!(text.contains("failure"), "{text}");
    assert!(!text.contains("success"), "{text}");
}

#[test]
fn the_verdict_is_byte_identical_across_two_runs() {
    let first = verdict("stable-a", &[single("failure")]);
    let second = verdict("stable-b", &[single("failure")]);
    assert_eq!(first, second);
}

#[test]
fn an_unpushed_sha_is_could_not_look_and_clears_a_stale_record() {
    for (name, status, body) in [
        ("404", 404, r#"{"message": "Not Found"}"#),
        (
            "422",
            422,
            r#"{"message": "No commit found for SHA: deadbeef"}"#,
        ),
    ] {
        // THE STALENESS CASE: a first reading records a failure, the second is
        // refused. The refusal removes the first record, so nothing answers as
        // the current reading.
        let (dir, forge) = consumer(&format!("unpushed-{name}"));
        respond(&forge, 1, 200, &page(&[single("failure")]));
        let (_, code, text) = gate(&dir, &forge);
        assert_eq!(code, Some(2), "the first reading decides: {text}");

        respond(&forge, 2, status, body);
        let (queried, code, text) = gate(&dir, &forge);
        assert_eq!(
            queried.status.code(),
            Some(3),
            "{name}: could-not-look is exit 3\n{}",
            said(&queried)
        );
        assert!(
            !said(&queried).contains("No commit found"),
            "rule 4: the forge's body never reaches the report: {}",
            said(&queried)
        );
        assert_eq!(code, Some(0), "{name}: nothing recorded to judge: {text}");
    }
}

#[test]
fn any_other_failed_read_is_could_not_look() {
    for (name, status) in [("auth", 401), ("validation", 422), ("server", 500)] {
        let (dir, forge) = consumer(&format!("unreadable-{name}"));
        respond(&forge, 1, status, r#"{"message": "refused"}"#);
        let (queried, code, _) = gate(&dir, &forge);
        assert_eq!(queried.status.code(), Some(3), "{name}: {}", said(&queried));
        assert_eq!(code, Some(0), "{name}: a refused read records nothing");
    }
}

#[test]
fn a_successful_fetch_returning_nothing_is_absent() {
    let (code, text) = verdict("fetched-nothing", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_truncated_window_is_partial_never_a_pass() {
    // Three pages of 100 against a head reporting 400 runs: the prefix is
    // recorded and LABELLED, and the module refuses to judge it as the whole —
    // even though every run it did read, the analyzer's included, is green.
    let (dir, forge) = consumer("truncated");
    for n in 1..=3u32 {
        let mut runs: Vec<Value> = (0..100u64)
            .map(|i| {
                run(
                    "completed",
                    Some("success"),
                    &format!("leg-{n}-{i}"),
                    Some("2026-08-12T03:00:00Z"),
                    Some("2026-08-12T03:01:00Z"),
                    Some(u64::from(n) * 1000 + i),
                )
            })
            .collect();
        if n == 1 {
            runs[0] = single("success");
        }
        respond(
            &forge,
            n,
            200,
            &json!({"total_count": 400, "check_runs": runs}).to_string(),
        );
    }
    let (queried, code, text) = gate(&dir, &forge);
    assert_eq!(queried.status.code(), Some(0), "{}", said(&queried));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check read partial"), "{text}");
}

#[test]
fn a_warn_row_reports_without_failing_an_ordinary_check() {
    // The record is branch-keyed and the SHA is not, so a red reading of some
    // other commit must not fail every later `check` on the branch it was run
    // from. Only the task's own `--fail-on-warning` step exits 2.
    let (dir, forge) = consumer("warn");
    respond(&forge, 1, 200, &page(&[single("failure")]));
    let (_, code, _) = gate(&dir, &forge);
    assert_eq!(code, Some(2));
    let ordinary = step(&dir, &forge, &["check".to_owned()]);
    assert_eq!(ordinary.status.code(), Some(0), "{}", said(&ordinary));
    assert!(
        said(&ordinary).contains("check grade red"),
        "{}",
        said(&ordinary)
    );
}
