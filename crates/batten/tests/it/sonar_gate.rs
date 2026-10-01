//! `check grade other` — the external analyzer's verdict on one SHA (CLOUD-441)
//! — over the compiled binary, retiring `[tasks."sonar-gate"]`'s bash body under
//! CLOUD-843.
//!
//! The task is two argv steps now, and every case here runs exactly those two:
//! the `check-runs` `[[forge.query]]` row walked by `batten record query` against
//! `rest`'s `BATTEN_REST_FIXTURE` seam, then `batten check --rule 'check grade
//! other' --fail-on-warning` over what it recorded. Both argvs are read out of
//! the committed `mise.toml`, and the query row, the family and the rule out of
//! the committed `batten.toml`, so a case asserts the declared gate rather than a
//! copy of it. The DECISION is the vendored `check-verdict` preset, whose verdicts
//! ship in the binary, so the consumer config here declares none.
//!
//! # THE EXIT CONTRACT CHANGED, and the `changed:` arms below say where
//!
//! The retired body answered `0` green / `1` red / `2` could-not-look / `3` no
//! answer yet. On the engine's one contract a finding is `2`, whichever finding it
//! is — the verdict token (`check grade red` or `check grade early`) carries the
//! distinction, as `checks green` already made red and not-yet share a code — and
//! could-not-look is the query's `3`, with any stale record removed.
//!
//! # ONE ORDERING, PINNED BY REPLAY
//!
//! The preset orders a name's runs as `batten checks green` does, which the
//! retired body delegated to. Two orderings over one reading are two authorities,
//! so `the_preset_and_checks_green_agree_on_every_reading` replays every reading
//! this tier knows through both and holds them to one answer.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/sonar-gate.sh subject:mise.toml crates/batten/tests/it/sonar_gate.rs
// ported: tests/sonar-gate.bats subject:mise.toml crates/batten/tests/it/sonar_gate.rs
// carried: "a green analysis passes" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "a failed analysis is red, and named" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego the exit is 2 through `check`, where the body used 1; still named, by the check's name and its conclusion beside the `check grade red` token
// carried: "a neutral conclusion passes — the analyzer graded and did not object" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "timed_out is red like any other non-success conclusion" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego red still, at exit 2 where the body used 1
// carried: "ABSENT IS NOT A VETO — an analyzer with no opinion cannot wedge a PR" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "an empty reading is absent, and takes no network to say so" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego there is no injected reading any more: the reading is the query's, so "empty" is a fetch that returned no check-runs, recorded as a closed window with no rows, and absent from there on. The property kept is that nothing is not a veto
// changed: "a pending analysis is not an answer" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego `check grade early` at exit 2, where the body used 3
// changed: "a skipped analysis is not an answer either" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego `check grade early` at exit 2, where the body used 3
// changed: "a cancelled analysis is not an answer either — it judged nothing" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego `check grade early` at exit 2, where the body used 3
// changed: "another check's failure is none of this gate's business" batten.toml the name is a FORGE-SIDE filter now, the query row's `check_name` parameter bound by the task's `--check`, so another check's run never reaches the record; the preset judges each name it is handed on its own latest run, and the request carrying the filter is what this tier asserts
// carried: "a skip superseded by a success passes — the residue does not veto" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "a success superseded by a FAILURE is red" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego red still, at exit 2 where the body used 1
// changed: "a success superseded by a re-run in flight is not an answer yet" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego `check grade early` at exit 2, where the body used 3
// "the id breaks a tie between two runs started in the same second" shares its title with a case already ledgered in `checks_green.rs`; a title owes exactly one arm, so that row answers for both suites.
// changed: "a reading with no ordering key fails closed — the least conclusive wins" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego still closed on the least conclusive run, now red at exit 2 through `check` where the body used 1
// changed: "output is a pointer — a conclusion and a name, never the analysis" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego still a pointer, but its shape moved: a finding naming the check and its conclusion beside the `check grade red` token at exit 2, where the body printed a stdout `failure<TAB>NAME` line at exit 1
// carried: "the verdict is byte-identical across two runs on identical input" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "a SHA the remote has never seen is NO ANSWER YET, not a failed reading" mise.toml the forge's refusal is the query's could-not-look at exit 3, and it records nothing. The body told a missing commit from any other refusal by reading `gh`'s error text; the vendored client reports a status and never the body (non-negotiable rule 4), so the two are one answer now — never a pass either way, which is the half of the property that mattered
// changed: "any other fetch failure is COULD NOT LOOK — a reading we cannot take is not a pass" mise.toml the query's exit 3, where the body used 2
// changed: "an auth failure is could not look too, never a pass" mise.toml the query's exit 3, where the body used 2
// carried: "a successful fetch returning nothing is absent — the SHA exists and has no analysis" crates/batten/src/policy/presets/check-verdict/latest-run-decides.rego
// changed: "an AUTHENTICATED unpushed SHA is no answer yet — 422, not 404" mise.toml the same move as the 404 arm above: exit 3, nothing recorded
// changed: "a 422 that is NOT a missing commit stays could-not-look" mise.toml the query's exit 3, where the body used 2

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};
use serde_json::{Value, json};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// The commit every case asks about.
const SHA: &str = "deadbeef";

/// The one name this repository's analyzer posts under: the task flag's default.
const NAME: &str = "SonarCloud Code Analysis";

/// The same name as the query puts it on the wire.
const NAME_ON_THE_WIRE: &str = "check_name=SonarCloud%20Code%20Analysis";

/// The family, the rule and the preset this tier installs, by id.
const FAMILY: &str = "check-runs";
const RULE: &str = "check grade other";
const PRESET: &str = "check-verdict";

/// Every conclusion the forge's check-run vocabulary carries.
const VOCABULARY: [&str; 8] = [
    "success",
    "neutral",
    "failure",
    "timed_out",
    "action_required",
    "cancelled",
    "skipped",
    "stale",
];

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

/// The consumer config: THIS repository's query row, family and rule, lifted out
/// of the committed authority and nothing else.
fn config() -> String {
    let real = committed();
    let query = rows(&real["forge"]["query"], "id", &[FAMILY]);
    assert_eq!(query.len(), 1, "one `{FAMILY}` query row is declared");
    let record = rows(&real["record"], "record", &[FAMILY]);
    assert_eq!(record.len(), 1, "the `{FAMILY}` family is declared");
    let rule = rows(&real["rule"], "id", &[RULE]);
    assert_eq!(rule.len(), 1, "the `{RULE}` rule is declared");
    assert_eq!(
        rule[0].get("preset").and_then(toml::Value::as_str),
        Some(PRESET),
        "the rule enables the vendored preset rather than a module of this repository's"
    );

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
    toml::to_string(&toml::Value::Table(table)).expect("re-serializes")
}

/// A committed consumer repository enabling the preset, and an empty fixture
/// forge beside it.
fn consumer(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("sonar-gate-{name}"));
    write(&dir, "batten.toml", &config());
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "enable the preset"]);
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

/// The task's declared block, parsed.
fn task() -> toml::Value {
    let block = common::task_block("sonar-gate").expect("[tasks.\"sonar-gate\"] is declared");
    let parsed: toml::Value = toml::from_str(&block).expect("a task block is a TOML table");
    parsed["tasks"]["sonar-gate"].clone()
}

/// The two argv steps of `[tasks."sonar-gate"]`, as the committed manifest spells
/// them: `run`'s entries, each with the `batten` invocation's arguments split on
/// spaces outside single quotes and the `sha` and `check` arguments bound.
fn steps(sha: &str) -> Vec<Vec<String>> {
    task()["run"]
        .as_array()
        .expect("`run` is an argv list, not a shell body")
        .iter()
        .map(|step| step.as_str().expect("a command string").to_owned())
        .map(|step| {
            let (_, arguments) = step
                .split_once(" -- ")
                .expect("each step invokes the batten binary");
            split(
                &arguments
                    .replace("{{usage.sha}}", sha)
                    .replace("{{usage.check}}", NAME),
            )
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
            format!("sha={SHA}").as_str(),
            "--input",
            format!("check={NAME}").as_str(),
        ]
    );
    assert_eq!(decide, ["check", "--rule", RULE, "--fail-on-warning"]);
    // The name is this repository's fact, declared once as the flag's default,
    // and the retired body's override survives as the flag's environment.
    let usage = task()["usage"].as_str().expect("a usage spec").to_owned();
    assert!(usage.contains(&format!("default=\"{NAME}\"")), "{usage}");
    assert!(usage.contains("env=\"SONAR_CHECK_NAME\""), "{usage}");
}

#[test]
fn green_and_neutral_pass() {
    for conclusion in ["success", "neutral"] {
        let (dir, forge) = consumer(&format!("green-{conclusion}"));
        respond(&forge, 1, 200, &page(&[single(conclusion)]));
        let (queried, code, text) = gate(&dir, &forge);
        assert_eq!(queried.status.code(), Some(0), "{}", said(&queried));
        assert_eq!(code, Some(0), "{conclusion}: {text}");
        // THE REQUEST IS THE ASSERTION: the slug, the SHA and the name are bound.
        let asked = requests(&forge);
        assert!(
            asked.contains(&format!("repos/{REPO}/commits/{SHA}/check-runs?")),
            "the request names the bound endpoint: {asked}"
        );
        assert!(asked.contains("per_page=100"), "{asked}");
        assert!(asked.contains(NAME_ON_THE_WIRE), "{asked}");
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
        assert!(text.contains(NAME), "and the check's name: {text}");
        assert!(
            !text.contains("THE ANALYSIS BODY") && !text.contains("sonar.example"),
            "rule 4: the analysis never reaches the report: {text}"
        );
    }
}

#[test]
fn absent_is_not_a_veto_and_an_empty_reading_is_absent() {
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
fn the_answered_set_is_the_declared_one_in_both_directions() {
    // The preset owns the answered set, and `[env] CI_ANSWERED_CONCLUSIONS` is
    // `checks green`'s. Over the forge's whole vocabulary a conclusion is an
    // answer to one exactly when it is an answer to the other, so neither can
    // call a verdict "not yet" nor a non-answer a verdict.
    let declared = common::task_env("CI_ANSWERED_CONCLUSIONS");
    let declared: Vec<&str> = declared.split(',').filter(|c| !c.is_empty()).collect();
    assert!(!declared.is_empty(), "the answered set is declared");
    for conclusion in VOCABULARY {
        let (_, text) = verdict(&format!("answered-{conclusion}"), &[single(conclusion)]);
        assert_eq!(
            declared.contains(&conclusion),
            !text.contains("check grade early"),
            "{conclusion}: declared {declared:?}, decided {text}"
        );
    }
}

#[test]
fn each_name_is_judged_on_its_own_latest_run() {
    // The forge filters to one name, so a second name here is a reading that
    // did not come from this task's query — and the preset still judges each
    // name on its own runs rather than one name's run against another's.
    let failed = run(
        "completed",
        Some("failure"),
        "ci",
        Some("2026-08-12T03:00:00Z"),
        Some("2026-08-12T03:01:00Z"),
        Some(2),
    );
    let later = run(
        "completed",
        Some("success"),
        NAME,
        Some("2026-08-12T03:05:00Z"),
        Some("2026-08-12T03:06:00Z"),
        Some(3),
    );
    let (code, text) = verdict("per-name", &[failed, later]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check grade red"), "{text}");
    assert!(text.contains("ci"), "{text}");
}

/// CLOUD-1662's measured shape: the failure STARTED first and CONCLUDED last.
fn concurrent_skip() -> Vec<Value> {
    vec![
        run(
            "completed",
            Some("failure"),
            NAME,
            Some("2026-08-12T04:05:37Z"),
            Some("2026-08-12T04:20:00Z"),
            Some(7),
        ),
        run(
            "completed",
            Some("skipped"),
            NAME,
            Some("2026-08-12T04:05:39Z"),
            Some("2026-08-12T04:05:40Z"),
            Some(8),
        ),
    ]
}

/// Every multi-run reading this tier decides, by name, with its expected token.
fn readings() -> Vec<(&'static str, Vec<Value>, Option<&'static str>)> {
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
    let bare = |conclusion: &str| run("completed", Some(conclusion), NAME, None, None, None);
    let unstamped = |conclusion: &str, start: &str, id: u64| {
        run(
            "completed",
            Some(conclusion),
            NAME,
            Some(start),
            None,
            Some(id),
        )
    };
    vec![
        (
            "skip-then-success",
            vec![
                at("completed", Some("skipped"), "18:10", Some("18:11"), 1),
                at("completed", Some("success"), "20:16", Some("25:00"), 2),
            ],
            None,
        ),
        (
            "success-then-failure",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 1),
                at("completed", Some("failure"), "05:00", Some("06:00"), 2),
            ],
            Some("check grade red"),
        ),
        (
            "success-then-rerun",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 1),
                at("in_progress", None, "05:00", None, 2),
            ],
            Some("check grade early"),
        ),
        (
            "same-second-tie",
            vec![
                at("completed", Some("success"), "00:00", Some("01:00"), 10),
                at("completed", Some("failure"), "00:00", Some("01:00"), 11),
            ],
            Some("check grade red"),
        ),
        (
            "concurrent-skip",
            concurrent_skip(),
            Some("check grade red"),
        ),
        (
            "unstamped-skip",
            vec![
                unstamped("success", "2026-08-12T02:34:02Z", 1),
                unstamped("skipped", "2026-08-12T02:34:03Z", 2),
            ],
            None,
        ),
        (
            "unorderable-red",
            vec![bare("failure"), bare("success")],
            Some("check grade red"),
        ),
        (
            "unorderable-cancelled",
            vec![bare("cancelled"), bare("success")],
            Some("check grade early"),
        ),
        ("single-success", vec![single("success")], None),
        (
            "single-failure",
            vec![single("failure")],
            Some("check grade red"),
        ),
        (
            "single-skipped",
            vec![single("skipped")],
            Some("check grade early"),
        ),
        ("empty", Vec::new(), None),
    ]
}

#[test]
fn the_latest_run_decides() {
    for (name, runs, want) in readings() {
        let (code, text) = verdict(&format!("latest-{name}"), &runs);
        match want {
            None => assert_eq!(code, Some(0), "{name}: {text}"),
            Some(token) => {
                assert_eq!(code, Some(2), "{name}: {text}");
                assert!(text.contains(token), "{name}: {text}");
            }
        }
    }
}

#[test]
fn a_concurrent_skip_does_not_bury_the_failure_it_raced() {
    // CLOUD-1662's measured shape: the failure STARTED first and CONCLUDED last,
    // so by the conclusion stamp it is the event's latest. Ordering by the start
    // alone would let the skipped twin read "not yet" over a red head.
    let (_, runs, _) = readings()
        .into_iter()
        .find(|(name, _, _)| *name == "concurrent-skip")
        .expect("the reading is tabled");
    let (code, text) = verdict("concurrent-skip", &runs);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("check grade red"), "{text}");
}

#[test]
fn a_later_unstamped_skip_does_not_erase_a_verdict() {
    // A reading with no conclusion stamp falls back to the start, where the
    // path-filtered twin registers a second later and concludes `skipped`. It
    // judged nothing, so it never displaces the success before it.
    let (_, runs, _) = readings()
        .into_iter()
        .find(|(name, _, _)| *name == "unstamped-skip")
        .expect("the reading is tabled");
    let (code, text) = verdict("unstamped-skip", &runs);
    assert_eq!(code, Some(0), "{text}");
}

/// The reading as `checks green` takes it on stdin: `status`, `conclusion`,
/// `name`, `started_at`, `id`, `completed_at`, tab-separated.
fn tsv(runs: &[Value]) -> String {
    use std::fmt::Write as _;
    let text = |value: &Value, dash: bool| {
        value.as_str().map_or_else(
            || String::from(if dash { "-" } else { "" }),
            ToOwned::to_owned,
        )
    };
    let mut out = String::new();
    for row in runs {
        // `writeln!` to a String cannot fail.
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            text(&row["status"], false),
            text(&row["conclusion"], true),
            text(&row["name"], false),
            text(&row["started_at"], false),
            row["id"].as_u64().unwrap_or(0),
            text(&row["completed_at"], false),
        );
    }
    out
}

/// `checks green`'s word over one reading, for the analyzer as a roster of one
/// name that may be absent — the exact invocation the retired body made.
fn engine_word(runs: &[Value]) -> String {
    let answered = common::task_env("CI_ANSWERED_CONCLUSIONS");
    let mut child = common::batten()
        .args([
            "checks",
            "green",
            "--required",
            NAME,
            "--absent-ok",
            NAME,
            "--answered",
            answered.as_str(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the compiled binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(tsv(runs).as_bytes())
        .expect("the reading reaches the child");
    let output = child.wait_with_output().expect("the child answers");
    let document: Value = serde_json::from_slice(&output.stdout).expect("a JSON verdict");
    document["verdict"]
        .as_str()
        .expect("a verdict word")
        .to_owned()
}

#[test]
fn the_preset_and_checks_green_agree_on_every_reading() {
    // THE REPLAY: the retired body's decision (`checks green`) and the preset's,
    // over the same readings. Green is a pass; red is `check grade red`; pending
    // and dead-end are both "no answer" and are `check grade early`.
    for (name, runs, _) in readings() {
        // THE EMPTY READING IS NOT THE SAME INPUT TO BOTH, so it is not replayed.
        // `checks green` reads every check on a commit, where nothing at all is
        // "nothing graded yet" — pending, and pinned so by its own unit tier. The
        // preset reads a window the forge query already filtered to ONE name,
        // where nothing is "that check never ran", which `--absent-ok` says is no
        // veto: `absent_is_not_a_veto_and_an_empty_reading_is_absent` pins it.
        if runs.is_empty() {
            continue;
        }
        let (code, text) = verdict(&format!("replay-{name}"), &runs);
        let preset = if code == Some(0) {
            "green"
        } else if text.contains("check grade red") {
            "red"
        } else if text.contains("check grade early") {
            "early"
        } else {
            panic!("{name}: the preset answered neither: {text}");
        };
        let engine = match engine_word(&runs).as_str() {
            "green" => "green",
            "red" => "red",
            "pending" | "dead-end" => "early",
            other => panic!("{name}: an unknown engine word `{other}`"),
        };
        assert_eq!(preset, engine, "{name}: the two orderings disagree");
    }
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
    // recorded and LABELLED, and the preset refuses to judge it as the whole —
    // even though every run it did read is green.
    let (dir, forge) = consumer("truncated");
    for n in 1..=3u32 {
        let runs: Vec<Value> = (0..100u64)
            .map(|i| {
                run(
                    "completed",
                    Some("success"),
                    NAME,
                    Some("2026-08-12T03:00:00Z"),
                    Some("2026-08-12T03:01:00Z"),
                    Some(u64::from(n) * 1000 + i),
                )
            })
            .collect();
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
fn a_record_torn_without_its_closing_line_is_partial() {
    // The producer writes whole or removes, so a family with no closing line was
    // torn by something else — present, so not could-not-look, and never whole.
    let (dir, forge) = consumer("torn");
    let row = json!({
        "status": "completed",
        "conclusion": "success",
        "name": NAME,
        "started_at": "2026-08-12T03:00:00Z",
        "completed_at": "2026-08-12T03:01:00Z",
        "id": 1,
    });
    record_by_hand(&dir, &format!("row\t{row}\n"));
    assert_partial(&dir, &forge);
}

#[test]
fn a_row_torn_mid_json_is_partial() {
    // A row line cut off inside its JSON, beside a whole closing line: the preset
    // must neither fault (which would read as could-not-look) nor drop the row
    // quietly and judge what is left as the whole reading.
    let (dir, forge) = consumer("torn-row");
    record_by_hand(
        &dir,
        "row\t{\"status\": \"compl\nwindow\tstate=whole\tread=1\tkept=1\n",
    );
    assert_partial(&dir, &forge);
    // THE TOKEN'S MEANING COVERS THIS SOURCE TOO. A torn row is the third way to
    // `check read partial`, and no page budget clears it: the class a reader
    // reaches from the refusal names the torn row and routes to the writer that
    // tore it, not only to the query row's budget.
    let explained = common::batten()
        .args(["policy", "explain", "check read partial"])
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    assert_eq!(explained.status.code(), Some(0), "{}", said(&explained));
    let class = String::from_utf8_lossy(&explained.stdout);
    assert!(class.contains("torn mid-JSON"), "{class}");
    assert!(
        class.contains("every writer of the family besides its query row"),
        "{class}"
    );
}

/// Write the `check-runs` record through `batten record named`, which stores its
/// stdin verbatim — the one writer that can hand the preset a torn record.
fn record_by_hand(dir: &Path, body: &str) {
    let mut writer = common::batten()
        .args(["record", "named", FAMILY])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .spawn()
        .expect("the compiled binary runs");
    writer
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(body.as_bytes())
        .expect("the torn record reaches the child");
    assert_eq!(writer.wait().expect("the writer answers").code(), Some(0));
}

/// The gate's decision step over whatever is recorded is `check read partial` at 2.
fn assert_partial(dir: &Path, forge: &Path) {
    let decided = step(
        dir,
        forge,
        &[
            "check".to_owned(),
            "--rule".to_owned(),
            RULE.to_owned(),
            "--fail-on-warning".to_owned(),
        ],
    );
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("check read partial"),
        "{}",
        said(&decided)
    );
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
