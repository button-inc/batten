//! `release grade early` over the compiled binary, the COMMITTED `[[forge.query]]`
//! windows and a fixture forge (CLOUD-319, CLOUD-1717, CLOUD-843).
//!
//! `[tasks.release-due-record]` read a clock and the forge and recorded two ages;
//! it retired under CLOUD-843 onto two `[[forge.query]]` rows that `record query`
//! walks and windows by its OWN clock. So every case here drives the whole path a
//! consumer depends on: the committed rows load, `record query` asks the fixture
//! forge (`BATTEN_REST_FIXTURE`, routed by endpoint), the windows land where
//! `Fact::Records` projects them, and `batten check` decides over both. The
//! instants are written RELATIVE to the real clock, because the producer's clock
//! is the one thing a caller cannot inject — which is the point of moving it in.
//!
//! A HOLD is `check`'s exit 2, which `auto-release-land.yml` reads as "not yet";
//! could-not-look is `record query`'s exit 3 and removes the window.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-due.sh policy/release-due.rego kind:mechanism crates/batten/tests/it/release_due.rs
// carried: tests/release-due.bats policy/release-due.rego kind:mechanism crates/batten/tests/it/release_due.rs
// carried: "main quiet past the window is due" policy/release-due.rego kind:mechanism
// changed: "a busy main inside the max wait holds, and says what it is waiting on" policy/release-due.rego the hold is carried, as `check`'s exit 2 over `release ship early`; its pointer is the trunk window's kept count now, because no age is recorded any more — the window is decided by the producer's clock and what it is waiting on is the class's own text
// changed: "a hold carries no ::error:: annotation — it is the ordinary outcome" policy/release-due.rego a hold is a finding line through `check` now, which carries no `::error::` either; the case asserts the annotation is absent
// carried: "the max wait interrupts a main that never goes quiet" policy/release-due.rego kind:mechanism
// carried: "no release yet is due — nothing to wait out" policy/release-due.rego kind:mechanism
// changed: "the quiet window is inclusive at exactly 30 minutes" crates/batten/src/forge_query.rs kind:mechanism THE BOUNDARY INVERTED, and in the conservative direction: the old gate was DUE at exactly the window (`age >= quiet`), and now a commit whose instant is exactly the cut-off is KEPT by the producer (`at < cutoff` drops, equality keeps), so kept=1 and the gate HOLDS for that one second, due only once the commit is strictly older than the window; `forge_query`'s own unit tier pins the equality, and a case here cannot place an instant on the second the producer's clock will read
// changed: "the max wait is inclusive at exactly 24 hours" crates/batten/src/forge_query.rs kind:mechanism the same inversion one window over: a release published exactly the max wait ago is kept, so that arm is not due at the boundary and becomes due one second later, where the old gate was due at it (`age >= max-wait`)
// changed: "both windows are honoured from the environment" batten.toml the windows are the committed rows' `since.seconds` — 7200 and 86400, the operating point `auto-release-land.yml` exported — so a window is changed in the authority a reviewer reads, never per invocation; the case asserts the committed rows ARE the windows this tier decides with
// changed: "a non-numeric window is exit 2, never a silent fall back to the default" crates/batten/src/forge_query.rs kind:mechanism a window is a TOML integer now, so a non-numeric one is refused at load (exit 1) before any forge is asked, and `seconds = 0` by `forge_query::validate`
// changed: "an unparseable timestamp is exit 2, on either reading" crates/batten/src/forge_query.rs kind:mechanism a row whose instant does not parse is `record query`'s could-not-look — exit 3, the window removed — which the case asserts over the trunk reading
// changed: "an empty last-commit reading is could-not-look, not a quiet main" policy/release-due.rego a trunk window that read no commit is recorded (read=0) and the module refuses it as `release measure partial`, never as quiet
// withdrawn: "a timestamp later than now is refused rather than subtracted" nothing subtracts: a future instant is inside any trailing window, so it reads as a busy trunk (the conservative answer, a hold) rather than as a negative age the old body had to refuse

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, git_in, init_repo, scratch, write};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// The two window ids, as the committed rows and the module spell them.
const ACTIVITY: &str = "release-due-activity";
const LATEST: &str = "release-due-latest";

/// The committed `[[forge.query]]` rows this gate reads, re-serialised verbatim.
///
/// READ FROM `batten.toml`, never restated: the windows are the rows' own
/// `since.seconds`, and a fixture carrying its own copy would test a window
/// nobody ships.
fn committed_queries() -> String {
    let text = std::fs::read_to_string(at_root("batten.toml")).expect("the authority");
    let parsed: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    let rows: Vec<toml::Value> = parsed["forge"]["query"]
        .as_array()
        .expect("[[forge.query]] rows")
        .iter()
        .filter(|row| {
            row.get("id")
                .and_then(toml::Value::as_str)
                .is_some_and(|id| id == ACTIVITY || id == LATEST)
        })
        .cloned()
        .collect();
    assert_eq!(rows.len(), 2, "both windows are declared");
    let mut forge = toml::map::Map::new();
    forge.insert("query".to_owned(), toml::Value::Array(rows));
    let mut root = toml::map::Map::new();
    root.insert("forge".to_owned(), toml::Value::Table(forge));
    toml::to_string(&toml::Value::Table(root)).expect("the rows serialise")
}

/// A committed consumer repository: the real module, the committed windows, and
/// the two families declared.
fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("release-due-{name}"));
    let module = std::fs::read_to_string(at_root("policy/release-due.rego")).expect("the module");
    write(&dir, "policy/release-due.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run release-due\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n[[pattern]]\nid = \"whole-number\"\n\
             regex = '^[0-9]+$'\n\n{}{}\
             [[rule]]\nid = \"release grade early\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/release-due.rego\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"{ACTIVITY}\"\nwriter = \"batten record query {ACTIVITY}\"\n\n\
             [[record]]\nrecord = \"{LATEST}\"\nwriter = \"batten record query {LATEST}\"\n\n{}",
            verdict("release ship early"),
            verdict("release measure partial"),
            committed_queries(),
        ),
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// An RFC 3339 instant `seconds` before the real clock.
fn ago(seconds: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads")
        .as_secs();
    batten::receipt::rfc3339_utc(now - seconds)
}

/// A fixture forge answering the two endpoints BY ENDPOINT, never by call order:
/// each window is a separate `record query` process.
fn forge(name: &str, trunk: &str, releases: &str) -> PathBuf {
    let forge = scratch(&format!("release-due-{name}-forge"));
    let answer = |file: &str, body: &str| {
        std::fs::write(
            forge.join(file),
            format!("HTTP/2 200\ncontent-type: application/json\n\n{body}\n"),
        )
        .expect("write the canned answer");
    };
    answer("commits", trunk);
    answer("releases", releases);
    std::fs::write(
        forge.join("routes"),
        "/commits?\tcommits\n/releases?\treleases\n",
    )
    .expect("write the routes");
    forge
}

/// The trunk's newest commit, committed `seconds` ago.
fn trunk(seconds: u64) -> String {
    format!(
        r#"[{{"sha": "abc", "commit": {{"committer": {{"date": "{}"}}}}}}]"#,
        ago(seconds)
    )
}

/// The newest release, published `seconds` ago — or none.
fn latest(seconds: Option<u64>) -> String {
    seconds.map_or_else(
        || String::from("[]"),
        |seconds| {
            format!(
                r#"[{{"tag_name": "v1", "published_at": "{}"}}]"#,
                ago(seconds)
            )
        },
    )
}

/// `batten <args>` in `dir` against the fixture forge, naming the repository.
fn against(dir: &Path, forge: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
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

/// Record both windows (asserting each recorded), then decide.
fn verdict(name: &str, trunk_body: &str, releases_body: &str) -> (Option<i32>, String) {
    let dir = repo(name);
    let forge = forge(name, trunk_body, releases_body);
    for id in [ACTIVITY, LATEST] {
        let recorded = against(&dir, &forge, &["record", "query", id]);
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "{name}: `record query {id}` records: {}",
            said(&recorded)
        );
    }
    let decided = against(&dir, &forge, &["check", "--rule", "release grade early"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn main_quiet_past_the_window_is_due() {
    // Three hours quiet against a two-hour window; the release is an hour old, so
    // ONLY the quiet arm can make this due — which is what `quiet-ignored` reds.
    let (code, text) = verdict("quiet", &trunk(3 * 3600), &latest(Some(3600)));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_busy_main_inside_the_max_wait_holds() {
    let (code, text) = verdict("busy", &trunk(300), &latest(Some(3600)));
    assert_eq!(code, Some(2), "a hold: {text}");
    // THE HOLD, NOT ONLY THE CODE: a torn window also exits 2 under this rule, so
    // a producer regression writing a malformed record would pass on the exit
    // alone. The POINTER tells them apart, because `check` carries pointers and
    // never the verdict token: a hold points at a count, a torn window names the
    // window that would not read.
    assert!(text.contains("release grade early"), "a hold: {text}");
    assert!(
        !text.contains("release-due-"),
        "a hold, not a torn window: {text}"
    );
    assert!(
        !text.contains("::error::"),
        "a hold is the ordinary outcome: {text}"
    );
}

#[test]
fn the_max_wait_interrupts_a_main_that_never_goes_quiet() {
    // A trunk that moved a minute ago, and a release older than 24 hours.
    let (code, text) = verdict("max-wait", &trunk(60), &latest(Some(25 * 3600)));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn no_release_yet_is_due() {
    let (code, text) = verdict("no-release", &trunk(60), &latest(None));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_timestamp_later_than_now_reads_as_a_busy_trunk() {
    // Nothing subtracts any more, so a future instant is simply inside the window:
    // the conservative answer, a hold, and never a due release on a clock skew.
    let future = r#"[{"sha": "abc", "commit": {"committer": {"date": "2099-01-01T00:00:00Z"}}}]"#;
    let (code, text) = verdict("future", future, &latest(Some(3600)));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        !text.contains("release-due-"),
        "a hold, not a torn window: {text}"
    );
}

#[test]
fn the_committed_windows_are_the_operating_point() {
    // The knobs `auto-release-land.yml` exported are committed now; this pins the
    // two numbers the workflow's own measurement argues for, so a change to either
    // is a reviewed edit to this case as well as to the row.
    let rows = committed_queries();
    let parsed: toml::Value = toml::from_str(&rows).expect("the rows reparse");
    let seconds = |id: &str| {
        parsed["forge"]["query"]
            .as_array()
            .expect("rows")
            .iter()
            .find(|row| row["id"].as_str() == Some(id))
            .and_then(|row| row["since"]["seconds"].as_integer())
            .expect("a window")
    };
    assert_eq!(seconds(ACTIVITY), 7200, "two quiet hours on the trunk");
    assert_eq!(seconds(LATEST), 86_400, "a day's max wait");
}

#[test]
fn an_unparseable_instant_is_could_not_look_and_records_nothing() {
    let dir = repo("unparseable");
    let forge = forge(
        "unparseable",
        r#"[{"sha": "abc", "commit": {"committer": {"date": "yesterday-ish"}}}]"#,
        &latest(Some(3600)),
    );
    let refused = against(&dir, &forge, &["record", "query", ACTIVITY]);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    let after = against(&dir, &forge, &["check", "--rule", "release grade early"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "nothing recorded to judge: {}",
        said(&after)
    );
}

#[test]
fn a_release_due_window_that_is_absent_or_torn_is_partial() {
    // ONE WINDOW ALONE decides over part of the answer.
    let dir = repo("one-window");
    let forge = forge("one-window", &trunk(300), &latest(Some(3600)));
    let recorded = against(&dir, &forge, &["record", "query", ACTIVITY]);
    assert_eq!(recorded.status.code(), Some(0), "{}", said(&recorded));
    let decided = against(&dir, &forge, &["check", "--rule", "release grade early"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("batten deny release grade early at release-due-latest"),
        "partial, pointing at the window never recorded: {}",
        said(&decided)
    );

    // A TRUNK THAT READ NO COMMIT measured nothing, which is not quiet.
    let (code, text) = verdict("empty-trunk", "[]", &latest(Some(3600)));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten deny release grade early at release-due-activity"),
        "{text}"
    );

    // A WINDOW TORN MID-WRITE: the closing line disagrees with the rows.
    let torn = repo("torn");
    for (id, body) in [
        (ACTIVITY, "window\tstate=whole\tread=1\tkept=1\n"),
        (
            LATEST,
            "row\t{\"published_at\":\"x\"}\nwindow\tstate=whole\tread=1\tkept=1\n",
        ),
    ] {
        let written = common::run_with_stdin(&torn, &["record", "named", id], body);
        assert!(written.status.success(), "{}", said(&written));
    }
    let decided = common::run(&torn, &["check", "--rule", "release grade early"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("batten deny release grade early at release-due-activity"),
        "torn, not a hold: {}",
        said(&decided)
    );
}

#[test]
fn a_refusing_forge_is_exit_3_and_leaves_no_window_to_judge() {
    let dir = repo("refused");
    let forge = scratch("release-due-refused-forge");
    std::fs::write(
        forge.join("resp.1"),
        "HTTP/2 403\ncontent-type: application/json\n\n{\"message\": \"no\"}\n",
    )
    .expect("write the refusal");
    let refused = against(&dir, &forge, &["record", "query", ACTIVITY]);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    let after = against(&dir, &forge, &["check", "--rule", "release grade early"]);
    assert_eq!(after.status.code(), Some(0), "{}", said(&after));
}
