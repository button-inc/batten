//! The bot lane over the compiled binary (CLOUD-1295).
//!
//! `tests/bot-issue.bats` replayed. Every case there drove `mise-tasks/bot-issue.sh`
//! against a stubbed forge client on `PATH`; these drive `batten pr …` and
//! `batten claim bot` against the same stub, so the port is asserted at the seam a
//! consumer actually uses rather than against a fabricated input shape.
//!
//! # Why the stub rather than a fixture policy
//!
//! `.claude/rules/policy-modules.md`'s second tier exists because the load-time
//! tier cannot see whether the ENGINE builds what a predicate reads. The same
//! reasoning applies one level up here: `bot::conventional_type` and
//! `bot::closing_key` are already pinned as pure functions in their own module,
//! and what those cannot see is whether the verb reaches them with the fields the
//! forge actually answers with. A stub that answers the real endpoints is what
//! closes that gap, and it is what lets this suite run on a machine with no
//! credentials at all — the standing `tests/checks-green.bats` had for the same
//! reason.
//!
//! # The ledger
//!
//! Two deleted paths, one arm each, and one arm per deleted `@test` case. The
//! successor is engine source rather than a `policy/*.rego` module — the lane
//! needs stdin, spawns the forge's client with its own arguments, and performs
//! writes, none of which a tree-scoped module may do — so each file arm declares
//! `kind:verb`: `batten pr derive|file|link|ensure|closes` and `batten claim bot`
//! are six new leaves on the command surface.
//!
//! ONE arm per deleted path, which `V-RETIREMENT-AMBIGUOUS` requires, and its
//! `runs:` field names `batten claim bot`. That is the only invocation a
//! GOVERNED caller loses: `tests/verify.bats` names the retired receipt command
//! in a comment and in an assertion, and both are repointed at the verb. The
//! lander's two workflow steps lose `pr ensure` and `pr closes`, and they need
//! no field — `.github/workflows/**` is ungoverned, so those repoints are free.
//! The field's spaces travel as `+`, since an arm is space-separated.
//
// carried: mise-tasks/bot-issue.sh crates/batten/src/bot.rs kind:verb crates/batten/tests/it/bot_lane.rs runs:batten+claim+bot
// carried: tests/bot-issue.bats crates/batten/src/bot.rs kind:verb crates/batten/tests/it/bot_lane.rs
//
// carried: "a bump PR with no row gets one, and the PR is told which row it closes" crates/batten/src/bot.rs kind:verb
// carried: "the mirror issue carries the derived block and a marker naming its PR" crates/batten/src/bot.rs kind:verb
// carried: "THE PR CLOSES THE CLOUD KEY, never the mirror issue (CLOUD-750)" crates/batten/src/bot.rs kind:verb
// carried: "a mirror that is not yet mirrored links nothing, and says so" crates/batten/src/bot.rs kind:verb
// carried: "a second tick reuses the mirror it already filed rather than opening another" crates/batten/src/bot.rs kind:verb
// carried: "IDEMPOTENCE: a second call on the same PR files nothing" crates/batten/src/bot.rs kind:verb
// carried: "a non-bot PR is untouched, and the refusal says whose it is" crates/batten/src/bot.rs kind:verb
// carried: "the retired bot is not on the allowlist either (CLOUD-660)" crates/batten/src/bot.rs kind:verb
// carried: "a PR touching no owned manifest is REFUSED, never given an invented row" crates/batten/src/bot.rs kind:verb
// carried: "a workflow bump is owned too — that manager is in the same lane" crates/batten/src/bot.rs kind:verb
// carried: "a subject with no Conventional type is refused, because that commit could never land" crates/batten/src/bot.rs kind:verb
// carried: "THE DERIVED BLOCK PASSES ready-lint — the same gate a human's row passes" crates/batten/src/bot.rs kind:verb
// carried: "the §6 type is READ from the subject, not chosen here" crates/batten/src/bot.rs kind:verb
// carried: "derive writes nothing — it is the half a gate can read" crates/batten/src/bot.rs kind:verb
// carried: "a mirror that cannot be opened is exit 2, and no key is invented" crates/batten/src/bot.rs kind:verb
// carried: "a body that still closes its row is landable, and the verdict names the key" crates/batten/src/bot.rs kind:verb
// carried: "A KEY NAMED BUT NOT CLOSED IS REFUSED — that is the whole failure being caught" crates/batten/src/bot.rs kind:verb
// carried: "a body naming no key at all is refused, not treated as nothing to check" crates/batten/src/bot.rs kind:verb
// carried: "fixes and resolves close it too — the predicate is closing-key-check's, not link's" crates/batten/src/bot.rs kind:verb
// carried: "DO-NOT-CLOSE does not read as a close, though the marker ends in a closing verb" crates/batten/src/bot.rs kind:verb
// carried: "POINTER, NEVER PAYLOAD: the refusal names the PR and no part of the body" crates/batten/src/bot.rs kind:verb
// carried: "closes writes nothing — it is a read, and a refusal must not repair by editing" crates/batten/src/bot.rs kind:verb

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
//
// UNIX-ONLY, AND THE WINDOWS FAILURE IS WORSE THAN A COULD-NOT-RUN. Every case
// below answers the forge from a `#!/usr/bin/env bash` stub placed first on
// `PATH`. Windows resolves an executable by `PATHEXT`, so an extensionless
// script is not a candidate at all: the stub is skipped, and a Windows runner
// with the REAL `gh` installed then resolves to it — the suite would drive an
// unauthenticated client at `repos/demo/repo` instead of asserting anything.
// Measured on this branch: two cases reported the port broken (exit 3) where the
// port was fine and the stub had simply never run.
//
// `session_provisioning.rs` and `connector_allow_door.rs` gate their whole
// suites on this rung for the same reason, and the retired `tests/bot-issue.bats`
// never ran on Windows either — it stubbed the same client the same way — so
// nothing is narrowed that was covered. A `.cmd` twin of the dispatch would be a
// second authority over what the stub answers, which is the class
// `.claude/rules/policy-modules.md` refuses one level down.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common::{
    Fixture, batten, declared_patterns, run_with_stdin, scratch, stderr, stdout, write,
};

/// What the stubbed forge answers about the pull request under test.
///
/// A struct rather than a pile of environment variables so a case names only the
/// field it is about — the same shape the dying suite's `setup()` had, where each
/// case rewrote one variable and inherited the rest.
struct Forge {
    title: String,
    login: String,
    body: String,
    files: String,
    /// Whether a mirror issue already exists for this pull request.
    mirror: bool,
    /// Whether the tracker's sync has posted its linkback comment yet.
    linkback: bool,
    /// Whether opening an issue succeeds.
    create_ok: bool,
}

impl Default for Forge {
    fn default() -> Self {
        Forge {
            title: "build(deps): update cargo".to_owned(),
            login: "renovate[bot]".to_owned(),
            body: "This PR contains the following updates.".to_owned(),
            files: "Cargo.toml\nCargo.lock".to_owned(),
            mirror: false,
            linkback: true,
            create_ok: true,
        }
    }
}

/// The lane's own facts, as `batten.toml` declares them.
///
/// Spelled here rather than read from this repository's committed table, and
/// deliberately: the suite is about the MATCHER, and a fixture inheriting the
/// consumer's real logins would pass or fail on whether Renovate is still the
/// bot this repository uses.
const LANE: &str = "\n[bot_lane]\n\
repo = \"demo/repo\"\n\
bots = [\"renovate\", \"renovate[bot]\", \"mend-for-github-com[bot]\"]\n\
owned_manifests = [\"mise.toml\", \"Cargo.toml\", \"Cargo.lock\", \".github/workflows/**\"]\n\
marker_prefix = \"bot-lane pr=\"\n\
linkback_marker = \"<!-- linear-linkback -->\"\n\
key_prefix = \"CLOUD-\"\n\
branch_prefix = \"renovate/\"\n\
body_template = \"row.md\"\n";

/// The body template the fixture derives from. Short on purpose: the real one is
/// a page of consumer prose, and what these cases are about is that the
/// placeholders reach it and that no unfilled one survives.
const TEMPLATE: &str = "**Refinement — Ready**\n\n\
* **Source of truth (§1).** The manifest diff on #{{pr}}, opened by `{{login}}` on `{{branch}}`.\n\n\
{{manifests}}\n\n\
* **Commit / bump (§6).** `{{type}}` → no bump.\n";

/// A fixture repository declaring the lane, with the stub on `PATH`.
///
/// Returns the repository and the directory the stub records its writes into, so
/// a case can assert what the forge was ASKED to store rather than only what the
/// verb printed.
fn lane(name: &str, forge: &Forge) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n")
        .config_append(LANE)
        // The REAL Ready grammar, read from the committed table rather than
        // re-typed: `ready lint`'s vocabulary is the consumer's `[[pattern]]`
        // rows, and a fixture spelling its own would assert about a grammar this
        // repository does not use.
        .config_append(&declared_patterns())
        .file("row.md", TEMPLATE)
        // `ready lint`'s own minimum input: §6 needs the workspace version to
        // know which SemVer arrows fire, and it reports an unreadable one as a
        // usage error rather than as a clean pass. Below 0.1.0, matching this
        // repository, so the arrows the derived block's `→ no bump` is judged
        // against are the ones a real row is judged against.
        .file(
            "Cargo.toml",
            "[workspace]\nmembers = []\n[workspace.package]\nversion = \"0.0.1\"\n",
        )
        .git()
        .base_commit()
        .build();
    let stub = root.join("stub");
    let recorded = root.join("recorded");
    std::fs::create_dir_all(&stub).unwrap();
    std::fs::create_dir_all(&recorded).unwrap();
    write_stub(&stub, &recorded, forge);
    (repo, recorded)
}

/// Write the `gh` stub.
///
/// It DISPATCHES ON THE ENDPOINT and answers what `--jq` would have produced, so
/// the stub answers the call rather than re-implementing the tool — the dying
/// suite's own words, and the property that keeps this from asserting its own
/// fixture.
fn write_stub(stub: &Path, recorded: &Path, forge: &Forge) {
    let body = format!(
        "#!/usr/bin/env bash\n\
args=\"$*\"\n\
case \"$args\" in\n\
  *\"-X POST\"*\"/issues\"*)\n\
    if [ '{create_ok}' != yes ]; then echo refused >&2; exit 1; fi\n\
    cat > '{recorded}/issue-body'\n\
    echo 41\n\
    ;;\n\
  *\"-X PATCH\"*)\n\
    cat > '{recorded}/patched-body'\n\
    echo '{{}}'\n\
    ;;\n\
  *\"/comments\"*)\n\
    if [ '{linkback}' = yes ]; then\n\
      printf '%s\\n' '<!-- linear-linkback --> see https://example.test/CLOUD-700/x'\n\
    fi\n\
    ;;\n\
  *\"issues?state=all\"*)\n\
    if [ '{mirror}' = yes ]; then printf '%s\\n' 41; fi\n\
    ;;\n\
  *\"/files\"*)\n\
    printf '%s\\n' '{files}'\n\
    ;;\n\
  *\"pulls?state=open\"*)\n\
    printf '%s\\n' 7\n\
    ;;\n\
  *\"repos/demo/repo/pulls/\"*)\n\
    printf '%s\\t%s\\t%s\\t%s\\n' '{title}' '{body}' '{login}' 'renovate/cargo'\n\
    ;;\n\
  *) echo \"unstubbed gh call: $args\" >&2; exit 1 ;;\n\
esac\n",
        create_ok = yes_no(forge.create_ok),
        linkback = yes_no(forge.linkback),
        mirror = yes_no(forge.mirror),
        recorded = recorded.display(),
        files = forge.files,
        title = forge.title,
        body = forge.body,
        login = forge.login,
    );
    let path = stub.join("gh");
    std::fs::write(&path, body).unwrap();
    make_executable(&path);
}

fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

// No `#[cfg(unix)]` pair here: the module gate above already decides the target,
// so a `#[cfg(not(unix))]` twin would be a definition nothing can reach.
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Run `batten` in `repo` with the stub ahead of the real `PATH`.
fn lane_run(repo: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let stub = repo.parent().unwrap().join("stub");
    // `join_paths` rather than an interpolated separator (CLOUD-617): the
    // separator is `;` on Windows, where a path begins `D:\`, so a `format!`
    // here does not merely fail to separate — it yields a PATH whose first entry
    // is a drive letter.
    let mut entries = vec![stub];
    entries.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(entries).expect("compose PATH");
    let output = batten()
        .args(args)
        .current_dir(repo)
        .env("PATH", path)
        .output()
        .expect("run batten");
    (output.status.code(), stdout(&output), stderr(&output))
}

/// What the stub recorded the mirror issue's body as.
fn issue_body(recorded: &Path) -> String {
    std::fs::read_to_string(recorded.join("issue-body")).unwrap_or_default()
}

/// What the stub recorded the pull request's rewritten body as.
fn patched_body(recorded: &Path) -> String {
    std::fs::read_to_string(recorded.join("patched-body")).unwrap_or_default()
}

// -- ensure ------------------------------------------------------------------

#[test]
fn a_bump_pr_with_no_row_gets_one_and_the_pr_is_told_which_row_it_closes() {
    let (repo, recorded) = lane("lane-ensure", &Forge::default());
    let (code, _, err) = lane_run(&repo, &["pr", "ensure", "7"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(!issue_body(&recorded).is_empty(), "the row was filed");
    assert!(
        patched_body(&recorded).contains("Closes CLOUD-700"),
        "the pull request is told which row it closes: {}",
        patched_body(&recorded)
    );
}

#[test]
fn the_mirror_issue_carries_the_derived_block_and_a_marker_naming_its_pr() {
    let (repo, recorded) = lane("lane-marker", &Forge::default());
    assert_eq!(lane_run(&repo, &["pr", "ensure", "7"]).0, Some(0));
    let filed = issue_body(&recorded);
    assert!(filed.contains("**Refinement — Ready**"), "{filed}");
    // The marker goes LAST, so it is the one line a reader never has to look at
    // and the one line `ensure` always finds.
    assert!(
        filed.trim_end().ends_with("<!-- bot-lane pr=7 -->"),
        "{filed}"
    );
}

#[test]
fn the_pr_closes_the_tracker_key_never_the_mirror_issue() {
    // Closing the mirror would move the row to Done, and Done means RELEASED —
    // so it would assert a release that has not happened.
    let (repo, recorded) = lane("lane-closes-key", &Forge::default());
    assert_eq!(lane_run(&repo, &["pr", "ensure", "7"]).0, Some(0));
    let patched = patched_body(&recorded);
    assert!(patched.contains("Closes CLOUD-700"), "{patched}");
    assert!(
        !patched.contains("Closes #41"),
        "never the mirror: {patched}"
    );
}

#[test]
fn a_mirror_that_is_not_yet_mirrored_links_nothing_and_says_so() {
    let forge = Forge {
        linkback: false,
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-unmirrored", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "ensure", "7"]);
    assert_eq!(
        code,
        Some(0),
        "a tick that cannot finish still made progress"
    );
    assert!(err.contains("not mirrored yet"), "{err}");
    assert!(patched_body(&recorded).is_empty(), "nothing was linked");
}

#[test]
fn a_second_tick_reuses_the_mirror_it_already_filed_rather_than_opening_another() {
    let forge = Forge {
        mirror: true,
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-reuse", &forge);
    assert_eq!(lane_run(&repo, &["pr", "ensure", "7"]).0, Some(0));
    assert!(
        issue_body(&recorded).is_empty(),
        "no second issue was opened"
    );
    assert!(patched_body(&recorded).contains("Closes CLOUD-700"));
}

#[test]
fn idempotence_a_second_call_on_the_same_pr_files_nothing() {
    // The mutation the dying suite declared: dropping the already-linked short
    // circuit files a second row on every tick, forever, against a pull request
    // that already has one.
    let forge = Forge {
        body: "This PR contains the following updates. Closes CLOUD-700".to_owned(),
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-idempotent", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "ensure", "7"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("already names CLOUD-700"), "{err}");
    assert!(issue_body(&recorded).is_empty(), "nothing filed");
    assert!(patched_body(&recorded).is_empty(), "nothing patched");
}

// -- derive's refusals -------------------------------------------------------

#[test]
fn a_non_bot_pr_is_untouched_and_the_refusal_says_whose_it_is() {
    let forge = Forge {
        login: "a-human".to_owned(),
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-human", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("a-human"), "names whose it is: {err}");
    assert!(issue_body(&recorded).is_empty());
}

#[test]
fn the_retired_bot_is_not_on_the_allowlist_either() {
    // A row filed for a bot that cannot open a pull request would be a claim
    // about a lane this repository does not have.
    let forge = Forge {
        login: "dependabot[bot]".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-dependabot", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("dependabot[bot]"), "{err}");
}

#[test]
fn a_pr_touching_no_owned_manifest_is_refused_never_given_an_invented_row() {
    let forge = Forge {
        files: "README.md\nsrc/main.rs".to_owned(),
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-unowned", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("README.md"), "names the paths: {err}");
    assert!(issue_body(&recorded).is_empty(), "no row was invented");
}

#[test]
fn a_workflow_bump_is_owned_too() {
    let forge = Forge {
        title: "ci: bump the action".to_owned(),
        files: ".github/workflows/ci.yml".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-workflow", &forge);
    let (code, report, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(report.contains(".github/workflows/ci.yml"), "{report}");
}

#[test]
fn a_subject_with_no_conventional_type_is_refused() {
    // That commit could never land: the commit gate would refuse it, so the lane
    // says so rather than filing a row for a commit that cannot merge.
    let forge = Forge {
        title: "update cargo deps".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-untyped", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("Conventional type"), "{err}");
}

#[test]
fn the_section_six_type_is_read_from_the_subject_not_chosen_here() {
    let forge = Forge {
        title: "ci: bump the action".to_owned(),
        files: ".github/workflows/ci.yml".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-type", &forge);
    let (_, report, _) = lane_run(&repo, &["pr", "derive", "7"]);
    assert!(report.contains("`ci` → no bump"), "{report}");
    assert!(!report.contains("`build` → no bump"), "{report}");
}

#[test]
fn derive_writes_nothing_it_is_the_half_a_gate_can_read() {
    let (repo, recorded) = lane("lane-derive-pure", &Forge::default());
    let (code, report, _) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(0));
    assert!(issue_body(&recorded).is_empty(), "opened no issue");
    assert!(patched_body(&recorded).is_empty(), "patched no body");
    // The payload's shape is the tracker's own, so the refinement gate reads it
    // unchanged — which is what keeps "derived" from meaning "exempt".
    let payload: serde_json::Value = serde_json::from_str(report.trim()).expect("a payload");
    assert_eq!(payload["status"], "Todo");
    assert!(payload["description"].as_str().unwrap().contains("Ready"));
}

#[test]
fn a_mirror_that_cannot_be_opened_is_not_a_key_invented() {
    let forge = Forge {
        create_ok: false,
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-create-fails", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "ensure", "7"]);
    // Could-not-look rather than a verdict: the forge refused, so nothing is
    // known about whether a row should exist.
    assert_eq!(code, Some(3), "{err}");
    assert!(patched_body(&recorded).is_empty(), "no key was invented");
}

// -- closes ------------------------------------------------------------------

#[test]
fn a_body_that_still_closes_its_row_is_landable_and_the_verdict_names_the_key() {
    let forge = Forge {
        body: "updates. Closes CLOUD-700".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-still-closes", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "closes", "7"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("CLOUD-700"), "{err}");
}

#[test]
fn a_key_named_but_not_closed_is_refused() {
    // THE WHOLE FAILURE BEING CAUGHT, and the mutation the dying suite declared:
    // a rebase regenerates the bot's body and the closing line goes with it,
    // leaving a body that still mentions the key and moves nothing.
    let forge = Forge {
        body: "updates. See CLOUD-700 for context".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-named-only", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "closes", "7"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("closes no tracker key"), "{err}");
}

#[test]
fn a_body_naming_no_key_at_all_is_refused() {
    let (repo, _) = lane("lane-no-key", &Forge::default());
    let (code, _, err) = lane_run(&repo, &["pr", "closes", "7"]);
    assert_eq!(code, Some(2), "{err}");
}

#[test]
fn fixes_and_resolves_close_it_too() {
    // The predicate is the board gate's, not `link`'s: a body a human edited to
    // say "Fixes CLOUD-767" closes the row just as well.
    for verb in ["Fixes", "Resolves", "fixed"] {
        let forge = Forge {
            body: format!("updates. {verb} CLOUD-701"),
            ..Forge::default()
        };
        let (repo, _) = lane(&format!("lane-verb-{verb}"), &forge);
        let (code, _, err) = lane_run(&repo, &["pr", "closes", "7"]);
        assert_eq!(code, Some(0), "{verb}: {err}");
    }
}

#[test]
fn do_not_close_does_not_read_as_a_close() {
    // The marker ends in a closing verb, which is exactly why it is the case
    // worth pinning.
    let forge = Forge {
        body: "updates. DO-NOT-CLOSE CLOUD-388".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-do-not-close", &forge);
    let (code, _, err) = lane_run(&repo, &["pr", "closes", "7"]);
    assert_eq!(code, Some(2), "{err}");
}

#[test]
fn pointer_never_payload_the_refusal_names_the_pr_and_no_part_of_the_body() {
    // A bot pull request carries a release-notes dump, and echoing it would put
    // that in the log of every landing (non-negotiable rule 4).
    let forge = Forge {
        body: "SECRETSAUCE release notes for every bumped package".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-pointer", &forge);
    let (_, report, err) = lane_run(&repo, &["pr", "closes", "7"]);
    assert!(err.contains("#7"), "names the pull request: {err}");
    assert!(!err.contains("SECRETSAUCE"), "no body on stderr: {err}");
    assert!(!report.contains("SECRETSAUCE"), "none on stdout: {report}");
}

#[test]
fn closes_writes_nothing() {
    // It is a read, and a refusal must not repair by editing.
    let forge = Forge {
        body: "updates. See CLOUD-700".to_owned(),
        ..Forge::default()
    };
    let (repo, recorded) = lane("lane-closes-pure", &forge);
    assert_eq!(lane_run(&repo, &["pr", "closes", "7"]).0, Some(2));
    assert!(patched_body(&recorded).is_empty());
    assert!(issue_body(&recorded).is_empty());
}

/// THE CLAIM THAT MAKES A MECHANICAL ROW HONEST, and the dying suite's own
/// load-bearing case: the derived block is checkable by the SAME gate a human's
/// row passes. The real `ready lint` runs over the real derived payload — a stub
/// here would assert the property rather than test it.
///
/// It runs over THIS REPOSITORY's committed template rather than the fixture's
/// short one, because that is the text a tracker row will actually carry, and it
/// is the one a formatter can silently reshape out from under the grammar.
#[test]
fn the_derived_block_passes_ready_lint() {
    let (repo, _) = lane("lane-ready-lint", &Forge::default());
    let template = std::fs::read_to_string(crate::common::at_root(".github/bot-lane-row.md"))
        .expect("the committed body template");
    write(&repo, "row.md", &template);
    let (code, payload, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(0), "{err}");
    let linted = run_with_stdin(&repo, &["ready", "lint"], &payload);
    assert_eq!(
        linted.status.code(),
        Some(0),
        "the derived block must pass the gate a human's row passes: {}{}",
        stdout(&linted),
        stderr(&linted)
    );
}

// -- the receipt -------------------------------------------------------------

#[test]
fn a_bot_branch_whose_facts_hold_earns_the_receipt() {
    // THE PREMISE. Every refusal below is a refusal against this one, which is
    // what keeps them from being satisfied by a verb that refuses everything.
    let forge = Forge {
        body: "updates. Closes CLOUD-700".to_owned(),
        ..Forge::default()
    };
    let (repo, _) = lane("lane-receipt", &forge);
    crate::common::git_in(&repo, &["checkout", "-q", "-b", "renovate/cargo"]);
    let (code, _, err) = lane_run(&repo, &["claim", "bot"]);
    assert_eq!(code, Some(0), "{err}");
    let recorded = std::fs::read_to_string(
        repo.join(".git")
            .join("batten-receipts")
            .join("bot.renovate-cargo"),
    )
    .expect("the receipt is written");
    assert!(recorded.contains("CLOUD-700"), "{recorded}");
    assert!(recorded.contains("bot renovate[bot]"), "{recorded}");
    // The base line is what gives this receipt CLOUD-516's staleness rule: a
    // branch restarted out from under it is void rather than silently trusted.
    assert!(recorded.contains("\nbase "), "{recorded}");
}

#[test]
fn a_branch_outside_the_lanes_prefix_is_sent_to_the_agent_claim() {
    // The two receipts attest different things, and widening the agent one to
    // cover bots would make it mean less everywhere (CLOUD-431).
    let (repo, _) = lane("lane-not-bot-branch", &Forge::default());
    crate::common::git_in(&repo, &["checkout", "-q", "-b", "claude/some-work"]);
    let (code, _, err) = lane_run(&repo, &["claim", "bot"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("claim check"), "names the other route: {err}");
    assert!(!receipt_dir(&repo).exists(), "and mints nothing");
}

#[test]
fn a_bot_branch_whose_pr_names_no_row_yet_earns_nothing() {
    let (repo, _) = lane("lane-unnamed", &Forge::default());
    crate::common::git_in(&repo, &["checkout", "-q", "-b", "renovate/cargo"]);
    let (code, _, err) = lane_run(&repo, &["claim", "bot"]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("pr ensure"), "names the remedy: {err}");
    assert!(!receipt_dir(&repo).exists());
}

/// Where a receipt would be, so a case can assert that none was minted.
fn receipt_dir(repo: &Path) -> PathBuf {
    repo.join(".git").join("batten-receipts")
}

// -- the lane's own absence --------------------------------------------------

#[test]
fn a_repository_declaring_no_lane_says_so_rather_than_filing_against_defaults() {
    // A lane assembled from engine defaults would file a row asserting a bump
    // nobody configured, which is the class this whole surface exists to refuse.
    let root = scratch("lane-absent");
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let output = batten()
        .args(["pr", "derive", "7"])
        .current_dir(&repo)
        .output()
        .expect("run batten");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a usage error, not a verdict"
    );
    assert!(
        stderr(&output).contains("[bot_lane]"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_template_naming_a_placeholder_nothing_fills_refuses_rather_than_rendering_it() {
    // A tracker row carrying a literal `{{...}}` reads as a lane that half-ran,
    // and nobody would notice until a human opened the row.
    let (repo, _) = lane("lane-bad-template", &Forge::default());
    write(&repo, "row.md", "* §1 the diff on #{{pr}} by {{whoever}}\n");
    let (code, _, err) = lane_run(&repo, &["pr", "derive", "7"]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("whoever"), "names the placeholder: {err}");
}
