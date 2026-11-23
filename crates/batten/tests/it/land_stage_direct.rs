//! `gate run twice`, over the compiled binary and the committed table: every
//! spelling of rerunning a land or verify stage out of band is refused, and the
//! development forms beside it are not.
//!
//! # Why every spelling, and why through `adjudicate`
//!
//! The module reads `input.call.programs` and `input.call["task-programs"]` and
//! parses nothing, so whether a spelling is refused is a property of the
//! ENGINE's reading, which only the compiled binary exercises. The plan's step 14
//! lists the spellings; each is a row here, and a row that the engine stops
//! seeing through turns this suite red on the row that names it.
//!
//! Judged against the committed `batten.toml` for `forced_push.rs`'s reason: the
//! question is whether the table this repository ships refuses the command, not
//! whether the engine could be configured to.
//!
//! # The task receipt
//!
//! A `mise run` is classified by what its task reaches, followed through the
//! task receipt a session mints at start. Each case mints it first through the
//! library's own writer, so the suite asserts the reading a real session gets
//! rather than the fail-closed path a missing receipt takes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The verdict this row raises.
const VERDICT: &str = "gate run twice";

/// A Claude Code `PreToolUse` envelope carrying a shell command, backgrounded or
/// not.
fn bash_payload(command: &str, background: bool) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped},\"run_in_background\":{background}}}}}"
    )
}

/// The repository root, with its task receipt minted as a session start mints it.
fn root() -> std::path::PathBuf {
    let root = common::at_root(".");
    let minted = batten::taskset::refresh(
        &root,
        &[batten::facts::TaskQuery {
            manifest: String::from("mise.toml"),
            node: String::from("tasks"),
        }],
    );
    assert!(
        matches!(minted, batten::facts::Look::Is(_)),
        "the task receipt must mint over the committed manifest"
    );
    root
}

fn decision(root: &std::path::Path, command: &str, background: bool) -> String {
    common::stdout(&common::run_with_stdin(
        root,
        &["adjudicate", "--harness", "claude-code"],
        &bash_payload(command, background),
    ))
}

/// Every command in `table` is refused by THIS row.
///
/// THE ROOT IS THE REAL CLONE, so its singleton locks are real too: run under
/// `mise run land`, a `mise run land` row meets the live lap's lock first and
/// is refused as `task run twice`, the gate before this one (#1276). That is
/// the same command refused harder, and is accepted only while a live process
/// holds `land`'s lock.
fn all_refused(table: &[(&str, bool)]) {
    let root = root();
    let land_held = batten::git::git_dir(&root)
        .ok()
        .and_then(|git_dir| batten::task::singleton_holder(&git_dir, "land"))
        .is_some();
    let escaped: Vec<String> = table
        .iter()
        .filter_map(|(command, background)| {
            let out = decision(&root, command, *background);
            let held_first = land_held && out.contains("task run twice");
            (!(out.contains("\"deny\"") && (out.contains(VERDICT) || held_first)))
                .then(|| format!("{command} (background: {background})\n{out}"))
        })
        .collect();
    assert!(
        escaped.is_empty(),
        "each spelling must be refused as `{VERDICT}`:\n{}",
        escaped.join("\n")
    );
}

/// No command in `table` is refused by this row. Another row may refuse one;
/// that is that row's business, and asserting a bare allow would couple this
/// suite to every other gate on the table.
fn none_refused(table: &[(&str, bool)]) {
    let root = root();
    let refused: Vec<String> = table
        .iter()
        .filter_map(|(command, background)| {
            let out = decision(&root, command, *background);
            out.contains(VERDICT)
                .then(|| format!("{command} (background: {background})\n{out}"))
        })
        .collect();
    assert!(
        refused.is_empty(),
        "these are not a stage rerun and must not raise `{VERDICT}`:\n{}",
        refused.join("\n")
    );
}

/// `batten enforce`, through every program spelling and every shell construct
/// the plan lists. The first rows are the incident itself.
#[test]
fn every_spelling_of_enforce_is_refused() {
    all_refused(&[
        (
            "mise exec -- cargo run -p batten -- enforce --half live",
            false,
        ),
        (
            "mise exec -- cargo run -p batten -- enforce --half live",
            true,
        ),
        ("batten enforce", false),
        ("batten enforce --half tree", true),
        ("./target/debug/batten enforce --half live", false),
        ("./target/release/batten enforce", false),
        ("mise x -- cargo run -p batten -- enforce", false),
        (
            "mise exec -- cargo run -q -p batten -- enforce --half live",
            false,
        ),
        (
            "mise exec -- cargo run --quiet --package batten -- enforce",
            false,
        ),
        ("mise exec -- cargo run --bin batten -- enforce", false),
        ("env X=1 batten enforce", false),
        ("X=1 batten enforce", false),
        ("time batten enforce", false),
        ("(batten enforce)", false),
        ("{ batten enforce; }", false),
        ("! batten enforce", false),
        ("command batten enforce", false),
        ("exec batten enforce", false),
        ("timeout 600 batten enforce", false),
        ("if true; then batten enforce; fi", false),
        ("bash -c 'batten enforce'", false),
        ("sh -c \"batten enforce --half live\"", false),
        ("bash -lc 'cargo run -p batten -- enforce'", false),
        ("bash -c 'sh -c \"batten enforce\"'", false),
        ("bash -c 'batten enforce \"unterminated'", false),
        ("eval 'batten enforce'", false),
        ("eval batten enforce", false),
        ("echo live | xargs batten enforce --half", false),
        ("xargs batten enforce", false),
        ("echo $(batten enforce)", false),
        ("out=$(mise exec -- cargo run -p batten -- enforce)", false),
        ("echo `batten enforce`", false),
        ("true && batten enforce", false),
        ("true; batten enforce", false),
        ("false || batten enforce", false),
        ("batten enforce | tail -5", false),
        ("cd /tmp\nbatten enforce", false),
        (
            "batten step run enforce-tree -- cargo run --quiet -p batten -- enforce --half tree",
            false,
        ),
        ("batten enforce \"unterminated", false),
        ("env -S 'batten enforce'", false),
        ("env -S \"batten enforce --half live\"", false),
        ("env --split-string='batten enforce'", false),
        ("watch -n 5 batten enforce", false),
        ("find . -maxdepth 0 -exec batten enforce \\;", false),
        ("find . -maxdepth 0 -execdir batten enforce {} +", false),
        ("find . -maxdepth 0 -ok batten enforce \\;", false),
        // No `-p`/`--bin`: the workspace's one binary, resolved from the
        // manifest as cargo resolves it.
        ("mise exec -- cargo run -- enforce", false),
        ("mise exec -- cargo run -q -- enforce --half live", false),
    ]);
}

/// The lap's own verbs, outside `mise run land` backgrounded.
#[test]
fn every_spelling_of_a_lap_verb_is_refused() {
    all_refused(&[
        ("batten land verify", true),
        ("batten land lap", false),
        ("bash -c 'batten land lap'", false),
        ("mise exec -- cargo run -q -p batten -- land lap", false),
    ]);
}

/// A task is refused for what it REACHES: `verify` reaches `batten-check`'s
/// `enforce` and `test:cargo`'s unfiltered suite, `land` reaches the lap.
#[test]
fn every_spelling_of_a_stage_task_is_refused() {
    all_refused(&[
        ("mise run verify", true),
        ("mise run verify", false),
        ("mise r verify", true),
        ("mise run -- verify", true),
        ("mise run verify:gated", true),
        ("mise run batten-check", true),
        ("mise run test:cargo", true),
        ("mise tasks run verify", true),
        ("mise run lint:clippy ::: batten-check", true),
        ("mise -C . run verify", true),
        ("mise verify", true),
        ("mise run land", false),
        ("bash -c 'mise run verify'", true),
        ("cd /tmp && mise run verify", true),
        ("mise run verify && git push", true),
        ("eval mise run batten-check", true),
        ("mise watch verify", true),
        ("mise watch -t verify", true),
        ("mise watch --task=batten-check", true),
    ]);
}

/// The workspace suite, run around the receipted `test:cargo` step.
#[test]
fn an_unfiltered_suite_is_refused() {
    all_refused(&[
        (
            "mise exec -- cargo nextest run --workspace --no-fail-fast",
            true,
        ),
        ("mise exec -- cargo nextest run", true),
        ("mise exec -- cargo test", true),
        ("mise exec -- cargo test --workspace", true),
        ("mise exec -- cargo +stable test", true),
        ("mise exec -- cargo nextest run -p batten", true),
        // The exact spelling a coordinator ran and killed: `-p` scopes the
        // package, which here is the workspace, and filters no test.
        (
            "mise exec -- cargo nextest run -p batten --no-fail-fast --color never",
            true,
        ),
        ("mise exec -- cargo test -p batten --no-fail-fast", true),
        ("bash -c 'cargo nextest run --workspace'", true),
        (
            "mise exec -- cargo nextest run --test it --test other",
            true,
        ),
        ("mise exec -- cargo nextest run --tests", true),
    ]);
}

/// Spellings another row ANSWERS FIRST. A mediated call gets one decision, and
/// the typed shape rows are judged before modules: a bare `cargo` is
/// `cargo run loose`'s, a trailing `&` is `detached-call`'s. Each is still a
/// refusal, which is what the plan asks of every spelling; the same stage under
/// a spelling those rows do not own is asserted as THIS row's above
/// (`mise exec -- cargo …`, a `-c` script).
#[test]
fn a_spelling_another_row_owns_is_still_refused() {
    let root = root();
    let open: Vec<String> = [
        ("cargo run -p batten -- enforce", false),
        ("cargo run -q -p batten -- enforce --half live", false),
        ("cargo run --quiet --package batten -- enforce", false),
        ("cargo run --bin batten -- enforce", false),
        ("cargo run -q -p batten -- land lap", false),
        ("nohup batten enforce &", false),
        ("cargo nextest run", true),
        ("cargo nextest run --workspace", true),
        ("cargo test", true),
        ("cargo test --workspace", true),
        ("cargo +stable test", true),
        ("cargo nextest run -p batten", true),
        ("cargo clippy", false),
        (
            "env CARGO_TARGET_DIR=target/clippy cargo clippy --all-targets",
            true,
        ),
    ]
    .iter()
    .filter_map(|(command, background)| {
        let out = decision(&root, command, *background);
        (!out.contains("\"deny\"")).then(|| format!("{command}\n{out}"))
    })
    .collect();
    assert!(
        open.is_empty(),
        "each must be refused:\n{}",
        open.join("\n")
    );
}

/// The sanctioned lap: `mise run land`, backgrounded.
/// What a `[[step]]` receipts, run outside that step: re-execution the lap pays
/// again, with nothing kept (step 21). The set is derived from the committed
/// manifest's `step run` lines, so each row names a program a step runs today.
#[test]
fn a_receipted_steps_program_run_outside_it_is_refused() {
    all_refused(&[
        (
            "mise exec -- cargo clippy -q --all-targets -- -D warnings",
            true,
        ),
        ("mise exec -- cargo clippy --workspace", true),
        (
            "mise exec -- env CARGO_TARGET_DIR=target/clippy cargo clippy --all-targets",
            true,
        ),
        ("bash -c 'cargo clippy --all-targets'", true),
        ("mise exec -- cargo deny check", true),
        (
            "mise exec -- cargo check --workspace --target x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl",
            true,
        ),
        (
            "mise exec -- cargo run --quiet -p batten -- policy test",
            true,
        ),
        ("batten semver check", true),
        ("batten hk drift", false),
        ("mise exec -- cargo run -q -p batten -- perf gate", true),
    ]);
}

/// Fails by: a one-package clippy read as the workspace `lint:clippy` stage,
/// which left an 881 s lap as the only route to a lint verdict (CLOUD-2806).
/// The package is part of what cargo builds, so a different selection is
/// development and keeps nothing the lap would reuse.
#[test]
fn a_single_package_clippy_is_not_a_stage() {
    none_refused(&[
        (
            "mise exec -- cargo clippy -q -p batten --all-targets -- -D warnings",
            true,
        ),
        (
            "mise exec -- cargo clippy -p batten-codemods --all-targets",
            true,
        ),
        ("cargo clippy --package=batten-base", true),
    ]);
}

/// A stage run from a script file, a shebang file or a sourced file is the
/// stage (#1276, step 23): the reach reads the file the shell runs.
#[test]
fn a_stage_inside_a_script_file_is_refused() {
    let dir = std::env::temp_dir().join(format!("batten-stage-script-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let plain = dir.join("ship.sh");
    std::fs::write(&plain, "set -e\nbatten enforce --half live\n").unwrap();
    let banged = dir.join("ship-banged");
    std::fs::write(&banged, "#!/usr/bin/env bash\nbatten enforce\n").unwrap();
    let sourced = dir.join("lib.sh");
    std::fs::write(&sourced, "batten enforce\n").unwrap();
    let harmless = dir.join("echo.sh");
    std::fs::write(&harmless, "echo 'batten enforce'\n").unwrap();
    let (plain, banged, sourced, harmless) = (
        plain.to_str().unwrap().to_owned(),
        banged.to_str().unwrap().to_owned(),
        sourced.to_str().unwrap().to_owned(),
        harmless.to_str().unwrap().to_owned(),
    );
    // The incident: every landing of one session ran as `sh ship<N>.sh`.
    all_refused(&[
        (&format!("sh {plain}"), false),
        (&format!("bash -e {plain}"), false),
        (&format!("mise exec -- bash {plain}"), false),
        (&banged, false),
        (&format!("source {sourced}"), false),
        (&format!(". {sourced}"), false),
    ]);
    // The mutation's target: a file that only names the stage runs nothing.
    none_refused(&[(&format!("sh {harmless}"), false)]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stage a Python program spawns with literal arguments is the stage
/// (#1276, CLOUD-2775): the reach reads the interpreter's spawn calls.
#[test]
fn a_stage_a_python_script_spawns_is_refused() {
    // Under the checkout's own scratch, so the script is in the repository
    // and `script run loose` (an interpreter running a file from outside it)
    // is not the refusal that answers.
    let dir = common::scratch("stage-python-spawn");
    let script = dir.join("ship.py");
    std::fs::write(
        &script,
        "import subprocess\nsubprocess.run(['batten', 'enforce', '--half', 'live'])\n",
    )
    .unwrap();
    let inline =
        String::from("python3 -c \"import subprocess; subprocess.run(['batten', 'enforce'])\"");
    all_refused(&[
        (&format!("python3 {}", script.display()), false),
        (&inline, false),
    ]);
    let harmless = dir.join("echo.py");
    std::fs::write(&harmless, "print('batten enforce')\n").unwrap();
    none_refused(&[(&format!("python3 {}", harmless.display()), false)]);
}

/// A TASK'S FORWARDED WORDS ARE PART OF WHAT IT RUNS (CLOUD-2837). mise appends
/// the words after a task's name to its run line, so `mise run test:filter --
/// -E '<filter>'` runs a filtered `cargo nextest run` — selection, which the
/// rule admits — while the bare task still runs the whole workspace suite and
/// is still refused. Fails by: the task followed into its body with the
/// forwarded words dropped, so every filtered run of the task read as the
/// suite.
#[test]
fn a_task_handed_a_filter_is_selection_not_the_stage() {
    none_refused(&[
        (
            "mise run test:filter -- -p batten --test it -E 'test(/forced_push|land_stage/)'",
            true,
        ),
        ("mise run test:filter -- -E 'test(/forced_push/)'", true),
        ("mise run test:filter -p batten forced_push", true),
    ]);
    all_refused(&[
        ("mise run test:filter", true),
        ("mise run test:filter -- -p batten", true),
    ]);
}

/// A landing is the one way a stage is meant to run.
#[test]
fn a_backgrounded_land_is_allowed() {
    none_refused(&[("mise run land", true)]);
}

/// Development forms: a filtered run, another verb, and a file that happens to
/// be named after a stage.
#[test]
fn the_development_forms_stay_allowed() {
    none_refused(&[
        (
            "mise exec -- cargo nextest run -p batten --no-fail-fast -E 'test(/forced_push/)'",
            true,
        ),
        ("cargo nextest run -E 'test(/land_stage/)'", true),
        ("cargo nextest run -p batten forced_push", true),
        ("cargo nextest run -p batten -- forced_push", true),
        ("cargo test -p batten forced_push", true),
        // A help request runs no case.
        ("mise exec -- cargo nextest run --help", true),
        ("cargo test --help", true),
        // One `--test <target>` selects that target.
        ("mise exec -- cargo nextest run -p batten --test it", true),
        ("mise exec -- cargo test --test=it", true),
        ("batten check --rule x", false),
        ("cat enforce", false),
        ("grep -n enforce batten.toml", false),
        ("echo 'batten enforce'", false),
        ("bash -c 'echo batten enforce'", false),
        // Another target or profile than any step's is development.
        ("mise exec -- cargo check -p batten", true),
        ("mise exec -- cargo build --release -p batten", true),
        ("mise exec -- cargo fmt --all", true),
        // The program through its own step writes the receipt the lap hits.
        (
            "mise exec -- cargo run -q -p batten -- step run lint:clippy -- cargo clippy --all-targets",
            true,
        ),
        // Tasks that reach no stage program are not refused for sitting in
        // `verify`'s graph: the classification is by what a task runs.
        ("mise run lint:clippy", true),
        ("mise run policy-test", true),
        ("mise run test:config-schema", true),
    ]);
}
