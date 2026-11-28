//! Harness registration at the USER level, over the compiled binary
//! (CLOUD-2205, CLOUD-2676, CLOUD-2953).
//!
//! **THE HARNESS LOADS PROJECT SETTINGS FROM WHEREVER IT IS, AND IT MOVES.** A
//! session's primary working directory went checkout → `/home/user` → checkout in
//! one turn with no restart (CLOUD-2953, measured), and while it was elsewhere no
//! batten hook was loaded. Project files written above the clone (CLOUD-2205's
//! repair) and the harness process's own cwd (CLOUD-2676's reading) both named a
//! place the harness had already left. The one registration every directory loads
//! is the user-level surface, so `batten startup --repair` and `wiring register`
//! own it — exactly batten's own wiring, byte-identical to the committed copy, so
//! the harness runs the handler once — wherever the environment is disposable,
//! which a hosted container is without being told.
//!
//! Every case points the binary's home at a scratch home, and a case whose
//! directory must be in no repository builds it with `scratch_outside_tree`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{StateHome as _, scratch, stderr};

/// `<home>/sessions/clones/repo`: a clone two directories below the home.
fn layout(name: &str) -> (PathBuf, PathBuf) {
    let home = scratch(name);
    let repo = home.join("sessions").join("clones").join("repo");
    std::fs::create_dir_all(&repo).expect("the fixture clone");
    common::init_repo(&repo);
    common::write(&repo, "batten.toml", "version = 1\n");
    (home, repo)
}

/// A scratch home in no repository, so a run from it resolves no `batten.toml`.
fn bare_home(name: &str) -> PathBuf {
    common::scratch_outside_tree("wiring-register", name)
}

/// The binary at `cwd` with `home` as its home, every ambient signal removed and
/// then `env` set.
fn run(home: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    common::batten()
        .current_dir(cwd)
        .args(args)
        .at_home(home)
        .env_remove("BATTEN_ENVIRONMENT")
        .env_remove("CLAUDE_PID")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CLAUDE_CODE_REMOTE")
        .envs(env.iter().copied())
        .streamed_output()
        .expect("the binary runs")
}

/// The user-level Claude Code surface under `home`.
fn user_surface(home: &Path) -> PathBuf {
    home.join(".claude").join("settings.json")
}

fn registers_batten(file: &Path) -> bool {
    std::fs::read_to_string(file).is_ok_and(|text| text.contains("batten adjudicate"))
}

/// What `register_committed` writes for Claude Code, as `generate hooks` derives it.
fn derived_hooks(repo: &Path) -> serde_json::Value {
    let generated = common::batten()
        .current_dir(repo)
        .args(["generate", "hooks", "--harness", "claude-code"])
        .streamed_output()
        .expect("the binary runs");
    let generated: serde_json::Value =
        serde_json::from_slice(&generated.stdout).expect("generate hooks parses");
    serde_json::Value::Object(events_of(&generated))
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("the file")).expect("it parses")
}

/// A Claude Code hook block registering one foreign command on `PreToolUse`.
const FOREIGN: &str =
    r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/tool/hook.sh"}]}]}}"#;

// --- part 1: a hosted container is disposable without being told -------------

/// One container case: name, environment-manager directory, env, writes.
type ContainerCase<'a> = (&'a str, bool, &'a [(&'a str, &'a str)], bool);

#[test]
fn a_cloud_container_is_disposable_without_the_variable_and_the_variable_overrides() {
    let repair = ["startup", "--repair"];
    let cases: &[ContainerCase<'_>] = &[
        // (name, environment-manager directory, env, writes)
        ("remote", false, &[("CLAUDE_CODE_REMOTE", "true")], true),
        ("manager", true, &[], true),
        ("nothing", false, &[], false),
        (
            "remote-refused",
            false,
            &[
                ("CLAUDE_CODE_REMOTE", "true"),
                ("BATTEN_ENVIRONMENT", "machine"),
            ],
            false,
        ),
        (
            "manager-refused",
            true,
            &[("BATTEN_ENVIRONMENT", "machine")],
            false,
        ),
        (
            "declared",
            false,
            &[("BATTEN_ENVIRONMENT", "disposable")],
            true,
        ),
    ];
    for (name, manager, env, writes) in cases {
        let home = bare_home(&format!("detect-{name}"));
        if *manager {
            std::fs::create_dir_all(home.join(".claude").join("environment-manager"))
                .expect("the setup run's directory");
        }
        let done = run(&home, &home, &repair, env);
        assert_eq!(
            registers_batten(&user_surface(&home)),
            *writes,
            "{name}: {}",
            stderr(&done)
        );
    }

    // The user's config directory is resolved in one place: `CLAUDE_CONFIG_DIR`
    // wins over `.claude` under the home.
    let home = bare_home("detect-config-dir");
    let config = home.join("elsewhere");
    let done = run(
        &home,
        &home,
        &repair,
        &[
            ("CLAUDE_CODE_REMOTE", "true"),
            ("CLAUDE_CONFIG_DIR", config.to_str().expect("utf-8")),
        ],
    );
    assert!(
        registers_batten(&config.join("settings.json")),
        "{}",
        stderr(&done)
    );
    assert!(!user_surface(&home).exists(), "{}", stderr(&done));
}

// --- part 2: `startup --repair` with no `batten.toml` --------------------------

#[test]
fn startup_repair_with_no_batten_toml_registers_the_user_surface() {
    let (_, repo) = layout("startup-no-toml-derive");
    let derived = derived_hooks(&repo);
    let remote = [("CLAUDE_CODE_REMOTE", "true")];

    let home = bare_home("startup-no-toml");
    let done = run(&home, &home, &["startup", "--repair"], &remote);
    let stdout = String::from_utf8_lossy(&done.stdout).into_owned();
    assert!(!stdout.contains("0 row(s)"), "{stdout}");
    assert!(user_surface(&home).exists(), "{stdout}{}", stderr(&done));
    let written = read_json(&user_surface(&home));
    let events: Vec<&String> = written["hooks"]
        .as_object()
        .expect("hooks")
        .keys()
        .collect();
    let owed: Vec<&String> = derived.as_object().expect("derived").keys().collect();
    assert_eq!(events, owed, "every event register_committed writes");
    for (event, entries) in written["hooks"].as_object().expect("hooks") {
        assert!(
            entries.to_string().contains("batten adjudicate"),
            "{event}: {written}"
        );
    }

    // The check mode writes nothing and reports the step owed.
    let fresh = bare_home("startup-no-toml-check");
    let checked = run(&fresh, &fresh, &["startup"], &remote);
    assert!(!user_surface(&fresh).exists(), "the check mode wrote");
    let stdout = String::from_utf8_lossy(&checked.stdout).into_owned();
    assert!(
        stdout.contains("harness-registration failed"),
        "the step is reported owed: {stdout}"
    );
}

#[test]
fn a_disposable_repair_leaves_exactly_battens_identical_registration() {
    let (_, repo) = layout("disposable-exact-derive");
    let derived = derived_hooks(&repo);
    let mut seeded = derived.clone();
    // A batten entry with one byte changed, and a foreign hook beside it.
    let entries = seeded
        .as_object_mut()
        .expect("derived")
        .values_mut()
        .next()
        .expect("an event");
    let command = entries[0]["hooks"][0]["command"]
        .as_str()
        .expect("a command")
        .to_owned();
    entries[0]["hooks"][0]["command"] = serde_json::Value::from(format!("{command}x"));
    entries
        .as_array_mut()
        .expect("entries")
        .push(serde_json::json!({"hooks": [{"type": "command", "command": "/opt/tool/hook.sh"}]}));
    let home = bare_home("disposable-exact");
    std::fs::create_dir_all(home.join(".claude")).expect("config dir");
    std::fs::write(
        user_surface(&home),
        serde_json::json!({"model": "kept", "hooks": seeded}).to_string(),
    )
    .expect("seed");

    let remote = [("CLAUDE_CODE_REMOTE", "true")];
    let done = run(&home, &home, &["startup", "--repair"], &remote);
    let after = read_json(&user_surface(&home));
    assert_eq!(after["hooks"], derived, "{}", stderr(&done));
    assert!(!after.to_string().contains("/opt/tool/hook.sh"), "{after}");
    assert_eq!(after["model"], "kept", "{after}");

    let first = std::fs::read(user_surface(&home)).expect("the surface");
    let _ = run(&home, &home, &["startup", "--repair"], &remote);
    assert_eq!(
        std::fs::read(user_surface(&home)).expect("the surface"),
        first,
        "a second run changes nothing"
    );
}

#[test]
fn a_developer_machine_repair_writes_only_the_repository_and_warns_of_user_level_conflicts() {
    let warnings = |output: &Output| -> Vec<String> {
        stderr(output)
            .lines()
            .filter(|line| line.contains("not batten's"))
            .map(str::to_owned)
            .collect()
    };

    // The control: no foreign hook anywhere.
    let (home, repo) = layout("developer-machine-control");
    let control = run(&home, &repo, &["startup", "--repair"], &[]);
    assert!(warnings(&control).is_empty(), "{}", stderr(&control));

    let (home, repo) = layout("developer-machine");
    common::write(&home, ".claude/settings.json", FOREIGN);
    let before = std::fs::read(user_surface(&home)).expect("seeded");
    let one = run(&home, &repo, &["startup", "--repair"], &[]);
    assert_eq!(
        std::fs::read(user_surface(&home)).expect("the user surface"),
        before,
        "the user surface is left byte for byte"
    );
    assert!(
        registers_batten(&repo.join(".claude/settings.json")),
        "the repository's committed surface is written: {}",
        stderr(&one)
    );
    let lines = warnings(&one);
    assert_eq!(lines.len(), 1, "{}", stderr(&one));
    assert!(lines[0].contains("claude-code"), "{lines:?}");
    assert!(lines[0].contains(".claude/settings.json"), "{lines:?}");
    assert!(lines[0].contains(" 1 "), "a count: {lines:?}");
    assert!(
        !lines[0].contains("batten ") && !lines[0].contains('`'),
        "never a command line: {lines:?}"
    );
    assert_eq!(one.status.code(), control.status.code());

    common::write(&home, ".claude/settings.local.json", FOREIGN);
    let two = run(&home, &repo, &["startup", "--repair"], &[]);
    assert_eq!(warnings(&two).len(), 2, "{}", stderr(&two));
    assert_eq!(two.status.code(), control.status.code());
}

// --- part 3: `wiring register` writes nothing above the repository ------------

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: a live session is a PROCESS whose cwd `/proc/<pid>/cwd` reads, which has no in-process form"
)]
fn register_writes_no_project_file_above_the_repository() {
    let (home, repo) = layout("register-above");
    let parent = repo.parent().expect("the clone has a parent").to_path_buf();
    let mut session = std::process::Command::new("cat")
        .current_dir(&parent)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("cat runs");
    let pid = session.id().to_string();
    let rooted = run(
        &home,
        &repo,
        &["wiring", "register"],
        &[("BATTEN_ENVIRONMENT", "disposable"), ("CLAUDE_PID", &pid)],
    );
    let _ = session.kill();
    let _ = session.wait();
    let unrooted = run(
        &home,
        &repo,
        &["wiring", "register"],
        &[("BATTEN_ENVIRONMENT", "disposable")],
    );
    assert_eq!(rooted.status.code(), Some(0), "{}", stderr(&rooted));
    assert_eq!(unrooted.status.code(), Some(0), "{}", stderr(&unrooted));
    for above in [parent.clone(), home.join("sessions")] {
        assert!(
            !above.join(".claude/settings.json").exists(),
            "{} gained a project file",
            above.display()
        );
    }
    assert!(
        registers_batten(&user_surface(&home)),
        "the user level is what it registers: {}",
        stderr(&unrooted)
    );
}

#[test]
fn a_machine_not_declared_disposable_owes_nothing_outside_a_session() {
    // A developer's laptop or a CI runner: nothing may be written at the user
    // level there, so reporting it owed would turn every `startup` red over a
    // non-defect.
    let (home, repo) = layout("wiring-register-real");
    let check = run(
        &home,
        &repo,
        &["wiring", "register", "--check"],
        &[("BATTEN_ENVIRONMENT", "")],
    );
    assert_eq!(check.status.code(), Some(0), "{}", stderr(&check));
    assert!(!user_surface(&home).exists());
}

// --- part 5: doctor judges the user level, never the process's directory ------

fn claude_findings(output: &Output) -> Vec<serde_json::Value> {
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor hooks --json parses");
    let claude = report["harnesses"]
        .as_array()
        .expect("harnesses")
        .iter()
        .find(|harness| harness["harness"] == "claude-code")
        .cloned()
        .expect("claude-code is diagnosed");
    claude["findings"].as_array().cloned().unwrap_or_default()
}

fn merged_registration(findings: &[serde_json::Value]) -> bool {
    findings
        .iter()
        .any(|finding| finding["reason"] == "hook-wiring-merged-registration")
}

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: a live session is a PROCESS whose cwd `/proc/<pid>/cwd` reads, which has no in-process form"
)]
fn doctor_accepts_an_identical_user_registration_and_refuses_a_differing_one() {
    let (home, repo) = layout("doctor-user-registration");
    let all = run(&home, &repo, &["wiring", "register", "--all"], &[]);
    assert_eq!(all.status.code(), Some(0), "{}", stderr(&all));
    let derived = derived_hooks(&repo);
    let doctor = |env: &[(&str, &str)]| run(&home, &repo, &["doctor", "hooks", "--json"], env);
    let identical_block = serde_json::json!({"hooks": derived}).to_string();

    common::write(&home, ".claude/settings.json", &identical_block);
    let identical = claude_findings(&doctor(&[]));
    assert!(!merged_registration(&identical), "{identical:?}");

    let changed = identical_block.replacen("batten adjudicate", "batten  adjudicate", 1);
    common::write(&home, ".claude/settings.json", &changed);
    let differing = claude_findings(&doctor(&[]));
    assert!(merged_registration(&differing), "{differing:?}");

    common::write(&home, ".claude/settings.json", &identical_block);
    common::write(&home, ".claude/settings.local.json", &identical_block);
    let local = claude_findings(&doctor(&[]));
    assert!(merged_registration(&local), "{local:?}");

    let parent = repo.parent().expect("the clone has a parent").to_path_buf();
    let mut session = std::process::Command::new("cat")
        .current_dir(&parent)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("cat runs");
    let pid = session.id().to_string();
    let rooted = claude_findings(&doctor(&[("CLAUDE_PID", &pid)]));
    let _ = session.kill();
    let _ = session.wait();
    assert!(
        !rooted.iter().any(|finding| finding["file"]
            .as_str()
            .is_some_and(|file| file.starts_with("session-root:"))),
        "{rooted:?}"
    );
}

// --- `register --all`, the committed half (CLOUD-2676) ------------------------

/// Every harness's committed surface, and the token `generate hooks` takes.
const COMMITTED: &[(&str, &str)] = &[
    ("claude-code", ".claude/settings.json"),
    ("cursor", ".cursor/hooks.json"),
    ("gemini-cli", ".gemini/settings.json"),
    ("codex-cli", ".codex/hooks.json"),
    ("copilot-cli", ".github/hooks/batten.json"),
];

/// `wiring register --all` with no disposable home: only the committed half may
/// write.
fn register_all(home: &Path, repo: &Path, args: &[&str]) -> Output {
    run(
        home,
        repo,
        &[&["wiring", "register", "--all"], args].concat(),
        &[],
    )
}

/// The events map a wiring document carries, wherever its host keys it.
fn events_of(document: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    document
        .get("hooks")
        .unwrap_or(document)
        .as_object()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn register_all_writes_every_committed_surface() {
    let (home, repo) = layout("wiring-register-all");
    let owed = register_all(&home, &repo, &["--check"]);
    assert_eq!(owed.status.code(), Some(2), "{}", stderr(&owed));
    for (_, surface) in COMMITTED {
        assert!(!repo.join(surface).exists(), "--check wrote {surface}");
    }
    let written = register_all(&home, &repo, &[]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr(&written));
    let again = register_all(&home, &repo, &["--check"]);
    assert_eq!(again.status.code(), Some(0), "a second run owes nothing");

    let hooks = run(&home, &repo, &["doctor", "hooks", "--json"], &[]);
    let report: serde_json::Value =
        serde_json::from_slice(&hooks.stdout).expect("doctor hooks --json parses");
    assert_eq!(hooks.status.code(), Some(0), "{report}");
    for harness in report["harnesses"].as_array().expect("harnesses") {
        assert_eq!(harness["ok"], true, "{harness}");
    }

    for (token, surface) in COMMITTED {
        let generated = common::batten()
            .current_dir(&repo)
            .args(["generate", "hooks", "--harness", token])
            .streamed_output()
            .expect("the binary runs");
        let generated: serde_json::Value =
            serde_json::from_slice(&generated.stdout).expect("generate hooks parses");
        let file = std::fs::read_to_string(repo.join(surface)).expect("the surface was written");
        let file: serde_json::Value = serde_json::from_str(&file).expect("the surface parses");
        assert_eq!(
            events_of(&file),
            events_of(&generated),
            "{token}: register --all writes the entries generate derives"
        );
    }
}

#[test]
fn register_all_writes_flat_hosts_flat() {
    // CLOUD-2694: Copilot's file seeded with v0.0.220's nested batten entry is
    // migrated to the flat shape the host reads, and a second run is a no-op.
    let (home, repo) = layout("wiring-register-flat");
    common::write(
        &repo,
        ".github/hooks/batten.json",
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"batten adjudicate --harness copilot-cli"}]}]}}"#,
    );
    let written = register_all(&home, &repo, &[]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr(&written));
    let path = repo.join(".github/hooks/batten.json");
    let first = std::fs::read(&path).expect("the surface");
    let file: serde_json::Value = serde_json::from_slice(&first).expect("the surface parses");
    assert_eq!(file["version"], 1, "{file}");
    for (_, entries) in events_of(&file) {
        for entry in entries.as_array().expect("an event's entries") {
            assert!(entry.get("hooks").is_none(), "no nested entry: {file}");
            assert!(entry["bash"].is_string(), "every entry is flat: {file}");
        }
    }
    assert_eq!(register_all(&home, &repo, &[]).status.code(), Some(0));
    assert_eq!(
        std::fs::read(&path).expect("the surface"),
        first,
        "idempotent"
    );
}
