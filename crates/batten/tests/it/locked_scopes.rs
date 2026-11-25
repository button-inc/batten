//! Locked mode reaches project tools only, inside this repository's tasks
//! (CLOUD-2881).
//!
//! `[settings] locked = true` is invocation-wide, and mise applies it to the
//! user-global scope too: a global config pinning a tool this lock does not hold
//! failed `mise run toolchain-check` with "not in the lockfile", installed or
//! not, measured on mise 2026.9.1. `locked_scopes` is global-only as config, so
//! a project cannot narrow it there; as `MISE_LOCKED_SCOPES` in a task's `env` it
//! reaches the nested `mise` the task runs. The top-level run only warns about
//! the global tool, so the task's verdict is the nested call's.
//!
//! The case drives the real `mise` over the COMMITTED `[settings]` and the
//! committed `toolchain-check` task, copied out of `mise.toml`, with a scratch
//! data dir and a scratch global config.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{scratch, write};

/// The `mise` the suite runs under.
fn host_mise() -> PathBuf {
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join("mise"))
        .find(|candidate| candidate.is_file())
        .expect("the suite runs under mise, so `mise` is on PATH")
}

/// Mark `path` executable where the platform has the bit.
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("make the tool executable");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// `mise run toolchain-check` in `project`, with `home`'s data dir and global
/// config, every ambient `MISE_*` dropped: whether it exited 0.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is how the real `mise` scopes locked mode, so nothing in process can stand in for it"
)]
fn toolchain_check(project: &Path, home: &Path) -> (bool, String) {
    use batten::capture::Streamed as _;
    let mut command = std::process::Command::new(host_mise());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("MISE_") {
            command.env_remove(name);
        }
    }
    let output = command
        .args(["run", "toolchain-check"])
        .current_dir(project)
        .env("MISE_DATA_DIR", home.join("data"))
        .env("MISE_CACHE_DIR", home.join("cache"))
        .env("MISE_STATE_DIR", home.join("state"))
        .env("MISE_CONFIG_DIR", home.join("config"))
        .env("MISE_GLOBAL_CONFIG_FILE", home.join("config/config.toml"))
        .env("MISE_CEILING_PATHS", home)
        .env("MISE_TRUSTED_CONFIG_PATHS", project)
        .streamed_output()
        .expect("run mise");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// One `github:` tool installed by hand under `home`'s data dir, registered.
fn install(home: &Path, repo: &str) {
    let dir = home.join(format!("data/installs/github-example-org-{repo}"));
    write(&dir, &format!("1.0.0/{repo}"), "#!/bin/sh\nexit 0\n");
    make_executable(&dir.join(format!("1.0.0/{repo}")));
    let tool = format!("github:example-org/{repo}");
    write(
        &dir,
        ".mise.backend.toml",
        &format!("short = \"{tool}\"\nfull = \"{tool}\"\nexplicit_backend = true\n"),
    );
}

/// The lock entry for one `github:` tool.
fn locked(repo: &str) -> String {
    let tool = format!("github:example-org/{repo}");
    let mut lock = format!("[[tools.\"{tool}\"]]\nversion = \"1.0.0\"\nbackend = \"{tool}\"\n\n");
    for platform in ["linux-x64", "linux-arm64", "macos-x64", "macos-arm64"] {
        let block = format!(
            "[tools.\"{tool}\".\"platforms.{platform}\"]\nchecksum = \"sha256:{}\"\nurl = \"https://example.invalid/{platform}.tar.gz\"\n\n",
            "0".repeat(64)
        );
        lock.push_str(&block);
    }
    lock
}

/// A project carrying the committed `[settings]` and `toolchain-check` task,
/// pinning `tools`, with `home` holding a global config that pins a tool the
/// project's lock does not hold.
fn project(home: &Path, tools: &[&str]) -> PathBuf {
    let committed: toml::Table = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("read mise.toml")
        .parse()
        .expect("mise.toml parses");
    let mut manifest = toml::Table::new();
    manifest.insert("settings".to_owned(), committed["settings"].clone());
    let mut task = committed["tasks"]["toolchain-check"]
        .as_table()
        .expect("the committed toolchain-check task")
        .clone();
    task.remove("description");
    let mut tasks = toml::Table::new();
    tasks.insert("toolchain-check".to_owned(), toml::Value::Table(task));
    manifest.insert("tasks".to_owned(), toml::Value::Table(tasks));
    let mut pinned = toml::Table::new();
    for repo in tools {
        pinned.insert(
            format!("github:example-org/{repo}"),
            toml::Value::String("1.0.0".to_owned()),
        );
        install(home, repo);
    }
    manifest.insert("tools".to_owned(), toml::Value::Table(pinned));
    let dir = home.join("project");
    write(&dir, "mise.toml", &toml::to_string(&manifest).expect("serialize"));
    write(&dir, "mise.lock", &locked("project-tool"));
    install(home, "global-tool");
    write(
        home,
        "config/config.toml",
        "[tools]\n\"github:example-org/global-tool\" = \"1.0.0\"\n",
    );
    dir
}

/// A GLOBAL TOOL ABSENT FROM THE LOCK DOES NOT FAIL THE TASK, AND AN UNLOCKED
/// PROJECT TOOL STILL DOES. Fails by: `MISE_LOCKED_SCOPES` dropped from the
/// committed `toolchain-check` env (`[tasks.lock-complete]`'s `scopes-dropped`
/// row), so the nested install refuses the global tool; or scoped wider than
/// the project, so the unlocked project tool passes.
#[test]
fn locked_mode_reaches_project_tools_only() {
    // THE FIXTURE TOOLS ARE `sh` SCRIPTS: off unix there is nothing to install,
    // and the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let home = scratch("locked-scopes-global");
    let dir = project(&home, &["project-tool"]);
    let (passed, said) = toolchain_check(&dir, &home);
    assert!(passed, "a global tool absent from the lock fails the task\n{said}");

    let home = scratch("locked-scopes-unlocked-project");
    let dir = project(&home, &["project-tool", "unlocked-tool"]);
    let (passed, said) = toolchain_check(&dir, &home);
    assert!(!passed, "an unlocked project tool passes the task\n{said}");
}
