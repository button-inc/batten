//! Setup never compiles batten (CLOUD-2840).
//!
//! The engine a session runs is the pinned release, downloaded and installed by
//! `batten engine install`, and that is all setup does with it. A compile on the
//! setup path cost 224.87 s on every cold container, and 714 s of a `verify`
//! when a compaction's `SessionStart` fired it mid-lap. Two rows naming the
//! release (`install_local.rs`) did not stop a THIRD route back: any setup
//! command reaching a build through the task graph — a `depends`, a nested
//! `mise run`, or a body spelling `{{vars.batten}}`, whose default is
//! `cargo run`.
//!
//! THE WALK IS THE TASK GRAPH, NOT THE ROW TEXT. Every `on = "session-start"`
//! handler's `run` and every `[[startup]]` `check` and `repair` is a seed. From a
//! seed, a `mise run <task>` reaches that task; a task reaches each entry of its
//! `depends` and `depends_post` and every `mise run` in its `run` steps. A seed
//! is red when anything it reaches is a build task, spells a cargo build or run,
//! or spells `{{vars.batten}}` in a task whose own `env` does not set
//! `BATTEN_BIN` (which is what turns that expression into a named binary).

use std::collections::BTreeSet;

use crate::common;

/// Assembled rather than spelled, `install_local.rs`'s reason: a literal here
/// would be a second site claiming to be the call (`rules/scanning.md`).
fn build_tasks() -> [String; 3] {
    [
        ["build", ":release"].concat(),
        ["build", ":debug"].concat(),
        ["install", ":local"].concat(),
    ]
}

/// The compile spellings a step may not carry, assembled for the same reason.
fn cargo_compiles() -> [String; 2] {
    [["cargo", " build"].concat(), ["cargo", " run"].concat()]
}

/// The `vars.batten` expression, assembled for the same reason.
fn batten_var() -> String {
    ["{{vars", ".batten}}"].concat()
}

fn parse(path: &str) -> toml::Table {
    std::fs::read_to_string(common::at_root(path))
        .unwrap_or_else(|why| panic!("{path}: {why}"))
        .parse()
        .unwrap_or_else(|why| panic!("{path} parses: {why}"))
}

/// A value that is one string or an array of strings, as a list.
fn strings(value: Option<&toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::String(one)) => vec![one.clone()],
        Some(toml::Value::Array(many)) => many
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Every setup command the authority declares, as `(label, command line)`.
fn seeds(authority: &toml::Table) -> Vec<(String, String)> {
    let mut seeds = Vec::new();
    let handlers = authority
        .get("hook")
        .and_then(|hook| hook.get("handler"))
        .and_then(toml::Value::as_array);
    for handler in handlers.into_iter().flatten() {
        if handler.get("on").and_then(toml::Value::as_str) != Some("session-start") {
            continue;
        }
        let id = handler
            .get("id")
            .and_then(toml::Value::as_str)
            .unwrap_or("?");
        seeds.push((
            format!("hook.handler {id}"),
            strings(handler.get("run")).join(" "),
        ));
    }
    let startup = authority.get("startup").and_then(toml::Value::as_array);
    for row in startup.into_iter().flatten() {
        let id = row.get("id").and_then(toml::Value::as_str).unwrap_or("?");
        for key in ["check", "repair"] {
            let argv = strings(row.get(key));
            if !argv.is_empty() {
                seeds.push((format!("startup {id} {key}"), argv.join(" ")));
            }
        }
    }
    seeds
}

/// The task each `mise run` in `line` names, flags skipped.
fn mise_runs(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut tasks = Vec::new();
    for (at, pair) in words.windows(2).enumerate() {
        if pair != ["mise", "run"] {
            continue;
        }
        if let Some(task) = words[at + 2..].iter().find(|word| !word.starts_with('-')) {
            tasks.push((*task).trim_matches(['"', '\'', ';']).to_owned());
        }
    }
    tasks
}

/// What `line` spells that compiles, or `None`.
fn compiles_in(line: &str, task_sets_bin: bool) -> Option<String> {
    if let Some(spelling) = cargo_compiles().into_iter().find(|c| line.contains(c)) {
        return Some(spelling);
    }
    (!task_sets_bin && line.contains(&batten_var()))
        .then(|| format!("{} unset BATTEN_BIN", batten_var()))
}

/// Every reason `seed` reaches a compile through `manifest`'s task graph.
fn reaches_a_build(manifest: &toml::Table, seed: &str) -> Vec<String> {
    let tasks = manifest.get("tasks").and_then(toml::Value::as_table);
    let mut found = Vec::new();
    if let Some(spelling) = compiles_in(seed, false) {
        found.push(format!("the command spells {spelling}"));
    }
    let mut pending = mise_runs(seed);
    let mut visited = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        if build_tasks().contains(&name) {
            found.push(format!("reaches task {name}"));
        }
        let Some(task) = tasks.and_then(|tasks| tasks.get(&name)) else {
            continue;
        };
        for key in ["depends", "depends_post"] {
            for entry in strings(task.get(key)) {
                if let Some(dependency) = entry.split_whitespace().next() {
                    pending.push(dependency.to_owned());
                }
            }
        }
        let sets_bin = task
            .get("env")
            .and_then(toml::Value::as_table)
            .is_some_and(|env| env.contains_key("BATTEN_BIN"));
        for step in strings(task.get("run")) {
            if let Some(spelling) = compiles_in(&step, sets_bin) {
                found.push(format!("task {name} spells {spelling}"));
            }
            pending.extend(mise_runs(&step));
        }
    }
    found
}

/// Fails by: any setup command — a session-start handler, a startup check or a
/// startup repair — reaching a build of batten through the task graph.
#[test]
fn no_setup_command_reaches_a_build() {
    let manifest = parse("mise.toml");
    let seeds = seeds(&parse("batten.toml"));
    assert!(
        seeds.len() > 10,
        "the walk found the setup commands at all: {}",
        seeds.len()
    );
    let red: Vec<String> = seeds
        .iter()
        .filter_map(|(label, line)| {
            let reasons = reaches_a_build(&manifest, line);
            (!reasons.is_empty()).then(|| format!("{label}: {}", reasons.join(", ")))
        })
        .collect();
    assert!(red.is_empty(), "setup reaches a build:\n{}", red.join("\n"));
}

/// ANTI-VACUITY: a fixture handler reaching a build through two hops of the
/// graph — a nested `mise run`, then a `depends` — is red, as is each other
/// spelling the walk refuses.
#[test]
fn a_handler_reaching_a_build_is_red() {
    let [release, _, local] = build_tasks();
    let manifest: toml::Table = format!(
        "[tasks.\"session:x\"]\nrun = \"mise run -q outer\"\n\
         [tasks.outer]\ndepends = [\"{local}\"]\nrun = \"true\"\n\
         [tasks.\"{local}\"]\ndepends = [\"{release}\"]\n\
         [tasks.spelled]\nrun = [\"{} --version\"]\n\
         [tasks.named]\nenv = {{ BATTEN_BIN = \"batten\" }}\nrun = [\"{} --version\"]\n\
         [tasks.direct]\nrun = \"{} -p batten\"\n",
        batten_var(),
        batten_var(),
        cargo_compiles()[0],
    )
    .parse()
    .expect("the fixture manifest parses");
    let authority: toml::Table = "[[hook.handler]]\nid = \"x\"\non = \"session-start\"\n\
         run = [\"mise\", \"run\", \"session:x\"]\n\
         [[hook.handler]]\nid = \"later\"\non = \"pre-tool-use\"\n\
         run = [\"mise\", \"run\", \"direct\"]\n"
        .parse()
        .expect("the fixture authority parses");
    let seeds = seeds(&authority);
    assert_eq!(seeds.len(), 1, "only session-start handlers seed the walk");
    let reasons = reaches_a_build(&manifest, &seeds[0].1);
    assert!(
        reasons.iter().any(|reason| reason.contains(&local)),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().any(|reason| reason.contains(&release)),
        "{reasons:?}"
    );
    assert!(!reaches_a_build(&manifest, "mise run spelled").is_empty());
    assert!(reaches_a_build(&manifest, "mise run named").is_empty());
    assert!(!reaches_a_build(&manifest, "mise run direct").is_empty());
    assert!(reaches_a_build(&manifest, "batten engine install").is_empty());
}
