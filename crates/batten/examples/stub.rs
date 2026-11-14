//! A test-only stand-in for any program a test needs to run (CLOUD-2336).
//!
//! # Why it exists
//!
//! Tests used to author `#!/bin/sh` stubs, make them executable and run them:
//! shell, written by this repository, in 51 files. A test that needs a child
//! process that only exits gets a real one (`true`, `false`). Everything else
//! gets this program, driven by a PLAN rather than a script, so no test authors
//! shell.
//!
//! # NEVER SHIPPED
//!
//! An `[[example]]` target, never a `[[bin]]`: `batten dist` counts every bin
//! target and refuses unless there is exactly one, and cargo-dist would put a
//! second bin in the archive. An example is kind `example` in `cargo metadata`,
//! which neither reads. `dist.rs`'s `the_package_ships_exactly_one_binary` holds
//! that.
//!
//! # The plan
//!
//! A JSON list of rules, read from the file `BATTEN_STUB_PLAN` names, or else
//! from `<the invoked path>.plan.json` beside the program (for a fixture whose
//! environment does not reach the child). The FIRST rule whose every condition
//! holds runs its steps in order, then the program exits 0 unless a step said
//! otherwise. No rule matched: exit 127 with the argv on stderr.
//!
//! Conditions: `name` (the invoked file name, so a symlink named `cargo` is a
//! fake `cargo`), `argv` (exact, after the program), `argv_prefix`, `env` (set),
//! `env_eq` (`[name, value]`), `stdin_contains`, `file_exists`, `file_contains`
//! (`[path, text]`).
//!
//! Steps: `stdout`, `stderr`, `write` (`[path, text]`), `append`, `mkdir`,
//! `cat`, `sleep` (ms), `run` (an argv, waited for), `spawn` (`{argv, pid}`: not
//! waited for, its pid written), `probe-pid` (`{pid, to}`: writes `alive` or
//! `dead`), `exit`.
//!
//! Text and paths expand `{argv}`, `{argv:N}` (1-based), `{argv-after:FLAG}`,
//! `{argv-strip:PREFIX}`, `{pid}`, `{ppid}` and `{env:NAME}`.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// One rule: the conditions that select it and what it does.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Rule {
    name: Option<String>,
    argv: Option<Vec<String>>,
    argv_prefix: Option<Vec<String>>,
    env: Option<String>,
    env_eq: Option<(String, String)>,
    stdin_contains: Option<String>,
    file_exists: Option<String>,
    file_contains: Option<(String, String)>,
    steps: Vec<Step>,
}

/// One thing a matched rule does.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum Step {
    Stdout(String),
    Stderr(String),
    Write(String, String),
    Append(String, String),
    Mkdir(String),
    Cat(String),
    Sleep(u64),
    Run(Vec<String>),
    Spawn { argv: Vec<String>, pid: String },
    ProbePid { pid: String, to: String },
    Exit(i32),
}

/// What an invocation is: its argv and its stdin.
struct Call {
    name: String,
    args: Vec<String>,
    stdin: String,
}

//MUTANT-SUITE crates/batten/tests/it/acceptance_corpus.rs
//MUTANT stub-seed-ignored|s@^    Path::new(\&call.expand(path)).exists()$@    false@|enforce_is_clean_on_the_fixture_and_a_violation_when_seeded
//MUTANT stub-dispatch-collapsed|s@^    named(rule, call) \&\& argued(rule, call)$@    true@|the_warn_items_report_without_failing_until_promoted
impl Rule {
    /// Whether every condition this rule declares holds for `call`.
    fn matches(&self, call: &Call) -> bool {
        selects(self, call)
            && self
                .env
                .as_ref()
                .is_none_or(|name| std::env::var_os(name).is_some())
            && self
                .env_eq
                .as_ref()
                .is_none_or(|(name, value)| std::env::var(name).ok().as_deref() == Some(value))
            && self
                .stdin_contains
                .as_ref()
                .is_none_or(|text| call.stdin.contains(text.as_str()))
            && self
                .file_exists
                .as_ref()
                .is_none_or(|path| exists(call, path))
            && self.file_contains.as_ref().is_none_or(|(path, text)| {
                std::fs::read_to_string(call.expand(path))
                    .is_ok_and(|body| body.contains(&call.expand(text)))
            })
    }
}

/// The dispatch half of [`Rule::matches`]: which program was invoked, and with
/// what argv.
fn selects(rule: &Rule, call: &Call) -> bool {
    named(rule, call) && argued(rule, call)
}

/// Whether the rule names the invoked program, or names none.
fn named(rule: &Rule, call: &Call) -> bool {
    rule.name.as_ref().is_none_or(|name| *name == call.name)
}

/// Whether the call's argv is the rule's exactly, and starts with its prefix.
fn argued(rule: &Rule, call: &Call) -> bool {
    rule.argv.as_ref().is_none_or(|argv| *argv == call.args)
        && rule
            .argv_prefix
            .as_ref()
            .is_none_or(|prefix| call.args.starts_with(prefix))
}

/// Whether the file a `file_exists` condition names is there, read from the
/// working directory the program was run in.
fn exists(call: &Call, path: &str) -> bool {
    Path::new(&call.expand(path)).exists()
}

impl Call {
    /// `text` with every placeholder replaced.
    fn expand(&self, text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let Some(close) = rest[open..].find('}') else {
                out.push_str(&rest[open..]);
                return out;
            };
            let key = &rest[open + 1..open + close];
            match self.placeholder(key) {
                Some(value) => out.push_str(&value),
                None => out.push_str(&rest[open..=open + close]),
            }
            rest = &rest[open + close + 1..];
        }
        out.push_str(rest);
        out
    }

    /// One placeholder's value, or `None` when `key` names none.
    fn placeholder(&self, key: &str) -> Option<String> {
        if key == "argv" {
            return Some(self.args.join(" "));
        }
        if key == "pid" {
            return Some(std::process::id().to_string());
        }
        if key == "ppid" {
            return Some(parent_id());
        }
        if let Some(index) = key.strip_prefix("argv:") {
            let index: usize = index.parse().ok()?;
            return Some(
                index
                    .checked_sub(1)
                    .and_then(|at| self.args.get(at))
                    .cloned()
                    .unwrap_or_default(),
            );
        }
        if let Some(flag) = key.strip_prefix("argv-after:") {
            let at = self.args.iter().position(|arg| arg == flag)?;
            return Some(self.args.get(at + 1).cloned().unwrap_or_default());
        }
        if let Some(prefix) = key.strip_prefix("argv-strip:") {
            return Some(
                self.args
                    .iter()
                    .find_map(|arg| arg.strip_prefix(prefix))
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
        if let Some(name) = key.strip_prefix("env:") {
            return Some(std::env::var(name).unwrap_or_default());
        }
        None
    }
}

#[cfg(unix)]
fn parent_id() -> String {
    std::os::unix::process::parent_id().to_string()
}

#[cfg(not(unix))]
fn parent_id() -> String {
    String::new()
}

/// Where the plan is: the variable, else beside the invoked program.
///
/// A program run by bare NAME carries no directory in `argv[0]`, so the plan is
/// looked for beside the first `PATH` entry that holds both the name and its
/// plan — the entry the caller's lookup found.
fn plan_path(invoked: &str) -> PathBuf {
    if let Some(named) = std::env::var_os("BATTEN_STUB_PLAN") {
        return PathBuf::from(named);
    }
    let beside = PathBuf::from(format!("{invoked}.plan.json"));
    if invoked.contains(std::path::MAIN_SEPARATOR) || invoked.contains('/') {
        return beside;
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join(format!("{invoked}.plan.json")))
        .find(|plan| plan.is_file())
        .unwrap_or(beside)
}

/// Run one step, returning the exit code it sets, if it sets one.
fn step(call: &Call, step: &Step) -> anyhow::Result<Option<i32>> {
    match step {
        Step::Stdout(text) => print!("{}", call.expand(text)),
        Step::Stderr(text) => eprint!("{}", call.expand(text)),
        Step::Write(path, text) => std::fs::write(call.expand(path), call.expand(text))?,
        Step::Append(path, text) => {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(call.expand(path))?;
            file.write_all(call.expand(text).as_bytes())?;
        }
        Step::Mkdir(path) => std::fs::create_dir_all(call.expand(path))?,
        Step::Cat(path) => print!("{}", std::fs::read_to_string(call.expand(path))?),
        Step::Sleep(ms) => {
            #[expect(
                clippy::disallowed_methods,
                reason = "a test stand-in's delay is its declared `sleep` step, bounded by the plan's own `ms`"
            )]
            std::thread::sleep(std::time::Duration::from_millis(*ms));
        }
        Step::Run(argv) => {
            let _ = command(call, argv)?.status()?;
        }
        Step::Spawn { argv, pid } => {
            let child = command(call, argv)?.spawn()?;
            std::fs::write(call.expand(pid), child.id().to_string())?;
        }
        Step::ProbePid { pid, to } => {
            let pid = std::fs::read_to_string(call.expand(pid))?;
            let alive = command(
                call,
                &["kill".to_owned(), "-0".to_owned(), pid.trim().to_owned()],
            )?
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
            std::fs::write(call.expand(to), if alive { "alive" } else { "dead" })?;
        }
        Step::Exit(code) => return Ok(Some(*code)),
    }
    Ok(None)
}

/// The child a `run`, `spawn` or `probe-pid` step starts, its argv expanded.
#[expect(
    clippy::disallowed_types,
    reason = "a test stand-in's `run` and `spawn` steps start the program its plan names; it is never shipped (CLOUD-2336)"
)]
fn command(call: &Call, argv: &[String]) -> anyhow::Result<std::process::Command> {
    let mut words = argv.iter().map(|word| call.expand(word));
    let program = words
        .next()
        .ok_or_else(|| anyhow::anyhow!("stub: a step names an empty argv"))?;
    let mut command = std::process::Command::new(program);
    command.args(words);
    Ok(command)
}

fn main() -> anyhow::Result<std::process::ExitCode> {
    let mut argv = std::env::args();
    let invoked = argv.next().unwrap_or_default();
    let name = Path::new(&invoked)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut stdin = String::new();
    // stdin is read whole: a hook stub swallows the payload it is handed, and a
    // rule may match on it. A test that leaves stdin open must close it.
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let call = Call {
        name,
        args: argv.collect(),
        stdin,
    };
    let plan = std::fs::read_to_string(plan_path(&invoked))
        .map_err(|error| anyhow::anyhow!("stub: no plan for `{invoked}`: {error}"))?;
    let rules: Vec<Rule> = serde_json::from_str(&plan)?;
    let Some(rule) = rules.iter().find(|rule| rule.matches(&call)) else {
        eprintln!(
            "stub: no rule matched `{} {}`",
            call.name,
            call.args.join(" ")
        );
        return Ok(std::process::ExitCode::from(127));
    };
    for each in &rule.steps {
        if let Some(code) = step(&call, each)? {
            std::io::stdout().flush()?;
            return Ok(std::process::ExitCode::from(
                u8::try_from(code).unwrap_or(u8::MAX),
            ));
        }
    }
    std::io::stdout().flush()?;
    Ok(std::process::ExitCode::SUCCESS)
}
