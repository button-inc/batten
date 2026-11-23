//! The adopted runner's surface contract, over the compiled binary (CLOUD-947).
//!
//! # Why this tier
//!
//! `hk.rs`'s own `#[test]` cases hand [`batten::hk::project`] a JSON document
//! they wrote, so they are green over a shape the runner may never emit — the
//! hazard `.claude/rules/policy-modules.md` names for a policy module and which
//! applies verbatim to a projection over a delegated tool's output. Two things
//! can only be proved against the real boundary: that the pinned runner's ACTUAL
//! plan projects at all, and that the committed artifact is the one this binary
//! derives from it rather than one that agreed with an earlier canonicaliser.
//!
//! # The case that carries the most
//!
//! [`the_committed_contract_is_the_one_the_binary_derives`] runs the gate over
//! this checkout. Every other case here is a shape somebody wrote to fail; that
//! one is the shape that has to keep passing, and it is what says the committed
//! projection and the pinned runner still agree rather than that a fixture of
//! them would.
//!
//! # Why the could-not-look arms are asserted in a scratch directory
//!
//! A directory with no runner config is a place the runner genuinely cannot
//! plan, so the `3` those cases assert is the engine's own answer to a real
//! failure rather than one a fixture faked. `.claude/rules/rust.md` asks for a
//! failing condition a test can actually create; this is that condition.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::verdict::DeclaredVerdictExt as _;

use std::fs;
use std::path::Path;

use batten::capture::Streamed as _;
use batten::hk;

/// The exit code a caller reads, as an integer, for the assertions below.
fn code(output: &std::process::Output) -> Option<i32> {
    output.status.code()
}

/// The `exclude` globs one `hk.pkl` step block declares, read off the committed
/// file. `None` when the step is not found, so a renamed step fails loudly rather
/// than reading as "excludes nothing".
fn step_excludes(pkl: &str, step: &str) -> Option<Vec<String>> {
    let opener = format!("  [\"{step}\"] = ");
    let start = pkl.lines().position(|line| line.starts_with(&opener))?;
    let block = pkl
        .lines()
        .skip(start + 1)
        .take_while(|line| *line != "  }");
    let mut globs = Vec::new();
    for line in block {
        let Some(list) = line.trim().strip_prefix("exclude = List(") else {
            continue;
        };
        globs.extend(
            list.trim_end_matches(')')
                .split(',')
                .map(|glob| glob.trim().trim_matches('"').to_owned())
                .filter(|glob| !glob.is_empty()),
        );
    }
    Some(globs)
}

/// The commands no commit-time hook step may run: each compiles, and a commit
/// hook is a batten hook held to the same 10 ms / 100 ms budget. `cargo fmt` is
/// absent on purpose: it formats, it does not build.
const COMPILES: &[&str] = &[
    "cargo clippy",
    "cargo build",
    "cargo run",
    "cargo test",
    "cargo check",
    "cargo nextest",
    "cargo mutants",
    "{{vars.batten}}",
];

/// The `check`/`fix` commands of every step a plain commit runs: the `gate`
/// steps outside a profile, plus the steps the `pre-commit` and `commit-msg`
/// hooks declare inline. A profiled step (`slow`) runs only where landing asks.
fn commit_time_commands(pkl: &str) -> Vec<(String, String)> {
    let mut commands = Vec::new();
    let mut in_gate = false;
    let mut hook: Option<String> = None;
    let mut step: Option<(String, Vec<String>, bool)> = None;
    let flush = |step: &mut Option<(String, Vec<String>, bool)>,
                 out: &mut Vec<(String, String)>| {
        if let Some((name, cmds, profiled)) = step.take()
            && !profiled
        {
            out.extend(cmds.into_iter().map(|cmd| (name.clone(), cmd)));
        }
    };
    for line in pkl.lines() {
        if line.starts_with("local gate = ") {
            in_gate = true;
            continue;
        }
        if in_gate && line == "}" {
            flush(&mut step, &mut commands);
            in_gate = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("  [\"") {
            let name = rest.split('"').next().unwrap_or_default().to_owned();
            flush(&mut step, &mut commands);
            if in_gate {
                step = Some((name, Vec::new(), false));
            } else {
                hook = Some(name);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("      [\"")
            && matches!(hook.as_deref(), Some("pre-commit" | "commit-msg"))
        {
            flush(&mut step, &mut commands);
            let name = rest.split('"').next().unwrap_or_default().to_owned();
            step = Some((name, Vec::new(), false));
            continue;
        }
        let trimmed = line.trim_start();
        if let Some((_, cmds, profiled)) = step.as_mut() {
            if trimmed.starts_with("profiles") {
                *profiled = true;
            } else if let Some(cmd) = trimmed
                .strip_prefix("check = \"")
                .or_else(|| trimmed.strip_prefix("fix = \""))
            {
                cmds.push(cmd.trim_end_matches('"').to_owned());
            }
        }
    }
    flush(&mut step, &mut commands);
    commands
}

/// The body a `mise run <task>` resolves to, one level down, so a step that
/// hides a compile inside a task is still seen.
fn task_body(mise: &toml::Table, command: &str) -> String {
    let Some(rest) = command.split("mise run").nth(1) else {
        return String::new();
    };
    let task = rest
        .split_whitespace()
        .find(|word| !word.starts_with('-'))
        .unwrap_or_default();
    mise.get("tasks")
        .and_then(|tasks| tasks.get(task))
        .and_then(|row| row.get("run"))
        .map(|run| match run {
            toml::Value::String(text) => text.clone(),
            toml::Value::Array(items) => items
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        })
        .unwrap_or_default()
}

/// No step a plain commit runs compiles anything, directly or through the
/// `mise` task it calls. Commits are made early and often and pushed to draft
/// pull requests; a commit hook proves the commit well-formed on pinned
/// released binaries, and landing proves the tree.
///
/// Fails by: a compiling step moved out of the `slow` profile (clippy, the
/// module census on the tree's engine), or a step calling a task whose body
/// spells `{{vars.batten}}`, which is `cargo run`.
#[test]
fn no_commit_time_hook_step_compiles() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pkl = fs::read_to_string(root.join("hk.pkl")).expect("hk.pkl reads");
    let mise: toml::Table = fs::read_to_string(root.join("mise.toml"))
        .expect("mise.toml reads")
        .parse()
        .expect("mise.toml parses");
    let commands = commit_time_commands(&pkl);
    assert!(
        commands
            .iter()
            .any(|(name, _)| name == "conventional-commit"),
        "the parse found the commit-msg steps: {commands:?}"
    );
    let compiling: Vec<String> = commands
        .iter()
        .filter_map(|(name, command)| {
            let body = task_body(&mise, command);
            COMPILES
                .iter()
                .find(|form| command.contains(*form) || body.contains(*form))
                .map(|form| format!("{name}: `{form}`"))
        })
        .collect();
    assert!(
        compiling.is_empty(),
        "commit-time steps compile: {compiling:?}"
    );
}

/// Every command of every step a plain commit runs, AS HK RESOLVES IT:
/// `pkl eval` over `hk.pkl` with its pinned `Builtins`, so a step taking its
/// `check`, `check_diff`, `check_list_files` or `fix` from an upstream builtin
/// (shfmt, taplo, pkl-format, prettier, actionlint, cargo-fmt's fixer) is read
/// as hk will run it, not as this file happens to spell it. Unprofiled steps of
/// the `pre-commit` and `commit-msg` hooks only: a `slow` step runs only where
/// landing asks.
fn resolved_commit_time_commands() -> Vec<(String, String)> {
    let config = resolved_hk();
    let mut commands = Vec::new();
    for hook in ["pre-commit", "commit-msg"] {
        let steps = config["hooks"][hook]["steps"]
            .as_object()
            .unwrap_or_else(|| panic!("hk.pkl resolves a `{hook}` hook with steps"));
        for (name, step) in steps {
            if step.get("profiles").is_some_and(|p| !p.is_null()) {
                continue;
            }
            for key in ["check", "check_diff", "check_list_files", "fix"] {
                if let Some(command) = step.get(key).and_then(command_text) {
                    commands.push((name.clone(), command));
                }
            }
        }
    }
    commands
}

/// One resolved step command as a single line: a string as written, or an
/// `argv` joined by spaces.
fn command_text(spec: &serde_json::Value) -> Option<String> {
    let command = spec.get("command").unwrap_or(spec);
    command.as_str().map(str::to_owned).or_else(|| {
        let argv = command.get("argv")?.as_array()?;
        Some(
            argv.iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        )
    })
}

/// `hk.pkl` as hk resolves it: `pkl eval` with its pinned `Builtins`.
fn resolved_hk() -> serde_json::Value {
    let mut command = common::pkl_command();
    command
        .args(["-f", "json", "hk.pkl"])
        .current_dir(common::at_root("."));
    let output = command.streamed_output().expect("pkl evaluates hk.pkl");
    assert!(
        output.status.success(),
        "pkl eval hk.pkl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("`-f json` prints one JSON document")
}

/// No command a plain commit runs, as hk resolves it from its builtins as well
/// as from this file, compiles or pays `mise`'s startup unbudgeted.
///
/// `mise` alone costs 105-125 ms before a task body runs (CLOUD-1397), past the
/// 100 ms ceiling every commit-time step answers to, so a step routed through
/// `mise` is refused unless `policy/perf-assert.rego` budgets it by name — then
/// its measured arm, not this test, decides.
///
/// Fails by: `cargo-fmt` routed back through `mise run lint:fmt` with no
/// budget, or a builtin's default command (which
/// `no_commit_time_hook_step_compiles` cannot see) compiling.
#[test]
fn no_resolved_commit_time_command_compiles_or_pays_mise_startup_unbudgeted() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let budgets =
        fs::read_to_string(root.join("policy/perf-assert.rego")).expect("perf-assert reads");
    let mise: toml::Table = fs::read_to_string(root.join("mise.toml"))
        .expect("mise.toml reads")
        .parse()
        .expect("mise.toml parses");
    let commands = resolved_commit_time_commands();
    for reached in ["taplo", "taplo-format", "prettier", "conventional-commit"] {
        assert!(
            commands.iter().any(|(name, _)| name == reached),
            "the resolution reached {reached}: {commands:?}"
        );
    }
    let offending: Vec<String> = commands
        .iter()
        .filter_map(|(name, command)| {
            let body = task_body(&mise, command);
            if let Some(form) = COMPILES
                .iter()
                .find(|form| command.contains(*form) || body.contains(*form))
            {
                return Some(format!("{name} compiles: `{form}`"));
            }
            let through_mise = command.starts_with("mise ") || command.contains("mise run");
            (through_mise && !budgets.contains(&format!("\"{name}\": 100")))
                .then(|| format!("{name} pays mise's startup unbudgeted: `{command}`"))
        })
        .collect();
    assert!(offending.is_empty(), "commit-time commands: {offending:?}");
}

/// The rustfmt line the commit-time `cargo-fmt` step runs, for `edition`.
fn staged_rustfmt(edition: &str) -> String {
    format!("rustfmt --check --edition {edition} --config skip_children=true {{{{files}}}}")
}

/// The commit-time formatter judges EXACTLY the staged `.rs` files (CLOUD-2789).
///
/// `cargo fmt --all --check` formatted the whole workspace on every commit, 5.0 s
/// p50, past the 100 ms ceiling whatever the commit touched. hk hands a
/// pre-commit step's `{{files}}` the staged paths its glob selects, so the step's
/// file set is the staged set only when every command reads `{{files}}`, none
/// widens to `--all` or a manifest, and no `workspace_indicator` splits the job
/// per Cargo workspace. The edition is the workspace's, so the hook and landing's
/// `lint:fmt` cannot disagree on a file.
///
/// Fails by: a command going back to `cargo fmt`, `--all` or the indicator; the
/// glob widening past `.rs`; or the edition drifting from `Cargo.toml`'s.
#[test]
fn the_commit_time_formatter_reads_exactly_the_staged_rs_files() {
    let root = common::at_root(".");
    let manifest: toml::Table = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Cargo.toml reads")
        .parse()
        .expect("Cargo.toml parses");
    let edition = manifest["workspace"]["package"]["edition"]
        .as_str()
        .expect("the workspace declares one edition");
    let config = resolved_hk();
    let step = &config["hooks"]["pre-commit"]["steps"]["cargo-fmt"];
    assert_eq!(step["glob"], "**/*.rs", "the step selects staged Rust only");
    assert!(
        step["workspace_indicator"].is_null(),
        "one job over the staged files, not one per Cargo workspace: {step}"
    );
    assert_eq!(
        step.get("check").and_then(command_text),
        Some(staged_rustfmt(edition))
    );
    for key in ["check_list_files", "fix"] {
        let command = step.get(key).and_then(command_text).unwrap_or_default();
        assert!(
            command.starts_with("rustfmt ")
                && command.ends_with(" {{files}}")
                && command.contains(&format!("--edition {edition} "))
                && command.contains("--config skip_children=true"),
            "cargo-fmt's {key} formats the staged files as `check` does: `{command}`"
        );
    }
}

/// The schema-bound TOML is linted at landing, every other TOML at the commit,
/// and the two sets are exactly `.taplo.toml`'s schema bindings (CLOUD-2789).
///
/// `taplo lint batten.toml` is 110 ms p95 against its 512 KB schema, over the
/// commit ceiling, so the default `taplo` step excludes the bound files and a
/// `slow` `taplo-schema` step lints them where `ci:checks` (`hk check --all`)
/// reaches it in `verify`. A binding added to `.taplo.toml` and not here would
/// be linted at the commit again, or at no point at all if dropped from both.
///
/// Fails by: the commit step linting a bound file, the landing step losing
/// `slow` or a bound file, or the list drifting from `.taplo.toml`.
#[test]
fn schema_bound_toml_is_linted_at_landing_and_the_rest_at_the_commit() {
    let root = common::at_root(".");
    let taplo: toml::Table = fs::read_to_string(root.join(".taplo.toml"))
        .expect(".taplo.toml reads")
        .parse()
        .expect(".taplo.toml parses");
    let mut bound: Vec<String> = taplo["rule"]
        .as_array()
        .expect(".taplo.toml declares rules")
        .iter()
        .filter(|rule| rule.get("schema").is_some())
        .flat_map(|rule| {
            rule["include"]
                .as_array()
                .expect("a schema rule includes files")
                .iter()
                .map(|glob| glob.as_str().expect("a glob").to_owned())
        })
        .collect();
    bound.sort();
    assert!(
        bound.contains(&String::from("batten.toml")),
        "the scan found the bindings this tree carries: {bound:?}"
    );
    let config = resolved_hk();
    let steps = &config["hooks"]["pre-commit"]["steps"];
    let listed = |value: &serde_json::Value| -> Vec<String> {
        let mut globs: Vec<String> = value
            .as_array()
            .map(|globs| {
                globs
                    .iter()
                    .filter_map(|glob| glob.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        globs.sort();
        globs
    };
    let commit = &steps["taplo"];
    assert!(
        commit["profiles"].is_null(),
        "taplo still runs at the commit"
    );
    assert_eq!(
        listed(&commit["exclude"]),
        bound,
        "and skips every bound file"
    );
    let landing = &steps["taplo-schema"];
    assert_eq!(
        listed(&landing["profiles"]),
        ["slow"],
        "the schema check runs where `hk check --all` reaches it"
    );
    assert_eq!(listed(&landing["glob"]), bound, "over every bound file");
    assert_eq!(
        landing.get("check").and_then(command_text),
        commit.get("check").and_then(command_text),
        "with the same lint the commit runs over the rest"
    );
}

/// A staged `lib.rs` does not drag its UNSTAGED children in (CLOUD-2789).
///
/// rustfmt given a file recurses into every out-of-line `mod` it declares, so
/// over the crate root it formats the whole crate: 2.5 s for this tree's
/// `lib.rs`, and a verdict on files the commit does not contain. The step's
/// `skip_children` is what stops it, and stable rustfmt honours it — asserted
/// here against the pinned formatter, not assumed from its docs.
///
/// Fails by: `skip_children` dropped from the step, or the pinned rustfmt
/// ignoring it (the unformatted child then fails the staged root's check).
#[test]
fn a_staged_crate_root_is_formatted_without_its_children() {
    // `rustfmt` is a component of the `rust` pin, not a `[tools]` entry of its own.
    let rustfmt = common::require_bin("rust", "rustfmt");
    let dir = common::scratch("staged-rustfmt");
    fs::write(dir.join("lib.rs"), "mod child;\n\nfn root() {}\n").expect("write lib.rs");
    fs::write(dir.join("child.rs"), "fn   child( ) {}\n").expect("write child.rs");
    let command = resolved_hk()["hooks"]["pre-commit"]["steps"]["cargo-fmt"]
        .get("check")
        .and_then(command_text)
        .expect("cargo-fmt has a check");
    let run = |file: &str| {
        let argv: Vec<String> = command
            .split_whitespace()
            .skip(1)
            .map(|word| word.replace("{{files}}", file))
            .collect();
        #[expect(
            clippy::disallowed_types,
            reason = "stays, and test-only: the subject is the pinned formatter's own verdict on a scratch file; a read-only `--check`"
        )]
        let mut process = std::process::Command::new(&rustfmt);
        process.args(&argv).current_dir(&dir);
        code(&process.streamed_output().expect("rustfmt runs"))
    };
    assert_eq!(run("lib.rs"), Some(0), "the staged root alone is formatted");
    assert_eq!(
        run("child.rs"),
        Some(1),
        "and the child really is unformatted, so the first answer means something"
    );
}

/// Every nested Cargo workspace is outside the root clippy step (CLOUD-2051).
///
/// The builtin forms one hk job per Cargo workspace, and the step's command,
/// `mise run lint:clippy`, checks the ROOT whichever job runs it — so a nested
/// `[workspace]` the step does not exclude is a second full clippy of the root per
/// lap, and a workspace the step reads as covering while it checks nothing of it.
/// Measured on the 2026-09-30 landing lap: `fuzz/` made it run twice.
//
// The declared mutation, in a plain comment because `hk.pkl` is no sweep route;
// killed by hand:
#[test]
fn every_nested_cargo_workspace_is_excluded_from_the_root_clippy_step() {
    let root = common::at_root(".");
    let pkl = fs::read_to_string(root.join("hk.pkl")).expect("hk.pkl is committed");
    let excludes =
        step_excludes(&pkl, "cargo-clippy").expect("hk.pkl still declares the cargo-clippy step");
    let manifests = common::git_in(&root, &["ls-files", "--", "*Cargo.toml"]);
    let nested: Vec<&str> = manifests
        .lines()
        .filter(|manifest| *manifest != "Cargo.toml")
        .filter(|manifest| {
            fs::read_to_string(root.join(manifest))
                .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        })
        .collect();
    // ANTI-VACUITY: the case was written over `fuzz/`, and a listing that finds no
    // nested workspace would pass whatever the step declared.
    assert!(
        nested.contains(&"fuzz/Cargo.toml"),
        "the nested-workspace scan found none of the ones this tree carries: {nested:?}"
    );
    for manifest in nested {
        let dir = manifest.trim_end_matches("Cargo.toml");
        assert!(
            excludes.iter().any(|glob| glob == &format!("{dir}**")),
            "`{manifest}` declares its own [workspace], so hk forms a second cargo-clippy job \
             for it that re-runs the root's `lint:clippy`; exclude `{dir}**` from the step. \
             Declared: {excludes:?}"
        );
    }
}

/// The whole point of the row: the committed projection still matches the
/// pinned runner.
///
/// Exit `0` from the real gate at the real root. A `2` here means the artifact
/// is stale and `mise run hk-contract` is the remedy; a `3` means the pinned
/// runner could not be reached, which is a provisioning fault rather than a
/// drifted contract, and the two are deliberately different codes.
#[test]
fn the_committed_contract_is_the_one_the_binary_derives() {
    let root = common::at_root(".");
    let output = common::run(&root, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(0),
        "the committed contract drifted from the pinned runner; run `mise run hk-contract` and read the diff.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// **And it is the same contract from a caller that suppresses steps** — the
/// arm CI found and this file could not, because every case here ran from a
/// shell that sets nothing.
///
/// `.github/workflows/ci.yml`'s `ci` job hands the runner
/// `HK_SKIP_STEPS: batten-check`, so that step runs in its own lane — and it
/// carved the shell suite out beside it until CLOUD-843 retired that suite.
/// Measured on `478a8482`: `hk drift` there reported both steps restatused on
/// two surfaces and exited `2`, over an artifact and a config that had not
/// moved. A contract that varied by caller could not be committed at all, so the
/// plan spawn scrubs the variable ([`hk::CALLER_SKIP`]) and this is the case
/// that says so.
///
/// Set on the CHILD rather than on this process: the subject is what the
/// spawned runner's environment carries, and mutating the harness's own would
/// leak into every other case in the binary.
#[test]
fn a_caller_suppressing_steps_does_not_drift_the_contract() {
    let root = common::at_root(".");
    let output = common::batten()
        .args(["hk", "drift"])
        .current_dir(&root)
        .env(hk::CALLER_SKIP, "sbom-check,batten-check")
        .streamed_output()
        .expect("run batten");
    assert_eq!(
        code(&output),
        Some(0),
        "a caller's step suppression is not the config's plan.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The committed artifact is a projection this build can read back.
///
/// Separate from the gate above because they fail for different reasons: this
/// one goes red when the artifact's SHAPE and the type disagree — a field
/// renamed, a key added — where the gate goes red when the CONTENT disagrees
/// with the runner. A shape change would otherwise surface as a `1` from the
/// gate with no case naming it.
#[test]
fn the_committed_artifact_reads_back_as_this_builds_shape() {
    let text =
        fs::read_to_string(common::at_root(hk::ARTIFACT)).expect("the artifact is committed");
    let contract = hk::Contract::parse(&text).expect("the artifact is this build's shape");
    assert_eq!(contract.version, hk::SHAPE);
    assert_eq!(
        contract.surfaces.len(),
        hk::SURFACES.len(),
        "one projected surface per declared surface"
    );
    assert!(
        contract
            .surfaces
            .iter()
            .all(|surface| !surface.steps.is_empty()),
        "an empty surface would commit clean against every later comparison"
    );
    assert_eq!(
        text,
        contract.render().expect("the artifact renders"),
        "the committed bytes are the ones this build emits; run `mise run hk-contract`"
    );
}

/// Where the runner cannot plan, the gate says so and does not say "clean".
///
/// `3`, never `0`: an absent answer and a passing one are different, and this is
/// the arm where the engine could not look. Asserted over the compiled binary
/// because a unit test can only fabricate the failure, and the fabrication is
/// what would hide a boundary that swallowed it.
#[test]
fn a_directory_the_runner_cannot_plan_is_could_not_look() {
    let dir = common::scratch("hk-contract-unplannable");
    common::init_repo(&dir);
    let output = common::run(&dir, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(3),
        "a tree the runner cannot plan is could-not-look, never clean"
    );
    assert_ne!(
        code(&output),
        Some(0),
        "an unreachable runner must never read as a passing contract"
    );
}

/// The read verb writes nothing, which is what makes its declared effect honest.
///
/// The structural half of `surface.rs`'s `generate_writes_no_file`: a `read` row
/// that touched the working directory would be a write verb with a read
/// declaration, and the declaration is what the read-only allowlist is derived
/// from.
#[test]
fn the_drift_verb_writes_no_file() {
    let dir = common::scratch("hk-contract-read-effect");
    common::init_repo(&dir);
    let before = tracked_entries(&dir);
    let _ = common::run(&dir, &["hk", "drift"]);
    assert_eq!(
        tracked_entries(&dir),
        before,
        "a read-effect verb wrote to the working directory"
    );
}

/// The directory's entries, excluding the git dir the harness created.
fn tracked_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("the directory reads")
        .filter_map(|entry| Some(entry.ok()?.file_name().to_str()?.to_owned()))
        .filter(|name| name != ".git")
        .collect();
    names.sort();
    names
}

/// The two verbs carry the two effects the row specifies, read off the surface
/// the allowlist is derived from.
///
/// Asserted through `spec` rather than by reading `surface.rs`, because the
/// published document is what a third party pins against — and a row whose
/// effect moved would keep compiling.
#[test]
fn the_generator_is_a_write_and_the_gate_is_a_read() {
    let root = common::at_root(".");
    let output = common::run(&root, &["spec", "--format", "json"]);
    let spec: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the spec is one JSON document");
    let mut seen = 0;
    let mut pending = vec![&spec];
    while let Some(command) = pending.pop() {
        if let Some(children) = command["subcommands"].as_array() {
            pending.extend(children);
        }
        match command["id"].as_str() {
            Some("hk.contract") => {
                assert_eq!(command["effect"], "write");
                seen += 1;
            }
            Some("hk.drift") => {
                assert_eq!(command["effect"], "read");
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 2, "both verbs are published on the surface");

    // The allowlist is a walk over the same tree, so a write verb reaching it
    // would mean the effect declared above is not the one the allowlist derives
    // from. The gate is on it; the generator must not be.
    let allowlist = spec["read_only_allowlist"]
        .as_array()
        .expect("the spec publishes the read-only allowlist");
    let ids: Vec<&str> = allowlist
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert!(ids.contains(&"hk.drift"), "the gate is read-only");
    assert!(
        !ids.contains(&"hk.contract"),
        "a generator that regenerates a committed artifact is never read-only"
    );
}

/// The gate's refusal names the class the registry declares, and points at the
/// artifact rather than quoting either plan (non-negotiable rule 4).
#[test]
fn the_refusal_is_a_declared_class_with_a_route() {
    let registry = batten::config_check::verdict::vendored();
    let token = batten::error::Native::PlanReadStale.id();
    let row = registry
        .iter()
        .find(|declared| declared.id == token)
        .expect("the class is declared");
    assert!(
        !row.routes.is_empty(),
        "a class with no route has no remedy"
    );
    assert!(!row.retired(), "the gate raises a live class");
}

/// **The drifted arm, over the real runtime path** — the one this file could not
/// otherwise show able to fire.
///
/// Every other case here reaches clean, could-not-look, or `hk::compare` in
/// isolation. None of them drives `hk drift` to a `2`, so the CLI's own
/// comparison, its refusal construction and its exit mapping were unexercised:
/// a build that mapped drift to `0` would have passed this whole file. That is
/// the CLOUD-418 shape — a gate never shown able to fail is a gate nobody has
/// evidence for — and the gap was reported in review of #873 rather than found
/// here, which is the reason it is written out.
///
/// **The baseline is GENERATED in the scratch root rather than copied from the
/// committed one**, and that is load-bearing. `hk` plans against the tree it
/// runs in, so a step whose glob matches nothing here is `skipped` where the
/// real tree has it `included` — and `status` is in the projection. Seeding
/// with the repository's own artifact would therefore drift for a reason this
/// case is not about, and would pass while proving nothing. Generating first
/// makes the mutation below the ONLY difference, and exercises the writer on
/// the way past.
#[test]
fn a_drifted_contract_exits_two_and_names_the_class() {
    // `Fixture` rather than a `tempfile`: it is this suite's own scratch
    // convention and needs no dev-dependency the binary does not link.
    let scratch = common::Fixture::new("hk-contract-drift");
    let root = scratch.path();
    fs::copy(common::at_root("hk.pkl"), root.join("hk.pkl")).expect("the runner config copies");
    fs::create_dir_all(root.join("contracts")).expect("the artifact directory");

    let generated = common::run(root, &["hk", "contract"]);
    // The pinned runner is provisioned by `mise.toml`, so an unreachable one is a
    // provisioning fault — and a fault FAILS, beside
    // `the_committed_contract_is_the_one_the_binary_derives`, rather than letting
    // this case pass over an arm it never reached (CLOUD-2059).
    assert_eq!(
        code(&generated),
        Some(0),
        "the pinned runner generates the contract: {}",
        common::stderr(&generated)
    );

    let artifact = root.join(hk::ARTIFACT);
    let text = fs::read_to_string(&artifact).expect("the generator wrote the artifact");
    let mut contract = hk::Contract::parse(&text).expect("it reads back");
    let step = contract
        .surfaces
        .first_mut()
        .and_then(|surface| surface.steps.first_mut())
        .expect("the generated contract carries a step");
    // A RENAME rather than a deletion: renaming drifts both directions at once
    // (one step gone, one arrived) and leaves the counts equal, so an
    // implementation comparing only lengths still goes red here.
    step.name = format!("{}-renamed", step.name);
    fs::write(&artifact, contract.render().expect("it renders")).expect("the drift is committed");

    let output = common::run(root, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(2),
        "a drifted contract is a policy verdict, not a fault.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(batten::error::Native::PlanReadStale.id()),
        "the refusal names its declared class: {stderr}"
    );
    assert!(
        stderr.contains(hk::ARTIFACT),
        "and points at the artifact, which is the remedy's subject: {stderr}"
    );
    // RULE 4, at the one site where a diff would be the tempting thing to
    // print: the refusal carries step NAMES and never either plan's body.
    assert!(
        !stderr.contains("\"steps\":") && !stderr.contains("orderIndex"),
        "the refusal quoted a plan instead of pointing at one: {stderr}"
    );
}
