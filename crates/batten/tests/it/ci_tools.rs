//! The install lists name real declared tools, every pull-request workflow
//! carries a binding one, and every tool a policy row spawns is on the list —
//! over the compiled binary (CLOUD-180, CLOUD-812 and CLOUD-480, ported from
//! `mise-tasks/ci-tools-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/ci-tools.rego` carries load-time
//! cases pinning all three directions, and every one hands the module a
//! ready-made map of workflows with `with input as`. That fabricates the very
//! shape the engine may be unable to produce (CLOUD-845), and the second direction
//! IS that shape: its whole finding was that the retiring gate had been pointed at
//! one file which happened to conform, so two other workflows installed every
//! declared tool on every push with nothing red and nothing able to be. A
//! resolution reaching only some workflows reintroduces exactly that blindness,
//! and no fabricated map can tell it from a clean tree.
//!
//! The self-consumption cases are the two the retiring suite kept: the committed
//! workflow and manifest agree, and every committed pull-request workflow carries
//! a binding list.
//
// carried: mise-tasks/ci-tools-check.sh policy/ci-tools.rego crates/batten/tests/it/ci_tools.rs
// carried: tests/ci-tools-check.bats policy/ci-tools.rego crates/batten/tests/it/ci_tools.rs
//
// carried: "the real ci.yml and mise.toml agree" policy/ci-tools.rego
// carried: "a tool a policy row spawns must be in the install list" policy/ci-tools.rego
// carried: "THE DEFECT: a declared tool a row spawns but no list installs is refused" policy/ci-tools.rego
// carried: "a spawned tool mise does not own is out of scope, not a finding" policy/ci-tools.rego
// carried: "every requested tool declared is a pass" policy/ci-tools.rego
// carried: "quoted and backend-prefixed names resolve" policy/ci-tools.rego
// carried: "a tool declared but never installed by CI is not a failure" policy/ci-tools.rego
// carried: "a renamed tool leaves install_args naming something undeclared" policy/ci-tools.rego
// carried: "the error names the tool and both files, not the file contents" policy/ci-tools.rego
// carried: "a key from another table does not count as declared" policy/ci-tools.rego
// carried: "a config with no [tools] table fails rather than passing" policy/ci-tools.rego
// carried: "a PR workflow with a narrowed, binding list passes" policy/ci-tools.rego
// carried: "a PR workflow running mise-action with no install_args fails" policy/ci-tools.rego
// carried: "a declared list without the auto-install variables fails" policy/ci-tools.rego
// carried: "an auto-install variable set to true is not binding either" policy/ci-tools.rego
// carried: "a workflow with no pull_request trigger is out of scope" policy/ci-tools.rego
// carried: "a PR workflow that never runs mise-action is out of scope" policy/ci-tools.rego
// carried: "the committed PR workflows all carry a binding list" policy/ci-tools.rego
// carried: "a tool name that resolves nowhere fails in a PR workflow other than the first argument" policy/ci-tools.rego
// changed: "a workflow with no install_args lists fails rather than passing" policy/ci-tools.rego the shell was pointed at ONE workflow and refused it for declaring no list; the successor asks the question over every workflow, so the arm is the stronger one CLOUD-812 wrote — a pull-request workflow that runs the installer and declares no list is `tool select missing`, which the retiring suite pins separately and which reaches the workflows the single-file form structurally could not see
// changed: "a missing file is an error, not a pass" policy/ci-tools.rego the shell took explicit paths and refused one it could not open; the successor declares `line_sources` and the ENGINE decides this earlier — a rule whose declared paths match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). The vacuity that mattered survives whole: a manifest that resolves and declares no tools is `tool list empty`

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn tools_repo(name: &str, manifest: &str, policy: &str, workflows: &[(&str, &str)]) -> PathBuf {
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[pattern]]\n\
         id = \"install-args-line\"\n\
         regex = '^[ \\t]*install_args:'\n\n\
         [[pattern]]\n\
         id = \"workflow-pull-request-trigger\"\n\
         regex = '^[ \\t]*pull_request:'\n\n\
         [[pattern]]\n\
         id = \"mise-task-auto-install-off\"\n\
         regex = '^[ \\t]*MISE_TASK_RUN_AUTO_INSTALL:[ \\t]*\"?false\"?[ \\t]*$'\n\n\
         [[pattern]]\n\
         id = \"mise-exec-auto-install-off\"\n\
         regex = '^[ \\t]*MISE_EXEC_AUTO_INSTALL:[ \\t]*\"?false\"?[ \\t]*$'\n\n\
         [[pattern]]\n\
         id = \"mise-exec-spawn\"\n\
         regex = 'mise exec -- [a-z][a-z0-9._-]*'\n\n\
         [[verdict]]\n\
         id = \"tool name unknown\"\n\
         gloss = \"an install list names a tool the manifest does not declare\"\n\
         class = \"The installer does not fail on an unknown name; it surfaces later as a missing command.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"tool select missing\"\n\
         gloss = \"a pull-request workflow runs the installer without an install list\"\n\
         class = \"Judging the names IN a list can never see a workflow that declares none.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"tool pin loose\"\n\
         gloss = \"an install list is declared without the variables that make it bind\"\n\
         class = \"The runner re-installs the rest at task time, so the list decides nothing.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"spawn reach absent\"\n\
         gloss = \"a policy row spawns a declared tool no install list installs\"\n\
         class = \"With auto-install off the row fails CLOSED in CI while passing locally.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"tool list empty\"\n\
         gloss = \"the manifest declares no tools, so the question cannot be asked\"\n\
         class = \"With the declared set empty every install list resolves vacuously.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"tool pin wrong\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\"mise.toml\", \"batten.toml\", \".github/workflows/*.yml\"]\n\
         module = \"policy/ci-tools.rego\"\n\
         severity = \"deny\"\n\n",
    );
    fixture = fixture
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("mise.toml", manifest);
    for (path, body) in workflows {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    // The spawns the third direction reads live in the fixture's own config,
    // which is the file the rule names — so they are appended to it rather than
    // written beside it. They go on a COMMENT line: the module is a line scan, so
    // where in the file the text sits does not change the predicate, and a bare
    // key appended after the rule tables would attach to the last one and be a
    // load error rather than the verdict these cases are about.
    let config_path = dir.join("batten.toml");
    let existing = std::fs::read_to_string(&config_path).unwrap();
    std::fs::write(&config_path, format!("{existing}\n# {policy}")).unwrap();
    common::write(
        &dir,
        "policy/ci-tools.rego",
        &std::fs::read_to_string(common::at_root("policy/ci-tools.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "tool pin wrong"])
}

const MANIFEST: &str = "[tools]\nrust = \"1.97\"\n\"aqua:open-policy-agent/opa\" = \"1.0\"\nzig = \"0.13\"\n\n[env]\nX = \"1\"\n";

const NO_SPAWNS: &str = "this config spawns nothing\n";

/// A pull-request workflow running the installer once, with `entries` inside the
/// step and the auto-install variables bound.
fn pr_flow(entries: &str) -> String {
    format!(
        "on:\n  pull_request:\njobs:\n  ci:\n    steps:\n      - uses: jdx/mise-action@abc\n{entries}      env:\n        MISE_TASK_RUN_AUTO_INSTALL: \"false\"\n        MISE_EXEC_AUTO_INSTALL: \"false\"\n"
    )
}

#[test]
fn every_requested_tool_declared_is_a_pass() {
    let dir = tools_repo(
        "tools-clean",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust aqua:open-policy-agent/opa\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_renamed_tool_leaves_the_list_naming_something_undeclared() {
    let dir = tools_repo(
        "tools-renamed",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust zigg\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("zigg"),
        "the finding names the tool: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_tool_declared_but_never_installed_is_not_a_failure() {
    // The predicate is that names RESOLVE, not that every declared tool is
    // installed everywhere — inferring which tools a job should need is a
    // judgement, not a predicate.
    let dir = tools_repo(
        "tools-declared-unused",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_key_from_another_table_does_not_count_as_declared() {
    let dir = tools_repo(
        "tools-other-table",
        "[tools]\nrust = \"1.97\"\n\n[env]\nzig = \"decoy\"\n",
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust zig\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_manifest_with_no_tools_table_is_not_a_pass() {
    let dir = tools_repo(
        "tools-no-table",
        "[env]\nX = \"1\"\n",
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_pull_request_workflow_with_no_list_is_refused() {
    // THE HOLE CLOUD-812 MEASURED: judging the names IN a list can never see a
    // workflow that declares none, and two such workflows were installing
    // everything on every push with nothing red.
    let dir = tools_repo(
        "tools-no-list",
        MANIFEST,
        NO_SPAWNS,
        &[
            (
                ".github/workflows/ci.yml",
                &pr_flow("        install_args: rust\n"),
            ),
            (".github/workflows/lint.yml", &pr_flow("")),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("lint.yml"),
        "the finding names the blind workflow: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_list_without_the_auto_install_variables_is_refused() {
    // Decorative: the runner re-installs the rest at task time, which is
    // indistinguishable from a fix by reading the workflow.
    let dir = tools_repo(
        "tools-nonbinding",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            "on:\n  pull_request:\njobs:\n  ci:\n    steps:\n      - uses: jdx/mise-action@abc\n        install_args: rust\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_variable_set_true_is_not_binding_either() {
    // The same hole wearing a fix's clothing.
    let dir = tools_repo(
        "tools-true",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            "on:\n  pull_request:\njobs:\n  ci:\n    steps:\n      - uses: jdx/mise-action@abc\n        install_args: rust\n      env:\n        MISE_TASK_RUN_AUTO_INSTALL: \"true\"\n        MISE_EXEC_AUTO_INSTALL: \"false\"\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_workflow_with_no_pull_request_trigger_is_out_of_scope() {
    let dir = tools_repo(
        "tools-scheduled",
        MANIFEST,
        NO_SPAWNS,
        &[
            (
                ".github/workflows/ci.yml",
                &pr_flow("        install_args: rust\n"),
            ),
            (
                ".github/workflows/nightly.yml",
                "on:\n  schedule:\njobs:\n  x:\n    steps:\n      - uses: jdx/mise-action@abc\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_pull_request_workflow_that_never_runs_the_installer_is_out_of_scope() {
    let dir = tools_repo(
        "tools-no-action",
        MANIFEST,
        NO_SPAWNS,
        &[
            (
                ".github/workflows/ci.yml",
                &pr_flow("        install_args: rust\n"),
            ),
            (
                ".github/workflows/labels.yml",
                "on:\n  pull_request:\njobs:\n  x:\n    steps:\n      - run: echo hi\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_spawned_tool_the_list_omits_is_refused() {
    // THE DEFECT that cost two CI runs: with auto-install off the row does not
    // run slowly, it fails CLOSED — green locally, red in CI, with nothing
    // naming the cause.
    let dir = tools_repo(
        "tools-spawn-omitted",
        MANIFEST,
        "check = mise exec -- opa check -s schema/ policy/\n",
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("opa"),
        "the finding names the spawned tool: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_spawned_tool_the_manifest_does_not_own_is_out_of_scope() {
    // A binary can arrive bundled, pre-installed or vendored, and all three came
    // back as findings on the first run of that block. The question narrows to
    // what the manifest declares rather than carrying a second exemption list.
    let dir = tools_repo(
        "tools-spawn-unowned",
        MANIFEST,
        "check = mise exec -- gh pr view\n",
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust aqua:open-policy-agent/opa\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_spawned_tool_the_list_installs_by_backend_name_resolves() {
    // Basename matching on both sides: the list holds a backend-qualified key
    // and the spawn names a binary.
    let dir = tools_repo(
        "tools-spawn-backend",
        MANIFEST,
        "check = mise exec -- opa check\n",
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust aqua:open-policy-agent/opa\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = tools_repo(
        "tools-pointer-only",
        MANIFEST,
        NO_SPAWNS,
        &[(
            ".github/workflows/ci.yml",
            &pr_flow("        install_args: rust zigg\n        name: a-distinctive-step\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("a-distinctive-step"),
        "the workflow body is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_committed_workflows_and_manifest_agree() {
    // The two self-consumption cases the retiring suite kept, in one run.
    let output = common::run(&common::at_root(""), &["check", "--rule", "tool pin wrong"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the committed install lists and manifest disagree: {}",
        stdout(&output)
    );
}

/// The shell commands in a `run` text: each line's code up to a `#` that opens a
/// comment (at a word start, outside quotes), split on `&&`, `||`, `;` and `|`.
fn commands(run: &str) -> Vec<&str> {
    let mut found = Vec::new();
    for line in run.lines() {
        let mut quote = None;
        let mut end = line.len();
        let mut previous = ' ';
        for (at, c) in line.char_indices() {
            match (quote, c) {
                (None, '"' | '\'') => quote = Some(c),
                (Some(open), _) if c == open => quote = None,
                (None, '#') if previous.is_whitespace() => {
                    end = at;
                    break;
                }
                _ => {}
            }
            previous = c;
        }
        found.extend(
            line[..end]
                .split(['&', '|', ';'])
                .map(str::trim)
                .filter(|command| !command.is_empty()),
        );
    }
    found
}

/// Whether a `run` text runs the suite (CLOUD-2381, CLOUD-2388), given the mise
/// tasks known to. A command does when it runs `nextest run`, `cargo test` or
/// `llvm-cov` unfiltered (no `--no-run`, no `-E`, no `path::` filter, not
/// `llvm-cov report`), `hk check --all` with the slow tier (hk's `test` step is
/// `mise run test:cargo`), `mutate sweep`, or `mise run` naming a task in `suite`
/// before its first `--`, whatever flags and values come before it.
//MUTANT suite-via-hk-unseen|s@ (command.contains("hk check --all")@ (false@|every_suite_job_installs_the_pinned_tools_its_cases_require
fn runs_suite(run: &str, suite: &BTreeSet<String>) -> bool {
    commands(run).into_iter().any(|command| {
        let words: Vec<&str> = command.split_whitespace().collect();
        let filtered = command.contains("--no-run")
            || command.contains("llvm-cov report")
            || words
                .iter()
                .any(|word| *word == "-E" || word.contains("::"));
        (["nextest run", "cargo test", "llvm-cov"]
            .iter()
            .any(|runner| command.contains(runner))
            && !filtered)
            || (command.contains("hk check --all") && !command.contains("!slow"))
            || command.contains("mutate sweep")
            || command.split("mise run ").skip(1).any(|rest| {
                rest.split_whitespace()
                    .take_while(|word| *word != "--")
                    .any(|word| suite.contains(word))
            })
    })
}

/// The mise tasks that run the suite: closed over `mise run` and `depends`, so
/// a wrapper task is found from what it runs, never from a list of names.
fn suite_tasks(manifest: &toml::Value) -> BTreeSet<String> {
    let tasks: Vec<(&String, String, Vec<&str>)> = manifest["tasks"]
        .as_table()
        .expect("[tasks]")
        .iter()
        .map(|(name, task)| {
            let body = match task.get("run") {
                Some(toml::Value::String(line)) => line.clone(),
                Some(toml::Value::Array(lines)) => lines
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            let depends = task
                .get("depends")
                .and_then(toml::Value::as_array)
                .map_or_else(Vec::new, |deps| {
                    deps.iter()
                        .filter_map(toml::Value::as_str)
                        .filter_map(|dep| dep.split_whitespace().next())
                        .collect()
                });
            (name, body, depends)
        })
        .collect();
    let mut suite = BTreeSet::new();
    loop {
        let before = suite.len();
        for (name, body, depends) in &tasks {
            if depends.iter().any(|dep| suite.contains(*dep)) || runs_suite(body, &suite) {
                suite.insert((*name).clone());
            }
        }
        if suite.len() == before {
            return suite;
        }
    }
}

/// A tool's name as `[tools]` and `install_args` both reduce to it: the last
/// `/` or `:` segment, any `@version` dropped.
fn tool_name(key: &str) -> String {
    let key = key.split('@').next().unwrap_or(key);
    key.rsplit(['/', ':']).next().unwrap_or(key).to_owned()
}

/// Every tool a `common::require_tool` or `common::require_bin` call names
/// across the crate's sources: the call's first argument, a string literal
/// naming the `[tools]` entry's last segment (CLOUD-2388). A call whose first
/// argument is not a literal, and a `mise which` spawned anywhere but `common`,
/// are refused: either would be a requirement this scan cannot read.
//MUTANT require-call-unread|s@^            required.insert(tool.to_owned());$@@|every_suite_job_installs_the_pinned_tools_its_cases_require
fn required_tools() -> BTreeSet<String> {
    // Split, so this file's own text is not read as a call.
    let calls = [
        concat!("common::require_", "tool("),
        concat!("common::require_", "bin("),
    ];
    let private_lookup = concat!(".args([\"", "which\"");
    let resolver = common::at_root("crates/batten/tests/it/common/mod.rs");
    let mut required = BTreeSet::new();
    for path in common::rust_sources() {
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            path == resolver || !text.contains(private_lookup),
            "{}: resolves a pinned tool with its own `mise which`; call `common::require_tool`",
            path.display()
        );
        for (at, call) in calls
            .iter()
            .flat_map(|call| text.match_indices(call).map(move |(at, _)| (at, *call)))
        {
            let tool = text[at + call.len()..]
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            assert!(
                !tool.is_empty() && tool.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{}: a `{call}` call names no tool as a string literal",
                path.display()
            );
            required.insert(tool.to_owned());
        }
    }
    required
}

/// EVERY JOB THAT RUNS THE SUITE INSTALLS EVERY PINNED TOOL A CASE REQUIRES
/// (CLOUD-2381). `tool pin wrong` is blind to this twice over: it reads what
/// `batten.toml` rows spawn, never what a case spawns, and ANY install list in
/// ANY workflow satisfies it. So the dist tamper case passed locally while the
/// `ci` job, the `musl` leg and release-plz's musl cache warm all ran the suite
/// without cargo-dist, and with auto-install off each failed only in CI.
///
/// THE REQUIREMENT IS THE RESOLVING CALL (CLOUD-2388). A case reaches a pinned
/// tool through `common::require_tool` or `require_bin`, whose first argument
/// names the `[tools]` entry; the first version read a prose mark instead, and
/// `cache-warm-musl` ran the three pkl cases without pkl on every `main` push.
///
/// A case's `cfg!` gate is not read: a job on any OS that runs the suite
/// installs every required tool, which `mise.lock` pins for every platform. A
/// mise-action step with no `install_args` installs every `[tools]` entry.
#[test]
fn every_suite_job_installs_the_pinned_tools_its_cases_require() {
    use yaml_rust2::YamlLoader;
    let required = required_tools();
    for floor in ["cargo-dist", "pkl"] {
        assert!(
            required.contains(floor),
            "the {floor} requirement went unread: {required:?}"
        );
    }
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("mise.toml")).unwrap()).unwrap();
    let keys = manifest["tools"].as_table().expect("[tools]");
    let pinned: BTreeSet<String> = keys.keys().map(|key| tool_name(key)).collect();
    assert_eq!(
        pinned.len(),
        keys.len(),
        "two [tools] entries share a last segment, so one could satisfy the other"
    );
    let unpinned: Vec<&String> = required.difference(&pinned).collect();
    assert!(
        unpinned.is_empty(),
        "a case requires a tool mise.toml does not pin: {unpinned:?}"
    );

    let suite = suite_tasks(&manifest);
    let mut suite_jobs = Vec::new();
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(common::at_root(".github/workflows"))
        .unwrap()
        .flatten()
    {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|ext| ext == "yml" || ext == "yaml")
        {
            continue;
        }
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let Some(jobs) = docs.first().and_then(|doc| doc["jobs"].as_hash()) else {
            continue;
        };
        for (name, job) in jobs {
            let name = name.as_str().unwrap_or_default();
            let steps = job["steps"].as_vec().map_or(&[][..], Vec::as_slice);
            if !steps.iter().any(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| runs_suite(run, &suite))
            }) {
                continue;
            }
            suite_jobs.push(format!("{file}:{name}"));
            let installs_all = steps.iter().any(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("jdx/mise-action@"))
                    && step["with"]["install_args"].is_badvalue()
                    && step["with"]["install"].as_bool() != Some(false)
            });
            if installs_all {
                continue;
            }
            let installed: BTreeSet<String> = steps
                .iter()
                .filter_map(|step| step["with"]["install_args"].as_str())
                .flat_map(str::split_whitespace)
                .map(tool_name)
                .collect();
            missing.extend(
                required
                    .difference(&installed)
                    .map(|tool| format!("{file}:{name} {tool}")),
            );
        }
    }
    for expected in [
        "ci.yml:ci",
        "rust.yml:musl",
        "coverage.yml:coverage",
        "release-plz.yml:cache-warm-musl",
    ] {
        assert!(
            suite_jobs.iter().any(|job| job == expected),
            "{expected} runs the suite but was not found: {suite_jobs:?}"
        );
    }
    assert!(
        missing.is_empty(),
        "a suite-running job omits a pinned tool a case requires: {missing:?}"
    );
}

/// The suite predicate counts what runs the suite, through any wrapper task,
/// and nothing that only looks like it.
#[test]
fn a_suite_step_is_a_suite_task_or_a_suite_command() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("mise.toml")).unwrap()).unwrap();
    let suite = suite_tasks(&manifest);
    for task in [
        "ci",
        "test:cargo",
        "test:musl",
        "coverage",
        "hooks",
        "mutant",
    ] {
        assert!(suite.contains(task), "{task} runs the suite: {suite:?}");
    }
    // hk's own test step is what makes `hk check --all` a suite run.
    let hk = std::fs::read_to_string(common::at_root("hk.pkl")).unwrap();
    assert!(hk.contains(r#"check = "mise run test:cargo""#));
    for run in [
        "mise run ci",
        "mise run -q ci",
        "mise run test:musl",
        "mise run test:cargo --",
        "mise run batten -- ci step --summary x -- mise run coverage",
        "mise exec -- cargo nextest run --workspace",
        "mise exec -- cargo test --workspace",
        "mise exec -- cargo nextest run -p batten --no-fail-fast",
        "mise run -j 4 ci",
        "mise run batten -- ci step --summary \"Suite, see #2388\" -- mise run ci",
    ] {
        assert!(runs_suite(run, &suite), "{run}");
    }
    for run in [
        "mise run ci:quick",
        "mise run ci-drift",
        "mise run batten -- ci step -- mise run ci-slow-needed --",
        "mise exec -- cargo nextest run --no-run --workspace",
        "mise exec -- cargo nextest run -p batten --test it hook_profile::",
        "# then mise run ci",
        "mise run tree-clean # runs after mise run ci",
        "cargo nextest run -p batten --test it hook_profile:: && cargo clippy --workspace",
        "mise exec -- cargo llvm-cov report --summary-only",
    ] {
        assert!(!runs_suite(run, &suite), "{run}");
    }
}
