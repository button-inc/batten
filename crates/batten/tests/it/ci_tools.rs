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

/// What a `run` text does toward the suite (CLOUD-2381, CLOUD-2388): whether a
/// command in it runs the suite itself, and every mise task it runs. Commands
/// come from the hooks' own bash parse, so quotes, escapes, comments and `&&`,
/// `||`, `;`, `|` are bash's, and a `bash -c`/`sh -c` script is parsed in turn.
///
/// The direction is deliberate: a command is held as the suite whenever it
/// might be one, because an over-required install is visible in the job's list
/// where an under-required one is what CI discovers. So: any test-runner run,
/// filtered or not (`cargo [flags] test|t|nextest run|llvm-cov` other than
/// `llvm-cov report`, not `--no-run`); `hk check|run` outside the `!slow`
/// profile (hk's `test` step is `mise run test:cargo`); `mutate sweep`; whatever
/// a script in the tree runs; and text the parse cannot read. A template is read
/// once per branch it can render (CLOUD-2450), so one branch's flags never
/// reach another's command.
fn suite_facts(run: &str) -> (bool, Vec<String>) {
    let Some(texts) = renderings(run) else {
        return (true, Vec::new());
    };
    let mut direct = false;
    let mut tasks = Vec::new();
    for text in texts {
        // A text that is only comments parses to nothing, which is not
        // unreadable; any other text is parsed as written.
        if text
            .lines()
            .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        {
            continue;
        }
        let Some(commands) = batten::testing::shell_commands(&text) else {
            return (true, Vec::new());
        };
        for (words, stdin) in commands {
            let (inner, more) = command_facts(&words, &stdin);
            direct |= inner;
            tasks.extend(more);
        }
    }
    (direct, tasks)
}

/// A word that stands for a value only a renderer knows: a GitHub `${{ … }}`
/// or a mise `{{ … }}` expression. A task named by one is held as a suite task.
const UNRENDERED: &str = "__unrendered__";

/// The most texts one `run` may render to before it is held as the suite
/// unread (CLOUD-2450).
const RENDERINGS: usize = 16;

/// One piece of a template: text, or a Tera `{% … %}` tag by its keyword.
enum Piece {
    Text(String),
    Tag(String),
}

/// `run` cut into text and Tera tags. In text, `{{vars.X}}` is `X`
/// (`{{vars.batten}}` is the batten program) and any other `{{ … }}` or
/// `${{ … }}` is [`UNRENDERED`].
fn pieces(run: &str) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut rest = run;
    while let Some(open) = rest.find(['{', '$']) {
        let (head, tail) = rest.split_at(open);
        text.push_str(head);
        if let Some(body) = tail.strip_prefix("{%")
            && let Some(end) = body.find("%}")
        {
            let keyword = body[..end]
                .trim_matches(|c: char| c == '-' || c.is_whitespace())
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            pieces.push(Piece::Text(std::mem::take(&mut text)));
            pieces.push(Piece::Tag(keyword));
            rest = &body[end + 2..];
        } else if let Some(body) = tail.strip_prefix("${{").or_else(|| tail.strip_prefix("{{"))
            && let Some(end) = body.find("}}")
        {
            let inner = body[..end].trim();
            text.push_str(
                &inner
                    .strip_prefix("vars.")
                    .filter(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    .map_or_else(|| UNRENDERED.to_owned(), str::to_owned),
            );
            rest = &body[end + 2..];
        } else {
            text.push_str(&tail[..1]);
            rest = &tail[1..];
        }
    }
    text.push_str(rest);
    pieces.push(Piece::Text(text));
    pieces
}

/// Every text `run` can render to (CLOUD-2450): an `{% if %}` group renders
/// each of its `if`, `elif` and `else` branches, or the empty text when it has
/// no `else`; successive and nested groups multiply; a `{% for %}` body is read
/// once; any other tag is a space. `None` past [`RENDERINGS`] texts, or where a
/// closing tag has no group to close.
//MUTANT template-branches-joined|s@^    sequence(&pieces, &mut at).filter(@    sequence(\&pieces, \&mut at).map(\x7ctexts\x7c vec![texts.join(" ::: ")]).filter(@|a_suite_step_is_a_suite_task_or_a_suite_command
fn renderings(run: &str) -> Option<Vec<String>> {
    let pieces = pieces(run);
    let mut at = 0;
    sequence(&pieces, &mut at).filter(|_| at == pieces.len())
}

/// The texts `pieces[*at..]` renders to, up to a tag that closes or divides
/// the enclosing group, which is left for the caller.
fn sequence(pieces: &[Piece], at: &mut usize) -> Option<Vec<String>> {
    let mut texts = vec![String::new()];
    while let Some(piece) = pieces.get(*at) {
        let branches = match piece {
            Piece::Text(text) => {
                *at += 1;
                vec![text.clone()]
            }
            Piece::Tag(tag) => match tag.as_str() {
                "elif" | "else" | "endif" | "endfor" => break,
                "if" => {
                    *at += 1;
                    let mut branches = sequence(pieces, at)?;
                    let mut has_else = false;
                    while let Some(Piece::Tag(tag)) = pieces.get(*at) {
                        match tag.as_str() {
                            "elif" | "else" => {
                                has_else |= tag == "else";
                                *at += 1;
                                branches.extend(sequence(pieces, at)?);
                            }
                            "endif" => {
                                *at += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                    if !has_else {
                        branches.push(String::new());
                    }
                    branches
                }
                "for" => {
                    *at += 1;
                    let body = sequence(pieces, at)?;
                    if matches!(pieces.get(*at), Some(Piece::Tag(tag)) if tag == "endfor") {
                        *at += 1;
                    }
                    body
                }
                _ => {
                    *at += 1;
                    vec![" ".to_owned()]
                }
            },
        };
        if texts.len() * branches.len() > RENDERINGS {
            return None;
        }
        texts = texts
            .iter()
            .flat_map(|head| branches.iter().map(move |tail| format!("{head}{tail}")))
            .collect();
    }
    Some(texts)
}

/// The words of `words` from index `from` on that are operands, each with its
/// index: not a flag, not a value-taking flag's value, not a redirection.
fn operand_at<'a>(
    words: &'a [String],
    from: usize,
    valued: &'a [&'a str],
) -> impl Iterator<Item = (usize, &'a str)> {
    let mut operand = is_operand(valued);
    words
        .iter()
        .enumerate()
        .skip(from)
        .map(|(index, word)| (index, word.as_str()))
        .filter(move |(_, word)| operand(word))
}

/// The tasks `mise run` names after `words[at]`: the first word that is not a
/// flag, and the first after each `:::`. The rest are those tasks' arguments.
fn tasks_after(words: &[String], at: usize) -> Vec<String> {
    let end = own_end(words, at);
    let mut tasks = Vec::new();
    let mut expecting = true;
    for (index, word) in operand_at(words, at + 1, MISE_VALUED) {
        if index >= end {
            break;
        }
        if word == ":::" {
            expecting = true;
        } else if std::mem::take(&mut expecting) {
            tasks.push(word.to_owned());
        }
    }
    tasks
}

/// Where the program at `words[at]` stops owning words: its first `--` after
/// it, or the end of the command. A flag past it is another program's.
fn own_end(words: &[String], at: usize) -> usize {
    words[at + 1..]
        .iter()
        .position(|word| word == "--")
        .map_or(words.len(), |offset| at + 1 + offset)
}

/// Whether batten, given `args`, runs cases, and the mise tasks it runs:
/// `mutate sweep` runs the suites its rows name, `test replay` every modified
/// case through nextest, `land lap` runs `verify`, and `enforce` runs
/// `batten.toml`'s `[[rule]] check` commands (only the `--rule` named).
/// `check` is the read-effect verb and refuses a command rule (`hk.pkl`), so it
/// runs no case (CLOUD-2450).
fn batten_facts(args: &[String]) -> (bool, Vec<String>) {
    let mut next = operand_at(args, 0, BATTEN_VALUED).map(|(_, word)| word);
    match (next.next(), next.next()) {
        (Some("mutate"), Some("sweep"))
        | (Some("test"), Some("replay"))
        | (Some("land"), Some("lap")) => (true, Vec::new()),
        (Some("enforce"), _) => {
            // `--rule` repeats, and is spelled `--rule X` or `--rule=X`.
            let only: Vec<&str> = args
                .iter()
                .enumerate()
                .filter_map(|(at, word)| {
                    word.strip_prefix("--rule=").or_else(|| {
                        (word == "--rule")
                            .then(|| args.get(at + 1).map(String::as_str))
                            .flatten()
                    })
                })
                .collect();
            rule_checks()
                .iter()
                .filter(|(id, _)| only.is_empty() || only.contains(&id.as_str()))
                .fold((false, Vec::new()), |(direct, mut tasks), (_, facts)| {
                    tasks.extend(facts.1.iter().cloned());
                    (direct || facts.0, tasks)
                })
        }
        _ => (false, Vec::new()),
    }
}

/// A text's facts toward the suite: whether it runs it, and the tasks it runs.
type Facts = (bool, Vec<String>);

/// Each `[[rule]]`'s id and the facts of its `check` command, read once.
fn rule_checks() -> &'static [(String, Facts)] {
    static CHECKS: std::sync::OnceLock<Vec<(String, Facts)>> = std::sync::OnceLock::new();
    thread_local! {
        static READING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    // A check that itself runs `batten enforce` re-enters here while the read
    // is under way; it is that same read, so it adds nothing.
    if CHECKS.get().is_none() && READING.with(std::cell::Cell::get) {
        return &[];
    }
    READING.with(|reading| reading.set(true));
    CHECKS.get_or_init(|| {
        let config: toml::Value =
            toml::from_str(&std::fs::read_to_string(common::at_root("batten.toml")).unwrap())
                .unwrap();
        config
            .get("rule")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|rule| {
                let check = match rule.get("check")? {
                    toml::Value::String(line) => line.clone(),
                    // An argv array is the same command, word for word.
                    toml::Value::Array(argv) => argv
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => return None,
                };
                let id = rule
                    .get("id")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default();
                Some((id.to_owned(), suite_facts(&check)))
            })
            .collect()
    })
}

/// The one rule for what is an operand: not a flag (`-x`, `+toolchain`), not a
/// value-taking flag's value, not a redirection (`<<'EOF'`, `>log`).
fn is_operand<'a>(valued: &'a [&'a str]) -> impl FnMut(&str) -> bool + 'a {
    let mut skip_next = false;
    move |word| {
        if std::mem::take(&mut skip_next) {
            return false;
        }
        if word.starts_with('-') || word.starts_with('+') {
            skip_next = valued.contains(&word);
            return false;
        }
        !word.starts_with(['<', '>'])
    }
}

/// mise's own subcommands, which `mise <word>` runs instead of a task.
const MISE_COMMANDS: &[&str] = &[
    "activate",
    "alias",
    "bin-paths",
    "cache",
    "completion",
    "config",
    "deactivate",
    "doctor",
    "en",
    "env",
    "exec",
    "x",
    "fmt",
    "generate",
    "implode",
    "install",
    "i",
    "install-into",
    "latest",
    "link",
    "lock",
    "ls",
    "ls-remote",
    "outdated",
    "plugins",
    "prune",
    "registry",
    "reshim",
    "search",
    "self-update",
    "set",
    "settings",
    "shell",
    "sync",
    "test-tool",
    "tool",
    "trust",
    "uninstall",
    "unset",
    "unuse",
    "upgrade",
    "up",
    "usage",
    "use",
    "u",
    "version",
    "where",
    // Split, so the census does not read a `mise which` here.
    concat!("whi", "ch"),
];

/// Flags that take the next word as their value, before the subcommand.
const MISE_VALUED: &[&str] = &[
    "-C",
    "--cd",
    "-E",
    "--env",
    "-j",
    "--jobs",
    "-o",
    "--output",
    "-t",
    "--tool",
    "--timeout",
];
const CARGO_VALUED: &[&str] = &["-C", "--config", "--manifest-path", "-Z", "--color"];
const BATTEN_VALUED: &[&str] = &["--config-from", "--config-in", "--strictness", "--rule"];
const SHELL_VALUED: &[&str] = &["-o", "-O", "+o", "+O", "--rcfile", "--init-file"];

/// One command's facts: whether it runs the suite, and the mise tasks it runs.
/// Every word is tried as a program, so a suite run that is another program's
/// operand (`ci step -- mise run coverage`) is read too: over-reading only
/// over-requires.
//MUTANT no-run-whole-command|s@^                let scope = own;$@                let scope = words;@|a_suite_step_is_a_suite_task_or_a_suite_command
//MUTANT suite-via-hk-unseen|s@^            "hk" => @            "hk-unread" => @|every_suite_job_installs_the_pinned_tools_its_cases_require
fn command_facts(words: &[String], stdin: &[String]) -> (bool, Vec<String>) {
    let mut direct = false;
    let mut tasks = Vec::new();
    let mut take = |(inner, more): (bool, Vec<String>)| {
        direct |= inner;
        tasks.extend(more);
    };
    for (at, word) in words.iter().enumerate() {
        let program = word.rsplit('/').next().unwrap_or(word);
        match program {
            "cargo" => {
                // Cargo's own words run to its own `--`; past it they are the
                // test binary's or the program's (CLOUD-2450).
                let end = own_end(words, at);
                let own = &words[at + 1..end];
                let mut next = operand_at(own, 0, CARGO_VALUED).map(|(_, word)| word);
                let runner = match next.next() {
                    Some("test" | "t") => true,
                    Some("nextest") => matches!(next.next(), Some("run" | "r")),
                    Some("llvm-cov") => next.next() != Some("report"),
                    _ => false,
                };
                let scope = own;
                take((runner && !scope.iter().any(|w| w == "--no-run"), Vec::new()));
                // `cargo run --package=batten -- <verb>` is batten itself.
                let names_batten = own
                    .iter()
                    .any(|w| matches!(w.as_str(), "--package=batten" | "--bin=batten"))
                    || own.windows(2).any(|w| {
                        matches!(w[0].as_str(), "-p" | "--package" | "--bin") && w[1] == "batten"
                    });
                if names_batten && end < words.len() {
                    take(batten_facts(&words[end + 1..]));
                }
            }
            "hk" => {
                // `!slow` counts only as its own profile's value (CLOUD-2450).
                let own = &words[at + 1..own_end(words, at)];
                let slow = own.iter().enumerate().any(|(index, word)| {
                    word.strip_prefix("--profile=")
                        .or_else(|| {
                            matches!(word.as_str(), "--profile" | "-P")
                                .then(|| own.get(index + 1).map(String::as_str))
                                .flatten()
                        })
                        .is_some_and(|profile| profile.contains("!slow"))
                });
                let mut next = operand_at(own, 0, &["--profile", "-P"]).map(|(_, word)| word);
                take((
                    matches!(next.next(), Some("check" | "run")) && !slow,
                    Vec::new(),
                ));
            }
            "batten" => take(batten_facts(&words[at + 1..])),
            "bash" | "sh" => {
                // `-c`, alone or in a cluster (`-ec`), takes the next word as
                // the script; with neither a script nor a file, stdin is it.
                // Only among the shell's own flags, a flag's value skipped with
                // it (`-o pipefail`): after its script operand, a `-c` is the
                // script's argument.
                let mut operand = is_operand(SHELL_VALUED);
                let mut inline = None;
                let mut file = None;
                for (index, word) in words.iter().enumerate().skip(at + 1) {
                    if operand(word) {
                        file = Some(word);
                        break;
                    }
                    if word.starts_with('-') && !word.starts_with("--") && word.contains('c') {
                        inline = words.get(index + 1);
                        break;
                    }
                }
                if let Some(script) = inline {
                    take(suite_facts(script));
                } else if let Some(file) = file {
                    take(script_facts(file));
                } else {
                    for text in stdin {
                        take(suite_facts(text));
                    }
                }
            }
            // A shell's own script operand was read by its arm above.
            _ if Path::new(word)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"))
                && !(at > 0 && matches!(words[at - 1].rsplit('/').next(), Some("bash" | "sh"))) =>
            {
                take(script_facts(word));
            }
            "mise" => {
                let mut next = operand_at(words, at + 1, MISE_VALUED);
                let named: Vec<String> = match next.next() {
                    // `mise watch <task>` runs it on every change.
                    Some((sub, "run" | "r" | "watch" | "w")) => tasks_after(words, sub),
                    Some((_, "tasks")) => match next.next() {
                        Some((sub, "run" | "r")) => tasks_after(words, sub),
                        _ => Vec::new(),
                    },
                    // One of mise's own subcommands names no task.
                    Some((_, sub)) if MISE_COMMANDS.contains(&sub) => Vec::new(),
                    // `mise <task>` is mise's own shorthand for `mise run <task>`.
                    Some((_, task)) => vec![task.to_owned()],
                    None => Vec::new(),
                };
                take((named.iter().any(|task| task == UNRENDERED), named));
            }
            _ => {}
        }
    }
    (direct, tasks)
}

/// A script file's facts: its text read like a `run:` body when git tracks it
/// (`install.sh`). One git does not track is a build's output (`sh
/// target/distrib/batten-installer.sh`), which runs no case, whatever an
/// earlier local build left at that path.
fn script_facts(path: &str) -> (bool, Vec<String>) {
    static TRACKED: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    thread_local! {
        static READING: std::cell::RefCell<BTreeSet<String>> = const {
            std::cell::RefCell::new(BTreeSet::new())
        };
    }
    let relative = path.trim_start_matches("./");
    let root = common::at_root(".");
    let tracked = TRACKED.get_or_init(|| {
        common::git_in(&root, &["ls-files"])
            .lines()
            .map(str::to_owned)
            .collect()
    });
    // Untracked, outside the tree, a glob, or already being read (a script
    // that runs itself): nothing this census can read further.
    if !tracked.contains(relative)
        || !READING.with(|reading| reading.borrow_mut().insert(relative.to_owned()))
    {
        return (false, Vec::new());
    }
    let facts = std::fs::read_to_string(root.join(relative))
        .map_or_else(|_| (false, Vec::new()), |text| suite_facts(&text));
    READING.with(|reading| reading.borrow_mut().remove(relative));
    facts
}

/// Whether a `run` text runs the suite, given the mise tasks known to.
fn runs_suite(run: &str, suite: &BTreeSet<String>) -> bool {
    let (direct, tasks) = suite_facts(run);
    direct || tasks.iter().any(|task| suite.contains(task))
}

/// The mise tasks a `depends`, `depends_post` or `wait_for` entry or a `run`
/// table entry names, `*` globs expanded against `tasks`.
fn task_refs(value: Option<&toml::Value>, tasks: &[&String]) -> Vec<String> {
    let entries: Vec<&toml::Value> = match value {
        Some(toml::Value::Array(items)) => items.iter().collect(),
        Some(other) => vec![other],
        None => Vec::new(),
    };
    let mut refs = Vec::new();
    for entry in entries {
        let references: Vec<&str> = match entry {
            toml::Value::String(text) => text.split_whitespace().next().into_iter().collect(),
            // `{ task = "x" }`, or the parallel `{ tasks = ["x", "y"] }`.
            toml::Value::Table(table) => table
                .get("task")
                .into_iter()
                .chain(
                    table
                        .get("tasks")
                        .and_then(toml::Value::as_array)
                        .into_iter()
                        .flatten(),
                )
                .filter_map(toml::Value::as_str)
                .collect(),
            _ => Vec::new(),
        };
        for reference in references {
            match reference.split_once('*') {
                Some((head, tail)) => refs.extend(
                    tasks
                        .iter()
                        .filter(|name| name.starts_with(head) && name.ends_with(tail))
                        .map(|name| (*name).clone()),
                ),
                None => refs.push(reference.to_owned()),
            }
        }
    }
    refs
}

/// Whether mise would run `path` as a file task: executable, on unix. Windows
/// keeps no execute bit, and the census runs on every leg, Linux among them.
#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(_: &Path) -> bool {
    false
}

/// The mise tasks that run the suite: closed over `mise run`, `depends`,
/// `depends_post`, `wait_for` and `run = { task = … }`, so a wrapper task is
/// found from what it runs, never from a list of names. Each body is parsed
/// once; the closure runs over the graph that leaves. A file task would be a
/// body this reads none of, so one is refused.
fn suite_tasks(manifest: &toml::Value) -> BTreeSet<String> {
    let mut pending: Vec<PathBuf> = [
        "mise-tasks",
        ".mise-tasks",
        ".mise/tasks",
        "mise/tasks",
        ".config/mise/tasks",
    ]
    .map(common::at_root)
    .into();
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    !executable(&path),
                    "{}: a file task, whose body the suite census does not read",
                    path.display()
                );
            }
        }
    }
    let tasks = manifest["tasks"].as_table().expect("[tasks]");
    let names: Vec<&String> = tasks.keys().collect();
    let mut suite = BTreeSet::new();
    let mut edges: Vec<(&String, Vec<String>)> = Vec::new();
    for (name, task) in tasks {
        let body = match task.get("run") {
            Some(toml::Value::String(line)) => line.clone(),
            Some(toml::Value::Array(lines)) => lines
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        };
        let (direct, mut targets) = suite_facts(&body);
        for key in ["depends", "depends_post", "wait_for"] {
            targets.extend(task_refs(task.get(key), &names));
        }
        match task.get("run") {
            Some(toml::Value::Array(entries)) => targets.extend(task_refs(
                Some(&toml::Value::Array(
                    entries.iter().filter(|e| e.is_table()).cloned().collect(),
                )),
                &names,
            )),
            Some(table @ toml::Value::Table(_)) => targets.extend(task_refs(Some(table), &names)),
            _ => {}
        }
        if direct {
            suite.insert(name.clone());
        }
        edges.push((name, targets));
    }
    loop {
        let before = suite.len();
        for (name, targets) in &edges {
            if targets.iter().any(|target| suite.contains(target)) {
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

/// Every tool a `require_tool` or `require_bin` call names across the crate's
/// sources, read by `syn` whatever path reaches the call (CLOUD-2388): the
/// call's first argument, a string literal naming the `[tools]` entry's last
/// segment. Outside the resolver itself, a call whose first argument is not a
/// literal, or a `"which"` literal (a `mise which` of a case's own), is refused:
/// either is a requirement this census cannot read.
//MUTANT require-call-unread|s@^        required.extend(found.tools);$@@|every_suite_job_installs_the_pinned_tools_its_cases_require
fn required_tools() -> (BTreeSet<String>, Vec<(String, PathBuf)>) {
    let mut required = BTreeSet::new();
    let mut spawned = Vec::new();
    for path in common::rust_sources() {
        let source = std::fs::read_to_string(&path).unwrap();
        let found = batten::testing::require_census(
            &syn::parse_file(&source).expect("every crate source parses"),
        );
        assert!(
            found.unnamed == 0,
            "{}: a require_tool/require_bin call names no tool as a string literal",
            path.display()
        );
        assert!(
            found.which_literals == 0,
            "{}: resolves a pinned tool with its own `mise which`; call `common::require_tool`",
            path.display()
        );
        for tool in &found.tools {
            assert!(
                !tool.is_empty() && tool.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{}: `{tool}` is not a [tools] name",
                path.display()
            );
        }
        required.extend(found.tools);
        spawned.extend(
            found
                .spawned
                .into_iter()
                .map(|program| (program, path.clone())),
        );
    }
    (required, spawned)
}

/// The required tools a job's steps do not install. A mise-action step with no
/// `install_args` installs every `[tools]` entry, unless it says `install: false`.
//MUTANT install-all-unread|s@^                && step\["with"\]\["install"\]\.as_bool() != Some(false)$@                \&\& true@|a_job_installs_what_its_mise_steps_say
fn job_missing(steps: &[yaml_rust2::Yaml], required: &BTreeSet<String>) -> Vec<String> {
    let installing: Vec<&yaml_rust2::Yaml> = steps
        .iter()
        .filter(|step| {
            step["uses"]
                .as_str()
                .and_then(|action| action.split('@').next())
                .is_some_and(|action| action.ends_with("/mise-action"))
                && step["with"]["install"].as_bool() != Some(false)
        })
        .collect();
    if installing
        .iter()
        .any(|step| step["with"]["install_args"].is_badvalue())
    {
        return Vec::new();
    }
    let installed: BTreeSet<String> = installing
        .iter()
        .filter_map(|step| step["with"]["install_args"].as_str())
        .flat_map(str::split_whitespace)
        .map(tool_name)
        .collect();
    required.difference(&installed).cloned().collect()
}

/// A narrowed list installs what it names, an unnarrowed mise-action step
/// everything, and `install: false` nothing (CLOUD-2388).
#[test]
fn a_job_installs_what_its_mise_steps_say() {
    let required: BTreeSet<String> = ["cargo-dist", "pkl"].map(str::to_owned).into();
    let steps = |with: &str| {
        let text = format!("- uses: jdx/mise-action@abc\n  with:\n{with}\n- run: mise run ci\n");
        yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0]
            .as_vec()
            .unwrap()
            .clone()
    };
    assert_eq!(
        job_missing(&steps("    version: 1"), &required),
        Vec::<String>::new()
    );
    assert_eq!(
        job_missing(&steps("    install: false"), &required),
        ["cargo-dist", "pkl"]
    );
    assert_eq!(
        job_missing(
            &steps("    install: false\n    install_args: rust pkl aqua:axodotdev/cargo-dist"),
            &required
        ),
        ["cargo-dist", "pkl"]
    );
    assert_eq!(
        job_missing(
            &steps("    install_args: rust aqua:axodotdev/cargo-dist@0.33.0"),
            &required
        ),
        ["pkl"]
    );
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
    let (required, spawned) = required_tools();
    for floor in ["cargo-dist", "pkl", "node", "jq"] {
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
    // A pinned tool spawned by name is reached around the resolver: whatever
    // `PATH` holds answers, and no job is held to installing it.
    // The program each pinned tool provides, where it is not the tool's name:
    // `aqua:mvdan/sh` is shfmt, never the shell; `rust` is every job's first
    // install, so a bare `cargo` reaches the pin wherever the suite runs.
    let programs: BTreeSet<&str> = pinned
        .iter()
        .flat_map(|tool| match tool.as_str() {
            "sh" => vec!["shfmt"],
            "cargo-dist" => vec!["dist"],
            "cli" => vec!["gh"],
            "nextest" => vec!["cargo-nextest"],
            "node" => vec!["node", "npm", "npx"],
            "serena-agent" => vec!["serena"],
            "rust" => Vec::new(),
            other => vec![other],
        })
        .collect();
    let around: Vec<String> = spawned
        .iter()
        .filter(|(program, _)| programs.contains(program.as_str()))
        .map(|(program, path)| format!("{}: Command::new(\"{program}\")", path.display()))
        .collect();
    assert!(
        around.is_empty(),
        "a case spawns a pinned tool by name; resolve it with common::require_tool: {around:?}"
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
            missing.extend(
                job_missing(steps, &required)
                    .into_iter()
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
        "verify:test-replay",
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
        // A filtered run is held as the suite: its filter can reach a case
        // that requires a tool.
        "mise exec -- cargo nextest run -p batten --test it hook_profile::",
        "mise exec -- cargo test --workspace -- --skip flaky::case",
        "mise -E ci exec -- cargo nextest run --workspace",
        "mise exec -- cargo +stable test --workspace",
        "cargo --locked t",
        "cargo -q nextest run",
        "mise r ci",
        "mise -q run ci",
        "~/.local/bin/mise run ci",
        "mise ci",
        "mise tasks run ci",
        "mise exec -- hk check -a",
        "hk run pre-push",
        "mise exec -- bash -c \"cargo nextest run --workspace\"",
        "bash -ec \"cargo nextest run --workspace\"",
        "bash <<'EOF'\ncargo nextest run --workspace\nEOF",
        "mise -C crates run ci",
        "cargo --manifest-path Cargo.toml test",
        "cargo --config net.retry=5 nextest run",
        "{% if usage.f %}cargo fuzz run x{% else %}mise run test:cargo{% endif %}",
        "{{vars.batten}} mutate sweep",
        "mise run ${{ matrix.task }}",
        "cargo run --quiet --package=batten -- mutate sweep",
        "{{vars.batten}} test replay --base origin/main",
        "mise run -j 4 ci ::: lint",
        "batten --config-from origin/main mutate sweep",
        "mise run {% if env.X %}lint{% else %}ci{% endif %}",
        // `enforce` runs the rules' checks, among them a filtered nextest run.
        "mise run batten -- enforce",
        "mise run --output prefix ci",
        "mise watch ci",
        // Each template branch is its own command; one branch's flag never
        // reaches another's runner (CLOUD-2450).
        "{% if b %}cargo nextest run --workspace{% else %}cargo nextest run --no-run{% endif %}",
        "{% if b %}cargo nextest run --no-run{% else %}cargo nextest run --workspace{% endif %}",
        "hk check {% if x %}--profile '!slow'{% endif %} --all",
        // A flag counts only among its own program's words.
        "ci step --summary \"hooks (!slow skipped)\" -- hk check --all",
        "ci step --summary --no-run -- cargo nextest run --workspace",
        "cargo run --package=batten -- step run x -- cargo run --package=batten -- mutate sweep",
        "bash -o pipefail -c \"cargo nextest run --workspace\"",
        // A closing tag with no group to close is unreadable.
        "{% endif %}mise run lint",
    ] {
        assert!(runs_suite(run, &suite), "{run}");
    }
    for run in [
        "mise run ci:quick",
        "mise run ci-drift",
        "mise run batten -- ci step -- mise run ci-slow-needed --",
        "mise exec -- cargo nextest run --no-run --workspace",
        "# then mise run ci",
        "mise run tree-clean # runs after mise run ci",
        "mise run tree-clean;# mise run ci",
        "echo it\\'s # then mise run ci",
        "mise run batten -- ci step --summary \"x; cargo test\" -- mise run lint",
        "batten --config-in /tmp/c lease guard",
        "bash /tmp/setup.sh",
        "sh \"$HOME/x.sh\"",
        "mise exec -- pkl --version",
        "mise exec -- cargo llvm-cov report --summary-only",
        "./install.sh",
        "sh target/distrib/batten-installer.sh",
        // `check` refuses a command rule, so it runs no rule's check.
        "batten check --rule 'config retire unnamed'",
        "hk check --profile '!slow' --all",
        "hk check -P=x -P '!slow'",
    ] {
        assert!(!runs_suite(run, &suite), "{run}");
    }
}
