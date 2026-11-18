//! The task runner's own argv, read back from a receipt minted outside the
//! mediated call (CLOUD-856).
//!
//! # The predicate that had nowhere to go
//!
//! `cargo-substitutes-for-a-task` asks one question — *is this argv a weaker form
//! of a task's own* — and derives it from the manifest's task bodies, never from a
//! restated list. `hook::call_document` projects [`crate::facts::Fact::Document`]
//! as `None`, and rightly: a document is unbounded where a git ref read is not,
//! and parsing one on every mediated call would spend the whole invocation
//! budget. So that family stayed in bash while the rest of its guard moved.
//!
//! # Shape (c): a receipt, not a read
//!
//! The bounded data is acquired OUTSIDE `PreToolUse` — at session start, where an
//! effect is admissible — and persisted as a record keyed to the manifest as it
//! stands. The mediated call then reads one small file and validates its key. It
//! never parses the manifest, never invokes the runner, never probes a binary and
//! never walks the tree.
//!
//! **This is [`crate::pinned`]'s mechanism, and it files under the same key
//! deliberately.** Both are memoised readings of the same toolchain manifest, so
//! two key derivations would be two answers to *has the manifest moved* that can
//! disagree — and the one that says "no" wins by being read first. `pinned::key`
//! is that one derivation; this module owns only what it records.
//!
//! # Staleness is structural rather than trusted
//!
//! The key is recomputed at read time from the RECORDED config paths, so a record
//! taken over a manifest that has since changed does not answer — it is not a
//! stale answer to be trusted a little, it is an answer about a different
//! toolchain. Same for a record from a different schema version, and for one past
//! the size cap.
//!
//! Every one of those is [`crate::facts::Look::CouldNotLook`], never an empty
//! task set. *"The manifest defines no tasks"* and *"I could not read the
//! manifest"* are different claims, and a guard that confused them would permit
//! every substitution it exists to refuse.
//!
//! # What this deliberately does NOT record
//!
//! **Provider-resolved executable aliases**, which CLOUD-856's bundle extension
//! lists. Resolving which executable a tool key puts on `PATH` means asking the
//! provider, which is [`crate::facts::Cost::Effect`] — and [`crate::pinned`]
//! already asks it and already records the answer under this same store. A second
//! recorder for that would be a second authority over one question, which is the
//! defect this module's own key-sharing exists to avoid. A consumer wanting both
//! reads `input.facts["pinned-programs"]` beside `input.facts.tasks`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::facts::{Look, Node, TaskQuery};

/// The record's name inside [`crate::pinned::STORE`].
const RECORD: &str = "task-argv";

/// The record shape this build writes and reads.
///
/// Bumped when the recorded shape changes. A record from another version does not
/// answer — could-not-look rather than a best-effort read, because a field this
/// build interprets differently is worse than a field it does not have.
///
/// NOT BUMPED FOR AN ADDED FIELD (step 17): every task's BODY rides beside its
/// argv as an optional field, and a record written before it — which has
/// none — answers task existence as before while its bodies are
/// could-not-look, never "no task runs anything". A bump would have refused
/// the whole record to every reader, the released engine's included.
const SCHEMA: u32 = 1;

/// The largest record this will read.
///
/// A bound rather than a guideline: the mediated call's whole budget is ~100ms,
/// and a record that grew without limit would spend it. A record past the cap is
/// could-not-look, never a truncated read — half a task table is a task table
/// that answers wrongly.
const RECORD_MAX: u64 = 256 * 1024;

/// What a task's body resolves to, per name.
///
/// `None` is a task that EXISTS and is not a single command — a pipeline, a
/// sequence, a multi-line body. Distinct from the name being absent, which is a
/// task the manifest does not define, and a consumer must not read the first as
/// the second: a guard asking *is this a weaker form of a task* has nothing to
/// compare against for the first and a real negative for the second.
pub type TaskFacts = Look<BTreeMap<String, Option<Vec<String>>>>;

/// What every task's body RUNS, per name: each command line its `run` carries
/// (a scalar is one line, an array is one line per element) and a `mise run
/// <task>` line per task it depends on or names as a `{ task = … }` step.
///
/// Distinct from [`TaskFacts`] on purpose. That table answers *is this argv a
/// weaker form of a task's own*, which only a single command can answer, so a
/// sequence is `None` there. This one answers *which programs does running the
/// task reach*, which a sequence answers line by line — the reading
/// `hook::task_programs` walks to classify a `mise run` by what it runs rather
/// than by its name.
pub type TaskBodies = Look<BTreeMap<String, Vec<String>>>;

/// The record, as one writer writes it and one reader reads it.
///
/// A struct rather than a hand-rolled format for [`crate::pinned`]'s recorded
/// reason (CLOUD-1093): a fixture that spells the bytes itself passes while the
/// real writer and the real reader disagree.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    /// The shape version this record was written at.
    schema: u32,
    /// Which build wrote it, so a reader diagnosing a mismatch has the producer.
    generator: String,
    /// The digest of the manifest set at the moment the tasks were read.
    key: String,
    /// The files that decide the key, so the reader can recompute it without
    /// parsing anything.
    configs: Vec<PathBuf>,
    /// The answer.
    tasks: BTreeMap<String, Option<Vec<String>>>,
    /// Every task's body lines ([`TaskBodies`]); absent from a record written
    /// before step 14, whose bodies are then could-not-look.
    #[serde(default)]
    bodies: Option<BTreeMap<String, Vec<String>>>,
    /// The keyed files' stat identity when `key` was derived
    /// ([`crate::pinned::stamped`]); absent from a record written before
    /// CLOUD-2440, which is then believed only by its key.
    #[serde(default)]
    stamps: crate::pinned::Stamps,
}

/// Where the record lives for `root`'s checkout.
fn record_path(root: &Path) -> Option<PathBuf> {
    crate::git::git_dir(root)
        .ok()
        .map(|dir| dir.join(crate::pinned::STORE).join(RECORD))
}

/// The recorded task set, or could-not-look. **Reads one file and nothing else.**
///
/// This is the reading the mediated path takes, and every refusal in it is the
/// same refusal: a record that is not about the manifest as it stands now is not
/// evidence about this call.
///
/// **It DIGESTS the declared manifest and never parses it**, and that distinction
/// took a correction to state honestly: the key is recomputed here, so the
/// manifest's bytes are read — what does not happen is a parse, a runner
/// invocation, a binary probe or a tree walk. Where the record carries stamps
/// that still match (CLOUD-2440, unix), even the read is replaced by a `stat`
/// of each keyed file and a listing of their directories.
/// `crates/batten/tests/it/task_receipt.rs`'s
/// `the_mediated_call_digests_the_manifest_and_never_parses_it` is what
/// discriminates the two: it records over a manifest that is not valid TOML, so a
/// read that parsed would answer could-not-look and a read that digests answers.
#[must_use]
pub fn cached(root: &Path) -> TaskFacts {
    read(root).map_or(Look::CouldNotLook, |record| Look::Is(record.tasks))
}

/// The recorded task bodies, or could-not-look — the same one-file read as
/// [`cached`], under the same refusals.
#[must_use]
pub fn cached_bodies(root: &Path) -> TaskBodies {
    read(root).map_or(Look::CouldNotLook, |record| answers(record).1)
}

/// [`cached`] and [`cached_bodies`] from one read of the record.
#[must_use]
pub fn cached_with_bodies(root: &Path) -> (TaskFacts, TaskBodies) {
    read(root).map_or((Look::CouldNotLook, Look::CouldNotLook), answers)
}

/// What a record that stands answers: its tasks, and its bodies where it
/// carries them — could-not-look where it does not, which leaves
/// `input.call["task-programs"]` null and every guard reading it closed.
fn answers(record: Record) -> (TaskFacts, TaskBodies) {
    let bodies = record.bodies.map_or(Look::CouldNotLook, Look::Is);
    (Look::Is(record.tasks), bodies)
}

/// The record, when it is about the manifest as it stands; `None` for every
/// refusal [`cached`] names.
fn read(root: &Path) -> Option<Record> {
    let path = record_path(root)?;
    // THE CAP IS CHECKED BEFORE THE READ, which is the only order that bounds
    // anything: reading first and measuring after has already spent the bytes.
    let Ok(meta) = std::fs::metadata(&path) else {
        return None;
    };
    if meta.len() > RECORD_MAX {
        return None;
    }
    let Ok(text) = crate::fsio::read_to_string(&path) else {
        return None;
    };
    let Ok(record) = serde_json::from_str::<Record>(&text) else {
        return None;
    };
    if record.schema != SCHEMA {
        return None;
    }
    // Recomputed from the RECORDED configs, which is what keeps this function
    // free of the parse its own doc says it may not make — and believed by their
    // stat identity where it is recorded and unchanged (CLOUD-2440).
    if !crate::pinned::still_keyed(&record.configs, &record.key, &record.stamps) {
        return None;
    }
    Some(record)
}

/// Parse the declared manifests, record the tasks, and return them.
///
/// Called where a read of this size is admissible — at session start, once — so
/// that every mediated call afterwards pays a single small file read.
///
/// A failure to record is not a failure to answer: the caller still gets the
/// resolved set, and the next session resolves again, which is the same
/// could-not-look the reader already handles.
#[must_use]
pub fn refresh(root: &Path, declared: &[TaskQuery]) -> TaskFacts {
    if declared.is_empty() {
        // NOBODY ASKED, which is could-not-look and not an empty task table: a
        // repository that declares no manifest has not established that it
        // defines no tasks.
        return Look::CouldNotLook;
    }
    let mut tasks: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    let mut bodies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut configs: Vec<PathBuf> = Vec::new();
    for row in declared {
        let path = root.join(&row.manifest);
        configs.push(path.clone());
        let Some(format) = crate::facts::Format::for_path(&row.manifest) else {
            continue;
        };
        let Ok(text) = crate::fsio::read_to_string(&path) else {
            continue;
        };
        // THROUGH `rules::parse_node`, the one `Format::read` call in the crate
        // (CLOUD-849): a second call site is a second error mapping.
        let Ok(node) = crate::rules::parse_node(format, &text) else {
            continue;
        };
        if let Look::Is(table) = node.at(&row.node) {
            tasks.extend(named(table));
            let vars = match node.at("vars") {
                Look::Is(Node::Map(entries)) => entries
                    .iter()
                    .filter_map(|(name, value)| value.scalar().map(|value| (name.clone(), value)))
                    .collect(),
                _ => BTreeMap::new(),
            };
            bodies.extend(
                lines(table).into_iter().map(|(name, body)| {
                    (name, body.iter().map(|line| render(line, &vars)).collect())
                }),
            );
        }
    }
    // A BODY LINE RUNNING `step graph run <group>` REACHES ITS GROUP'S ROWS
    // (CLOUD-2785): the gate set moved from task bodies into `[[step]]` rows, and
    // a reader of bodies alone would see `mise run verify` reach none of it. The
    // authority joins the keyed configs, so a row edit moves the record too.
    let authority = root.join(crate::config::CONFIG_FILE);
    if let Some(groups) = graph_rows(&authority) {
        configs.push(authority);
        expand_graphs(&mut bodies, &groups);
    }
    if tasks.is_empty() {
        // The manifests were declared and none of them yielded a task. That is
        // could-not-look rather than an empty answer for the reason the header
        // gives: a guard comparing against no tasks permits every substitution.
        return Look::CouldNotLook;
    }
    let _recorded = write(root, &configs, &tasks, &bodies);
    Look::Is(tasks)
}

/// Each graph group's rows' `run` argvs, as shell lines, from the authority at
/// `path`; `None` where it does not read or declares no grouped row.
fn graph_rows(path: &Path) -> Option<BTreeMap<String, Vec<String>>> {
    let text = crate::fsio::read_to_string(path).ok()?;
    let node = crate::rules::parse_node(crate::facts::Format::Toml, &text).ok()?;
    let Look::Is(Node::List(rows)) = node.at("step") else {
        return None;
    };
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let (Look::Is(group), Look::Is(Node::List(run))) = (row.at("group"), row.at("run")) else {
            continue;
        };
        let Some(group) = group.scalar() else {
            continue;
        };
        let words: Vec<String> = run
            .iter()
            .filter_map(Node::scalar)
            .map(|word| crate::engine::shell_word(&word))
            .collect();
        if !words.is_empty() {
            groups.entry(group).or_default().push(words.join(" "));
        }
    }
    (!groups.is_empty()).then_some(groups)
}

/// Follow every body line naming `step graph run <group>` with that group's
/// row lines, so a reader of the body reaches what the graph runs.
fn expand_graphs(
    bodies: &mut BTreeMap<String, Vec<String>>,
    groups: &BTreeMap<String, Vec<String>>,
) {
    for lines in bodies.values_mut() {
        let mut expanded = Vec::with_capacity(lines.len());
        for line in lines.drain(..) {
            let rows = graph_group(&line).and_then(|group| groups.get(group));
            expanded.push(line.clone());
            expanded.extend(rows.into_iter().flatten().cloned());
        }
        *lines = expanded;
    }
}

/// The group a `… step graph run <group>` line names.
fn graph_group(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once("step graph run ")?;
    rest.split_whitespace().next()
}

/// Write `tasks` as `root`'s record, keyed to `configs` as they stand.
///
/// Public for [`crate::pinned::record`]'s reason: a fixture that hand-spells the
/// bytes passes while the real writer and the real reader disagree, so one writer
/// and one reader, and the test drives both.
///
/// Returns whether the record was written — the difference between "recorded" and
/// "resolved", which a caller asserting the first should not have to infer.
#[must_use]
pub fn record(
    root: &Path,
    configs: &[PathBuf],
    tasks: &BTreeMap<String, Option<Vec<String>>>,
) -> bool {
    write(root, configs, tasks, &BTreeMap::new())
}

/// [`record`], with the bodies [`cached_bodies`] reads back.
fn write(
    root: &Path,
    configs: &[PathBuf],
    tasks: &BTreeMap<String, Option<Vec<String>>>,
    bodies: &BTreeMap<String, Vec<String>>,
) -> bool {
    let (Some((key, stamps)), Some(path)) =
        (crate::pinned::stamped_key(configs), record_path(root))
    else {
        return false;
    };
    let record = Record {
        schema: SCHEMA,
        generator: format!("{}@{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        key,
        configs: configs.to_vec(),
        tasks: tasks.clone(),
        bodies: Some(bodies.clone()),
        stamps,
    };
    let Ok(body) = serde_json::to_string(&record) else {
        return false;
    };
    if body.len() as u64 > RECORD_MAX {
        // REFUSED AT THE WRITE as well as at the read, so a record this build
        // could never read back is never left on disk to be diagnosed later.
        return false;
    }
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    crate::durable::replace(path, body).is_ok()
}

/// Every task the declared node names, with its argv where it has one.
///
/// A task's body is its own scalar, or the scalar under `run` where the entry is
/// a table — the two shapes a task table carries. Anything else is a task that
/// exists with no readable body, which is `None` rather than absent.
fn named(table: &Node) -> BTreeMap<String, Option<Vec<String>>> {
    let Node::Map(entries) = table else {
        return BTreeMap::new();
    };
    entries
        .iter()
        .map(|(name, entry)| (name.clone(), argv(entry)))
        .collect()
}

/// A body line with its `{{vars.X}}` templates rendered from the manifest's
/// `[vars]`, and a `{{ get_env(name='N', default='D') }}` (in a line or in a
/// var) rendered as the runner renders it: the variable when set, else the
/// default (step 14). Anything else between `{{` and `}}` is kept as written —
/// it is not a value this can know at session start.
///
/// Without this a body spelled `{{vars.batten}} step run …` names a program
/// called `{{vars.batten}}`, and every module classifying a task by what it
/// runs reads it as running nothing it knows.
fn render(line: &str, vars: &BTreeMap<String, String>) -> String {
    render_depth(line, vars, 4)
}

fn render_depth(line: &str, vars: &BTreeMap<String, String>, depth: usize) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(open) = rest.find("{{") {
        let Some(close) = rest[open..].find("}}").map(|at| at + open) else {
            break;
        };
        out.push_str(&rest[..open]);
        let inner = rest[open + 2..close].trim();
        let rendered = if let Some(name) = inner.strip_prefix("vars.") {
            vars.get(name.trim())
                .filter(|_| depth > 0)
                .map(|value| render_depth(value, vars, depth - 1))
        } else if inner.starts_with("get_env(") {
            get_env(inner)
        } else {
            None
        };
        match rendered {
            Some(value) => out.push_str(&value),
            None => out.push_str(&rest[open..close + 2]),
        }
        rest = &rest[close + 2..];
    }
    out.push_str(rest);
    out
}

/// `get_env(name='N', default='D')`: the variable `N` when set, else `D`.
fn get_env(call: &str) -> Option<String> {
    let argument = |key: &str| -> Option<String> {
        let at = call.find(&format!("{key}="))? + key.len() + 1;
        let quote = call[at..]
            .chars()
            .next()
            .filter(|c| *c == '\'' || *c == '"')?;
        let body = &call[at + 1..];
        body.find(quote).map(|end| body[..end].to_owned())
    };
    let name = argument("name")?;
    std::env::var(&name).ok().or_else(|| argument("default"))
}

/// Every task the declared node names, with the command lines its body runs
/// ([`TaskBodies`]).
fn lines(table: &Node) -> BTreeMap<String, Vec<String>> {
    let Node::Map(entries) = table else {
        return BTreeMap::new();
    };
    entries
        .iter()
        .map(|(name, entry)| (name.clone(), body_lines(entry)))
        .collect()
}

/// One task's body as command lines. A `{ task = "x" }` step and every
/// `depends` entry become `mise run x`, which is how the runner reaches them, so
/// the reader walks one shape. A `file =` task and an unreadable body are no
/// lines: what they run is not in the manifest.
fn body_lines(entry: &Node) -> Vec<String> {
    let step = |node: &Node| -> Option<String> {
        node.scalar().or_else(|| match node.at("task") {
            Look::Is(task) => task.scalar().map(|task| format!("mise run {task}")),
            Look::IsNot | Look::CouldNotLook => None,
        })
    };
    let each = |node: &Node| -> Vec<String> {
        match node {
            Node::List(items) => items.iter().filter_map(step).collect(),
            other => step(other).into_iter().collect(),
        }
    };
    let Node::Map(_) = entry else {
        return each(entry);
    };
    let mut found = match entry.at("run") {
        Look::Is(run) => each(run),
        Look::IsNot | Look::CouldNotLook => Vec::new(),
    };
    for key in ["depends", "depends_post"] {
        if let Look::Is(Node::List(names)) = entry.at(key) {
            found.extend(
                names
                    .iter()
                    .filter_map(Node::scalar)
                    .map(|name| format!("mise run {name}")),
            );
        } else if let Look::Is(name) = entry.at(key)
            && let Some(name) = name.scalar()
        {
            found.push(format!("mise run {name}"));
        }
    }
    found
}

/// One task's normalised argv, or `None` where it is not a single command.
///
/// **Only a single command gets an argv, and that bound is the point.** A body
/// carrying a separator is a pipeline or a sequence, and reducing one to a word
/// list would let a consumer compare a call against something the task does not
/// actually run — a refusal naming a task whose argv it invented.
///
/// **DECIDED BY A PARSE SINCE CLOUD-1381, and it was a scan before.** The bound
/// above is unchanged and the way it is established is not. This read
/// `body.contains("&&")` and then `split_whitespace()`, which is the same class
/// of defect the mediation boundary was carrying one surface over: a substring
/// test fires on a separator inside a quoted operand, so
/// `echo "a && b"` was refused an argv it plainly has, and a whitespace split
/// ignores quoting, so `cargo test --filter "a b"` yielded five words where the
/// task runs four. Both were silent — the first under-reports (a task with no
/// argv is simply not judged) and the second hands a guard an argv nobody runs.
///
/// [`rable`] answers the same question structurally: one [`Command`] node and
/// nothing else is a single command, and its words are its argv. A pipeline, a
/// list, a compound body and a body that will not parse are all `None`, which
/// they already were.
///
/// [`Command`]: rable::NodeKind::Command
fn argv(entry: &Node) -> Option<Vec<String>> {
    let body = match entry {
        Node::Map(_) => match entry.at("run") {
            Look::Is(run) => run.scalar()?,
            Look::IsNot | Look::CouldNotLook => return None,
        },
        other => other.scalar()?,
    };
    // A body that does not parse has no argv, which is the same answer a
    // pipeline gets: the task exists and its argv is unknowable as a word list.
    let nodes = rable::parse(&body, false).ok()?;
    let [node] = nodes.as_slice() else {
        // Zero nodes is an empty body; two or more is a multi-line body, which
        // this has always refused an argv.
        return None;
    };
    let rable::NodeKind::Command {
        words, redirects, ..
    } = &node.kind
    else {
        // A pipeline, a list, a subshell, an `if` — every one of them runs
        // something other than one program with one argv.
        return None;
    };
    // A REDIRECTION MEANS THE TASK IS NOT ITS ARGV EITHER. `mise run x` sets up
    // the redirect and a bare `prog` does not, so calling them the same command
    // is the substitution this fact exists to refuse.
    if !redirects.is_empty() {
        return None;
    }
    let spelled: Vec<String> = words
        .iter()
        .map(|word| match &word.kind {
            rable::NodeKind::Word { value, .. } => crate::hook::unquote(value),
            _ => String::new(),
        })
        .filter(|word| !word.is_empty())
        .collect();
    (!spelled.is_empty()).then_some(spelled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn table(text: &str) -> Node {
        match crate::facts::Format::Toml.read(text) {
            Look::Is(node) => match node.at("tasks") {
                Look::Is(inner) => inner.clone(),
                Look::IsNot | Look::CouldNotLook => panic!("the fixture must carry a task table"),
            },
            Look::IsNot | Look::CouldNotLook => panic!("the fixture must parse"),
        }
    }

    /// Fails by: a record written before bodies existed refused whole (every
    /// reader of a released engine's receipt losing task existence), or read
    /// as bodies that run nothing (`task-programs` an empty list, so a guard
    /// following a `mise run` finds nothing to refuse).
    #[test]
    fn a_record_without_bodies_answers_tasks_and_leaves_task_programs_null() {
        let record: Record = serde_json::from_str(
            r#"{"schema":1,"generator":"batten@0.0.0","key":"k","configs":[],
                "tasks":{"lint":["cargo","clippy"],"ci":null}}"#,
        )
        .expect("a record without bodies still parses");
        assert_eq!(record.schema, SCHEMA, "an added field is no new shape");
        let (tasks, bodies) = answers(record);
        let Look::Is(tasks) = tasks else {
            panic!("task existence still answers");
        };
        assert!(tasks.contains_key("lint") && tasks.contains_key("ci"));
        assert_eq!(bodies, Look::CouldNotLook);
        assert_eq!(
            crate::hook::task_programs("mise run lint", &bodies),
            serde_json::Value::Null
        );
    }

    #[test]
    fn a_single_command_task_yields_its_argv() {
        let tasks = named(&table("[tasks]\nlint = \"cargo clippy --all\"\n"));
        assert_eq!(
            tasks.get("lint"),
            Some(&Some(vec![
                String::from("cargo"),
                String::from("clippy"),
                String::from("--all"),
            ]))
        );
    }

    /// A task's body lines are what it runs: a scalar is one line, an array one
    /// per element, and a `depends` entry or a `{ task = … }` step is the `mise
    /// run` that reaches it (step 14).
    ///
    /// Fails by: an array body read as no lines (a sequence reaches nothing),
    /// `depends` dropped, or a `{ task = … }` step dropped.
    /// A `{{vars.X}}` template renders from `[vars]`, through a `get_env`
    /// default, and an unknown template is kept (step 14).
    ///
    /// Fails by: the var lookup, the `get_env` default, or the keep arm dropped.
    #[test]
    fn a_body_line_renders_its_var_templates() {
        let vars = BTreeMap::from([(
            "tool".to_owned(),
            "{{ get_env(name='BATTEN_NO_SUCH_VAR_FOR_TEST', default='cargo run -p x --') }}"
                .to_owned(),
        )]);
        assert_eq!(render("{{vars.tool}} go", &vars), "cargo run -p x -- go");
        assert_eq!(render("{{ vars.tool }} go", &vars), "cargo run -p x -- go");
        assert_eq!(render("a {{env.HOME_X}} b", &vars), "a {{env.HOME_X}} b");
    }

    #[test]
    fn a_task_body_yields_every_line_it_runs() {
        let bodies = lines(&table(
            "[tasks]\none = \"cargo build\"\n\
             [tasks.seq]\nrun = [\"a x\", { task = \"b\" }]\ndepends = [\"c\"]\n",
        ));
        assert_eq!(bodies["one"], vec!["cargo build"]);
        assert_eq!(bodies["seq"], vec!["a x", "mise run b", "mise run c"]);
    }

    #[test]
    fn a_graph_line_is_followed_by_its_groups_rows_and_nothing_else_moves() {
        let dir = std::env::temp_dir().join(format!("taskset-graph-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let authority = dir.join("batten.toml");
        crate::durable::replace(
            &authority,
            "[[step]]\nid = \"a\"\ngroup = \"g\"\nrun = [\"mise\", \"run\", \"zizmor\"]\n\
             [[step]]\nid = \"b\"\ngroup = \"g\"\nrun = [\"batten\", \"check\", \"--rule\", \"x y\"]\n\
             [[step]]\nid = \"c\"\ngroup = \"h\"\nrun = [\"mise\", \"run\", \"other\"]\n\
             [[step]]\nid = \"d\"\ninputs = [\".\"]\ntools = []\n",
        )
        .unwrap();
        let groups = graph_rows(&authority).expect("two groups");
        let mut bodies = BTreeMap::from([(
            "gated".to_owned(),
            vec![
                "batten step graph run g --jobs 2".to_owned(),
                "mise run ci".to_owned(),
            ],
        )]);
        expand_graphs(&mut bodies, &groups);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            bodies["gated"],
            vec![
                "batten step graph run g --jobs 2",
                "mise run zizmor",
                "batten check --rule 'x y'",
                "mise run ci",
            ]
        );
    }

    #[test]
    fn a_compound_body_is_present_with_no_argv() {
        // THE DISTINCTION THIS FAMILY TURNS ON. The task exists, so a consumer
        // must not read it as absent; its argv is unknowable as a word list, so a
        // consumer must not be handed one. Reducing `a && b` to five words would
        // let a guard refuse a call by naming a command the task never runs.
        let tasks = named(&table("[tasks]\nship = \"build && push\"\n"));
        assert!(tasks.contains_key("ship"), "the task exists: {tasks:?}");
        assert_eq!(tasks.get("ship"), Some(&None), "and has no single argv");
    }

    #[test]
    fn a_table_entry_reads_its_run_member() {
        let tasks = named(&table(
            "[tasks.check]\nrun = \"cargo test\"\ndescription = \"unused here\"\n",
        ));
        assert_eq!(
            tasks.get("check"),
            Some(&Some(vec![String::from("cargo"), String::from("test")]))
        );
    }

    #[test]
    fn a_multi_line_body_is_not_a_single_command() {
        let tasks = named(&table("[tasks]\nwide = \"\"\"\nfirst\nsecond\n\"\"\"\n"));
        assert_eq!(tasks.get("wide"), Some(&None), "{tasks:?}");
    }

    #[test]
    fn no_declaration_is_could_not_look_rather_than_an_empty_table() {
        // A repository that declares no manifest has not established that it
        // defines no tasks — and a guard comparing against an empty table permits
        // every substitution it exists to refuse.
        assert!(matches!(refresh(Path::new("."), &[]), Look::CouldNotLook));
    }

    /// A one-task set whose record serializes to exactly `len` bytes over
    /// `configs`, the task name padding it out.
    fn sized(configs: &[PathBuf], len: usize) -> BTreeMap<String, Option<Vec<String>>> {
        let body = |name: String| {
            serde_json::to_string(&Record {
                schema: SCHEMA,
                generator: format!("{}@{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                key: crate::pinned::key(configs).unwrap(),
                configs: configs.to_vec(),
                tasks: BTreeMap::from([(name, None)]),
                bodies: Some(BTreeMap::new()),
                // None: the caller's manifest yields no stamp, so `record` writes
                // none either and the sized body is the one it writes.
                stamps: crate::pinned::Stamps::new(),
            })
            .unwrap()
            .len()
        };
        let name = "t".repeat(len - body(String::new()));
        assert_eq!(
            body(name.clone()),
            len,
            "the padding is one byte a character"
        );
        BTreeMap::from([(name, None)])
    }

    /// Fails by: a record not read back, one about a manifest that has since
    /// moved still answering, or the size cap applied anywhere but at exactly
    /// [`RECORD_MAX`] on both the write and the read.
    #[test]
    fn a_record_answers_up_to_its_cap_until_its_manifest_moves() {
        // Spelled rather than read from the constant, so the cap itself is pinned.
        const CAP: usize = 256 * 1024;
        let dir = crate::scratch::scratch("taskset-record");
        crate::gitwrite::init_on_main(&dir).unwrap();
        let manifest = dir.join("tasks.toml");
        std::fs::write(&manifest, "[tasks]\nlint = \"cargo clippy\"\n").unwrap();
        // A pre-epoch mtime yields no stamp, so no record carries stamps whatever
        // the clock does between `sized` and `record`: each body is the measured one.
        std::fs::File::options()
            .write(true)
            .open(&manifest)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH - std::time::Duration::from_secs(1))
            .unwrap();
        let configs = vec![manifest.clone()];
        assert!(
            crate::pinned::stamped(&configs, crate::cache::now()).is_empty(),
            "the premise: the manifest yields no stamps"
        );
        let small = sized(&configs, 1024);
        assert!(record(&dir, &configs, &small));
        assert!(matches!(cached(&dir), Look::Is(read) if read == small));
        let at_cap = sized(&configs, CAP);
        assert!(
            record(&dir, &configs, &at_cap),
            "a record at the cap is written"
        );
        assert!(matches!(cached(&dir), Look::Is(read) if read == at_cap));
        let over = sized(&configs, CAP + 1);
        assert!(
            !record(&dir, &configs, &over),
            "one byte past it is refused"
        );
        std::fs::write(&manifest, "[tasks]\n").unwrap();
        assert!(matches!(cached(&dir), Look::CouldNotLook));
    }
}
