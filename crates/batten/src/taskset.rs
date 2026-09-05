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
/// invocation, a binary probe or a tree walk.
/// `crates/batten/tests/it/task_receipt.rs`'s
/// `the_mediated_call_digests_the_manifest_and_never_parses_it` is what
/// discriminates the two: it records over a manifest that is not valid TOML, so a
/// read that parsed would answer could-not-look and a read that digests answers.
#[must_use]
pub fn cached(root: &Path) -> TaskFacts {
    let Some(path) = record_path(root) else {
        return Look::CouldNotLook;
    };
    // THE CAP IS CHECKED BEFORE THE READ, which is the only order that bounds
    // anything: reading first and measuring after has already spent the bytes.
    let Ok(meta) = std::fs::metadata(&path) else {
        return Look::CouldNotLook;
    };
    if meta.len() > RECORD_MAX {
        return Look::CouldNotLook;
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Look::CouldNotLook;
    };
    let Ok(record) = serde_json::from_str::<Record>(&text) else {
        return Look::CouldNotLook;
    };
    if record.schema != SCHEMA {
        return Look::CouldNotLook;
    }
    // Recomputed from the RECORDED configs, which is what keeps this function
    // free of the parse its own doc says it may not make.
    if crate::pinned::key(&record.configs).as_ref() != Some(&record.key) {
        return Look::CouldNotLook;
    }
    Look::Is(record.tasks)
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
    let mut configs: Vec<PathBuf> = Vec::new();
    for row in declared {
        let path = root.join(&row.manifest);
        configs.push(path.clone());
        let Some(format) = crate::facts::Format::for_path(&row.manifest) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // THROUGH `rules::parse_node`, the one `Format::read` call in the crate
        // (CLOUD-849): a second call site is a second error mapping.
        let Ok(node) = crate::rules::parse_node(format, &text) else {
            continue;
        };
        if let Look::Is(table) = node.at(&row.node) {
            tasks.extend(named(table));
        }
    }
    if tasks.is_empty() {
        // The manifests were declared and none of them yielded a task. That is
        // could-not-look rather than an empty answer for the reason the header
        // gives: a guard comparing against no tasks permits every substitution.
        return Look::CouldNotLook;
    }
    let _recorded = record(root, &configs, &tasks);
    Look::Is(tasks)
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
    let (Some(key), Some(path)) = (crate::pinned::key(configs), record_path(root)) else {
        return false;
    };
    let record = Record {
        schema: SCHEMA,
        generator: format!("{}@{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        key,
        configs: configs.to_vec(),
        tasks: tasks.clone(),
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
    std::fs::write(path, body).is_ok()
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
}
