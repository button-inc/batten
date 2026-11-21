//! `batten step graph run` (CLOUD-2785): a group's `[[step]]` rows as a
//! dependency graph, over the compiled binary.
//!
//! Each node's command is a script under the fixture's `bin/` that appends its
//! start and end to one log, so what ran, in which order and how many at once
//! is read from the log the children wrote, never from the verb's own report,
//! which each case then checks against it.

use crate::common;
use std::path::PathBuf;
use std::process::Output;

/// A node: logs `start <name>`, waits so siblings can overlap, logs `end
/// <name>`, and exits with `$2` (0 when absent).
const NODE: &str = "#!/bin/sh\necho \"start $1\" >>\"$GRAPH_LOG\"\nsleep 0.3\necho \"end $1\" >>\"$GRAPH_LOG\"\nexit \"${2:-0}\"\n";

struct Graph {
    dir: PathBuf,
    log: PathBuf,
}

impl Graph {
    /// A repository whose step table is `rows` (TOML `[[step]]` tables).
    fn new(name: &str, rows: &str) -> Self {
        let dir = common::scratch(&format!("step-graph-{name}"));
        common::write(&dir, "bin/node", NODE);
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join("bin/node"), std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        common::write(&dir, ".gitignore", "bin/\ngraph.log\n");
        common::write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));
        common::init_repo(&dir);
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-qm", "init"]);
        let log = dir.join("graph.log");
        Self { dir, log }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut all = vec!["step", "graph", "run"];
        all.extend_from_slice(args);
        common::batten()
            .args(&all)
            .current_dir(&self.dir)
            .env("GRAPH_LOG", &self.log)
            .env_remove("CI")
            .env_remove("BATTEN_TASK_PID")
            .streamed_output()
            .expect("run batten")
    }

    fn events(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The most nodes the log shows running at once.
    fn overlap(&self) -> usize {
        let (mut now, mut most) = (0_usize, 0_usize);
        for event in self.events() {
            if event.starts_with("start ") {
                now += 1;
                most = most.max(now);
            } else {
                now -= 1;
            }
        }
        most
    }

    fn started(&self, name: &str) -> bool {
        self.events()
            .iter()
            .any(|event| event == &format!("start {name}"))
    }
}

/// A schedule-only node of group `g`: `bin/node <id> <code>`, after `after`.
fn node(id: &str, code: u8, after: &[&str]) -> String {
    let after = after
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[step]]\nid = \"{id}\"\ngroup = \"g\"\nrun = [\"bin/node\", \"{id}\", \"{code}\"]\ndepends_on = [{after}]\n\n"
    )
}

#[test]
fn dependants_of_a_failure_are_skipped_and_siblings_run() {
    // `a` passes and `b` follows it; `c` fails, so `d` (after `c`) and `e`
    // (after `d`) never start, while `a`'s branch is untouched.
    let rows = [
        node("a", 0, &[]),
        node("b", 0, &["a"]),
        node("c", 2, &[]),
        node("d", 0, &["c"]),
        node("e", 0, &["d"]),
    ]
    .concat();
    let graph = Graph::new("skip", &rows);
    let out = graph.run(&["g"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    for ran in ["a", "b", "c"] {
        assert!(graph.started(ran), "{ran} ran: {stderr}");
    }
    for skipped in ["d", "e"] {
        assert!(!graph.started(skipped), "{skipped} never started: {stderr}");
    }
    assert!(
        stderr.contains("step graph: d skipped (c failed)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("step graph: e skipped (d failed)"),
        "{stderr}"
    );
    let events = graph.events();
    let at = |event: &str| events.iter().position(|e| e == event).unwrap();
    assert!(
        at("end a") < at("start b"),
        "a dependency finishes first: {events:?}"
    );
}

#[test]
fn no_more_than_jobs_run_at_once() {
    let rows = ["w", "x", "y", "z"].map(|id| node(id, 0, &[])).concat();
    let graph = Graph::new("jobs", &rows);
    let out = graph.run(&["g", "--jobs", "2"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        graph.events().len(),
        8,
        "every node ran once: {:?}",
        graph.events()
    );
    assert_eq!(graph.overlap(), 2, "the bound is met and never passed");
    assert!(stderr.contains("step graph: g peak 2 of 2"), "{stderr}");
}

#[test]
fn the_exit_is_the_worst_childs() {
    let rows = [
        node("ok", 0, &[]),
        node("refused", 2, &[]),
        node("broken", 3, &[]),
    ]
    .concat();
    let graph = Graph::new("worst", &rows);
    let out = graph.run(&["g"]);
    assert_eq!(out.status.code(), Some(3), "{}", common::stderr(&out));
    assert!(common::stderr(&out).contains("step graph: refused ran 2"));
}

#[test]
fn a_schedule_only_row_runs_and_records_nothing() {
    let graph = Graph::new("unkeyed", &node("only", 0, &[]));
    let out = graph.run(&["g"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(graph.started("only"));
    assert!(
        !graph.dir.join(".git/batten-records/step-receipts").exists(),
        "a node with no inputs or tools takes no receipt"
    );
}

#[test]
fn an_unknown_group_or_jobs_value_is_a_usage_error() {
    let graph = Graph::new("usage", &node("a", 0, &[]));
    assert_eq!(graph.run(&["nope"]).status.code(), Some(1));
    assert_eq!(graph.run(&["g", "--jobs", "0"]).status.code(), Some(1));
    assert!(!graph.started("a"), "nothing ran");
}
