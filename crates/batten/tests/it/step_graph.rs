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
    node_in("g", id, code, after)
}

/// [`node`] in group `group`.
fn node_in(group: &str, id: &str, code: u8, after: &[&str]) -> String {
    let after = after
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[[step]]\nid = \"{id}\"\ngroup = \"{group}\"\nrun = [\"bin/node\", \"{id}\", \"{code}\"]\ndepends_on = [{after}]\n\n"
    )
}

/// A LATER TIER STARTS ONLY ONCE EVERY EARLIER ONE PASSED (CLOUD-2853; owner
/// ruling, `.batten/asked.jsonl:223`). Fails by: a group after a red one
/// starting (the CLOUD-2789 shape this reverses), a skipped row missing from
/// the red list, or the run exiting 0 over a red. `t1` holds a red and a green
/// row; `t2` and `t3` are green and independent of both, and never start.
#[test]
fn a_red_group_stops_every_later_group_and_every_red_is_listed() {
    let rows = [
        node_in("t1", "a", 2, &[]),
        node_in("t1", "a-ok", 0, &[]),
        node_in("t2", "b", 0, &[]),
        node_in("t3", "c", 0, &[]),
    ]
    .concat();
    let graph = Graph::new("tiers", &rows);
    let out = graph.run(&["t1", "t2", "t3"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    for ran in ["a", "a-ok"] {
        assert!(graph.started(ran), "{ran} ran: {stderr}");
    }
    for held in ["b", "c"] {
        assert!(!graph.started(held), "{held} never started: {stderr}");
    }
    for red in [
        "step graph: red t1 a ran 2",
        "step graph: red t2 b skipped",
        "step graph: red t3 c skipped",
        "step graph: t2 skipped (t1 red)",
    ] {
        assert!(stderr.contains(red), "{red}: {stderr}");
    }
    assert!(!stderr.contains("red t1 a-ok"), "{stderr}");
}

/// A TIER STILL REPORTS EVERY RED IT HOLDS (CLOUD-2789, kept by CLOUD-2853).
/// Fails by: a group stopped at its first red, so `y` or `z` never starts, or
/// `t2` starting after the red tier.
#[test]
fn every_red_in_a_tier_is_reported() {
    let rows = [
        node_in("t1", "x", 2, &[]),
        node_in("t1", "y", 3, &[]),
        node_in("t1", "z", 0, &[]),
        node_in("t2", "w", 0, &[]),
    ]
    .concat();
    let graph = Graph::new("tier-reds", &rows);
    let out = graph.run(&["t1", "t2"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    for ran in ["x", "y", "z"] {
        assert!(graph.started(ran), "{ran} ran: {stderr}");
    }
    assert!(!graph.started("w"), "w never started: {stderr}");
    for red in ["step graph: red t1 x ran 2", "step graph: red t1 y ran 3"] {
        assert!(stderr.contains(red), "{red}: {stderr}");
    }
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
    assert_eq!(graph.run(&["g=0"]).status.code(), Some(1));
    assert_eq!(
        graph.run(&["g", "nope"]).status.code(),
        Some(1),
        "every group resolves first"
    );
    assert!(!graph.started("a"), "nothing ran");
}
