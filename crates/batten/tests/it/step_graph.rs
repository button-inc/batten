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

/// A slow node: [`NODE`] holding long enough that a line written when another
/// node ends is plainly read while this one still runs.
const SLOW: &str = "#!/bin/sh\necho \"start $1\" >>\"$GRAPH_LOG\"\nsleep 3\necho \"end $1\" >>\"$GRAPH_LOG\"\nexit 0\n";

struct Graph {
    dir: PathBuf,
    log: PathBuf,
}

impl Graph {
    /// A repository whose step table is `rows` (TOML `[[step]]` tables).
    fn new(name: &str, rows: &str) -> Self {
        let dir = common::scratch(&format!("step-graph-{name}"));
        common::write(&dir, "bin/node", NODE);
        common::write(&dir, "bin/slow", SLOW);
        for script in ["bin/node", "bin/slow"] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.join(script), std::fs::Permissions::from_mode(0o755))
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

    /// Run the graph, reading its stderr as it arrives: the events the node log
    /// held when the first line starting `line` arrived, and every line read.
    fn events_when(&self, args: &[&str], line: &str) -> (Option<Vec<String>>, Vec<String>) {
        use std::io::BufRead as _;
        let mut all = vec!["step", "graph", "run"];
        all.extend_from_slice(args);
        let mut command = common::batten();
        command
            .args(&all)
            .current_dir(&self.dir)
            .env("GRAPH_LOG", &self.log)
            .env_remove("CI")
            .env_remove("BATTEN_TASK_PID")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn batten");
        let stderr = child.stderr.take().expect("piped stderr");
        let (mut seen, mut lines) = (None, Vec::new());
        for read in std::io::BufReader::new(stderr).lines() {
            let read = read.expect("read stderr");
            if seen.is_none() && read.starts_with(line) {
                seen = Some(self.events());
            }
            lines.push(read);
        }
        child.wait().expect("wait for batten");
        (seen, lines)
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

/// A [`SLOW`] node of group `group`, depending on nothing.
fn slow_in(group: &str, id: &str) -> String {
    format!(
        "[[step]]\nid = \"{id}\"\ngroup = \"{group}\"\nrun = [\"bin/slow\", \"{id}\"]\ndepends_on = []\n\n"
    )
}

/// The fields of a `step graph: <ok|red> <group> <id> <exit> <secs> <pointer>`
/// line, after `step graph: `, checked for shape: six of them, a code, a
/// decimal second count and a one-token pointer.
fn verdict_fields(line: &str) -> Vec<String> {
    let fields: Vec<String> = line
        .strip_prefix("step graph: ")
        .unwrap_or_default()
        .split(' ')
        .map(str::to_owned)
        .collect();
    assert_eq!(fields.len(), 6, "{line}");
    assert!(fields[3].parse::<i32>().is_ok(), "{line}");
    assert!(fields[4].parse::<f64>().is_ok(), "{line}");
    assert!(!fields[5].is_empty(), "{line}");
    assert_pointer(&fields[5], line);
    fields
}

/// A verdict line's pointer is `-` or comma-joined `<stream>:<handle>` parts,
/// each matching `^(stdout|stderr):\S+$` (CLOUD-2838): capture handles a reader
/// follows, and nothing else `step::logged` could hand over.
fn assert_pointer(pointer: &str, line: &str) {
    if pointer == "-" {
        return;
    }
    for part in pointer.split(',') {
        let shaped = part.split_once(':').is_some_and(|(stream, handle)| {
            matches!(stream, "stdout" | "stderr")
                && !handle.is_empty()
                && !handle.contains(char::is_whitespace)
        });
        assert!(shaped, "pointer part `{part}` is no capture handle: {line}");
    }
}

/// A FINISHED STEP'S VERDICT IS WRITTEN WHEN IT FINISHES (CLOUD-2838), before
/// the next group starts. Group 1 holds a red and a green step; group 2's slow
/// step starts only once group 1 has ended, and still runs (CLOUD-2904). Fails
/// by: no six-field verdict line for either group-1 step, group 2 starting
/// before group 1 ended, or group 2 not running at all. The timing of the line
/// is the sibling case's to show.
#[test]
fn a_red_step_in_an_earlier_group_is_read_before_a_later_group_ends() {
    let rows = [
        node_in("t1", "a", 2, &[]),
        node_in("t1", "b", 0, &[]),
        slow_in("t2", "slow"),
    ]
    .concat();
    let graph = Graph::new("live-groups", &rows);
    let (seen, lines) = graph.events_when(&["t1", "t2"], "step graph: red t1 a ");
    let seen = seen.unwrap_or_else(|| panic!("no red line for a: {lines:#?}"));
    assert!(
        !seen.iter().any(|event| event == "start slow"),
        "group 2 started before group 1 ended: {seen:?}"
    );
    let red = lines
        .iter()
        .find(|line| line.starts_with("step graph: red t1 a "))
        .expect("the red line");
    let fields = verdict_fields(red);
    assert_eq!(fields[..4], ["red", "t1", "a", "2"], "{red}");
    assert_ne!(
        fields[5], "-",
        "exec reports a handle for each stream, so a red node points somewhere: {red}"
    );
    let ok = lines
        .iter()
        .find(|line| line.starts_with("step graph: ok t1 b "))
        .unwrap_or_else(|| panic!("no ok line for b: {lines:#?}"));
    assert_eq!(verdict_fields(ok)[..4], ["ok", "t1", "b", "0"], "{ok}");
    assert!(
        graph.started("slow"),
        "group 2's independent step ran: {lines:#?}"
    );
}

/// The same within one group: a fast red sibling is read while a slow sibling
/// still runs, which is where #1276's tier-2 `test-replay` red waited.
#[test]
fn a_red_step_is_read_while_its_slow_sibling_still_runs() {
    let rows = [node("a", 2, &[]), slow_in("g", "slow")].concat();
    let graph = Graph::new("live-siblings", &rows);
    let (seen, lines) = graph.events_when(&["g"], "step graph: red g a ");
    let seen = seen.unwrap_or_else(|| panic!("no red line for a: {lines:#?}"));
    assert!(
        seen.iter().any(|event| event == "start slow")
            && !seen.iter().any(|event| event == "end slow"),
        "the red line waited for its sibling to end: {seen:?}"
    );
}

/// A HELD PIPE NEVER REACHES THE POINTER (CLOUD-2838). The node backgrounds a
/// grandchild that keeps its stdout open past exec's drain deadline, so exec
/// writes `… a process still holds the pipe open`, whose last field is `open`.
/// Fails by: `verdict_line` passing `step::logged`'s fields through unfiltered.
#[test]
fn a_held_pipe_never_reaches_the_pointer() {
    let rows = "[[step]]\nid = \"held\"\ngroup = \"g\"\nrun = [\"bin/held\"]\ndepends_on = []\n\n";
    let graph = Graph::new("held-pipe", rows);
    common::write(&graph.dir, "bin/held", "#!/bin/sh\nsleep 12 &\nexit 0\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            graph.dir.join("bin/held"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
    }
    let output = graph.run(&["g"]);
    let stderr = common::stderr(&output);
    let line = stderr
        .lines()
        .find(|line| line.starts_with("step graph: ok g held "))
        .unwrap_or_else(|| panic!("no verdict line for held: {stderr}"));
    let fields = verdict_fields(line);
    // exec's held-pipe line goes to the step's report, not this stderr; the
    // node's own seconds show the drain waited out its deadline instead.
    let seconds: f64 = fields[4].parse().expect("seconds");
    assert!(
        seconds >= 9.5,
        "the fixture must hold the pipe past exec's 10 s drain deadline: {line}"
    );
    assert!(!fields[5].contains("open"), "{line}");
}

/// A RED TIER STOPS NO INDEPENDENT LATER STEP (CLOUD-2904): 21 laps of #1276
/// each surfaced one red because a red first tier skipped every later one.
/// Fails by: a later group skipped over an earlier red (the CLOUD-2853 shape
/// this reverses), a later step's pass not recorded, a red in a later tier
/// missing from the closing list, or the run exiting 0 over a red. `t1` holds
/// a red and a green row; `t2` holds a green row and a red one, and `t3` a
/// green one, none depending on anything.
#[test]
fn a_red_tier_stops_no_independent_later_step_and_every_red_is_listed() {
    let rows = [
        node_in("t1", "a", 2, &[]),
        node_in("t1", "a-ok", 0, &[]),
        node_in("t2", "b", 0, &[]),
        node_in("t2", "b-red", 1, &[]),
        node_in("t3", "c", 0, &[]),
    ]
    .concat();
    let graph = Graph::new("tiers", &rows);
    let out = graph.run(&["t1", "t2", "t3"]);
    let stderr = common::stderr(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the worst code, as before: {stderr}"
    );
    for ran in ["a", "a-ok", "b", "b-red", "c"] {
        assert!(graph.started(ran), "{ran} ran: {stderr}");
    }
    let passes = std::fs::read_dir(graph.dir.join(".git/batten-records/step-passes"))
        .map(Iterator::count)
        .unwrap_or_default();
    assert_eq!(passes, 3, "a-ok, b and c each recorded a pass: {stderr}");
    for red in [
        "step graph: red t1 a ran 2",
        "step graph: red t2 b-red ran 1",
    ] {
        assert!(stderr.contains(red), "{red}: {stderr}");
    }
    assert!(
        !stderr.contains("skipped"),
        "nothing depended on a red: {stderr}"
    );
    let closing: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("step graph: red ") && line.contains(" ran "))
        .collect();
    assert_eq!(
        closing.len(),
        2,
        "one closing line per red, every tier: {stderr}"
    );
}

/// A STEP DECLARED TO CONSUME A RED STEP'S OUTPUT IS SKIPPED AND NAMED
/// (CLOUD-2904), across groups: `t2`'s `d` depends on `t1`'s red `a`, `e` on
/// nothing, and `f` on `t3`'s `g`, a group this lap runs after it. Fails by:
/// `d` started, `e` held back with it, `f` waiting forever or starting, or the
/// closing list not naming the red each skip waited on.
#[test]
fn a_consumer_of_a_red_step_in_an_earlier_group_is_skipped_and_named() {
    let rows = [
        node_in("t1", "a", 2, &[]),
        node_in("t2", "d", 0, &["a"]),
        node_in("t2", "e", 0, &[]),
        node_in("t2", "f", 0, &["g"]),
        node_in("t3", "g", 0, &[]),
    ]
    .concat();
    let graph = Graph::new("consumer", &rows);
    let out = graph.run(&["t1", "t2", "t3"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(!graph.started("d"), "d consumes a's output: {stderr}");
    assert!(
        !graph.started("f"),
        "g had not run when f's group did: {stderr}"
    );
    assert!(graph.started("e"), "e is independent: {stderr}");
    assert!(graph.started("g"), "g is independent: {stderr}");
    for line in [
        "step graph: d skipped (a failed)",
        "step graph: f skipped (g not run)",
        "step graph: red t1 a ran 2",
        "step graph: red t2 d skipped (a red)",
        "step graph: red t2 f skipped (g not run)",
    ] {
        assert!(stderr.contains(line), "{line}: {stderr}");
    }
}

/// A TIER STILL REPORTS EVERY RED IT HOLDS (CLOUD-2789, kept by CLOUD-2853).
/// Fails by: a group stopped at its first red, so `y` or `z` never starts, or
/// `t2` held back by the red tier (CLOUD-2904); or a row that ran and exited 1 listed as
/// skipped (the skip code read `1`, a mutant missed at 34c6e4d1f).
#[test]
fn every_red_in_a_tier_is_reported() {
    let rows = [
        node_in("t1", "x", 2, &[]),
        node_in("t1", "y", 3, &[]),
        node_in("t1", "v", 1, &[]),
        node_in("t1", "z", 0, &[]),
        node_in("t2", "w", 0, &[]),
    ]
    .concat();
    let graph = Graph::new("tier-reds", &rows);
    let out = graph.run(&["t1", "t2"]);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    for ran in ["x", "y", "v", "z"] {
        assert!(graph.started(ran), "{ran} ran: {stderr}");
    }
    assert!(
        graph.started("w"),
        "w is independent of every red: {stderr}"
    );
    for red in [
        "step graph: red t1 x ran 2",
        "step graph: red t1 y ran 3",
        "step graph: red t1 v ran 1",
    ] {
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

/// Fails by: a pass recorded for the node that exited non-zero rather than for
/// the two that exited 0 (`==` for `!=`), which `step cover` would then read.
#[test]
fn a_pass_is_recorded_only_for_a_node_that_exited_zero() {
    let rows = [node("a", 0, &[]), node("b", 0, &[]), node("c", 2, &[])].concat();
    let graph = Graph::new("passes", &rows);
    let out = graph.run(&["g"]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    let passes = std::fs::read_dir(graph.dir.join(".git/batten-records/step-passes"))
        .map(Iterator::count)
        .unwrap_or_default();
    assert_eq!(passes, 2, "one pass per node that exited 0");
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

// ---- a lap whose starter is killed ends with it (CLOUD-2955) ---------------
//
// The lap is an inner `step graph run g` under a `sh -c` that an OUTER graph
// runs, so killing the outer one with SIGKILL leaves the inner graph's parent
// alive and its grandparent gone: the shape a killed `mise run verify` leaves
// (CLOUD-2904, "Defect 1"). Group `g` runs `fast`, then `hold`, each through
// `step run`. `hold`'s body opens a FIFO the case reads, so "the body started"
// is a pipe read and "the body is gone" is that pipe's end of file, never a
// clock. Unchecked, the body runs on for ~30 s and then logs `end hold`.

/// `hold`'s body: logs `start hold <pid>`, says so on `$TICK`, checks whether
/// `$FIRST` names a live process, then runs `$HOLD_TICKS` tenths of a second
/// (300 when unset) and logs `end hold`.
const HOLD: &str = "#!/bin/sh\nexec 3>\"$TICK\"\n\
    if [ -n \"$FIRST\" ] && [ -d /proc/$FIRST ] && ! grep -q '^State:.*Z' /proc/$FIRST/status 2>/dev/null; \
    then echo overlap >>\"$GRAPH_LOG\"; fi\n\
    echo \"start hold $$\" >>\"$GRAPH_LOG\"\necho \"$$\" >&3\n\
    i=0\nwhile [ $i -lt \"${HOLD_TICKS:-300}\" ]; do sleep 0.1; i=$((i+1)); done\n\
    echo \"end hold\" >>\"$GRAPH_LOG\"\n";

/// The killed-lap table: `fast` and `hold` (after `fast`) in group `g`, each
/// keyed on `input.txt` and one tool, and run through `step run`; group `outer` runs `g`.
const LAP: &str = "[[step]]\nid = \"fast\"\ngroup = \"g\"\ninputs = [\"input.txt\"]\ntools = [[\"sh\", \"-c\", \"echo v1\"]]\n\
    run = [\"sh\", \"-c\", \"exec \\\"$BATTEN_BIN\\\" step run fast -- bin/node fast\"]\n\n\
    [[step]]\nid = \"hold\"\ngroup = \"g\"\ninputs = [\"input.txt\"]\ntools = [[\"sh\", \"-c\", \"echo v1\"]]\ndepends_on = [\"fast\"]\n\
    run = [\"sh\", \"-c\", \"exec \\\"$BATTEN_BIN\\\" step run hold -- bin/hold\"]\n\n\
    [[step]]\nid = \"lap\"\ngroup = \"outer\"\n\
    run = [\"sh\", \"-c\", \"\\\"$BATTEN_BIN\\\" step graph run g; :\"]\n\n";

/// A lap killed through its starter: the fixture, and the first `hold` body's
/// pid. Returns once that body's FIFO reached end of file, i.e. once no
/// process holds its write end, asserting the body never logged its end.
fn killed_lap(name: &str) -> (Graph, u32) {
    use std::io::BufRead as _;
    let graph = Graph::new(name, LAP);
    common::write(&graph.dir, "bin/hold", HOLD);
    common::write(&graph.dir, "input.txt", "one\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            graph.dir.join("bin/hold"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
    }
    common::git_in(&graph.dir, &["add", "input.txt"]);
    common::git_in(&graph.dir, &["commit", "-qm", "input"]);
    let tick = graph.dir.join("hold.tick");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &tick,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .expect("mkfifo");
    let mut starter = common::batten();
    starter
        .args(["step", "graph", "run", "outer"])
        .current_dir(&graph.dir)
        .env("GRAPH_LOG", &graph.log)
        .env("TICK", &tick)
        .env_remove("CI")
        .env_remove("BATTEN_TASK_PID")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut starter = starter.spawn().expect("spawn the starter");
    let mut ticks = std::io::BufReader::new(std::fs::File::open(&tick).expect("open the FIFO"));
    let mut line = String::new();
    ticks.read_line(&mut line).expect("the body's pid");
    let body: u32 = line.trim().parse().expect("a pid");
    starter.kill().expect("SIGKILL the starter");
    let _ = starter.wait();
    // End of file: every holder of the write end, the body first, is gone.
    let mut rest = String::new();
    let _ = std::io::Read::read_to_string(&mut ticks, &mut rest);
    assert!(
        !graph.events().iter().any(|event| event == "end hold"),
        "the killed lap's body ran on to its end: {:?}",
        graph.events()
    );
    (graph, body)
}

/// `step graph run g` again in the fixture, `$FIRST` naming the killed body.
fn second_lap(graph: &Graph, first: u32) -> Output {
    common::batten()
        .args(["step", "graph", "run", "g"])
        .current_dir(&graph.dir)
        .env("GRAPH_LOG", &graph.log)
        .env("TICK", "/dev/null")
        .env("HOLD_TICKS", "1")
        .env("FIRST", first.to_string())
        .env_remove("CI")
        .env_remove("BATTEN_TASK_PID")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .streamed_output()
        .expect("run the second lap")
}

/// Every live process whose parent is `parent`, read off `/proc`.
fn children_of(parent: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|body| {
                let rest = body.rfind(')').map_or("", |end| &body[end + 1..]);
                let mut fields = rest.split_whitespace();
                let state = fields.next().unwrap_or("Z");
                state != "Z" && fields.next() == Some(parent.to_string().as_str())
            })
        })
        .collect()
}

/// Fails by: the killed lap's body running on to its end (the FIFO stays open
/// until it does), or a child of it left alive once its pipe has closed.
#[test]
fn a_lap_whose_starter_is_killed_leaves_no_live_child() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (_graph, body) = killed_lap("starter-killed");
    assert!(
        children_of(body).is_empty(),
        "nothing the killed body started is alive"
    );
}

/// Fails by: the second lap's `hold` body starting while the killed lap's is
/// alive (`overlap` in the log), or the killed body running to its end.
#[test]
fn a_lap_after_a_killed_one_overlaps_none_of_its_steps() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (graph, first) = killed_lap("no-overlap");
    let out = second_lap(&graph, first);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    let events = graph.events();
    assert!(!events.iter().any(|event| event == "overlap"), "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("start hold"))
            .count(),
        2,
        "the second lap ran its own `hold`: {events:?}"
    );
}

/// Fails by: the second lap re-running `fast`, whose receipt the killed lap
/// recorded before it was killed, or the killed body running to its end.
#[test]
fn a_lap_after_a_killed_one_hits_what_the_killed_one_recorded() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (graph, first) = killed_lap("receipts-kept");
    let out = second_lap(&graph, first);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    let events = graph.events();
    assert_eq!(
        events.iter().filter(|event| *event == "start fast").count(),
        1,
        "`fast` ran once, in the killed lap, and was hit after: {events:?}"
    );
}
