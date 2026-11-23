//! `batten session watch`'s states, over recorded toolbox answers (CLOUD-2826).
//!
//! The source is a fake that serves the recorded event shapes in pages, newest
//! page first, with `before`/`after` cursors, as the toolbox does. The states are
//! decided from those events and the session row only; no prose is read.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeMap;

use batten::session_watch::{
    Cache, Ending, Inventory, Page, Row, Source, State, UNSTARTED_POLLS, Watch, refresh, state,
};
use serde_json::Value;

/// A recorded transcript's events, oldest first.
fn events(name: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(common::at_root(&format!(
        "crates/batten/tests/fixtures/session-watch/{name}"
    )))
    .expect("the fixture");
    let document: Value = serde_json::from_str(&text).expect("the fixture parses");
    match document.pointer("/ccr/data") {
        Some(Value::Array(items)) => items.clone(),
        _ => vec![document],
    }
}

fn row(id: &str, status: &str, connection: Option<&str>) -> Value {
    let mut row =
        serde_json::json!({"id": id, "session_status": format!("SESSION_STATUS_{status}")});
    if let Some(connection) = connection {
        row["connection_status"] = Value::from(connection);
    }
    row
}

/// The toolbox, recorded: session rows and each session's events, paged.
#[derive(Default)]
struct Recorded {
    rows: Vec<Value>,
    transcripts: BTreeMap<String, Vec<Value>>,
    page: usize,
    /// Every events call, as `(session, before, after)`.
    calls: Vec<(String, Option<String>, Option<String>)>,
    unreadable: bool,
}

impl Recorded {
    fn new(page: usize) -> Self {
        Self {
            page,
            ..Self::default()
        }
    }

    fn child(mut self, row: Value, events: Vec<Value>) -> Self {
        let id = row["id"].as_str().unwrap().to_owned();
        self.rows.push(row);
        self.transcripts.insert(id, events);
        self
    }

    fn id(session: &str, index: usize) -> String {
        format!("{session}#{index}")
    }

    fn index(cursor: &str) -> usize {
        cursor.rsplit('#').next().unwrap().parse().unwrap()
    }
}

impl Source for Recorded {
    fn sessions(&mut self, _after: Option<&str>) -> Option<Page> {
        if self.unreadable {
            return None;
        }
        Some(Page {
            items: self.rows.clone(),
            ..Page::default()
        })
    }

    fn events(&mut self, session: &str, before: Option<&str>, after: Option<&str>) -> Option<Page> {
        self.calls.push((
            session.to_owned(),
            before.map(str::to_owned),
            after.map(str::to_owned),
        ));
        if self.unreadable {
            return None;
        }
        let all = self.transcripts.get(session)?;
        let (start, end) = match (before, after) {
            (_, Some(after)) => {
                let start = Self::index(after) + 1;
                (start, (start + self.page).min(all.len()))
            }
            (Some(before), None) => {
                let end = Self::index(before);
                (end.saturating_sub(self.page), end)
            }
            (None, None) => (all.len().saturating_sub(self.page), all.len()),
        };
        let start = start.min(all.len());
        let items = all[start..end.max(start)].to_vec();
        Some(Page {
            first_id: (!items.is_empty()).then(|| Self::id(session, start)),
            last_id: (!items.is_empty()).then(|| Self::id(session, end - 1)),
            has_more: if after.is_some() {
                end < all.len()
            } else {
                start > 0
            },
            items,
        })
    }
}

fn cache(name: &str) -> Cache {
    Cache::new(common::scratch(&format!("session-watch-{name}")))
}

fn single(name: &str, source: &mut Recorded) -> (State, Inventory, Option<Ending>) {
    let mut watch = Watch::new(Vec::new());
    let (reports, ending) = watch
        .poll(source, &cache(name))
        .expect("the source answers");
    let report = reports.into_iter().next().expect("one child");
    (report.state, report.inventory, ending)
}

/// Fails by: idle read as done while a backgrounded job still runs — the
/// measured case, a child idle with its shard launched and never notified.
#[test]
fn a_child_with_an_unnotified_launch_is_waiting_not_done() {
    let mut source = Recorded::new(2).child(
        row("session_waiting", "IDLE", Some("connected")),
        events("worker-events.json"),
    );
    let (state, inventory, ending) = single("waiting", &mut source);
    assert_eq!(state, State::Waiting);
    assert_eq!(inventory.open(), ["bgwg3bqcd"]);
    assert_eq!(ending, None, "a waiting child ends nothing");
}

/// Fails by: a notified launch still counted open, or done never reached.
#[test]
fn a_child_whose_every_launch_notified_is_done() {
    let mut transcript = events("worker-events.json");
    transcript.extend(events("shard-exit.json"));
    let mut source = Recorded::new(2).child(row("session_done", "IDLE", None), transcript);
    let mut watch = Watch::new(Vec::new());
    let (reports, ending) = watch.poll(&mut source, &cache("done")).unwrap();
    assert_eq!(reports[0].state, State::Done);
    assert_eq!(ending, Some(Ending::Done));
    assert_eq!(
        reports[0].line(),
        "session_done done open=0 exited=bgwg3bqcd,bt0h7b90r"
    );
    let shard = &reports[0].inventory.exited["bgwg3bqcd"];
    assert_eq!((shard.status.as_str(), shard.code), ("failed", Some(100)));
}

/// Fails by: a dead worker's open tasks read as still waiting, or a dead child
/// with nothing open read as done.
#[test]
fn a_disconnected_child_is_dead_whatever_is_open() {
    let mut finished = events("worker-events.json");
    finished.extend(events("shard-exit.json"));
    for (name, transcript) in [("open", events("worker-events.json")), ("closed", finished)] {
        let mut source = Recorded::new(100).child(
            row("session_dead", "RUNNING", Some("disconnected")),
            transcript,
        );
        let (state, _, ending) = single(&format!("dead-{name}"), &mut source);
        assert_eq!(state, State::Dead, "{name}");
        assert_eq!(ending, Some(Ending::Dead), "{name}");
    }
    // Archived with a task open: its container is gone, so the task never notifies.
    let mut source = Recorded::new(100).child(
        row("session_archived", "ARCHIVED", None),
        events("worker-events.json"),
    );
    let mut watch = Watch::new(vec!["session_archived".to_owned()]);
    let (reports, _) = watch.poll(&mut source, &cache("archived-open")).unwrap();
    assert_eq!(reports[0].state, State::Dead);
}

/// Fails by: a cold page skipping the transcript's start, a warm one re-reading
/// it, or a torn cache answering differently from no cache at all.
#[test]
fn a_cache_miss_pages_from_the_start_and_rebuilds_the_same_answer() {
    let mut transcript = events("worker-events.json");
    let mut source = Recorded::new(2).child(row("session_paged", "IDLE", None), transcript.clone());
    let cold = refresh(&mut source, "session_paged", None).expect("cold rebuild");
    assert!(
        cold.handoff && cold.prompted,
        "the first page was read: {cold:?}"
    );
    assert_eq!(
        source.calls.len(),
        3,
        "six events in pages of two, newest first"
    );

    // The transcript grows; a warm refresh pages forward from the cursor only.
    transcript.extend(events("shard-exit.json"));
    source
        .transcripts
        .insert("session_paged".to_owned(), transcript.clone());
    source.calls.clear();
    let warm = refresh(&mut source, "session_paged", Some(cold)).expect("warm refresh");
    assert!(
        source
            .calls
            .iter()
            .all(|(_, before, after)| before.is_none() && after.is_some()),
        "a hit pages forward only: {:?}",
        source.calls
    );

    let rebuilt = refresh(&mut source, "session_paged", None).expect("cold rebuild");
    assert_eq!(
        warm, rebuilt,
        "the cache is an accelerator, never the authority"
    );

    // A torn write reads as a miss and rebuilds the same answer.
    let store = cache("torn");
    let dir = common::scratch("session-watch-torn");
    std::fs::write(
        dir.join("session_paged.json"),
        b"{\"cursor\":\"session_paged#",
    )
    .unwrap();
    assert_eq!(store.load("session_paged"), None);
    let mut watch = Watch::new(Vec::new());
    let (reports, _) = watch.poll(&mut source, &store).unwrap();
    assert_eq!(reports[0].inventory, rebuilt);
}

/// Fails by: a source that could not be read answered as done, or as no
/// children and therefore nothing to wait on.
#[test]
fn an_unreadable_source_is_could_not_look_never_done() {
    let mut source =
        Recorded::new(2).child(row("session_x", "IDLE", None), events("worker-events.json"));
    source.unreadable = true;
    let mut watch = Watch::new(Vec::new());
    assert!(watch.poll(&mut source, &cache("unreadable")).is_none());

    // Readable rows but an unreadable transcript is could-not-look too.
    source.unreadable = false;
    source.transcripts.clear();
    assert!(
        watch
            .poll(&mut source, &cache("unreadable-events"))
            .is_none()
    );
}

/// CLOUD-2826's comment: a child past `turn_handoff_available` with no `user`
/// event after it never received its task. Over the recorded transcript of the
/// measured case, it is unstarted, and the watch ends on it only after
/// [`UNSTARTED_POLLS`] consecutive polls, never on the first.
#[test]
fn a_child_whose_prompt_never_arrived_is_unstarted() {
    let mut source = Recorded::new(100).child(
        row("session_unstarted", "IDLE", None),
        events("unstarted-events.json"),
    );
    let mut watch = Watch::new(Vec::new());
    let store = cache("unstarted");
    for poll in 1..=UNSTARTED_POLLS {
        let (reports, ending) = watch.poll(&mut source, &store).unwrap();
        assert_eq!(reports[0].state, State::Unstarted);
        let expected = (poll == UNSTARTED_POLLS).then_some(Ending::Dead);
        assert_eq!(ending, expected, "poll {poll}");
    }
    // Once a prompt lands, the same child is no longer unstarted.
    let mut inventory = Inventory::default();
    inventory.fold(&events("worker-events.json"));
    let idle = Row::of(&row("s", "IDLE", None)).unwrap();
    assert_ne!(state(&idle, &inventory), State::Unstarted);
}
