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
    /// How many session-list pages were asked for.
    session_calls: usize,
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
    fn sessions(&mut self, after: Option<&str>) -> Option<Page> {
        self.session_calls += 1;
        if self.unreadable {
            return None;
        }
        // Paged like the toolbox: `after` is the last id of the page before.
        let start = after.map_or(0, |after| {
            self.rows
                .iter()
                .position(|row| row["id"] == after)
                .map_or(self.rows.len(), |at| at + 1)
        });
        let end = (start + self.page).min(self.rows.len());
        let items = self.rows[start..end].to_vec();
        Some(Page {
            first_id: items
                .first()
                .map(|row| row["id"].as_str().unwrap().to_owned()),
            last_id: items
                .last()
                .map(|row| row["id"].as_str().unwrap().to_owned()),
            has_more: end < self.rows.len(),
            items,
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

/// Fails by: an archived child watched when none is named (it takes no further
/// turn), or the live one beside it dropped.
#[test]
fn an_archived_child_is_not_watched_unless_named() {
    let mut source = Recorded::new(100)
        .child(
            row("session_live", "IDLE", None),
            events("worker-events.json"),
        )
        .child(
            row("session_gone", "ARCHIVED", None),
            events("worker-events.json"),
        );
    let mut watch = Watch::new(Vec::new());
    let (reports, _) = watch.poll(&mut source, &cache("archived")).unwrap();
    let sessions: Vec<&str> = reports.iter().map(|r| r.session.as_str()).collect();
    assert_eq!(sessions, ["session_live"]);
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

/// The `child-session` event a child's ending dispatches (CLOUD-2826): its name
/// is the state, its input is tokens only, and only a child that ENDED fires —
/// a waiting child, or an unstarted one short of the poll count, does not.
#[test]
fn an_ended_child_dispatches_its_state_as_a_child_session_event() {
    use batten::config_model::Event;
    use batten::session_watch::{ending_key, envelope};

    let mut transcript = events("worker-events.json");
    transcript.extend(events("shard-exit.json"));
    let mut source = Recorded::new(100)
        .child(row("session_done", "IDLE", None), transcript)
        .child(
            row("session_waiting", "IDLE", None),
            events("worker-events.json"),
        );
    let mut watch = Watch::new(Vec::new());
    let (reports, _) = watch.poll(&mut source, &cache("events")).unwrap();
    let done = reports
        .iter()
        .find(|r| r.session == "session_done")
        .unwrap();
    let waiting = reports
        .iter()
        .find(|r| r.session == "session_waiting")
        .unwrap();

    assert!(watch.ended(done));
    assert!(!watch.ended(waiting), "a waiting child ends nothing");
    let event = envelope(done);
    assert_eq!(event.event, Event::ChildSession);
    assert_eq!(event.raw_tool, "session.done");
    assert_eq!(
        event.input,
        serde_json::json!({"session": "session_done", "state": "done", "open": []})
    );
    assert!(
        !event.input.to_string().contains("Run shard"),
        "no transcript byte reaches the event"
    );
    assert_ne!(ending_key(done), ending_key(waiting));

    // Unstarted ends, and so dispatches, only at the poll count.
    let mut source = Recorded::new(100).child(
        row("session_unstarted", "IDLE", None),
        events("unstarted-events.json"),
    );
    let mut watch = Watch::new(Vec::new());
    let store = cache("events-unstarted");
    for poll in 1..=UNSTARTED_POLLS {
        let (reports, _) = watch.poll(&mut source, &store).unwrap();
        assert_eq!(
            watch.ended(&reports[0]),
            poll == UNSTARTED_POLLS,
            "poll {poll}"
        );
    }
}

/// A recorded toolbox answer about another session: one text block wrapping
/// the record in the host's `<other-session nonce=…>` envelope.
fn wrapped(document: &Value) -> Value {
    let text = format!(
        "<other-session nonce=\"9f\" untrusted=\"true\">\nAnother Claude session's record (JSON):\n    {document}\n</other-session nonce=\"9f\">"
    );
    serde_json::json!({"content": [{"type": "text", "text": text}]})
}

/// Fails by: a page read wrong off the toolbox's answer, an enveloped record
/// left unread, or a failed or pageless result answered as an empty page.
#[test]
fn a_recorded_answer_decodes_to_its_page_and_a_failed_one_to_could_not_look() {
    use batten::session_watch::{document, page_of_result};

    let recorded: Value = serde_json::from_str(
        &std::fs::read_to_string(common::at_root(
            "crates/batten/tests/fixtures/session-watch/worker-events.json",
        ))
        .unwrap(),
    )
    .unwrap();
    // Bare (this session's own answer) and enveloped (another's) read alike.
    assert_eq!(document(&recorded), Some(recorded.clone()));
    for answer in [recorded.clone(), wrapped(&recorded)] {
        let page = page_of_result(&answer).expect("a page");
        assert_eq!(page.items.len(), 6);
        assert_eq!(page.first_id.as_deref(), Some("w0"));
        assert_eq!(page.last_id.as_deref(), Some("w5"));
        assert!(!page.has_more);
    }
    let more = serde_json::json!({"ccr": {"data": [], "has_more": true}});
    assert!(Page::of(&more).unwrap().has_more);

    let failed =
        serde_json::json!({"isError": true, "content": [{"type": "text", "text": "denied"}]});
    assert_eq!(page_of_result(&failed), None);
    assert_eq!(
        page_of_result(&serde_json::json!({"ccr": {"note": "no data"}})),
        None
    );
}

/// Fails by: a cursor dropped from, or a stray key added to, the toolbox's
/// arguments.
#[test]
fn the_toolbox_is_asked_for_children_and_pages_by_cursor() {
    use batten::session_watch::{PAGE, events_arguments, sessions_arguments};

    assert_eq!(
        sessions_arguments(None),
        serde_json::json!({"children": true, "limit": PAGE})
    );
    assert_eq!(
        sessions_arguments(Some("s9")),
        serde_json::json!({"children": true, "limit": PAGE, "after_id": "s9"})
    );
    assert_eq!(
        events_arguments("s1", Some("e4"), None),
        serde_json::json!({"session_id": "s1", "limit": PAGE, "before_id": "e4"})
    );
    assert_eq!(
        events_arguments("s1", None, Some("e7")),
        serde_json::json!({"session_id": "s1", "limit": PAGE, "after_id": "e7"})
    );
}

/// Fails by: a child on a later page of the session list never watched, or
/// the list paged past its last page.
#[test]
fn every_page_of_children_is_watched_and_no_more() {
    let mut source = Recorded::new(2);
    for id in ["session_a", "session_b", "session_c"] {
        source = source.child(row(id, "IDLE", None), events("worker-events.json"));
    }
    let mut watch = Watch::new(Vec::new());
    let (reports, _) = watch.poll(&mut source, &cache("paged-children")).unwrap();
    let ids: Vec<&str> = reports.iter().map(|r| r.session.as_str()).collect();
    assert_eq!(ids, ["session_a", "session_b", "session_c"]);
    assert_eq!(source.session_calls, 2, "three children in pages of two");
}

/// Fails by: a dead child outranked by a done one, or the backoff not
/// doubling between polls.
#[test]
fn a_dead_child_outranks_a_done_one_and_the_wait_backs_off() {
    use batten::session_watch::{FIRST_DELAY, run};

    let mut finished = events("worker-events.json");
    finished.extend(events("shard-exit.json"));
    let mut source = Recorded::new(100)
        .child(row("session_done", "IDLE", None), finished)
        .child(
            row("session_dead", "IDLE", Some("disconnected")),
            events("worker-events.json"),
        );
    let mut watch = Watch::new(Vec::new());
    let (_, ending) = watch.poll(&mut source, &cache("rank")).unwrap();
    assert_eq!(ending, Some(Ending::Dead));
    assert!(Ending::Dead > Ending::Done && Ending::Done > Ending::Nothing);

    // An unstarted child ends the run at the poll count, after two waits.
    let mut source = Recorded::new(100).child(
        row("session_unstarted", "IDLE", None),
        events("unstarted-events.json"),
    );
    let mut waits = Vec::new();
    let mut wait = |delay| waits.push(delay);
    let mut watch = Watch::new(Vec::new());
    let (_, ending) = run(&mut watch, &mut source, &cache("backoff"), &mut wait).unwrap();
    assert_eq!(ending, Ending::Dead);
    assert_eq!(waits, [FIRST_DELAY, FIRST_DELAY * 2]);
}

/// Fails by: a session id that could name another path accepted as a cache
/// file name, a well-formed one refused, or the cache not round-tripping.
#[test]
fn the_cache_keeps_a_well_formed_session_and_refuses_a_path() {
    let store = cache("round-trip");
    let mut inventory = Inventory::default();
    inventory.fold(&events("worker-events.json"));
    inventory.cursor = Some("w5".to_owned());
    store.store("session_01Gg-x9", &inventory);
    assert_eq!(store.load("session_01Gg-x9"), Some(inventory.clone()));
    for bad in ["../escape", "a/b", "a.b", ""] {
        store.store(bad, &inventory);
        assert_eq!(store.load(bad), None, "{bad:?}");
    }
}

/// Fails by: the inventory capture or the state directory answered empty.
#[test]
fn the_inventory_capture_names_each_childs_state_and_tasks() {
    use batten::session_watch::{inventory_document, state_dir};

    let mut source = Recorded::new(100).child(
        row("session_waiting", "IDLE", None),
        events("worker-events.json"),
    );
    let mut watch = Watch::new(Vec::new());
    let (reports, _) = watch.poll(&mut source, &cache("capture")).unwrap();
    let document = inventory_document(&reports);
    assert_eq!(document[0]["session"], "session_waiting");
    assert_eq!(document[0]["state"], "waiting");
    assert_eq!(document[0]["open"], serde_json::json!(["bgwg3bqcd"]));
    assert_eq!(document[0]["exited"]["bt0h7b90r"]["code"], 0);

    let dir = state_dir(&common::at_root(".")).expect("the state directory resolves");
    assert!(dir.ends_with("session-watch"), "{}", dir.display());
}
