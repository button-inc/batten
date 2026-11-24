//! A parent session's children, followed to done or dead (CLOUD-2826).
//!
//! # Why this exists
//!
//! A session can dispatch child cloud sessions, and nothing tells the parent
//! when one finishes, fails or stalls. A child's own message reaches the parent
//! only if it sends one; its background work runs in another container, so no
//! local task exit can wake the parent; and `idle` is not `done` — a child reads
//! idle while its own backgrounded jobs run. Telling those apart by reading the
//! child's last words is a model's prose, which rule 3 forbids a gate deciding on.
//!
//! # What is decided, and from what
//!
//! Every fact is the child's own transcript or its session row:
//!
//! * **open tasks** = launched − notified, over the whole transcript. A launch is
//!   the host's `task_started` system event; an exit is its `task_notification`,
//!   carrying the status and, in its summary, the exit code. This is the pairing
//!   [`batten_base::background::exits`] does for this session's own transcript,
//!   read here off another session's.
//! * **unstarted**: the child passed `turn_handoff_available` and no `user` event
//!   followed it — its prompt never arrived. Measured 2026-11-23 on two children
//!   the session list called working (CLOUD-2826's comment).
//! * **dead**: the session row says `disconnected` (its worker died mid-turn), or
//!   it was archived with tasks still open, which can now never notify.
//!
//! [`state`] maps those to five states, and [`Watch::poll`] exits the verb at the
//! first child that is done, dead, or unstarted across [`UNSTARTED_POLLS`]
//! consecutive polls — a count, not a clock, because a child created a moment
//! ago is idle past its handoff until its prompt lands.
//!
//! # The cache is an accelerator, never the authority
//!
//! Per child it holds the reduction only ([`Inventory`]): the last event id read,
//! the launched ids and each exit. A hit pages forward from that id; a miss —
//! absent, evicted, or a torn write that will not decode — pages from the
//! session's start and rebuilds the same answer, which
//! `a_cache_miss_pages_from_the_start_and_rebuilds_the_same_answer` pins.
//!
//! # The host's vocabulary, not a consumer's
//!
//! The method names, their parameters and the event subtypes below are the
//! Claude Code Remote toolbox's own wire format, the same class as the
//! `<task-notification>` tag `background.rs` reads. Which declared MCP server
//! answers them is the consumer's fact and arrives as `--server`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The toolbox method listing sessions.
pub const LIST_SESSIONS: &str = "list_sessions";
/// The toolbox method listing one session's transcript events.
pub const LIST_EVENTS: &str = "list_events";
/// A page's size, the toolbox's own maximum.
pub const PAGE: u64 = 100;
/// Consecutive polls a child must read unstarted before the watch ends on it.
pub const UNSTARTED_POLLS: u32 = 3;

/// The system subtype a launched task logs.
const STARTED: &str = "task_started";
/// The system subtype an exited task logs.
const NOTIFIED: &str = "task_notification";
/// The system subtype a warm session logs when it can take its first turn.
const HANDOFF: &str = "turn_handoff_available";

/// How one task ended, as its notification says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exited {
    /// The host's status word: `completed`, `failed`, `killed`, ….
    pub status: String,
    /// The exit code its summary names, where it names one.
    pub code: Option<i64>,
}

/// One child's transcript, reduced (the cache's whole content).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// The newest event id folded in, the forward-paging cursor.
    pub cursor: Option<String>,
    /// Every task id the transcript launched.
    pub launched: BTreeSet<String>,
    /// Every task id the transcript reported exited, and how.
    pub exited: BTreeMap<String, Exited>,
    /// Whether a `turn_handoff_available` was seen.
    pub handoff: bool,
    /// Whether a `user` event followed the latest handoff.
    pub prompted: bool,
}

impl Inventory {
    /// The launched ids no notification has answered.
    #[must_use]
    pub fn open(&self) -> Vec<&str> {
        self.launched
            .iter()
            .filter(|id| !self.exited.contains_key(*id))
            .map(String::as_str)
            .collect()
    }

    /// Fold `events`, oldest first, into this reduction.
    pub fn fold(&mut self, events: &[Value]) {
        for event in events {
            let Some((kind, body)) = kind_of(event) else {
                continue;
            };
            let inner = body.get("internal_anthropic_catchall").unwrap_or(body);
            match kind {
                "system" => self.fold_system(inner),
                // Unguarded on purpose: a `user` event before any handoff sets
                // `prompted`, and the handoff that follows resets it, so only a
                // `user` event AFTER the latest handoff survives to be read.
                "user" => self.prompted = true,
                _ => {}
            }
        }
    }

    fn fold_system(&mut self, inner: &Value) {
        let field = |name: &str| inner.get(name).and_then(Value::as_str);
        let task = field("task_id").filter(|id| !id.is_empty());
        match field("subtype") {
            Some(STARTED) => {
                if let Some(id) = task {
                    self.launched.insert(id.to_owned());
                }
            }
            Some(NOTIFIED) => {
                if let Some(id) = task {
                    // A notification for a launch this page range never saw is
                    // still a launch: the pairing is over ids, and an exit proves
                    // the task existed.
                    self.launched.insert(id.to_owned());
                    self.exited.insert(
                        id.to_owned(),
                        Exited {
                            status: field("status").unwrap_or("unknown").to_owned(),
                            code: field("summary").and_then(exit_code),
                        },
                    );
                }
            }
            Some(HANDOFF) => {
                self.handoff = true;
                self.prompted = false;
            }
            _ => {}
        }
    }
}

/// An event's kind — its one key beside `created_at` and `id` — and its body.
fn kind_of(event: &Value) -> Option<(&str, &Value)> {
    event
        .as_object()?
        .iter()
        .find(|(key, _)| key.as_str() != "created_at" && key.as_str() != "id")
        .map(|(key, body)| (key.as_str(), body))
}

/// The integer after `exit code ` in a notification summary.
fn exit_code(summary: &str) -> Option<i64> {
    let rest = &summary[summary.find("exit code ")? + "exit code ".len()..];
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

/// One row of the session list, as much of it as the states read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The session id.
    pub id: String,
    /// `session_status`: `SESSION_STATUS_RUNNING`, `…_IDLE`, `…_ARCHIVED`.
    pub status: String,
    /// `connection_status`, where the list carries it.
    pub connection: Option<String>,
}

impl Row {
    /// The row a list entry describes, or `None` where it names no session.
    #[must_use]
    pub fn of(entry: &Value) -> Option<Self> {
        let text = |name: &str| entry.get(name).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            id: text("id")?,
            status: text("session_status").unwrap_or_default(),
            connection: text("connection_status"),
        })
    }

    fn is(&self, status: &str) -> bool {
        self.status.ends_with(status)
    }

    /// Whether the session was archived: it takes no further turn.
    #[must_use]
    pub fn archived(&self) -> bool {
        self.is("ARCHIVED")
    }
}

/// What a child is doing, from facts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// A turn is open.
    Working,
    /// Idle, connected, with tasks still open.
    Waiting,
    /// Past its handoff with no prompt after it.
    Unstarted,
    /// Idle with nothing open.
    Done,
    /// Disconnected, or archived with tasks that will never notify.
    Dead,
}

impl State {
    /// The word the pointer line prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Waiting => "waiting",
            Self::Unstarted => "unstarted",
            Self::Done => "done",
            Self::Dead => "dead",
        }
    }
}

/// A child's state from its row and its reduced transcript.
#[must_use]
pub fn state(row: &Row, inventory: &Inventory) -> State {
    if row.connection.as_deref() == Some("disconnected") {
        return State::Dead;
    }
    if row.is("RUNNING") {
        return State::Working;
    }
    if inventory.handoff && !inventory.prompted {
        return State::Unstarted;
    }
    match (inventory.open().is_empty(), row.archived()) {
        (true, _) => State::Done,
        (false, true) => State::Dead,
        (false, false) => State::Waiting,
    }
}

/// One page of a listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// The items, oldest first.
    pub items: Vec<Value>,
    /// The oldest item's id, the backward cursor.
    pub first_id: Option<String>,
    /// The newest item's id, the forward cursor.
    pub last_id: Option<String>,
    /// Whether more remain past this page.
    pub has_more: bool,
}

impl Page {
    /// The page a toolbox answer carries, or `None` where it carries none.
    #[must_use]
    pub fn of(document: &Value) -> Option<Self> {
        let body = document.get("ccr").unwrap_or(document);
        let text = |name: &str| body.get(name).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            items: body.get("data")?.as_array()?.clone(),
            first_id: text("first_id"),
            last_id: text("last_id"),
            has_more: body
                .get("has_more")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

/// The document an MCP result carries, unwrapping the toolbox's
/// `<other-session nonce=…>` envelope around another session's record.
///
/// The envelope is the host marking the bytes as data, not instructions, and
/// that is exactly how they are used here: read for ids and subtypes, never
/// followed. Only the closing tag carrying the opening tag's nonce ends it.
#[must_use]
pub fn document(payload: &Value) -> Option<Value> {
    if payload.get("ccr").is_some() || payload.get("data").is_some() {
        return Some(payload.clone());
    }
    let text = payload
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()?;
    let opening = text.find("<other-session")?;
    let nonce_at = opening + text[opening..].find("nonce=\"")? + "nonce=\"".len();
    let nonce = &text[nonce_at..nonce_at + text[nonce_at..].find('"')?];
    let close = text.rfind(&format!("</other-session nonce=\"{nonce}\">"))?;
    let start = nonce_at + text[nonce_at..close].find('{')?;
    serde_json::from_str(text[start..close].trim()).ok()
}

/// Where the watch reads its facts: the toolbox, or a recording of it.
pub trait Source {
    /// One page of the calling session's children, after `after`. `None` is
    /// could-not-look.
    fn sessions(&mut self, after: Option<&str>) -> Option<Page>;
    /// One page of a session's events: the newest page with no cursor, the page
    /// before `before`, or the page after `after`. `None` is could-not-look.
    fn events(&mut self, session: &str, before: Option<&str>, after: Option<&str>) -> Option<Page>;
}

/// Where each child's reduction is kept between polls and runs.
#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    /// A cache under `dir`.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn file(&self, session: &str) -> Option<PathBuf> {
        // Non-empty: an empty id would name the file `.json`, which no session is.
        (!session.is_empty()
            && session
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .then(|| self.dir.join(format!("{session}.json")))
    }

    /// The kept reduction, or `None` on any miss — absent, evicted, torn.
    #[must_use]
    pub fn load(&self, session: &str) -> Option<Inventory> {
        let bytes = crate::fsio::read(&self.file(session)?).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Keep `inventory`. A failed write costs the next run a cold page, never
    /// an answer, so it is not an error.
    pub fn store(&self, session: &str, inventory: &Inventory) {
        let Some(file) = self.file(session) else {
            return;
        };
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        if let Ok(body) = serde_json::to_vec(inventory) {
            drop(crate::durable::replace(file, body));
        }
    }
}

/// The ceiling on pages read for one child in one refresh: a transcript longer
/// than this is a source that will not stop answering, and could-not-look.
const MAX_PAGES: usize = 10_000;

/// `session`'s reduction, brought up to date from `cached` or rebuilt.
///
/// A cached cursor pages forward; any failure on that path falls back to the
/// cold rebuild rather than answering from a stale reduction. `None` only when
/// the cold rebuild could not read either.
pub fn refresh(
    source: &mut dyn Source,
    session: &str,
    cached: Option<Inventory>,
) -> Option<Inventory> {
    if let Some(mut inventory) = cached.filter(|cached| cached.cursor.is_some())
        && forward(source, session, &mut inventory).is_some()
    {
        return Some(inventory);
    }
    rebuild(source, session)
}

fn forward(source: &mut dyn Source, session: &str, inventory: &mut Inventory) -> Option<()> {
    for _ in 0..MAX_PAGES {
        let page = source.events(session, None, inventory.cursor.as_deref())?;
        if page.items.is_empty() {
            return Some(());
        }
        inventory.fold(&page.items);
        if page.last_id.is_some() {
            inventory.cursor = page.last_id;
        }
    }
    None
}

fn rebuild(source: &mut dyn Source, session: &str) -> Option<Inventory> {
    let newest = source.events(session, None, None)?;
    let cursor = newest.last_id.clone();
    let mut pages = vec![newest];
    for _ in 0..MAX_PAGES {
        let Some(last) = pages.last() else { break };
        if !last.has_more {
            let mut inventory = Inventory::default();
            for page in pages.iter().rev() {
                inventory.fold(&page.items);
            }
            inventory.cursor = cursor;
            return Some(inventory);
        }
        let before = last.first_id.clone()?;
        pages.push(source.events(session, Some(&before), None)?);
    }
    None
}

/// One child's answer for this poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The session id.
    pub session: String,
    /// Its state.
    pub state: State,
    /// Its reduced transcript.
    pub inventory: Inventory,
}

impl Report {
    /// The reading a `child-state` receipt is minted from (CLOUD-2900):
    /// `{"state": <word>, "open": "<id>,<id>"}`, with `open` omitted when
    /// nothing is open, so the row's `{open}` piece records the absent token.
    ///
    /// **The newest complete read, never a page of one.** It is built after the
    /// whole transcript is paired, which is what a `[[mint]]` row over one raw
    /// `list_events` result cannot do: a page shows only the launches on it.
    #[must_use]
    pub fn reading(&self) -> Value {
        let mut reading = serde_json::json!({"state": self.state.as_str()});
        let open = self.inventory.open();
        if !open.is_empty() {
            reading["open"] = Value::from(open.join(","));
        }
        reading
    }

    /// The pointer line: `<session> <state> open=<n> exited=<ids,…>`.
    #[must_use]
    pub fn line(&self) -> String {
        let exited: Vec<&str> = self.inventory.exited.keys().map(String::as_str).collect();
        format!(
            "{} {} open={} exited={}",
            self.session,
            self.state.as_str(),
            self.inventory.open().len(),
            if exited.is_empty() {
                "-".to_owned()
            } else {
                exited.join(",")
            }
        )
    }
}

/// The data channel's one funnel (CLOUD-371): `session watch` writes a report
/// through `output::line`, never a bare `writeln!`.
impl crate::output::Line for Report {
    fn line(&self) -> String {
        Report::line(self)
    }
}

/// Where a poll mints each child's reading (CLOUD-2900): a sink handed each
/// report's input (`{"session_id": <id>}`) and its [`Report::reading`].
///
/// **The engine names no receipt, and this module names no minting authority.**
/// `run_session` passes a sink over the crate's one minting authority, the
/// resolved `[[mint]]` rows, the bare method [`LIST_EVENTS`] and
/// [`store_root`]'s checkout; which receipt that writes, if any, is the
/// consumer's row to declare. Injected rather than called, so this module's
/// closure stays its own (`module_closure.rs`).
///
/// **The store is [`store_root`]'s git dir**, the checkout the hook judges a
/// structured call from: a linked worktree carrying the authority is its own
/// root, so the watch's read and the `send_message` hook's clear of it land in
/// one store, the one the `archive_session` gate reads.
#[derive(Clone, Copy)]
pub struct Mints<'a> {
    sink: Option<&'a dyn Fn(&Value, &Value)>,
}

impl std::fmt::Debug for Mints<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mints")
            .field("sink", &self.sink.is_some())
            .finish()
    }
}

impl<'a> Mints<'a> {
    /// Mint each report through `sink`, called with the input and the reading.
    #[must_use]
    pub const fn new(sink: &'a dyn Fn(&Value, &Value)) -> Self {
        Self { sink: Some(sink) }
    }

    /// No sink: a poll handed this mints nothing.
    #[must_use]
    pub const fn none() -> Mints<'static> {
        Mints { sink: None }
    }

    /// Mint `report`'s reading. Silent on every failure, as the mint boundary
    /// has always been: the gate that reads the receipt simply refuses again.
    fn mint(&self, report: &Report) {
        if let Some(sink) = self.sink {
            sink(
                &serde_json::json!({"session_id": report.session}),
                &report.reading(),
            );
        }
    }
}

/// The checkout a watch run from `start` mints into (CLOUD-2900): the linked
/// worktree's own root when it carries the authority, else the repository's,
/// which is the root the hook anchors a call with no path target on
/// (`config::anchor_at`, which asks the same question). [`crate::git::repo_root`] alone is the MAIN checkout
/// from a linked worktree, where the hook's clear and the gate's read would
/// never meet the receipt.
///
/// # Errors
///
/// As [`crate::git::authority_root`]: `start` is not inside a repository.
pub fn store_root(start: &Path) -> anyhow::Result<PathBuf> {
    crate::git::authority_root(start, crate::config_model::CONFIG_FILE)
}

/// How a watch ended, ordered by precedence: one dead child is the answer
/// whatever else ended, so `Dead` is declared last and outranks `Done`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ending {
    /// Nothing to watch: no unarchived child, or none of the named sessions.
    /// A statement about the invocation, since waiting on it would never end.
    Nothing,
    /// A child is done and none is dead or unstarted.
    Done,
    /// A child is dead, or unstarted across [`UNSTARTED_POLLS`] polls.
    Dead,
}

/// The watch's state across polls: which children, and each one's unstarted
/// streak.
#[derive(Debug, Clone, Default)]
pub struct Watch {
    /// The sessions named on the command line; empty watches the children.
    pub named: Vec<String>,
    streaks: BTreeMap<String, u32>,
}

impl Watch {
    /// A watch over `named`, or over the calling session's children when empty.
    #[must_use]
    pub fn new(named: Vec<String>) -> Self {
        Self {
            named,
            streaks: BTreeMap::new(),
        }
    }

    /// One poll: every watched child's report, and the ending it reaches, if
    /// any. `None` is could-not-look, which is never an ending.
    ///
    /// Each child's report is minted through `mints` once its transcript is
    /// stored (CLOUD-2900), so the newest receipt is the newest complete read.
    pub fn poll(
        &mut self,
        source: &mut dyn Source,
        cache: &Cache,
        mints: &Mints<'_>,
    ) -> Option<(Vec<Report>, Option<Ending>)> {
        let rows = self.rows(source)?;
        let mut reports = Vec::new();
        for row in rows {
            let inventory = refresh(source, &row.id, cache.load(&row.id))?;
            cache.store(&row.id, &inventory);
            let report = Report {
                state: state(&row, &inventory),
                session: row.id,
                inventory,
            };
            mints.mint(&report);
            reports.push(report);
        }
        reports.sort_by(|a, b| a.session.cmp(&b.session));
        if reports.is_empty() {
            return Some((reports, Some(Ending::Nothing)));
        }
        let mut ending = None;
        for report in &reports {
            let streak = self.streaks.entry(report.session.clone()).or_default();
            *streak = if report.state == State::Unstarted {
                streak.saturating_add(1)
            } else {
                0
            };
            let reached = match report.state {
                State::Dead => Some(Ending::Dead),
                State::Unstarted if *streak >= UNSTARTED_POLLS => Some(Ending::Dead),
                State::Done => Some(Ending::Done),
                _ => None,
            };
            ending = ending.max(reached);
        }
        Some((reports, ending))
    }

    /// Whether `report`'s child reached an ending on the last poll: done, dead,
    /// or unstarted across [`UNSTARTED_POLLS`] polls. The children whose
    /// ending dispatches an event.
    #[must_use]
    pub fn ended(&self, report: &Report) -> bool {
        match report.state {
            State::Done | State::Dead => true,
            State::Unstarted => self
                .streaks
                .get(&report.session)
                .is_some_and(|streak| *streak >= UNSTARTED_POLLS),
            State::Working | State::Waiting => false,
        }
    }

    /// The rows to judge: every listed child not archived, or the named ones.
    fn rows(&self, source: &mut dyn Source) -> Option<Vec<Row>> {
        let mut rows = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let page = source.sessions(after.as_deref())?;
            rows.extend(page.items.iter().filter_map(Row::of));
            if !page.has_more || page.last_id.is_none() {
                break;
            }
            after = page.last_id;
        }
        Some(if self.named.is_empty() {
            rows.into_iter().filter(|row| !row.archived()).collect()
        } else {
            rows.into_iter()
                .filter(|row| self.named.contains(&row.id))
                .collect()
        })
    }
}

/// The first delay between polls, doubled each poll up to [`MAX_DELAY`].
pub const FIRST_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
/// The longest delay between polls.
pub const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(60);

/// Poll until an ending, waiting with `wait` between polls, with backoff.
///
/// Returns the reports and ending that stopped it, or `None` the first time the
/// source could not be read — could-not-look ends the watch rather than being
/// retried into a silent wait, because a parent waiting on a source that will
/// not answer is waiting on nothing.
pub fn run(
    watch: &mut Watch,
    source: &mut dyn Source,
    cache: &Cache,
    mints: &Mints<'_>,
    wait: &mut dyn FnMut(std::time::Duration),
) -> Option<(Vec<Report>, Ending)> {
    let mut delay = FIRST_DELAY;
    loop {
        let (reports, ending) = watch.poll(source, cache, mints)?;
        if let Some(ending) = ending {
            return Some((reports, ending));
        }
        wait(delay);
        delay = (delay * 2).min(MAX_DELAY);
    }
}

/// The session toolbox over a declared MCP connection.
#[derive(Debug)]
pub struct Mcp {
    wiring: crate::mcp::Wiring,
}

impl Mcp {
    /// A source dispatching over `wiring`.
    #[must_use]
    pub const fn new(wiring: crate::mcp::Wiring) -> Self {
        Self { wiring }
    }

    /// The one live step: dispatch, then [`page_of_result`]. Everything it
    /// decides is in that function and the two argument builders, which the
    /// suite drives over recorded answers; this wrapper is the transport alone.
    fn call(&self, method: &str, arguments: &Value) -> Option<Page> {
        let params = serde_json::json!({"name": method, "arguments": arguments});
        let result = crate::mcp::dispatch(&self.wiring, "tools/call", &params).ok()?;
        page_of_result(&result)
    }
}

impl Source for Mcp {
    fn sessions(&mut self, after: Option<&str>) -> Option<Page> {
        self.call(LIST_SESSIONS, &sessions_arguments(after))
    }

    fn events(&mut self, session: &str, before: Option<&str>, after: Option<&str>) -> Option<Page> {
        self.call(LIST_EVENTS, &events_arguments(session, before, after))
    }
}

/// The `list_sessions` arguments for one page of the caller's children.
#[must_use]
pub fn sessions_arguments(after: Option<&str>) -> Value {
    let mut arguments = serde_json::json!({"children": true, "limit": PAGE});
    if let Some(after) = after {
        arguments["after_id"] = Value::from(after);
    }
    arguments
}

/// The `list_events` arguments for one page of `session`'s transcript.
#[must_use]
pub fn events_arguments(session: &str, before: Option<&str>, after: Option<&str>) -> Value {
    let mut arguments = serde_json::json!({"session_id": session, "limit": PAGE});
    if let Some(before) = before {
        arguments["before_id"] = Value::from(before);
    }
    if let Some(after) = after {
        arguments["after_id"] = Value::from(after);
    }
    arguments
}

/// The page a `tools/call` result carries: `None` for a result the server
/// marked failed or one whose payload carries no page — could-not-look, never
/// an empty page, because an empty transcript and an unread one must not read
/// alike.
#[must_use]
pub fn page_of_result(result: &Value) -> Option<Page> {
    if crate::mcp::failed(result) {
        return None;
    }
    Page::of(&document(&crate::mcp::payload(result).value)?)
}

/// The hook event a child's ending dispatches (CLOUD-2826): `session.done`,
/// `session.dead` or `session.unstarted`, on [`crate::config_model::Event::ChildSession`].
///
/// A `[[hook.handler]]` row on `child-session` selects it by that name through
/// its `matcher`, as a `forge` row selects `pull_request.opened`. The input is
/// tokens only — the session id, the state, the open count and the open task
/// ids — never a transcript byte (rule 4).
#[must_use]
pub fn envelope(report: &Report) -> crate::hook::Envelope {
    use crate::config_model::Event;
    use crate::hook::EventExt as _;
    let state = report.state.as_str();
    crate::hook::Envelope {
        event: Event::ChildSession,
        raw_event: Event::ChildSession.as_str().to_owned(),
        raw_tool: format!("session.{state}"),
        operation: crate::hook::Operation::Other("session".to_owned()),
        input: serde_json::json!({
            "session": report.session,
            "state": state,
            "open": report.inventory.open(),
        }),
        result: Value::Null,
        command: String::new(),
        writes: None,
        reads: None,
        cwd: None,
        session: None,
        agent: None,
        start_source: None,
        call_id: None,
        background_ceiling: None,
        stop_active: None,
        last_message: None,
        transcript: None,
        mode: None,
        forge: None,
        mediated: None,
    }
}

/// The key one ending is remembered under, so a later watch over the same
/// unchanged transcript does not fire it again: the session, the state, and
/// the newest event read. A child that takes another turn and ends again has a
/// new cursor, and so a new key.
#[must_use]
pub fn ending_key(report: &Report) -> String {
    format!(
        "{}:{}:{}",
        report.session,
        report.state.as_str(),
        report.inventory.cursor.as_deref().unwrap_or("-")
    )
}

/// The full inventory, as the capture file holds it.
#[must_use]
pub fn inventory_document(reports: &[Report]) -> Value {
    Value::Array(
        reports
            .iter()
            .map(|report| {
                serde_json::json!({
                    "session": report.session,
                    "state": report.state.as_str(),
                    "open": report.inventory.open(),
                    "exited": report.inventory.exited,
                })
            })
            .collect(),
    )
}

/// Where the cache and the inventory capture live under a repository's state.
///
/// # Errors
///
/// The state directory could not be resolved.
pub fn state_dir(repo_root: &Path) -> anyhow::Result<PathBuf> {
    Ok(crate::state::repo_state_dir(repo_root)?.join("session-watch"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fails by: the transport answering a page where the dispatch failed, so
    /// a source nothing answered reads as a child with no events.
    #[test]
    fn a_dispatch_that_fails_reads_as_could_not_look() {
        let mut source = Mcp::new(crate::mcp::Wiring {
            source: "s".to_owned(),
            endpoint: "https://mcp.invalid/mcp".to_owned(),
            headers: Vec::new(),
            credential: None,
        });
        assert!(source.events("s1", None, None).is_none());
    }

    #[test]
    fn an_exit_code_is_read_from_the_summary_and_absent_when_unnamed() {
        assert_eq!(
            exit_code("Background command \"x\" failed with exit code 100"),
            Some(100)
        );
        assert_eq!(exit_code("(exit code 0)"), Some(0));
        assert_eq!(exit_code("Push the branch"), None);
    }

    /// A child that stays running for `polls` polls and then is gone.
    struct Running {
        polls: usize,
    }

    impl Source for Running {
        fn sessions(&mut self, _after: Option<&str>) -> Option<Page> {
            let items = if self.polls == 0 {
                Vec::new()
            } else {
                self.polls -= 1;
                vec![serde_json::json!({"id": "child", "session_status": "RUNNING"})]
            };
            Some(Page {
                items,
                ..Page::default()
            })
        }

        fn events(&mut self, _: &str, _: Option<&str>, _: Option<&str>) -> Option<Page> {
            Some(Page::default())
        }
    }

    /// Fails by: a `Mints` whose debug form hides whether it mints at all,
    /// which is the one thing a reader of a watch's state needs from it.
    #[test]
    fn a_mints_debug_form_says_whether_it_mints() {
        let sink = |_: &Value, _: &Value| {};
        assert_eq!(format!("{:?}", Mints::none()), "Mints { sink: false }");
        assert_eq!(format!("{:?}", Mints::new(&sink)), "Mints { sink: true }");
    }

    /// Fails by: the delay shrinking between polls, which turns a patient
    /// watch into a busy poll; or a poll that never reports the child gone,
    /// which the bounded wait turns from a hang into a failure (CLOUD-2789).
    #[test]
    fn the_delay_doubles_between_polls() {
        let cache = Cache::new(crate::scratch::scratch("session-watch-backoff"));
        let mut waits = Vec::new();
        let ended = run(
            &mut Watch::new(Vec::new()),
            &mut Running { polls: 3 },
            &cache,
            &Mints::none(),
            &mut |delay| {
                waits.push(delay);
                assert!(waits.len() <= 8, "the watch never ended: {waits:?}");
            },
        );
        assert!(matches!(ended, Some((_, Ending::Nothing))));
        assert_eq!(waits, [FIRST_DELAY, FIRST_DELAY * 2, FIRST_DELAY * 4]);
    }

    /// A child handed its work and never prompted, on every poll.
    struct NeverStarted;

    impl Source for NeverStarted {
        fn sessions(&mut self, _after: Option<&str>) -> Option<Page> {
            Some(Page {
                items: vec![serde_json::json!({"id": "child", "session_status": "IDLE"})],
                ..Page::default()
            })
        }

        fn events(&mut self, _: &str, _: Option<&str>, _: Option<&str>) -> Option<Page> {
            Some(Page::default())
        }
    }

    /// Fails by: an unstarted child never ending the watch, so it polls for
    /// ever. The case owns its bound: a wait past it fails the case rather
    /// than hanging the suite.
    #[test]
    fn a_child_unstarted_across_the_polls_ends_the_watch_dead() {
        let cache = Cache::new(crate::scratch::scratch("session-watch-unstarted"));
        cache.store(
            "child",
            &Inventory {
                cursor: Some(String::from("e1")),
                handoff: true,
                ..Inventory::default()
            },
        );
        let mut waits = 0_u32;
        let mut watch = Watch::new(Vec::new());
        let ended = run(
            &mut watch,
            &mut NeverStarted,
            &cache,
            &Mints::none(),
            &mut |_| {
                waits += 1;
                assert!(
                    waits <= UNSTARTED_POLLS,
                    "the unstarted child never ended it"
                );
            },
        );
        let Some((reports, Ending::Dead)) = ended else {
            panic!("an unstarted child ends the watch dead: {ended:?}");
        };
        assert_eq!(waits, UNSTARTED_POLLS - 1);
        assert!(watch.ended(&reports[0]));
    }

    #[test]
    fn the_envelope_is_unwrapped_only_at_its_own_nonce() {
        let text = "<other-session nonce=\"ab\" untrusted=\"true\">\nheader (JSON):\n    {\"ccr\":{\"data\":[],\"note\":\"</other-session nonce=\\\"zz\\\">\"}}\n</other-session nonce=\"ab\">";
        let payload = serde_json::json!({"content": [{"type": "text", "text": text}]});
        let document = document(&payload).expect("the envelope unwraps");
        assert_eq!(document["ccr"]["data"], serde_json::json!([]));
    }

    /// Fails by: the toolbox's session list answered without dispatching it.
    #[test]
    fn the_toolbox_lists_sessions_over_its_wiring() {
        crate::fetch::stand_in(Box::new(|calls: &[crate::fetch::Call<'_>]| {
            Ok(calls
                .iter()
                .map(|call| {
                    let request: Value =
                        serde_json::from_slice(call.body.unwrap_or_default()).unwrap_or_default();
                    let (status, body) = match request.get("method").and_then(Value::as_str) {
                        Some("initialize") => (200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
                        Some("notifications/initialized") => (202, ""),
                        _ => (
                            200,
                            r#"{"jsonrpc":"2.0","id":2,"result":{"ccr":{"data":[{"id":"s1"}],"has_more":false}}}"#,
                        ),
                    };
                    crate::fetch::Response {
                        status,
                        body: body.as_bytes().to_vec(),
                        headers: Vec::new(),
                    }
                })
                .collect())
        }));
        let mut toolbox = Mcp::new(crate::mcp::Wiring {
            source: "s".to_owned(),
            endpoint: "https://mcp.invalid/mcp".to_owned(),
            headers: Vec::new(),
            credential: None,
        });
        let page = toolbox.sessions(None).expect("a page");
        assert_eq!(page.items.len(), 1);
    }

    /// Fails by: the toolbox's event page answered without dispatching it.
    #[test]
    fn the_toolbox_lists_events_over_its_wiring() {
        crate::fetch::stand_in(Box::new(|calls: &[crate::fetch::Call<'_>]| {
            Ok(calls
                .iter()
                .map(|call| {
                    let request: Value =
                        serde_json::from_slice(call.body.unwrap_or_default()).unwrap_or_default();
                    let (status, body) = match request.get("method").and_then(Value::as_str) {
                        Some("initialize") => (200, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
                        Some("notifications/initialized") => (202, ""),
                        _ => (
                            200,
                            r#"{"jsonrpc":"2.0","id":2,"result":{"ccr":{"data":[{"id":"e1"},{"id":"e2"}],"has_more":false}}}"#,
                        ),
                    };
                    crate::fetch::Response {
                        status,
                        body: body.as_bytes().to_vec(),
                        headers: Vec::new(),
                    }
                })
                .collect())
        }));
        let mut toolbox = Mcp::new(crate::mcp::Wiring {
            source: "s".to_owned(),
            endpoint: "https://mcp.invalid/mcp".to_owned(),
            headers: Vec::new(),
            credential: None,
        });
        let page = toolbox.events("s1", None, None).expect("a page");
        assert_eq!(page.items.len(), 2);
    }

    /// Fails by: a session id spelled with `-` or `_` refused a cache file, or
    /// a kept reduction not read back.
    #[test]
    fn a_kept_reduction_is_read_back() {
        let cache = Cache::new(crate::scratch::scratch("session-watch-cache"));
        let mut inventory = Inventory {
            cursor: Some(String::from("e9")),
            ..Inventory::default()
        };
        inventory.launched.insert(String::from("t1"));
        cache.store("session_01-ab", &inventory);
        assert_eq!(cache.load("session_01-ab"), Some(inventory));
        assert_eq!(cache.load("../escape"), None);
    }

    /// Fails by: the capture's inventory emptied of its reports, or the data
    /// channel's `Line` writing anything but the report's line (CLOUD-2789).
    #[test]
    fn the_inventory_document_carries_each_report() {
        let mut inventory = Inventory::default();
        inventory.launched.insert(String::from("t1"));
        let report = Report {
            session: String::from("session_a"),
            state: State::Done,
            inventory,
        };
        assert_eq!(
            crate::output::Line::line(&report),
            Report::line(&report),
            "the data channel writes the report's own line"
        );
        let document = inventory_document(&[report]);
        assert_eq!(document[0]["session"], "session_a");
        assert_eq!(document[0]["state"], State::Done.as_str());
        assert_eq!(document[0]["open"], serde_json::json!(["t1"]));
    }
}
