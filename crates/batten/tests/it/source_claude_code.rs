//! Claude Code's session source over a fixture projects directory
//! (CLOUD-1011).
//!
//! The fixture is the layout the agent documents: one JSON-lines file per
//! session under an encoded working directory, and subagent transcripts in a
//! `subagents` directory beside the session they belong to. Every line here is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{link_dir, scratch};
use batten::sessions::claude_code::{ClaudeCode, root_from};
use batten::sessions::{
    Cursor, Fidelity, MISSING, REPLACED, SessionRef, SessionSource, Unavailable,
};
use std::fs;
use std::path::{Path, PathBuf};

/// A record a person authored in session `id`, run from `cwd`.
fn authored(id: &str, cwd: &str, uuid: &str) -> String {
    format!(
        "{{\"type\":\"user\",\"sessionId\":\"{id}\",\"cwd\":\"{cwd}\",\"uuid\":\"{uuid}\",\
         \"message\":{{\"role\":\"user\",\"content\":\"hello\"}}}}"
    )
}

/// A record the harness wrote in session `id`: nobody authored it.
fn unauthored(id: &str) -> String {
    format!(
        "{{\"type\":\"assistant\",\"sessionId\":\"{id}\",\
         \"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"hi\"}}]}}}}"
    )
}

fn write(root: &Path, relative: &str, lines: &[String]) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    path
}

/// Three project directories, four authored sessions and one file nobody
/// authored.
fn fixture(name: &str) -> PathBuf {
    let root = scratch(name).join("projects");
    write(
        &root,
        "-work-a/s-1.jsonl",
        &[unauthored("s-1"), authored("s-1", "/work/a", "u1")],
    );
    write(
        &root,
        "-work-a/s-2.jsonl",
        &[authored("s-2", "/work/a", "u2")],
    );
    write(
        &root,
        "-work-b/s-3.jsonl",
        &[authored("s-3", "/work/b", "u3")],
    );
    write(
        &root,
        "-work-c/s-4.jsonl",
        &[authored("s-4", "/work/c", "u4")],
    );
    write(&root, "-work-c/s-5.jsonl", &[unauthored("s-5")]);
    root
}

fn one(root: &Path, id: &str) -> (ClaudeCode, SessionRef) {
    let source = ClaudeCode::at(root);
    let session = source
        .list()
        .unwrap()
        .into_iter()
        .find(|session| session.id == id && session.sub.is_empty())
        .expect("the session is listed");
    (source, session)
}

/// Fails by: a transcript nobody was in being listed as a session, an
/// unsorted listing, or a session without the directory it was run from.
#[test]
fn every_authored_session_is_listed_sorted_with_its_cwd() {
    let root = fixture("source-claude-list");
    let listed = ClaudeCode::at(&root).list().unwrap();
    let seen: Vec<(&str, Option<&Path>, &str)> = listed
        .iter()
        .map(|session| {
            (
                session.id.as_str(),
                session.project.as_deref(),
                session.sub.as_str(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("s-1", Some(Path::new("/work/a")), ""),
            ("s-2", Some(Path::new("/work/a")), ""),
            ("s-3", Some(Path::new("/work/b")), ""),
            ("s-4", Some(Path::new("/work/c")), ""),
        ]
    );
}

/// Fails by: a subagent's transcript being stored as a session of its own, or
/// not being stored at all.
#[test]
fn a_subagent_file_is_listed_under_its_parent_session() {
    let root = fixture("source-claude-subagent");
    let sidechain = "{\"type\":\"user\",\"isSidechain\":true,\"sessionId\":\"s-1\",\
                     \"message\":{\"role\":\"user\",\"content\":\"sub\"}}"
        .to_owned();
    write(&root, "-work-a/s-1/subagents/agent-1.jsonl", &[sidechain]);
    // And one whose records name no session: its directory does.
    write(
        &root,
        "-work-a/s-2/subagents/agent-9.jsonl",
        &[String::from("{\"type\":\"progress\"}")],
    );

    let listed = ClaudeCode::at(&root).list().unwrap();
    let subs: Vec<(&str, &str)> = listed
        .iter()
        .filter(|session| !session.sub.is_empty())
        .map(|session| (session.id.as_str(), session.sub.as_str()))
        .collect();
    assert_eq!(subs, [("s-1", "agent-1"), ("s-2", "agent-9")]);
    assert_eq!(listed.len(), 6, "four sessions and two subagent streams");
}

/// Fails by: the walk following a directory link out of the root.
#[test]
fn a_directory_link_is_not_followed() {
    let root = fixture("source-claude-link");
    let outside = scratch("source-claude-link-outside");
    write(
        &outside,
        "s-9.jsonl",
        &[authored("s-9", "/elsewhere", "u9")],
    );
    link_dir(&outside, root.join("-linked"));
    // THE PREMISE: the link resolves, so a walk that followed it would list
    // the session behind it.
    assert!(root.join("-linked").join("s-9.jsonl").is_file());

    let listed = ClaudeCode::at(&root).list().unwrap();
    assert!(
        listed.iter().all(|session| session.id != "s-9"),
        "{listed:?}"
    );
    assert_eq!(listed.len(), 4);
}

/// Fails by: a record being anything but the line the agent wrote.
#[test]
fn records_are_read_verbatim_with_their_ids() {
    let root = scratch("source-claude-verbatim").join("projects");
    let lines = vec![
        authored("s-1", "/work/a", "u1"),
        String::from("not json, and  kept  as  it  is"),
        unauthored("s-1"),
    ];
    write(&root, "-work-a/s-1.jsonl", &lines);
    let (source, session) = one(&root, "s-1");

    let batch = source.read(&session, &Cursor::start(), u64::MAX).unwrap();
    assert_eq!(batch.fidelity, Fidelity::Full);
    let read: Vec<String> = batch
        .records
        .iter()
        .map(|record| String::from_utf8(record.bytes.clone()).unwrap())
        .collect();
    assert_eq!(read, lines);
    let ids: Vec<Option<&str>> = batch.records.iter().map(|r| r.id.as_deref()).collect();
    assert_eq!(ids, [Some("u1"), None, None]);
}

/// Fails by: a line the agent is still writing being stored as a record.
#[test]
fn an_unterminated_line_is_withheld_until_it_ends() {
    let root = scratch("source-claude-partial").join("projects");
    let path = write(
        &root,
        "-work-a/s-1.jsonl",
        &[authored("s-1", "/work/a", "u1")],
    );
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("{\"type\":\"assistant\",\"uuid\":\"u2\"");
    fs::write(&path, &text).unwrap();
    let (source, session) = one(&root, "s-1");

    let first = source.read(&session, &Cursor::start(), u64::MAX).unwrap();
    assert_eq!(first.records.len(), 1);

    text.push_str("}\n");
    fs::write(&path, &text).unwrap();
    let second = source.read(&session, &first.cursor, u64::MAX).unwrap();
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].id.as_deref(), Some("u2"));
}

/// Fails by: a bounded read losing a line between two batches, or returning
/// one twice.
#[test]
fn a_bounded_read_returns_every_line_exactly_once() {
    let root = scratch("source-claude-bounded").join("projects");
    let lines: Vec<String> = (0..9)
        .map(|n| authored("s-1", "/work/a", &format!("u{n}")))
        .collect();
    write(&root, "-work-a/s-1.jsonl", &lines);
    let (source, session) = one(&root, "s-1");
    let bound = u64::try_from(lines[0].len() * 2 + 1).unwrap();

    let mut cursor = Cursor::start();
    let mut read = Vec::new();
    let mut batches = 0;
    loop {
        let batch = source.read(&session, &cursor, bound).unwrap();
        assert_eq!(batch.fidelity, Fidelity::Full);
        if batch.records.is_empty() {
            break;
        }
        batches += 1;
        read.extend(
            batch
                .records
                .iter()
                .map(|record| String::from_utf8(record.bytes.clone()).unwrap()),
        );
        cursor = batch.cursor;
    }
    assert_eq!(read, lines);
    assert_eq!(batches, 3, "three lines a batch under this bound");
}

/// Fails by: a file cut below its cursor being read from the old offset.
#[test]
fn a_truncated_file_is_partial() {
    let root = scratch("source-claude-truncated").join("projects");
    let lines = vec![
        authored("s-1", "/work/a", "u1"),
        authored("s-1", "/work/a", "u2"),
    ];
    let path = write(&root, "-work-a/s-1.jsonl", &lines);
    let (source, session) = one(&root, "s-1");
    let first = source.read(&session, &Cursor::start(), u64::MAX).unwrap();
    assert_eq!(first.records.len(), 2);

    fs::write(&path, format!("{}\n", lines[0])).unwrap();
    let after = source.read(&session, &first.cursor, u64::MAX).unwrap();
    assert_eq!(after.fidelity, Fidelity::Partial(REPLACED));
    assert!(after.cursor.is_start());
}

/// Fails by: a projects directory that is not there reading as a machine with
/// no sessions.
#[test]
fn a_missing_root_is_unavailable() {
    let absent = scratch("source-claude-missing").join("no-such-projects");
    let refusal = ClaudeCode::at(&absent).list().unwrap_err();
    assert_eq!(
        refusal.downcast_ref::<Unavailable>(),
        Some(&Unavailable(MISSING))
    );
}

/// Fails by: reading some other agent's directory than the one this session's
/// own transcript is in.
#[test]
fn the_root_is_two_levels_above_the_transcript_then_the_variable_then_home() {
    let transcript = Path::new("/cfg/projects/-work-a/s-1.jsonl");
    let home = Path::new("/home/agent");
    assert_eq!(
        root_from(Some(transcript), Some("/named"), Some(home)),
        Some(PathBuf::from("/cfg/projects"))
    );
    assert_eq!(
        root_from(None, Some("/named"), Some(home)),
        Some(PathBuf::from("/named"))
    );
    assert_eq!(
        root_from(None, Some(""), Some(home)),
        Some(home.join(".claude").join("projects"))
    );
    assert_eq!(root_from(None, None, None), None);
}
