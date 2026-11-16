//! The session-source contract over its neutral implementation (CLOUD-1010).
//!
//! One JSON-lines file the caller names. The cases are the contract's own
//! clauses: records verbatim, a half-written line withheld, a bounded read, a
//! replaced file noticed, and could-not-look never reported as nothing-new.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::scratch;
use batten::sessions::{
    Batch, Cursor, Fidelity, JsonlFile, MISSING, REPLACED, SessionRef, SessionSource,
};
use std::fs;
use std::path::{Path, PathBuf};

fn file_in(name: &str, contents: &str) -> PathBuf {
    let path = scratch(name).join("session.jsonl");
    fs::write(&path, contents).unwrap();
    path
}

fn session(path: &Path) -> (JsonlFile, SessionRef) {
    let source = JsonlFile::at(path);
    let listed = source.list().unwrap();
    assert_eq!(listed.len(), 1, "the named file is the one session");
    (source, listed.into_iter().next().unwrap())
}

fn read(path: &Path, from: &Cursor, max_bytes: u64) -> Batch {
    let (source, session) = session(path);
    source.read(&session, from, max_bytes).unwrap()
}

fn bodies(batch: &Batch) -> Vec<String> {
    batch
        .records
        .iter()
        .map(|record| String::from_utf8_lossy(&record.bytes).into_owned())
        .collect()
}

/// Fails by: a line a host is still writing being stored as a record.
#[test]
fn a_half_written_line_waits_for_its_newline() {
    let lines = [
        "{\"n\":1}",
        "{\"n\":2}",
        "{\"n\":3}",
        "{\"n\":4}",
        "{\"n\":5}",
    ];
    let path = file_in(
        "session-source-partial",
        &format!("{}\n{{\"n\":6", lines.join("\n")),
    );

    let first = read(&path, &Cursor::start(), u64::MAX);
    assert_eq!(first.fidelity, Fidelity::Full);
    assert_eq!(bodies(&first), lines);
    assert!(!first.cursor.is_start());

    // Nothing new until the line is finished, and that is a full, empty batch.
    let waiting = read(&path, &first.cursor, u64::MAX);
    assert!(waiting.is_ended());
    assert_eq!(waiting.cursor, first.cursor);

    let mut whole = fs::read_to_string(&path).unwrap();
    whole.push_str("}\n");
    fs::write(&path, whole).unwrap();
    let second = read(&path, &first.cursor, u64::MAX);
    assert_eq!(bodies(&second), ["{\"n\":6}"]);
}

/// Fails by: a record being anything but the bytes the agent wrote, or an id
/// being read out of a line that has none.
#[test]
fn records_are_the_files_lines_byte_for_byte() {
    let lines = [
        "{ \"uuid\" : \"abc-1\",  \"text\": \"two  spaces\" }",
        "this line is not json at all\t",
        "{\"uuid\":7,\"note\":\"an id that is not a string\"}",
        "{\"message\":{\"uuid\":\"nested, so not the record's own\"}}\r",
    ];
    let path = file_in(
        "session-source-verbatim",
        &format!("{}\n", lines.join("\n")),
    );

    let batch = read(&path, &Cursor::start(), u64::MAX);
    assert_eq!(bodies(&batch), lines);
    let ids: Vec<Option<&str>> = batch
        .records
        .iter()
        .map(|record| record.id.as_deref())
        .collect();
    assert_eq!(ids, [Some("abc-1"), None, None, None]);
}

/// Fails by: a file that is not the one a cursor was taken over being read
/// from the old offset.
#[test]
fn a_replaced_file_is_partial_and_starts_again() {
    let path = file_in(
        "session-source-replaced",
        "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n",
    );
    let first = read(&path, &Cursor::start(), u64::MAX);
    assert_eq!(first.records.len(), 3);

    // Shorter, with the same first line.
    fs::write(&path, "{\"n\":1}\n").unwrap();
    let shorter = read(&path, &first.cursor, u64::MAX);
    assert_eq!(shorter.fidelity, Fidelity::Partial(REPLACED));
    assert!(shorter.cursor.is_start());
    assert!(shorter.records.is_empty());
    assert_eq!(read(&path, &shorter.cursor, u64::MAX).records.len(), 1);

    // Longer, opening with a different record.
    fs::write(&path, "{\"other\":1}\n{\"n\":2}\n{\"n\":3}\n{\"n\":4}\n").unwrap();
    let different = read(&path, &first.cursor, u64::MAX);
    assert_eq!(different.fidelity, Fidelity::Partial(REPLACED));
    assert!(different.cursor.is_start());

    // A cursor this source never produced is not the start either.
    let foreign = read(&path, &Cursor(b"not-a-cursor".to_vec()), u64::MAX);
    assert_eq!(foreign.fidelity, Fidelity::Partial(REPLACED));
}

/// Fails by: a read returning the whole source whatever the bound, or cutting
/// a record to fit it.
#[test]
fn a_read_stops_at_the_byte_bound_and_never_splits_a_record() {
    let path = file_in("session-source-bound", "aaaaaaaa\nbbbbbbbb\ncccccccc\n");

    let first = read(&path, &Cursor::start(), 10);
    assert_eq!(bodies(&first), ["aaaaaaaa", "bbbbbbbb"]);
    let second = read(&path, &first.cursor, 10);
    assert_eq!(bodies(&second), ["cccccccc"]);
    assert!(read(&path, &second.cursor, 10).is_ended());

    // At least one record, even when one alone is over the bound.
    let one = read(&path, &Cursor::start(), 1);
    assert_eq!(bodies(&one), ["aaaaaaaa"]);
}

/// Fails by: could-not-look being reported as nothing-new.
#[test]
fn a_missing_source_is_unavailable_and_never_empty() {
    let absent = scratch("session-source-missing").join("nobody-wrote-this.jsonl");
    let source = JsonlFile::at(&absent);
    assert!(source.list().unwrap().is_empty(), "no session to name");
    let named = SessionRef {
        id: String::from("gone"),
        project: None,
        locator: absent.to_string_lossy().into_owned(),
        sub: String::new(),
    };
    let batch = source.read(&named, &Cursor::start(), u64::MAX).unwrap();
    assert_eq!(batch.fidelity, Fidelity::Unavailable(MISSING));
    assert!(!batch.is_ended(), "unavailable is not the end of a source");
    assert!(batch.records.is_empty());
}

/// Fails by: a harness nobody wrote a source for reading as one that stores
/// no sessions.
#[test]
fn a_harness_without_a_source_names_the_row_that_owes_one() {
    use batten::hook::Harness;
    use batten::sessions::{Sourced, source_for};

    let path = file_in("session-source-neutral", "{\"uuid\":\"u\"}\n");
    let Sourced::Surveyed(neutral) = source_for(Harness::ExitCode, Some(&path)) else {
        panic!("the neutral contract has a source");
    };
    assert_eq!(neutral.list().unwrap().len(), 1);
    for harness in [
        Harness::CodexCli,
        Harness::GeminiCli,
        Harness::Cursor,
        Harness::CopilotCli,
    ] {
        let Sourced::Unsurveyed(row) = source_for(harness, None) else {
            panic!("{harness:?} has no source yet");
        };
        assert!(row.starts_with("CLOUD-"), "{row}");
    }
}
