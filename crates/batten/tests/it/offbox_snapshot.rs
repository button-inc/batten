//! `offbox::snapshot` — one session as an orphan commit in its own local
//! repository (CLOUD-2719).
//!
//! Every case builds a real repository, real stores under the state directory
//! and the git directory, and a real JSON-lines source, then reads the commit's
//! tree back. Nothing here reaches a network: a snapshot never does.
//!
//! # The scanner is a stub that really looks
//!
//! `secrets_kind.rs` stubs the scanner with a script that prints fixed matches.
//! A snapshot calls the scanner more than once, over files whose names this
//! suite does not choose, so the stub here searches the files it is handed for
//! one token and reports the lines that hold it. The token is assembled from
//! parts, in the stub and here, so no committed byte sequence holds it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use batten::gitwrite::{self, Content};
use batten::offbox::{self, Feed, Meta, Refusal, Snapshot};
use batten::provision::digest;
use batten::sessions::{Batch, Cursor, JsonlFile, SessionRef, SessionSource};

use crate::common::{self, Fixture, batten, git_in, scratch};

const TOKEN_PARTS: [&str; 5] = ["AKIA", "7QF2", "NX8M", "3JD5", "W0PC"];
const MIB: usize = 1024 * 1024;
const TIME: i64 = 1_700_000_000;
const NO_CAP: u64 = u64::MAX;
const MAIN: &str = "transcript/main";

fn token() -> String {
    TOKEN_PARTS.concat()
}

/// A scanner that reports every line of every file it is handed that holds the
/// token, in the `<path>:<line>:<span>` shape, and exits 1 when it found one.
fn looking_stub() -> String {
    let mut assembled = String::new();
    for part in TOKEN_PARTS {
        assembled.push('"');
        assembled.push_str(part);
        assembled.push('"');
    }
    format!(
        "#!/bin/sh\nT={assembled}\nfound=0\nfor f in \"$@\"; do\n  [ -f \"$f\" ] || continue\n  \
         for n in $(grep -n -F \"$T\" \"$f\" | cut -d: -f1); do\n    \
         printf '%s\\n' \"$f:$n:$T\"\n    found=1\n  done\ndone\nexit $found\n"
    )
}

/// One checkout: a repository, its state directory, and somewhere to keep the
/// files a source reads.
struct Rig {
    repo: PathBuf,
    state: PathBuf,
    sources: PathBuf,
    artifacts: PathBuf,
}

impl Rig {
    /// A checkout with the looking stub installed.
    fn new(name: &str) -> Self {
        let rig = Rig::bare(name);
        rig.install(&looking_stub());
        rig
    }

    /// A checkout with no scanner declared.
    fn bare(name: &str) -> Self {
        // THE CALLS ARE IN-PROCESS, so state resolves under this process's own
        // contained root; pin it before anything is derived from it.
        let _ = common::scratch_state_root();
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .build();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);
        let repo = repo.canonicalize().unwrap();
        let state = batten::state::repo_state_dir(&repo).unwrap();
        let sources = root.join("sources");
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&sources).unwrap();
        fs::create_dir_all(&artifacts).unwrap();
        Rig {
            repo,
            state,
            sources,
            artifacts,
        }
    }

    fn install(&self, script: &str) {
        let path = self.artifacts.join("ripsecrets");
        fs::write(&path, script).unwrap();
        let sha = digest(&fs::read(&path).unwrap());
        fs::write(
            self.repo.join("batten.toml"),
            format!(
                "version = 1\n\n[[provision]]\nname = \"ripsecrets\"\nversion = \"0.0.0-stub\"\n\
                 url = 'file://{}'\nsha256 = \"{sha}\"\nbinary = \"ripsecrets\"\n",
                path.display()
            ),
        )
        .unwrap();
        let applied = batten()
            .args(["provision", "apply"])
            .current_dir(&self.repo)
            .output()
            .expect("run batten");
        assert!(
            applied.status.success(),
            "the stub scanner installs: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
    }

    fn provisions(&self) -> Vec<batten::provision::Provision> {
        let config = self.repo.join("batten.toml");
        if !config.is_file() {
            return Vec::new();
        }
        batten::config::load(&config)
            .expect("the fixture config loads")
            .provisions
    }

    fn meta(session: &str) -> Meta {
        Meta {
            harness: String::from("claude-code"),
            session: session.to_owned(),
            origin: String::from("acme/widgets"),
        }
    }

    /// Write `body` as a file under the state directory.
    fn state_file(&self, path: &str, body: &str) {
        write(&self.state.join(path), body);
    }

    /// Write `body` as a file under the project's git directory.
    fn git_file(&self, path: &str, body: &str) {
        write(&self.repo.join(".git").join(path), body);
    }

    /// The file a source reads, named `name`.
    fn source(&self, name: &str) -> PathBuf {
        self.sources.join(format!("{name}.jsonl"))
    }

    fn snap(&self, meta: &Meta, feeds: &[Feed<'_>], time: i64, cap: u64) -> Snapshot {
        offbox::snapshot(&self.repo, &self.provisions(), meta, feeds, time, cap)
            .expect("the snapshot runs")
    }

    fn dir(&self, meta: &Meta) -> PathBuf {
        offbox::session_dir(&self.repo, meta).unwrap()
    }

    /// The tree of `commit` in `meta`'s local repository: path to blob id.
    fn tree(&self, meta: &Meta, commit: &str) -> BTreeMap<String, String> {
        gitwrite::tree_index(&offbox::local_repo(&self.dir(meta)), commit)
            .unwrap()
            .into_iter()
            .collect()
    }

    fn blob(&self, meta: &Meta, id: &str) -> Vec<u8> {
        gitwrite::read_blob(&offbox::local_repo(&self.dir(meta)), id).unwrap()
    }

    /// Every file under `prefix/` of a tree, joined in name order.
    fn joined(&self, meta: &Meta, tree: &BTreeMap<String, String>, prefix: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, id) in tree {
            if path.starts_with(&format!("{prefix}/")) {
                out.extend_from_slice(&self.blob(meta, id));
            }
        }
        out
    }

    /// Say the snapshot `commit` was pushed: move the ref a snapshot reads.
    fn pushed(&self, meta: &Meta, commit: &str) {
        gitwrite::set_ref(&offbox::local_repo(&self.dir(meta)), offbox::LAST, commit).unwrap();
    }
}

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn append(path: &Path, body: &str) {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    file.write_all(body.as_bytes()).unwrap();
}

/// `count` records of about `size` bytes each, numbered from `from`.
fn records(from: usize, count: usize, size: usize) -> String {
    let mut out = String::new();
    for index in from..from + count {
        let head = format!("{{\"n\":{index},\"pad\":\"");
        out.push_str(&head);
        out.push_str(&"x".repeat(size.saturating_sub(head.len() + 2)));
        out.push_str("\"}\n");
    }
    out
}

fn feed<'a>(prefix: &str, source: &'a JsonlFile) -> Feed<'a> {
    let session = source
        .list()
        .unwrap()
        .into_iter()
        .next()
        .unwrap_or(SessionRef {
            id: String::from("absent"),
            project: None,
            locator: String::from("/nonexistent/absent.jsonl"),
            sub: String::new(),
        });
    Feed {
        prefix: prefix.to_owned(),
        source,
        session,
    }
}

fn built(snapshot: Snapshot) -> (String, String, u64, usize, Vec<String>) {
    match snapshot {
        Snapshot::Built {
            commit,
            tree,
            new_bytes,
            spans_redacted,
            ended,
        } => (commit, tree, new_bytes, spans_redacted, ended),
        Snapshot::Refused(refusal) => panic!("refused: {refusal:?}"),
    }
}

fn cursors(rig: &Rig, meta: &Meta, tree: &BTreeMap<String, String>) -> serde_json::Value {
    serde_json::from_slice(&rig.blob(meta, &tree["cursor.json"])).unwrap()
}

/// Fails by: a path of the layout missing, a rebuilt or lock entry shipped, or
/// the transcript stored as one growing file.
#[test]
fn the_tree_holds_the_stores_and_the_transcript_in_segments() {
    let rig = Rig::new("offbox-snapshot-layout");
    let meta = Rig::meta("layout");
    rig.state_file("captures/a/one.txt", "one\n");
    rig.state_file("cache/rebuilt.bin", "rebuilt\n");
    rig.state_file("captures/calls.lock", "1\n");
    rig.git_file("batten-ledger/x.json", "{}\n");
    rig.git_file("batten-ledger/held.lock", "1\n");
    rig.git_file("batten-receipt", "r\n");
    rig.git_file("batten-singleton", "1\n");
    rig.git_file("batten-mcp-spawns", "1\n");
    rig.git_file("batten-land-lock", "1\n");
    rig.git_file("batten-tasks/t", "1\n");
    rig.git_file("batten-push-1-2.request", "1\n");
    let path = rig.source("main");
    let body = records(0, 2600, 1000);
    assert!(body.len() > 2 * MIB, "the premise: over two segments");
    write(&path, &body);
    let source = JsonlFile::at(&path);

    let (commit, _, new_bytes, _, ended) =
        built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let tree = rig.tree(&meta, &commit);

    for held in [
        "meta.json",
        "cursor.json",
        "state/captures/a/one.txt",
        "git/batten-ledger/x.json",
        "git/batten-receipt",
        "transcript/main/0/000000.jsonl",
        "transcript/main/0/000001.jsonl",
        "transcript/main/0/000002.jsonl",
    ] {
        assert!(tree.contains_key(held), "{held} is in the tree: {tree:?}");
    }
    for path in tree.keys() {
        assert!(
            !path.starts_with("state/") || path.starts_with("state/captures/"),
            "only an allow-listed state entry ships: {path}"
        );
        assert!(!path.contains(".lock"), "no lock ships: {path}");
        for excluded in [
            "git/batten-singleton",
            "git/batten-mcp-spawns",
            "git/batten-land-lock",
            "git/batten-tasks",
            "git/batten-push-",
            "git/HEAD",
        ] {
            assert!(!path.starts_with(excluded), "{path} is not a store");
        }
    }
    assert!(!tree.contains_key("transcript/main/0/000003.jsonl"));
    for closed in ["000000", "000001"] {
        let size = rig
            .blob(&meta, &tree[&format!("transcript/main/0/{closed}.jsonl")])
            .len();
        assert!(
            (MIB..MIB + 1000).contains(&size),
            "{closed} closed at {size}"
        );
    }
    assert_eq!(
        rig.joined(&meta, &tree, "transcript/main/0"),
        body.as_bytes()
    );
    assert_eq!(new_bytes, body.len() as u64);
    assert_eq!(ended, vec![String::from(MAIN)]);
    let described: serde_json::Value =
        serde_json::from_slice(&rig.blob(&meta, &tree["meta.json"])).unwrap();
    assert_eq!(described["harness"], "claude-code");
    assert_eq!(described["session"], "layout");
    assert_eq!(described["origin"], "acme/widgets");
    assert!(
        !rig.dir(&meta).join("staging").exists(),
        "staging is removed"
    );
}

/// Fails by: a path of the first snapshot missing from the second, or a closed
/// segment's blob changing.
#[test]
fn a_second_snapshot_holds_everything_the_first_did() {
    let rig = Rig::new("offbox-snapshot-superset");
    let meta = Rig::meta("superset");
    rig.state_file("captures/a/one.txt", "one\n");
    let path = rig.source("main");
    write(&path, &records(0, 1500, 1000));
    let source = JsonlFile::at(&path);
    let (first, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let before = rig.tree(&meta, &first);

    // WHAT A PUSH THAT ABSORBED ANOTHER WRITER LEAVES AS `last`: the first tree
    // and a file under `absorbed/` that is nowhere on this disk.
    let repo = offbox::local_repo(&rig.dir(&meta));
    let mut entries: Vec<(String, Content)> = before
        .iter()
        .map(|(path, id)| (path.clone(), Content::Blob(id.clone())))
        .collect();
    entries.push((
        String::from("absorbed/0123/meta.json"),
        Content::Bytes(b"{}\n".to_vec()),
    ));
    let (merged, _) = gitwrite::commit_tree(&repo, &entries, &[], TIME, "absorbed").unwrap();
    rig.pushed(&meta, &merged);
    let last = rig.tree(&meta, &merged);

    append(&path, &records(1500, 20, 1000));
    let (second, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME + 60, NO_CAP));
    let after = rig.tree(&meta, &second);

    for path in last.keys() {
        assert!(after.contains_key(path), "{path} is carried");
    }
    assert_eq!(
        after["transcript/main/0/000000.jsonl"], before["transcript/main/0/000000.jsonl"],
        "a closed segment keeps its blob"
    );
    assert_ne!(
        after["transcript/main/0/000001.jsonl"], before["transcript/main/0/000001.jsonl"],
        "the open segment grew"
    );
    assert_eq!(
        rig.joined(&meta, &after, "transcript/main/0"),
        fs::read(&path).unwrap()
    );
}

/// Fails by: the tree depending on the commit time, or on being built twice.
#[test]
fn an_unchanged_session_gives_the_same_tree() {
    let rig = Rig::new("offbox-snapshot-unchanged");
    let meta = Rig::meta("unchanged");
    rig.state_file("captures/a/one.txt", "one\n");
    let path = rig.source("main");
    write(&path, &records(0, 10, 200));
    let source = JsonlFile::at(&path);

    let (first, tree_one, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let (second, tree_two, new_bytes, ..) =
        built(rig.snap(&meta, &[feed(MAIN, &source)], TIME + 60, NO_CAP));

    assert_eq!(tree_one, tree_two);
    assert_ne!(first, second, "the commit carries the caller's time");
    assert_eq!(new_bytes, 0);
}

/// Fails by: a store that is gone locally being dropped from the snapshot.
#[test]
fn a_store_deleted_locally_is_carried_forward_whole() {
    let rig = Rig::new("offbox-snapshot-store-gone");
    let meta = Rig::meta("store-gone");
    rig.git_file("batten-ledger/x.json", "{}\n");
    rig.git_file("batten-ledger/deep/y.json", "{}\n");
    rig.state_file("captures/a/one.txt", "one\n");
    let (first, ..) = built(rig.snap(&meta, &[], TIME, NO_CAP));
    rig.pushed(&meta, &first);
    let before = rig.tree(&meta, &first);

    fs::remove_dir_all(rig.repo.join(".git/batten-ledger")).unwrap();
    let (second, ..) = built(rig.snap(&meta, &[], TIME, NO_CAP));
    let after = rig.tree(&meta, &second);

    for path in ["git/batten-ledger/x.json", "git/batten-ledger/deep/y.json"] {
        assert_eq!(after.get(path), before.get(path), "{path}");
    }
}

/// Fails by: a file its own store removed coming back from the last snapshot.
#[test]
fn a_file_a_store_removed_itself_stays_removed() {
    let rig = Rig::new("offbox-snapshot-file-gone");
    let meta = Rig::meta("file-gone");
    rig.state_file("captures/a/one.txt", "one\n");
    rig.state_file("captures/a/two.txt", "two\n");
    let (first, ..) = built(rig.snap(&meta, &[], TIME, NO_CAP));
    rig.pushed(&meta, &first);
    // THE PREMISE: the last snapshot holds the file about to go.
    assert!(
        rig.tree(&meta, &first)
            .contains_key("state/captures/a/one.txt")
    );

    fs::remove_file(rig.state.join("captures/a/one.txt")).unwrap();
    let (second, ..) = built(rig.snap(&meta, &[], TIME, NO_CAP));
    let after = rig.tree(&meta, &second);

    assert!(!after.contains_key("state/captures/a/one.txt"));
    assert!(after.contains_key("state/captures/a/two.txt"));
}

/// Fails by: a matched span reaching a blob or a local segment.
#[test]
fn matched_spans_are_redacted_in_stores_and_records() {
    let rig = Rig::new("offbox-snapshot-redaction");
    let meta = Rig::meta("redaction");
    rig.state_file(
        "captures/a/one.txt",
        &format!("before\nkey={}\nafter\n", token()),
    );
    let path = rig.source("main");
    write(
        &path,
        &format!("{{\"n\":1}}\n{{\"k\":\"{}\"}}\n{{\"n\":3}}\n", token()),
    );
    let source = JsonlFile::at(&path);

    let (commit, _, _, spans, _) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let tree = rig.tree(&meta, &commit);

    assert_eq!(spans, 2);
    let needle = token();
    for (path, id) in &tree {
        let blob = rig.blob(&meta, id);
        assert!(
            !String::from_utf8_lossy(&blob).contains(&needle),
            "{path} holds the span"
        );
    }
    assert_eq!(
        rig.blob(&meta, &tree["state/captures/a/one.txt"]),
        b"before\nkey=[REDACTED]\nafter\n"
    );
    assert_eq!(
        rig.joined(&meta, &tree, "transcript/main/0"),
        b"{\"n\":1}\n{\"k\":\"[REDACTED]\"}\n{\"n\":3}\n"
    );
    let local = fs::read(rig.dir(&meta).join("transcript/main/0/000000.jsonl")).unwrap();
    assert!(!String::from_utf8_lossy(&local).contains(&needle));
    // The store itself is the project's and is not rewritten.
    assert!(
        fs::read_to_string(rig.state.join("captures/a/one.txt"))
            .unwrap()
            .contains(&needle)
    );
    assert!(!rig.dir(&meta).join("staging").exists());
}

/// Fails by: a record too large for one object being dropped, shortened or
/// replaced, or a file over the forge's object limit.
#[test]
fn an_oversized_record_is_cut_into_parts_and_never_replaced() {
    let rig = Rig::new("offbox-snapshot-oversized");
    let meta = Rig::meta("oversized");
    let path = rig.source("main");
    let mut body = String::from("{\"n\":1}\n");
    body.push_str(&"y".repeat(120 * MIB));
    body.push('\n');
    body.push_str("{\"n\":3}\n");
    write(&path, &body);
    let source = JsonlFile::at(&path);

    let (commit, _, new_bytes, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let tree = rig.tree(&meta, &commit);

    let names: Vec<&str> = tree
        .keys()
        .filter_map(|path| path.strip_prefix("transcript/main/0/"))
        .collect();
    assert_eq!(
        names,
        [
            "000000.jsonl",
            "000001.part",
            "000002.part",
            "000003.jsonl",
            "000004.jsonl"
        ]
    );
    let mut joined = Vec::new();
    for name in &names {
        let blob = rig.blob(&meta, &tree[&format!("transcript/main/0/{name}")]);
        assert!(blob.len() <= 50 * MIB, "{name} is {} bytes", blob.len());
        joined.extend_from_slice(&blob);
    }
    assert!(
        joined == body.as_bytes(),
        "the stream is the source's bytes"
    );
    assert_eq!(new_bytes, body.len() as u64);
}

/// Fails by: a snapshot growing past the cap between two applied pushes.
#[test]
fn the_byte_cap_counts_what_an_unapplied_push_left_waiting() {
    let rig = Rig::new("offbox-snapshot-cap");
    let meta = Rig::meta("cap");
    let path = rig.source("main");
    write(&path, &records(0, 100, 100));
    let source = JsonlFile::at(&path);
    let cap = 1000;

    let (_, _, first, _, ended) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, cap));
    assert!((1000..1200).contains(&first), "one cap's worth: {first}");
    assert!(ended.is_empty(), "the feed has more");

    // NOT PUSHED: what the first call appended is still waiting.
    let (_, _, second, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, cap));
    assert_eq!(second, 0, "the waiting bytes fill the cap");

    let (third, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, cap));
    rig.pushed(&meta, &third);
    let (_, _, fourth, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, cap));
    assert!(
        (1000..1200).contains(&fourth),
        "an applied push frees it: {fourth}"
    );
}

/// A source that lists one session and cannot be read.
struct Broken;

impl SessionSource for Broken {
    fn list(&self) -> anyhow::Result<Vec<SessionRef>> {
        Ok(Vec::new())
    }

    fn read(&self, _: &SessionRef, _: &Cursor, _: u64) -> anyhow::Result<Batch> {
        Err(anyhow::anyhow!("the read was killed"))
    }
}

/// Fails by: bytes a killed call appended being kept and then read again, or a
/// feed's segment directory existing before its cursor entry does.
#[test]
fn a_killed_append_is_cut_back_and_no_record_is_stored_twice() {
    let rig = Rig::new("offbox-snapshot-crash");
    let meta = Rig::meta("crash");
    let path = rig.source("main");
    write(&path, &records(0, 5, 200));
    let source = JsonlFile::at(&path);
    built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));

    // WHAT A KILL BETWEEN THE APPEND AND THE CURSOR LEAVES: bytes in the open
    // segment, and a later segment, that the cursor file does not cover.
    let generation = rig.dir(&meta).join("transcript/main/0");
    let torn = records(5, 2, 200);
    append(&generation.join("000000.jsonl"), &torn);
    write(&generation.join("000001.jsonl"), &torn);
    append(&path, &records(5, 4, 200));

    let (commit, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let tree = rig.tree(&meta, &commit);
    assert_eq!(
        rig.joined(&meta, &tree, "transcript/main/0"),
        fs::read(&path).unwrap(),
        "each record once"
    );
    assert!(!tree.contains_key("transcript/main/0/000001.jsonl"));

    // AND THE ENTRY COMES FIRST: a call killed at its first read has already
    // written the feed's cursor entry.
    let other = Rig::meta("crash-entry");
    let killed = offbox::snapshot(
        &rig.repo,
        &rig.provisions(),
        &other,
        &[Feed {
            prefix: String::from(MAIN),
            source: &Broken,
            session: feed(MAIN, &source).session,
        }],
        TIME,
        NO_CAP,
    );
    assert!(killed.is_err());
    let entries: serde_json::Value =
        serde_json::from_slice(&fs::read(rig.dir(&other).join("cursor.json")).unwrap()).unwrap();
    assert!(entries.get(MAIN).is_some(), "{entries}");
    assert!(!rig.dir(&other).join("staging").exists());
}

/// Fails by: a later session in the same checkout inheriting the earlier one's
/// transcript, cursors or last-pushed commit.
#[test]
fn a_second_session_in_one_checkout_gets_its_own_directory() {
    let rig = Rig::new("offbox-snapshot-two-sessions");
    let (one, two) = (Rig::meta("one"), Rig::meta("two"));
    let (path_one, path_two) = (rig.source("one"), rig.source("two"));
    write(&path_one, &records(0, 5, 200));
    write(&path_two, &records(100, 3, 200));
    let (source_one, source_two) = (JsonlFile::at(&path_one), JsonlFile::at(&path_two));

    let (first, ..) = built(rig.snap(&one, &[feed(MAIN, &source_one)], TIME, NO_CAP));
    rig.pushed(&one, &first);
    let (second, ..) = built(rig.snap(&two, &[feed(MAIN, &source_two)], TIME, NO_CAP));

    assert_ne!(rig.dir(&one), rig.dir(&two));
    assert_eq!(
        rig.dir(&two).file_name().unwrap().to_string_lossy(),
        offbox::leaf("claude-code", "two")
    );
    let tree = rig.tree(&two, &second);
    assert_eq!(
        rig.joined(&two, &tree, "transcript/main/0"),
        fs::read(&path_two).unwrap()
    );
    let leaf = offbox::leaf("claude-code", "one");
    assert!(leaf.starts_with("claude-code-") && leaf.len() == "claude-code-".len() + 16);
}

/// Fails by: a replaced source overwriting what was read from the file it
/// replaced.
#[test]
fn a_replaced_source_starts_a_new_generation() {
    let rig = Rig::new("offbox-snapshot-replaced");
    let meta = Rig::meta("replaced");
    let path = rig.source("main");
    let old = records(0, 5, 200);
    write(&path, &old);
    let source = JsonlFile::at(&path);
    let (first, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let before = rig.tree(&meta, &first);

    let new = records(900, 2, 150);
    write(&path, &new);
    let (second, ..) = built(rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP));
    let after = rig.tree(&meta, &second);

    assert_eq!(
        after["transcript/main/0/000000.jsonl"],
        before["transcript/main/0/000000.jsonl"]
    );
    assert_eq!(
        rig.joined(&meta, &after, "transcript/main/0"),
        old.as_bytes()
    );
    assert_eq!(
        rig.joined(&meta, &after, "transcript/main/1"),
        new.as_bytes()
    );
    assert_eq!(cursors(&rig, &meta, &after)[MAIN]["generation"], 1);
}

/// Fails by: a feed the cap never reached having no cursor entry, feeds read
/// out of the order given, or an unavailable source reading as an ended one.
#[test]
fn a_feed_the_cap_never_reached_still_has_a_cursor_entry() {
    let rig = Rig::new("offbox-snapshot-feeds");
    let (path_one, path_two) = (rig.source("one"), rig.source("two"));
    write(&path_one, &records(0, 50, 100));
    write(&path_two, &records(500, 50, 100));
    let (source_one, source_two) = (JsonlFile::at(&path_one), JsonlFile::at(&path_two));
    let gone = JsonlFile::at(&rig.source("gone"));
    let history = "history/claude-code-0000000000000000/transcript/main";

    for (session, first, second) in [
        ("forward", (MAIN, &source_one), (history, &source_two)),
        ("backward", (history, &source_two), (MAIN, &source_one)),
    ] {
        let meta = Rig::meta(session);
        let feeds = [
            feed(first.0, first.1),
            feed(second.0, second.1),
            feed("history/gone/transcript/main", &gone),
        ];
        let (commit, _, _, _, ended) = built(rig.snap(&meta, &feeds, TIME, 1000));
        let tree = rig.tree(&meta, &commit);
        let entries = cursors(&rig, &meta, &tree);

        assert!(
            tree.contains_key(&format!("{}/0/000000.jsonl", first.0)),
            "{session}: the first feed given is read first"
        );
        assert!(
            !tree
                .keys()
                .any(|path| path.starts_with(&format!("{}/", second.0))),
            "{session}: the cap was spent before the second"
        );
        for prefix in [first.0, second.0, "history/gone/transcript/main"] {
            assert!(
                entries.get(prefix).is_some(),
                "{session}: {prefix} has an entry"
            );
        }
        assert!(ended.is_empty(), "{session}: nothing ended: {ended:?}");
    }

    // WITH ROOM, the unavailable source is recorded as such and is not ended.
    let meta = Rig::meta("roomy");
    let feeds = [
        feed(MAIN, &source_one),
        feed("history/gone/transcript/main", &gone),
    ];
    let (commit, _, _, _, ended) = built(rig.snap(&meta, &feeds, TIME, NO_CAP));
    let entries = cursors(&rig, &meta, &rig.tree(&meta, &commit));
    assert_eq!(ended, vec![String::from(MAIN)]);
    assert_eq!(
        entries["history/gone/transcript/main"]["fidelity"],
        "source-missing"
    );
}

/// Fails by: a scanner that is absent or failed reading as nothing to redact.
#[test]
fn a_missing_or_failing_scanner_refuses_and_writes_nothing() {
    let absent = Rig::bare("offbox-snapshot-scanner-absent");
    let failing = Rig::bare("offbox-snapshot-scanner-failing");
    failing.install("#!/bin/sh\nexit 2\n");

    for (rig, refusal) in [
        (&absent, Refusal::ScannerAbsent),
        (&failing, Refusal::ScannerFailed),
    ] {
        let meta = Rig::meta("refused");
        rig.state_file("captures/a/one.txt", "one\n");
        let path = rig.source("main");
        write(&path, &records(0, 5, 200));
        let source = JsonlFile::at(&path);

        let outcome = rig.snap(&meta, &[feed(MAIN, &source)], TIME, NO_CAP);

        assert_eq!(outcome, Snapshot::Refused(refusal));
        let dir = rig.dir(&meta);
        assert!(
            !dir.join("cursor.json").exists(),
            "no cursor entry is written"
        );
        assert!(!dir.join("transcript").exists(), "no record is read");
        assert!(!dir.join("staging").exists(), "staging is removed");
        assert_eq!(
            batten::git::resolve_ref(&offbox::local_repo(&dir), offbox::LAST).unwrap(),
            None
        );
    }
}
