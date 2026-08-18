//! End-to-end: the enforce surface journals, and the secret-identity key has
//! rotation and loss custody (CLOUD-529).
//!
//! # Why this is a separate target
//!
//! Every case here needs the same fixture and it is an expensive one: a git
//! repository, an isolated `HOME`/`XDG_DATA_HOME` so the store and the minted key
//! land somewhere the test owns, and for the secret-class half a provisioned stub
//! scanner. That is `tests/secrets_kind.rs`'s shape and `tests/advisory_drain.rs`'s
//! reason for existing beside `tests/cli.rs` rather than inside it.
//!
//! # What only an end-to-end case can pin
//!
//! The unit suites cover the decisions — the fold, the ratio, the custody
//! refusals. What they structurally cannot reach is the *wiring*: that `enforce`
//! reaches the store at all and `check` does not, that journaling cannot move an
//! exit code, that `state record` still refuses a spawning kind, and that a
//! custody event an operator has to see is actually printed. Each of those is a
//! claim about which surface does what, and a library call proves nothing about it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, batten, git_in, scratch};

/// A repository plus the out-of-tree state it writes into.
struct Env {
    repo: PathBuf,
    home: PathBuf,
    artifacts: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .build();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        Env {
            repo,
            home: root.join("home"),
            artifacts,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        batten()
            .args(args)
            .current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("APPDATA", self.home.join("data"))
            .output()
            .expect("run batten")
    }

    fn file(&self, path: &str, contents: &str) {
        let full = self.repo.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, contents).unwrap();
    }

    /// The state root every out-of-tree write lands under.
    fn state(&self) -> PathBuf {
        self.home.join("data").join("batten")
    }

    /// This repository's state segment, found rather than derived: the segment
    /// carries a checkout digest, and recomputing it here would be a second
    /// implementation of `state::derive_repo_name` that could drift from the one
    /// under test.
    fn segment(&self) -> PathBuf {
        let name = self
            .repo
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        fs::read_dir(self.state())
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|found| found.to_string_lossy().starts_with(&name))
            })
            .expect("the repository's state segment exists once something has written")
    }

    fn key_file(&self) -> PathBuf {
        self.segment().join("identity").join("secret-key")
    }

    fn ledger(&self) -> PathBuf {
        self.segment().join("identity").join("custody.jsonl")
    }

    /// Bind the store, which `state record` is the declared verb for.
    ///
    /// Called with a config carrying **no** spawning kind, because that verb
    /// refuses one — which is the whole reason the journaling had to move to the
    /// enforce surface, and is asserted directly further down.
    fn bind_store(&self) {
        self.file("batten.toml", &forbid_only());
        let recorded = self.run(&["state", "record"]);
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "state record: {}",
            common::stderr(&recorded)
        );
    }

    /// Every stored record, as `state list -J` parses it.
    fn records(&self) -> Vec<serde_json::Value> {
        let listed = self.run(&["state", "list", "-J"]);
        assert_eq!(
            listed.status.code(),
            Some(0),
            "state list: {}",
            common::stderr(&listed)
        );
        serde_json::from_str(&common::stdout(&listed)).expect("state list -J is a document")
    }

    /// One record by rule id, or `None`.
    fn record(&self, rule: &str) -> Option<serde_json::Value> {
        self.records()
            .into_iter()
            .find(|record| record["rule"] == rule)
    }

    /// Settle a finding's disposition by writing the record.
    ///
    /// **No verb sets one yet**, which is why this reaches into the store rather
    /// than driving the CLI: `journal::Entry` has carried a disposition since
    /// CLOUD-78 and the surface that supplies it is still ahead. The cases below
    /// need a *settled* record because that is the state custody has to be able to
    /// keep across a rotation and to undo on a loss, and asserting on a state the
    /// fixture cannot create would be asserting its own premise.
    fn settle(&self, fingerprint: &str, disposition: &str) {
        let path = self
            .segment()
            .join("findings")
            .join(format!("{fingerprint}.json"));
        let mut record: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        record["disposition"] = serde_json::Value::String(disposition.to_owned());
        fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(
            self.records()
                .iter()
                .find(|found| found["identity"]["fingerprint"] == fingerprint)
                .map(|found| found["disposition"].clone()),
            Some(serde_json::Value::String(disposition.to_owned())),
            "the fixture's premise: the store really does read this record back settled"
        );
    }
}

/// A config with one static rule: what the read surface can compute.
fn forbid_only() -> String {
    "version = 1\n\n\
     [[rule]]\n\
     id = \"no-todo\"\n\
     kind = \"forbid\"\n\
     glob = \"**/*.rs\"\n\
     pattern = \"TODO\"\n\
     severity = \"deny\"\n\
     no_fix_reason = \"delete the marker\"\n"
        .to_owned()
}

/// The same config plus a `command` rule — an enforce-only kind, because it runs a
/// process declared in `batten.toml`.
///
/// `no_fix_reason` rather than `fix`: `run_all` refuses a rule declaring `fix`
/// (CLOUD-215), and the store refuses a finding with no remediation at all, so this
/// is the one column a storable command rule can carry.
fn with_command(check: &str) -> String {
    format!(
        "{}\n\
         [[rule]]\n\
         id = \"gate\"\n\
         kind = \"command\"\n\
         glob = \"**/*.rs\"\n\
         check = \"{check}\"\n\
         severity = \"deny\"\n\
         no_fix_reason = \"fix what the gate names\"\n",
        forbid_only()
    )
}

// --- (a) an enforce-only kind reaches the store, idempotently -----------------

#[test]
fn an_enforce_only_kinds_finding_reaches_the_store_and_is_idempotent() {
    let env = Env::new("enforce-journal-command");
    env.file("src/a.rs", "fn main() {}\n");
    env.bind_store();
    assert!(
        env.record("gate").is_none(),
        "the read surface cannot compute a command rule's finding at all"
    );

    env.file("batten.toml", &with_command("false"));
    let first = env.run(&["enforce"]);
    assert_eq!(
        first.status.code(),
        Some(2),
        "a deny finding is still a violation: {}",
        common::stderr(&first)
    );
    let gate = env
        .record("gate")
        .expect("the command rule's finding reached the store");
    let fingerprint = gate["identity"]["fingerprint"].as_str().unwrap().to_owned();
    assert_eq!(fingerprint.len(), 64, "a pointer, and the whole pointer");

    // Idempotent on identity: a second run of the same scan is the same finding
    // with the same key, never a second record.
    let second = env.run(&["enforce"]);
    assert_eq!(second.status.code(), Some(2));
    let after = env.record("gate").unwrap();
    assert_eq!(
        after["identity"]["fingerprint"].as_str().unwrap(),
        fingerprint
    );
    assert_eq!(
        env.records().iter().filter(|r| r["rule"] == "gate").count(),
        1
    );
}

// The static half of the same scan keeps the identity the read surface minted, so
// the two surfaces agree about what a finding IS rather than each keying its own.
#[test]
fn the_enforce_surface_keys_a_static_finding_exactly_as_the_read_surface_did() {
    let env = Env::new("enforce-journal-identity");
    env.file("src/a.rs", "// TODO: later\n");
    env.bind_store();
    let recorded = env.record("no-todo").expect("the read surface recorded it")["identity"].clone();

    env.file("batten.toml", &with_command("false"));
    env.run(&["enforce"]);
    assert_eq!(
        env.record("no-todo").unwrap()["identity"],
        recorded,
        "same finding, same identity, whichever surface looked"
    );
}

// --- (b) the recording verb's effect did not move ----------------------------

#[test]
fn state_record_still_refuses_a_spawning_kind_and_records_nothing_from_it() {
    let env = Env::new("enforce-journal-effect");
    env.file("src/a.rs", "fn main() {}\n");
    env.bind_store();

    env.file("batten.toml", &with_command("false"));
    let recorded = env.run(&["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(1),
        "a recording verb that could execute a configured command is a much larger \
         promise than remembering what the read-only gates found"
    );
    assert!(
        common::stderr(&recorded).contains("batten enforce"),
        "the refusal names the verb that runs it: {}",
        common::stderr(&recorded)
    );
    assert!(
        env.record("gate").is_none(),
        "and it recorded nothing from the kind it refused"
    );
}

// Journaling is a side record of a verdict already reached, so it cannot move the
// exit code in either direction — including the case where the store write itself
// has nowhere to go.
#[test]
fn journaling_never_moves_the_exit_code() {
    let env = Env::new("enforce-journal-exit");
    env.file("src/a.rs", "fn main() {}\n");
    // No `state record`, so there is no bound store: the enforce surface has
    // nothing to journal into and must still render the same verdict.
    env.file("batten.toml", &with_command("false"));
    let unbound = env.run(&["enforce"]);
    assert_eq!(unbound.status.code(), Some(2));
    assert!(
        !common::stderr(&unbound).contains("no bound findings store"),
        "the note is verbose-only; a default run spends nothing on it: {}",
        common::stderr(&unbound)
    );
    let told = env.run(&["-v", "enforce"]);
    assert!(
        common::stderr(&told).contains("not journalled"),
        "and it is available when asked for: {}",
        common::stderr(&told)
    );

    // A clean gate is exit 0 with the store bound, which is the other direction.
    env.bind_store();
    env.file("batten.toml", &with_command("true"));
    let clean = env.run(&["enforce"]);
    assert_eq!(clean.status.code(), Some(0), "{}", common::stderr(&clean));
}

// `check` must reach no store write at all — that is what keeps its `read` effect
// honest, and it is a property of the surface rather than of the kinds configured.
#[test]
fn the_read_surface_journals_nothing() {
    let env = Env::new("enforce-journal-check");
    env.file("src/a.rs", "// TODO: later\n");
    env.bind_store();
    let before = env.records();

    // A config with no spawning kind, so `check` runs rather than refusing.
    env.file("src/b.rs", "// TODO: also later\n");
    let checked = env.run(&["check"]);
    assert_eq!(checked.status.code(), Some(2), "it still finds them");
    assert_eq!(
        env.records(),
        before,
        "and records none of it: the second file's finding is nowhere in the store"
    );
}

// --- the secret class: journaling, then custody -------------------------------

/// The fragments the synthetic credential is assembled from, split so no
/// contiguous token exists in a committed byte — consumer #1's own `no-secrets`
/// rule globs this file.
const TOKEN_PARTS: [&str; 5] = ["AKIA", "6RJ4", "MP2T", "V8QX", "L3ZB"];

fn token() -> String {
    TOKEN_PARTS.concat()
}

/// A stub scanner reporting one match, in ripsecrets' measured output shape.
///
/// The token is reassembled inside the script so it is not a literal there
/// either: `provision` caches the artifact bytes by contract, and a literal would
/// put the token under the state root — which is exactly where a leak would land.
fn stub(path: &str, line: usize) -> String {
    let mut parts = String::new();
    for part in TOKEN_PARTS {
        parts.push('"');
        parts.push_str(part);
        parts.push('"');
    }
    format!("#!/bin/sh\nT={parts}\nprintf '%s\\n' \"{path}:{line}:$T\"\nexit 1\n")
}

/// A config carrying the provisioned stub and a `secrets` rule beside the static
/// one, so a run produces both classes of record.
fn secrets_config(url: &str, sha: &str) -> String {
    // A TOML *literal* string for the url, because it carries a filesystem
    // path: `file://D:\a\batten\...` in a basic string reads `\a` as a
    // control character and rejects `\U`, so the config fails to parse and
    // every case here dies on its own fixture rather than on its subject
    // (CLOUD-113's Windows job). Literal strings process no escapes.
    format!(
        "{}\n\
         [[provision]]\n\
         name = \"ripsecrets\"\n\
         version = \"0.0.0-stub\"\n\
         url = '{url}'\n\
         sha256 = \"{sha}\"\n\
         binary = \"ripsecrets\"\n\n\
         [[rule]]\n\
         id = \"no-secrets\"\n\
         kind = \"secrets\"\n\
         glob = \"**/*.conf\"\n\
         severity = \"deny\"\n\
         scope = \"tree\"\n\
         no_fix_reason = \"rotate the credential and remove it\"\n",
        forbid_only()
    )
}

/// A fixture whose `enforce` produces one secret-class record.
fn secret_env(name: &str) -> Env {
    let env = Env::new(name);
    env.file("src/a.rs", "fn main() {}\n");
    env.file("app.conf", "token = placeholder\n");
    env.bind_store();

    let scanner = env.artifacts.join("ripsecrets");
    fs::write(&scanner, stub("app.conf", 1)).unwrap();
    let sha = digest(&fs::read(&scanner).unwrap());
    env.file(
        "batten.toml",
        &secrets_config(&format!("file://{}", scanner.display()), &sha),
    );
    let applied = env.run(&["provision", "apply"]);
    assert!(
        applied.status.success(),
        "the stub scanner installs: {}",
        common::stderr(&applied)
    );
    let enforced = env.run(&["enforce"]);
    assert_eq!(
        enforced.status.code(),
        Some(2),
        "the planted secret is a deny finding: {}",
        common::stderr(&enforced)
    );
    env
}

// (a) for the other enforce-only kind, plus (e): the class carries no
// `FindingKind`, so nothing may classify it — and the record still has to be
// storable and emittable rather than filtered away for being unclassifiable.
#[test]
fn a_secret_class_finding_reaches_the_store_carrying_no_kind() {
    let env = secret_env("enforce-journal-secret");
    let record = env
        .record("no-secrets")
        .expect("the secrets kind's finding reached the store");
    assert_eq!(
        record["identity"]["version"].as_str().unwrap(),
        "secret:2026-08-13",
        "the version names no kind, which is what makes `kind()` answer None"
    );
    assert_eq!(
        record["identity"]["fingerprint"].as_str().unwrap().len(),
        64
    );
    // Pointer-only, in the channel a consumer actually reads back.
    let listed = common::stdout(&env.run(&["state", "list", "-J"]));
    assert!(!listed.contains(&token()), "the store holds no span");

    // And the unclassifiable record is not scope-filtered away: the drain's own
    // filter reads `kind()`, and `None` must bypass rather than default to `Code`.
    // `state list` shows it whatever the changed scope; the drain's side of this is
    // pinned in `drain.rs`'s own suite over a synthetic future version.
    assert_eq!(
        env.records()
            .iter()
            .filter(|r| r["rule"] == "no-secrets")
            .count(),
        1
    );
}

// (d) key loss: the loud orphan event, and never a silent re-mint.
#[test]
fn a_lost_key_re_opens_its_findings_loudly_and_re_mints_nothing() {
    let env = secret_env("enforce-journal-orphan");
    let before = env.record("no-secrets").unwrap();
    let fingerprint = before["identity"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();

    // The finding is triaged, which is the state a loss has to be able to undo:
    // the decision was reached by looking at evidence that can no longer be
    // reproduced, so keeping it would assert a triage nobody can now check.
    env.settle(&fingerprint, "rejected-by-design");

    // The generation the ledger names goes missing. This is the case the key file
    // ALONE cannot see: absent-and-re-minted is indistinguishable from a first
    // mint, which is why the predicate is ledger-against-file.
    let ledger_before = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger_before.contains("minted"), "{ledger_before}");
    fs::remove_file(env.key_file()).unwrap();

    let next = env.run(&["enforce"]);
    let told = common::stderr(&next);
    assert!(
        told.contains("re-opened for re-triage"),
        "the event is loud and unladdered: {told}"
    );
    assert!(
        told.contains("nothing has been re-minted"),
        "and says what it did not do: {told}"
    );
    assert!(!told.contains(&token()), "pointer-only: {told}");

    let ledger_after = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger_after.contains("orphaned"), "{ledger_after}");

    // Re-opened means unsettled, so an operator re-triages rather than inheriting
    // a decision about evidence that is gone.
    let reopened = env
        .records()
        .into_iter()
        .find(|record| record["identity"]["fingerprint"] == fingerprint.as_str())
        .expect("the record is still there — re-opened, not removed");
    assert!(
        reopened["disposition"].is_null(),
        "{}",
        reopened["disposition"]
    );

    // Reported ONCE. A loud event on every subsequent run is a line, not an event,
    // and it would re-open a finding the operator had just re-triaged.
    let again = env.run(&["enforce"]);
    assert!(
        !common::stderr(&again).contains("re-opened for re-triage"),
        "{}",
        common::stderr(&again)
    );
}

// (c) the store side of rotation: a join moves a record onto its new identity
// carrying everything the old one knew, and closing the window is what says the
// rotation finished.
#[test]
fn a_rotation_join_moves_the_record_and_keeps_its_disposition() {
    let env = secret_env("enforce-journal-rotate");
    let old = env.record("no-secrets").unwrap()["identity"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    env.settle(&old, "rejected-by-design");

    // A rotation window, opened the way an operator would: two generations in the
    // key file, current first. Written here rather than through a verb because
    // rotation deliberately adds no command and no effect-table row.
    let text = fs::read_to_string(env.key_file()).unwrap();
    let mut lines = text.lines();
    let old_id = lines.next().unwrap().to_owned();
    let old_hex = lines.next().unwrap().to_owned();
    let new_hex = "1".repeat(64);
    fs::write(
        env.key_file(),
        format!("2099-01-01\n{new_hex}\n{old_id}\n{old_hex}\n"),
    )
    .unwrap();

    // The scan mints under the new key and pairs it with the old one while both are
    // held, which is the only moment the pair is computable at all.
    let rotated = env.run(&["enforce"]);
    let told = common::stderr(&rotated);
    assert!(told.contains("re-keyed"), "{told}");

    let ledger = fs::read_to_string(env.ledger()).unwrap();
    assert!(ledger.contains("joined"), "{ledger}");
    assert!(
        !ledger.contains(&old_hex),
        "the ledger carries no key bytes"
    );

    let moved = env.record("no-secrets").unwrap();
    let new = moved["identity"]["fingerprint"].as_str().unwrap();
    assert_ne!(new, old, "the identity moved with the key");
    assert_eq!(
        moved["disposition"].as_str(),
        Some("rejected-by-design"),
        "and the decision travelled: a rotation that dropped it would resurrect \
         every finding a reviewer had already dismissed"
    );
    assert_eq!(
        env.records()
            .iter()
            .filter(|r| r["rule"] == "no-secrets")
            .count(),
        1,
        "one finding, not two — the pre-rotation file is dropped, and it must be, \
         because nothing can re-derive that fingerprint to clear it"
    );

    // Nothing is keyed under the retired generation any more, so the window closes
    // and the key file holds one generation again.
    assert!(told.contains("rotation complete"), "{told}");
    assert_eq!(
        fs::read_to_string(env.key_file()).unwrap().lines().count(),
        2
    );
}

/// The store's own segment is where every custody file lives, out of tree.
///
/// Asserted rather than assumed: the whole containment argument depends on the key
/// never being in the repository, and a test that only checked the state root
/// would pass with a key committed beside `batten.toml`.
#[test]
fn no_custody_file_is_ever_written_into_the_repository() {
    let env = secret_env("enforce-journal-out-of-tree");
    assert!(env.key_file().starts_with(env.state()));
    assert!(env.ledger().starts_with(env.state()));
    let tracked = git_in(&env.repo, &["status", "--porcelain"]);
    assert!(
        !tracked.contains("secret-key") && !tracked.contains("custody"),
        "{tracked}"
    );
    assert!(!in_tree(&env.repo, "secret-key"), "the key is out of tree");
}

/// Whether any path under `root` (excluding `.git`) carries `needle` in its name.
fn in_tree(root: &Path, needle: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            return false;
        }
        name.contains(needle) || (path.is_dir() && in_tree(&path, needle))
    })
}
