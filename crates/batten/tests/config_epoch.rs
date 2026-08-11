//! End-to-end tests over the compiled binary for `batten config epoch`
//! (CLOUD-32).
//!
//! The epoch's whole value is attribution: two records carrying the same epoch
//! were produced under provably the same rules. That claim rests on three
//! properties, and each is asserted here rather than argued from the code —
//! it is **stable** for an unchanged surface, it **moves** when any tracked file
//! changes, and it **refuses** rather than skipping a path it cannot read.
//!
//! That third one is the load-bearing case. A skip would compute a *stable*
//! epoch over a surface that changed, which looks exactly like a valid answer:
//! the failure would be invisible precisely when attribution mattered.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Fixture, batten};

/// A scratch repository containing `batten.toml` plus any extra files.
fn repo(name: &str, config: &str, files: &[(&str, &str)]) -> PathBuf {
    Fixture::at(std::env::temp_dir().join("batten-epoch-e2e").join(name))
        .config(config)
        .files(files)
        .build()
}

fn epoch(dir: &Path) -> Output {
    common::run(dir, &["config", "epoch"])
}

fn value(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// --- stable, and moves when the surface does ---------------------------------

#[test]
fn the_epoch_is_stable_across_runs_on_an_unchanged_tree() {
    let dir = repo("epoch-stable", "version = 1\n", &[]);
    let first = epoch(&dir);
    let second = epoch(&dir);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(value(&first).len(), 64, "lowercase hex, 32 bytes");
}

#[test]
fn editing_any_tracked_file_changes_the_epoch() {
    // Asserted per file rather than on one of them: a fold that hashed only the
    // first entry would pass a single-file test and be wrong for every real
    // tracked set.
    let config =
        "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"guide.md\", \"hooks.conf\"]\n";
    let files = [("guide.md", "guidance\n"), ("hooks.conf", "config\n")];
    let dir = repo("epoch-moves", config, &files);
    let before = value(&epoch(&dir));

    for (path, _) in files {
        fs::write(dir.join(path), "edited\n").expect("edit tracked file");
        assert_ne!(
            before,
            value(&epoch(&dir)),
            "editing {path} left the epoch unchanged"
        );
        // Restore, so each file is tested against the same baseline.
        let original = files.iter().find(|(p, _)| *p == path).expect("file").1;
        fs::write(dir.join(path), original).expect("restore");
    }
    assert_eq!(
        before,
        value(&epoch(&dir)),
        "restoring must restore the epoch"
    );
}

#[test]
fn editing_the_config_itself_changes_the_epoch() {
    // The default tracked set is `batten.toml`, so a policy edit always moves
    // the epoch even in a repository that declares no `[epoch]` table.
    let dir = repo("epoch-config-edit", "version = 1\n", &[]);
    let before = value(&epoch(&dir));
    fs::write(
        dir.join("batten.toml"),
        "version = 1\nstrictness = \"strict\"\n",
    )
    .expect("edit config");
    assert_ne!(before, value(&epoch(&dir)));
}

#[test]
fn an_untracked_file_does_not_move_the_epoch() {
    // The epoch attributes *policy*, not the working tree. If every file moved
    // it, it would change on every commit and attribute nothing.
    let dir = repo(
        "epoch-untracked",
        "version = 1\n",
        &[("src.rs", "fn main() {}\n")],
    );
    let before = value(&epoch(&dir));
    fs::write(dir.join("src.rs"), "fn main() { todo!() }\n").expect("edit untracked file");
    assert_eq!(before, value(&epoch(&dir)));
}

#[test]
fn authoring_order_does_not_reach_the_value() {
    // Two configs governing the same surface must attribute identically, or the
    // epoch would distinguish records that were produced under the same rules.
    let files = [("a", "one\n"), ("b", "two\n")];
    let forward = repo(
        "epoch-order-forward",
        "version = 1\n\n[epoch]\ntracked = [\"a\", \"b\"]\n",
        &files,
    );
    let reverse = repo(
        "epoch-order-reverse",
        "version = 1\n\n[epoch]\ntracked = [\"b\", \"a\"]\n",
        &files,
    );
    // The configs differ textually, so `batten.toml` is deliberately not in
    // either tracked set — the test is about ordering, not about the config.
    assert_eq!(value(&epoch(&forward)), value(&epoch(&reverse)));
}

#[test]
fn tracking_one_more_file_changes_the_epoch_even_when_it_is_empty() {
    // The *set* is part of what governs, so the path is hashed as well as the
    // bytes. Without that, adding an empty file to the tracked set would be
    // invisible — and so would starting to govern by it.
    let files = [("extra", "")];
    let one = repo("epoch-set-one", "version = 1\n", &files);
    let two = repo(
        "epoch-set-two",
        "version = 1\n\n[epoch]\ntracked = [\"extra\"]\n",
        &files,
    );
    assert_ne!(value(&epoch(&one)), value(&epoch(&two)));
}

// --- an unreadable tracked path fails, never skips ---------------------------

#[test]
fn a_missing_tracked_path_is_refused_by_name_rather_than_forging_a_stable_epoch() {
    // CLOUD-32's load-bearing refusal, and the reason it is exit 1: the
    // `[epoch] tracked` set IS config — it defaults to batten.toml itself — so
    // an unreadable tracked path is unreadable config, which §7 routes to 1.
    // `3` stays for an I/O failure not attributable to the config. Same shape as
    // config_trust's unreadable-ref case, which also names what it could not
    // read: a refusal the reader cannot act on is barely better than a skip.
    let dir = repo(
        "epoch-missing-path",
        "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"gone.md\"]\n",
        &[],
    );
    let output = epoch(&dir);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "no value may be printed for a surface that could not be read"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("gone.md"),
        "the refusal must name the path it could not read"
    );
}

#[test]
fn a_tracked_directory_is_a_failure_not_a_skip() {
    // A directory reads as an error rather than as empty bytes; treating it as
    // empty would hash a surface nobody declared.
    let dir = repo(
        "epoch-tracked-dir",
        "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"adir\"]\n",
        &[("adir/inner", "x\n")],
    );
    assert_eq!(epoch(&dir).status.code(), Some(1));
}

#[test]
fn an_absolute_tracked_path_is_a_usage_error() {
    // An epoch that depended on a checkout location would differ between two
    // clones of the same commit. That is bad *input*, so exit 1, not 3.
    let dir = repo(
        "epoch-absolute",
        "version = 1\n\n[epoch]\ntracked = [\"/etc/hostname\"]\n",
        &[],
    );
    assert_eq!(epoch(&dir).status.code(), Some(1));
}

#[test]
fn a_missing_config_is_a_usage_error() {
    let dir = std::env::temp_dir()
        .join("batten-epoch-e2e")
        .join("no-config");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");
    assert_eq!(epoch(&dir).status.code(), Some(1));
}

// --- the epoch follows the authority that governed the run -------------------

#[test]
fn under_config_from_the_epoch_is_the_refs_surface_not_the_working_trees() {
    // An epoch attributing a run to a config that did NOT govern it would be
    // worse than none: the whole value is "these two records ran under the same
    // rules". Under `--config-from`, the ref's config governs, so the ref's
    // surface is what the epoch must cover — both the tracked list and the
    // bytes (CLOUD-31).
    let dir = repo("epoch-config-from", "version = 1\n", &[]);
    for args in [
        &["init", "-q"][..],
        &["config", "user.email", "t@example.com"],
        &["config", "user.name", "t"],
        &["add", "-A"],
        &["commit", "-q", "-m", "base"],
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("run git");
        assert!(output.status.success(), "git {args:?} failed");
    }
    let base = value(&epoch(&dir));

    // Change the working tree only. The ref still holds the base bytes.
    fs::write(
        dir.join("batten.toml"),
        "version = 1\nstrictness = \"strict\"\n",
    )
    .expect("edit working config");
    let working = value(&epoch(&dir));
    assert_ne!(base, working, "the working-tree epoch must have moved");

    let from_ref = batten()
        .args(["config", "epoch", "--config-from", "origin/main"])
        .current_dir(&dir)
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config epoch --config-from");
    assert_eq!(from_ref.status.code(), Some(0));
    assert_eq!(
        value(&from_ref),
        base,
        "under --config-from the epoch must be the ref's surface, not the working tree's"
    );
}

// --- the surface and the doctor join -----------------------------------------

#[test]
fn config_epoch_is_declared_read_in_the_spec() {
    let output = batten().arg("spec").output().expect("run batten spec");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let config = spec["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config")
        .expect("config is in the spec");
    let epoch = config["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config epoch")
        .expect("config epoch is in the spec");
    assert_eq!(epoch["effect"], "read");
}

#[test]
fn doctor_json_carries_the_same_epoch_the_verb_prints() {
    // The join CLOUD-133 will key guard records on: two surfaces reporting the
    // epoch must report the *same* one, or a record could not be matched to a
    // diagnosis.
    let dir = repo("epoch-doctor-join", "version = 1\n", &[]);
    let printed = value(&epoch(&dir));
    let output = batten()
        .args(["doctor", "--json"])
        .current_dir(&dir)
        .output()
        .expect("run batten doctor");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["config_epoch"], printed);
}

#[test]
fn doctor_omits_the_epoch_when_the_surface_cannot_be_read() {
    // Absent rather than a placeholder: a placeholder would be a stable value
    // over an unknown surface, the exact thing the epoch exists to prevent.
    // `doctor` still exits 1 rather than 3 — it stays the config-or-usage-only
    // verb §7 needs it to be, and its `config` check already names the cause.
    let dir = std::env::temp_dir()
        .join("batten-epoch-e2e")
        .join("doctor-no-epoch");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");
    let output = batten()
        .args(["doctor", "--json"])
        .current_dir(&dir)
        .output()
        .expect("run batten doctor");
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert!(report.get("config_epoch").is_none(), "got: {report}");
}

#[test]
fn this_repositorys_own_epoch_is_computable() {
    // Consumer #1: Batten's own `[epoch] tracked` list is a worked example of
    // the feature, in the config the feature reads — so it has to work.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = batten()
        .args(["config", "epoch"])
        .current_dir(&root)
        .output()
        .expect("run batten config epoch");
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's tracked surface is unreadable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value(&output).len(), 64);
}

// --- the cache, and the equality that makes it safe (CLOUD-232) --------------
//
// A cache over an attribution value is only admissible if it cannot answer
// differently from the recompute it replaces. So these assert an *equality*
// against `--no-cache` rather than asserting that caching "works": a cache that
// is fast and wrong is strictly worse than no cache, and the failure would be
// silent exactly when attribution mattered.
//
// Every case runs with `XDG_DATA_HOME` pointed at scratch. The cache lives in
// the OS data directory by design (never in the checkout), and a suite that
// wrote into the developer's real one would both pollute it and let two tests
// collide through it.

/// Run `config epoch` with the cache isolated to `home`.
fn epoch_in(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let mut command = batten();
    command.args(["config", "epoch"]).args(args);
    command.env("XDG_DATA_HOME", home);
    command
        .current_dir(dir)
        .output()
        .expect("run batten config epoch")
}

/// A scratch `XDG_DATA_HOME`, wiped so each test starts with no cache.
fn cache_home(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join("batten-epoch-cache").join(name);
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).expect("create cache home");
    home
}

/// The cache file for the repo at `dir`, wherever it landed under `home`.
fn cache_file(home: &Path, dir: &Path) -> PathBuf {
    let repo = dir.file_name().expect("repo dir has a name");
    home.join("batten").join(repo).join("epoch.json")
}

#[test]
fn a_cache_hit_equals_the_cold_recompute() {
    // The safety bar. The second run is served from the cache written by the
    // first; if the two ever diverge the epoch stops meaning "produced under
    // provably the same rules", which is the only thing it is for.
    let dir = repo(
        "cache-equals-cold",
        "version = 1\n",
        &[("AGENTS.md", "a\n")],
    );
    let home = cache_home("cache-equals-cold");

    let cold = epoch_in(&dir, &home, &["--no-cache"]);
    let warm_write = epoch_in(&dir, &home, &[]);
    let warm_read = epoch_in(&dir, &home, &[]);

    assert_eq!(cold.status.code(), Some(0));
    assert_eq!(warm_read.status.code(), Some(0));
    assert_eq!(
        cold.stdout, warm_write.stdout,
        "the run that populates the cache already disagrees with the cold path"
    );
    assert_eq!(
        cold.stdout, warm_read.stdout,
        "a cache HIT disagrees with the cold recompute"
    );
    assert!(cache_file(&home, &dir).exists(), "nothing was cached");
}

#[test]
fn editing_a_tracked_file_invalidates_the_cache() {
    let dir = repo(
        "cache-invalidates",
        "version = 1\n[epoch]\ntracked = [\"batten.toml\", \"AGENTS.md\"]\n",
        &[("AGENTS.md", "before\n")],
    );
    let home = cache_home("cache-invalidates");

    let before = value(&epoch_in(&dir, &home, &[]));
    fs::write(dir.join("AGENTS.md"), "after, and a different length\n").expect("rewrite");
    let after = epoch_in(&dir, &home, &[]);

    assert_ne!(before, value(&after), "a stale hash was served");
    assert_eq!(
        value(&after),
        value(&epoch_in(&dir, &home, &["--no-cache"])),
        "the post-edit cached value disagrees with the recompute"
    );
}

#[test]
fn a_tracked_path_that_goes_unreadable_after_a_cache_write_is_refused() {
    // THE case this whole design turns on. A warm cache plus a vanished tracked
    // path must exit 1 naming it — never a stale-but-successful hash. Serving
    // the cached value here would forge a stable epoch over a surface that
    // changed and exit 0 doing it, which is the precise false green the module
    // exists to prevent, reintroduced as an optimization.
    let dir = repo(
        "cache-unreadable",
        "version = 1\n[epoch]\ntracked = [\"batten.toml\", \"GONE.md\"]\n",
        &[("GONE.md", "here for now\n")],
    );
    let home = cache_home("cache-unreadable");

    let warm = epoch_in(&dir, &home, &[]);
    assert_eq!(warm.status.code(), Some(0), "setup: the cache must be warm");
    assert!(
        cache_file(&home, &dir).exists(),
        "setup: nothing was cached"
    );

    fs::remove_file(dir.join("GONE.md")).expect("remove the tracked path");
    let after = epoch_in(&dir, &home, &[]);

    assert_eq!(
        after.status.code(),
        Some(1),
        "a cached hash was served over an unreadable tracked path; stdout: {}",
        String::from_utf8_lossy(&after.stdout)
    );
    assert!(
        String::from_utf8_lossy(&after.stderr).contains("GONE.md"),
        "the refusal must name the path it could not read"
    );
    assert!(after.stdout.is_empty(), "a refusal printed a value");
}

#[test]
fn a_corrupt_cache_costs_the_run_nothing() {
    // Derived out-of-tree state: unreadable, truncated, or written by a future
    // format are all the same answer — recompute. A cache that can fail a run is
    // worse than no cache.
    let dir = repo("cache-corrupt", "version = 1\n", &[]);
    let home = cache_home("cache-corrupt");

    let expected = value(&epoch_in(&dir, &home, &["--no-cache"]));
    epoch_in(&dir, &home, &[]);
    fs::write(cache_file(&home, &dir), "{ not json at all").expect("corrupt the cache");

    let after = epoch_in(&dir, &home, &[]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "a corrupt cache failed the run"
    );
    assert_eq!(value(&after), expected);
}

#[test]
fn a_future_cache_format_is_a_miss_rather_than_a_misread() {
    let dir = repo("cache-future", "version = 1\n", &[]);
    let home = cache_home("cache-future");

    let expected = value(&epoch_in(&dir, &home, &["--no-cache"]));
    epoch_in(&dir, &home, &[]);
    let path = cache_file(&home, &dir);
    let mut record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read cache"))
            .expect("cache is JSON");
    record["schema"] = serde_json::json!(u32::MAX);
    record["epoch"] = serde_json::json!("0".repeat(64));
    fs::write(&path, record.to_string()).expect("write cache");

    assert_eq!(
        value(&epoch_in(&dir, &home, &[])),
        expected,
        "a record from an unrecognised format version was believed"
    );
}

#[test]
fn adding_a_tracked_path_invalidates_even_when_no_file_changed() {
    // The stamped set carries the tracked LIST, not just each file's state. A
    // cache keyed only on the surviving files' stamps would serve the old hash
    // over a surface that provably grew.
    let dir = repo(
        "cache-list-grows",
        "version = 1\n[epoch]\ntracked = [\"batten.toml\"]\n",
        &[("AGENTS.md", "unchanged throughout\n")],
    );
    let home = cache_home("cache-list-grows");

    let before = value(&epoch_in(&dir, &home, &[]));
    fs::write(
        dir.join("batten.toml"),
        "version = 1\n[epoch]\ntracked = [\"batten.toml\", \"AGENTS.md\"]\n",
    )
    .expect("widen the tracked list");

    let after = epoch_in(&dir, &home, &[]);
    assert_ne!(before, value(&after));
    assert_eq!(
        value(&after),
        value(&epoch_in(&dir, &home, &["--no-cache"])),
        "the widened surface's cached value disagrees with the recompute"
    );
}

#[test]
fn the_json_document_is_identical_warm_and_cold() {
    // `-J` carries the tracked list as well as the digest, so the cached path
    // must reproduce BOTH halves — a hit that served the right hash with a
    // stale surface would be a document whose two halves disagree.
    let dir = repo(
        "cache-json",
        "version = 1\n[epoch]\ntracked = [\"batten.toml\", \"AGENTS.md\"]\n",
        &[("AGENTS.md", "a\n")],
    );
    let home = cache_home("cache-json");

    let cold = epoch_in(&dir, &home, &["-J", "--no-cache"]);
    epoch_in(&dir, &home, &["-J"]);
    let warm = epoch_in(&dir, &home, &["-J"]);

    assert_eq!(cold.status.code(), Some(0));
    assert_eq!(
        cold.stdout, warm.stdout,
        "the -J document differs warm vs cold"
    );
}

#[test]
fn config_from_neither_reads_nor_writes_the_cache() {
    // The stamps describe the working tree; under `--config-from` the epoch
    // covers a git ref instead. Revalidating a ref's hash against the worktree's
    // mtimes would compare two different things — so that path is cold, and it
    // must also leave no record a later worktree run could hit.
    let dir = repo("cache-config-from", "version = 1\n", &[]);
    let home = cache_home("cache-config-from");
    for args in [
        &["init", "-q"][..],
        &["config", "user.email", "t@example.com"],
        &["config", "user.name", "t"],
        &["add", "-A"],
        &["commit", "-q", "-m", "base"],
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("run git");
        assert!(output.status.success(), "git {args:?} failed");
    }

    // Diverge the working tree from the ref, so a cache confusion between them
    // is observable rather than hidden behind two equal answers.
    fs::write(
        dir.join("batten.toml"),
        "version = 1\nstrictness = \"strict\"\n",
    )
    .expect("edit working config");

    let from_ref = epoch_in(&dir, &home, &["--config-from", "origin/main"]);
    assert_eq!(from_ref.status.code(), Some(0));
    assert!(
        !cache_file(&home, &dir).exists(),
        "the --config-from path wrote a cache entry keyed to the working tree"
    );

    // And it does not READ one either: warm the cache from the worktree, then
    // ask for the ref again — the answer must still be the ref's.
    let worktree = value(&epoch_in(&dir, &home, &[]));
    assert_ne!(
        worktree,
        value(&from_ref),
        "setup: the two surfaces must differ"
    );
    assert_eq!(
        value(&epoch_in(&dir, &home, &["--config-from", "origin/main"])),
        value(&from_ref),
        "a worktree cache entry was served for a --config-from run"
    );
}
