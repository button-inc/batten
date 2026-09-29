//! `batten doctor forge` — which forge claims this repository's tasks need,
//! answered by the forge itself (CLOUD-843, retiring `[tasks.gh-preflight]`),
//! over the compiled binary with the REST tier answered from a fixture
//! (`BATTEN_REST_FIXTURE`). The table is `[[forge.probe]]` rows, so each case
//! declares its own rather than reading this repository's.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/gh-preflight.sh crates/batten/src/preflight.rs kind:verb crates/batten/tests/it/gh_preflight.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

/// A reduced probe table in the committed one's shape: two probed reads, one
/// read declared and never probed, and two write claims.
const AUTHORITY: &str = r#"version = 1

[forge]
credential_names = []

[[forge.probe]]
endpoint = "repos/{owner}/{repo}"
claim = "metadata=read"
used_by = "every task that resolves the repo"

[[forge.probe]]
endpoint = "repos/{owner}/{repo}/commits/HEAD/check-runs"
claim = "checks=read"
used_by = "ci-wait (the whole poll)"

[[forge.probe]]
endpoint = "repos/{owner}/{repo}/actions/runs/1/jobs"
claim = "actions=read"
used_by = "a reader of per-step conclusions"
probe = false

[[forge.probe]]
endpoint = "repos/{owner}/{repo}/issues/1/comments"
claim = "pull_requests=write"
used_by = "land (posting a comment)"
probe = false

[[forge.probe]]
endpoint = "repos/{owner}/{repo}/pulls/1"
claim = "pull_requests=write"
used_by = "marking a draft ready"
probe = false
"#;

/// The forge's answer to anything no route names.
const OK: &str = "HTTP/2.0 200\n\n{}\n";

struct Forge {
    dir: PathBuf,
    answers: PathBuf,
}

impl Forge {
    /// A checkout declaring `authority`, and a forge answering `routes` — each
    /// `(needle, raw response)` — by endpoint, and `200` otherwise.
    fn new(name: &str, authority: &str, routes: &[(&str, &str)]) -> Self {
        let dir = common::scratch(&format!("gh-preflight-{name}"));
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("the checkout");
        common::write(&repo, "batten.toml", authority);
        common::git_in(&repo, &["init", "-q", "-b", "main", "."]);
        let answers = dir.join("answers");
        std::fs::create_dir_all(&answers).expect("the fixture forge");
        let mut table = String::from("api.github.com/user\tuser\n");
        common::write(&answers, "user", "HTTP/2.0 200\n\n{\"login\":\"tester\"}\n");
        for (at, (needle, response)) in routes.iter().enumerate() {
            let file = format!("route-{at}");
            common::write(&answers, &file, response);
            table.push_str(&format!("{needle}\t{file}\n"));
        }
        common::write(&answers, "routes", &table);
        common::write(&answers, "resp.last", OK);
        Self { dir: repo, answers }
    }

    fn run_with(&self, repo: Option<&str>) -> (Option<i32>, String) {
        let mut command = common::batten();
        command
            .current_dir(&self.dir)
            .args(["doctor", "forge"])
            .env("BATTEN_REST_FIXTURE", &self.answers)
            .env_remove("GH_REPO")
            .env_remove("LAND_LOCK_REMOTE");
        if let Some(repo) = repo {
            command.env("GH_REPO", repo);
        }
        let out = command.output().expect("run the diagnosis");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn run(&self) -> (Option<i32>, String) {
        self.run_with(Some("o/r"))
    }

    /// Every request the forge was asked, one per line.
    fn asked(&self) -> String {
        std::fs::read_to_string(self.answers.join("args")).unwrap_or_default()
    }
}

fn forbidden(named: Option<&str>) -> String {
    match named {
        Some(named) => format!("HTTP/2.0 403\nX-Accepted-GitHub-Permissions: {named}\n\n{{}}\n"),
        None => String::from("HTTP/2.0 403\n\n{}\n"),
    }
}

#[test]
fn every_read_answering_passes_and_names_the_identity() {
    let (code, text) = Forge::new("clean", AUTHORITY, &[]).run();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("doctor forge: o/r"), "{text}");
    assert!(text.contains("authenticated as tester"), "{text}");
    assert!(
        text.contains("every probed read endpoint answered"),
        "{text}"
    );
}

#[test]
fn a_forbidden_read_is_missing_and_named() {
    let response = forbidden(Some("checks=read"));
    let forge = Forge::new("forbidden", AUTHORITY, &[("check-runs", &response)]);
    let (code, text) = forge.run();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("MISS checks=read"), "{text}");
    assert!(text.contains("needed by: ci-wait"), "{text}");
    assert!(text.contains("the forge names: checks=read"), "{text}");
    assert!(text.contains("missing 1 read claim(s)"), "{text}");
    // Declared as the forge named it, so the table is not stale.
    assert!(!text.contains("STALE"), "{text}");
}

/// The forge is the authority on which claim an endpoint needs.
#[test]
fn a_claim_the_forge_names_that_the_table_does_not_marks_it_stale() {
    let response = forbidden(Some("actions=read"));
    let forge = Forge::new("stale", AUTHORITY, &[("check-runs", &response)]);
    let (code, text) = forge.run();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("STALE"), "{text}");
    assert!(
        text.contains("the forge wants actions=read, the table declares checks=read"),
        "{text}"
    );
}

/// A 404 can be an empty repository: reported, never counted as missing.
#[test]
fn a_not_found_read_is_reported_not_counted() {
    let forge = Forge::new(
        "absent",
        AUTHORITY,
        &[("check-runs", "HTTP/2.0 404\n\n{}\n")],
    );
    let (code, text) = forge.run();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("(HTTP 404)"), "{text}");
}

/// Testing a write means performing one, so a declared-only row is reported and
/// its endpoint is never asked — even where the forge would refuse it.
#[test]
fn the_declared_only_claims_are_never_probed() {
    let refused = forbidden(None);
    let forge = Forge::new(
        "writes",
        AUTHORITY,
        &[("issues/1/comments", &refused), ("pulls/1", &refused)],
    );
    let (code, text) = forge.run();
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        text.matches("(declared, never probed)").count(),
        3,
        "{text}"
    );
    let asked = forge.asked();
    for endpoint in ["issues/1/comments", "pulls/1", "runs/1/jobs"] {
        assert!(!asked.contains(endpoint), "{endpoint} was asked: {asked}");
    }
    // And the probed rows WERE asked, or the assertion above is vacuous.
    assert!(asked.contains("check-runs"), "{asked}");
}

#[test]
fn no_resolvable_repository_is_a_failed_diagnosis() {
    let forge = Forge::new("no-repo", AUTHORITY, &[]);
    let (code, text) = forge.run_with(None);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("could not resolve owner/repo"), "{text}");
}

/// THE COMMITTED TABLE, NOT A FIXTURE'S (CLOUD-843 review). The retired task
/// carried its table inline, so it could not lose it; the verb reads
/// `[[forge.probe]]` rows, and with none committed `batten doctor forge` refuses
/// on this repository and diagnoses nothing. Every case above declares its own
/// table, so this is the one that reddens on the committed rows being absent.
#[test]
fn this_repository_declares_the_claims_its_tasks_need() {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("the config");
    let config: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    let probes = config
        .get("forge")
        .and_then(|forge| forge.get("probe"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    assert!(
        probes > 0,
        "batten.toml declares no [[forge.probe]] row, so `batten doctor forge` probes nothing here"
    );
}

#[test]
fn a_repository_declaring_no_probe_is_refused_rather_than_passed() {
    let (code, text) = Forge::new("undeclared", "version = 1\n", &[]).run();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("no `[[forge.probe]]` row"), "{text}");
}
