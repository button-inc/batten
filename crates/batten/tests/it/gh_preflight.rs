//! `[tasks.gh-preflight]` — which GitHub claims this repository's tasks need,
//! answered by GitHub itself (CLOUD-1752), over the task's own body with a
//! stubbed `gh` first on `PATH`. The retired program had no suite; these cases
//! are its first.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/gh-preflight.sh mise.toml kind:mechanism crates/batten/tests/it/gh_preflight.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

/// A `gh` that answers from `answers`: each line `<path-substring> <status>
/// [<named-claim>]`, first match wins, and 200 otherwise.
const STUB: &str = r#"#!/usr/bin/env bash
case "$1 $2" in
"repo view") [ -f "$(dirname "$0")/../no-repo" ] || echo o/r; exit 0 ;;
"api user") echo tester; exit 0 ;;
esac
path="${@: -1}"
while read -r needle status named; do
	[ -n "$needle" ] || continue
	case "$path" in
	*"$needle"*)
		printf 'HTTP/2.0 %s\r\n' "$status"
		[ -z "$named" ] || printf 'X-Accepted-GitHub-Permissions: %s\r\n' "$named"
		printf '\r\n{}\n'
		exit 0
		;;
	esac
done <"$(dirname "$0")/../answers"
printf 'HTTP/2.0 200\r\n\r\n{}\n'
"#;

struct Github {
    dir: PathBuf,
}

impl Github {
    fn new(name: &str, answers: &str) -> Self {
        let dir = common::scratch(&format!("gh-preflight-{name}"));
        std::fs::create_dir_all(dir.join("bin")).expect("bin");
        let gh = dir.join("bin/gh");
        std::fs::write(&gh, STUB).expect("stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        std::fs::write(dir.join("answers"), answers).expect("answers");
        Self { dir }
    }

    fn run(&self) -> (Option<i32>, String) {
        let out = common::task_command(&self.dir, "gh-preflight")
            .output()
            .expect("run the preflight");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
}

#[test]
fn every_read_answering_passes_and_names_the_identity() {
    let (code, text) = Github::new("clean", "").run();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("gh-preflight: o/r"), "{text}");
    assert!(text.contains("authenticated as tester"), "{text}");
    assert!(
        text.contains("every probed read endpoint answered"),
        "{text}"
    );
}

#[test]
fn a_forbidden_read_is_missing_and_named() {
    let (code, text) = Github::new("forbidden", "check-runs 403 checks=read\n").run();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("MISS checks=read"), "{text}");
    assert!(text.contains("needed by: ci-wait"), "{text}");
    assert!(text.contains("GitHub names: checks=read"), "{text}");
    assert!(text.contains("missing 1 read claim(s)"), "{text}");
    // Declared as GitHub named it, so the table is not stale.
    assert!(!text.contains("STALE"), "{text}");
}

/// GitHub is the authority on which claim an endpoint needs.
#[test]
fn a_claim_github_names_that_the_table_does_not_marks_it_stale() {
    let (code, text) = Github::new("stale", "check-runs 403 actions=read\n").run();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("This table is STALE"), "{text}");
    assert!(
        text.contains("GitHub wants actions=read, we declare checks=read"),
        "{text}"
    );
}

/// A 404 can be an empty repository: reported, never counted as missing.
#[test]
fn a_not_found_read_is_reported_not_counted() {
    let (code, text) = Github::new("absent", "check-runs 404\n").run();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("(HTTP 404)"), "{text}");
}

/// Testing a write means performing one, so writes are declared and never probed.
#[test]
fn the_write_claims_are_declared_never_probed() {
    let (code, text) = Github::new("writes", "issues/1/comments 403\npulls/1 403\n").run();
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        text.matches("(write — declared, never probed)").count(),
        3,
        "{text}"
    );
}

#[test]
fn no_resolvable_repository_is_could_not_look() {
    let github = Github::new("no-repo", "");
    std::fs::write(github.dir.join("no-repo"), "").expect("marker");
    let (code, text) = github.run();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("could not resolve owner/repo"), "{text}");
}
