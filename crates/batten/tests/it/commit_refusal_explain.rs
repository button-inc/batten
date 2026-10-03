//! A commit-msg refusal leads with a class `policy explain` resolves
//! (CLOUD-1960), over the compiled binary.
//!
//! The unit cases in `commit.rs` and `attribution.rs` pin each finding's class.
//! This tier pins what the hook actually prints: the line `report` writes is the
//! one a reader sees, so a writer that went back to bare pointers would pass every
//! unit case and fail here.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::{Fixture, batten, stdout, write};

/// Both engine tables, one version line: the commit convention from
/// `commit.rs`'s fixture and the attribution policy from `attribution.rs`'s.
const POLICY: &str = r#"version = 1

[commit]
subject_pattern = '^(feat|fix|chore)([(][a-z]+[)])?!?: .+'

[attribution]
identity_deny = ['^Vendorbot <', '@no-reply\.example>$']
trailer_deny = ['^Co-Authored-By:.*Vendorbot', '^Vendorbot-Session:', '^Assisted-by:']
body_deny = ['[Gg]enerated with']
trailer_allow = []

[attribution.identity]
name = "Accountable Human"
email = "human@example.test"
"#;

fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(POLICY)
        .git()
        .base_commit()
        .build()
}

/// Run `<verb> check --message` over `body`, asserting the policy verdict.
fn refused(dir: &Path, verb: &str, body: &str) -> String {
    write(dir, "msg", body);
    let out = batten()
        .args([verb, "check", "--message", "msg"])
        .current_dir(dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(2), "{verb}: {}", stdout(&out));
    stdout(&out)
}

#[test]
fn a_refused_commit_msg_line_names_a_class_policy_explain_resolves() {
    let dir = fixture("commit-refusal-explain");
    let registry: Vec<String> = batten::verdict::vendored()
        .into_iter()
        .map(|row| row.id)
        .collect();
    for (verb, body, class, pointer) in [
        (
            "commit",
            "fix(test:cargo): x\n",
            "commit spelling wrong",
            "pending subject",
        ),
        (
            "attribution",
            "fix(x): y\n\nGenerated with a tool\n",
            "commit state refused",
            "pending body",
        ),
    ] {
        let printed = refused(&dir, verb, body);
        let lines: Vec<&str> = printed.lines().collect();
        assert_eq!(lines.len(), 1, "{verb}: {printed}");
        let line = lines[0];
        let carried: BTreeSet<&str> = registry
            .iter()
            .map(String::as_str)
            .filter(|id| line.contains(id))
            .collect();
        assert_eq!(carried, BTreeSet::from([class]), "{verb}: {line}");
        assert!(line.contains(pointer), "{verb}: {line}");

        let explained = batten()
            .args(["policy", "explain", class])
            .current_dir(&dir)
            .output()
            .expect("run batten");
        assert_eq!(explained.status.code(), Some(0), "{class}");
        assert!(!stdout(&explained).trim().is_empty(), "{class}");
    }
}
