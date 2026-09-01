//! End-to-end tests for `batten attribution` over the compiled binary (CLOUD-274).
//!
//! Every case drives a **throwaway repository** rather than this one. The property
//! under test is "a commit carrying X is refused", and this repository's own
//! history is deliberately full of X — 39 of its first 50 commits. Judging the
//! real history would make the suite a measurement of the past instead of a gate
//! on the future, and the rule is forward-only by design.
//!
//! The fixture policy uses invented vendor names, never this repository's
//! configured ones. That is not squeamishness: `crates/batten/tests/` is inside
//! the `crates/**` glob that non-negotiable rule 1 gates, and a fixture carrying a
//! real vendor literal would put the very string the policy exists to keep out of
//! the crate *into* the crate.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_command, git_in, scratch, stderr, stdout, write};

/// A policy whose literals name nobody real.
const POLICY: &str = r#"version = 1

[attribution]
identity_deny = ['^Vendorbot <', '@no-reply\.example>$']
trailer_deny = ['^Co-Authored-By:.*Vendorbot', '^Vendorbot-Session:', '^Assisted-by:']
body_deny = ['[Gg]enerated with']
trailer_allow = []

[attribution.identity]
name = "Accountable Human"
email = "human@example.test"
"#;

/// A fixture repository with `POLICY` committed and one base commit.
fn fixture(name: &str) -> PathBuf {
    let dir = scratch(name);
    git_in(&dir, &["init", "-q", "-b", "main"]);
    git_in(&dir, &["config", "user.name", "Accountable Human"]);
    git_in(&dir, &["config", "user.email", "human@example.test"]);
    write(&dir, "batten.toml", POLICY);
    git_in(&dir, &["add", "batten.toml"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    dir
}

/// Commit with an arbitrary **author**, leaving the committer accountable.
///
/// `GIT_AUTHOR_*` rather than `-c user.name`: the latter sets both fields at
/// once, which would make the author case indistinguishable from the committer
/// case. Each field gets its own case precisely because a repair can reach one
/// and miss the other.
fn commit_authored_by(dir: &Path, name: &str, email: &str, message: &str) -> String {
    let output = git_command(dir, &["commit", "-q", "--allow-empty", "-m", message])
        .env("GIT_AUTHOR_NAME", name)
        .env("GIT_AUTHOR_EMAIL", email)
        .output()
        .expect("run git");
    assert!(output.status.success(), "{}", stderr(&output));
    git_in(dir, &["rev-parse", "HEAD"])
}

/// A clean commit by the accountable identity.
fn commit_clean(dir: &Path, message: &str) -> String {
    git_in(dir, &["commit", "-q", "--allow-empty", "-m", message]);
    git_in(dir, &["rev-parse", "HEAD"])
}

fn check_range(dir: &Path, base: &str, head: &str) -> Output {
    batten()
        .args(["attribution", "check", &format!("{base}..{head}")])
        .current_dir(dir)
        .output()
        .expect("run batten")
}

fn short(sha: &str) -> String {
    sha.chars().take(8).collect()
}

fn base_of(dir: &Path) -> String {
    git_in(dir, &["rev-parse", "HEAD"])
}

// --- the clean path -----------------------------------------------------------

#[test]
fn a_clean_range_is_silent_and_exits_zero() {
    let dir = fixture("attribution-clean");
    let base = base_of(&dir);
    let head = commit_clean(&dir, "fix(x): a real change");
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(0));
    // Silence is the success signal on the human channel (§6). Asserted as an
    // exact empty string, not a substring: a gate that prints reassurance is one
    // whose real findings scroll away.
    assert_eq!(stdout(&out), "");
}

#[test]
fn an_empty_range_is_clean_rather_than_an_error() {
    let dir = fixture("attribution-empty-range");
    let base = base_of(&dir);
    let out = check_range(&dir, &base, &base);
    assert_eq!(out.status.code(), Some(0));
}

// --- one case per deny-set surface ---------------------------------------------

#[test]
fn a_denied_author_is_refused_and_the_pointer_names_the_field() {
    let dir = fixture("attribution-author");
    let base = base_of(&dir);
    let head = commit_authored_by(
        &dir,
        "Vendorbot",
        "bot@no-reply.example",
        "fix(x): a change",
    );
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), format!("{} author\n", short(&head)));
}

#[test]
fn a_denied_committer_is_refused_too() {
    // The field `git log` does not show by default, and the one a repair reaching
    // only `author` would leave behind — invisible locally, fully public.
    let dir = fixture("attribution-committer");
    let base = base_of(&dir);
    let output = git_command(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "fix(x): a change"],
    )
    .env("GIT_COMMITTER_NAME", "Vendorbot")
    .env("GIT_COMMITTER_EMAIL", "bot@no-reply.example")
    .output()
    .expect("run git");
    assert!(output.status.success(), "{}", stderr(&output));
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), format!("{} committer\n", short(&head)));
}

#[test]
fn a_model_identity_in_co_authorship_form_reports_the_key_and_never_the_value() {
    let dir = fixture("attribution-coauthor");
    let base = base_of(&dir);
    let head = commit_clean(
        &dir,
        "fix(x): a change\n\nCo-Authored-By: Vendorbot Model <bot@no-reply.example>",
    );
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stdout(&out),
        format!("{} trailer:Co-Authored-By\n", short(&head))
    );
    // Pointer, never payload: the address is what the policy exists to suppress,
    // so a gate that reprints it has published the thing it was catching.
    assert!(!stdout(&out).contains("no-reply.example"));
}

#[test]
fn a_vendor_session_url_is_refused_without_echoing_the_url() {
    let dir = fixture("attribution-session");
    let base = base_of(&dir);
    let head = commit_clean(
        &dir,
        "fix(x): a change\n\nVendorbot-Session: https://vendor.example/session_secret",
    );
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stdout(&out),
        format!("{} trailer:Vendorbot-Session\n", short(&head))
    );
    assert!(!stdout(&out).contains("session_secret"));
}

#[test]
fn a_marketing_formula_in_the_body_is_refused_without_echoing_it() {
    let dir = fixture("attribution-body");
    let base = base_of(&dir);
    let head = commit_clean(&dir, "fix(x): a change\n\nGenerated with SomeProduct");
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), format!("{} body\n", short(&head)));
    assert!(!stdout(&out).contains("SomeProduct"));
}

// --- the allow-set is a carve-out, and its emptiness is the posture ------------

#[test]
fn with_an_empty_allow_set_a_disclosure_trailer_is_refused() {
    // That refusal IS the silent posture, expressed as data rather than code.
    let dir = fixture("attribution-silent");
    let base = base_of(&dir);
    let head = commit_clean(
        &dir,
        "fix(x): a change\n\nAssisted-by: some-agent:some-model",
    );
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stdout(&out),
        format!("{} trailer:Assisted-by\n", short(&head))
    );
}

#[test]
fn opting_in_carves_out_the_well_formed_shape_and_only_that_shape() {
    let dir = fixture("attribution-disclosing");
    write(
        &dir,
        "batten.toml",
        &POLICY.replace(
            "trailer_allow = []",
            r"trailer_allow = ['^Assisted-by: [a-z0-9-]+:[a-z0-9.-]+$']",
        ),
    );
    git_in(&dir, &["add", "batten.toml"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: disclose"]);
    let base = base_of(&dir);

    let ok = commit_clean(
        &dir,
        "fix(x): a change\n\nAssisted-by: some-agent:some-model",
    );
    assert_eq!(check_range(&dir, &base, &ok).status.code(), Some(0));

    // Opting in must not mean "stop checking".
    let bad = commit_clean(
        &dir,
        "fix(x): another\n\nAssisted-by: Vendorbot Model <bot@no-reply.example>",
    );
    let out = check_range(&dir, &ok, &bad);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stdout(&out),
        format!("{} trailer:Assisted-by\n", short(&bad))
    );
}

// --- could-not-look is 1, never a pass -----------------------------------------

#[test]
fn an_unresolvable_range_is_one_not_a_pass() {
    let dir = fixture("attribution-bad-range");
    let base = base_of(&dir);
    let out = check_range(&dir, &base, "0000000000000000000000000000000000000000");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_malformed_range_is_one() {
    let dir = fixture("attribution-malformed-range");
    let out = batten()
        .args(["attribution", "check", "not-a-range"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn neither_mode_is_one_rather_than_a_vacuous_pass() {
    // The failure this forbids: a gate invoked with nothing to judge exiting 0,
    // which reads identically to "these commits are clean".
    let dir = fixture("attribution-no-mode");
    let out = batten()
        .args(["attribution", "check"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn both_modes_at_once_is_one() {
    let dir = fixture("attribution-both-modes");
    write(&dir, "msg", "fix(x): a change\n");
    let out = batten()
        .args(["attribution", "check", "HEAD..HEAD", "--message", "msg"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn no_attribution_table_is_one_not_a_silent_pass() {
    // "This repository declares no attribution policy" and "these commits are
    // clean" are different answers; collapsing them reports green over a gate
    // that never ran.
    let dir = scratch("attribution-no-table");
    git_in(&dir, &["init", "-q", "-b", "main"]);
    git_in(&dir, &["config", "user.name", "Accountable Human"]);
    git_in(&dir, &["config", "user.email", "human@example.test"]);
    write(&dir, "batten.toml", "version = 1\n");
    git_in(&dir, &["add", "batten.toml"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    let base = base_of(&dir);
    let head = commit_clean(&dir, "fix(x): a change");
    assert_eq!(check_range(&dir, &base, &head).status.code(), Some(1));
}

#[test]
fn an_uncompilable_pattern_is_refused_at_load() {
    let dir = fixture("attribution-bad-pattern");
    write(
        &dir,
        "batten.toml",
        &POLICY.replace(
            r"body_deny = ['[Gg]enerated with']",
            "body_deny = ['(unclosed']",
        ),
    );
    let base = base_of(&dir);
    let head = commit_clean(&dir, "fix(x): a change");
    let out = check_range(&dir, &base, &head);
    assert_eq!(out.status.code(), Some(1));
    // The pattern is the consumer's own config, so naming it is a pointer to the
    // line they must fix — not a payload leak.
    assert!(stderr(&out).contains("body_deny"));
}

// --- message mode: the commit-time seam ----------------------------------------

#[test]
fn message_mode_refuses_a_pending_message_before_the_commit_exists() {
    let dir = fixture("attribution-message-trailer");
    write(
        &dir,
        "msg",
        "fix(x): a change\n\nVendorbot-Session: https://vendor.example/session_x\n",
    );
    let out = batten()
        .args(["attribution", "check", "--message", "msg"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "pending trailer:Vendorbot-Session\n");
}

#[test]
fn message_mode_refuses_the_identity_git_is_about_to_stamp() {
    let dir = fixture("attribution-message-identity");
    write(&dir, "msg", "fix(x): a change\n");
    let out = batten()
        .args(["attribution", "check", "--message", "msg"])
        .current_dir(&dir)
        .env("GIT_AUTHOR_NAME", "Vendorbot")
        .env("GIT_AUTHOR_EMAIL", "bot@no-reply.example")
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "pending author\n");
}

#[test]
fn message_mode_passes_a_clean_pending_message() {
    let dir = fixture("attribution-message-clean");
    write(&dir, "msg", "fix(x): a change\n\nRefs: CLOUD-274\n");
    let out = batten()
        .args(["attribution", "check", "--message", "msg"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");
}

#[test]
fn an_unreadable_message_file_is_one() {
    let dir = fixture("attribution-message-missing");
    let out = batten()
        .args(["attribution", "check", "--message", "does-not-exist"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

// --- JSON is emitted unconditionally, including when clean ---------------------

#[test]
fn json_is_emitted_for_a_clean_run_too() {
    // JSON that is sometimes absent is unparseable, so an empty `findings` list
    // is the clean answer rather than silence.
    //
    // The document became an object when the attribution rows landed (CLOUD-276):
    // `caller` and `expects` join `findings` under stable keys, and every key is
    // present on every run — including this clean one and a run naming no host.
    // A shape that varied with the flags would be the same unparseable problem
    // the empty list exists to avoid, one level up.
    let dir = fixture("attribution-json-clean");
    let base = base_of(&dir);
    let head = commit_clean(&dir, "fix(x): a change");
    let out = batten()
        .args(["attribution", "check", "--json", &format!("{base}..{head}")])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(0));
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("--json is one JSON document");
    assert_eq!(document["findings"], serde_json::json!([]));
    // Named no host, so it declares nothing and captures nothing — which is a
    // different answer from any host's row, not a stand-in for one.
    assert_eq!(document["expects"], serde_json::json!([]));
    assert_eq!(document["caller"]["harness"], "unknown");
}

#[test]
fn json_carries_the_pointer_and_no_payload() {
    let dir = fixture("attribution-json-finding");
    let base = base_of(&dir);
    let head = commit_clean(
        &dir,
        "fix(x): a change\n\nVendorbot-Session: https://vendor.example/session_secret",
    );
    let out = batten()
        .args(["attribution", "check", "--json", &format!("{base}..{head}")])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(2));
    let rendered = stdout(&out);
    assert!(rendered.contains("trailer:Vendorbot-Session"));
    assert!(!rendered.contains("session_secret"));
}

// --- the fixer -----------------------------------------------------------------

/// Run the fixer with the global and system config scopes fenced off.
///
/// The fixer reads the identity as git *resolves* it, which is the whole point —
/// the defect is an identity inherited from a wider scope. That makes the ambient
/// global config an input, so a case that did not fence it would be asserting
/// about whatever identity the developer's machine happens to carry. Measured:
/// this container's global identity is itself a vendor one, which silently turned
/// the "unset" case into the "left alone" case.
fn identity(dir: &Path) -> Output {
    batten()
        .args(["attribution", "identity"])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("run batten")
}

/// A repo-local config value, or the empty string when the key is unset.
///
/// Not `git_in`: that asserts success, and `--get` on a missing key exits 1,
/// which is a legitimate answer here rather than a fixture failure.
fn local(dir: &Path, key: &str) -> String {
    let output = git_command(dir, &["config", "--local", "--get", key])
        .output()
        .expect("run git");
    String::from_utf8(output.stdout)
        .expect("git stdout is UTF-8")
        .trim_end()
        .to_owned()
}

#[test]
fn an_unset_identity_is_written() {
    let dir = fixture("attribution-identity-unset");
    git_in(&dir, &["config", "--unset", "user.name"]);
    git_in(&dir, &["config", "--unset", "user.email"]);
    let out = identity(&dir);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(local(&dir, "user.name"), "Accountable Human");
    assert_eq!(local(&dir, "user.email"), "human@example.test");
    assert!(stderr(&out).contains("was: unset"));
}

#[test]
fn a_denied_identity_is_overwritten_and_the_value_is_not_echoed() {
    let dir = fixture("attribution-identity-denied");
    git_in(&dir, &["config", "user.name", "Vendorbot"]);
    git_in(&dir, &["config", "user.email", "bot@no-reply.example"]);
    let out = identity(&dir);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(local(&dir, "user.name"), "Accountable Human");
    assert!(stderr(&out).contains("was: denied"));
    assert!(!stderr(&out).contains("no-reply.example"));
}

#[test]
fn an_accountable_identity_is_left_exactly_as_the_contributor_set_it() {
    // The case that matters most. A fixer that always overwrites would replace a
    // real contributor's name with a configured default on every session start,
    // asserting the opposite of what the record says accountability is.
    let dir = fixture("attribution-identity-accountable");
    git_in(&dir, &["config", "user.name", "Someone Real"]);
    git_in(&dir, &["config", "user.email", "someone@example.test"]);
    let out = identity(&dir);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(local(&dir, "user.name"), "Someone Real");
    assert_eq!(local(&dir, "user.email"), "someone@example.test");
    assert!(stderr(&out).contains("left as configured"));
}

#[test]
fn the_fixer_is_idempotent() {
    let dir = fixture("attribution-identity-idempotent");
    git_in(&dir, &["config", "user.name", "Vendorbot"]);
    git_in(&dir, &["config", "user.email", "bot@no-reply.example"]);
    assert_eq!(identity(&dir).status.code(), Some(0));
    let second = identity(&dir);
    assert_eq!(second.status.code(), Some(0));
    assert!(stderr(&second).contains("left as configured"));
    assert_eq!(local(&dir, "user.name"), "Accountable Human");
}

#[test]
fn a_commit_made_after_the_fixer_passes_the_gate() {
    // The pair, end to end: the fixer repairs the clone, and the gate then has
    // nothing to catch. This is the property `session-start.sh` relies on.
    let dir = fixture("attribution-identity-pair");
    git_in(&dir, &["config", "user.name", "Vendorbot"]);
    git_in(&dir, &["config", "user.email", "bot@no-reply.example"]);
    assert_eq!(identity(&dir).status.code(), Some(0));
    let base = base_of(&dir);
    git_in(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "fix(x): after"],
    );
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    assert_eq!(check_range(&dir, &base, &head).status.code(), Some(0));
}
