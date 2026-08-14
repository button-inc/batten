//! Zero-config onboarding, over the compiled binary (CLOUD-70).
//!
//! A repository with no `batten.toml` runs on the compiled-in default layer
//! instead of being refused, so `check` works out of the box and `init` is
//! opt-in. Every case here is end-to-end because the claim is about what the
//! *binary* does when there is no config — the loader's unit tests cannot see
//! the exit code or the channel split, and those are the whole contract.
//!
//! ## The property this suite is really defending
//!
//! Not "an unconfigured run succeeds" — a run that evaluated nothing would also
//! succeed, and would be the false green the engine exists to refuse. The
//! property is that **the defaults gate something**:
//! `a_seeded_violation_of_a_default_rule_is_a_violation` is the load-bearing
//! case, and the clean run below is only meaningful beside it.
//!
//! ## And the boundary it is defending
//!
//! Absence selects the defaults; **invalidity never does**. A present-but-broken
//! `batten.toml` still exits `1` with no note, because defaulting there would
//! report green over rules its author wrote and believes are running.
//!
//! Every fixture is `git init`ed. Scratch directories live under this crate's
//! `target/`, which is inside this repository, so a fixture that is *not* its own
//! repository would have `anchor()` resolve to the real checkout — and the case
//! would then be measuring this repository's committed config.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use batten::config;
use common::{Fixture, run, stderr, stdout};

/// A line no default rule fires on, so a fixture's clean case is clean because
/// nothing matched rather than because nothing was read.
const QUIET: &str = "fn main() {}\n";

/// An unresolved merge conflict — what the default rule is about. Written by
/// `git` itself, refused by every language, defended by no project.
const CONFLICTED: &str = "fn main() {}\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> other\n";

/// The `batten.toml` that states, as a committed authority, the same gate the
/// default layer states. The §5 byte-identity clause is about this pair.
///
/// It states the shape as a `regex` where the defaults use a `pattern`, and the
/// reason is the trap `starter.toml`'s own comment records: **a `forbid` pattern
/// is a literal, so it appears in the config that declares it.** A committed
/// authority spelling this rule with `pattern` under a repo-wide glob reports
/// itself, which is an artifact of writing the rule down rather than a
/// difference in what it gates — and it is a trap the default layer cannot fall
/// into, because in that case there is no config file to match. Comparing a
/// `regex` spelling isolates the variable this case is actually about: which
/// layer supplied the policy, not what the policy says.
const SAME_AS_DEFAULTS: &str = "version = 1\n\n[[rule]]\nid = \"no-conflict-markers\"\n\
     kind = \"forbid\"\nglob = \"**/*\"\nregex = \"^<{7} \"\nseverity = \"deny\"\n\
     scope = \"tree\"\n";

/// A git repository with no `batten.toml` and the given files.
fn unconfigured(name: &str, files: &[(&str, &str)]) -> PathBuf {
    Fixture::new(&format!("zero-config/{name}"))
        .files(files)
        .git()
        .build()
}

// --- the defaults are in effect ----------------------------------------------

#[test]
fn an_unconfigured_repository_checks_clean_and_says_so() {
    // §7 (a). Exit 0 on findings alone — never the usage error a missing
    // authority used to produce — and the one stderr line that tells a first
    // contact which rules just ran.
    let dir = unconfigured("clean", &[("src/lib.rs", QUIET)]);
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output), "", "a clean run prints nothing (§6)");
    assert!(
        stderr(&output).contains(config::DEFAULTS_NOTE),
        "stderr must name the defaults, got: {:?}",
        stderr(&output)
    );
}

#[test]
fn a_seeded_violation_of_a_default_rule_is_a_violation() {
    // §7 (b), and the case the rest of this suite rests on: without it, every
    // assertion above is satisfied by a build that reads no files at all.
    let dir = unconfigured("violation", &[("src/lib.rs", CONFLICTED)]);
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "src/lib.rs:2 no-conflict-markers\n",
        "the finding is a pointer — `path:line rule-id`, never the matched line"
    );
    assert!(stderr(&output).contains(config::DEFAULTS_NOTE));
}

#[test]
fn the_defaults_note_does_not_change_what_stdout_says() {
    // §5's byte-identity clause: the same tree, once on the defaults and once on
    // a committed authority stating the same rule, must produce the same
    // findings channel. This is what makes "the defaults" a real configuration
    // rather than a special case with its own reporting.
    let defaulted = unconfigured("identity-defaults", &[("src/lib.rs", CONFLICTED)]);
    let committed = Fixture::new("zero-config/identity-committed")
        .config(SAME_AS_DEFAULTS)
        .file("src/lib.rs", CONFLICTED)
        .git()
        .build();

    let by_default = run(&defaulted, &["check"]);
    let by_config = run(&committed, &["check"]);

    assert_eq!(stdout(&by_default), stdout(&by_config));
    assert_eq!(by_default.status.code(), by_config.status.code());
}

#[test]
fn two_unconfigured_runs_emit_identical_stdout() {
    // §7 (e) / §6: the defaults are compiled in, so nothing about them can vary
    // between two runs over one tree.
    let dir = unconfigured("stable", &[("src/lib.rs", CONFLICTED)]);
    let first = run(&dir, &["check"]);
    let second = run(&dir, &["check"]);
    assert_eq!(stdout(&first), stdout(&second));
    assert_eq!(first.status.code(), second.status.code());
}

// --- the note is a message, and messages are ladder-gated --------------------

#[test]
fn a_committed_authority_gets_no_defaults_note() {
    // §7 (d). The note is news about which layer supplied the policy; a repo
    // that wrote its own policy is not receiving news.
    let dir = Fixture::new("zero-config/configured")
        .config(SAME_AS_DEFAULTS)
        .file("src/lib.rs", QUIET)
        .git()
        .build();
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !stderr(&output).contains(config::DEFAULTS_NOTE),
        "got: {:?}",
        stderr(&output)
    );
}

#[test]
fn quiet_silences_the_note_without_changing_the_verdict() {
    // The note rides the §6 verbosity ladder, like every other message: a caller
    // that asked for less chatter gets less chatter and the same exit code. The
    // verdict half is the assertion that matters — a ladder that could move a
    // verdict would be a policy knob wearing a formatting flag's name.
    let dir = unconfigured("quiet", &[("src/lib.rs", CONFLICTED)]);
    let loud = run(&dir, &["check"]);
    let quiet = run(&dir, &["--quiet", "check"]);

    assert!(stderr(&loud).contains(config::DEFAULTS_NOTE));
    assert!(
        !stderr(&quiet).contains(config::DEFAULTS_NOTE),
        "got: {:?}",
        stderr(&quiet)
    );
    assert_eq!(quiet.status.code(), Some(2));
    assert_eq!(stdout(&quiet), stdout(&loud));
}

// --- absence selects the defaults; invalidity never does ---------------------

#[test]
fn a_present_but_invalid_authority_still_exits_usage_with_no_note() {
    // §7 (c), over the three shapes §5 names. Each would be a silent policy
    // downgrade if it defaulted: the operator wrote a file, so answering with
    // the engine's own rules would report on rules they never chose.
    for (name, text) in [
        ("malformed", "version = = 1\n"),
        ("unknown-key", "version = 1\nbogus = true\n"),
        ("bad-version", "version = 9\n"),
    ] {
        let dir = Fixture::new(&format!("zero-config/invalid-{name}"))
            .config(text)
            .file("src/lib.rs", QUIET)
            .git()
            .build();
        let output = run(&dir, &["check"]);

        assert_eq!(
            output.status.code(),
            Some(1),
            "{name} must be refused, not defaulted; stderr: {}",
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains(config::DEFAULTS_NOTE),
            "{name} must not claim the defaults are in use"
        );
    }
}

#[test]
fn config_from_a_ref_stays_strict_about_a_missing_authority() {
    // The trust mechanism (CLOUD-31) is the one place absence must still refuse:
    // a caller naming a ref asked to be judged by what that ref declares, and
    // answering with the defaults would let a branch that deletes `batten.toml`
    // choose its own policy — the exact weakening the flag exists to prevent.
    let dir = Fixture::new("zero-config/config-from")
        .file("src/lib.rs", CONFLICTED)
        .git()
        .base_commit()
        .build();
    let output = run(&dir, &["--config-from", "origin/main", "check"]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}, stderr: {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains(config::DEFAULTS_NOTE));
}

// --- what `config show` says about an unconfigured repository ----------------

#[test]
fn config_show_attributes_every_key_to_the_default_layer() {
    // §7 (f). `config show` is how a reader asks "where did this come from", and
    // on an unconfigured repository there is exactly one honest answer for every
    // key — including `version`, which used to be hard-coded to the authority
    // because the file was required.
    let dir = unconfigured("show", &[("src/lib.rs", QUIET)]);
    let output = run(&dir, &["config", "show", "--json"]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));

    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let keys = document.as_object().expect("an object of keys");
    assert!(!keys.is_empty(), "the scan must find keys");
    for (key, entry) in keys {
        assert_eq!(
            entry["source"], "default",
            "{key} is not attributed to the default layer"
        );
    }
}
