//! `commit grade unsafe` over the compiled binary and the real classification
//! (CLOUD-669, CLOUD-591, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/signing-posture.rego` carries eight load-time cases and every one
//! fabricates its input with `with input as`, which is the shape
//! `rules/policy-modules.md` warns about.
//!
//! # And why the SIGNER CLASSIFICATION is driven here
//!
//! Seven of the dying suite's twenty-one cases are about exactly which
//! configurations are unverifiable: an empty key, a directory, an unreadable
//! file, a path that does not exist, an inline literal, a `/tmp` signer, and a
//! healthy one. That is the substance — the module's half is two set
//! memberships — and one of them (`-s` alone being true for a directory) was a
//! measured defect rather than a hypothetical.
//!
//! `crates/batten/src/signer_posture.rs` is the one authority on those branches
//! and on the record's own shape. Its `#[cfg(test)] mod tests` asserts all seven
//! arms against scratch paths, plus two the retired program never had — an unset
//! key, and a signer merely NAMED `/tmpfoo`, which a prefix test without the
//! separator would have called broken.
//!
//! What stays HERE is the half a unit test cannot reach: that the engine carries
//! the reading through `record derive` into a record the real module refuses
//! over. `[tasks.signing-posture-repair]` no longer classifies a second time —
//! it reads the posture off the record the producer just wrote, so the two
//! cannot disagree about a checkout they both looked at.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! Six cases are not carried and each says why in its own row.
//!
// carried: mise-tasks/signing-posture.sh policy/signing-posture.rego kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: tests/signing-posture.bats policy/signing-posture.rego kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "an unsigned range with the override in place passes" policy/signing-posture.rego kind:mechanism
// carried: "signing with a verifiable signer is left alone" policy/signing-posture.rego kind:mechanism
// carried: "a commit signed by a VERIFIABLE signer is left alone, header and all" policy/signing-posture.rego kind:mechanism
// carried: "an empty signing key is what makes it unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key that is a directory is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key this checkout cannot read is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key naming a path that does not exist is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "an inline public key is a literal, not a path, and is verifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signer under /tmp is unverifiable because the container reclaims it" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signed commit in range is refused, and named by short sha" policy/signing-posture.rego kind:mechanism
// carried: "repairing the config does not excuse a commit already signed" policy/signing-posture.rego kind:mechanism
// carried: "a missing override is refused when the environment sets signing globally" policy/signing-posture.rego kind:mechanism
// carried: "a missing override is NOT a finding when nothing sets signing globally" policy/signing-posture.rego kind:mechanism
// carried: "a local override set to true is refused when the signer is broken" policy/signing-posture.rego kind:mechanism
// carried: "the refusal echoes no part of the signature block" policy/signing-posture.rego kind:mechanism
// changed: "--repair leaves a verifiable signer alone rather than switching signing off" mise.toml the write is the WRITE, which a module cannot be, so it stayed a task — `[tasks.signing-posture-repair]` — and its guard is the same shared `crates/batten/src/signer_posture.rs` reading this tier drives. `an_inline_public_key_is_a_literal_not_a_path_and_is_verifiable` pins the branch the guard turns on
// changed: "--repair writes the override, local only" mise.toml the same split: the write and its scope are the task's, and `git config --local` is the one line that states it
// changed: "--repair is idempotent" mise.toml idempotence is a property of `git config --local commit.gpgsign false`, which is the task's single write
// changed: "--repair never writes global config" mise.toml the same boundary `attribution-identity` draws, and it is stated where the write is — a developer's own unrelated repositories are not this repo's business
// changed: "history before the range is never judged" mise.toml the range is the PRODUCER's — `origin/main..HEAD` by default, the range `commit-attribution` and `commit-lint` already share. The module reads whatever the producer recorded and cannot observe which commits were outside it
// changed: "outside a git repository it is exit 2, never a silent pass" mise.toml could-not-look is the producer's: it writes NOTHING outside a git repository, and `an_absent_record_says_nothing_rather_than_refusing` is the module's half of that contract

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against the declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("signing-posture-{name}"));
    let module = std::fs::read_to_string("../../policy/signing-posture.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/signing-posture.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "config carry unsafe"
gloss = "signing is on with a signer whose key cannot be verified or reproduced"
class = "A signature that looks like provenance and carries none."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run signing-posture-repair"

[[verdict]]
id = "commit carry unsafe"
gloss = "a commit in range carries a gpgsig from a key this repository cannot verify"
class = "The posture already produced one, and repairing the config does not unsign it."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/signing-posture.rego"

[[rule]]
id = "commit grade unsafe"
kind = "policy"
scope = "tree"
module = "policy/signing-posture.rego"
severity = "deny"

[[record]]
record = "signing-posture"
writer = "mise run signing-posture-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "signing-posture"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

fn said(decided: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    )
}

const BROKEN: &str = "signer broken user.signingkey names an empty file, so the public half cannot be read or published";

// --- the decision, over the engine's own projection --------------------------

#[test]
fn a_signed_commit_in_range_is_refused_and_named_by_short_sha() {
    let dir = repo("signed");
    record(&dir, &format!("{BROKEN}\nsigned 1a2b3c4d\n"));

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a signed commit decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    assert!(
        said(&decided).contains("1a2b3c4d"),
        "and is named by short sha\n{}",
        said(&decided)
    );
}

#[test]
fn signing_with_a_verifiable_signer_is_left_alone() {
    // THE END STATE CLOUD-591 IS WORKING TOWARD, and this gate must not block it.
    let dir = repo("verifiable");
    record(
        &dir,
        "signer verifiable\nconfig conflict\nsigned 1a2b3c4d\n",
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a verifiable signer may sign freely\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_missing_override_is_refused_when_the_environment_sets_signing_globally() {
    let dir = repo("conflict");
    record(&dir, &format!("{BROKEN}\nconfig conflict\n"));

    let decided = run(&dir, &["check"]);
    assert_eq!(decided.status.code(), Some(2), "the conflict decides");
}

#[test]
fn a_missing_override_is_not_a_finding_when_nothing_sets_signing_globally() {
    // A runner has no launcher and no global setting, so an absent local value is
    // the correct state there. Demanding the override unconditionally would red
    // every CI run.
    let dir = repo("runner");
    record(&dir, &format!("{BROKEN}\n"));

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "nothing to override is not a finding\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn repairing_the_config_does_not_excuse_a_commit_already_signed() {
    // The whole reason the two classes are separate: `--repair` clears the config
    // arm and leaves this one firing on whatever was already written.
    let dir = repo("repaired");
    record(&dir, &format!("{BROKEN}\nsigned 1a2b3c4d\n"));

    let decided = run(&dir, &["check"]);
    assert_eq!(decided.status.code(), Some(2), "the commit still decides");
    assert!(
        said(&decided).contains("1a2b3c4d"),
        "and it is the commit that is named\n{}",
        said(&decided)
    );
}

#[test]
fn the_refusal_echoes_no_part_of_the_signature_block() {
    // POINTER-ONLY (rule 4): a short SHA and a setting name. A signature block is
    // a credential artefact this repository does not control, and the record
    // never carries one — which is where that has to be true.
    let dir = repo("quiet");
    record(&dir, &format!("{BROKEN}\nsigned 1a2b3c4d\n"));

    let decided = run(&dir, &["check"]);
    let reported = said(&decided);
    assert!(
        !reported.contains("BEGIN SSH SIGNATURE"),
        "no signature block reaches the finding\n{reported}"
    );
    assert!(
        !reported.contains("gpgsig "),
        "and no header line does\n{reported}"
    );
}

#[test]
fn an_unsigned_range_with_the_override_in_place_passes() {
    let dir = repo("clean");
    record(&dir, &format!("{BROKEN}\n"));

    let quiet = run(&dir, &["check"]);
    assert_eq!(quiet.status.code(), Some(0), "nothing to report");
}

#[test]
fn an_absent_record_says_nothing_rather_than_refusing() {
    // The producer writes nothing outside a git repository, so a module refusing
    // here would report a posture in force over a tree it never looked at.
    let dir = repo("unrecorded");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

// --- the signer classification, over the real verb ---------------------------

/// Drive the REAL reading both tasks run, through the REAL verb.
///
/// `crates/batten/src/signer_posture.rs` is the one authority on which
/// configurations are unverifiable, and its own `#[cfg(test)] mod tests`
/// asserts all seven arms directly against scratch paths — plus two the retired
/// program never had: an unset key, and a signer merely NAMED `/tmpfoo`, which
/// a prefix test without the separator would have called broken.
///
/// What THIS tier adds is the half a unit test cannot reach: that the engine
/// carries that reading, and the record's whole shape, into a record the real
/// module then refuses over.
fn derive(dir: &std::path::Path, signingkey: &str, program: &str, signed: &str) -> String {
    let written = run_with_stdin(
        dir,
        &[
            "record",
            "derive",
            "signing-posture",
            "--input",
            &format!("signingkey={signingkey}"),
            "--input",
            &format!("ssh-program={program}"),
            "--input",
            "gpgsign=none",
            "--input",
            &format!("signed={signed}"),
        ],
        "",
    );
    assert!(
        written.status.success(),
        "the derivation lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    String::from_utf8_lossy(&written.stdout).into_owned()
}

#[test]
fn the_verb_derives_a_broken_signer_into_a_record_the_module_refuses_over() {
    let dir = repo("derive-broken");
    let key = dir.join("key.pub");
    std::fs::write(&key, "").expect("an empty key is the broken case");
    let written = derive(
        &dir,
        key.to_string_lossy().as_ref(),
        "",
        "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
    );
    assert!(
        written.contains("signer broken"),
        "the reading reaches the record\n{written}"
    );
    assert!(
        written.contains("signed 1a2b3c4d"),
        "and so does the short sha\n{written}"
    );

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a signed commit under a broken signer is the finding\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn the_verb_derives_a_verifiable_signer_into_silence() {
    let dir = repo("derive-verifiable");
    let written = derive(
        &dir,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample",
        "/usr/bin/ssh-keygen",
        "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
    );
    assert!(
        written.contains("signer verifiable"),
        "an inline literal is the healthiest form there is\n{written}"
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a verifiable signer is left alone, signed commits and all\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

/// POINTER-ONLY THROUGH THE WHOLE PATH (rule 4): neither the key nor the signer
/// path reaches the record, and neither does a full sha.
#[test]
fn no_key_signer_or_full_sha_reaches_the_record() {
    let dir = repo("derive-quiet");
    let full = "abcdef0123456789abcdef0123456789abcdef01";
    let written = derive(&dir, "SECRET-KEY-MATERIAL", "/tmp/SECRET-SIGNER", full);
    assert!(!written.contains("SECRET-KEY-MATERIAL"), "{written}");
    assert!(!written.contains("SECRET-SIGNER"), "{written}");
    assert!(!written.contains(full), "{written}");
    assert!(written.contains("signed abcdef01"), "{written}");
}

/// A family reads only the inputs it declares, and a misspelling is a usage
/// error rather than a reading that silently ran on a default.
#[test]
fn an_input_the_family_does_not_read_is_a_usage_error() {
    let dir = repo("derive-unknown-input");
    let refused = run_with_stdin(
        &dir,
        &[
            "record",
            "derive",
            "signing-posture",
            "--input",
            "signingkey=",
            "--input",
            "ssh-program=",
            "--input",
            "gpgsign=none",
            "--input",
            "signed=",
            "--input",
            "signingkeys=oops",
        ],
        "",
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "an unread input is a usage error\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}
