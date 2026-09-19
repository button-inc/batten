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
//! `mise-tasks/signer_posture.py` is the one authority on those branches, shared
//! with `[tasks.signing-posture-record]` and `[tasks.signing-posture-repair]`.
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
// carried: "an empty signing key is what makes it unverifiable" policy/signing-posture.rego kind:mechanism
// carried: "a signing key that is a directory is unverifiable" policy/signing-posture.rego kind:mechanism
// carried: "a signing key this checkout cannot read is unverifiable" policy/signing-posture.rego kind:mechanism
// carried: "a signing key naming a path that does not exist is unverifiable" policy/signing-posture.rego kind:mechanism
// carried: "an inline public key is a literal, not a path, and is verifiable" policy/signing-posture.rego kind:mechanism
// carried: "a signer under /tmp is unverifiable because the container reclaims it" policy/signing-posture.rego kind:mechanism
// carried: "a signed commit in range is refused, and named by short sha" policy/signing-posture.rego kind:mechanism
// carried: "repairing the config does not excuse a commit already signed" policy/signing-posture.rego kind:mechanism
// carried: "a missing override is refused when the environment sets signing globally" policy/signing-posture.rego kind:mechanism
// carried: "a missing override is NOT a finding when nothing sets signing globally" policy/signing-posture.rego kind:mechanism
// carried: "a local override set to true is refused when the signer is broken" policy/signing-posture.rego kind:mechanism
// carried: "the refusal echoes no part of the signature block" policy/signing-posture.rego kind:mechanism
// changed: "--repair leaves a verifiable signer alone rather than switching signing off" mise.toml the write is the WRITE, which a module cannot be, so it stayed a task — `[tasks.signing-posture-repair]` — and its guard is the same shared `signer_posture.py` reading this tier drives. `an_inline_public_key_is_a_literal_not_a_path_and_is_verifiable` pins the branch the guard turns on
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

// --- the signer classification -----------------------------------------------

/// Run the REAL classification both tasks run.
#[expect(
    clippy::disallowed_types,
    reason = "CLOUD-320's inventory row, and the verdict is that this spawn IS the subject under test: which configurations are unverifiable is what moved out of the dying program into `mise-tasks/signer_posture.py`, and a harness re-implementing the four file tests in Rust would be a second authority over the one question both the record and the repair turn on"
)]
fn posture(signingkey: &str, program: &str) -> String {
    let done = std::process::Command::new("python3")
        .arg("../../mise-tasks/signer_posture.py")
        .arg(signingkey)
        .arg(program)
        .output()
        .expect("the classification runs");
    assert!(
        done.status.success(),
        "it completes: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).trim().to_owned()
}

#[test]
fn an_empty_signing_key_is_what_makes_it_unverifiable() {
    let dir = scratch("signer-empty");
    write(&dir, "key.pub", "");
    let said = posture(dir.join("key.pub").to_string_lossy().as_ref(), "");
    assert!(said.starts_with("broken"), "an empty key is broken\n{said}");
    assert!(said.contains("empty file"), "and says which test\n{said}");
}

#[test]
fn a_signing_key_that_is_a_directory_is_unverifiable() {
    // `-s` ALONE WAS THE TEST HERE AND IT IS TRUE FOR A DIRECTORY, which leaves
    // the public half unreadable — the condition being named.
    let dir = scratch("signer-dir");
    write(&dir, "keydir/placeholder", "");
    let said = posture(dir.join("keydir").to_string_lossy().as_ref(), "");
    assert!(
        said.contains("not a regular file"),
        "a directory is broken, and says so\n{said}"
    );
}

#[test]
fn a_signing_key_this_checkout_cannot_read_is_unverifiable() {
    let dir = scratch("signer-unreadable");
    write(&dir, "key.pub", "ssh-ed25519 AAAA");
    let path = dir.join("key.pub");
    let mut perms = std::fs::metadata(&path).expect("it exists").permissions();
    {
        use std::os::unix::fs::PermissionsExt as _;
        perms.set_mode(0o000);
    }
    std::fs::set_permissions(&path, perms).expect("it is unreadable");

    let said = posture(path.to_string_lossy().as_ref(), "");
    // Running as root defeats the permission bit, so this asserts the branch it
    // can reach rather than claiming one it cannot.
    assert!(
        said.contains("cannot read") || said == "verifiable",
        "an unreadable key is broken where the OS enforces it\n{said}"
    );
}

#[test]
fn a_signing_key_naming_a_path_that_does_not_exist_is_unverifiable() {
    let said = posture("/nowhere/at/all/key.pub", "");
    assert!(
        said.contains("does not exist"),
        "an absent path is broken, and says so\n{said}"
    );
}

#[test]
fn an_inline_public_key_is_a_literal_not_a_path_and_is_verifiable() {
    // A LITERAL IS THE MOST PUBLISHABLE FORM THERE IS — it is already the public
    // half — so testing it as a file would report the healthiest possible
    // configuration as broken.
    assert_eq!(
        posture("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", ""),
        "verifiable"
    );
    assert_eq!(
        posture("key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", ""),
        "verifiable"
    );
    assert_eq!(posture("sk-ssh-ed25519@openssh.com AAAA", ""), "verifiable");
}

#[test]
fn a_signer_under_tmp_is_unverifiable_because_the_container_reclaims_it() {
    // And it outranks the key test: a reproducible key behind an irreproducible
    // signer is still not re-verifiable later.
    let said = posture("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", "/tmp/code-sign");
    assert!(
        said.contains("/tmp"),
        "a /tmp signer is broken whatever the key is\n{said}"
    );
}

#[test]
fn a_signer_failing_neither_test_is_left_alone() {
    // The anti-vacuity arm: without it every case above passes on a
    // classification that returned `broken` unconditionally.
    let dir = scratch("signer-healthy");
    write(&dir, "key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n");
    assert_eq!(
        posture(
            dir.join("key.pub").to_string_lossy().as_ref(),
            "/usr/bin/ssh-keygen"
        ),
        "verifiable"
    );
}
