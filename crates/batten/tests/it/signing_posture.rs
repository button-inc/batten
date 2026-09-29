//! `commit grade unsafe`'s signing half over the compiled binary: the
//! `supply-chain` preset, the engine's own signer reading, and the real git
//! facts it decides over (CLOUD-669, CLOUD-591, CLOUD-1717, CLOUD-843).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `signer-is-verifiable.rego` carries its load-time cases, and every one
//! fabricates its input with `with input as` — the shape
//! `rules/policy-modules.md` warns about. Since CLOUD-843 the module reads THREE
//! engine surfaces (a record the engine writes, `input.tree["git-config"]` per
//! scope and `input.tree["commit-meta"]`'s `signed` bit), so a fabricated input
//! is three chances to pass over a key nothing fills. Every case here builds a
//! real repository, a real key file, real config scopes (`GIT_CONFIG_GLOBAL`
//! points at a scratch file, so a developer's own configuration never reaches a
//! case) and a real signed commit header, and runs the real binary.
//!
//! # A consumer that is not this repository
//!
//! The fixture writes its own `batten.toml` enabling the preset, with no
//! `[[verdict]]` and no `[[pattern]]` rows: a preset reaches a consumer who wrote
//! neither, so a case passing only because the harness supplied one would pass
//! for the wrong reason.
//!
//! # The signer classification
//!
//! `crates/batten/src/signer_posture.rs` is the one authority on which
//! configurations are unverifiable, and its `#[cfg(test)] mod tests` asserts all
//! seven arms against scratch paths. What THIS tier adds is that the engine reads
//! the checkout's own config (no task hands the values in any more) and carries
//! the reading into a record the preset refuses over.
//!
//! # The gate replay
//!
//! `the_retired_conflict_reading_and_the_preset_agree_on_every_scope_pair` runs
//! the retired producer body's own `git config --type=bool` reads and its `case`
//! over sixteen (global, local) pairs, and asserts the preset's verdict agrees on
//! every one — the replay the retirement owes, over the same config files.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! `[tasks.signing-posture-record]` and `[tasks.signing-posture-repair]` retired
//! under CLOUD-843 onto `record derive signing-posture` and `attribution
//! signing`; `[tasks.signing-posture-check]` is argv glue over the two verbs.
//!
// carried: mise-tasks/signing-posture.sh crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego crates/batten/tests/it/signing_posture.rs
// carried: tests/signing-posture.bats crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego crates/batten/tests/it/signing_posture.rs
// carried: "an unsigned range with the override in place passes" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "signing with a verifiable signer is left alone" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "a commit signed by a VERIFIABLE signer is left alone, header and all" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "an empty signing key is what makes it unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key that is a directory is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key this checkout cannot read is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signing key naming a path that does not exist is unverifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "an inline public key is a literal, not a path, and is verifiable" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signer under /tmp is unverifiable because the container reclaims it" crates/batten/src/signer_posture.rs kind:mechanism crates/batten/tests/it/signing_posture.rs
// carried: "a signed commit in range is refused, and named by short sha" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "repairing the config does not excuse a commit already signed" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "a missing override is refused when the environment sets signing globally" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "a missing override is NOT a finding when nothing sets signing globally" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "a local override set to true is refused when the signer is broken" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "the refusal echoes no part of the signature block" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "history before the range is never judged" crates/batten/src/policy/presets/supply-chain/signer-is-verifiable.rego
// carried: "--repair leaves a verifiable signer alone rather than switching signing off" crates/batten/src/signer_posture.rs kind:verb crates/batten/tests/it/signing_posture.rs
// carried: "--repair writes the override, local only" crates/batten/src/signer_posture.rs kind:verb crates/batten/tests/it/signing_posture.rs
// carried: "--repair is idempotent" crates/batten/src/signer_posture.rs kind:verb crates/batten/tests/it/signing_posture.rs
// carried: "--repair never writes global config" crates/batten/src/signer_posture.rs kind:verb crates/batten/tests/it/signing_posture.rs
// changed: "outside a git repository it is exit 2, never a silent pass" crates/batten/src/record.rs kind:mechanism could-not-look is `record derive`'s usage refusal (exit 1) and it writes NOTHING, so the preset — which reads an absent record as silence — says nothing over a tree nobody looked at; `outside_a_repository_the_derivation_refuses_and_records_nothing` and `an_absent_record_says_nothing_rather_than_refusing` are the two halves

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, stderr, stdout, write};

/// The consumer row, as a consumer that is not this repository writes it.
const CONFIG: &str = r#"version = 1
scope = ["**"]

[[rule]]
id = "commit grade unsafe"
kind = "policy"
scope = "tree"
preset = "supply-chain"
git_config = ["commit.gpgsign"]
commits = ["origin/main..HEAD"]
severity = "deny"

[[record]]
record = "signing-posture"
writer = "batten record derive signing-posture"
"#;

/// A committed consumer with `origin/main` pinned at its base, and a global
/// config file of the case's own beside it (empty until a case writes one).
fn repo(name: &str) -> (PathBuf, PathBuf) {
    let dir = Fixture::new(&format!("signing-posture-{name}"))
        .config(CONFIG)
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let global = dir.join(".git").join("case-global.gitconfig");
    std::fs::write(&global, "").expect("an empty global config");
    (dir, global)
}

/// `batten <args>` in `dir`, with git's global scope pointed at `global` and the
/// system scope off, so the engine reads exactly the scopes the case wrote.
fn batten_in(dir: &Path, global: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run batten")
}

/// What `git` itself answers under the same scopes — the retired body's reading.
fn git_scoped(dir: &Path, global: &Path, args: &[&str]) -> String {
    let output = common::git_command(dir, args)
        .env("GIT_CONFIG_GLOBAL", global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run git");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn said(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

/// A key file this checkout signs with, set in the LOCAL scope. Empty is the
/// broken case; non-empty is a healthy one.
fn signing_key(dir: &Path, contents: &str) {
    let key = dir.join(".git").join("case-key.pub");
    std::fs::write(&key, contents).expect("write the key");
    git_in(
        dir,
        &[
            "config",
            "user.signingkey",
            key.to_str().expect("utf8 path"),
        ],
    );
}

/// Write a commit carrying a `gpgsig` HEADER on top of HEAD and move `main` to
/// it, returning its sha.
///
/// Written as a raw object by the reference implementation, because a signature
/// header cannot be produced without a signing program — and the property under
/// test is the header's presence, never whether a key verifies.
fn signed_commit(dir: &Path, subject: &str) -> String {
    let tree = git_in(dir, &["rev-parse", "HEAD^{tree}"]);
    let parent = git_in(dir, &["rev-parse", "HEAD"]);
    let identity = "t <t@example.com> 1577934245 +0000";
    write(
        dir,
        ".git/case-signed.raw",
        &format!(
            "tree {tree}\nparent {parent}\nauthor {identity}\ncommitter {identity}\n\
             gpgsig -----BEGIN SSH SIGNATURE-----\n U1NIU0lHnotarealsignature\n \
             -----END SSH SIGNATURE-----\n\n{subject}\n"
        ),
    );
    let sha = git_in(
        dir,
        &["hash-object", "-t", "commit", "-w", ".git/case-signed.raw"],
    );
    git_in(dir, &["update-ref", "refs/heads/main", &sha]);
    sha
}

/// `record derive signing-posture`, asserted to land.
fn derive(dir: &Path, global: &Path) -> String {
    let written = batten_in(dir, global, &["record", "derive", "signing-posture"]);
    assert_eq!(
        written.status.code(),
        Some(0),
        "the derivation lands\n{}",
        said(&written)
    );
    stdout(&written)
}

/// Derive, then check the one row, the way `[tasks.signing-posture-check]` does.
fn gate(dir: &Path, global: &Path) -> Output {
    derive(dir, global);
    batten_in(dir, global, &["check", "--rule", "commit grade unsafe"])
}

// --- the decision, over the engine's own projection --------------------------

#[test]
fn a_signed_commit_in_range_is_refused_and_named_by_short_sha() {
    let (dir, global) = repo("signed");
    signing_key(&dir, "");
    let sha = signed_commit(&dir, "signed in range");

    let decided = gate(&dir, &global);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains(&sha[..8]),
        "named by its short sha\n{}",
        said(&decided)
    );
    assert!(
        !said(&decided).contains(&sha),
        "and never the full one\n{}",
        said(&decided)
    );
}

#[test]
fn a_detached_head_records_and_decides_as_ci_checks_it_out() {
    // CI checks out a detached HEAD by design (CLOUD-1422), so the producer and
    // the gate both run with no branch; the record key falls back to the commit
    // so writer and reader still meet.
    let (dir, global) = repo("detached");
    signing_key(&dir, "");
    let sha = signed_commit(&dir, "signed, detached");
    git_in(&dir, &["checkout", "--quiet", "--detach", &sha]);

    let decided = gate(&dir, &global);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(said(&decided).contains(&sha[..8]), "{}", said(&decided));
}

#[test]
fn signing_with_a_verifiable_signer_is_left_alone() {
    // THE END STATE CLOUD-591 IS WORKING TOWARD: a healthy key, signing on
    // globally, a signed commit in range — and nothing to report.
    let (dir, global) = repo("verifiable");
    signing_key(&dir, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");
    signed_commit(&dir, "signed by a healthy key");

    let quiet = gate(&dir, &global);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a verifiable signer may sign freely\n{}",
        said(&quiet)
    );
}

#[test]
fn a_missing_override_is_refused_when_the_environment_sets_signing_globally() {
    let (dir, global) = repo("conflict");
    signing_key(&dir, "");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");

    let decided = gate(&dir, &global);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("commit.gpgsign"),
        "the setting is the pointer\n{}",
        said(&decided)
    );
}

#[test]
fn a_missing_override_is_not_a_finding_when_nothing_sets_signing_globally() {
    // A runner has no launcher and no global setting, so an absent local value is
    // the correct state there.
    let (dir, global) = repo("runner");
    signing_key(&dir, "");

    let quiet = gate(&dir, &global);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_local_override_answers_the_global_setting() {
    // git's boolean reading on both sides: a global `1` and a local `off`, which
    // literal `true`/`false` comparisons got wrong in both directions.
    let (dir, global) = repo("override");
    signing_key(&dir, "");
    std::fs::write(&global, "[commit]\n\tgpgsign = 1\n").expect("global config");
    git_in(&dir, &["config", "commit.gpgsign", "off"]);

    let quiet = gate(&dir, &global);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "the local override answers the global setting\n{}",
        said(&quiet)
    );
}

#[test]
fn a_local_override_set_to_true_is_refused_when_the_signer_is_broken() {
    let (dir, global) = repo("local-true");
    signing_key(&dir, "");
    git_in(&dir, &["config", "commit.gpgsign", "true"]);

    let decided = gate(&dir, &global);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("commit.gpgsign"),
        "{}",
        said(&decided)
    );
}

#[test]
fn repairing_the_config_does_not_excuse_a_commit_already_signed() {
    // The whole reason the two classes are separate: the repair clears the
    // config arm and leaves this one firing on whatever was already written.
    let (dir, global) = repo("repaired");
    signing_key(&dir, "");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");
    let sha = signed_commit(&dir, "signed before the repair");

    let repaired = batten_in(&dir, &global, &["attribution", "signing"]);
    assert_eq!(repaired.status.code(), Some(0), "{}", said(&repaired));

    let decided = gate(&dir, &global);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains(&sha[..8]),
        "the commit is still named\n{}",
        said(&decided)
    );
    assert!(
        !said(&decided).contains("commit.gpgsign"),
        "and the config arm is cleared\n{}",
        said(&decided)
    );
}

#[test]
fn the_refusal_echoes_no_part_of_the_signature_block() {
    // POINTER-ONLY (rule 4): a short SHA and a setting name. A signature block is
    // a credential artefact this repository does not control.
    let (dir, global) = repo("quiet");
    signing_key(&dir, "");
    signed_commit(&dir, "signed");

    let reported = said(&gate(&dir, &global));
    assert!(!reported.contains("BEGIN SSH SIGNATURE"), "{reported}");
    assert!(!reported.contains("notarealsignature"), "{reported}");
    assert!(!reported.contains("gpgsig "), "{reported}");
}

#[test]
fn an_unsigned_range_with_the_override_in_place_passes() {
    let (dir, global) = repo("clean");
    signing_key(&dir, "");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");
    git_in(&dir, &["config", "commit.gpgsign", "false"]);
    write(&dir, "src/more.rs", "fn more() {}\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "an unsigned commit in range"]);

    let quiet = gate(&dir, &global);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn history_before_the_range_is_never_judged() {
    // RANGE, NEVER HISTORY: a signed commit already on `origin/main` is history
    // nobody can now unsign, and judging it would make the gate permanently red.
    let (dir, global) = repo("history");
    signing_key(&dir, "");
    signed_commit(&dir, "signed before the range");
    common::pin_origin_main(&dir);

    let quiet = gate(&dir, &global);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn an_absent_record_says_nothing_rather_than_refusing() {
    // The signer is the one reading the engine RECORDS, and nobody recorded it:
    // the preset must not report a posture in force over a signer it never read.
    let (dir, global) = repo("unrecorded");
    signing_key(&dir, "");
    std::fs::write(&global, "[commit]\n\tgpgsign = true\n").expect("global config");
    signed_commit(&dir, "signed, never recorded");

    let quiet = batten_in(&dir, &global, &["check", "--rule", "commit grade unsafe"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        said(&quiet)
    );
}

// --- the gate replay: the retired producer's conflict reading ----------------

/// The retired body's reading, verbatim in effect: `--type=bool` on the local and
/// the global scope, and `conflict` iff the local value is not `false` and either
/// reads `true`.
fn retired_conflict(dir: &Path, global: &Path) -> bool {
    let local_setting = git_scoped(
        dir,
        global,
        &[
            "config",
            "--type=bool",
            "--local",
            "--get",
            "commit.gpgsign",
        ],
    );
    let inherited = git_scoped(
        dir,
        global,
        &[
            "config",
            "--type=bool",
            "--global",
            "--get",
            "commit.gpgsign",
        ],
    );
    local_setting != "false" && format!("{inherited}{local_setting}").contains("true")
}

#[test]
fn the_retired_conflict_reading_and_the_preset_agree_on_every_scope_pair() {
    let (dir, global) = repo("replay");
    signing_key(&dir, "");
    derive(&dir, &global);
    let values = [None, Some("true"), Some("1"), Some("off")];
    for global_value in values {
        for local_value in values {
            match global_value {
                Some(value) => std::fs::write(&global, format!("[commit]\n\tgpgsign = {value}\n")),
                None => std::fs::write(&global, ""),
            }
            .expect("global config");
            let _ =
                common::git_command(&dir, &["config", "--unset-all", "commit.gpgsign"]).output();
            if let Some(value) = local_value {
                git_in(&dir, &["config", "commit.gpgsign", value]);
            }
            let old = retired_conflict(&dir, &global);
            let decided = batten_in(&dir, &global, &["check", "--rule", "commit grade unsafe"]);
            let new = decided.status.code() == Some(2) && said(&decided).contains("commit.gpgsign");
            assert_eq!(
                old,
                new,
                "global {global_value:?}, local {local_value:?}: the retired body said \
                 conflict={old}, the preset said {new}\n{}",
                said(&decided)
            );
        }
    }
}

// --- the signer classification, over the real verb ---------------------------

#[test]
fn the_verb_reads_a_broken_signer_off_the_checkouts_own_config() {
    let (dir, global) = repo("derive-broken");
    signing_key(&dir, "");
    let written = derive(&dir, &global);
    assert!(written.starts_with("signer broken"), "{written}");
    assert!(written.contains("empty file"), "{written}");
}

#[test]
fn the_verb_reads_a_signer_program_under_tmp_from_the_global_scope() {
    // THE LAUNCHER'S SHAPE: a signer written to the GLOBAL scope, which a task
    // passing only local values would never have seen.
    let (dir, global) = repo("derive-tmp");
    std::fs::write(
        &global,
        "[user]\n\tsigningkey = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n\
         [gpg \"ssh\"]\n\tprogram = /tmp/SECRET-SIGNER\n",
    )
    .expect("global config");
    let written = derive(&dir, &global);
    assert!(written.starts_with("signer broken"), "{written}");
    assert!(written.contains("/tmp"), "{written}");
    assert!(!written.contains("SECRET-SIGNER"), "{written}");
}

#[test]
fn the_verb_reads_an_unset_key_as_verifiable() {
    let (dir, global) = repo("derive-unset");
    assert_eq!(derive(&dir, &global), "signer verifiable\n");
}

/// POINTER-ONLY THROUGH THE WHOLE PATH (rule 4): the key path never reaches
/// the record.
#[test]
fn no_key_path_reaches_the_record() {
    let (dir, global) = repo("derive-quiet");
    signing_key(&dir, "");
    let written = derive(&dir, &global);
    assert!(!written.contains("case-key.pub"), "{written}");
    assert_eq!(written.lines().count(), 1, "{written}");
}

/// The family reads no inputs now, and a caller still speaking the retired
/// contract is a usage error rather than a reading that silently ignored it.
#[test]
fn an_input_the_family_does_not_read_is_a_usage_error() {
    let (dir, global) = repo("derive-unknown-input");
    let refused = batten_in(
        &dir,
        &global,
        &[
            "record",
            "derive",
            "signing-posture",
            "--input",
            "signingkey=oops",
        ],
    );
    assert_eq!(refused.status.code(), Some(1), "{}", said(&refused));
}

#[test]
fn outside_a_repository_the_derivation_refuses_and_records_nothing() {
    let dir = common::scratch_outside_tree("batten-signing-posture", "not-a-repo");
    let global = dir.join("global.gitconfig");
    std::fs::write(&global, "").expect("global config");
    let refused = batten_in(&dir, &global, &["record", "derive", "signing-posture"]);
    assert_eq!(refused.status.code(), Some(1), "{}", said(&refused));
    assert!(stdout(&refused).is_empty(), "no record printed");
}

// --- the repair, over the real verb -------------------------------------------

fn local_gpgsign(dir: &Path, global: &Path) -> String {
    git_scoped(
        dir,
        global,
        &["config", "--local", "--get", "commit.gpgsign"],
    )
}

#[test]
fn the_repair_leaves_a_verifiable_signer_alone_rather_than_switching_signing_off() {
    let (dir, global) = repo("repair-verifiable");
    signing_key(&dir, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample\n");
    let repaired = batten_in(&dir, &global, &["attribution", "signing"]);
    assert_eq!(repaired.status.code(), Some(0), "{}", said(&repaired));
    assert!(
        stderr(&repaired).contains("leaving signing on"),
        "{}",
        said(&repaired)
    );
    assert_eq!(local_gpgsign(&dir, &global), "", "nothing was written");
}

#[test]
fn the_repair_writes_the_override_local_only_and_is_idempotent() {
    let (dir, global) = repo("repair-broken");
    signing_key(&dir, "");
    let global_before = "[commit]\n\tgpgsign = true\n";
    std::fs::write(&global, global_before).expect("global config");

    for _ in 0..2 {
        let repaired = batten_in(&dir, &global, &["attribution", "signing"]);
        assert_eq!(repaired.status.code(), Some(0), "{}", said(&repaired));
        assert!(
            stderr(&repaired).contains("signing disabled"),
            "{}",
            said(&repaired)
        );
        assert!(
            !said(&repaired).contains("case-key.pub"),
            "{}",
            said(&repaired)
        );
        assert_eq!(local_gpgsign(&dir, &global), "false");
    }
    assert_eq!(
        std::fs::read_to_string(&global).expect("read the global config"),
        global_before,
        "the global scope is never written"
    );
}
