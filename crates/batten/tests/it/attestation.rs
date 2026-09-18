//! `release grade unsafe` over the compiled binary (CLOUD-583, CLOUD-1717).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in `policy/attestation.rego` fabricates its input with
//! `with input as`, which cannot see a fact the engine never projects. That is
//! not hypothetical here: `policy/branch-age.rego` spent a whole session
//! registered, its own suite green, and deciding nothing, because
//! `recorder_records` projected no `record named` family at all (CLOUD-1810).
//! These cases run the real module over a record the real verb wrote.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The program's successor is `policy/attestation.rego` for every DECISION it
//! made, and `[tasks.attestation-record]` for everything that is not one: the
//! posture probe, the release download, the unpack, and `gh attestation verify`
//! itself. House style §5 makes `check` `read` and structurally incapable of
//! spawning a process, so that half could not move whatever the ledger said —
//! CLOUD-1559's rule, carry the decisions rather than the steps.
//!
//! THE EXIT CONTRACT CHANGED, AND FIVE ARMS RIDE ON IT. The shell ran `0` pass /
//! `1` an artifact failed / `2` could-not-look. The engine runs `0/1/2/3` where
//! `2` is a FINDING, so carrying the shell's `2` over would have turned every
//! could-not-look into a violation. Each of those arms is now the producer
//! refusing at write time — loudly, while its author is watching — and writing
//! nothing, which leaves the record absent and the module silent.
//!
// carried: mise-tasks/attestation-check.sh policy/attestation.rego kind:mechanism crates/batten/tests/it/attestation.rs
// carried: tests/attestation-check.bats policy/attestation.rego kind:mechanism crates/batten/tests/it/attestation.rs
// carried: "THE GAP IS NOT A VERDICT: a 404 endpoint reports the platform gap and exits 0" policy/attestation.rego kind:mechanism
// carried: "with the platform available and provenance present, the run passes" policy/attestation.rego kind:mechanism
// carried: "with the platform available and provenance absent, the run fails" policy/attestation.rego kind:mechanism
// carried: "THE SUBJECT IS THE BINARY, NOT THE ARCHIVE" policy/attestation.rego kind:mechanism
// carried: "a release carrying no archive is exit 2, not a green verdict about nothing" policy/attestation.rego kind:mechanism
// carried: "output is pointer-only — no attestation body reaches the log" policy/attestation.rego kind:mechanism
// changed: "the gap names the repository it asked about, derived from the remote" mise.toml the slug is the producer's to derive and the producer's to name: it reads the origin remote, and a module naming a repository would be a consumer identifier inside a decision surface. The gap is still reported — `posture 404` is recorded and readable — but the repository it asked about is named where it was asked
// changed: "a download that fails is exit 2 — could not look is not a verdict" mise.toml the download is a step, so its failure is the producer's: it refuses and records nothing, and an absent record is the module's silence. On the engine's contract exit 2 is a FINDING, so the shell's spelling would have made could-not-look a violation
// changed: "a status that is neither 200 nor 404 is exit 2, naming the code" mise.toml the same split: the producer reads the status, so an unreadable posture refuses there and records nothing. Naming the code stays in the producer's own message, where the reader who can act on it is looking
// changed: "a missing credential IS exit 2 in the world half — a 404 could not be told from a denial" mise.toml the credential is what the producer needs to make the probe at all, so its absence refuses before anything is recorded
// changed: "no github.com remote is exit 2 in the world half, and irrelevant to the precondition" mise.toml the remote is how the producer derives the repository to ask about, so its absence refuses there
// changed: "the precondition holds when the verifier resolves" mise.toml the precondition survives as `[tasks.attestation-record] --precondition`, which the `release check unread` row still runs at `deny` — the gate is preserved rather than removed, and only the program carrying it changed
// changed: "THE SEVERITY SPLIT: the precondition holds while the platform gap is open" mise.toml the same split, on the same row: the precondition is local and offline, and the platform gap is the world half the record carries
// changed: "the precondition makes no network call" mise.toml asserted of the producer's precondition mode now; the property is what keeps the `deny` row safe to run on every gate invocation
// changed: "an absent verifier is exit 2 in precondition mode" mise.toml the producer's precondition refuses when `gh` does not resolve, which is the one fact that mode ever asserted
// changed: "a missing credential does NOT fail the precondition — cannot-look is not a deny" mise.toml kept in the producer's precondition mode: a credential is could-not-look, and the landing path must not block on ambient environment

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against a declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("attestation-{name}"));
    let module = std::fs::read_to_string("../../policy/attestation.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/attestation.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "release ship unsafe"
gloss = "a release archive's binary carries no verifiable provenance"
class = "The verifier refused the executable where attestation IS available."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run attestation-record"

[[verdict]]
id = "release carry missing"
gloss = "a release archive carries no executable to verify"
class = "A packaging problem rather than a provenance one."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run attestation-record"

[[verdict]]
id = "release list empty"
gloss = "the producer looked at a tag and found no archive on it"
class = "A green verdict over a release carrying nothing would be about nothing."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run attestation-record"

[[rule]]
id = "release grade unsafe"
kind = "policy"
scope = "tree"
module = "policy/attestation.rego"
severity = "deny"

[[record]]
record = "attestation"
writer = "mise run attestation-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write the producer's record, as `mise run attestation-record` would.
fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "attestation"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// Both streams: which one carries a finding is the output contract's business,
/// and what these cases assert is that the pointer reaches the reader.
fn said(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn an_unverified_archive_is_reported_over_the_engines_projection() {
    let dir = repo("unverified");
    record(
        &dir,
        "posture\t200\narchive\tbatten-x86_64.tar.gz\tunverified\n",
    );

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "an archive the verifier refused decides\n{}",
        said(&decided)
    );
    assert!(
        said(&decided).contains("batten-x86_64.tar.gz"),
        "and the finding names the archive\n{}",
        said(&decided)
    );
}

#[test]
fn a_verified_archive_is_clean() {
    let dir = repo("verified");
    record(
        &dir,
        "posture\t200\narchive\tbatten-x86_64.tar.gz\tverified\n",
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "provenance present is the state the gate must be able to reach\n{}",
        said(&quiet)
    );
}

#[test]
fn a_platform_gap_judges_nothing_even_with_archives_recorded() {
    // THE GAP IS NOT A VERDICT (CLOUD-585). `gh attestation verify` exits 1 both
    // when an artifact has no provenance and when the platform never offered
    // any, and those are opposite facts. With the endpoint answering 404 the
    // verifier refuses everything, so judging here would red every release for a
    // reason no branch causes.
    let dir = repo("gap");
    record(
        &dir,
        "posture\t404\narchive\tbatten-x86_64.tar.gz\tunverified\n",
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a platform gap judges no artifact\n{}",
        said(&quiet)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    // Every could-not-look arm of the retired program — no credential, no
    // remote, an unreadable status, a failed download — is now the producer
    // refusing and writing nothing. This is what that absence must read as.
    let dir = repo("absent");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}

#[test]
fn a_tag_carrying_no_archive_is_refused_rather_than_read_as_clean() {
    // "A green verdict would be about nothing." Present-and-empty and absent are
    // different readings: the case above is nobody having looked, and this is the
    // producer having looked and found a tag with no archives.
    let dir = repo("empty");
    record(&dir, "posture\t200\n");

    let refused = run(&dir, &["check"]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "a tag with no archive is refused\n{}",
        said(&refused)
    );
}

#[test]
fn the_report_names_the_archive_and_carries_no_attestation_body() {
    // POINTER, NEVER PAYLOAD (rule 4). The retired program discarded the
    // verifier's own output deliberately — it names the attesting workflow and
    // signer, which is not this gate's to republish.
    let dir = repo("pointer");
    record(
        &dir,
        "posture\t200\narchive\tbatten-aarch64.tar.gz\tno-binary\n",
    );

    let refused = run(&dir, &["check"]);
    let text = said(&refused);
    assert!(
        text.contains("batten-aarch64.tar.gz"),
        "the asset name is the pointer\n{text}"
    );
    assert!(
        !text.contains("sha256:"),
        "and no digest or bundle travels with it\n{text}"
    );
}
