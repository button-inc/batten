//! `diff key other` over the compiled binary and the REAL producer (CLOUD-192,
//! CLOUD-674, CLOUD-1717).
//!
//! The producer's body is read out of `mise.toml` and run against a fixture
//! branch whose commits carry real `Refs:` trailers, and the engine decides over
//! what it recorded. The closing reading is the engine grammar's
//! `keys_closed_in`, built from the committed `[[pattern]]` table the fixture
//! carries — so a verb, an inflection or a boundary the retired regex honoured is
//! asserted against the one reader that now owns it.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/closing-key-check.sh policy/closing-key.rego kind:mechanism crates/batten/tests/it/closing_key.rs
// carried: tests/closing-key-check.bats policy/closing-key.rego kind:mechanism crates/batten/tests/it/closing_key.rs
// carried: "the measured failing body — named, never closed — is refused" policy/closing-key.rego kind:mechanism
// carried: "the measured passing body — a closing keyword — is accepted" policy/closing-key.rego kind:mechanism
// carried: "all three verbs in all three inflections close" crates/batten/src/ready.rs kind:mechanism
// carried: "case and the optional punctuation the integration tolerates" crates/batten/src/ready.rs kind:mechanism
// carried: "the keyword and the key must be ADJACENT, not merely both present" crates/batten/src/ready.rs kind:mechanism
// carried: "a body that MENTIONS the marker has not used it" policy/closing-key.rego kind:mechanism
// carried: "a closing key wins over a marker the body merely discusses" policy/closing-key.rego kind:mechanism
// carried: "DO-NOT-CLOSE opts out — a PR that does not complete its issue" policy/closing-key.rego kind:mechanism
// carried: "a body that both closes and opts out is reported as closing" policy/closing-key.rego kind:mechanism
// carried: "the marker may name the issue it declines to close" policy/closing-key.rego kind:mechanism
// carried: "a hyphen-prefixed verb is still not a close, wherever it appears" crates/batten/src/ready.rs kind:mechanism
// carried: "an indented marker still opts out — leading whitespace is not a mention" policy/closing-key.rego kind:mechanism
// carried: "a body naming no key at all is the key rule's case, not this one" policy/closing-key.rego kind:mechanism
// carried: "one closed key is enough, even beside a named-but-unclosed one" policy/closing-key.rego kind:mechanism
// carried: "a key embedded in a longer token is not a key" crates/batten/src/ready.rs kind:mechanism
// carried: "several named keys are each reported, in stable numeric order" policy/closing-key.rego kind:mechanism
// carried: "output is a pointer — keys and a verdict, never a line of the body" policy/closing-key.rego kind:mechanism
// carried: "empty stdin exits 2, distinct from a passing body" policy/closing-key.rego kind:mechanism
// carried: "whitespace-only stdin exits 2 as well" policy/closing-key.rego kind:mechanism
// withdrawn: "the positive control: PR #491's real body closes every key its branch served" the case replayed one captured body against a served log passed through `--served-log`. That flag is gone — the producer reads the branch it runs on — and the property the control guarded, that a body closing every served key passes, is `a_body_closing_every_served_key_passes`
// carried: "a body closing a strict subset of the served keys is refused" policy/closing-key.rego kind:mechanism
// carried: "the strand refusal names keys and a remedy, never a line of the body" policy/closing-key.rego kind:mechanism
// carried: "only the FIRST key of a Refs: trailer is served — the rest are citations" crates/batten/src/race.rs kind:mechanism
// carried: "DO-NOT-CLOSE exempts the subtraction, not merely the closing form" policy/closing-key.rego kind:mechanism
// carried: "a branch whose commits carry no Refs: trailer is not judged" policy/closing-key.rego kind:mechanism
// carried: "a single-ticket PR is unaffected" policy/closing-key.rego kind:mechanism
// withdrawn: "--served-log '' is distinct from the flag being absent" the flag was an injection seam for a suite run from inside this repository, so a served set read from git would depend on whichever branch was checked out. The producer runs in its fixture's own checkout, so there is no ambient branch to shield and no flag to distinguish
// changed: "--list decides nothing, even when keys are stranded" crates/batten/src/recorder.rs `--list` was the `pr-closes` recorder's only way to reuse the closing-verb regex without a second copy. That caller now asks the `closing-keys` authority, which is the grammar's own reading and decides nothing by construction — it returns keys and a zero status
// carried: "the served set ignores a closing keyword — the comparison is not circular" crates/batten/src/race.rs kind:mechanism
// carried: "a marker naming a key exempts THAT key and no other" policy/closing-key.rego kind:mechanism
// carried: "a keyed marker does not excuse a key it never named" policy/closing-key.rego kind:mechanism
// carried: "a bare marker still declines the whole body" policy/closing-key.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{at_root, git_in, init_repo, run, scratch, write};

fn committed_patterns() -> String {
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(at_root("batten.toml")).expect("the config"))
            .expect("batten.toml parses");
    let mut table = toml::map::Map::new();
    table.insert(
        "pattern".to_owned(),
        config.get("pattern").expect("[[pattern]] rows").clone(),
    );
    toml::to_string(&toml::Value::Table(table)).expect("re-serializes")
}

/// A repository registering the real module, with `origin/main` at the base and
/// a keyless branch `work` checked out, whose commits serve `served` — each
/// entry one commit's `Refs:` trailer.
fn repo(name: &str, served: &[&str]) -> PathBuf {
    let dir = scratch(&format!("closing-key-{name}"));
    let module = std::fs::read_to_string(at_root("policy/closing-key.rego")).expect("the module");
    write(&dir, "policy/closing-key.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run closing-key-record\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n{}{}{}\
             [[rule]]\nid = \"diff key other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/closing-key.rego\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"closing-key\"\nwriter = \"mise run closing-key-record\"\n\n{}",
            verdict("diff key missing"),
            verdict("diff key dropped"),
            verdict("diff read partial"),
            committed_patterns()
        ),
    );
    init_repo(&dir);
    git_in(&dir, &["checkout", "-q", "-b", "main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "main"]);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    for trailer in served {
        git_in(
            &dir,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("feat: part\n\n{trailer}"),
            ],
        );
    }
    dir
}

fn producer_body() -> String {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["closing-key-record"]["run"]
        .as_str()
        .expect("[tasks.closing-key-record] declares a run body")
        .to_owned()
}

fn produce(dir: &Path, body: &str) -> Output {
    use std::io::Write as _;

    let template = common::batten();
    let mut command = Command::new("bash");
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let mut child = command
        .args(["-c", &producer_body()])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the producer");
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(body.as_bytes());
    child.wait_with_output().expect("run the producer")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce over `body` on a branch serving `served`, then decide.
fn verdict(name: &str, served: &[&str], body: &str) -> (Option<i32>, String) {
    let dir = repo(name, served);
    let produced = produce(&dir, body);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = run(&dir, &["check", "--rule", "diff key other"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn a_body_naming_its_issue_but_never_closing_it_is_refused() {
    // The measured pair: #398 said `Refs:` and never moved; #400 said `Closes`.
    let (code, text) = verdict("named", &[], "Refs: CLOUD-192\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-192"), "{text}");
    let (closed, text) = verdict("closed", &[], "Closes CLOUD-192\n");
    assert_eq!(closed, Some(0), "{text}");
}

#[test]
fn every_closing_verb_inflection_case_and_punctuation_closes() {
    for (n, body) in [
        "close CLOUD-1",
        "closes CLOUD-1",
        "closed CLOUD-1",
        "fix CLOUD-1",
        "fixes CLOUD-1",
        "fixed CLOUD-1",
        "resolve CLOUD-1",
        "resolves CLOUD-1",
        "resolved CLOUD-1",
        "CLOSES CLOUD-1",
        "Closes: CLOUD-1",
    ]
    .iter()
    .enumerate()
    {
        let (code, text) = verdict(&format!("verb-{n}"), &[], &format!("{body}\n"));
        assert_eq!(code, Some(0), "`{body}` closes: {text}");
    }
}

#[test]
fn a_verb_must_be_adjacent_and_a_hyphen_prefix_or_embedded_key_is_not_a_close() {
    for (name, body) in [
        ("apart", "This fixes things.\n\nSee CLOUD-1.\n"),
        ("hyphen", "Some prose then pre-closes CLOUD-1 here.\n"),
        ("embedded", "Closes XCLOUD-1 but names CLOUD-1.\n"),
    ] {
        let (code, text) = verdict(name, &[], body);
        assert_eq!(code, Some(2), "{name} closes nothing: {text}");
    }
}

#[test]
fn the_marker_opts_out_only_when_used_not_when_mentioned() {
    let (bare, text) = verdict("bare", &[], "Refs: CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(bare, Some(0), "a bare marker opts out: {text}");
    let (indented, text) = verdict("indented", &[], "Refs: CLOUD-1\n   DO-NOT-CLOSE\n");
    assert_eq!(indented, Some(0), "indentation is not a mention: {text}");
    let (keyed, text) = verdict("keyed", &[], "Refs: CLOUD-388\nDO-NOT-CLOSE CLOUD-388\n");
    assert_eq!(keyed, Some(0), "the marker may name its issue: {text}");
    let (mentioned, text) = verdict(
        "mentioned",
        &[],
        "Refs: CLOUD-1. This PR explains the DO-NOT-CLOSE marker.\n",
    );
    assert_eq!(mentioned, Some(2), "a mention is not a use: {text}");
    let (wins, text) = verdict(
        "close-wins",
        &[],
        "Closes CLOUD-1. This PR explains the DO-NOT-CLOSE marker.\n",
    );
    assert_eq!(wins, Some(0), "a close is read first: {text}");
    let (both, text) = verdict("both", &[], "Closes CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(both, Some(0), "closing and opting out is closing: {text}");
}

#[test]
fn no_key_passes_one_close_is_enough_and_every_named_key_is_reported() {
    let (none, text) = verdict("no-key", &[], "A body with no key.\n");
    assert_eq!(none, Some(0), "not this gate's case: {text}");
    let (one, text) = verdict("one-closed", &[], "Closes CLOUD-2, related to CLOUD-3.\n");
    assert_eq!(one, Some(0), "{text}");
    let (several, text) = verdict(
        "several",
        &[],
        "A secret body line. Refs: CLOUD-10 and CLOUD-2.\n",
    );
    assert_eq!(several, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("CLOUD-10"),
        "{text}"
    );
    assert!(!text.contains("secret body line"), "pointer only: {text}");
}

#[test]
fn empty_or_whitespace_stdin_is_could_not_look() {
    for (name, body) in [("empty", ""), ("blank", "  \n\t\n")] {
        let dir = repo(name, &[]);
        assert_eq!(produce(&dir, body).status.code(), Some(2), "{name}");
    }
}

#[test]
fn a_body_closing_a_strict_subset_of_the_served_keys_is_refused() {
    // CLOUD-674, measured at `b2f8992`: a bundle closing one of five served rows.
    let (code, text) = verdict(
        "strand",
        &["Refs: CLOUD-1", "Refs: CLOUD-2"],
        "Closes CLOUD-1\n",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-2"),
        "the stranded key is named: {text}"
    );
    assert!(
        !text.contains("Closes CLOUD-1"),
        "never a body line: {text}"
    );
}

#[test]
fn a_body_closing_every_served_key_passes() {
    let (code, text) = verdict(
        "all-served",
        &["Refs: CLOUD-1", "Refs: CLOUD-2"],
        "Closes CLOUD-1\nCloses CLOUD-2\n",
    );
    assert_eq!(code, Some(0), "{text}");
    let (single, text) = verdict("single", &["Refs: CLOUD-1"], "Closes CLOUD-1\n");
    assert_eq!(single, Some(0), "a single-ticket PR is unaffected: {text}");
}

#[test]
fn only_the_first_key_of_a_trailer_is_served_and_the_served_set_ignores_the_body() {
    // The rest of a trailer are citations; and a closing keyword in the body is
    // not a served key, or the comparison agrees with itself by construction.
    let (code, text) = verdict("first-key", &["Refs: CLOUD-1, CLOUD-2"], "Closes CLOUD-1\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_branch_with_no_refs_trailer_is_not_judged_by_the_subtraction() {
    let (code, text) = verdict("no-refs", &[], "Closes CLOUD-1, see CLOUD-2.\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_keyed_marker_does_not_excuse_a_key_it_never_named() {
    let served = &["Refs: CLOUD-1", "Refs: CLOUD-2", "Refs: CLOUD-3"];
    let (exempt, text) = verdict(
        "keyed-exempt",
        served,
        "Closes CLOUD-1\nCloses CLOUD-3\nDO-NOT-CLOSE CLOUD-2\n",
    );
    assert_eq!(exempt, Some(0), "the named key is exempt: {text}");
    let (other, text) = verdict(
        "keyed-other",
        served,
        "Closes CLOUD-1\nDO-NOT-CLOSE CLOUD-2\n",
    );
    assert_eq!(other, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-3"),
        "the un-named key still strands: {text}"
    );
    let (global, text) = verdict("global", served, "Closes CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(
        global,
        Some(0),
        "a bare marker declines the whole body: {text}"
    );
}

#[test]
fn a_record_missing_a_reading_is_torn_rather_than_clean() {
    let dir = repo("torn", &[]);
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "closing-key"],
        "named\tCLOUD-1\nclosing\tCLOUD-1\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = run(&dir, &["check", "--rule", "diff key other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}
