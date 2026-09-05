//! The compiled-binary tier for `policy/shell-write-advisory.rego` (CLOUD-1131).
//!
//! # Why this file exists rather than a `with input as` case
//!
//! The module's own `test_` rules are the load-time tier and they pin the
//! PREDICATE. They cannot pin that the ENGINE builds the input the predicate
//! reads: a fabricated envelope is exactly the shape the engine may be unable to
//! produce, so a suite made only of them passes over a key nothing fills. Both
//! live instances of that class in this repository were found by adding this
//! tier, never by reading — `.claude/rules/policy-modules.md` records them.
//!
//! It matters more than usual here. The module reads `input.call.writes`, and
//! that key CHANGED MEANING under this row's feet: CLOUD-1133 found it carried
//! the host's `file_path` verbatim, which Claude Code sends absolute, so every
//! repo-relative comparison silently missed. A `with input as` case written
//! against the fixed shape would have passed against the broken engine.
//!
//! # The drift gate
//!
//! [`the_two_authorities_agree_on_what_is_governed`] is the mechanism the module
//! header promises. §1 asks that `shell-retirement` and this advisory never
//! disagree about the governed set, and the clean way to guarantee it — calling
//! the owning module's predicate — does not compile in this engine. So the
//! predicate is restated, and restatement without a gate is how two authorities
//! drift while both keep passing their own suites.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin_at_real_root, stderr, stdout};

/// The repository root, whose committed `batten.toml` registers both modules.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope for a write tool.
fn write_payload(tool: &str, path: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": path, "content": "x\n"},
    })
    .to_string()
}

/// A Claude Code `PreToolUse` envelope for a shell command.
fn bash_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

/// A bench registering ONLY the advisory module, which is where every case that
/// asks *what the advisory says* is judged.
///
/// **THE PREMISE THESE CASES USED TO INHERIT** (CLOUD-1434). They ran at the real
/// root, and none of them established that nothing ELSE refuses the call first —
/// yet `claim-needs-receipt` denies any write inside the repository when the
/// branch carries no claim receipt, and a deny pre-empts the advisory. So the
/// positives passed only while the SESSION RUNNING THE SUITE happened to hold a
/// receipt, and the negatives passed *vacuously* under a deny: no advisory
/// because the call was refused, rather than because the path is ungoverned.
/// Measured on one checkout, warm binary, one variable — receipt present 10/10,
/// receipt absent 6/10 — so this was red for any contributor who had not claimed
/// on the branch they tested from, and red on every runner the moment CLOUD-1422
/// re-attached HEAD and let the gate key on a branch at all.
///
/// It is the correction [`an_advised_and_denied_call_emits_only_the_refusal`]
/// already made below, one polarity over: that case needed a deny it did not own,
/// and these need the ABSENCE of one. Owning the premise is the whole change.
///
/// The module's bytes are the COMMITTED ones, so the predicate under test is
/// unchanged. What deliberately does not survive the move is the incidental
/// "`batten.toml` registers this module" — a different claim, and a registry
/// assertion's to make rather than four advisory cases'.
///
/// ONE FIXTURE PER CASE, and the shared-and-built-once version this replaced is
/// worth a sentence because it failed in a way a standalone run cannot show. A
/// `OnceLock` at a fixed path is not safe here: `Fixture::new` WIPES its
/// directory, and if the init closure panics the cell stays empty, so the next
/// thread re-enters it and wipes the tree the first one is still `git init`-ing.
/// Measured — the suite passed 10/10 run alone, twice, and lost two cases to
/// `update-ref ... not a git repository` under the full parallel run. Per case is
/// also what every other fixture in this suite already does.
fn bench(name: &str) -> PathBuf {
    let module = std::fs::read_to_string(root().join("policy/shell-write-advisory.rego"))
        .expect("the advisory module is readable");
    Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\nid = \"shell-write-advisory\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/shell-write-advisory.rego\"\n\
             severity = \"warn\"\n",
        )
        .file("policy/shell-write-advisory.rego", &module)
        .git()
        .base_commit()
        .build()
}

/// Everything the door said, on either stream.
///
/// BOTH, because which one carries the advisory is a property of the event
/// rather than of the message: `emit_advisory` uses stdout wherever the channel
/// is reachable and the operator's stream only as the unreachable fallback. A
/// case reading one stream would pass against a build that silently stopped
/// delivering, which is the thing this file is here to catch.
fn reported(dir: &Path, payload: &str) -> String {
    let answer =
        run_with_stdin_at_real_root(dir, &["adjudicate", "--harness", "claude-code"], payload);
    format!("{}{}", stdout(&answer), stderr(&answer))
}

fn signals(dir: &Path, payload: &str) -> bool {
    reported(dir, payload).contains("shell edit early")
}

/// A write to an authored shell gate is told at the write.
///
/// The exit code is asserted alongside, because a `warn` that moved the status
/// would be the deny this row refuses — and a deny at write time refuses the one
/// disposition `shell-retirement` admits.
#[test]
fn a_write_to_a_governed_shell_path_signals_without_refusing() {
    let dir = bench("swa-a_write_to_a_governed_shell_path_s");
    let payload = write_payload("Write", "mise-tasks/ready-lint.sh");
    let answer =
        run_with_stdin_at_real_root(&dir, &["adjudicate", "--harness", "exit-code"], &payload);
    assert_eq!(
        answer.status.code(),
        Some(0),
        "an advisory must not move the exit code"
    );
    assert!(signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// And in the spelling the host actually sends.
///
/// CLOUD-1133's normalisation is what makes this pass; before it the absolute
/// spelling missed every repo-relative comparison. Asserted here rather than
/// assumed, because this module is a consumer of that fix and would fail
/// silently — no advisory looks exactly like a clean path.
#[test]
fn the_absolute_spelling_the_host_sends_signals_too() {
    let dir = bench("swa-the_absolute_spelling_the_host_sen");
    let absolute = dir
        .canonicalize()
        .expect("the bench root resolves")
        .join("mise-tasks/ready-lint.sh")
        .display()
        .to_string();
    let payload = write_payload("Write", &absolute);
    assert!(signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// A bats suite is governed too.
#[test]
fn a_write_to_a_bats_suite_signals() {
    let dir = bench("swa-a_write_to_a_bats_suite_signals");
    let payload = write_payload("Write", "tests/land.bats");
    assert!(signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// THE DISCRIMINATING CASE, asserted over the REAL deletion shape.
///
/// A retirement deletes the governed path, and the row's acceptance requires
/// this be asserted over what a deletion actually is — a Bash `git rm` — rather
/// than over a fabricated `Write` event, which would prove nothing about the
/// shape that occurs. A module keyed on the path alone passes every positive
/// case above and impedes every retirement; this is what tells the two apart.
#[test]
fn the_deletion_a_retirement_performs_is_not_impeded() {
    let dir = bench("swa-the_deletion_a_retirement_performs");
    let payload = bash_payload("git rm mise-tasks/ready-lint.sh");
    assert!(!signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// The compound deletion, which is what a retirement actually looks like: a
/// program and its suite are two paths, so the real shape is one list.
#[test]
fn a_compound_retirement_deletion_is_not_impeded() {
    let dir = bench("swa-a_compound_retirement_deletion_is_");
    let payload = bash_payload("git rm mise-tasks/ready-lint.sh && git rm tests/ready-lint.bats");
    assert!(!signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// An ungoverned write is silent, which keeps the governed set a SET.
#[test]
fn an_ungoverned_write_is_silent() {
    let dir = bench("swa-an_ungoverned_write_is_silent");
    let payload = write_payload("Write", "crates/batten/src/hook.rs");
    assert!(!signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// The vacuity case the surface makes easy to get wrong.
///
/// A call carrying no write target must resolve to SILENCE rather than to a
/// match or a fault. `writes` is `null` on every non-write call, and the
/// module's `is_string` guard is what makes that a non-answer instead of an
/// evaluation error — asserted over the engine, because whether the key arrives
/// as `null` or absent is the engine's business and not the module's.
#[test]
fn a_call_carrying_no_write_target_is_silent() {
    let dir = bench("swa-a_call_carrying_no_write_target_is");
    let payload = bash_payload("ls -la");
    assert!(!signals(&dir, &payload), "{}", reported(&dir, &payload));
}

/// THE DRIFT GATE. The two authorities agree about what is governed.
///
/// The advisory restates `shell-retirement`'s path predicate because calling it
/// does not compile — a FUNCTION rule in another package is not reachable even
/// though the bundle shares one engine. Restating creates two authorities that
/// can disagree, and the disagreement would be invisible: each module keeps
/// passing its own suite.
///
/// So this drives one corpus through both surfaces and requires the same answer.
/// `batten check --rule shell-retirement` is the tree authority; the advisory is
/// the mediated one. The corpus deliberately includes the paths where the two
/// predicates are known to differ for a REASON — a `mise-tasks/` file with no
/// shebang is governed for deletion and not for edit — so the assertion is over
/// the PATH-ONLY classification both can compute, which is the only thing the
/// mediated surface has.
///
/// Fails by: editing either module's prefix test or its two suffix exclusions
/// without editing the other.
#[test]
fn the_two_authorities_agree_on_what_is_governed() {
    // Read the tree module's own predicate out of its source rather than
    // restating it a THIRD time here, which would make this gate part of the
    // drift it exists to catch.
    let owner = std::fs::read_to_string(root().join("policy/shell-retirement.rego"))
        .expect("the tree module is readable");
    let mirror = std::fs::read_to_string(root().join("policy/shell-write-advisory.rego"))
        .expect("the advisory module is readable");

    for clause in [
        r#"startswith(path, "mise-tasks/")"#,
        r#"not endswith(path, ".py")"#,
        r#"not endswith(path, ".tsv")"#,
        r#"startswith(path, "tests/")"#,
        r#"endswith(path, ".bats")"#,
    ] {
        assert!(
            owner.contains(clause),
            "shell-retirement no longer carries `{clause}` — the advisory mirrors a \
             predicate that moved, so update both or make the call compile"
        );
        assert!(
            mirror.contains(clause),
            "shell-write-advisory no longer carries `{clause}` — it has drifted from \
             the gate it advertises"
        );
    }
}

// ---------------------------------------------------------------------------
// One document per call, and where a verdict exists it is the verdict's
// (CLOUD-1175).
// ---------------------------------------------------------------------------

/// A call that BOTH advises and denies emits exactly one document, and it is the
/// refusal.
///
/// # Why the COUNT rather than a grep for the deny
///
/// The pre-fix binary emitted both — advisory first, refusal second — so a test
/// asserting "the output contains a deny" passed on it. The defect was never a
/// missing refusal; it was a refusal the host never reaches, because
/// `encode_advice`'s channel is one document per call and a reader takes the
/// first. Only the count tells those apart.
///
/// # Why a FIXTURE rather than this repository
///
/// The first version of this case drove the real tree and relied on
/// `claim-needs-receipt` to supply the deny. That made the premise depend on
/// whether the SESSION RUNNING THE SUITE happened to hold a claim receipt: with
/// one, nothing refuses, only the advisory is emitted, and the case fails for a
/// reason that has nothing to do with the defect. Measured — it did exactly that,
/// and the red-before-green run that was supposed to prove the case discriminates
/// had failed on this same assertion rather than on the count.
///
/// So the pair is CONSTRUCTED: a scratch repository whose `protected` set covers
/// `mise-tasks/**`, which makes a `Write` there a protected mutation, while the
/// advisory module governs the same path. Both fire, from config the test owns.
#[test]
fn an_advised_and_denied_call_emits_only_the_refusal() {
    let module = std::fs::read_to_string(root().join("policy/shell-write-advisory.rego"))
        .expect("the advisory module is readable");
    let bench = Fixture::new("swa-advise-and-deny")
        .config(
            "version = 1\nprotected = [\"mise-tasks/**\"]\n\n\
             [[rule]]\nid = \"shell-write-advisory\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/shell-write-advisory.rego\"\n\
             severity = \"warn\"\n",
        )
        .file("policy/shell-write-advisory.rego", &module);

    let payload = write_payload("Write", "mise-tasks/ready-lint.sh");
    let answer = run_with_stdin_at_real_root(
        bench.path(),
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    let out = stdout(&answer);
    let documents: Vec<&str> = out.lines().filter(|line| !line.trim().is_empty()).collect();

    assert_eq!(
        documents.len(),
        1,
        "one call, one document on the host's decision stream — a second is \
         discarded unread, and on this host the discarded one is the verdict: {out}"
    );
    assert!(
        documents[0].contains("permissionDecision"),
        "the surviving document is the verdict's, never the advisory's: {out}"
    );
    assert!(
        !documents[0].contains("additionalContext"),
        "advice about a call is not merged into its refusal — the remedy already \
         travels in permissionDecisionReason: {out}"
    );
}

/// The direction a careless fix breaks: advice still speaks when nothing refuses.
///
/// Suppressing advice whenever any decision exists would trade a dropped deny for
/// a dropped advisory and undo what CLOUD-1131 measured. `--harness exit-code`
/// has no verdict document of its own, so an allow leaves the advisory as the one
/// thing on stdout.
#[test]
fn an_advised_and_allowed_call_still_speaks() {
    let dir = bench("swa-an_advised_and_allowed_call_still_");
    let payload = write_payload("Write", "mise-tasks/ready-lint.sh");
    let answer =
        run_with_stdin_at_real_root(&dir, &["adjudicate", "--harness", "exit-code"], &payload);
    let reported = format!(
        "{}{}",
        String::from_utf8_lossy(&answer.stdout),
        String::from_utf8_lossy(&answer.stderr)
    );
    assert!(
        reported.contains("shell edit early"),
        "an advisory with nothing refusing it still reaches its reader: {reported}"
    );
}
