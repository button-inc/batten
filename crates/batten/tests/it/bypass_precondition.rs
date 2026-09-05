//! `BATTEN_HOOK_BYPASS` stops answering for any class that has a real way out
//! (CLOUD-1357).
//!
//! # What this tier is for
//!
//! `mediated_admission.rs` already proves the hatch does not open `path write
//! refused`, and that the admission route admits it. That was one class, carved
//! out by hand in `adjudicated`. This file is about the **generalisation**: the
//! carve-out is now a property of the class — does it declare an override route
//! carrying a precondition — rather than a branch naming one gate.
//!
//! So the cases here are chosen to be a class that is NOT `path write refused`:
//! `branch write unsafe` declares `override`/`precondition` in `batten.toml` and
//! was suppressible by the string until this change.
//!
//! # Judged against the LIVE repository root, deliberately
//!
//! `mediated_admission.rs` uses a fixture because its cases must WRITE an
//! admission into `$GIT_DIR`. These cases write nothing — they ask which classes
//! the hatch still answers for — and the question is only meaningful over the
//! registry this repository actually ships. A fixture would declare its own
//! classes and prove the predicate against inputs nobody consumes, which is the
//! `with input as` defect one layer up.
//!
//! # CLOUD-1227 IS THE REASON FOR `the_suite_scrubs_the_hatch`
//!
//! Every case below is vacuous if `BATTEN_HOOK_BYPASS` leaks in from the
//! developer's shell: the deny cases would pass because the variable was absent
//! for the wrong reason, and the suppression case would pass because it was
//! present for the wrong reason. CLOUD-1227 is that exact failure, measured — an
//! entire tier of mediated refusal assertions green because a string was set. So
//! the scrub is asserted here rather than assumed of `common::batten()`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

/// A class that declares an `override` route with a precondition, and is raised
/// on the mediated boundary. `batten.toml`'s `leased-push` row.
const PRECONDITIONED: &str = "branch write unsafe";
/// The same, spelled as a command this repository refuses.
const PRECONDITIONED_CALL: &str = "git push --force-with-lease origin main";

/// A class with NO override route, raised on the same boundary by the vendored
/// `trunk-based` preset. The scope pin: this one keeps the hatch.
const BARE: &str = "trunk push forced";
/// The same, spelled as a command.
const BARE_CALL: &str = "git push --force origin main";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// Adjudicate over the compiled binary at the real root, with the hatch set or
/// not, and hand back the exit code and what was written to stderr.
///
/// `common::batten()` scrubs every bypass variable by construction, so `hatch`
/// is the ONLY way one is present — which is what
/// [`the_suite_scrubs_the_hatch`] asserts rather than trusts.
fn adjudicate(command: &str, hatch: bool) -> (Option<i32>, String) {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut builder = common::batten();
    builder
        .args(["adjudicate", "--harness", "exit-code"])
        .current_dir(root());
    if hatch {
        builder.env("BATTEN_HOOK_BYPASS", "1");
    }
    let mut child = builder
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(payload(command).as_bytes());
    }
    let out = child.wait_with_output().expect("await batten");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// THE PREMISE, and CLOUD-1227's lesson made a case rather than a comment.
///
/// Both halves are needed and they fail in opposite directions. If the harness
/// leaked a set `BATTEN_HOOK_BYPASS`, the first assertion would fail — a class
/// that keeps the hatch would be suppressed when the case asked for no hatch. If
/// the harness somehow stripped an explicitly set one, the second would fail.
/// Together they pin that this file controls the variable and nothing else does.
#[test]
fn the_suite_scrubs_the_hatch() {
    let (bare_without, cause) = adjudicate(BARE_CALL, false);
    assert_eq!(
        bare_without,
        Some(2),
        "with no hatch set, a bare-hatch class must refuse — a leaked \
         BATTEN_HOOK_BYPASS is exactly CLOUD-1227's vacuous green\n{cause}"
    );
    assert!(
        cause.contains(BARE),
        "and it must be the class this case names\n{cause}"
    );
    let (bare_with, _) = adjudicate(BARE_CALL, true);
    assert_eq!(
        bare_with,
        Some(0),
        "and an explicitly set hatch must actually reach the binary"
    );
}

/// (a) A CLASS WITH A DECLARED PRECONDITION REFUSES WITH THE HATCH SET.
///
/// The whole row. `branch write unsafe` declares an `override` route with a
/// precondition, so `batten override request` can issue an admission for it and
/// `admit_mediated` honours the spent record — there is a way through that leaves
/// a record, which is what makes taking the password away a repair.
///
/// SHOWN ABLE TO FAIL (CLOUD-418): measured against the unmodified binary, this
/// call exited **0** with the hatch set. That is the defect.
#[test]
fn a_preconditioned_class_is_not_suppressed_by_the_hatch() {
    let (code, cause) = adjudicate(PRECONDITIONED_CALL, true);
    assert_eq!(
        code,
        Some(2),
        "a class with an override precondition must refuse even under the \
         hatch\n{cause}"
    );
    assert!(
        cause.contains(PRECONDITIONED),
        "and it must be that class rather than a neighbour's\n{cause}"
    );
}

/// (b) THE SCOPE PIN, AND THE ANTI-VACUITY CONTROL IN ONE.
///
/// Without this, "refuse everything under the hatch" passes (a) — which is the
/// shape CLOUD-1357 explicitly refuses, because removing the password where
/// nothing replaces it is a wall rather than a repair. `trunk push forced`
/// declares no override route, so it keeps the hatch until it has one, and each
/// such class is a migration row of its own.
#[test]
fn a_class_with_no_precondition_keeps_the_hatch() {
    let (code, cause) = adjudicate(BARE_CALL, true);
    assert_eq!(
        code,
        Some(0),
        "a class with no override route must still be suppressed — the row \
         refuses to build a wall\n{cause}"
    );
}

/// (c) THE CARVE-OUT THIS GENERALISES IS UNCHANGED.
///
/// `path write refused` was the one class the hatch already could not open, by a
/// branch naming its gate. It is now covered by the same predicate every other
/// class is, so this asserts the special case survived becoming a general one.
#[test]
fn the_original_carve_out_still_holds_under_the_general_rule() {
    let (code, cause) = adjudicate("rm batten.toml", true);
    assert_eq!(
        code,
        Some(2),
        "the class the carve-out was written for must still refuse\n{cause}"
    );
    assert!(
        cause.contains("path write refused"),
        "and under its own class\n{cause}"
    );
}

/// (d) NO REFUSAL ADVERTISES A HATCH IT NO LONGER HONOURS (CLOUD-122).
///
/// A deny naming a remedy that does not work is worse than one naming none.
/// The property holds **by construction** rather than by inspection, and the
/// case says which construction: `deny_text` renders `Bypass with …=1.` only
/// where the refusal carries no class token, and `Policy::honours_hatch` answers
/// `true` for exactly that case. So the set that advertises the hatch and the set
/// that no longer honours it are disjoint.
///
/// Asserted over the refusal a caller actually sees, because "by construction" is
/// what the two live instances in `.claude/rules/policy-modules.md` were also
/// said to be.
#[test]
fn a_non_suppressible_refusal_does_not_advertise_the_hatch() {
    for call in [PRECONDITIONED_CALL, "rm batten.toml"] {
        let (code, cause) = adjudicate(call, true);
        assert_eq!(code, Some(2), "the premise: {call}\n{cause}");
        assert!(
            !cause.contains("BATTEN_HOOK_BYPASS"),
            "a refusal the hatch cannot open must not advertise it: {call}\n{cause}"
        );
    }
}
