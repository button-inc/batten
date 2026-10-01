//! `verify` as a sequence of argv steps, and the engine decisions that let it stop
//! being a shell mapper (CLOUD-843, CLOUD-1990).
//!
//! # What moved, and where each property is held now
//!
//! `verify` and `verify:gated` were hand-guarded bash: a task body does not run
//! under `set -e`, so every step was `if ! …; then exit 1; fi`, and `verify` was a
//! MAPPER — every failure left as `1` except `linear-check`'s behind-verdict, which
//! left as `2`, because `land` read a `2` from the gate as "main moved, lap". Two
//! suites pinned that shell: `tests/verify.bats` (the exit-code contract) and
//! `tests/task-fail-closed.bats` (the guard shape). Both bodies are `run` arrays
//! now, and each property went to the one place that can hold it without a shell:
//!
//! * **fail-closed** is mise's own run-array semantics — the first failing step
//!   stops the task with its own code, so the receipt, the last step, is never
//!   written after a refusal. Asserted here as ORDER over the committed arrays.
//! * **"main moved" is read, not numbered.** `land::confirmed` keeps a gate's `2`
//!   as "lap" only when the lap's own reading of the base agrees; any other `2` is
//!   a refusal of the tree and stops, which is CLOUD-407 held in the one reader
//!   that acted on the code. Pinned in `land.rs`'s unit tier and, over the binary,
//!   in `land_verify_advice.rs`.
//! * **the claim disjunction** is `receipt status <check> --or <check>…`, each kind
//!   judged by `receipt::branch_validity` — CLOUD-516's staleness rule for all
//!   three. Pinned below over the compiled binary.
//!
//! # RETIREMENT LEDGER, PER PATH
//!
// ported: tests/verify.bats subject:mise.toml crates/batten/tests/it/verify_chain.rs
// ported: tests/task-fail-closed.bats subject:mise.toml crates/batten/tests/it/verify_chain.rs
//
// `tests/verify.bats`, case by case.
//
// carried: "the mapper body was found at all — this suite is not passing vacuously" mise.toml
// carried: "verify declares no depends, which is the escape route CLOUD-407 closed" mise.toml
// carried: "verify:gated carries the depends verify gave up" mise.toml
// changed: "the mapper mints exactly one exit 2, and it is the behind-verdict arm" crates/batten/src/land.rs kind:mechanism no body mints a code any more — every step's code leaves `verify` unchanged, so a `2` is `linear-check`'s behind-verdict OR any refusal that happens to be a policy verdict. The property the count protected — a refused tree never laps — is `land::confirmed`'s: a `2` becomes "main moved" only when the lap's own read of the base agrees. It survives as `land::tests::an_unconfirmed_move_is_a_refusal_of_the_tree` and `land_verify_advice.rs`'s `a_gate_exiting_2_over_an_unmoved_base_is_a_refusal_of_the_tree`
// changed: "verify:gated mints no exit 2 at all — a content failure is a stop" crates/batten/src/land.rs kind:mechanism a gate that refuses leaves `verify:gated` with its own code, a `2` included, and it is still a STOP: the lap confirms a `2` against the base before lapping on it. Same survivors as the arm above
// changed: "a clean run exits 0 and reaches the gate set" mise.toml the exit is mise's run-array semantics rather than a body's, so what this tier can pin is that the gate set is the LAST step and every step before it is a question that stops the task when refused — `the_steps_run_in_the_retired_order`
// changed: "linear-check's behind-verdict is the one thing that exits 2" mise.toml its `2` still leaves `verify` unchanged and still stops BEFORE the gate set is spent — the order is pinned by `the_steps_run_in_the_retired_order` — and whether that `2` laps is `land::confirmed`'s reading of the base rather than the code's
// carried: "linear-check's environment refusal is a stop, not a lap" mise.toml
// changed: "A POLICY VERDICT REACHING verify IS A STOP: gated's 2 leaves as 1" crates/batten/src/land.rs kind:mechanism it leaves as `2` now, and it is still a stop: `land::confirmed` reads a `2` the base did not move under as a refusal of the tree, which is exactly CLOUD-407's property held by the reader rather than by a re-numbering. The `this is not a rebase` prose went with the mapper; `land`'s own refusal advice is what an operator reads
// changed: "a code outside the table is flattened too, not passed through" crates/batten/src/land.rs kind:mechanism codes pass through; `land::verify` already reads `3`, `126` and `127` as a gate that did not judge and every other non-zero as a refusal of the tree, so a `101` from clippy stops the lap exactly as the flattened `1` did
// changed: "the two conditions are told apart by the code, never by parsing prose" crates/batten/src/land.rs kind:mechanism they are told apart by the lap's own read of the base, which is stronger than either — still never by prose
// carried: "a branch with no claim receipt cannot pass verify" crates/batten/src/receipt.rs kind:mechanism crates/batten/tests/it/verify_chain.rs
// changed: "the refusal names the remedy rather than only the rule" crates/batten/src/receipt.rs kind:mechanism `verify` prints no prose of its own now; the refusal is `receipt status`'s pointer lines, one per kind with its verdict word, and the remedy — `claim-check`, `batten claim bot`, `batten claim carry` — is the `claim-needs-receipt` row's in `batten.toml`, the one authority on it (CLOUD-1050: a remedy restated at a call site drifts)
// carried: "A BOT RECEIPT SATISFIES IT TOO, and it is a SECOND kind rather than a wider one" crates/batten/src/receipt.rs kind:mechanism crates/batten/tests/it/verify_chain.rs
// carried: "neither receipt is still a refusal — the pair is an OR, not an escape hatch" crates/batten/src/receipt.rs kind:mechanism crates/batten/tests/it/verify_chain.rs
// carried: "A STALE RECEIPT IS REFUSED — the row a presence test could not hold" crates/batten/src/receipt.rs kind:mechanism
// carried: "the refusal tells a re-claim apart from a first claim" crates/batten/src/receipt.rs kind:mechanism crates/batten/tests/it/verify_chain.rs
// carried: "a valid receipt that is merely present is not enough — the verdict decides" crates/batten/src/receipt.rs kind:mechanism
// carried: "a bot receipt is judged by the same predicate, not merely counted" crates/batten/src/receipt.rs kind:mechanism
// changed: "a detached HEAD is exempt, because a rebase detaches" crates/batten/src/receipt.rs kind:mechanism STRICTER: a detached HEAD is `receipt status`'s could-not-look now, so `verify` stops there instead of skipping the claim. The carve-out's stated reason was `land.sh` rebasing detached, and that program retired: `land`'s replay leaves the branch checked out, so no lap verifies detached
// carried: "RECLAIM RUNS, and runs before the claim receipt is even looked at" mise.toml
// changed: "a volume that cannot be recovered is a STOP, not a lap" crates/batten/src/land.rs kind:mechanism `target prune`'s own below-floor verdict (`2`) leaves `verify` unchanged and the lap confirms it against the base before lapping, so a full volume still stops; the "not enough disk" wording is the verb's own refusal rather than a caller's restatement of it
// carried: "the reclaim precedes the claim receipt in the mapper" mise.toml
// carried: "the receipt check precedes every other question in the mapper" mise.toml
//
// `tests/task-fail-closed.bats`, case by case.
//
// carried: "both verify bodies were found at all — this suite is not passing vacuously" mise.toml
// changed: "every command verify's verdict depends on is guarded, since the body has no set -e" mise.toml there is no body to leave a line unguarded in: a `run` array stops at its first failing step by mise's own semantics, and `every_step_is_argv` is what keeps a shell body from growing back
// changed: "a captured exit code is checked and exited on, never merely recorded" mise.toml nothing is captured — no step's code is read by anything but mise, which exits with it
// carried: "verify writes its receipt only after the guarded steps, never before" mise.toml
// carried: "the tree-clean precondition guards the receipt from both ends of the run" mise.toml
// changed: "each guard exits non-zero rather than merely warning" mise.toml a step that fails stops the sequence with its own non-zero code, so a guard that could print and carry on no longer has a spelling
// carried: "a failing step leaves no receipt — the guard's whole purpose" mise.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;

use common::{Fixture, batten, git_in, scratch};

/// One task's table from the committed manifest, parsed.
///
/// Through `common::task_block`, so under `mutate sweep` this is the STAGED
/// manifest and a declared mutation is what the case reads.
fn task(name: &str) -> toml::Value {
    let block = common::task_block(name).unwrap_or_else(|| panic!("{name} is a declared task"));
    let parsed: toml::Value = toml::from_str(&block).expect("a task block is a TOML table");
    parsed
        .get("tasks")
        .and_then(toml::Value::as_table)
        .and_then(|tasks| tasks.values().next())
        .cloned()
        .unwrap_or_else(|| panic!("{name} carries a table"))
}

/// A task's `run` as its steps: an array's entries, or a string as one step.
fn steps(name: &str) -> Vec<String> {
    match task(name).get("run") {
        Some(toml::Value::Array(entries)) => entries
            .iter()
            .map(|entry| entry.as_str().expect("every step is a string").to_owned())
            .collect(),
        Some(toml::Value::String(one)) => vec![one.clone()],
        other => panic!("{name} declares a run: {other:?}"),
    }
}

/// The position of the one step that `contains` the needle.
fn step_at(all: &[String], needle: &str) -> usize {
    let found: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, step)| step.contains(needle))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(found.len(), 1, "exactly one step runs `{needle}`: {all:?}");
    found[0]
}

/// A key of a task's `env`, as written.
fn env_of(name: &str, key: &str) -> String {
    task(name)
        .get("env")
        .and_then(|env| env.get(key))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{name} sets {key}"))
        .to_owned()
}

/// A task's `depends`, as entries.
fn depends_of(name: &str) -> Vec<String> {
    task(name)
        .get("depends")
        .and_then(toml::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The sequences, as committed.
// ---------------------------------------------------------------------------

/// ANTI-VACUITY: every order assertion below reads these arrays, so they must be
/// found and must be the steps this tier is about.
#[test]
fn the_verify_sequence_was_found_at_all() {
    let verify = steps("verify");
    assert!(verify.len() >= 5, "{verify:?}");
    let gated = steps("verify:gated");
    assert!(
        gated
            .iter()
            .any(|step| step.contains("receipt record verify")),
        "{gated:?}"
    );
}

/// NO SHELL GROWS BACK. Each step is judged by the census's own grammar — the
/// reading `policy/shell-banned.rego` shares — so a step that needed a shell to
/// run would be counted, and this reds before the census does.
#[test]
fn every_step_is_argv() {
    for name in [
        "verify",
        "verify:gated",
        "verify:commit-lint",
        "verify:config-lint",
        "target-prune",
        "target-prune:lap",
        "ci-wait",
        "test:cargo",
        "test:musl",
        "test:filter",
    ] {
        for step in steps(name) {
            assert!(
                !batten::census::shell_syntax(&step),
                "[tasks.{name}] runs a step that needs a shell: {step}"
            );
        }
    }
}

/// CLOUD-407's structural half, unchanged: `verify` carries no `depends`, so no
/// dependency's code reaches a caller ahead of the questions `verify` asks first.
#[test]
fn verify_declares_no_depends() {
    assert!(
        depends_of("verify").is_empty(),
        "{:?}",
        depends_of("verify")
    );
}

#[test]
fn verify_gated_carries_the_depends_verify_gave_up() {
    let depends = depends_of("verify:gated");
    for needed in ["tree-clean", "ci", "cross-check"] {
        assert!(
            depends.iter().any(|entry| entry == needed),
            "verify:gated depends on {needed}: {depends:?}"
        );
    }
}

/// THE RETIRED BODY'S ORDER, which the old suite pinned by behaviour and by text:
/// the reclaim first (the one refusal the others cannot survive), then the
/// toolchain, then the claim receipt (a question cheaper than any below it),
/// then linearity (a branch that is behind laps regardless, so the gate set is
/// not paid for first), and the gate set last.
#[test]
fn the_steps_run_in_the_retired_order() {
    let verify = steps("verify");
    let reclaim = step_at(&verify, "target-prune:lap");
    let toolchain = step_at(&verify, "toolchain-check");
    let claim = step_at(&verify, "receipt status claim");
    let linear = step_at(&verify, "linear-check");
    let gated = step_at(&verify, "verify:gated");
    assert!(reclaim < toolchain, "{verify:?}");
    assert!(toolchain < claim, "{verify:?}");
    assert!(claim < linear, "{verify:?}");
    assert!(linear < gated, "{verify:?}");
    assert_eq!(gated, verify.len() - 1, "the gate set is the last question");
}

/// THE CLAIM IS ANY ONE OF THE THREE KINDS, asked of the engine in one step.
#[test]
fn the_claim_step_asks_every_kind_by_branch() {
    let verify = steps("verify");
    let claim = &verify[step_at(&verify, "receipt status claim")];
    for kind in ["--or bot", "--or carry", "--key branch"] {
        assert!(claim.contains(kind), "the claim step asks {kind}: {claim}");
    }
}

/// THE RECEIPT IS WRITTEN LAST, and only past every gate — so a refused step
/// leaves none. The lap's close immediately precedes it, and the tree is asked
/// clean before anything is decided about the commit (CLOUD-277).
#[test]
fn the_receipt_is_the_last_step_and_follows_the_lap_close() {
    let gated = steps("verify:gated");
    let receipt = step_at(&gated, "receipt record verify");
    assert_eq!(receipt, gated.len() - 1, "{gated:?}");
    assert_eq!(
        step_at(&gated, "target-prune:lap"),
        receipt - 1,
        "the lap closes just before the receipt: {gated:?}"
    );
    assert!(gated[0].contains("tree-clean"), "{gated:?}");
    assert!(
        depends_of("verify:gated")
            .iter()
            .any(|entry| entry == "tree-clean"),
        "and the cheap end stays in `depends` (CLOUD-277)"
    );
}

/// THE OPEN-LAP MARKER reaches every step of `verify` — and through the nested
/// `mise run verify:gated`, everything that task depends on — while the lap's own
/// opener and closer clear it for their call (CLOUD-1913).
#[test]
fn the_open_lap_marker_is_exported_and_the_boundary_clears_it() {
    assert_eq!(env_of("verify", "BATTEN_PRUNE_LAP_OPEN"), "{{config_root}}");
    assert_eq!(env_of("target-prune:lap", "BATTEN_PRUNE_LAP_OPEN"), "");
    assert_eq!(steps("target-prune:lap"), steps("target-prune"));
}

/// THE LAP'S OWN RANGE AND BASE (CLOUD-1702): the speculative base when `land`
/// published one, `origin/main` otherwise — and only for the two gates that read
/// them, so no other step inherits a `BASE_SHA` it never saw before.
#[test]
fn the_commit_range_and_the_trusted_base_are_the_laps_own() {
    let base = "{{ get_env(name='BATTEN_SPEC_BASE', default='origin/main') }}";
    assert_eq!(env_of("verify:commit-lint", "BASE_SHA"), base);
    assert_eq!(env_of("verify:commit-lint", "HEAD_SHA"), "HEAD");
    assert_eq!(env_of("verify:config-lint", "CONFIG_LINT_BASE"), base);
    assert_eq!(
        steps("verify:commit-lint"),
        vec!["mise run commit-lint".to_owned()]
    );
    assert_eq!(
        steps("verify:config-lint"),
        vec!["mise run config-lint".to_owned()]
    );
    assert!(
        task("verify:gated").get("env").is_none(),
        "the gate set itself exports nothing a step did not see before"
    );
}

// ---------------------------------------------------------------------------
// `receipt status --or`, over the compiled binary.
// ---------------------------------------------------------------------------

/// A repository with one commit and an `origin/main` at it — `receipt_verified.rs`'
/// shape, for its reason: a committed config, because a receipt records the
/// policy epoch it was taken under.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = Fixture::at(scratch(name).join("repo"))
        .config("version = 1\n")
        .file("src.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

fn record(dir: &Path, check: &str) {
    let output = batten()
        .args(["receipt", "record", check])
        .current_dir(dir)
        .output()
        .expect("run batten receipt record");
    assert!(
        output.status.success(),
        "recording {check} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn status(dir: &Path, args: &[&str]) -> (i32, String) {
    let output = batten()
        .args(["receipt", "status"])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run batten receipt status");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// A SECOND KIND SATISFIES THE DISJUNCTION, and the output names which one did.
#[test]
fn a_second_kind_satisfies_the_disjunction() {
    let dir = repo("verify-chain-or-second");
    record(&dir, "carry");
    let (code, out) = status(&dir, &["claim", "--or", "bot", "--or", "carry"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("claim ") && out.contains(" missing"), "{out}");
    assert!(out.contains("carry ") && out.contains(" valid"), "{out}");
}

/// NO KIND VALID IS THE VERDICT, and every kind's pointer line is printed — the
/// verdict words are what tell a first claim from a re-claim.
#[test]
fn no_kind_valid_is_the_verdict() {
    let dir = repo("verify-chain-or-none");
    let (code, out) = status(&dir, &["claim", "--or", "bot", "--or", "carry"]);
    assert_eq!(code, 2, "{out}");
    for kind in ["claim ", "bot ", "carry "] {
        assert!(out.contains(kind), "every kind reports its verdict: {out}");
    }
}

/// Mint the branch-keyed claim receipt the way `claim-check` does, against the
/// `origin/main` of the moment: `claim_receipt.rs`' `mint`, for its reason — a
/// receipt with no `base` line is void by design, so omitting it would test a
/// receipt no real claim resembles.
fn mint_claim(dir: &Path, branch: &str) {
    let git_dir = git_in(dir, &["rev-parse", "--absolute-git-dir"]);
    let base = git_in(dir, &["rev-parse", "origin/main"]);
    let receipts = Path::new(git_dir.trim()).join("batten-receipts");
    std::fs::create_dir_all(&receipts).expect("create the receipt store");
    std::fs::write(
        receipts.join(format!("claim.{}", branch.replace('/', "-"))),
        format!("CLOUD-843\nready-lint pass\nbase {}\n", base.trim()),
    )
    .expect("mint the receipt");
}

/// The one line of `out` that reports `check`'s verdict.
fn line_of<'a>(out: &'a str, check: &str) -> &'a str {
    let prefix = format!("{check} ");
    let found: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect();
    assert_eq!(found.len(), 1, "exactly one `{check}` line: {out}");
    found[0]
}

/// THE REFUSAL TELLS A RE-CLAIM APART FROM A FIRST CLAIM, through the very step
/// `verify` runs (`tests/verify.bats`' case of that name). The restart —
/// `checkout -B <name> origin/main` after the claimed work merged — leaves a
/// receipt on disk that describes work which is gone: `claim` must answer
/// `stale-main`, never `missing`, because the two send the reader to different
/// remedies. The kinds that were never minted still answer `missing`, so the two
/// words are told apart in one run rather than across fixtures.
#[test]
fn a_restarted_branch_is_a_re_claim_and_not_a_first_claim() {
    let dir = repo("verify-chain-or-restart");
    let branch = "user/cloud-843-restart";
    git_in(&dir, &["checkout", "-q", "-b", branch]);
    mint_claim(&dir, branch);
    common::write(&dir, "src.rs", "fn main() { /* landed */ }\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "landed work"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&dir, &["checkout", "-q", "-B", branch, "origin/main"]);

    let (code, out) = status(
        &dir,
        &["claim", "--or", "bot", "--or", "carry", "--key", "branch"],
    );
    assert_eq!(code, 2, "the restart is refused: {out}");
    let claim = line_of(&out, "claim");
    assert!(claim.ends_with(" stale-main"), "a re-claim: {claim}");
    assert!(
        !claim.contains("missing"),
        "the receipt EXISTS; `missing` would name the wrong remedy: {claim}"
    );
    for never_minted in ["bot", "carry"] {
        let line = line_of(&out, never_minted);
        assert!(line.ends_with(" missing"), "a first claim: {line}");
    }
}

/// ONE DOCUMENT OR NONE: `--json` answers one receipt, so beside `--or` it is a
/// usage error rather than several documents on one stream.
#[test]
fn json_beside_several_kinds_is_refused_as_usage() {
    let dir = repo("verify-chain-or-json");
    let (code, _) = status(&dir, &["claim", "--or", "bot", "--json"]);
    assert_eq!(code, 1);
}
