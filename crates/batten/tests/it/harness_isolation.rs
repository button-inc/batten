//! A case's spawn of the binary judges its own fixture, never the checkout
//! holding this build (CLOUD-2059).
//!
//! `common::batten`'s door refuses a spawn whose working directory sits under the
//! build's scratch root with no repository of its own, because `git::repo_root`
//! ignores discovery ceilings by design and such a fixture resolves to the real
//! checkout. The decision is `batten::testing::falls_through`; these cases show
//! the door applies it, in both directions.

use std::path::Path;

use crate::common;

/// Whether a bare scratch directory falls through on THIS build's layout. It
/// does wherever the target directory sits inside a checkout — this repository's
/// own, and CI's — and does not where `CARGO_TARGET_DIR` is outside every
/// worktree, which the guard rightly leaves alone (review of #1089). Each door
/// case asserts the refusal EXACTLY when this holds, so neither layout reads red
/// for the wrong reason.
///
/// AN ORACLE OF ITS OWN, read straight off the resolver the binary uses, and
/// never `batten::testing::falls_through`: that function is what the mutants
/// change, and an expectation computed by it would move with the mutation and
/// pass every one of them.
fn falls_through(dir: &Path) -> bool {
    // The resolver's own spelling, never a bare `canonicalize`: on Windows that
    // answers verbatim and no plain root starts with it (CLOUD-2059).
    let scratch = batten::git::canonical(&common::target_tmp());
    batten::git::worktree_root(dir).is_ok_and(|owner| !owner.starts_with(&scratch))
}

/// The binary's door refuses a spawn in a bare scratch directory exactly when it
/// falls through.
#[test]
fn a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused() {
    let bare = common::scratch("harness-isolation-bare");
    let refused = std::panic::catch_unwind(|| {
        let _ = common::batten()
            .arg("--version")
            .current_dir(&bare)
            .output();
    })
    .is_err();
    assert_eq!(
        refused,
        falls_through(&bare),
        "the binary's door refuses exactly a directory that falls through"
    );
}

/// The task door refuses the same directory, and reads it WHEN THE BODY SPAWNS,
/// not when the command was built (review of #1089). A caller that builds in its
/// own repository and then moves the command somewhere that falls through is
/// refused before the body runs.
#[test]
fn a_task_body_redirected_to_a_fall_through_is_refused_before_it_runs() {
    let owned = common::scratch("harness-isolation-task-owned");
    common::init_repo(&owned);
    let bare = common::scratch("harness-isolation-task-bare");
    let refused = std::panic::catch_unwind(|| {
        let mut task = common::task_bash(&owned, "touch ran");
        task.current_dir(&bare);
        let _ = task.output();
    })
    .is_err();
    let falls = falls_through(&bare);
    assert_eq!(
        refused, falls,
        "the task door refuses exactly a directory that falls through"
    );
    assert!(
        !falls || !bare.join("ran").exists(),
        "and refuses it before the body runs"
    );
}

/// The piped door refuses before the child runs too (review of #1089).
/// `run_with_stdin` hands its command to a helper that spawns it as a plain
/// `Command`, below the wrapper's own checks, so without its own check the child
/// ran and only the drop check objected afterwards. `init` writes `batten.toml`,
/// so a child that ran leaves one.
#[test]
fn a_piped_spawn_into_a_fall_through_is_refused_before_it_runs() {
    let bare = common::scratch("harness-isolation-piped");
    let falls = falls_through(&bare);
    let refused = std::panic::catch_unwind(|| {
        let _ = common::run_with_stdin(&bare, &["init"], "");
    })
    .is_err();
    assert_eq!(
        refused, falls,
        "the piped door refuses exactly a directory that falls through"
    );
    assert!(
        !falls || !bare.join("batten.toml").exists(),
        "and refuses it before the child runs"
    );
}

/// The case's OWN library calls resolve the root its children are pinned to, so
/// an admission issued in-process, a lap verified in-process, or a decision
/// appended in-process lands in the case's store and not the developer's — the
/// 22 segments one full run still wrote after every spawn door was pinned.
#[test]
fn in_process_state_resolves_to_the_cases_own_root() {
    let _ = common::scratch("harness-isolation-in-process");
    assert_eq!(
        batten::state::data_dir().expect("a data directory"),
        common::scratch_state_root(),
        "a fixture contains the process, so the library resolves the case's root"
    );
}

/// The child's home is the case's own on every platform, so nothing in the
/// developer's `~/.claude`, `~/.gitconfig` or global mise config reaches a verdict
/// a CI runner, which has none of them, would not reproduce.
#[test]
fn every_spawn_of_the_binary_pins_the_home() {
    let homes = common::homes(&common::batten());
    assert_eq!(
        homes.len(),
        2,
        "the home must be pinned on every platform: {homes:?}"
    );
    for (name, value) in &homes {
        assert_eq!(
            value.as_path(),
            common::scratch_home(),
            "{name} must point at the case's own home, never the developer's"
        );
    }
}

/// REFUSED BEFORE THE CHILD EXISTS, not reported after it ran: the point is that
/// a falling-through fixture never touches the checkout. `init` writes
/// `batten.toml` into its working directory, so a child that ran leaves one.
#[test]
fn a_fall_through_is_refused_before_the_child_runs() {
    let bare = common::scratch("harness-isolation-before");
    let falls = falls_through(&bare);
    let attempt = std::panic::catch_unwind(|| {
        let _ = common::batten().arg("init").current_dir(&bare).output();
    });
    assert_eq!(attempt.is_err(), falls, "the door refused the spawn");
    assert!(
        !falls || !bare.join("batten.toml").exists(),
        "and refused it before the child ran"
    );
}

/// THE ANTI-VACUITY ARM: a door that refused every spawn would satisfy the case
/// above. A fixture that IS a repository runs, and so does a spawn at the real
/// root, which the committed-configuration suites make on purpose.
#[test]
fn a_spawn_in_its_own_repository_or_at_the_real_root_runs() {
    let owned = common::scratch("harness-isolation-owned");
    common::init_repo(&owned);
    for dir in [owned, common::at_root("")] {
        let output = common::batten()
            .arg("--version")
            .current_dir(&dir)
            .output()
            .expect("run batten");
        assert!(output.status.success(), "{}", common::stderr(&output));
    }
}
