//! A case's spawn of the binary judges its own fixture, never the checkout
//! holding this build (CLOUD-2059).
//!
//! `common::batten`'s door refuses a spawn whose working directory sits under the
//! build's scratch root with no repository of its own, because `git::repo_root`
//! ignores discovery ceilings by design and such a fixture resolves to the real
//! checkout. The decision is `batten::testing::falls_through`; these cases show
//! the door applies it, in both directions.

use crate::common;

#[test]
#[should_panic(expected = "falls through to the checkout")]
fn a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused() {
    let bare = common::scratch("harness-isolation-bare");
    let _ = common::batten()
        .arg("--version")
        .current_dir(&bare)
        .output();
}

/// The task door refuses the same directory (review of #1089): a task body runs
/// the engine through `PATH` from where it stands, so it falls through exactly as
/// a direct spawn does.
#[test]
#[should_panic(expected = "falls through to the checkout")]
fn a_task_body_whose_cwd_falls_through_to_the_checkout_is_refused() {
    let bare = common::scratch("harness-isolation-task-bare");
    let _ = common::task_bash(&bare, "true");
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
    let attempt = std::panic::catch_unwind(|| {
        let _ = common::batten().arg("init").current_dir(&bare).output();
    });
    assert!(attempt.is_err(), "the door refused the spawn");
    assert!(
        !bare.join("batten.toml").exists(),
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
