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
