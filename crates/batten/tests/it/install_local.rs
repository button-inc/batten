//! A provisioned dev container ends up on this clone's own build, and the rows
//! that ask for it are pinned here (CLOUD-1859, CLOUD-2739).
//!
//! `install.sh` resolves `-musl` for every Linux host deliberately — the static
//! binary runs on any Linux whatever its glibc version. That is right for a
//! consumer and wrong for a dev container, because the binary it leaves on PATH
//! is the one every harness hook spawns on every tool call.
//!
//! Measured 2026-09-19, same version, same tree, same box, warm and repeated:
//! `adjudicate` 1444ms against 96ms, `check` over 143 rules 15501ms against
//! 1791ms. `strace -c` on one adjudication: 5779 syscalls against 362, of which
//! 2728 `mmap` and 2718 `munmap` — mallocng returning freed memory to the OS on
//! every free where glibc retains its arenas.
//!
//! WHAT ASKS FOR THE SUPERSESSION IS TWO `[[startup]]` ROWS. A provisioning
//! script used to make the call and these cases read that script; it is gone,
//! and the environment's Setup field runs the installer and then
//! `batten startup --repair`. So the call lives in the committed authority: the
//! rows whose check is the mediator reading and the config reading each repair
//! through the local build.
//!
//! THE SUBJECT IS THE ROW, NOT THE BINARY. A test asserting that the installed
//! `batten` is dynamically linked would pass or fail on whatever the machine
//! running the suite happens to have provisioned, which is a property of the host
//! rather than of this repository. What this tree decides is whether its own
//! authority asks for the supersession, and that is what is asserted.

use crate::common;

/// The repair argv, assembled rather than spelled, because this file is scanned
/// by the same censuses that scan the tree and a literal here is a second site
/// claiming to be the call (`rules/scanning.md`).
fn local_build() -> Vec<String> {
    ["mise", "run", &["install", "local"].join(":")]
        .iter()
        .map(|word| (*word).to_owned())
        .collect()
}

fn argv(row: &toml::Value, key: &str) -> Option<Vec<String>> {
    row.get(key)?
        .as_array()?
        .iter()
        .map(|word| word.as_str().map(str::to_owned))
        .collect()
}

/// The predicate, factored out so the anti-vacuity case below drives the same
/// reading the real ones do rather than a paraphrase of it: some `[[startup]]`
/// row whose `check` is `batten doctor <reading>` repairs through the local build.
fn repairs_through_the_local_build(config: &str, reading: &str) -> bool {
    let Ok(authority) = toml::from_str::<toml::Value>(config) else {
        return false;
    };
    let check = vec!["batten".to_owned(), "doctor".to_owned(), reading.to_owned()];
    authority
        .get("startup")
        .and_then(toml::Value::as_array)
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                argv(row, "check").as_ref() == Some(&check)
                    && argv(row, "repair").as_ref() == Some(&local_build())
            })
        })
}

fn committed_authority() -> String {
    let path = common::at_root("batten.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("batten.toml should be readable at {}: {e}", path.display()))
}

#[test]
fn a_stale_mediator_is_repaired_with_the_local_build() {
    assert!(
        repairs_through_the_local_build(&committed_authority(), "mediator"),
        "the startup row checking the mediator should repair through the local build, or \
         every harness hook in a provisioned container spawns the musl consumer artifact"
    );
}

#[test]
fn an_engine_that_drops_rows_is_repaired_with_the_local_build() {
    assert!(
        repairs_through_the_local_build(&committed_authority(), "config"),
        "the startup row checking the config should repair through the local build, or an \
         engine too old for this config keeps deciding nothing for the rows it dropped"
    );
}

#[test]
fn a_row_with_no_repair_is_refused() {
    // ANTI-VACUITY. Without this, the cases above pass over any config that
    // happens to carry the check, and would keep passing if the predicate were
    // widened to something that cannot fail.
    let without = "[[startup]]\nid = \"mediator-matches-the-tree\"\n\
                   check = [\"batten\", \"doctor\", \"mediator\"]\n";
    assert!(
        !repairs_through_the_local_build(without, "mediator"),
        "a row that never repairs must be refused by the same reading that accepts the \
         committed one"
    );
}
