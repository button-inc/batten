//! The engine a session runs is the pinned release, never this clone's build,
//! unless the tree pins a source (CLOUD-2840, which retired `setup.sh` under
//! CLOUD-2739).
//!
//! `setup.sh` superseded the downloaded musl artifact with `mise run
//! install:local`: a cold `cargo build --release` (224.87 s measured) on every
//! fresh container, to escape musl's allocator (1444 ms against 96 ms per
//! adjudication, CLOUD-1859). Both halves now belong to the release path. The
//! bootstrap ends by running `batten engine install`, which fetches the gnu build
//! wherever a gnu binary runs (`engine::gnu_twin`), and CI runs the
//! released engine too, so a session that compiled its own would be judged by
//! an engine nothing else uses.
//!
//! THE SUBJECT IS THE DECLARATION. Which binary a given host ends up with is a
//! property of that host; what this tree decides is which command its two engine
//! rows repair with, and that is what is asserted.

use crate::common;

/// The two `[[startup]]` rows that repair the engine.
const ENGINE_ROWS: [&str; 2] = ["mediator-matches-the-tree", "engine-resolves-every-row"];

/// The pinned-release install, as a row's `repair` spells it.
const RELEASE_INSTALL: [&str; 3] = ["batten", "engine", "install"];

/// The local build, assembled rather than spelled: this file is scanned by the
/// same censuses that scan the tree, and a literal here would be a second site
/// claiming to be the call (`rules/scanning.md`).
fn local_build() -> String {
    ["install", ":local"].concat()
}

/// The committed `[[startup]]` rows.
fn startup_rows() -> Vec<toml::Value> {
    let text =
        std::fs::read_to_string(common::at_root("batten.toml")).expect("the committed authority");
    let table: toml::Table = text.parse().expect("the committed authority parses");
    table["startup"]
        .as_array()
        .expect("[[startup]] rows are declared")
        .clone()
}

/// A row's `repair` argv, or empty where it declares none.
fn repair_of(row: &toml::Value) -> Vec<String> {
    row.get("repair")
        .and_then(toml::Value::as_array)
        .map(|argv| {
            argv.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Fails by: an engine row repairing with anything but the pinned release —
/// the compile this file's header measured, back on every container.
#[test]
fn both_engine_rows_repair_with_the_pinned_release() {
    let rows = startup_rows();
    for id in ENGINE_ROWS {
        let row = rows
            .iter()
            .find(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
            .unwrap_or_else(|| panic!("`{id}` is a committed [[startup]] row"));
        assert_eq!(
            repair_of(row),
            RELEASE_INSTALL,
            "`{id}` repairs with the pinned release"
        );
    }
}

/// Fails by: any `[[startup]]` row compiling the engine. A source pin is the one
/// case a local build is right, and that is `batten engine install`'s own branch
/// to take (`mise exec -- batten engine install` builds a source pin), never a
/// row's.
#[test]
fn no_startup_row_builds_the_engine_locally() {
    for row in startup_rows() {
        let repair = repair_of(&row).join(" ");
        assert!(
            !repair.contains(&local_build()),
            "{:?} repairs with a local build: {repair}",
            row.get("id")
        );
    }
}

/// ANTI-VACUITY: the reading above refuses the repair it was written against,
/// so a predicate widened until it cannot fail is caught here.
#[test]
fn a_row_that_builds_locally_is_refused() {
    let row: toml::Value = toml::from_str(&format!(
        "id = \"x\"\nrepair = [\"mise\", \"run\", \"{}\"]\n",
        local_build()
    ))
    .expect("a row parses");
    assert!(repair_of(&row).join(" ").contains(&local_build()));
    assert_ne!(repair_of(&row), RELEASE_INSTALL);
}
