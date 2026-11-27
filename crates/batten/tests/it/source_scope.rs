//! Every crate-scoped `batten.toml` row reads every crate (CLOUD-2789).
//!
//! The crate split moved modules out of `crates/batten` into six packages. A
//! row whose source glob still names `crates/batten/src` — or a brace list of
//! the packages that existed when it was written — reads the moved code as
//! absent, and a row that reads nothing refuses nothing: the split becomes a way
//! out of the gate. The predicate is the committed glob itself, because a green
//! run of the row cannot tell a full read from a narrow one.

use crate::common;
use std::collections::BTreeSet;

/// The columns a row reads source paths through.
const SOURCE_KEYS: &[&str] = &[
    "glob",
    "line_sources",
    "delta_sources",
    "invocation_sources",
    "use_sources",
];

/// The committed config, parsed.
fn committed() -> toml::Table {
    std::fs::read_to_string(common::at_root("batten.toml"))
        .expect("batten.toml")
        .parse()
        .expect("batten.toml parses")
}

/// The one `[[rule]]` row named `id`.
fn rule<'a>(config: &'a toml::Table, id: &str) -> &'a toml::Table {
    let rows: Vec<&toml::Table> = config
        .get("rule")
        .and_then(toml::Value::as_array)
        .expect("batten.toml declares [[rule]] rows")
        .iter()
        .filter_map(toml::Value::as_table)
        .filter(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one [[rule]] row is {id:?}");
    rows[0]
}

/// Every glob one column of a row reads: a `glob` string or a `*_sources` list.
fn column(row: &toml::Table, key: &str) -> Vec<String> {
    match row.get(key) {
        Some(toml::Value::String(glob)) => vec![glob.clone()],
        Some(toml::Value::Array(list)) => list
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Every glob a row reads, across [`SOURCE_KEYS`].
fn globs(row: &toml::Table) -> BTreeSet<String> {
    SOURCE_KEYS
        .iter()
        .flat_map(|key| column(row, key))
        .collect()
}

/// The committed `[[rule]]` row `id`'s `key` column, so a suite builds its
/// fixture row from the globs `batten.toml` declares rather than from a copy
/// that stops tracking them the commit a row widens (CLOUD-2789: two suites
/// still hard-coded `crates/batten/src` after the rows read every crate).
pub(crate) fn committed_rule_sources(id: &str, key: &str) -> Vec<String> {
    let sources = column(rule(&committed(), id), key);
    assert!(!sources.is_empty(), "{id:?} declares no {key}");
    sources
}

/// Every workspace member's directory name under `crates/`, read from the tree.
fn members() -> BTreeSet<String> {
    std::fs::read_dir(common::at_root("crates"))
        .expect("the workspace's crates directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

/// The crate names a `crates/{a,b,…}/src/**/*.rs` glob lists.
fn brace_list(glob: &str) -> BTreeSet<String> {
    let inner = glob
        .strip_prefix("crates/{")
        .and_then(|rest| rest.strip_suffix("}/src/**/*.rs"))
        .unwrap_or_else(|| panic!("{glob:?} is not a crates/{{…}}/src/**/*.rs list"));
    inner.split(',').map(str::to_owned).collect()
}

/// A row's `.rs` globs under `crates/` that name one crate rather than every
/// one. A non-Rust entry (the preset tree's `.rego`) is not a crate scope.
fn single_crate_rust(read: &BTreeSet<String>) -> Vec<&String> {
    read.iter()
        .filter(|glob| {
            std::path::Path::new(glob.as_str()).extension() == Some(std::ffi::OsStr::new("rs"))
                && glob.starts_with("crates/")
        })
        .filter(|glob| !glob.starts_with("crates/*/"))
        .collect()
}

#[test]
fn every_crate_scoped_row_reads_every_crate() {
    let config = committed();
    let members = members();
    assert!(
        members.len() > 1,
        "the census found {} member(s), too few to be the split workspace",
        members.len()
    );
    let scoped = [
        ("waiver add refused", "crates/*/src/**/*.rs"),
        ("path write unsafe", "crates/*/src/**/*.rs"),
        ("test name undefined", "crates/*/src/**/*.rs"),
        ("test name undefined", "crates/*/{tests,examples}/**/*.rs"),
        ("marker name undefined", "crates/*/{tests,examples}/**/*.rs"),
        ("review state other", "crates/*/src/**/*.rs"),
        ("patch judge wrong", "crates/*/src/**/*.rs"),
        ("spawn add other", "crates/*/src/**/*.rs"),
        // ONE LEVEL on purpose: the module names a file by its stem.
        ("layer place wrong", "crates/*/src/*.rs"),
    ];
    for (id, expected) in scoped {
        let read = globs(rule(&config, id));
        assert!(
            read.contains(expected),
            "{id:?} does not read {expected}: {read:?}"
        );
        assert_eq!(
            single_crate_rust(&read),
            Vec::<&String>::new(),
            "{id:?} still reads Rust through a one-crate glob"
        );
    }
    // The fsio ratchets EXEMPT the crate that implements the reads, and only
    // it: a brace list is a census of the other members, so a new member is a
    // row edit, never a silent hole.
    let mut expected = members.clone();
    expected.remove("batten-fsio");
    for id in ["path read loose", "source read loose"] {
        let read = globs(rule(&config, id));
        assert_eq!(read.len(), 1, "{id:?} reads one glob: {read:?}");
        let listed = brace_list(read.first().expect("one glob"));
        assert_eq!(
            listed, expected,
            "{id:?} lists a crate set other than every member but batten-fsio"
        );
    }
}
