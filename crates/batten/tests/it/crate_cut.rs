//! `cut-crate` on a fixture built to break a splicer: a comment and a string
//! spelling the moved path, a path inside a macro's token tree, a use group
//! mixing moved and unmoved modules, a test outside `src/` and a second
//! package naming the moved module. Idempotent on its own output, and refused
//! when the set is not closed downward.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use batten::crate_cut::{Alias, Cut, Plan, cut_crate, respell_aliases, respell_body};

fn tree() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let files = [
        (
            "crates/big/src/lib.rs",
            "//! Big.\n\n/// The leaf.\npub mod a;\npub mod b;\nmod c;\n",
        ),
        (
            "crates/big/src/a.rs",
            "//! A leaf; prose naming crate::b is not an edge.\npub fn x() -> anyhow::Result<u8> {\n    let s = \"crate::b::y\";\n    Ok(crate::a::one(s))\n}\nfn one(s: &str) -> u8 { s.len() as u8 }\n",
        ),
        (
            "crates/big/src/b.rs",
            "use crate::a::x;\npub fn y() -> u8 { assert!(crate::a::x().is_ok()); x().unwrap_or(0) }\nuse crate::{a, c};\n",
        ),
        ("crates/big/src/c.rs", "pub fn z() {}\n"),
        (
            "crates/big/tests/t.rs",
            "#[test]\nfn t() {\n    let _ = big::a::x();\n    let _ = big::b::y();\n}\n",
        ),
        (
            "crates/other/src/lib.rs",
            "pub fn w() -> u8 { big::a::x().unwrap_or(0) }\n",
        ),
    ];
    let manifests = [
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"0.0.1\"\n",
        ),
        (
            "crates/big/Cargo.toml",
            "[package]\nname = \"big\"\nversion.workspace = true\n\n# Why big exists.\n[dependencies]\nanyhow = \"1\"\nserde = \"1\"\n\n[features]\nx = []\n\n[lints]\nworkspace = true\n",
        ),
        (
            "crates/other/Cargo.toml",
            "[package]\nname = \"other\"\nversion.workspace = true\n\n[dependencies]\nbig = { path = \"../big\" }\n",
        ),
    ];
    let own = |rows: &[(&str, &str)]| -> BTreeMap<String, String> {
        rows.iter()
            .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
            .collect()
    };
    (own(&files), own(&manifests))
}

const CUT: Cut<'static> = Cut {
    from: "crates/big",
    name: "small",
    modules: &["a"],
};

/// The plan's output applied: writes land in whichever map holds manifests or
/// sources, removes leave.
fn apply(
    plan: &Plan,
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut files = files.clone();
    let mut manifests = manifests.clone();
    for path in &plan.removes {
        files.remove(path);
    }
    for (path, text) in &plan.writes {
        let into = if path.ends_with("Cargo.toml") {
            &mut manifests
        } else {
            &mut files
        };
        into.insert(path.clone(), text.clone());
    }
    (files, manifests)
}

/// Fails by: a text splice (the comment and the string change), a parsed-path
/// rewrite (the `assert!` argument keeps `crate::a`), a shim left in `big`, a
/// mixed group spliced, or a dependency copied that the moved file never names.
#[test]
fn a_closed_module_set_moves_to_its_own_crate_with_every_path_respelled() {
    let (files, manifests) = tree();
    let plan = cut_crate(&CUT, &files, &manifests);
    assert!(plan.refused.is_empty(), "{:?}", plan.refused);
    assert_eq!(
        plan.removes.iter().collect::<Vec<_>>(),
        ["crates/big/src/a.rs"]
    );
    assert_eq!(
        plan.writes["crates/small/src/a.rs"],
        files["crates/big/src/a.rs"]
    );
    assert!(plan.writes["crates/small/src/lib.rs"].ends_with("\npub mod a;\n"));
    assert_eq!(
        plan.writes["crates/big/src/lib.rs"],
        "//! Big.\n\npub mod b;\nmod c;\n"
    );
    assert_eq!(
        plan.writes["crates/big/src/b.rs"],
        "use small::a::x;\npub fn y() -> u8 { assert!(small::a::x().is_ok()); x().unwrap_or(0) }\nuse crate::{a, c};\n"
    );
    assert_eq!(plan.remainder, ["crates/big/src/b.rs:3"]);
    assert_eq!(
        plan.writes["crates/big/tests/t.rs"],
        "#[test]\nfn t() {\n    let _ = small::a::x();\n    let _ = big::b::y();\n}\n"
    );
    assert_eq!(
        plan.writes["crates/other/src/lib.rs"],
        "pub fn w() -> u8 { small::a::x().unwrap_or(0) }\n"
    );
    let big = &plan.writes["crates/big/Cargo.toml"];
    assert!(
        big.contains("small = { path = \"../small\", version = \"=0.0.1\" }"),
        "{big}"
    );
    assert!(plan.writes["crates/other/Cargo.toml"].contains("small = { path = \"../small\""));
    let small = &plan.writes["crates/small/Cargo.toml"];
    assert!(small.contains("name = \"small\""), "{small}");
    assert!(small.contains("anyhow"), "{small}");
    assert!(
        !small.contains("serde") && !small.contains("[features]"),
        "{small}"
    );
    assert!(!small.contains("Why big exists"), "{small}");
}

/// Fails by: the second run moving or rewriting anything.
#[test]
fn a_cut_run_on_its_own_output_plans_nothing() {
    let (files, manifests) = tree();
    let plan = cut_crate(&CUT, &files, &manifests);
    let (files, manifests) = apply(&plan, &files, &manifests);
    assert_eq!(cut_crate(&CUT, &files, &manifests), Plan::default());
}

/// Fails by: an open set planned, which leaves the new crate depending on the
/// one it was cut from.
#[test]
fn a_set_reaching_an_unmoved_module_is_refused_with_each_site() {
    let (files, manifests) = tree();
    let plan = cut_crate(
        &Cut {
            modules: &["b"],
            ..CUT
        },
        &files,
        &manifests,
    );
    assert_eq!(
        plan.refused,
        [
            "crates/big/src/b.rs:1 crate::a",
            "crates/big/src/b.rs:2 crate::a",
            "crates/big/src/b.rs:3 crate::a",
            "crates/big/src/b.rs:3 crate::c",
        ]
    );
    assert!(plan.writes.is_empty() && plan.removes.is_empty());
}

/// Fails by: a base test body spliced into HEAD in a spelling the cut no
/// longer compiles (CLOUD-2789's replay), or respelled where the cut would
/// not: a comment, a string, a module that stayed.
#[test]
fn a_body_is_respelled_as_the_cut_respells_a_file() {
    let modules = ["git"].into_iter().collect();
    let body = "{\n    // crate::git::run\n    let _ = \"crate::git\";\n    assert_eq!(crate::git::run(), 1);\n    m!(crate::git::run);\n    crate::other::run();\n}";
    assert_eq!(
        respell_body(body, "crate", &modules, "two").as_deref(),
        Some(
            "{\n    // crate::git::run\n    let _ = \"crate::git\";\n    assert_eq!(two::git::run(), 1);\n    m!(two::git::run);\n    crate::other::run();\n}"
        )
    );
    // A use group mixing a moved and a kept module is the cut's remainder.
    assert_eq!(
        respell_body("{ use crate::{git, other}; }", "crate", &modules, "two"),
        None
    );
}

/// Fails by: a path through a root alias left spelled through the root, a
/// crate alias respelled as a module of itself, a comment, a string or an
/// unaliased module rewritten, or a group mixing targets split rather than
/// left as remainder (CLOUD-2800 step 0).
#[test]
fn a_path_through_a_root_alias_names_its_target() {
    let aliases: BTreeMap<&str, Alias<'_>> = [
        ("exit", Alias::Module("base")),
        ("doc", Alias::Module("base")),
        ("fsio", Alias::Crate("fsio_crate")),
        ("error", Alias::Module("facts")),
    ]
    .into_iter()
    .collect();
    let text = "//! crate::exit::ExitCode in prose.\n\
use crate::exit::ExitCode;\n\
use crate::{doc, exit::Code};\n\
use crate::{exit, findings::Finding};\n\
fn f() -> u8 {\n\
    let s = \"crate::exit::x\";\n\
    assert!(crate::fsio::read(s).is_ok());\n\
    crate::findings::one(crate::error::code())\n\
}\n";
    let (edited, left) = respell_aliases(text, "crate", &aliases).unwrap();
    assert_eq!(
        edited,
        "//! crate::exit::ExitCode in prose.\n\
use base::exit::ExitCode;\n\
use base::{doc, exit::Code};\n\
use crate::{exit, findings::Finding};\n\
fn f() -> u8 {\n\
    let s = \"crate::exit::x\";\n\
    assert!(fsio_crate::read(s).is_ok());\n\
    crate::findings::one(facts::error::code())\n\
}\n"
    );
    assert_eq!(left, vec![text.find("crate::{exit, findings").unwrap()]);
    let (again, _) = respell_aliases(&edited, "crate", &aliases).unwrap();
    assert_eq!(again, edited, "a second run rewrites nothing");
}
