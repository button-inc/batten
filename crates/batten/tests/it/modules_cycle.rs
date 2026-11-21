//! `batten modules cycle` (CLOUD-2789): the size of the largest cycle in a
//! crate's module graph, over the compiled binary and a fixture source tree.
//!
//! The fixture holds a three-module cycle (`a → b → c → a`) and a module
//! outside it, so the count is 3 and only the `--max` comparison decides the
//! exit.

use crate::common;
use std::path::PathBuf;
use std::process::Output;

/// A source root with a three-module cycle and one module outside it.
fn fixture(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("modules-cycle-{name}"));
    common::init_repo(&dir);
    common::write(&dir, "src/lib.rs", "mod a;\nmod b;\nmod c;\nmod d;\n");
    common::write(&dir, "src/a.rs", "pub fn f() { crate::b::f(); }\n");
    common::write(&dir, "src/b.rs", "pub fn f() { crate::c::f(); }\n");
    common::write(&dir, "src/c.rs", "pub fn f() { crate::a::f(); }\n");
    common::write(&dir, "src/d.rs", "pub fn f() { crate::a::f(); }\n");
    dir
}

fn run(dir: &std::path::Path, extra: &[&str]) -> Output {
    let root = dir.join("src");
    let mut args = vec![
        "modules",
        "cycle",
        "--root",
        root.to_str().expect("utf-8 path"),
    ];
    args.extend_from_slice(extra);
    common::batten()
        .args(&args)
        .current_dir(dir)
        .env_remove("CI")
        .env_remove("BATTEN_TASK_PID")
        .streamed_output()
        .expect("run batten")
}

/// Fails by: the count wrong, the members printed instead of a count, or a
/// pass at the exact bound read as a refusal.
#[test]
fn the_largest_cycle_is_counted_and_passes_at_its_bound() {
    let dir = fixture("at-bound");
    let out = run(&dir, &["--max", "3"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(
        common::stdout(&out).trim(),
        "modules cycle: 3 module(s) in the largest component"
    );
}

/// Fails by: a count above the bound passing, or the refusal at a usage code.
#[test]
fn a_cycle_above_its_bound_is_refused() {
    let dir = fixture("above-bound");
    let out = run(&dir, &["--max", "2"]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("3 is more than the committed 2"),
        "{}",
        common::stderr(&out)
    );
}

/// Fails by: a malformed bound read as no bound.
#[test]
fn a_bound_that_is_not_a_number_is_a_usage_error() {
    let dir = fixture("bad-bound");
    let out = run(&dir, &["--max", "many"]);
    assert_eq!(out.status.code(), Some(1), "{}", common::stderr(&out));
}

/// Fails by: an unparseable file read as an empty one, which would undercount.
#[test]
fn a_file_that_does_not_parse_is_could_not_look() {
    let dir = fixture("unparseable");
    common::write(&dir, "src/d.rs", "pub fn f( {\n");
    let out = run(&dir, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", common::stderr(&out));
}

/// A crate with one impl away from its type and one re-export shim
/// (CLOUD-2792): `T` is declared in `a`, implemented in `b`, and re-exported
/// from `b` under an alias.
fn split_fixture(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("modules-split-{name}"));
    common::init_repo(&dir);
    common::write(&dir, "src/lib.rs", "mod a;\nmod b;\n");
    common::write(&dir, "src/a.rs", "pub struct T;\n");
    common::write(
        &dir,
        "src/b.rs",
        "pub use crate::a::T as Alias;\nimpl crate::a::T { pub fn f() {} }\n",
    );
    dir
}

fn run_verb(dir: &std::path::Path, verb: &str, extra: &[&str]) -> Output {
    let root = dir.join("src");
    let mut args = vec![
        "modules",
        verb,
        "--root",
        root.to_str().expect("utf-8 path"),
    ];
    args.extend_from_slice(extra);
    common::batten()
        .args(&args)
        .current_dir(dir)
        .env_remove("CI")
        .env_remove("BATTEN_TASK_PID")
        .streamed_output()
        .expect("run batten")
}

/// Fails by: the impl census miscounting, printing the members, or not
/// refusing above its bound.
#[test]
fn the_impl_census_prints_its_count_and_holds_its_bound() {
    let dir = split_fixture("impls");
    let at = run_verb(&dir, "impls", &["--max", "1"]);
    assert_eq!(at.status.code(), Some(0), "{}", common::stderr(&at));
    assert_eq!(
        common::stdout(&at).trim(),
        "modules impls: 1 outside their type's module, 0 ambiguous"
    );
    let over = run_verb(&dir, "impls", &["--max", "0"]);
    assert_eq!(over.status.code(), Some(2), "{}", common::stderr(&over));
    let bad = run_verb(&dir, "impls", &["--max", "many"]);
    assert_eq!(bad.status.code(), Some(1), "{}", common::stderr(&bad));
}

/// Fails by: the shim census miscounting a leaf or its alias, or not refusing
/// above its bound.
#[test]
fn the_shim_census_prints_its_count_and_holds_its_bound() {
    let dir = split_fixture("shims");
    let at = run_verb(&dir, "shims", &["--max", "1"]);
    assert_eq!(at.status.code(), Some(0), "{}", common::stderr(&at));
    assert_eq!(
        common::stdout(&at).trim(),
        "modules shims: 1 re-export(s), 1 aliased"
    );
    let over = run_verb(&dir, "shims", &["--max", "0"]);
    assert_eq!(over.status.code(), Some(2), "{}", common::stderr(&over));
    let bad = run_verb(&dir, "shims", &["--max", "many"]);
    assert_eq!(bad.status.code(), Some(1), "{}", common::stderr(&bad));
}
