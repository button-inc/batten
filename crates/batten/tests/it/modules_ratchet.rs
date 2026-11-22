//! `batten modules metrics` and `batten modules ratchet` (CLOUD-2821): every
//! module-graph metric of a source root is held to a committed record, which
//! only ever tightens.
//!
//! The fixture holds a three-module cycle (`a → b → c → a`) and `d → a`, so the
//! largest component is 3 and five nodes (`lib` among them) reach 14 of 25
//! pairs: propagation 56.00 %, 5600 basis points.

use crate::common;
use std::path::{Path, PathBuf};
use std::process::Output;

const MEASURED: &str = "src cycle=3 propagation=5600 impls=0 shims=0";

fn fixture(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("modules-ratchet-{name}"));
    common::init_repo(&dir);
    common::write(&dir, "src/lib.rs", "mod a;\nmod b;\nmod c;\nmod d;\n");
    common::write(&dir, "src/a.rs", "pub fn f() { crate::b::f(); }\n");
    common::write(&dir, "src/b.rs", "pub fn f() { crate::c::f(); }\n");
    common::write(&dir, "src/c.rs", "pub fn f() { crate::a::f(); }\n");
    common::write(&dir, "src/d.rs", "pub fn f() { crate::a::f(); }\n");
    dir
}

fn batten(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .current_dir(dir)
        .env_remove("CI")
        .env_remove("BATTEN_TASK_PID")
        .streamed_output()
        .expect("run batten")
}

fn ratchet(dir: &Path, extra: &[&str]) -> Output {
    let record = dir.join("modules.lock");
    let mut args = vec![
        "modules",
        "ratchet",
        "--record",
        record.to_str().expect("utf-8 path"),
    ];
    args.extend_from_slice(extra);
    batten(dir, &args)
}

fn record(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("modules.lock")).expect("read the record")
}

/// Fails by: a percentage printed instead of basis points, a rounding that
/// differs from the record's, or a field order that is not byte-stable.
#[test]
fn propagation_cost_is_compared_in_basis_points() {
    let dir = fixture("basis-points");
    let out = batten(&dir, &["modules", "metrics", "--root", "src"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(common::stdout(&out).trim(), MEASURED);

    // One basis point under the measurement is a worse score, refused.
    common::write(
        &dir,
        "modules.lock",
        "src cycle=3 propagation=5599 impls=0 shims=0\n",
    );
    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("src propagation 5600 is worse than the recorded 5599"),
        "{}",
        common::stderr(&out)
    );
}

/// Fails by: a grown cycle passing, the refusal not naming the metric, or the
/// refused run rewriting the record to the worse value.
#[test]
fn a_worse_cycle_is_refused() {
    let dir = fixture("worse");
    common::write(&dir, "modules.lock", &format!("{MEASURED}\n"));
    assert_eq!(ratchet(&dir, &[]).status.code(), Some(0));

    // `d` joins the cycle: four modules now.
    common::write(
        &dir,
        "src/a.rs",
        "pub fn f() { crate::b::f(); crate::d::f(); }\n",
    );
    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("src cycle 4 is worse than the recorded 3"),
        "{}",
        common::stderr(&out)
    );
    assert_eq!(
        record(&dir),
        format!("{MEASURED}\n"),
        "a refusal writes nothing"
    );
}

/// Fails by: an inherent impl split from its type, or a re-export of the
/// crate's own item outside its root, passing a record taken at
/// `impls=0 shims=0` (CLOUD-2792), or the refusal not naming the count. Each
/// addition reuses an edge the cycle already has (`b → a` through `c`, and
/// `c → a`), so the graph's cycle and propagation do not move and only the
/// impl or shim count can refuse.
#[test]
fn a_new_split_impl_or_shim_is_refused() {
    let dir = fixture("split");
    common::write(&dir, "modules.lock", &format!("{MEASURED}\n"));
    common::write(
        &dir,
        "src/a.rs",
        "pub struct S;\npub fn f() { crate::b::f(); }\n",
    );
    assert_eq!(ratchet(&dir, &[]).status.code(), Some(0));

    // `S` is declared in `a`; its inherent impl lands in `b`.
    common::write(
        &dir,
        "src/b.rs",
        "pub fn f() { crate::c::f(); }\nimpl crate::a::S { pub fn g(&self) {} }\n",
    );
    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("src impls 1 is worse than the recorded 0"),
        "{}",
        common::stderr(&out)
    );

    // Back home; now `c` re-exports `a`'s item outside the crate root.
    common::write(&dir, "src/b.rs", "pub fn f() { crate::c::f(); }\n");
    common::write(
        &dir,
        "src/c.rs",
        "pub use crate::a::f as g;\npub fn f() { crate::a::f(); }\n",
    );
    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("src shims 1 is worse than the recorded 0"),
        "{}",
        common::stderr(&out)
    );
    assert_eq!(
        record(&dir),
        format!("{MEASURED}\n"),
        "a refusal writes nothing"
    );
}

/// Fails by: an improvement left unrecorded (so the next commit could spend
/// it), `--check` writing, or `--check` passing a stale record.
#[test]
fn a_better_score_tightens_the_record() {
    let dir = fixture("better");
    common::write(&dir, "modules.lock", &format!("# kept\n{MEASURED}\n"));

    // `c` stops naming `a`: the cycle is gone.
    common::write(&dir, "src/c.rs", "pub fn f() {}\n");
    let out = ratchet(&dir, &["--check"]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("scores better than"),
        "{}",
        common::stderr(&out)
    );
    assert_eq!(
        record(&dir),
        format!("# kept\n{MEASURED}\n"),
        "--check writes nothing"
    );

    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    let tightened = record(&dir);
    assert!(tightened.starts_with("# kept\nsrc cycle=1 "), "{tightened}");
    assert_eq!(ratchet(&dir, &["--check"]).status.code(), Some(0));
}

/// Fails by: a mangled record read as no bound.
#[test]
fn a_record_that_does_not_parse_is_could_not_look() {
    let dir = fixture("mangled");
    common::write(&dir, "modules.lock", "src cycle=3 propagation=lots\n");
    let out = ratchet(&dir, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", common::stderr(&out));
}
