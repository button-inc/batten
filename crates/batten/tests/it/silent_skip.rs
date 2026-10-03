//! No case returns before it asserts, unless a `cfg!` decides it.
//!
//! # The rule
//!
//! A missing tool is a failure; a missing subject is a `cfg!` arm. A case that
//! probes for `hk`, `pkl`, `flock` or the host's CA bundle and returns when it
//! finds none PASSES, so the leg that lacks the tool reports coverage it does not
//! have — and nextest cannot tell that pass from a real one. CLOUD-2059 counted
//! the shapes this tree carried: a provisioned tool behind an `Option`, a
//! Linux-only binary behind a runtime probe, a committed config read that
//! returned when the protected set was empty, a shallow clone without `HEAD~1`.
//!
//! The admitted exit is `if cfg!(…) { return; }`, the shape `cfg-gated-test`
//! already sanctions: decided at compile time, and stating the off-platform
//! contract where a reader sees it.
//!
//! # Why `syn`
//!
//! "Is this `return` the case's own, and does a platform guard hold it" is a
//! syntax question (`rules/scanning.md` row two). A return inside a closure
//! leaves the closure, and a guard is an `if` around it, not a line above it.
//! The predicates live in `batten::testing`, where the sweep shows each one red.

use crate::common;

use batten::testing::{SkipCensus, skip_census};

fn census(source: &str) -> SkipCensus {
    skip_census(&syn::parse_file(source).expect("the fixture parses"))
}

#[test]
fn no_case_returns_before_it_asserts() {
    let root = common::at_root("crates/batten");
    let sources = common::rust_sources();
    let (mut cases, mut guarded, mut offenders) = (0, 0, Vec::new());
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("read a crate source");
        let found = skip_census(&syn::parse_file(&source).expect("every crate source parses"));
        cases += found.cases;
        guarded += found.guarded;
        let relative = path.strip_prefix(&root).unwrap_or(path).display();
        offenders.extend(
            found
                .refused
                .iter()
                .map(|case| format!("{relative}: {case} returns before it asserts")),
        );
    }

    // ANTI-VACUITY. Cases are counted in the thousands; a census that stopped
    // matching the attribute walks none. Platform-guarded exits number in the
    // dozens; a census that stopped recognising the guard would refuse them all,
    // and one that stopped seeing a `return` would count none.
    assert!(
        cases > 5_000,
        "walked only {cases} cases across {} sources — the census is not reading \
         the crate it guards",
        sources.len()
    );
    assert!(
        guarded > 20,
        "saw only {guarded} platform-guarded exits — the census no longer \
         recognises a `cfg!` guard or a `return`"
    );
    assert!(
        offenders.is_empty(),
        "a case can pass without asserting; fail on a missing tool, or guard a \
         missing subject with `cfg!`:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn a_bare_return_in_a_case_is_refused() {
    let found = census("#[test] fn case() { if probe().is_none() { return; } assert!(true); }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn a_let_else_return_and_a_valued_return_are_refused() {
    let found = census(
        "#[test] fn first() { let Some(tool) = probe() else { return; }; run(tool); }\n\
         #[test] fn second() -> Result<(), E> { if absent() { return Ok(()); } run() }",
    );
    assert_eq!(found.refused, ["first", "second"]);
}

#[test]
fn a_return_under_a_cfg_guard_is_admitted() {
    let found = census(
        "#[test] fn first() { if !cfg!(unix) { return; } run(); }\n\
         #[test] fn second() { if cfg!(windows) { return; } run(); }",
    );
    assert!(found.refused.is_empty(), "{:?}", found.refused);
    assert_eq!(found.guarded, 2);
}

#[test]
fn a_cfg_guard_does_not_cover_a_sibling_return() {
    let found =
        census("#[test] fn case() { if !cfg!(unix) { return; } if probe().is_none() { return; } }");
    assert_eq!(found.refused, ["case"]);
    assert_eq!(found.guarded, 1);
}

#[test]
fn a_runtime_probe_beside_a_cfg_is_not_a_guard() {
    let found = census("#[test] fn case() { if cfg!(unix) && !has_flock() { return; } }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn a_return_inside_a_closure_or_nested_fn_is_not_the_cases() {
    let found = census(
        "#[test] fn case() { let pick = |x| { if x { return 1; } 2 }; fn inner() { return; } assert_eq!(pick(true), 1); }",
    );
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}

#[test]
fn a_return_in_a_helper_is_not_judged() {
    let found = census("fn helper() { if absent() { return; } }\n#[test] fn case() { helper(); }");
    assert!(found.refused.is_empty(), "{:?}", found.refused);
    assert_eq!(found.cases, 1);
}

#[test]
fn a_case_inside_a_test_module_is_walked() {
    let found = census(
        "#[cfg(test)] mod tests { #[test] fn case() { if absent() { return; } } }\n\
         #[rstest] fn table() { if absent() { return; } }",
    );
    assert_eq!(found.refused, ["case", "table"]);
}
