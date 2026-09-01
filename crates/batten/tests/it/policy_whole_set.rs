//! Whole-set analysis over a composed rule set (CLOUD-647): shadowing,
//! contradiction and cycles, with the sweep PROVEN to have reached every module.
//!
//! Batten's stability depends on properties of the rule *set* and nothing
//! decided any of them. Row order decides a mediated call and nothing says so;
//! cross-row validation was one check wide. At 33 committed rows that was still
//! tractable by reading, and "read it carefully" is not a gate — non-negotiable
//! rule 3 makes a model verdict inadmissible, so the alternative to a decidable
//! mechanism is nothing.
//!
//! # The caveat that is the whole engineering problem
//!
//! Regorus refuses a conflict and a recursion at **evaluation**, never at
//! `add_policy`. So a conflict on a path no query exercises is silently
//! unreported, and "load the policies and get a verdict" is not what the engine
//! offers. The sweep has to be driven, AND it has to prove it reached every
//! rule — `a_module_the_sweep_never_entered_is_reported` is that proof, and
//! without it every other case here passes on an analysis that ran over nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::facts::Look;
use batten::policy;

fn module(name: &str, body: &str) -> (String, String) {
    (format!("{name}.rego"), body.to_owned())
}

/// (c) The committed shape: a healthy set sweeps clean, and every module in it
/// is reached.
#[test]
fn a_healthy_set_sweeps_clean_and_reaches_every_module() {
    let bundle = policy::compile(
        "healthy",
        &[
            module(
                "a",
                "package batten.a\nimport rego.v1\nrules contains \"a\"\nviolation contains {\"rule\": \"a\", \"msg\": \"m\"} if { input.call.operation == \"write\" }\n",
            ),
            module(
                "b",
                "package batten.b\nimport rego.v1\nrules contains \"b\"\nviolation contains {\"rule\": \"b\", \"msg\": \"m\"} if { input.call.operation == \"read\" }\n",
            ),
        ],
        &serde_json::json!({}),
    )
    .expect("a healthy set compiles");

    let Look::Is(analysis) = policy::analyse(&bundle).expect("a healthy set resolves") else {
        panic!("the sweep ran");
    };
    assert!(
        analysis.unswept.is_empty(),
        "every module was entered: {:?}",
        analysis.unswept
    );
    assert_eq!(
        analysis.swept.len(),
        2,
        "and BOTH were — an analysis that reached one module and called the set \
         healthy is the false green this row exists to kill"
    );
}

/// **The anti-vacuity term (CLOUD-647 §2's coverage half).**
///
/// A module the sweep never entered contributes nothing, so every conflict and
/// cycle inside it goes unreported and the run is green. Without this case the
/// two below pass on an analysis that ran over nothing at all.
///
/// The discriminator is a module in a package the sweep's query does not reach:
/// `PACKAGE_QUERY` is rooted at `data.batten`, so a module declaring some other
/// top-level package compiles into the same engine and is never evaluated. That
/// is exactly the dark corner the coverage read exists to find.
#[test]
fn a_module_the_sweep_never_entered_is_reported() {
    let bundle = policy::compile(
        "partly-dark",
        &[
            module(
                "reached",
                "package batten.reached\nimport rego.v1\nrules contains \"reached\"\n",
            ),
            module(
                "dark",
                "package elsewhere\nimport rego.v1\nnever_reached contains \"x\" if { true }\n",
            ),
        ],
        &serde_json::json!({}),
    )
    .expect("both compile — being unreachable is not a compile error");

    let Look::Is(analysis) = policy::analyse(&bundle).expect("the set resolves") else {
        panic!("the sweep ran");
    };
    assert_eq!(
        analysis.unswept.len(),
        1,
        "the module outside the queried package was never entered: swept={:?} \
         unswept={:?}",
        analysis.swept,
        analysis.unswept
    );
    assert!(
        analysis.unswept[0].contains("dark"),
        "and it is named: {:?}",
        analysis.unswept
    );
}

/// (b) Two complete rules with the same name and different values do not
/// resolve, and the sweep says so.
///
/// Refused HERE rather than at the gate: left alone, the first thing to discover
/// this would be a denied tool call — the worst possible moment and the wrong
/// exit class.
#[test]
fn two_contradicting_complete_rules_are_refused_by_the_sweep() {
    let bundle = policy::compile(
        "contradiction",
        &[
            module("one", "package batten.c\nimport rego.v1\nverdict := 1\n"),
            module("two", "package batten.c\nimport rego.v1\nverdict := 2\n"),
        ],
        &serde_json::json!({}),
    );
    // The conflict may be caught by `compile`'s own smoke query — which is the
    // correct earliest place — or by the driven sweep. Either is a refusal at
    // load rather than at the gate, which is the property; asserting WHICH would
    // pin an implementation detail of where the same query runs.
    match bundle {
        Err(refused) => {
            let text = format!("{refused}");
            assert!(
                text.contains("conflict") || text.contains("faults when evaluated"),
                "the refusal says the set does not resolve: {text}"
            );
        }
        Ok(bundle) => {
            let err = policy::analyse(&bundle).expect_err("a contradicting set does not resolve");
            assert!(format!("{err}").contains("does not resolve as a set"));
        }
    }
}

/// (a)'s Rego form: a cycle does not resolve.
///
/// `add_policy` ACCEPTS this — regorus reports recursion when a query reaches it
/// — so a set-level sweep is the only thing that can find it, and a sweep that
/// did not reach the rule would not.
#[test]
fn a_cyclic_set_is_refused_by_the_sweep() {
    let bundle = policy::compile(
        "cycle",
        &[
            module(
                "a",
                "package batten.cyc\nimport rego.v1\nleft contains x if { right[x] }\n",
            ),
            module(
                "b",
                "package batten.cyc\nimport rego.v1\nright contains x if { left[x] }\n",
            ),
        ],
        &serde_json::json!({}),
    );
    match bundle {
        Err(refused) => {
            let text = format!("{refused}");
            assert!(
                text.contains("recursion") || text.contains("faults when evaluated"),
                "the refusal names the cycle: {text}"
            );
        }
        Ok(bundle) => {
            let err = policy::analyse(&bundle).expect_err("a cyclic set does not resolve");
            assert!(format!("{err}").contains("does not resolve as a set"));
        }
    }
}

/// Non-negotiable rule 4, and this is where it takes real care.
///
/// `regorus::coverage::File` carries a `code` field holding the policy body, and
/// `Report::to_string_pretty` renders the whole of it. A coverage report is the
/// most payload-shaped thing this crate touches, so the analysis must carry line
/// counts and paths and nothing else.
#[test]
fn the_analysis_carries_no_byte_of_any_policy_body() {
    const DISTINCTIVE: &str = "a-string-only-the-body-contains";
    let bundle = policy::compile(
        "pointer-only",
        &[module(
            "a",
            &format!(
                "package batten.p\nimport rego.v1\nrules contains \"p\"\nviolation contains {{\"rule\": \"p\", \"msg\": \"{DISTINCTIVE}\"}} if {{ input.call.operation == \"write\" }}\n"
            ),
        )],
        &serde_json::json!({}),
    )
    .expect("compiles");

    let Look::Is(analysis) = policy::analyse(&bundle).expect("resolves") else {
        panic!("the sweep ran");
    };
    let rendered = format!("{analysis:?}");
    assert!(
        !rendered.contains(DISTINCTIVE),
        "no byte of the module reaches the analysis: {rendered}"
    );
    assert!(
        !rendered.contains("package batten"),
        "not even its package line: {rendered}"
    );
}
