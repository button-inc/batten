//! CLOUD-763's bounds, each as a check with an exit code rather than a stated
//! intention.
//!
//! The verdict this file encodes: the axis `scopes` pairs on is **ambient
//! authority**, never "consumer-authored". A `command` row is excluded from the
//! mediated call because the process it starts can read any file, spawn anything
//! and reach the network — not because a consumer wrote the line that starts it.
//! A pure evaluator over supplied facts is admitted, because its authority is
//! exactly what the boundary handed it and the fact set is enumerable.
//!
//! The verdict came with four bounds, and the issue is explicit that they are
//! the condition on it rather than a wish list. The cross-product pin and the
//! first bound live beside the classification in `rules.rs`; the three that
//! reach outside the type live here.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::PathBuf;

use batten::facts::{Format, Look, Node};
use common::{Fixture, at_root, stderr};

/// Crates that would put ambient authority in the shipped binary's closure.
///
/// `jsonschema` is CLOUD-647's own constraint, and it is in the tree — as a
/// **dev**-dependency, which is exactly the distinction this checks.
///
/// ## `hyper` and `tokio` left this list, and the bound did not weaken
///
/// This list was a PROXY. The property it protects is CLOUD-745 item 5 and
/// CLOUD-747 constraint 3 — *"`batten hook` must build no runtime"* — and a
/// manifest scan could stand in for it only while tokio resolved to nothing.
/// Both `clippy.toml` and `.claude/rules/rust.md` say so in terms: the runtime
/// bans are *"inert today, because tokio resolves to nothing, and both go live
/// the day an HTTP client arrives"*. CLOUD-745 is the row that brings that day,
/// deliberately, after measuring that every alternative fails a link gate.
///
/// So absence is replaced by REACHABILITY, which is the property all along and
/// is strictly harder to satisfy by accident:
///
/// * `policy/module-layering.rego` forbids the edge `hook -> fetch` over the
///   RESOLVED `use` graph (CLOUD-762's fact, not a line predicate), so the one
///   module that builds a runtime is unreachable from the adjudicator. That is a
///   live `deny` row in `batten check`, not a comment.
/// * The `tokio` entry takes `default-features = false` without
///   `rt-multi-thread` or `signal`, so `new_multi_thread` and `tokio::signal`
///   are **compile errors** rather than lint findings — stronger than the
///   `clippy.toml` rows that name them, which is why those rows now carry
///   `allow-invalid` with that reason recorded.
/// * `perf-assert` holds the mediated path to CLOUD-689's ceiling, which is what
///   a runtime on that path would break and what a manifest scan never measured.
///
/// The other clients stay listed. Nothing in this tree may reach the network
/// through a second stack, and `fetch.rs` is the one adapter that reaches it at
/// all.
const AMBIENT_CRATES: &[&str] = &[
    "reqwest",
    "ureq",
    "curl",
    "isahc",
    "surf",
    "attohttpc",
    "async-std",
    "smol",
    "jsonschema",
];

/// The dependency tables that reach the shipped binary. `dev-dependencies` is
/// deliberately absent: a test may link what the binary must not.
const SHIPPED_TABLES: &[&str] = &[
    "dependencies",
    "target.cfg(unix).dependencies",
    "target.cfg(windows).dependencies",
];

#[test]
fn bound_two_no_ambient_crate_reaches_the_shipped_closure() {
    // CLOUD-647's constraint, computed rather than promised — and computed with
    // the document fact CLOUD-772 landed, so this gate is also the first
    // consumer of it outside its own suite.
    //
    // Fails by: moving `jsonschema` out of `[dev-dependencies]`, or adding a
    // SECOND HTTP stack beside the one `fetch.rs` adapts. The first stack is
    // vendored on purpose (CLOUD-745) and its bound is reachability rather than
    // absence — see the list above for what carries it now.
    let text = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read the crate manifest");
    let Look::Is(manifest) = Format::Toml.read(&text) else {
        panic!("the crate manifest did not parse");
    };
    let mut offenders = Vec::new();
    for table in SHIPPED_TABLES {
        let Look::Is(Node::Map(declared)) = manifest.at(table) else {
            // A table this manifest does not carry is not a finding: the Windows
            // target block genuinely does not exist here.
            continue;
        };
        for name in declared.keys() {
            if AMBIENT_CRATES.contains(&name.as_str()) {
                // Pointer-only: the table and the crate name, never the row.
                offenders.push(format!("{table}.{name}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "an ambient-authority crate reached the shipped closure, so `batten hook` would build a \
         runtime it promises not to (CLOUD-763 bound 2, CLOUD-745 item 5):\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_dev_only_exception_is_real_and_not_an_empty_allowance() {
    // The bound above passes trivially if nothing it names is in the tree at all,
    // and an allowance nobody exercises is one nobody notices going stale. This
    // asserts the interesting half is live: `jsonschema` IS vendored, and it is
    // vendored where the binary does not link it.
    let text = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read the crate manifest");
    let Look::Is(manifest) = Format::Toml.read(&text) else {
        panic!("the crate manifest did not parse");
    };
    assert_eq!(
        manifest.at("dev-dependencies.jsonschema.workspace"),
        Look::Is(&Node::Bool(true)),
        "the dev-only exception this bound is written against is no longer live"
    );
}

#[test]
fn bound_three_an_allow_row_cannot_override_a_deny() {
    // Deny-only and monotone. A rule may contribute a denial; nothing in the
    // config surface may produce an allow that takes one back — which preserves
    // §8's raise-only invariant and removes the allow/deny contradiction class by
    // construction rather than by detection.
    //
    // `severity = "allow"` is a per-row OFF switch, not a cross-row override, and
    // this is the case that says so: two rows match the same file, one denies and
    // one allows, and the run still fails.
    //
    // Fails by: letting an `allow` row suppress another row's finding.
    let dir = Fixture::new("authority-monotone")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"denies\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n\
             severity = \"deny\"\n\
             [[rule]]\n\
             id = \"switched-off\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n\
             severity = \"allow\"\n",
        )
        .file("lib.rs", "TODO fix this\n")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an allow row took back another row's denial: {}",
        stderr(&output)
    );
}

#[test]
fn the_monotonicity_case_discriminates_on_severity() {
    // The case above asserts an exit code, and an exit code is only evidence if
    // the fixture could have produced the other one. The same tree with BOTH rows
    // switched off exits 0 — so the `2` above is the denial surviving, not the
    // fixture failing for some unrelated reason.
    let dir = Fixture::new("authority-monotone-off")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"switched-off\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n\
             severity = \"allow\"\n",
        )
        .file("lib.rs", "TODO fix this\n")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn bound_four_the_policy_authority_is_a_protected_path() {
    // §8's out-of-band property: an agent must not be able to edit the rules that
    // judge it. The module registry the bound ultimately names does not exist
    // yet, so this asserts the half that does — this repository's own authority
    // is inside its own protected set, which is the shape any future registry
    // path has to join.
    //
    // Consumer-side by construction: WHICH paths are protected is this
    // repository's business and lives in its `batten.toml`, never in the crate
    // (non-negotiable rule 1).
    //
    // Fails by: dropping the authority from the protected set — the maximal
    // weakening, since it disarms every gate at once including this one.
    let text = fs::read_to_string(at_root("batten.toml")).expect("read the authority");
    let Look::Is(config) = Format::Toml.read(&text) else {
        panic!("the authority did not parse");
    };
    let Look::Is(Node::List(protected)) = config.at("protected") else {
        panic!("the authority declares no protected set");
    };
    let guarded: Vec<String> = protected.iter().filter_map(Node::scalar).collect();
    assert!(
        guarded.iter().any(|path| path == "batten.toml"),
        "the policy authority is not in its own protected set"
    );
}
