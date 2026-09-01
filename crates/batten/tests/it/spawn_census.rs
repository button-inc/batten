//! The spawn census, as a gate rather than a table (CLOUD-743).
//!
//! CLOUD-320 asked for a written position on every shell-out and shipped no
//! mechanism, so three more spawn sites landed unremarked. The mechanism is
//! `clippy::disallowed_types` over `std::process::Command`, and the verdict for
//! each site lives in the `#[expect]` **on the line it describes**. There is no
//! census table — not in this file and not anywhere else — which is the point:
//! a table drifts from the code, and a count is a number that can be wrong.
//!
//! What this file holds is the gate's own shape, which clippy cannot check about
//! itself:
//!
//! * the lint is `deny` **in the manifest**, not `warn` promoted by
//!   `-D warnings` (§2, and CLOUD-822's measurement of what the difference
//!   costs);
//! * `clippy.toml` names the type and gives a reason;
//! * every annotation is an `#[expect]` carrying a **verdict**, never a bare
//!   `#[allow]` — `expect` is what makes a DELETED spawn with a stale
//!   annotation red too, so the census self-cleans in both directions;
//! * `surface.rs`'s bare `clap::Command` import needs no annotation at all,
//!   which is the discriminator a string scan cannot draw and the reason this
//!   gate is clippy.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use batten::facts::{Format, Look, Node};
use common::{annotation_reason, annotations_naming, at_root, rust_sources};

/// The one type the census is about.
const SPAWN_TYPE: &str = "std::process::Command";

/// The lint whose level carries the gate.
const LINT: &str = "clippy::disallowed_types";

/// The verdict a `reason` must open with.
///
/// Two values and no third, because the inventory question has two answers: the
/// spawn is the design (`stays`), or it has a named successor and this row exists
/// so the successor lands as a deletion (`GOES`). Free prose here would let an
/// annotation satisfy the gate while recording nothing — which is the failure
/// mode of the table this replaced.
const VERDICTS: &[&str] = &["stays", "GOES"];

/// The attributes in `source` that name the census lint.
///
/// The scan itself is `common::annotations_naming`, shared with the delay
/// inventory (CLOUD-1177) rather than copied: two scanners over the same
/// question are two authorities that can disagree about what an annotation is.
fn census_attributes(source: &str) -> Vec<(usize, String)> {
    annotations_naming(source, LINT)
}

/// The workspace manifest as a parsed document, through the fact the engine
/// already owns (CLOUD-772) rather than a second TOML reader.
fn manifest() -> Node {
    let text = fs::read_to_string(at_root("Cargo.toml")).expect("the workspace manifest is here");
    match Format::Toml.read(&text) {
        Look::Is(node) => node,
        other => panic!("the workspace manifest did not parse: {other:?}"),
    }
}

#[test]
fn the_lint_is_denied_in_the_manifest_itself() {
    // §2, and the whole reason this row is not satisfied by adding an entry to
    // `clippy.toml` alone. Every other lint in this table is `warn`, promoted to
    // an error only by `mise run lint:clippy`'s `-D warnings`. CLOUD-822 measured
    // the consequence: `mise exec -- cargo clippy -p batten --all-targets` — the
    // escape `no-bare-cargo`'s own refusal text recommends — omits that flag and
    // missed 10 `expect_used` errors. A spawn gate at `warn` would report clean
    // over an unannotated spawn under a sanctioned command, and the agent would
    // then quote the clean run as verification.
    //
    // Relaxing the manifest line to `warn` turns THIS red, which is the §7(d)
    // obligation: the argument in §2 must not rest on a config line nothing
    // re-reads.
    let manifest = manifest();
    let level = manifest.at("workspace.lints.clippy.disallowed_types");
    let denied = Node::Text("deny".to_owned());
    assert_eq!(
        level,
        Look::Is(&denied),
        "[workspace.lints.clippy] must set `disallowed_types = \"deny\"`; found {level:?}. \
         A level only `-D warnings` promotes makes the verdict depend on which sanctioned \
         invocation ran (CLOUD-822), which is not a gate."
    );
}

#[test]
fn the_stale_annotation_arm_is_denied_too() {
    // `#[expect]` was chosen over `#[allow]` because it catches the OTHER
    // direction: a spawn deleted with its annotation left behind. That arm is
    // `unfulfilled_lint_expectations`, and it is warn-by-default — so until
    // CLOUD-743 it would have rested entirely on `mise run lint:clippy`'s
    // `-D warnings`, which is the same half-a-gate the clippy level above
    // refuses. Measured on a scratch crate in `tests/spawn-census.bats`: at the
    // default level, an `#[expect]` over code with no spawn is a warning and the
    // run exits 0.
    //
    // Two lints, two explicit denies, one gate. Relaxing either turns a test red.
    let manifest = manifest();
    let level = manifest.at("workspace.lints.rust.unfulfilled_lint_expectations");
    let denied = Node::Text("deny".to_owned());
    assert_eq!(
        level,
        Look::Is(&denied),
        "[workspace.lints.rust] must set `unfulfilled_lint_expectations = \"deny\"`; found \
         {level:?}. Without it the census only self-cleans in one direction, which is the \
         property a count table already had."
    );
}

#[test]
fn clippy_toml_names_the_spawn_type_and_says_why() {
    // The other half: the manifest carries the severity, this file carries the
    // subject. Split because they are different questions and clippy reads them
    // from different places — but neither alone is the gate, so both are asserted.
    let text = fs::read_to_string(at_root("clippy.toml")).expect("clippy.toml is committed");
    assert!(
        text.contains("disallowed-types"),
        "clippy.toml must carry a `disallowed-types` table"
    );
    assert!(
        text.contains(SPAWN_TYPE),
        "clippy.toml must name `{SPAWN_TYPE}` — the one type the census is about"
    );
    assert!(
        text.contains("reason ="),
        "the entry must carry a `reason`: clippy prints it at the deny site, and a deny that \
         does not say what to do is the CLOUD-437 defect"
    );
}

#[test]
fn the_signal_ban_is_declared_and_coupled_to_the_bound_that_holds_today() {
    // CLOUD-747. Signals are `signal-hook`'s, one registry: mise's supervisor
    // reaches for the same crate, so both ends of the pgroup protocol are
    // implemented against one set of semantics (CLOUD-427). A second signal
    // source would be a second answer.
    //
    // THE DAY ARRIVED, AND THE BAN IS STILL INERT — for a better reason than
    // before, which is the outcome this comment owes an answer to (CLOUD-1121).
    //
    // It used to read: `tokio` is in no dependency table, so the path cannot
    // resolve and clippy accepts it silently; it goes live the day CLOUD-745
    // vendors an HTTP client. CLOUD-745 vendored one. `tokio` IS in the shipped
    // closure now, and `tests/ambient_authority.rs` no longer refuses it.
    //
    // The entry still does not resolve, because the `tokio` dependency takes
    // `default-features = false` WITHOUT `rt-multi-thread` or `signal`. So
    // `tokio::signal` and `new_multi_thread` are not compiled into the graph at
    // all, and reaching for either is a COMPILE ERROR rather than a lint finding.
    // That is strictly stronger than the ban, which is why `clippy.toml` carries
    // `allow-invalid = true` on both rows with the reason recorded beside them —
    // a stronger guarantee recorded, never a weaker one waived.
    //
    // So the coupling still has work to do, and it is the same work: inert is
    // quiet in the wrong direction, and a misspelled path here would pass
    // unnoticed. The rows stay declared for the day somebody widens that feature
    // list to buy something else, when they resolve again and become the live
    // bound. Enabling the features now so the lint could see them would add the
    // surface in order to police it, which is backwards.
    let clippy = fs::read_to_string(at_root("clippy.toml")).expect("clippy.toml is committed");
    assert!(
        clippy.contains("tokio::signal::unix::Signal"),
        "clippy.toml must carry the `tokio::signal` ban — the posture in \
         .claude/rules/rust.md states it, and prose is feedforward only"
    );
    // The runtime-SHAPE bound travels with it, for the same reason and on the
    // same terms: the posture retired "builds no runtime" for "at most one, and
    // never multi-thread", and a rule without a runnable mechanism is half a
    // change (non-negotiable rule 2).
    assert!(
        clippy.contains("tokio::runtime::Builder::new_multi_thread"),
        "clippy.toml must carry the multi-thread runtime ban — the measured overhead is 12x \
         and it is the half of the posture a reader is most likely to reach for"
    );
    let manifest = manifest();
    for lint in ["disallowed_types", "disallowed_methods"] {
        let level = manifest.at(&format!("workspace.lints.clippy.{lint}"));
        let denied = Node::Text("deny".to_owned());
        assert_eq!(
            level,
            Look::Is(&denied),
            "[workspace.lints.clippy] must set `{lint} = \"deny\"`; found {level:?}. Both bans \
             above are configured in clippy.toml and neither carries a level of its own."
        );
    }
    // THE COUPLING MOVED WITH THE BOUND, and this is the half that has to be
    // re-pointed rather than deleted. It used to read `tokio` out of
    // `tests/ambient_authority.rs`'s ambient-crate list, because absence from the
    // closure was what made the rows unreachable. `tokio` is in the closure now,
    // so that list no longer answers the question and the FEATURE SET does: the
    // rows stay unreachable exactly while `signal` and `rt-multi-thread` are off.
    // Widening that list is therefore the event this case exists to catch — it is
    // the moment the two `allow-invalid = true` rows go live and must lose it.
    let features = manifest.at("workspace.dependencies.tokio.features");
    let Look::Is(Node::List(features)) = features else {
        panic!(
            "[workspace.dependencies] must declare tokio with an explicit feature list; \
                found {features:?}"
        )
    };
    let enabled: Vec<&str> = features
        .iter()
        .filter_map(|node| match node {
            Node::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let defaults = manifest.at("workspace.dependencies.tokio.default-features");
    let off = Node::Bool(false);
    assert_eq!(
        defaults,
        Look::Is(&off),
        "tokio must take `default-features = false`; found {defaults:?}. The default set carries \
         neither banned feature today, but relying on that is relying on tokio's own defaults not \
         to move, which is not a bound this repository holds."
    );
    for feature in ["signal", "rt-multi-thread"] {
        assert!(
            !enabled.contains(&feature),
            "tokio now enables `{feature}`, so clippy.toml's matching row RESOLVES again and is \
             the live bound rather than an unreachable one. Drop `allow-invalid = true` from that \
             row, show the ban fires, and rewrite the comment above — a stronger guarantee was \
             recorded there, and it has just been traded for a weaker one."
        );
    }
    for row in [
        "tokio::signal::unix::Signal",
        "tokio::runtime::Builder::new_multi_thread",
    ] {
        let at = clippy
            .find(row)
            .and_then(|at| clippy[at..].find('\n').map(|end| &clippy[at..at + end]));
        let Some(line) = at else {
            panic!("clippy.toml must carry a row for `{row}`")
        };
        assert!(
            line.contains("allow-invalid = true"),
            "the `{row}` row must carry `allow-invalid = true` while the feature that would make \
             it resolve is off — without it clippy rejects the unresolvable path and the config \
             fails to load at all, which is a red gate saying nothing about the ban."
        );
    }
}

#[test]
fn every_annotation_is_an_expect_carrying_a_verdict() {
    // The property that replaces the table. Each site's verdict is on the site,
    // so there is nothing to keep in sync — and `#[expect]` rather than
    // `#[allow]` is load-bearing rather than stylistic: `allow` goes quiet when
    // the lint stops firing, so deleting a spawn and leaving its annotation
    // behind would be invisible. `expect` makes that red, which is §7(b) and the
    // direction a count table cannot see at all.
    //
    // Pointer-only per non-negotiable rule 4: a path and a line, never the
    // annotated source.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let shown = path.display().to_string();
        for (line, attribute) in census_attributes(&source) {
            if attribute.contains("allow(") {
                problems.push(format!("{shown}:{line} allow — must be expect"));
                continue;
            }
            if !attribute.contains("expect(") {
                problems.push(format!("{shown}:{line} not-an-expect"));
                continue;
            }
            let Some(reason) = annotation_reason(&attribute) else {
                problems.push(format!("{shown}:{line} no-reason"));
                continue;
            };
            if !VERDICTS.iter().any(|verdict| reason.starts_with(verdict)) {
                problems.push(format!("{shown}:{line} no-verdict"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "every spawn annotation is an inventory row and must open with a verdict \
         ({VERDICTS:?}):\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_census_is_not_empty() {
    // The anti-vacuity arm. Every assertion above is about the SHAPE of an
    // annotation, and each of them passes trivially over a crate that carries
    // none — which is what a `disallowed-types` entry silently scoped to nothing
    // would produce, and is exactly the reading the count table was there to
    // prevent. So the discriminator is that the sweep found some.
    //
    // A floor rather than a count: the number is clippy's to maintain, and a
    // pinned figure here would be the table this row deleted.
    let annotated = rust_sources()
        .into_iter()
        .filter(|path| {
            let source = fs::read_to_string(path).expect("read a crate source file");
            !census_attributes(&source).is_empty()
        })
        .count();
    assert!(
        annotated >= 5,
        "only {annotated} files carry a spawn verdict — the sweep is not reaching the crate"
    );
}

#[test]
fn claps_command_needs_no_annotation() {
    // THE DISCRIMINATOR, and it is load-bearing (§7(c)). `surface.rs` imports
    // clap's `Command` BARE, so the token names two different types in this
    // crate. That ambiguity is what made both of CLOUD-743's wrong turns: a text
    // scan counted 14 sites and a syntax-only matcher counts 11, because neither
    // resolves names. clippy matches the fully resolved path, so `clap::Command`
    // is never matched at all.
    //
    // Asserted over the real file rather than a fixture: the claim is that THIS
    // module's `Command` sites need no annotation, and `mise run lint:clippy`
    // being green over a `surface.rs` that carries none is the proof. A fixture
    // would prove it about a fixture.
    let source = fs::read_to_string(at_root("crates/batten/src/surface.rs")).expect("read surface");
    assert!(
        source.contains("use clap::{Arg, ArgAction, Command};"),
        "surface.rs must still import clap's `Command` bare — that bare import IS the case \
         this gate has to get right, and requalifying it would delete the discriminator \
         rather than satisfy it"
    );
    assert!(
        source.contains("Command::new("),
        "surface.rs must still build the clap tree through `Command::new`"
    );
    assert!(
        census_attributes(&source).is_empty(),
        "surface.rs must carry NO spawn annotation: every `Command` in it is clap's, and an \
         annotation here would mean the gate had reproduced the very defect it exists to fix"
    );
}
