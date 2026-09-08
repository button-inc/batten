//! The strategy × residency matrix, and the report it prices (CLOUD-1606).
//!
//! **Against the committed `batten.toml`, not a fixture registry.** The question
//! is what an agent in THIS repository is actually charged when a real class
//! refuses, and a fabricated registry answers about a tree nobody works in — the
//! same argument `refusal_ceiling` makes at its own site.
//!
//! # What is a control and what is the measurement
//!
//! Four of the five declared relationships are properties of the PROJECTION
//! rather than of the renderer: both cold arms, and warm `Current` beside warm
//! `FirstFullThenCompact`, project to identical `first_sighting` inputs, so their
//! equalities would hold for any renderer whatsoever. They are kept as controls
//! that the table is wired as declared — and they are exactly why the
//! `current-warm-first-sighting` mutation is worth having, since a projection
//! that collapsed every arm to one value would satisfy them all.
//!
//! The two claims that are the renderer's own are that every compact warm repeat
//! is EXACTLY `Refusal::line()`, and that the full warm rendering is longer by a
//! measured margin. Those are what the report prices.
//!
//! **The second one was refuted as stated, and the cases record the correction
//! rather than the expectation.** Over what this repository actually EMITS, a
//! full warm delivery is not longer: the committed `[refusal] max_tokens` is 24,
//! the carried line for `branch write unsafe` is well over it, and `deny_text`
//! drops the routes rather than exceeding the budget. The margin is real in the
//! renderer and withheld by the ceiling, so it is asserted over the unbounded
//! column and the withholding is asserted separately against the declared bound.
//! Two cases, because they are two findings — one about a renderer, one about a
//! budget — and a single `>` over the emitted column would have reported the
//! second as the first.
//!
//! # The drift check is here rather than in the task
//!
//! `refusal_render_report` is re-rendered in this process and diffed against the
//! committed `bench/refusal-render/RESULTS.md`, so the report cannot go stale
//! without `test:cargo` reddening. That is what lets the benchmark task stay off
//! the landing path without the file it writes rotting there.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use batten::perf::{
    MEASURED_CLASSES, RenderRecord, Residency, Strategy, first_sighting, refusal_render,
    refusal_render_report,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The six records per class, rendered through the committed authority.
fn records() -> Vec<RenderRecord> {
    let config = batten::config::load(&root().join("batten.toml"))
        .expect("this repository's committed config loads");
    let registry =
        batten::policy::registry_for(&config.verdicts).expect("the committed registry resolves");
    refusal_render(&registry, config.refusal.as_ref()).expect("every measured class is declared")
}

fn arm(
    records: &[RenderRecord],
    class: &str,
    strategy: Strategy,
    residency: Residency,
) -> RenderRecord {
    records
        .iter()
        .find(|record| {
            record.class == class && record.strategy == strategy && record.residency == residency
        })
        .expect("every strategy/residency pair is rendered for every measured class")
        .clone()
}

/// The compact line the renderer produces for a class, taken from the authority
/// rather than restated: `Refusal::line` is what a repeat sighting must equal.
fn compact_line(class: &str, rule: &str) -> String {
    let config = batten::config::load(&root().join("batten.toml")).expect("the config loads");
    let registry = batten::policy::registry_for(&config.verdicts).expect("the registry resolves");
    batten::refusal::Refusal::from_class(rule, &registry, class, &[], batten::refusal::Fix::None)
        .line()
}

#[test]
fn the_matrix_is_six_records_per_measured_class() {
    // The anti-vacuity case. Every equality below is trivially true over an empty
    // or partial set, so the shape is asserted before anything is read from it.
    let records = records();
    assert_eq!(
        records.len(),
        MEASURED_CLASSES.len() * Strategy::ALL.len() * Residency::ALL.len(),
        "three strategies by two residency inputs, for each measured class"
    );
    for (class, _) in MEASURED_CLASSES {
        assert_eq!(
            records
                .iter()
                .filter(|record| record.class == *class)
                .count(),
            6,
            "{class} carries all six arms"
        );
    }
}

#[test]
fn every_cold_rendering_is_the_same_rendering() {
    let records = records();
    for (class, _) in MEASURED_CLASSES {
        let current = arm(&records, class, Strategy::Current, Residency::Cold);
        for strategy in Strategy::ALL {
            let other = arm(&records, class, *strategy, Residency::Cold);
            assert_eq!(
                current.line, other.line,
                "a cold sighting of {class} is the same line under every strategy"
            );
        }
    }
}

#[test]
fn warm_current_equals_warm_first_full_then_compact() {
    let records = records();
    for (class, _) in MEASURED_CLASSES {
        let current = arm(&records, class, Strategy::Current, Residency::Warm);
        let staged = arm(
            &records,
            class,
            Strategy::FirstFullThenCompact,
            Residency::Warm,
        );
        assert_eq!(
            current.line, staged.line,
            "{class}: today's behaviour IS first-full-then-compact on a repeat"
        );
    }
}

#[test]
fn a_compact_warm_repeat_is_exactly_the_refusal_line() {
    // The renderer's own claim, and the case the `current-warm-first-sighting`
    // mutation must redden: with warm `Current` projected to a first sighting,
    // the command-route class renders its routes and stops equalling `line()`.
    let records = records();
    for (class, rule) in MEASURED_CLASSES {
        let expected = compact_line(class, rule);
        for strategy in [Strategy::Current, Strategy::FirstFullThenCompact] {
            let record = arm(&records, class, strategy, Residency::Warm);
            assert_eq!(
                record.line,
                expected,
                "{class} under {} on a warm repeat is exactly Refusal::line()",
                strategy.as_str()
            );
        }
    }
}

#[test]
fn a_full_every_time_warm_rendering_is_never_shorter_than_the_compact_repeat() {
    let records = records();
    for (class, _) in MEASURED_CLASSES {
        let full = arm(&records, class, Strategy::FullEveryTime, Residency::Warm);
        let compact = arm(&records, class, Strategy::Current, Residency::Warm);
        assert!(
            full.characters >= compact.characters,
            "{class}: delivering in full every time cannot cost less than the compact repeat \
             ({} against {})",
            full.characters,
            compact.characters
        );
    }
}

#[test]
fn the_command_route_class_pays_a_measured_margin_when_the_budget_permits_it() {
    // The half of the previous case that is a strict inequality, and it is stated
    // over the UNBOUNDED rendering rather than the emitted one — which is what
    // measuring, rather than assuming, changed about this case.
    //
    // The expectation CLOUD-1606 declared was that a full warm delivery is longer
    // than a compact repeat. Over the emitted column that is FALSE in this
    // repository, and not because the renderer is wrong: `branch write unsafe`
    // declares two command routes, the carried line is ~37 estimated tokens, and
    // the committed `[refusal] max_tokens` is 24 — so `deny_text` drops the
    // routes and emits the compact line on both arms. The margin the row is about
    // exists in the renderer and is withheld by the budget, and asserting it over
    // the unbounded column is what says both of those things at once.
    let records = records();
    let full = arm(
        &records,
        "branch write unsafe",
        Strategy::FullEveryTime,
        Residency::Warm,
    );
    let compact = arm(
        &records,
        "branch write unsafe",
        Strategy::Current,
        Residency::Warm,
    );
    assert!(
        full.unbounded_characters > compact.unbounded_characters,
        "a class with command routes pays for them on every full delivery ({} against {})",
        full.unbounded_characters,
        compact.unbounded_characters
    );
}

#[test]
fn the_declared_ceiling_is_what_withholds_that_margin() {
    // The other half, and the one that keeps the case above from reading as a
    // renderer defect: the emitted arms are equal BECAUSE the carried line is over
    // the declared budget, not because nothing was rendered. Both facts are read
    // from the committed config rather than restated, so a ceiling change moves
    // this case rather than leaving it asserting a stale reason.
    let config = batten::config::load(&root().join("batten.toml")).expect("the config loads");
    let Some(ceiling) = config.refusal.as_ref() else {
        // No ceiling declared: there is nothing to withhold, and the emitted and
        // unbounded columns must then agree everywhere.
        for record in records() {
            assert_eq!(
                record.characters, record.unbounded_characters,
                "with no ceiling declared, nothing is withheld"
            );
        }
        return;
    };
    let full = arm(
        &records(),
        "branch write unsafe",
        Strategy::FullEveryTime,
        Residency::Warm,
    );
    if full.characters == full.unbounded_characters {
        assert!(
            full.unbounded_tokens <= ceiling.max_tokens,
            "a first sighting is emitted whole only while it fits the declared ceiling \
             ({} tokens against {})",
            full.unbounded_tokens,
            ceiling.max_tokens
        );
    } else {
        assert!(
            full.unbounded_tokens > ceiling.max_tokens,
            "the emitted line falls back only because the carried one is over the ceiling \
             ({} tokens against {})",
            full.unbounded_tokens,
            ceiling.max_tokens
        );
        assert!(
            full.characters < full.unbounded_characters,
            "the fallback is shorter than what it replaced"
        );
    }
}

#[test]
fn a_document_route_class_prices_its_cold_arm() {
    // THE CLOUD-1637 SEAM, asserted in both regimes rather than skipped in one.
    //
    // A first sighting appends `command` routes only, and `tool run loose`
    // declares a `document` route and no command route — so today its cold arm IS
    // its warm arm, and recording that bare line is the measured baseline
    // CLOUD-1606 asks for. Once CLOUD-1637 lands and the renderer appends the
    // document route, the cold arm must carry `rules/scanning.md` and must stop
    // equalling the compact repeat. Both branches assert; which one is live is
    // pinned by the committed report, so the drift case below is what turns the
    // regime change into a red run rather than a silent reinterpretation.
    let records = records();
    let cold = arm(
        &records,
        "tool run loose",
        Strategy::Current,
        Residency::Cold,
    );
    let warm = arm(
        &records,
        "tool run loose",
        Strategy::Current,
        Residency::Warm,
    );
    let bare = compact_line("tool run loose", "no-tool-substitution");

    if cold.line.contains("rules/scanning.md") {
        assert_ne!(
            cold.line, warm.line,
            "once a first sighting carries document routes, a cold arm costs more than a repeat"
        );
        assert!(
            cold.characters > warm.characters,
            "the route is emitted, so the cold arm is longer ({} against {})",
            cold.characters,
            warm.characters
        );
    } else {
        assert_eq!(
            cold.line, bare,
            "while a first sighting appends command routes only, a document-route class \
             renders the bare line cold"
        );
        assert_eq!(cold.line, warm.line, "and renders the identical line warm");
    }
}

#[test]
fn every_rendered_value_is_one_line() {
    for record in records() {
        assert!(
            !record.line.contains('\n'),
            "{} under {}/{} rendered more than one line",
            record.class,
            record.strategy.as_str(),
            record.residency.as_str()
        );
        assert!(
            record.characters > 0 && record.tokens <= record.characters,
            "a rendering is non-empty and its token estimate does not exceed its characters"
        );
    }
}

#[test]
fn the_projection_is_the_declared_table() {
    // The projection read directly, so a table that happened to render alike
    // cannot stand in for one that is wired as declared.
    assert!(first_sighting(Strategy::Current, Residency::Cold));
    assert!(!first_sighting(Strategy::Current, Residency::Warm));
    assert!(first_sighting(Strategy::FullEveryTime, Residency::Cold));
    assert!(first_sighting(Strategy::FullEveryTime, Residency::Warm));
    assert!(first_sighting(
        Strategy::FirstFullThenCompact,
        Residency::Cold
    ));
    assert!(!first_sighting(
        Strategy::FirstFullThenCompact,
        Residency::Warm
    ));
}

#[test]
fn the_committed_report_is_what_this_tree_renders() {
    // The drift check, and the reason the benchmark task can stay off the landing
    // path: the committed file is re-derived here from the same authority the
    // task reads, so a renderer or registry change that moves the numbers reddens
    // `test:cargo` instead of leaving a stale table in the tree.
    let path = root().join("bench/refusal-render/RESULTS.md");
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} is the benchmark's committed record; run `mise run refusal-render-bench` ({error})",
            Path::new("bench/refusal-render/RESULTS.md").display()
        )
    });
    let config = batten::config::load(&root().join("batten.toml")).expect("the config loads");
    let rendered = refusal_render_report(
        &records(),
        env!("CARGO_PKG_VERSION"),
        config.refusal.as_ref(),
    );
    assert_eq!(
        committed, rendered,
        "bench/refusal-render/RESULTS.md is stale — run `mise run refusal-render-bench`"
    );
}
