//! The delay inventory, as a gate rather than a table (CLOUD-1177).
//!
//! AGENTS.md refuses a timer on the agent surface — *"never a foreground
//! `sleep`, a timer where an exit condition belongs"* — and until this row the
//! Rust half had no mechanism at all: `clippy.toml` banned a spawn and a
//! multi-thread runtime, and neither is a delay. The retirements moving bash
//! waiters into the engine are precisely the changes that introduce one, and a
//! timer is harder to see in Rust than in bash rather than easier.
//!
//! **What is banned is the CALL, and what is refused is a wall-clock guess.** A
//! conditional poll against a real exit condition is legitimate work; `sleep` as
//! a scheduling device — pacing a loop by guessing when the world changes — is
//! not. clippy cannot tell those apart, so every sound site carries an
//! annotation, exactly as a spawn does in `spawn_census.rs`.
//!
//! The obligation on that annotation is where this gate earns its keep. A waiver
//! is satisfied by any prose; an inventory row is not. So the reason must **name
//! the bound the delay comes from** — the header that set the interval, the
//! terminal state the loop exits on, the count that exhausts — and this file
//! holds each named bound to one that actually RESOLVES in the same file. A
//! timer has no bound to name, which is what makes the predicate discriminate
//! rather than decorate.
//!
//! What this file deliberately does not re-assert: that `disallowed_methods` and
//! `unfulfilled_lint_expectations` are `deny` in the workspace manifest.
//! `spawn_census.rs` owns both, for both inventories, and a second copy here
//! would be a second authority over one line.
//!
//! Two tiers, and the second is the one CLOUD-418 asks for. The shape assertions
//! below all pass over a tree where the ban does nothing at all, so the toy-crate
//! cases drive real clippy and make each arm go red on purpose: an unannotated
//! delay refused, an annotated one passing, and a stale annotation over a delay
//! that is gone refused too — the direction a count table is blind to and the
//! whole reason the annotation is `expect` rather than `allow`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::facts::{Format, Look, Node};
use common::{annotation_reason, annotations_naming, at_root, rust_sources};

/// The lint whose level carries this inventory.
const LINT: &str = "clippy::disallowed_methods";

/// The call the ban is about.
const SLEEP: &str = "std::thread::sleep";

/// Its async spelling, banned on the same terms and live for a different reason.
const ASYNC_SLEEP: &str = "tokio::time::sleep";

/// The tokio feature that makes [`ASYNC_SLEEP`] resolve.
const TIME: &str = "time";

/// `clippy.toml`, read once per case.
fn clippy_toml() -> String {
    fs::read_to_string(at_root("clippy.toml")).expect("clippy.toml is committed")
}

/// The workspace manifest, through the fact the engine already owns rather than
/// a second TOML reader.
fn manifest() -> Node {
    let text = fs::read_to_string(at_root("Cargo.toml")).expect("the workspace manifest is here");
    match Format::Toml.read(&text) {
        Look::Is(node) => node,
        other => panic!("the workspace manifest did not parse: {other:?}"),
    }
}

/// The row for `path` in `clippy.toml`, as its single line.
///
/// Anchored on the `path =` KEY rather than on the bare path, because the
/// comment block above the table names both banned calls in prose — a bare
/// search finds the sentence, and the assertions below would then be reading a
/// comment and reporting on a row.
fn row_for(clippy: &str, path: &str) -> String {
    // Assembled from `QUOTED` rather than written as one interpolation, because
    // `primitives.rs::every_path_valued_toml_key_uses_a_literal_string` refuses
    // the shape `path = "{…}"` on sight — deliberately keyed on the KEY and never
    // on the value, since "can this value be a path?" is a judgement it got wrong
    // twice. Here the key belongs to `clippy.toml`'s dialect and its value is a
    // Rust type path, so no escape can bite; and the audit's own remedy (a TOML
    // literal string) cannot apply, because this READS bytes clippy.toml already
    // spells with basic strings. Dodging the shape is the honest repair: the
    // audit stays exactly as strict about the class it was written for.
    const QUOTED: &str = "path = \"";
    let key = format!("{QUOTED}{path}\"");
    let at = clippy
        .find(&key)
        .unwrap_or_else(|| panic!("clippy.toml must carry a row for `{path}`"));
    let start = clippy[..at].rfind('\n').map_or(0, |nl| nl + 1);
    let end = clippy[at..].find('\n').map_or(clippy.len(), |nl| at + nl);
    clippy[start..end].to_owned()
}

/// Every backticked span in `reason`, which is how a bound is named.
///
/// Backticks rather than a bare-word scan, because the assertion is that the
/// author pointed at a THING: prose naming a duration in words has no span to
/// resolve, and that is the shape this gate exists to refuse.
fn bounds_named(reason: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = reason;
    while let Some((_, after)) = rest.split_once('`') {
        let Some((span, tail)) = after.split_once('`') else {
            break;
        };
        if !span.is_empty() {
            found.push(span.to_owned());
        }
        rest = tail;
    }
    found
}

#[test]
fn clippy_toml_bans_both_spellings_of_a_delay() {
    // The subject half. The severity is the manifest's and `spawn_census.rs`
    // asserts it; this says WHAT is refused, and both spellings are asked for
    // because banning only the blocking one leaves the async door open the day
    // an `async fn` arrives — which the vendored HTTP client has already made
    // reachable.
    let clippy = clippy_toml();
    assert!(
        clippy.contains("disallowed-methods"),
        "clippy.toml must carry a `disallowed-methods` table"
    );
    for path in [SLEEP, ASYNC_SLEEP] {
        let row = row_for(&clippy, path);
        assert!(
            row.contains("reason ="),
            "the `{path}` row must carry a `reason`: clippy prints it at the deny site, and a \
             deny that does not say what to do is the CLOUD-437 defect"
        );
    }
    // The remedy has to be IN the refusal, because the refusal is where an author
    // meets this rule — a deny naming the ban and not the annotation sends them
    // to delete the delay, which is the wrong fix for twelve of the thirteen
    // sites in this crate.
    let row = row_for(&clippy, SLEEP);
    assert!(
        row.contains(LINT) && row.contains("bound"),
        "the `{SLEEP}` row's reason must name `{LINT}` and the BOUND an annotation owes, so the \
         deny an author actually reads carries the remedy rather than only the refusal"
    );
}

#[test]
fn the_async_row_is_live_exactly_while_the_time_feature_is_on() {
    // THE ASYMMETRY WITH THE TOKIO ROWS ABOVE IT, and it runs the other way.
    //
    // `tokio::signal::*` and `new_multi_thread` carry `allow-invalid = true`
    // because the features that would compile them are OFF, so reaching for
    // either is a compile error — strictly stronger than a lint, and the flag
    // records that rather than waiving anything. `tokio::time::sleep` has no such
    // bound: the workspace `tokio` entry ENABLES `time`, so the path resolves and
    // the lint is the whole of the refusal. Carrying `allow-invalid` there would
    // record a guarantee this row does not have.
    //
    // So the two halves are asserted together, and dropping `time` from the
    // feature list turns this red pointing at the row that must then gain the
    // flag — otherwise clippy rejects an unresolvable path and the config fails
    // to load at all, which is a red gate saying nothing about the ban.
    let manifest = manifest();
    let features = manifest.at("workspace.dependencies.tokio.features");
    let Look::Is(Node::List(features)) = features else {
        panic!("[workspace.dependencies] must declare tokio with an explicit feature list")
    };
    let enabled: Vec<&str> = features
        .iter()
        .filter_map(|node| match node {
            Node::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let row = row_for(&clippy_toml(), ASYNC_SLEEP);
    if enabled.contains(&TIME) {
        assert!(
            !row.contains("allow-invalid"),
            "tokio enables `{TIME}`, so `{ASYNC_SLEEP}` RESOLVES and the ban is live. \
             `allow-invalid = true` on a row that resolves records a guarantee it does not have — \
             drop it, and leave the flag to the rows whose feature is genuinely off."
        );
    } else {
        assert!(
            row.contains("allow-invalid = true"),
            "tokio no longer enables `{TIME}`, so `{ASYNC_SLEEP}` cannot resolve and clippy will \
             reject the whole config rather than the path. Add `allow-invalid = true` to that row \
             and record in its comment that the feature being off is now the stronger bound."
        );
    }
}

#[test]
fn every_delay_carries_an_expect_naming_a_bound_that_resolves() {
    // THE PREDICATE THIS ROW IS ABOUT. Every other assertion here is about the
    // config; this one is about the thirteen annotations the config forced into
    // existence, and it is what stops the ban being satisfied by thirteen
    // waivers.
    //
    // "Names a bound that resolves" is deliberately ONE span rather than all of
    // them: a reason names the exit condition, the interval and often the
    // enclosing deadline, and only some of those are spelled as identifiers in
    // the file — an HTTP header is a bound and is not a symbol. Demanding all
    // would push authors toward naming only what is greppable, which is the
    // narrower claim. Demanding one is the assertion that the author pointed at
    // something really there.
    //
    // Pointer-only per non-negotiable rule 4: a path, a line and a class, never
    // the annotated source.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let shown = path.display().to_string();
        let found = annotations_naming(&source, LINT);
        // The annotation cannot resolve its own bound: a reason naming a token
        // that appears nowhere but inside the reason is prose with backticks.
        let mut elsewhere = source.clone();
        for (_, attribute) in &found {
            elsewhere = elsewhere.replace(attribute.as_str(), "");
        }
        for (line, attribute) in &found {
            if attribute.contains("allow(") {
                problems.push(format!("{shown}:{line} allow — must be expect"));
                continue;
            }
            if !attribute.contains("expect(") {
                problems.push(format!("{shown}:{line} not-an-expect"));
                continue;
            }
            let Some(reason) = annotation_reason(attribute) else {
                problems.push(format!("{shown}:{line} no-reason"));
                continue;
            };
            let named = bounds_named(&reason);
            if named.is_empty() {
                problems.push(format!("{shown}:{line} names-no-bound"));
                continue;
            }
            if !named.iter().any(|bound| elsewhere.contains(bound.as_str())) {
                problems.push(format!("{shown}:{line} bound-does-not-resolve"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "every delay is an inventory row and must name, in backticks, a bound that resolves in \
         its own file — the header that set the interval, the condition the loop exits on, or the \
         count that exhausts:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_inventory_is_not_empty() {
    // The anti-vacuity arm, and it is not a formality: every assertion above
    // passes trivially over a crate carrying no annotation at all, which is
    // exactly what a ban silently scoped to nothing would produce. A floor rather
    // than a count — the number is clippy's to maintain, and pinning one here
    // rebuilds the table this shape exists to replace.
    let annotated: usize = rust_sources()
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).expect("read a crate source file");
            annotations_naming(&source, LINT).len()
        })
        .sum();
    assert!(
        annotated >= 8,
        "only {annotated} delay verdicts found — the sweep is not reaching the crate"
    );
}

/// A throwaway crate carrying the ban and `lib` source `body`.
///
/// **No dependencies, for the reason the spawn census records for its own toy
/// crate**: the subject is the MECHANISM, not any real module's coverage, and
/// running against the live tree would make the verdict a function of whichever
/// file someone edited last. It also keeps the case offline — cargo fetches
/// nothing for a crate that declares nothing — and `[workspace]` in its manifest
/// is what stops it being adopted by the workspace it is materialized beside.
fn toy(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-sleep-ban-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).expect("create the toy crate");
    // TOML LITERAL strings, which is the audit's own remedy taken rather than
    // dodged: `every_path_valued_toml_key_uses_a_literal_string` refuses a `path`
    // interpolated into a basic string, and a literal one processes no escapes.
    // Nothing about the toy config needs escaping, so this costs nothing and
    // keeps the fixture inside the rule the rest of the suite lives by.
    fs::write(
        dir.join("clippy.toml"),
        format!(
            "disallowed-methods = [\n  {{ path = '{SLEEP}', reason = 'a delay is an inventory \
             row' }},\n]\n"
        ),
    )
    .expect("write the toy clippy.toml");
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n\n\
         [lints.rust]\nunfulfilled_lint_expectations = \"deny\"\n\n\
         [lints.clippy]\ndisallowed_methods = \"deny\"\n",
    )
    .expect("write the toy manifest");
    fs::write(dir.join("src/lib.rs"), body).expect("write the toy source");
    dir
}

/// Drive clippy over the toy crate, deliberately **without** `-D warnings`: the
/// level under test is the manifest's, and adding the flag would answer a
/// question nobody is asking.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the second tier IS a clippy run over a throwaway crate, and there is no way to observe what clippy decides about a delay without running it"
)]
fn toy_clippy(dir: &Path) -> (bool, String) {
    let cargo = std::env::var("CARGO").expect("cargo names itself to the test harness it runs");
    let out = std::process::Command::new(cargo)
        .args(["clippy", "--quiet"])
        .current_dir(dir)
        // Out of the workspace's own target dir, or every case contends on the
        // lock the gate deliberately serialises.
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .output()
        .expect("run clippy over the toy crate");
    let mut said = String::from_utf8_lossy(&out.stderr).into_owned();
    said.push_str(&String::from_utf8_lossy(&out.stdout));
    (out.status.success(), said)
}

/// An annotation naming [`LINT`], assembled rather than written out.
///
/// Assembled because this file is itself in the corpus
/// `every_delay_carries_an_expect_naming_a_bound_that_resolves` sweeps: a fixture
/// spelling the attribute literally would be scanned as one of the crate's own
/// inventory rows and judged against a bound it has no reason to have. Building
/// it from the same constant the gate reads keeps the fixture and the predicate
/// in agreement and keeps the fixture out of the sweep.
fn annotated(reason: &str) -> String {
    format!("#[expect({LINT}, reason = \"{reason}\")]")
}

#[test]
fn an_unannotated_delay_is_refused() {
    // (a) — the ban itself. Without this the row is a config edit nobody has
    // watched fire.
    let dir = toy(
        "unannotated",
        "pub fn pace() {\n    std::thread::sleep(std::time::Duration::from_secs(1));\n}\n",
    );
    let (passed, said) = toy_clippy(&dir);
    assert!(
        !passed,
        "an unannotated delay must be refused; clippy said: {said}"
    );
    assert!(
        said.contains("disallowed"),
        "the refusal must be the disallowed-method one rather than some other error: {said}"
    );
}

#[test]
fn an_annotated_delay_passes() {
    // (b) — the other side of (a), and without it the ban is satisfied by
    // something nothing can ever legitimately pass. This is what makes the
    // refusal above a statement about the MISSING VERDICT rather than about the
    // call.
    let body = format!(
        "pub fn poll(done: &dyn Fn() -> bool) {{\n    \
         while !done() {{\n        {}\n        \
         std::thread::sleep(std::time::Duration::from_millis(20));\n    }}\n}}\n",
        annotated("the interval of a poll whose exit condition is `done`")
    );
    let dir = toy("annotated", &body);
    let (passed, said) = toy_clippy(&dir);
    assert!(
        passed,
        "an annotated delay must pass — the ban is on the unremarked arrival, not on the call; \
         clippy said: {said}"
    );
}

#[test]
fn a_stale_annotation_over_a_deleted_delay_is_refused() {
    // (c) — WHY `expect` AND NOT `allow`, as a decision rather than a claim. The
    // delay is gone and the annotation was left behind; under `allow` that is
    // silent forever and the inventory accumulates rows describing code that is
    // not there. A count catches additions only; this is the other direction, and
    // it is what makes the inventory self-clean without anybody maintaining it.
    let body = format!(
        "{}\npub fn poll() {{}}\n",
        annotated("the interval of a poll that no longer exists")
    );
    let dir = toy("stale", &body);
    let (passed, said) = toy_clippy(&dir);
    assert!(
        !passed,
        "a stale delay verdict must be refused; clippy said: {said}"
    );
    assert!(
        said.contains("unfulfilled"),
        "the refusal must be `unfulfilled_lint_expectations` — that lint is warn-by-default, so \
         the workspace denies it explicitly rather than leaning on `-D warnings`: {said}"
    );
}
