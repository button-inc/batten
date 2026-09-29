//! The `release-hygiene` preset (CLOUD-843): loaded the way a consumer gets it —
//! with the EMPTY vocabulary, no `[[pattern]]` and no `[[verdict]]` row — and then
//! over the compiled binary in a scratch consumer that is not this repository.
//!
//! The in-process half pins the predicate as shipped; the scratch half proves the
//! engine builds what the module reads for a consumer that names its record
//! family however it likes, because the module narrows on the KIND column and
//! never on a family name.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! Nothing is retired by THIS tier. The manifest half of `release-assets`' old
//! predicates carries its arms in `crates/batten/tests/it/release_assets.rs`,
//! which drives the preset beside the consumer module; these cases are the
//! preset's own, which every preset owes.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::facts::Look;
use batten::policy;
use batten::rules::Rule;
use batten::verdict::Subject;

use common::{git_in, init_repo, scratch, stderr, write};

/// A tree row enabling the preset, as a consumer writes it.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "release pin other",
        "kind": "policy",
        "scope": "tree",
        "preset": "release-hygiene",
        "severity": "deny",
    }))
    .expect("a preset row the loader accepts")
}

/// The one bundle the row compiles, with the EMPTY vocabulary.
fn loaded(name: &str) -> policy::Bundle {
    let root = scratch(&format!("release-hygiene-{name}"));
    let mut bundles = policy::load(
        &root,
        &[row()],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("the preset loads for a consumer with no vocabulary of its own");
    bundles.remove(0)
}

/// The findings over one record, by a family name no consumer would pick.
fn decided(bundle: &policy::Bundle, lines: &[&str]) -> Vec<policy::Violation> {
    let document = serde_json::json!({"tree": {"records": {"whatever-you-call-it": lines}}});
    let Look::Is(violations) = policy::deny(bundle, &document.to_string()) else {
        panic!("the preset answered");
    };
    violations
}

/// The record `batten record release` writes, closed by its census.
fn with_census(body: &[&str]) -> Vec<String> {
    let count = |kind: &str| {
        body.iter()
            .filter(|line| line.starts_with(&format!("release-{kind}\t")))
            .count()
    };
    let mut lines: Vec<String> = body.iter().map(|line| (*line).to_owned()).collect();
    lines.push(format!(
        "release-census\ttag={}\tmanifest={}\tasset={}\tcovered={}\tmismatch={}",
        count("tag"),
        count("manifest"),
        count("asset"),
        count("covered"),
        count("mismatch")
    ));
    lines
}

fn refs(lines: &[String]) -> Vec<&str> {
    lines.iter().map(String::as_str).collect()
}

/// The artifact pointers the findings carry.
fn pointers(found: &[policy::Violation]) -> Vec<String> {
    let mut all: Vec<String> = found
        .iter()
        .filter_map(|violation| match violation.subjects.first() {
            Some(Subject::Artifact { artifact }) => Some(artifact.clone()),
            _ => None,
        })
        .collect();
    all.sort();
    all
}

const HEALTHY: &[&str] = &[
    "release-tag\tv1",
    "release-manifest\tSUMS",
    "release-asset\ta.tar.gz",
    "release-asset\tb.json",
    "release-asset\tSUMS",
    "release-covered\ta.tar.gz",
    "release-covered\tb.json",
];

#[test]
fn the_release_hygiene_preset_refuses_a_release_with_no_manifest() {
    let bundle = loaded("no-manifest");
    let found = decided(
        &bundle,
        &refs(&with_census(&[
            "release-tag\tv1",
            "release-manifest\tSUMS",
            "release-asset\ta.tar.gz",
        ])),
    );
    assert_eq!(pointers(&found), ["SUMS:checksums-missing"]);
    assert_eq!(
        bundle.attribute(&found[0]),
        "release pin broken",
        "a preset finding names its own predicate id"
    );
    // THE ANTI-VACUITY MIRROR: a healthy release is clean, or this refuses all.
    assert!(decided(&bundle, &refs(&with_census(HEALTHY))).is_empty());
}

#[test]
fn the_release_hygiene_preset_refuses_an_omission_and_an_orphan() {
    let bundle = loaded("omits");
    let found = decided(
        &bundle,
        &refs(&with_census(&[
            "release-tag\tv1",
            "release-manifest\tSUMS",
            "release-asset\ta.tar.gz",
            "release-asset\tb.json",
            "release-asset\tSUMS",
            "release-covered\ta.tar.gz",
        ])),
    );
    assert_eq!(pointers(&found), ["b.json:checksums-omits"]);
    let mut orphaned: Vec<&str> = HEALTHY.to_vec();
    orphaned.push("release-covered\tghost.zip");
    orphaned.push("release-mismatch\tghost.zip");
    let found = decided(&bundle, &refs(&with_census(&orphaned)));
    assert_eq!(
        pointers(&found),
        ["ghost.zip:checksums-orphan"],
        "a mismatch is held back while a name disagrees"
    );
}

#[test]
fn the_release_hygiene_preset_refuses_a_byte_mismatch_once_the_names_agree() {
    let bundle = loaded("mismatch");
    let mut tampered: Vec<&str> = HEALTHY.to_vec();
    tampered.push("release-mismatch\ta.tar.gz");
    let found = decided(&bundle, &refs(&with_census(&tampered)));
    assert_eq!(pointers(&found), ["a.tar.gz:checksums-mismatch"]);
}

#[test]
fn the_release_hygiene_preset_refuses_a_torn_record() {
    let bundle = loaded("torn");
    let found = decided(&bundle, HEALTHY);
    assert_eq!(found.len(), 1, "no census: torn, and nothing else");
    assert_eq!(bundle.attribute(&found[0]), "release record torn");
    // A census that disagrees with its lines is torn too.
    let census = with_census(HEALTHY);
    let mut lying = refs(&census);
    lying.push("release-asset\tlate.tar.gz");
    let found = decided(&bundle, &lying);
    assert_eq!(bundle.attribute(&found[0]), "release record torn");
}

#[test]
fn the_release_hygiene_preset_reads_no_other_recorders_lines() {
    let bundle = loaded("foreign");
    assert!(decided(&bundle, &["asset\ta", "row\t{}", "window\tstate=whole"]).is_empty());
    let Look::Is(none) = policy::deny(&bundle, r#"{"tree":{"records":null}}"#) else {
        panic!("could-not-look over the whole store answers, and does not fault");
    };
    assert!(none.is_empty());
}

/// A scratch consumer that is not this repository: one preset row, one record
/// family under its own name, and no vocabulary at all.
#[test]
fn a_consumer_enabling_the_preset_is_refused_through_the_compiled_binary() {
    let dir = scratch("release-hygiene-consumer");
    init_repo(&dir);
    write(
        &dir,
        "batten.toml",
        "version = 1\nscope = [\"**\"]\n\n[[rule]]\nid = \"release pin other\"\n\
         kind = \"policy\"\nscope = \"tree\"\npreset = \"release-hygiene\"\nseverity = \"deny\"\n\n\
         [[record]]\nrecord = \"shipped\"\nwriter = \"batten record named shipped\"\n",
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "enable the preset"]);
    let unpinned = with_census(&[
        "release-tag\tv3",
        "release-manifest\tSUMS",
        "release-asset\tapp.tar.gz",
    ])
    .join("\n");
    let written = common::run_with_stdin(&dir, &["record", "named", "shipped"], &unpinned);
    assert!(written.status.success(), "{}", stderr(&written));
    let refused = common::run(&dir, &["check", "--rule", "release pin other"]);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let healthy = with_census(HEALTHY).join("\n");
    let written = common::run_with_stdin(&dir, &["record", "named", "shipped"], &healthy);
    assert!(written.status.success(), "{}", stderr(&written));
    let clean = common::run(&dir, &["check", "--rule", "release pin other"]);
    assert_eq!(clean.status.code(), Some(0), "{}", stderr(&clean));
}
