//! `policy/sbom-inventory.rego` over the compiled binary (CLOUD-262, retired
//! under CLOUD-1318).
//!
//! **The load-time tier pins the predicate and cannot pin that the engine builds
//! what it reads.** The module's own `test_` rules fabricate
//! `input.tree["tool-verdict"]["sbom"]` and `input.tree.lines` with `with input
//! as`, which passes whether or not anything can produce that shape — the class
//! `rules/policy-modules.md` opens with. This file runs the real producer
//! verb and the real engine, over a real lockfile and a real workflow.
//!
//! **The two halves are deliberately split, and the split is the subject here.**
//! Counts that require opening a DERIVED document travel through the record,
//! because `check` is `read` and cannot run `syft`. The two predicates readable
//! from committed text — the expected cargo count and the action-pin mapping —
//! are decided by the module from `line_sources`, so the producer cannot get them
//! wrong on its behalf. Cases below drive both routes.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! `sbom-check.sh` re-ran `sbom.sh` twice and adjudicated the documents in shell.
//! The scan stays outside — §9's prior art, and §5 makes `check` `read` — so
//! `mise run record-sbom` derives and records, and the adjudication moves here.
//! `sbom.sh` itself SURVIVES: it decides nothing, so it is a producer rather than
//! a gate, and its disposition is CLOUD-1159's rather than this row's.

// carried: mise-tasks/sbom-check.sh policy/sbom-inventory.rego crates/batten/tests/it/sbom_inventory.rs
// carried: tests/sbom-check.bats policy/sbom-inventory.rego crates/batten/tests/it/sbom_inventory.rs

//! # RETIREMENT LEDGER — `tests/sbom-check.bats`, 14 cases
//!
//! CARRIED — the decision table, which is what the gate was for.

// carried: "a matching, stable inventory passes — and that IS the normalizer working" crates/batten/tests/it/sbom_inventory.rs
// carried: "a cargo count that disagrees with Cargo.lock fails, naming both numbers" crates/batten/tests/it/sbom_inventory.rs
// carried: "an SBOM that catalogs nothing must not report green" crates/batten/tests/it/sbom_inventory.rs
// carried: "output is pointer-only — no document body reaches the log" crates/batten/tests/it/sbom_inventory.rs
// carried: "a lockfile whose local member has no source still matches: 1 purl, 1 sourced of 2" crates/batten/tests/it/sbom_inventory.rs
// carried: "the inflated shapes syft produces are all absorbed before the gate judges" crates/batten/tests/it/sbom_inventory.rs
// carried: "a document that DESCRIBES nothing is could-not-look, not a clean inventory" crates/batten/tests/it/sbom_inventory.rs
// carried: "THE DRIFT DETECTOR: a pin with no table row fails, which is how a bump arrives" crates/batten/tests/it/sbom_inventory.rs

//! CHANGED — four cases whose SUBJECT moved from the gate to the producer, so the
//! property is conserved where it is now decided rather than where it was.

// changed: "THE NEGATIVE SELF-TEST: a renamed package still fails after normalization" crates/batten/tests/it/sbom_inventory.rs the shell drove a syft stub whose two runs differed in a package NAME and asserted the normalizer did not absorb it. That comparison is `record-sbom`'s `stable()` now — it normalises the four volatile leaves and `cmp`s the rest — and what reaches the module is a yes/no token. `an_unstable_scan_is_refused` drives the token; the discrimination it protects lives in the producer's `jq -S 'del(...)'`, which still names exactly four leaves
// changed: "a syft that cannot run exits 2 — could not look is not a verdict" crates/batten/tests/it/sbom_inventory.rs deriving the document is the producer's job now, so a syft that cannot run fails `record-sbom` and writes NO record — leaving the id absent, which the module reads as could-not-look and refuses nothing. `an_unrecorded_scan_is_clean` is the successor; the exit code is the producer's rather than a gate's
// changed: "a missing Cargo.lock exits 2 rather than passing vacuously" crates/batten/tests/it/sbom_inventory.rs the module abstains from the count comparison when the lockfile was not read (`is_array(lock_lines)`) and `input.tree.missing` reports it, rather than the gate exiting 2 itself. Conserved as the module's `test_an_unreadable_lockfile_reports_no_drift` plus its `missing` clause — the vacuous PASS the case names is exactly what the guard prevents
// changed: "this repo's real tree satisfies the gate — with the real syft" crates/batten/tests/it/sbom_inventory.rs a whole-tree `syft scan dir:.` inside a cargo test would put two minutes of scanning in the test tier for what the hk gate already does. The successor is the `record-sbom` step plus `batten-check` running on this repository's own globs, which is where the real syft belongs; `a_clean_scan_over_the_real_lockfile_is_clean` keeps the end-to-end shape over a recorded scan

//! WITHDRAWN — two cases whose subject is unrepresentable in the successor, each
//! because the engine makes the property structural rather than assertable.

// withdrawn: "the failure names an asset, not a scratch path" the module never sees a scratch path: it receives counts and decides over `line_sources`, and its subjects are a tagged `{path}` naming the tracked lockfile or the tracked table. There is no filesystem path in the finding to get wrong, so the assertion has nothing left to discriminate
// withdrawn: "the gate leaves the tree it judges unmodified, and fails twice" `check` is declared `read` and `evaluator-io-check` is the standing gate on the engine opening nothing, so a module that wrote to the tree is unrepresentable rather than merely untested. The producer's two runs still go to scratch directories, which is `record-sbom`'s own concern

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, run_with_stdin, scratch, stderr, stdout, write};

/// The `syft` pin the row declares, and the one a record must be keyed to.
const DECLARED_VERSION: &str = "1.51.1";

/// A lockfile with TWO packages and ONE `source` line.
///
/// This is CLOUD-664's shape, and it is the fixture rather than a convenience:
/// syft gives the local workspace member no registry purl, so the expected count
/// is the SOURCED entries and not the total. A fixture with a `source` on every
/// entry would pass under either reading and discriminate nothing.
const LOCKFILE: &str = concat!(
    "[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\n",
    "[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.invalid\"\n",
);

/// One SHA-pinned action, and the table row that declares it.
const WORKFLOW: &str = "jobs:\n  build:\n    steps:\n      - uses: acme/checkout@0123456789abcdef0123456789abcdef01234567 # v1\n";

const TABLE: &str = "acme/checkout@0123456789abcdef0123456789abcdef01234567\tMIT\tAcme\n";

/// A recorded scan agreeing with [`LOCKFILE`]'s one sourced entry.
fn clean_scan() -> String {
    counts(&[("spdx-cargo", "1"), ("cdx-cargo", "1")])
}

/// The clean record with the named keys overridden.
fn counts(overrides: &[(&str, &str)]) -> String {
    use std::fmt::Write as _;

    let mut rows: Vec<(&str, &str)> = [
        ("spdx-cargo", "1"),
        ("cdx-cargo", "1"),
        ("spdx-stable", "yes"),
        ("cdx-stable", "yes"),
        ("subject", "1"),
        ("entries", "1"),
        ("distinct", "1"),
        ("pathlike", "0"),
        ("unversioned", "0"),
        ("nosupplier", "0"),
        ("subject-unset", "0"),
        ("originator-disagrees", "0"),
        ("copyright-unset", "0"),
        ("license-unset", "0"),
        ("license-slashed", "0"),
        ("action-unset", "0"),
    ]
    .to_vec();
    for (key, value) in overrides {
        if let Some(row) = rows.iter_mut().find(|(name, _)| name == key) {
            row.1 = value;
        }
    }
    rows.iter().fold(String::new(), |mut record, (key, value)| {
        let _ = writeln!(record, "{key} {value}");
        record
    })
}

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "sbom-inventory"
kind = "policy"
scope = "tree"
module = "sbom-inventory.rego"
line_sources = ["Cargo.lock", "mise-tasks/sbom-actions.tsv", ".github/workflows/*.yml"]
severity = "deny"

[[rule.tools]]
id = "sbom"
tool = "syft"
version = "{DECLARED_VERSION}"
input = "Cargo.lock"

[[pattern]]
id = "sbom-action-pin"
regex = 'uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{{40}}'

[[verdict]]
id = "tool read broken"
gloss = "the recorded SBOM scan cannot be judged, so the inventory is unverified"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "sbom-inventory.rego"

[[verdict]]
id = "manifest count wrong"
gloss = "the document and the tree it claims to describe do not agree"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "source read first"
kind = "document"
target = "Cargo.lock"

[[verdict]]
id = "manifest state missing"
gloss = "a field the tree states is NOASSERTION in the published document"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "source read first"
kind = "document"
target = "Cargo.lock"

[[verdict]]
id = "pin table missing"
gloss = "a SHA-pinned action in a workflow has no row in the licence table"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "source read first"
kind = "document"
target = "mise-tasks/sbom-actions.tsv"
"#
    )
}

/// A repository carrying the committed module, the row that reads it, a lockfile,
/// a workflow and the licence table.
fn fixture(name: &str, table: &str) -> PathBuf {
    let dir = scratch(&format!("sbom-inventory-{name}-{}", std::process::id()));
    write(&dir, "batten.toml", &config());
    write(
        &dir,
        "sbom-inventory.rego",
        &std::fs::read_to_string(at_repo("policy/sbom-inventory.rego")).expect("read the module"),
    );
    write(&dir, "Cargo.lock", LOCKFILE);
    write(&dir, ".github/workflows/ci.yml", WORKFLOW);
    write(&dir, "mise-tasks/sbom-actions.tsv", table);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

/// A path inside this repository, resolved from the test binary's manifest dir.
fn at_repo(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// Record a scan through the real producer verb.
fn record(dir: &Path, scan: &str) -> std::process::Output {
    run_with_stdin(dir, &["record", "tool", "sbom"], scan)
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_clean_scan_over_the_real_lockfile_is_clean() {
    // THE ANTI-VACUITY MIRROR, listed first because every refusal below is only
    // evidence if this one passes: a module denying unconditionally would satisfy
    // all of them. It is also what proves the ENGINE fills both halves — the
    // record AND `input.tree.lines` for three declared sources — since a count of
    // 1 only agrees with this lockfile if `Cargo.lock` was actually read.
    let dir = fixture("clean", TABLE);
    assert_eq!(record(&dir, &clean_scan()).status.code(), Some(0));

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a matching, stable inventory passes\n{answer}{cause}"
    );
}

#[test]
fn a_drifted_cargo_count_is_refused_over_the_real_lockfile() {
    // THE CENTRAL INVARIANT, and the one the declared mutation sits on. The
    // expected number is never written down: it is this lockfile's own `source =`
    // lines, so a count that disagrees means a cataloger missed something.
    let dir = fixture("drift", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-cargo", "2")])).status.code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a cargo count disagreeing with the lockfile is a policy verdict\n{answer}{cause}"
    );
    assert!(answer.contains("sbom-package-drift"), "{answer}{cause}");
}

#[test]
fn the_sourced_entries_are_counted_rather_than_every_package() {
    // CLOUD-664 AS A CASE. The fixture has two `[[package]]` entries and one
    // `source`, so a successor counting packages would expect 2 and refuse the
    // honest 1. This is the case that fails if anyone "simplifies" the predicate
    // back to counting entries.
    let dir = fixture("sourced", TABLE);
    assert_eq!(record(&dir, &clean_scan()).status.code(), Some(0));
    assert_eq!(check(&dir).status.code(), Some(0));

    let dir = fixture("sourced-two", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-cargo", "2"), ("cdx-cargo", "2")]))
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        check(&dir).status.code(),
        Some(2),
        "counting every package rather than the sourced ones must not pass"
    );
}

#[test]
fn an_empty_catalog_is_refused() {
    // A scan whose catalogers all missed agrees with every equality trivially:
    // two empty documents match, and an empty count matches an empty count.
    let dir = fixture("empty", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-cargo", "0"), ("cdx-cargo", "0")]))
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("sbom-empty"), "{answer}");
}

#[test]
fn an_unstable_scan_is_refused() {
    // Two scans of one tree must produce identical bytes once the four volatile
    // leaves are removed. The comparison is the producer's; the token is the
    // module's to judge.
    let dir = fixture("unstable", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-stable", "no")]))
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("sbom-unstable"), "{answer}");
}

#[test]
fn an_inflated_component_set_is_refused() {
    // syft emits a component per REFERENCE SITE. Measured once at 340 entries for
    // 290 distinct things; this is the clause that keeps `sbom.sh`'s normalisation
    // honest without anyone having predicted which shape comes next.
    let dir = fixture("inflated", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("entries", "3")])).status.code(),
        Some(0)
    );

    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("sbom-components-inflated"), "{answer}");
}

#[test]
fn a_document_describing_nothing_is_refused() {
    // The subject is what every component count is measured against, so a document
    // carrying no DESCRIBES edge leaves them all taken over the wrong set.
    let dir = fixture("describes", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("subject", "0")])).status.code(),
        Some(0)
    );
    assert_eq!(check(&dir).status.code(), Some(2));
}

#[test]
fn an_unmapped_action_pin_is_refused_from_committed_text_alone() {
    // THE DRIFT DETECTOR, decided with NO record involvement: the workflow and the
    // table are both `line_sources`, so this is the half a producer cannot get
    // wrong. A bump moves the sha, the row stops matching, and the gate fires.
    let dir = fixture("unmapped", "");
    assert_eq!(record(&dir, &clean_scan()).status.code(), Some(0));

    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("sbom-action-unmapped"), "{answer}");
}

#[test]
fn a_stale_sha_in_the_table_does_not_map_the_pin() {
    // The row is matched on repository AND commit together, because a row whose
    // sha is stale is exactly the drift this detects.
    let dir = fixture(
        "stale-sha",
        "acme/checkout@ffffffffffffffffffffffffffffffffffffffff\tMIT\tAcme\n",
    );
    assert_eq!(record(&dir, &clean_scan()).status.code(), Some(0));
    assert_eq!(check(&dir).status.code(), Some(2));
}

#[test]
fn an_unrecorded_scan_is_clean() {
    // NOTHING HAS SCANNED THESE BYTES is not a verdict. This is the ordinary state
    // of a checkout whose globs never fired, and refusing here would deny every
    // clone until a producer runs.
    let dir = fixture("unrecorded", TABLE);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "an absent record is could-not-look\n{answer}{cause}"
    );
}

#[test]
fn a_recorded_but_empty_scan_is_refused() {
    // PRESENT AND EMPTY is the producer having written nothing, which would let
    // every count above pass over an absent key — the vacuity arm.
    let dir = fixture("blank", TABLE);
    assert_eq!(record(&dir, "").status.code(), Some(0));

    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("sbom-unrecorded"), "{answer}");
}

#[test]
fn a_record_from_another_version_does_not_answer() {
    // THE KEY IS A TRIPLE, and the pinned version is one leg of it. A scan taken
    // at another syft is not evidence about this one — it is not found at all,
    // which is what keeps a stale verdict from reading as a fresh one.
    let dir = fixture("version", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-cargo", "99")])).status.code(),
        Some(0)
    );
    assert_eq!(check(&dir).status.code(), Some(2));

    // Move the pin; the record's key moves with it and the drift stops answering.
    write(
        &dir,
        "batten.toml",
        &config().replace(DECLARED_VERSION, "9.9.9"),
    );
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a record keyed to another pin must not answer\n{answer}{cause}"
    );
}

#[test]
fn a_verdict_does_not_survive_its_input() {
    // THE INPUT DIGEST IS TAKEN, NOT DECLARED, so a verdict goes stale by
    // construction: edit the lockfile and the key moves, so the old record is not
    // found rather than found and wrong.
    let dir = fixture("digest", TABLE);
    assert_eq!(
        record(&dir, &counts(&[("spdx-cargo", "99")])).status.code(),
        Some(0)
    );
    assert_eq!(check(&dir).status.code(), Some(2));

    write(&dir, "Cargo.lock", &format!("{LOCKFILE}\n# a later edit\n"));
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a record taken over different bytes must not answer\n{answer}{cause}"
    );
}

#[test]
fn the_report_is_pointer_only() {
    // NON-NEGOTIABLE RULE 4, and it matters more here than almost anywhere else in
    // the tree: an SBOM carries author names, email addresses and copyright
    // holders. The finding may name a tracked path and counts, and nothing else.
    let dir = fixture("pointer", TABLE);
    assert_eq!(
        record(
            &dir,
            &counts(&[
                ("nosupplier", "3"),
                ("copyright-unset", "4"),
                ("license-slashed", "2"),
            ]),
        )
        .status
        .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(outcome.status.code(), Some(2), "{answer}{cause}");
    for id in [
        "sbom-supplier-unset",
        "sbom-copyright-unenriched",
        "sbom-license-unenriched",
    ] {
        assert!(answer.contains(id), "{id} is not reported\n{answer}{cause}");
    }
    // No document body, no package name, no scratch path.
    for leak in ["NOASSERTION", "Copyright", "spdx.json", "/tmp/"] {
        assert!(
            !answer.contains(leak) && !cause.contains(leak),
            "{leak} reached the report\n{answer}{cause}"
        );
    }
}
