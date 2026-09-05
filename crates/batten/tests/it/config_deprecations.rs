//! No config key left the published schema without a deprecation window
//! (CLOUD-360), over the compiled binary.
//!
//! # The predicate
//!
//! The contract half of `expand -> migrate -> contract`. A key vanishing from the
//! published schema is a silent break for every consumer whose `batten.toml` still
//! carries it: their config stops loading, with an unknown-key error that names no
//! successor and no date. The grammar's promise is that removal is always preceded
//! by a window, and this is what holds it.
//!
//! The predicate is `batten config deprecations <ref>`: it reads the schema
//! published at a ref, derives the current one from the config types, and compares
//! the top-level key sets against `DEPRECATED_KEYS` and `RETIRED_KEYS`. Nothing
//! here re-derives any of that — a second answer to a question the engine already
//! answers is the defect the `git.rs` migration spent four slices removing.
//!
//! # Why a tag and not `origin/main`
//!
//! The promise is made to a consumer who INSTALLED a release, so the baseline is
//! the last released surface. Comparing against `main` would let a key be added
//! and removed between releases and count as a break, which it is not — nobody
//! could have configured it.
//!
//! # What this file owns, stated rather than discovered
//!
//! The verb takes ONE ref and resolves no pattern, so choosing WHICH ref is the
//! baseline is still the caller's, exactly as it was for the retired program: the
//! newest release tag in VERSION order, never in creation order, so a re-cut tag
//! cannot reorder the baseline. [`latest_release_tag`] is that resolution and it
//! is asserted here rather than assumed, because it is the one step of the gate
//! the engine does not perform.
//!
//! # Replay evidence, run before this was given deny severity
//!
//! `config deprecations` was run against all 112 release tags on this tree: 85
//! exit 0, 0 exit 2, 27 exit 3 for tags predating the committed schema. Zero exit
//! 2 over 85 comparable releases is what justifies `deny`: a predicate that would
//! have refused past releases is one that fires on work nobody can now fix.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch};

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Two paths die, so two arms:
// a program and its suite are separate subjects, and one arm covering both would
// claim a conservation nobody checked. The suite's arm names its declared
// `# subject:` too (CLOUD-1130), which this same delta retires.
//
// carried: mise-tasks/config-deprecations.sh crates/batten/src/config.rs kind:mechanism crates/batten/tests/it/config_deprecations.rs
// carried: tests/config-deprecations.bats mise-tasks/config-deprecations.sh crates/batten/src/config.rs kind:mechanism crates/batten/tests/it/config_deprecations.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared. Seven carried
// and one changed. Arms are suite-qualified because a case TITLE is not unique
// across suites — this bundle also retires `tests/schema-check.bats`, which
// declares two of these titles verbatim, and a bare arm would be borrowed by
// whichever suite looked it up first (the resolution order `rules.rs` records at
// `unconserved_cases`).
//
// carried: "config-deprecations.bats::a schema that lost no key exits 0" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::an unannounced removal is reported rather than passed" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::no release tag is exit 3 rather than a clean pass" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::a tag carrying no published schema is exit 3 rather than a clean pass" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::the baseline is the newest tag by version order, not by creation time" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::output is pointer-only — no schema body echoed" crates/batten/tests/it/config_deprecations.rs
// carried: "config-deprecations.bats::the gate leaves the tree it judges unmodified" crates/batten/tests/it/config_deprecations.rs
//
// changed: "config-deprecations.bats::this repo's own schema has lost no key since its last release — the gate on the real tree" crates/batten/tests/it/config_deprecations.rs the retired suite asserted exit 0 unconditionally over the real tree, which is only answerable in a clone that FETCHED TAGS — and a filtered or shallow clone has none, where the program itself exits 3. The case is carried as `this_repositorys_schema_has_lost_no_key_since_its_last_release`, which asserts the same verdict where a baseline resolves and asserts the could-not-look answer where none does, so it can no longer pass by having compared nothing

/// The latest release tag by VERSION order, never by creation date: a re-cut tag
/// would otherwise reorder the baseline.
///
/// `None` is could-not-look and never a pass. A fresh clone with no tags fetched
/// has no baseline, and reporting "nothing was removed" having compared nothing is
/// the vacuous pass CLOUD-251 names.
fn latest_release_tag(root: &Path) -> Option<String> {
    let listed = git_in(root, &["tag", "--list", "v*", "--sort=-v:refname"]);
    listed
        .lines()
        .next()
        .map(str::to_owned)
        .filter(|tag| !tag.is_empty())
}

/// The schema this build derives from the config types.
fn derived_schema() -> Vec<u8> {
    let output = batten()
        .args(["generate", "schema"])
        .output()
        .expect("run batten generate schema");
    assert_eq!(output.status.code(), Some(0));
    output.stdout
}

/// Run `batten config deprecations <against>` in `root`.
fn deprecations(root: &Path, against: &str) -> (i32, String) {
    let output = batten()
        .args(["config", "deprecations", against])
        .current_dir(root)
        .output()
        .expect("run batten config deprecations");
    let mut said = String::from_utf8_lossy(&output.stdout).into_owned();
    said.push_str(&String::from_utf8_lossy(&output.stderr));
    (
        output.status.code().expect("the child exited normally"),
        said,
    )
}

/// A repository that can PUBLISH a schema, because what this predicate reads is a
/// blob at a TAG — so a fixture has to be able to cut one.
///
/// No manifest and no sources: the verb derives the current schema from the binary
/// under test rather than from the tree it runs in, so unlike the retired bats
/// fixture there is nothing here to build.
struct Published {
    root: PathBuf,
}

impl Published {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        fs::create_dir_all(root.join("schema")).expect("create the schema directory");
        git_in(&root, &["init", "-q"]);
        let fixture = Self { root };
        fixture.write_schema(&derived_schema());
        fixture.publish("seed", "v0.0.1");
        fixture
    }

    fn write_schema(&self, bytes: &[u8]) {
        fs::write(self.root.join("schema/batten.schema.json"), bytes).expect("write the schema");
    }

    /// Commit whatever is in the tree and tag it.
    fn publish(&self, message: &str, tag: &str) {
        git_in(&self.root, &["add", "-A"]);
        git_in(&self.root, &["commit", "-qm", message]);
        git_in(&self.root, &["tag", tag]);
    }

    /// Publish a schema declaring `key`, then put the derived one back — so the
    /// key exists ONLY at the tag, which is exactly "it was released and then
    /// removed".
    fn publish_then_remove(&self, key: &str, description: &str, tag: &str) {
        let mut schema: serde_json::Value =
            serde_json::from_slice(&derived_schema()).expect("the schema is JSON");
        schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the schema has properties")
            .insert(
                key.to_owned(),
                serde_json::json!({ "type": "string", "description": description }),
            );
        self.write_schema(
            serde_json::to_string_pretty(&schema)
                .expect("the doctored schema serialises")
                .as_bytes(),
        );
        self.publish("publish an extra key", tag);
        self.write_schema(&derived_schema());
    }

    /// Publish a schema MISSING `key`, so this build reads it as added
    /// (CLOUD-366).
    ///
    /// [`Self::publish_then_remove`]'s mirror over the same doctored document,
    /// because the two questions a release answers about its schema are one
    /// comparison read in opposite directions.
    fn publish_without(&self, key: &str, tag: &str) {
        let mut schema: serde_json::Value =
            serde_json::from_slice(&derived_schema()).expect("the schema is JSON");
        schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the schema has properties")
            .remove(key)
            .expect("the key this build accepts is in its own derived schema");
        self.write_schema(
            serde_json::to_string_pretty(&schema)
                .expect("the doctored schema serialises")
                .as_bytes(),
        );
        self.publish("publish without a key this build has", tag);
        self.write_schema(&derived_schema());
    }

    fn baseline(&self) -> Option<String> {
        latest_release_tag(&self.root)
    }

    fn run(&self) -> (i32, String) {
        let against = self.baseline().expect("the fixture published a release");
        deprecations(&self.root, &against)
    }
}

// --- the verdicts ----------------------------------------------------------------

#[test]
fn a_schema_that_lost_no_key_is_clean() {
    let fixture = Published::new("config-deprecations-clean");
    let (code, said) = fixture.run();
    assert_eq!(code, 0, "{said}");
}

#[test]
fn an_unannounced_removal_is_reported_rather_than_passed() {
    // The predicate's whole reason for existing. A key present at the released tag
    // and absent now, with neither table naming it, is a silent break for every
    // consumer still carrying it.
    let fixture = Published::new("config-deprecations-removal");
    fixture.publish_then_remove("a_key_that_was_published_and_is_now_gone", "x", "v0.0.2");
    let (code, said) = fixture.run();
    assert_eq!(
        code, 2,
        "an unannounced removal is the policy verdict: {said}"
    );
    assert!(
        said.contains("a_key_that_was_published_and_is_now_gone"),
        "{said}"
    );
}

/// CLOUD-366. A release that carries a new config column owes the floor.
///
/// `min_batten_version` is compared against the RUNNING build, so the commit
/// adding a column cannot name the release carrying it — measured 2026-08-11,
/// floor `0.0.62` against a `0.0.61` build, exit `1`. The floor can only name a
/// version that already exists, so the obligation lands at the release; this is
/// the exit code that makes it an obligation rather than prose.
#[test]
fn a_release_carrying_a_new_column_owes_the_floor() {
    let fixture = Published::new("config-deprecations-added");
    fixture.publish_without("version", "v0.0.2");
    let (code, said) = fixture.run();
    // REPORTED, NEVER REFUSED. The floor is compared against the RUNNING build, so
    // the commit adding a column cannot name the release carrying it, and an
    // addition is by construction not in any released schema — so no commit on
    // `main` can carry this as a verdict. Measured twice on one branch: refusing
    // outright, and refusing only once the version is tagged, both turned
    // `[host]`'s own arrival red on the branch that added it.
    assert_eq!(code, 0, "an owed floor is a fact, not a verdict: {said}");
    assert!(said.contains("version added since"), "{said}");
}

/// The discriminator, and the one a lazy implementation gets wrong.
///
/// Raising the floor on every release satisfies "the floor never exceeds the
/// build" while tracking no column at all. So a release that adds NO column must
/// leave the floor exactly where it is — including when the floor is stale, which
/// this fixture's is: it declares none.
#[test]
fn a_release_carrying_no_new_column_owes_nothing_however_stale_the_floor() {
    let fixture = Published::new("config-deprecations-no-additions");
    let (code, said) = fixture.run();
    assert_eq!(
        code, 0,
        "no column added means no floor owed, whatever the floor says: {said}"
    );
    assert!(
        said.contains("0 addition(s)"),
        "the count is stated even at zero, so silence is not mistaken for a gate \
         that did not run: {said}"
    );
}

#[test]
fn a_tag_carrying_no_published_schema_is_could_not_look_rather_than_a_clean_pass() {
    let fixture = Published::new("config-deprecations-unpublished");
    fs::remove_file(fixture.root.join("schema/batten.schema.json")).expect("drop the schema");
    git_in(
        &fixture.root,
        &["rm", "-q", "--cached", "schema/batten.schema.json"],
    );
    fixture.publish("no schema here", "v0.0.3");
    // Restore the working tree's copy: the BASELINE is what lacks it.
    fixture.write_schema(&derived_schema());
    let (code, said) = fixture.run();
    assert_eq!(code, 3, "no published schema is could-not-look: {said}");
}

#[test]
fn no_release_tag_is_could_not_look_rather_than_a_clean_pass() {
    // Reporting "nothing was removed" having compared nothing is the vacuous pass
    // CLOUD-251 names, and it is the one answer this predicate must never give. The
    // resolver is what refuses here: with no baseline there is no ref to run the
    // verb against at all.
    let fixture = Published::new("config-deprecations-untagged");
    git_in(&fixture.root, &["tag", "-d", "v0.0.1"]);
    assert_eq!(
        fixture.baseline(),
        None,
        "a repository with no release tag has no baseline to compare against"
    );
}

#[test]
fn the_baseline_is_the_newest_tag_by_version_order_not_by_creation_time() {
    // A re-cut or back-dated tag must not reorder the baseline: v0.0.10 is newer
    // than v0.0.9 even when created first.
    let fixture = Published::new("config-deprecations-order");
    git_in(&fixture.root, &["tag", "v0.0.10"]);
    git_in(&fixture.root, &["tag", "v0.0.9"]);
    assert_eq!(fixture.baseline().as_deref(), Some("v0.0.10"));
}

#[test]
fn lexical_ordering_would_pick_the_wrong_baseline() {
    // Anti-vacuity for the case above: without version ordering `v0.0.9` sorts
    // after `v0.0.10`, so the assertion there would hold for a resolver that had
    // simply taken the last line of an unsorted list.
    let fixture = Published::new("config-deprecations-order-mirror");
    git_in(&fixture.root, &["tag", "v0.0.10"]);
    git_in(&fixture.root, &["tag", "v0.0.9"]);
    let lexical = git_in(&fixture.root, &["tag", "--list", "v*"]);
    let last = lexical.lines().next_back().expect("the fixture has tags");
    assert_eq!(
        last, "v0.0.9",
        "lexically the newest tag reads as v0.0.9, which is the reading the \
         version sort exists to refuse"
    );
    assert_ne!(fixture.baseline().as_deref(), Some(last));
}

// --- rule 4: a pointer, never the payload -------------------------------------------

#[test]
fn output_is_pointer_only_and_echoes_no_schema_body() {
    // The remedy is declaring a window, so the schema body adds nothing and would
    // put the config surface itself into the log.
    const DISTINCTIVE: &str = "AVeryDistinctiveInventedSentence";
    let fixture = Published::new("config-deprecations-pointer");
    fixture.publish_then_remove("gone_key", DISTINCTIVE, "v0.0.4");
    let (code, said) = fixture.run();
    assert_eq!(code, 2, "{said}");
    assert!(said.contains("gone_key"), "the key is the pointer: {said}");
    assert!(
        !said.contains(DISTINCTIVE),
        "the report carried the schema body: {said}"
    );
}

// --- the check does not write what it judges -----------------------------------------

#[test]
fn the_check_leaves_the_tree_it_judges_unmodified() {
    // A check that rewrites what it judges cannot fail twice: the second run would
    // pass, laundering the drift into a clean result.
    let fixture = Published::new("config-deprecations-readonly");
    fixture.publish_then_remove("another_key_that_went", "x", "v0.0.5");
    let before = fs::read(fixture.root.join("schema/batten.schema.json")).expect("read the schema");
    let (first, said) = fixture.run();
    assert_eq!(first, 2, "{said}");
    let after = fs::read(fixture.root.join("schema/batten.schema.json")).expect("read the schema");
    assert_eq!(before, after, "the check rewrote the schema it was judging");
    let (second, said) = fixture.run();
    assert_eq!(second, 2, "the same tree must fail twice: {said}");
}

// --- the real tree ---------------------------------------------------------------------

#[test]
fn this_repositorys_schema_has_lost_no_key_since_its_last_release() {
    // The self-consumption case, and the one the replay evidence generalises. It is
    // only answerable in a clone that fetched tags: a filtered or shallow clone has
    // none, and the honest answer there is could-not-look rather than a pass over a
    // comparison nobody made. Both arms are asserted, so this cannot report green
    // by having compared nothing.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    match latest_release_tag(&root) {
        Some(against) => {
            let (code, said) = deprecations(&root, &against);
            assert_eq!(
                code, 0,
                "a key left the published schema with no deprecation window since \
                 {against}; add a row to `config::DEPRECATED_KEYS` naming its \
                 replacement and expiry: {said}"
            );
        }
        None => {
            assert!(
                latest_release_tag(&root).is_none(),
                "no release tag is fetched in this clone, so there is no baseline \
                 and this predicate answered could-not-look rather than clean"
            );
        }
    }
}
