//! The `mutants` shards read a cache that `main` fills with what they build
//! (CLOUD-2588).
//!
//! Measured on run 41728967023, shard 0: three declared rows judged in 1s each
//! and no mutant, behind 4m21s of "building the cargo suites the rows run
//! under". The shards read `ci-`, which holds `target/`; the sweep builds into
//! `mutate.rs`'s `SUITE_TARGET` at `CARGO_PROFILE_TEST_DEBUG=0`. So the warm
//! job's target directory and profile are read from the engine's own source,
//! and its family from the shards' job, rather than restated here.

use yaml_rust2::{Yaml, YamlLoader};

use crate::common;

/// One committed file's text.
fn read(path: &str) -> String {
    std::fs::read_to_string(common::at_root(path)).unwrap_or_else(|_| panic!("{path} is committed"))
}

/// The job keyed `key` in the workflow at `path`.
fn job(path: &str, key: &str) -> Yaml {
    let docs = YamlLoader::load_from_str(&read(path)).expect("the workflow parses");
    docs[0]["jobs"][key].clone()
}

/// The steps of the job keyed `key` in the workflow at `path`.
fn steps(path: &str, key: &str) -> Vec<Yaml> {
    job(path, key)["steps"]
        .as_vec()
        .unwrap_or_else(|| panic!("{path} has a job `{key}` with steps"))
        .clone()
}

/// rust-cache puts the runner's arch inside its restore prefix, so a writer
/// on another arch writes an entry no shard can restore.
#[test]
fn the_mutants_warm_job_runs_on_the_shards_architecture() {
    let warm = job(".github/workflows/release-plz.yml", "cache-warm-mutants");
    let shards = job(".github/workflows/ci.yml", "mutants");
    assert_eq!(
        warm["runs-on"].as_str(),
        shards["runs-on"].as_str(),
        "cache-warm-mutants runs on a label the mutants shards do not"
    );
}

/// The one step of `steps` that uses rust-cache.
fn rust_cache(steps: &[Yaml]) -> &Yaml {
    let mut found = steps.iter().filter(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("Swatinem/rust-cache@"))
    });
    let step = found.next().expect("the job restores a rust-cache family");
    assert!(
        found.next().is_none(),
        "the job reads one rust-cache family"
    );
    step
}

/// The engine's `SUITE_TARGET`, read from its declaration.
fn suite_target() -> String {
    read("crates/batten/src/mutate.rs")
        .lines()
        .find_map(|line| line.strip_prefix("const SUITE_TARGET: &str = \""))
        .and_then(|rest| rest.strip_suffix("\";"))
        .expect("mutate.rs declares SUITE_TARGET")
        .to_owned()
}

/// `#MUTANT warm-target-elsewhere`, `#MUTANT warm-debug-level` and `#MUTANT
/// warm-family-elsewhere` redden here: a warm entry under another target
/// directory, another debug level or another family is one no shard reads.
#[test]
fn the_mutants_warm_job_builds_the_shards_target() {
    let warm = steps(".github/workflows/release-plz.yml", "cache-warm-mutants");
    let shards = steps(".github/workflows/ci.yml", "mutants");
    let target = suite_target();
    let suite_build = warm
        .iter()
        .find(|step| step["env"]["CARGO_TARGET_DIR"].as_str() == Some(target.as_str()))
        .expect("cache-warm-mutants builds into the sweep's SUITE_TARGET");
    assert_eq!(
        suite_build["env"]["CARGO_PROFILE_TEST_DEBUG"].as_str(),
        Some("0"),
        "cache-warm-mutants builds the suites under another debug level than suite_env"
    );
    let family = rust_cache(&shards)["with"]["shared-key"]
        .as_str()
        .expect("the mutants job names its family");
    assert_ne!(
        family, "ci-",
        "the shards read `ci-`, which holds nothing they build"
    );
    assert_eq!(
        rust_cache(&warm)["with"]["shared-key"].as_str(),
        Some(family),
        "cache-warm-mutants writes a family the mutants job does not read"
    );
    assert_eq!(
        rust_cache(&shards)["with"]["save-if"].as_bool(),
        Some(false),
        "a shard writes the family on its own ref, where no other pull request reads it"
    );
}
