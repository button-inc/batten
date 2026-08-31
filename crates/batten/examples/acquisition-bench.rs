//! Tree-surface acquisition cost as declared-document count scales (CLOUD-935).
//!
//! Retired out of `bench/acquisition/sweep.py` under CLOUD-1229, where it was 327
//! lines of Python run by a one-line task under an interpreter nothing pinned.
//!
//! # Why an example target and not a verb
//!
//! `perf pair` is a verb, and this was written as its sibling first. The command
//! surface refused it, correctly: `crates/batten/tests/pointer_only.rs` sweeps
//! EVERY leaf verb over a bare fixture corpus and refuses one that exits `3`,
//! because "it failed internally, so what it did not emit proves nothing". A
//! sweep cannot satisfy that. It needs a benchmark runner and a built binary to
//! time, and in a bare corpus it has neither — so its only honest answer there is
//! could-not-look. `perf pair` passes that sweep because it has a real SKIP
//! predicate (a commit that cannot change what gets invoked cannot have made the
//! invocation slower); there is no analogue here, and manufacturing one to get
//! past a census would be exactly the false green this repository exists to
//! refuse.
//!
//! So the measurement is a target the surface does not carry: no verb, no
//! completion, no man page, and nothing for that census to be wrong about. What
//! it is NOT is a way around the workspace lints — an example is built by
//! `--all-targets`, so it is held to the same clippy bar as everything else.
//!
//! # Why the work is still in `crates/batten/src/perf.rs`
//!
//! This file spawns nothing. `policy/spawn-adapters.rego` decides which modules
//! may spawn by NAME RESOLUTION, and it places `perf` with a rationale that reads
//! as though written for this case: a harness whose whole subject is what an
//! external process costs, so the spawns are the thing rather than an
//! implementation of it. A sweep with its own `Command`, its own hyperfine
//! invocation and its own percentile convention would be an unplaced spawning
//! module AND a second authority over a record shape `perf-compare` already
//! reads. Sharing the module is what makes both unwritable.
//!
//! # Reading the output
//!
//! One `arm=` record per measured arm, then a `ratio=` per comparison, then the
//! `null-spread` those ratios must be read against, then the per-document term in
//! microseconds. A sweep number inside the null spread has measured *no effect*,
//! and that is a result rather than a failure to deliver.
//!
//! Exit 0 measured / 1 could not look.

// The one sanctioned place to write to a stream: this target IS a binary
// boundary, exactly as `main.rs` is, and its whole output is the report.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::Path;

fn main() -> std::process::ExitCode {
    // `.` rather than a resolved toplevel: the task layer runs a task from the
    // repository root, and `acquire` canonicalises before it resolves anything
    // against it. A second repository-root resolver is the defect CLOUD-824
    // records one layer over, where a launcher asking git for `--show-toplevel`
    // disagreed with the engine asking for the common dir.
    match batten::perf::acquire(Path::new(".")) {
        Ok(sweep) => {
            print!("{sweep}");
            std::process::ExitCode::SUCCESS
        }
        // COULD NOT LOOK, in the `::error::` shape the workflow annotates, and
        // never an empty sweep that exits 0. A bench harness reporting "measured,
        // and there was nothing" over a run that never happened is the failure
        // CLOUD-1208 hit twice in one session — once publishing a residue-free
        // suite, once a null of 0.750.
        Err(reason) => {
            eprintln!("::error:: {reason}");
            std::process::ExitCode::FAILURE
        }
    }
}
