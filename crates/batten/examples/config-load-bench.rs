//! What `batten::config::load` costs over this repository's own committed
//! authority (CLOUD-1291).
//!
//! # The question, and the measurement that could not answer it
//!
//! `crates/batten/tests/common/mod.rs` re-reads and re-parses the committed
//! `batten.toml` on every fixture command it constructs — 761 static call sites
//! across the suite, none of them memoized. Whether that is worth fixing depends
//! on a number nobody had.
//!
//! The first attempt took it through a CLI verb, subtracting `batten --help` from
//! `batten config show` and calling the difference the parse. It is not: running
//! the same verb from a directory with no `batten.toml`, where nothing is parsed
//! at all, measured 30.2 ms against 29.1 ms in-repo — identical within noise. The
//! 22.5 ms was verb startup, paid whether or not a config exists. A 29 ms process
//! cannot resolve a cost that may be a millisecond, so the verb is the wrong
//! instrument and this target is the right one: one function call, timed in
//! process, with nothing else in the way.
//!
//! # Why an example target and not a verb
//!
//! `crates/batten/examples/acquisition-bench.rs`'s header owns this argument in
//! full and it applies unchanged: `crates/batten/tests/pointer_only.rs` sweeps
//! every leaf verb over a bare fixture corpus and refuses one that exits `3`, and
//! a benchmark has could-not-look as its only honest answer there. So the
//! measurement is a target the command surface does not carry — no verb, no
//! completion, no man page. It is still built by `--all-targets` and still held
//! to the same clippy bar.
//!
//! It also costs the integration-test census nothing: `examples/` is not
//! `tests/`, so this adds no linked test binary (CLOUD-1210).
//!
//! # Why the work is in `crates/batten/src/perf.rs`
//!
//! `Record`'s shape is a contract `perf-compare` parses and `perf-gate` greps,
//! and the percentile convention behind `p50` is what two readings must share
//! before their numbers can sit side by side. A bench with its own struct and its
//! own median is a second authority over both.
//!
//! # Reading the output
//!
//! One `arm=` record per arm in per-call milliseconds, the `parse/load` ratio —
//! whose distance from 1.0 is the READ's share — then the null spread the whole
//! thing must be read against. A saving inside that spread has measured no
//! effect, which for this row is a result and not a failure to deliver.
//!
//! Exit 0 measured / 1 could not look.

// The one sanctioned place to write to a stream: this target IS a binary
// boundary, exactly as `main.rs` is, and its whole output is the report.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::Path;

fn main() -> std::process::ExitCode {
    // The committed authority, relative to the repository root the task layer
    // runs from — the same path `common::at_root("batten.toml")` resolves for the
    // harness this is measuring on behalf of.
    match batten::perf::config_load(Path::new("batten.toml")) {
        Ok(reading) => {
            print!("{reading}");
            std::process::ExitCode::SUCCESS
        }
        // COULD NOT LOOK, in the `::error::` shape the workflow annotates, and
        // never an empty reading that exits 0 — a bench reporting "measured, and
        // there was nothing" over a run that never happened is the failure
        // CLOUD-1208 hit twice in one session.
        Err(reason) => {
            eprintln!("::error:: {reason}");
            std::process::ExitCode::FAILURE
        }
    }
}
