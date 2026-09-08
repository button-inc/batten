//! Price refusal rendering by strategy and explicit residency (CLOUD-1606).
//!
//! # A report, never a gate
//!
//! Nothing in `verify` or the hk gate calls this, for `address-transport-bench`'s
//! reason exactly: it answers a question about a MEASUREMENT rather than about a
//! commit. It writes `bench/refusal-render/RESULTS.md` and exits 0 on a complete
//! report, 1 if the config, the registry, the rendering or the write fails, and
//! never 2 — it decides nothing, so it has no verdict to report.
//!
//! # An example target rather than a verb
//!
//! `crates/batten/tests/pointer_only.rs` sweeps every leaf verb over a bare
//! fixture corpus and refuses one that exits 3, and a bench whose subject is this
//! repository's own committed registry has could-not-look as its only honest
//! answer there. `acquisition-bench` and `address-transport-bench` record that
//! reasoning at their own sites; this follows it.
//!
//! # A thin binary
//!
//! Everything measured and everything rendered lives in `perf`: the
//! strategy/residency projection, the record, and the report's bytes. That is
//! what lets `crates/batten/tests/it/refusal_render_bench.rs` re-render the table
//! in-process and diff it against the committed file, so the report cannot go
//! stale without `test:cargo` reddening. This file resolves the committed
//! authority, calls that code, and writes the result.

use std::path::Path;

use batten::perf::{refusal_render, refusal_render_report};

fn main() -> anyhow::Result<()> {
    // THE COMMITTED AUTHORITY, not a fixture: a bench that vendored its own
    // registry would price a class nobody is ever refused under, and the report's
    // baseline is the crate version plus these declared class ids.
    let config = batten::config::load(Path::new("batten.toml"))?;
    let registry = batten::policy::registry_for(&config.verdicts)?;
    // The committed `[refusal]` ceiling travels too, because it is part of the
    // shipped rendering contract: a first sighting whose routes would take the
    // line over it falls back to the compact form, and a bench that passed `None`
    // would report a rendering the harness never emits.
    let records = refusal_render(&registry, config.refusal.as_ref())?;
    let report = refusal_render_report(&records, config.refusal.as_ref());

    let dir = Path::new("bench/refusal-render");
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("RESULTS.md"), report)?;
    // The binary boundary is the one sanctioned place to write, and an example
    // IS that boundary — but the workspace lint is crate-wide, so the exemption
    // is stated here rather than assumed.
    #[expect(
        clippy::print_stdout,
        reason = "an example target is a binary boundary; this line is the bench's only output"
    )]
    {
        println!("refusal-render-bench: bench/refusal-render/RESULTS.md written");
    }
    Ok(())
}
