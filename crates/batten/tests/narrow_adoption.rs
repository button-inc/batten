//! CLOUD-745's scope clause, held as a mechanism rather than as a promise.
//!
//! The row vendors an async runtime, and the whole of what makes that
//! affordable is that it reaches exactly one call site. That is a CLAIM the row
//! makes about the rest of the crate, so it is this row's to prove — the
//! acceptance says as much, and it says the other half too: *"a diff touching
//! those has outgrown this issue"*. So these cases assert **over the committed
//! files**, and none of them edits the module it is about.
//!
//! ## What is held elsewhere, and is deliberately not restated here
//!
//! Three of the four scope clauses already carry a live mechanism, and a second
//! reading of any of them would be a second authority that can drift:
//!
//! * *the hook path constructs no runtime* — `policy/module-layering.rego`
//!   forbids the edge `hook -> fetch` over the RESOLVED `use` graph, which is a
//!   `deny` in `batten check` rather than a text match;
//! * *never multi-thread, never `tokio::signal`* —
//!   `crates/batten/tests/spawn_census.rs` reads the `tokio` feature list out of
//!   the manifest, so both are compile errors rather than lint findings;
//! * *the lock is still `fs4`* — `crates/batten/tests/bundle.rs` asserts the
//!   behaviour the choice was made for, that a `SIGKILL`ed writer leaves a
//!   reader a defined answer;
//! * *`tree_files` is byte-identical across runs* —
//!   `crates/batten/tests/walker.rs`.
//!
//! What was left with no sensor is the drain clause, and this file is that
//! sensor. It is a **text** assertion over `exec.rs`, which is the weakest of
//! the three instrument classes `.claude/rules/scanning.md` ranks — chosen
//! anyway, and the reason is worth writing down: the event it exists to catch is
//! somebody rewriting two OS threads as tasks, and that rewrite necessarily
//! introduces the tokens below. It cannot catch a subtler change, and no §7
//! claim here says otherwise.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;

use common::at_root;

/// The module the drain clause is about.
fn exec_source() -> String {
    fs::read_to_string(at_root("crates/batten/src/exec.rs")).expect("exec.rs is committed")
}

#[test]
fn the_pipe_drains_are_still_os_threads_rather_than_tasks() {
    // The clause: `exec.rs` still spawns its two drain threads. CLOUD-427's
    // process-group protocol interoperates with mise's supervisor, so rewriting
    // these as tasks changes a negotiated protocol rather than a call site —
    // which is why the row put it out of scope instead of merely not doing it.
    let source = exec_source();
    assert!(
        source.contains("std::thread::spawn"),
        "exec.rs must still spawn OS threads for its pipe drains"
    );
    assert!(
        source.contains("std::thread::scope"),
        "the `--jobs` wave is a scoped-thread wave, per .claude/rules/rust.md's table"
    );
}

#[test]
fn the_runtime_never_reaches_the_module_that_owns_a_process_group() {
    // Hardening item 6's precondition, and the reason the hard case does not
    // exist: `provision::apply` and `Forwarding::install` never coexist in one
    // process, so no signalled path has a runtime under it. A `tokio` token
    // appearing in this module is the event that would make that false — and it
    // would arrive quietly, because both halves compile.
    let source = exec_source();
    assert!(
        !source.contains("tokio"),
        "exec.rs must name no runtime: a fetch running while a process group is \
         managed needs a CancellationToken and a select!, which is a different \
         design from the one CLOUD-745 scoped"
    );
}

#[test]
fn one_module_reaches_the_network_and_it_is_the_adapter() {
    // The claim the row asks nobody to over-read: there is exactly ONE network
    // call site in the crate. Everything else is local files, the deliberately
    // serial walk, or subprocess pipes. `provision` is the caller and `fetch` is
    // the adapter; a THIRD module naming the client is the event here.
    let root = at_root("crates/batten/src");
    let mut callers: Vec<String> = Vec::new();
    for entry in fs::read_dir(&root)
        .expect("the crate's sources are here")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        // The call, not the word: `lib.rs` declares the module and `mem:core`'s
        // map names it, and neither is a caller.
        if source.contains("fetch::get(") {
            callers.push(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    callers.sort();
    assert_eq!(
        callers,
        vec!["provision.rs".to_owned()],
        "exactly one module may call the network adapter"
    );
}
