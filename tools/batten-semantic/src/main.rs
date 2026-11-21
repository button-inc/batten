//! Semantic codemods over rust-analyzer (CLOUD-2803).
//!
//! `probe [root]`: load the workspace, then print the load time, the crate
//! count, the module count of the `batten` crate and whether `hir` resolves
//! `config_model::Vocabulary`, as counts only. It measures what a semantic run
//! costs before any rewrite is built on it.

use std::error::Error;
use std::path::Path;
use std::time::Instant;

use ra_ap_hir::{Adt, Crate, ModuleDef};
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
use ra_ap_project_model::CargoConfig;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    if mode != "probe" {
        println!("usage: batten-semantic probe [root]");
        return Ok(());
    }
    let root = args.next().unwrap_or_else(|| String::from("."));
    // No sysroot and no proc-macro server: a codemod over this tree asks
    // about this tree's items, never std's, and both cost load time.
    let cargo = CargoConfig {
        sysroot: None,
        ..CargoConfig::default()
    };
    let load = LoadCargoConfig {
        load_out_dirs_from_check: false,
        with_proc_macro_server: ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 1,
    };
    let started = Instant::now();
    let (db, _vfs, _macros) = load_workspace_at(Path::new(&root), &cargo, &load, &|_| {})?;
    let loaded = started.elapsed();
    let crates = Crate::all(&db);
    let batten = crates.iter().copied().find(|krate| {
        krate
            .display_name(&db)
            .is_some_and(|name| name.to_string() == "batten")
    });
    let (modules, vocabulary) = batten.map_or((0, false), |krate| {
        let modules = krate.modules(&db);
        let found = modules.iter().any(|module| {
            module
                .name(&db)
                .is_some_and(|name| name.as_str() == "config_model")
                && module.declarations(&db).iter().any(|item| {
                    matches!(item, ModuleDef::Adt(Adt::Struct(found))
                        if found.name(&db).as_str() == "Vocabulary")
                })
        });
        (modules.len(), found)
    });
    println!(
        "probe: loaded in {:.1}s, {} crate(s), batten {} module(s), Vocabulary resolved {}",
        loaded.as_secs_f64(),
        crates.len(),
        modules,
        vocabulary
    );
    Ok(())
}
