//! Semantic codemods over rust-analyzer (CLOUD-2803).
//!
//! `probe [root]`: load the workspace, then print the load time, the crate
//! count, the module count of the `batten` crate and whether `hir` resolves
//! `config_model::Vocabulary`, as counts only. It measures what a semantic run
//! costs before any rewrite is built on it.

mod demote;

use std::error::Error;
use std::path::Path;
use std::time::Instant;

use std::collections::BTreeSet;

use ra_ap_hir::{Adt, Crate, Module, ModuleDef, PathResolution, Semantics};
use ra_ap_ide_db::RootDatabase;
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice, load_workspace_at};
use ra_ap_project_model::CargoConfig;
use ra_ap_syntax::{AstNode as _, ast};

/// Load the workspace with no sysroot and no proc-macro server: a codemod over
/// this tree asks about this tree's items, never std's, and both cost load time.
fn load(root: &str) -> Result<RootDatabase, Box<dyn Error>> {
    load_with_vfs(root).map(|(db, _vfs)| db)
}

/// [`load`], keeping the `Vfs`, which maps a file id back to its path.
fn load_with_vfs(root: &str) -> Result<(RootDatabase, ra_ap_vfs::Vfs), Box<dyn Error>> {
    // THE SYSROOT IS LOADED. Without it `std` names do not resolve, and a
    // rewrite that cannot see `Path` or `BTreeSet` adds no import for them:
    // the first `demote --write` produced exactly those errors.
    let cargo = CargoConfig {
        sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
        ..CargoConfig::default()
    };
    let load = LoadCargoConfig {
        load_out_dirs_from_check: false,
        with_proc_macro_server: ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 1,
    };
    let (db, vfs, _macros) = load_workspace_at(Path::new(root), &cargo, &load, &|_| {})?;
    Ok((db, vfs))
}

/// The crate-root child a module sits under: its layer in the module graph.
fn top_level(db: &RootDatabase, module: Module) -> Option<String> {
    let path = module.path_to_root(db);
    let below_root = path.get(path.len().checked_sub(2)?)?;
    below_root.name(db).map(|name| name.as_str().to_owned())
}

/// `traits [root]`: for each `…Ext` trait in `batten`, the self type's layer
/// and every other `batten` layer its impl's bodies name, resolved by `hir`.
/// An empty list means the bodies reach nothing above the type's own layer,
/// so the methods can move beside the type with no new edge. Writes nothing.
fn traits(root: &str) -> Result<(), Box<dyn Error>> {
    let db = load(root)?;
    // rust-analyzer's trait solver reads the database from the thread, so
    // every semantic query runs with it attached, as its own entry points do.
    ra_ap_hir::attach_db(&db, || {
        let sema = Semantics::new(&db);
        let Some(batten) = Crate::all(&db).into_iter().find(|krate| {
            krate
                .display_name(&db)
                .is_some_and(|name| name.to_string() == "batten")
        }) else {
            println!("traits: no batten crate");
            return;
        };
        let (mut legal, mut held) = (0_usize, 0_usize);
        for module in batten.modules(&db) {
            for implementation in module.impl_defs(&db) {
                let Some(trait_) = implementation.trait_(&db) else {
                    continue;
                };
                let name = trait_.name(&db).as_str().to_owned();
                if !name.ends_with("Ext") || trait_.module(&db).krate(&db) != batten {
                    continue;
                }
                let Some(home) = implementation
                    .self_ty(&db)
                    .as_adt()
                    .and_then(|adt| top_level(&db, adt.module(&db)))
                else {
                    continue;
                };
                let mut names: BTreeSet<String> = BTreeSet::new();
                if let Some(source) = sema.source(implementation) {
                    let node = source.value.syntax().clone();
                    for path in node.descendants().filter_map(ast::Path::cast) {
                        // The impl header names the trait itself; that is the
                        // edge demotion removes, never one it would keep.
                        if let Some(PathResolution::Def(def)) = sema.resolve_path(&path)
                            && def != ModuleDef::Trait(trait_)
                            && let Some(owner) = def.module(&db)
                            && owner.krate(&db) == batten
                            && let Some(layer) = top_level(&db, owner)
                        {
                            names.insert(layer);
                        }
                    }
                    for call in node.descendants().filter_map(ast::MethodCallExpr::cast) {
                        if let Some(function) = sema.resolve_method_call(&call)
                            && function.module(&db).krate(&db) == batten
                            && let Some(layer) = top_level(&db, function.module(&db))
                        {
                            names.insert(layer);
                        }
                    }
                }
                names.remove(&home);
                if names.is_empty() {
                    legal += 1;
                } else {
                    held += 1;
                }
                let reached: Vec<&str> = names.iter().map(String::as_str).collect();
                println!("{name} on {home}: {}", reached.join(","));
            }
        }
        println!("traits: {legal} demotable, {held} held by an upward name");
    });
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    if mode == "demote" {
        let root = args.next().unwrap_or_else(|| String::from("."));
        let write = args.any(|arg| arg == "--write");
        let (db, vfs) = load_with_vfs(&root)?;
        return ra_ap_hir::attach_db(&db, || demote::run(&db, &vfs, write));
    }
    if mode == "traits" {
        let root = args.next().unwrap_or_else(|| String::from("."));
        return traits(&root);
    }
    if mode != "probe" {
        println!("usage: batten-semantic probe|traits [root]");
        return Ok(());
    }
    let root = args.next().unwrap_or_else(|| String::from("."));
    // No sysroot and no proc-macro server: a codemod over this tree asks
    // about this tree's items, never std's, and both cost load time.
    // THE SYSROOT IS LOADED. Without it `std` names do not resolve, and a
    // rewrite that cannot see `Path` or `BTreeSet` adds no import for them:
    // the first `demote --write` produced exactly those errors.
    let cargo = CargoConfig {
        sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
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
