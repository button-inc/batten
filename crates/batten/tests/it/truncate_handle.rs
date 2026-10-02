//! Every truncation names the write handle it goes through (CLOUD-2055).
//!
//! # Why this tier exists
//!
//! Windows grants an append-only handle `FILE_APPEND_DATA` and not
//! `FILE_WRITE_DATA`, so `set_len` through one is access-denied there while Unix
//! allows it. `cross-check` only type-checks the windows target, so on #1056 the
//! refusal surfaced on CI's windows leg alone.
//!
//! # Why a tier and not a clippy ban
//!
//! A `disallowed-methods` row was tried first. Every legitimate site then needs an
//! `#[expect(clippy::disallowed_methods)]`, and `waiver add refused` holds that
//! count non-increasing — the two gates contradicted each other. This tier decides
//! the property itself, so a correct site needs no waiver: the receiver of every
//! `.set_len(` is an `OpenOptions` chain written inline, carrying `.write(true)`
//! and no `.append(…)`. A handle held in a variable is refused, because its
//! access mode is not visible at the call.

/*
#MUTANT-SUITE crates/batten/tests/it/truncate_handle.rs
#MUTANT receiver-unread|s@^            if !chain.through_a_write_handle() {$@            if false {@|a_truncation_through_a_variable_is_named
#MUTANT append-unread|s@^                    "append" => chain.appends = true,$@                    "append" => {}@|a_truncation_through_an_append_chain_is_named
*/

use crate::common;

use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// What the receiver chain of one `set_len` call opens its handle with.
#[derive(Default)]
struct Chain {
    writes: bool,
    appends: bool,
}

impl Chain {
    fn through_a_write_handle(&self) -> bool {
        self.writes && !self.appends
    }
}

fn is_true(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(flag),
            ..
        }) if flag.value
    )
}

/// Walk a receiver down through method calls, `?` and parentheses.
fn chain_of(mut expr: &syn::Expr) -> Chain {
    let mut chain = Chain::default();
    loop {
        match expr {
            syn::Expr::MethodCall(call) => {
                match call.method.to_string().as_str() {
                    "write" if call.args.len() == 1 && call.args.first().is_some_and(is_true) => {
                        chain.writes = true;
                    }
                    "append" => chain.appends = true,
                    _ => {}
                }
                expr = &call.receiver;
            }
            syn::Expr::Try(inner) => expr = &inner.expr,
            syn::Expr::Paren(inner) => expr = &inner.expr,
            _ => return chain,
        }
    }
}

#[derive(Default)]
struct Truncations {
    sites: usize,
    refused: Vec<usize>,
}

impl<'ast> Visit<'ast> for Truncations {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "set_len" {
            self.sites += 1;
            let chain = chain_of(&call.receiver);
            if !chain.through_a_write_handle() {
                self.refused.push(call.method.span().start().line);
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// `(sites, refused pointers)` for one source.
fn findings(label: &str, source: &str) -> (usize, Vec<String>) {
    let file = syn::parse_file(source).expect("every crate source parses");
    let mut truncations = Truncations::default();
    truncations.visit_file(&file);
    let refused = truncations
        .refused
        .iter()
        .map(|line| format!("{label}:{line}"))
        .collect();
    (truncations.sites, refused)
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("a source directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// THE GATE: every `set_len` in every crate's `src` truncates through an inline
/// write handle.
#[test]
fn every_truncation_goes_through_a_write_handle() {
    let crates = common::at_root("crates");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("read crates/") {
        let src = entry.expect("a crate entry").path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut sources);
        }
    }
    sources.sort();
    let mut sites = 0;
    let mut refused = Vec::new();
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("read a crate source");
        let label = path
            .strip_prefix(&crates)
            .unwrap_or(path)
            .display()
            .to_string();
        let (count, mut found) = findings(&label, &source);
        sites += count;
        refused.append(&mut found);
    }
    assert!(sites > 0, "a gate that found no truncation judged nothing");
    assert!(
        refused.is_empty(),
        "{sites} truncation(s) judged; not through an inline write handle: {refused:#?}"
    );
}

#[test]
fn a_truncation_through_a_write_chain_passes() {
    let source = "fn f(p: &std::path::Path) -> std::io::Result<()> {\n    std::fs::OpenOptions::new().write(true).open(p)?.set_len(0)\n}\n";
    assert_eq!(findings("fixture.rs", source), (1, Vec::new()));
}

#[test]
fn a_truncation_through_a_variable_is_named() {
    let source = "fn f(file: &std::fs::File) -> std::io::Result<()> {\n    file.set_len(0)\n}\n";
    assert_eq!(
        findings("fixture.rs", source),
        (1, vec!["fixture.rs:2".to_owned()])
    );
}

#[test]
fn a_truncation_through_an_append_chain_is_named() {
    let source = "fn f(p: &std::path::Path) -> std::io::Result<()> {\n    std::fs::OpenOptions::new().write(true).append(true).open(p)?.set_len(0)\n}\n";
    assert_eq!(
        findings("fixture.rs", source),
        (1, vec!["fixture.rs:2".to_owned()])
    );
}
