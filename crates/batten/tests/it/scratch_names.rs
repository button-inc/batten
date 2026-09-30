//! Every scratch directory a case builds is that case's own.
//!
//! # The convention, and why a comment was not enough
//!
//! `common::scratch` resolves a name to a fixed path in the default lane and
//! wipes it before building, and nextest runs every `#[test]` in its own
//! PROCESS, concurrently. So two cases that resolve one scratch name are two
//! processes deleting a directory out from under each other. Six suites in this
//! directory state the rule in prose ("the scratch name is this case's own") and
//! nothing enforced it, so it was broken twice in one campaign by the same
//! author, both times through a HELPER:
//!
//! - `verdict.rs` built every case's fixture through `anywhere()`, which named
//!   one fixed directory. A sibling's wipe landed inside a template copy and
//!   `init_repo`'s CLOUD-1832 assertion reported a copy that "did not produce a
//!   repository" — in a case about an exit code.
//! - `bats_invocation.rs`'s `helper_status` carried a comment saying its scratch
//!   dir "keeps concurrent cases from sharing one path", then gave all nine
//!   callers the same one.
//!
//! # The predicate, and why it is this one
//!
//! Two arms, both decidable from syntax alone:
//!
//! 1. **A scratch name spelled as a literal inside a function that is not
//!    itself a `#[test]` is refused.** A helper takes the name from its caller.
//!    The sharper question — "is this helper reached by more than one case" —
//!    needs call resolution, which is row three of `rules/scanning.md` and not
//!    something a syntax pass can answer honestly. This arm asks the question a
//!    syntax pass CAN answer, and it has exactly zero false positives on the
//!    tree it landed on: both hits it found were the two races above.
//! 2. **One literal spelled in two `#[test]` functions of the same file is
//!    refused.** The direct form of the same race, with no helper in between.
//!
//! A name built at runtime (`&format!(…)`) is not a literal and is not judged:
//! that is how a helper threads its caller's name through, which is the fix.
//!
//! # Why `syn` rather than a text search
//!
//! "Is this literal the first argument of a call, and which function encloses
//! it" is a syntax question — row two. A substring scan would match a scratch
//! call quoted in a doc comment, or in a fixture source held in a string, and
//! it could not tell which function a line belongs to. A parse sees neither
//! problem: a call inside a string literal is a string, and the enclosing item is
//! a node, not a guess from indentation.

use crate::common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// One literal scratch name, where it was spelled, and whether a case owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    function: String,
    in_test: bool,
    name: String,
}

/// Collects every literal scratch name, keyed to its enclosing function.
#[derive(Default)]
struct Sites {
    /// The innermost named function being walked, and whether it is a case.
    within: Vec<(String, bool)>,
    /// In-file helpers that thread a parameter into a wiping call, each with the
    /// directory name it builds from that parameter (CLOUD-2053).
    threading: BTreeMap<String, String>,
    found: Vec<Site>,
}

/// The directory-name template a callee applies to its first argument: `{}` for
/// a wiping constructor, the helper's own template for a threading helper.
fn template_of(func: &syn::Expr, threading: &BTreeMap<String, String>) -> Option<String> {
    if wipes_a_named_path(func) {
        return Some("{}".to_owned());
    }
    let syn::Expr::Path(path) = func else {
        return None;
    };
    if path.path.segments.len() != 1 {
        return None;
    }
    let name = path.path.segments.first()?.ident.to_string();
    threading.get(&name).cloned()
}

/// What an argument makes of the parameter `param`, as a template over it: the
/// bare name (or a reference to it) is `{}`, and a `format!` whose ONLY content is
/// one string literal interpolating `{param}` is that literal with the parameter
/// replaced by `{}`.
///
/// ANYTHING ELSE IS UNJUDGED, and that is the no-false-positive half of the arm.
/// A `format!` carrying a second argument — a pid, a counter, another parameter
/// — builds a name that is not a function of the caller's literal alone, so two
/// cases passing one literal need not share a directory (`memory_injection.rs`'s
/// `stream` appends the pid for exactly that reason). This arm may miss such a
/// race; it may not invent one.
fn template_through(arg: &syn::Expr, param: &str) -> Option<String> {
    let mut arg = arg;
    while let syn::Expr::Reference(inner) = arg {
        arg = &inner.expr;
    }
    match arg {
        syn::Expr::Path(path) if path.path.is_ident(param) => Some("{}".to_owned()),
        syn::Expr::Macro(mac) if mac.mac.path.is_ident("format") => {
            let only: syn::LitStr = syn::parse2(mac.mac.tokens.clone()).ok()?;
            let text = only.value();
            let placeholder = format!("{{{param}}}");
            let rest = text.replace(&placeholder, "");
            (text.contains(&placeholder) && !rest.contains('{') && !rest.contains('}'))
                .then(|| text.replace(&placeholder, "{}"))
        }
        _ => None,
    }
}

/// Finds the helpers that thread one of their own parameters into a wiping call.
///
/// A name a helper builds from its argument is the caller's, which is why the
/// helper itself is never judged — but then two CASES handing one literal to it
/// share a directory, and that is the race arm 2 exists for, one call removed
/// (CLOUD-2053: `config_forward_compatible.rs`'s `repo` did exactly this, and
/// CI's run caught the two cases wiping each other). Found by fixpoint, so a
/// helper that threads through another helper counts too. Within one file only:
/// a call into another module is resolution, which a syntax pass does not do.
///
/// Each helper resolves to the TEMPLATE its directory name follows, so two
/// helpers wrapping one literal in different prefixes (`admits-{}` against
/// `admission-{}`) are two directories, as they are on disk.
struct Threading<'a> {
    known: &'a BTreeMap<String, String>,
    params: Vec<String>,
    template: Option<String>,
}

impl<'ast> Visit<'ast> for Threading<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.template.is_none()
            && let Some(outer) = template_of(&call.func, self.known)
            && let Some(first) = call.args.first()
            && let Some(inner) = self
                .params
                .iter()
                .find_map(|param| template_through(first, param))
        {
            self.template = Some(outer.replace("{}", &inner));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn threading_helpers(file: &syn::File) -> BTreeMap<String, String> {
    let mut known = BTreeMap::new();
    loop {
        let before = known.len();
        for item in &file.items {
            let syn::Item::Fn(function) = item else {
                continue;
            };
            let name = function.sig.ident.to_string();
            if is_case(&function.attrs) || known.contains_key(&name) {
                continue;
            }
            let params = function
                .sig
                .inputs
                .iter()
                .filter_map(|input| match input {
                    syn::FnArg::Typed(typed) => match &*typed.pat {
                        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })
                .collect();
            let mut walk = Threading {
                known: &known,
                params,
                template: None,
            };
            walk.visit_block(&function.block);
            if let Some(template) = walk.template {
                known.insert(name, template);
            }
        }
        if known.len() == before {
            return known;
        }
    }
}

/// Whether a callee names one of the two constructors that wipe a fixed path.
///
/// `Fixture::new` by its last two segments, so a qualified spelling still
/// matches; `scratch` by its last segment alone, because suites call it bare
/// and through `common::`. `scratch_outside_tree` is a different identifier and
/// takes a group as its first argument, so it is not this constructor.
fn wipes_a_named_path(func: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = func else {
        return false;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        [.., owner, method] => (owner == "Fixture" && method == "new") || method == "scratch",
        [only] => only == "scratch",
        [] => false,
    }
}

/// The string a call's first argument spells, if it is a bare literal or a
/// reference to one.
fn literal_name(
    args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
) -> Option<String> {
    let mut first = args.first()?;
    while let syn::Expr::Reference(inner) = first {
        first = &inner.expr;
    }
    let syn::Expr::Lit(lit) = first else {
        return None;
    };
    let syn::Lit::Str(text) = &lit.lit else {
        return None;
    };
    Some(text.value())
}

fn is_case(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within
            .push((item.sig.ident.to_string(), is_case(&item.attrs)));
        syn::visit::visit_item_fn(self, item);
        self.within.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        // A method is a helper by construction: nextest never runs one as a
        // case, so a literal inside it is shared by every caller.
        self.within.push((item.sig.ident.to_string(), false));
        syn::visit::visit_impl_item_fn(self, item);
        self.within.pop();
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // MUTANT threading-helper-unjudged|s@threading: threading_helpers(\&file)@threading: BTreeMap::new()@|two_cases_sharing_a_name_through_a_threading_helper_are_refused
        if let Some(template) = template_of(&call.func, &self.threading)
            && let Some(literal) = literal_name(&call.args)
            && let Some((function, in_test)) = self.within.last()
        {
            self.found.push(Site {
                function: function.clone(),
                in_test: *in_test,
                // THE DIRECTORY, NOT THE LITERAL: two helpers wrapping one literal
                // differently resolve two paths, and only one path can be shared.
                name: template.replace("{}", &literal),
            });
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Every literal scratch site in one source file.
fn sites_in(source: &str) -> Vec<Site> {
    let file = syn::parse_file(source).expect("every test source parses");
    let mut sites = Sites {
        threading: threading_helpers(&file),
        ..Sites::default()
    };
    sites.visit_file(&file);
    sites.found
}

/// The refusals for one file, as `<function> <name>` pointers.
///
/// **Pointer-only** (rule 4): which function spelled which name, never the
/// surrounding source.
fn refusals(sites: &[Site]) -> Vec<String> {
    let mut found = Vec::new();
    let mut owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for site in sites {
        if site.in_test {
            owners.entry(&site.name).or_default().push(&site.function);
        } else {
            found.push(format!("helper {} spells {}", site.function, site.name));
        }
    }
    for (name, mut functions) in owners {
        functions.sort_unstable();
        functions.dedup();
        if functions.len() > 1 {
            found.push(format!("cases {} share {name}", functions.join(",")));
        }
    }
    found
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a test directory") {
        let path = entry.expect("a test directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_two_cases_can_reach_one_scratch_directory() {
    let root = common::at_root("crates/batten/tests");
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    sources.sort();

    let mut total = 0;
    let mut offenders = Vec::new();
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("read a test source");
        let sites = sites_in(&source);
        total += sites.len();
        let relative = path.strip_prefix(&root).unwrap_or(path);
        offenders.extend(
            refusals(&sites)
                .into_iter()
                .map(|refusal| format!("{}: {refusal}", relative.display())),
        );
    }

    // ANTI-VACUITY. A walker pointed at the wrong directory, or a callee match
    // that stopped matching, finds nothing and passes. 481 literal sites were
    // counted when this landed; the floor sits well under that so ordinary
    // churn does not trip it, and well over zero so a broken scan does.
    assert!(
        total > 300,
        "found only {total} literal scratch sites across {} sources — the scan \
         is not reading the suite it guards",
        sources.len()
    );
    assert!(
        offenders.is_empty(),
        "a scratch name reachable by more than one case:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn a_helper_that_spells_its_own_name_is_refused() {
    // The measured shape, reduced: a helper naming one fixed directory and two
    // cases reaching it. Shown here so the arm is known to FIRE, not merely
    // known to be quiet on a tree that has none.
    let needle = ["Fixture", "::new"].concat();
    let source = format!(
        "fn shared() -> PathBuf {{ {needle}(\"one-dir\").build() }}\n\
         #[test] fn first() {{ shared(); }}\n\
         #[test] fn second() {{ shared(); }}\n"
    );
    assert_eq!(
        refusals(&sites_in(&source)),
        ["helper shared spells one-dir"]
    );
}

#[test]
fn two_cases_spelling_one_name_are_refused() {
    let source = "#[test] fn first() { common::scratch(\"one-dir\"); }\n\
                  #[test] fn second() { scratch(&\"one-dir\"); }\n";
    assert_eq!(
        refusals(&sites_in(source)),
        ["cases first,second share one-dir"]
    );
}

#[test]
fn a_name_threaded_from_the_caller_is_not_judged() {
    // The fix's own shape: the helper builds the name from its argument, so no
    // literal reaches the constructor and there is nothing to share.
    let source = "fn shared(case: &str) { scratch(&format!(\"dir-{case}\")); }\n\
                  #[test] fn first() { shared(\"first\"); }\n\
                  #[test] fn second() { shared(\"second\"); }\n";
    assert!(refusals(&sites_in(source)).is_empty());
}

#[test]
fn two_cases_sharing_a_name_through_a_threading_helper_are_refused() {
    // CLOUD-2053's measured shape: a helper that is rightly not judged, because
    // it threads its caller's name, and two cases handing it the same literal.
    // Through one more helper too, since `repo` → `fixture` → `scratch` is the
    // same race one call further out.
    let source = "fn repo(name: &str) { scratch(name); }\n\
                  fn outer(case: &str) { repo(&format!(\"{case}-repo\")); }\n\
                  #[test] fn first() { repo(\"shared\"); }\n\
                  #[test] fn second() { repo(\"shared\"); }\n\
                  #[test] fn third() { outer(\"deep\"); }\n\
                  #[test] fn fourth() { outer(\"deep\"); }\n\
                  #[test] fn fifth() { repo(\"own\"); }\n";
    assert_eq!(
        refusals(&sites_in(source)),
        [
            "cases fourth,third share deep-repo",
            "cases first,second share shared"
        ]
    );
}

#[test]
fn one_literal_through_two_differently_named_helpers_is_two_directories() {
    // The false positive the literal-keyed first cut raised on four files:
    // `admission.rs`'s `fixture` and `admits_fixture_of` wrap `other-subject` as
    // `admission-other-subject` and `admits-other-subject`. Different paths, no
    // race, so no refusal.
    let source = "fn left(name: &str) { scratch(&format!(\"left-{name}\")); }\n\
                  fn right(name: &str) { scratch(&format!(\"right-{name}\")); }\n\
                  #[test] fn first() { left(\"same\"); }\n\
                  #[test] fn second() { right(\"same\"); }\n";
    assert!(refusals(&sites_in(source)).is_empty());
}

#[test]
fn a_helper_that_makes_its_own_name_unique_is_not_judged() {
    // `memory_injection.rs`'s `stream` appends the pid, so one literal from two
    // cases is two directories. A name that is not a function of the literal
    // alone is unjudged: the arm may miss a race, it may not invent one.
    let source = "fn seat(name: &str) { scratch(&format!(\"{name}-{}\", std::process::id())); }\n\
                  #[test] fn first() { seat(\"same\"); }\n\
                  #[test] fn second() { seat(\"same\"); }\n";
    assert!(refusals(&sites_in(source)).is_empty());
}

#[test]
fn one_case_reusing_its_own_name_is_not_a_share() {
    // Sequential calls inside ONE process cannot race each other, so a case
    // that rebuilds its own directory is not the defect.
    let source = "#[test] fn only() { scratch(\"mine\"); scratch(\"mine\"); }\n";
    assert!(refusals(&sites_in(source)).is_empty());
}

#[test]
fn a_call_quoted_in_a_string_is_not_a_call() {
    // Why this is a parse and not a substring scan: the fixture sources in this
    // very file hold constructor calls inside string literals.
    let source = "#[test] fn a() { let _ = \"scratch(\\\"x\\\")\"; }\n\
                  #[test] fn b() { let _ = \"scratch(\\\"x\\\")\"; }\n";
    assert!(sites_in(source).is_empty());
}
