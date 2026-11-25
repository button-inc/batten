//! Every session id a case sends is that case's own (CLOUD-2789).
//!
//! # The defect, and why it needs a gate
//!
//! A session's home is recorded in the state root BY ITS ID, and under plain
//! `cargo test` every case of this binary shares one state root. So two cases
//! that send one fixed `session_id` are one session: a later fixture's start
//! was judged in the first fixture's repository, already prepared, and said
//! nothing (fixed in ca2f8b3e4 for `contract_drift`, `session_provisioning` and
//! `session_start`, by qualifying each id with its fixture). Nothing stopped the
//! shape coming back, which is what this file is.
//!
//! # The predicate
//!
//! The same two arms as `scratch_names.rs`, decidable from syntax alone, but
//! keyed ACROSS the suite rather than per file: the shared resource is the one
//! state root of the whole binary, not a directory one file names.
//!
//! 1. **A literal session id spelled outside a `#[test]` function is refused.**
//!    A helper or a constant is reachable by every case that calls it, so the
//!    id it spells is everyone's. It takes the id from its caller, or derives it
//!    from the fixture (`format!("…@{}", repo.display())`).
//! 2. **One literal session id spelled in two `#[test]` functions is refused**,
//!    anywhere in the suite, naming both cases.
//!
//! A SITE is the value of a `"session_id"` key of a HOOK PAYLOAD (an object
//! that also carries `hook_event_name`) whose value is a string literal: inside
//! a `json!` invocation (`"session_id": "s-1"`), or inside the text of a string
//! literal holding JSON (`r#"{"hook_event_name":"Stop","session_id":"s-1"}"#`). A value built at
//! runtime (`format!`, a variable) is not a literal and is not judged: that is
//! the fix's own shape. A literal whose text carries a `{` is a format template
//! and is likewise unjudged.
//!
//! # The honest limit
//!
//! A payload assembled in pieces — a `session_id` spliced into an object whose
//! `hook_event_name` is added elsewhere — is not seen as one, and this gate's
//! own fixtures are its own file, which the sweep skips.
//!
//! Hook payloads under `tests/fixtures/**/*.json` are data, not sources, and are
//! not read here; a case that sends one should rewrite its id the way
//! `session_start.rs`'s `door` does. Unit tests under `src/` share a process
//! too, and are out of this sweep for the same reason `scratch_names.rs` reads
//! `tests/` only: they hold the suite's own fixtures in strings.

use crate::common;

use std::collections::BTreeMap;

use batten::testing::is_case;
use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

/// The JSON key whose literal value is a session's identity.
const KEY: &str = "session_id";

/// The key that makes an object a HOOK PAYLOAD, the one place a session's home
/// is recorded by its id. A `session_id` elsewhere — a tool's own argument, a
/// remote session a fixture pages through — names no home and is not judged.
const EVENT: &str = "hook_event_name";

/// One literal session id and the function that spelled it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    owner: String,
    in_test: bool,
    id: String,
}

/// Collects every literal session id, keyed to its enclosing function.
#[derive(Default)]
struct Sites {
    within: Vec<(String, bool)>,
    found: Vec<Site>,
    /// Every hook payload's `session_id` key seen, literal or not: the
    /// anti-vacuity count, since the fixed suite spells almost no literal.
    keys: usize,
}

impl Sites {
    fn record(&mut self, id: String) {
        let (owner, in_test) = self
            .within
            .last()
            .cloned()
            .unwrap_or_else(|| ("<item>".to_owned(), false));
        self.found.push(Site { owner, in_test, id });
    }

    /// The literal ids inside a string literal's text holding a hook payload.
    fn record_text(&mut self, text: &str) {
        if !text.contains(&format!("\"{EVENT}\"")) {
            return;
        }
        self.keys += text.matches(&format!("\"{KEY}\"")).count();
        for id in ids_in_text(text) {
            self.record(id);
        }
    }

    /// The literal ids in a macro's tokens: a `"session_id": "<lit>"` triple,
    /// as `json!` spells it, in a group that is a hook payload (it carries
    /// `hook_event_name` too), and any string literal's own text.
    fn record_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let payload = trees.iter().any(|tree| {
            matches!(tree, TokenTree::Literal(literal) if string_of(literal).as_deref() == Some(EVENT))
        });
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.record_tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    let Some(text) = string_of(literal) else {
                        continue;
                    };
                    if payload && text == KEY {
                        self.keys += 1;
                    }
                    if payload
                        && text == KEY
                        && let Some(TokenTree::Punct(colon)) = trees.get(at + 1)
                        && colon.as_char() == ':'
                        && let Some(TokenTree::Literal(value)) = trees.get(at + 2)
                        && let Some(id) = string_of(value)
                        && is_literal_id(&id)
                    {
                        self.record(id);
                    }
                    self.record_text(&text);
                }
                _ => {}
            }
        }
    }
}

/// A token literal's string value, if it is a string literal.
fn string_of(literal: &proc_macro2::Literal) -> Option<String> {
    match syn::parse_str::<syn::Lit>(&literal.to_string()).ok()? {
        syn::Lit::Str(text) => Some(text.value()),
        _ => None,
    }
}

/// A value spelled whole, as opposed to a format template over a variable.
fn is_literal_id(id: &str) -> bool {
    !id.contains('{') && !id.contains('}')
}

/// Every `"session_id": "<literal>"` in `text`, whitespace-tolerant.
fn ids_in_text(text: &str) -> Vec<String> {
    let quoted = format!("\"{KEY}\"");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(&quoted) {
        rest = &rest[at + quoted.len()..];
        let Some(value) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(value) = value.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some(end) = value.find('"') else {
            continue;
        };
        let id = &value[..end];
        if is_literal_id(id) {
            found.push(id.to_owned());
        }
    }
    found
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within
            .push((item.sig.ident.to_string(), is_case(&item.attrs)));
        syn::visit::visit_item_fn(self, item);
        self.within.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.within
            .push((item.sig.ident.to_string(), is_case(&item.attrs)));
        syn::visit::visit_impl_item_fn(self, item);
        self.within.pop();
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.record_text(&literal.value());
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.record_tokens(mac.tokens.clone());
    }
}

/// Every literal session id in `source`.
fn sites_in(source: &str) -> Vec<Site> {
    scan(source).found
}

/// The walk over `source`: its literal ids and how many payload keys it saw.
fn scan(source: &str) -> Sites {
    let Ok(file) = syn::parse_file(source) else {
        return Sites::default();
    };
    let mut sites = Sites::default();
    sites.visit_file(&file);
    sites
}

/// The refusals over `sites`, each `(file, site)`: a helper spelling an id, and
/// one id spelled by two cases. Deterministic order, so the message is stable.
fn refusals(sites: &[(String, Site)]) -> Vec<String> {
    let mut refused = Vec::new();
    let mut cases: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (file, site) in sites {
        if site.in_test {
            let case = format!("{file}::{}", site.owner);
            let owners = cases.entry(site.id.as_str()).or_default();
            if !owners.contains(&case) {
                owners.push(case);
            }
        } else {
            refused.push(format!("helper {file}::{} spells {}", site.owner, site.id));
        }
    }
    for (id, mut owners) in cases {
        if owners.len() > 1 {
            owners.sort();
            refused.push(format!("cases {} share {id}", owners.join(",")));
        }
    }
    refused
}

/// `source` read as one file named `f`.
fn in_one(source: &str) -> Vec<(String, Site)> {
    sites_in(source)
        .into_iter()
        .map(|site| ("f".to_owned(), site))
        .collect()
}

#[test]
fn no_two_cases_can_reach_one_session_id() {
    let root = common::at_root("crates");
    let sources = common::test_sources();

    let mut sites = Vec::new();
    let mut keys = 0;
    for path in &sources {
        // ITS OWN FIXTURES are payloads held in strings, by design.
        if path.ends_with("session_ids.rs") {
            continue;
        }
        let source = std::fs::read_to_string(path).expect("read a test source");
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let scanned = scan(&source);
        keys += scanned.keys;
        sites.extend(
            scanned
                .found
                .into_iter()
                .map(|site| (relative.clone(), site)),
        );
    }

    // ANTI-VACUITY: a scan that stopped seeing the key finds nothing and
    // passes. Counted over every payload KEY, literal or not, because the fix
    // leaves almost no literal behind: 94 keys were counted when this landed.
    assert!(
        keys > 60,
        "found only {keys} hook-payload session_id keys across {} sources — the \
         scan is not reading the suite it guards",
        sources.len()
    );
    let offenders = refusals(&sites);
    assert!(
        offenders.is_empty(),
        "a session id reachable by more than one case:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn two_cases_sending_one_id_are_refused_by_name() {
    let source = "#[test] fn first() { json!({\"hook_event_name\": \"Stop\", \"session_id\": \"s-1\"}); }\n\
                  #[test] fn second() { let _ = r#\"{\"hook_event_name\":\"Stop\",\"session_id\":\"s-1\"}\"#; }\n";
    assert_eq!(
        refusals(&in_one(source)),
        ["cases f::first,f::second share s-1"]
    );
}

#[test]
fn two_files_sending_one_id_are_refused() {
    let one = "#[test] fn first() { json!({\"hook_event_name\": e, \"session_id\": \"s-1\"}); }\n";
    let two = "#[test] fn second() { json!({\"hook_event_name\": e, \"session_id\": \"s-1\"}); }\n";
    let sites: Vec<_> = sites_in(one)
        .into_iter()
        .map(|site| ("a".to_owned(), site))
        .chain(sites_in(two).into_iter().map(|site| ("b".to_owned(), site)))
        .collect();
    assert_eq!(refusals(&sites), ["cases a::first,b::second share s-1"]);
}

#[test]
fn a_helper_spelling_an_id_is_refused() {
    let source = "fn door() { json!({\"hook_event_name\": \"Stop\", \"session_id\": \"fixed\"}); }\n\
                  #[test] fn first() { door(); }\n";
    assert_eq!(refusals(&in_one(source)), ["helper f::door spells fixed"]);
}

#[test]
fn an_id_derived_from_the_fixture_is_not_judged() {
    // The fix's own shape (ca2f8b3e4): built at runtime, so no literal.
    let source = "fn door(repo: &Path) { json!({\"session_id\": format!(\"start@{}\", repo.display())}); }\n\
                  #[test] fn first() { let _ = format!(r#\"{{\"session_id\":\"{id}\"}}\"#); }\n\
                  #[test] fn second() { let _ = format!(r#\"{{\"session_id\":\"{id}\"}}\"#); }\n";
    assert!(in_one(source).is_empty());
}

#[test]
fn a_session_id_outside_a_hook_payload_is_not_judged() {
    // preapprove's tool argument and session_watch's paged remote session:
    // keys named `session_id` that name no home in the state root.
    let source = "fn tool() { json!({\"tool_input\": { \"session_id\": \"x\" }}); }\n\
                  #[test] fn first() { json!({\"session_id\": \"s1\", \"limit\": 2}); }\n\
                  #[test] fn second() { json!({\"session_id\": \"s1\", \"limit\": 3}); }\n";
    assert!(in_one(source).is_empty());
}

#[test]
fn one_case_reusing_its_own_id_is_not_a_share() {
    let source = "#[test] fn only() { json!({\"hook_event_name\": e, \"session_id\": \"mine\"}); \
                  json!({\"hook_event_name\": e, \"session_id\": \"mine\"}); }\n";
    assert!(refusals(&in_one(source)).is_empty());
}
