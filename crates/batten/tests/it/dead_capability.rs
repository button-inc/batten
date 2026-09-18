//! `policy/dead-capability.rego` over the COMPILED engine (CLOUD-1423).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads, and this module reads three
//! facts a `with input as` case fabricates for free and the engine has to earn:
//! `input.tree.lines[path]` for the surface file, the same map for every CALLER
//! surface the row's `line_sources` names, and
//! `input.tree["base-delta"]["base-lines"][path]` for the surface file's
//! committed bytes.
//!
//! The second is the one worth its own tier here. The module's caller arm
//! iterates `input.tree.lines` and excludes the crate; if the row's
//! `line_sources` does not actually fill `mise.toml`, `.claude/**` and the
//! workflows, that arm reads an empty map, nothing is ever reached, and the gate
//! refuses every added verb while its own suite stays green — the module would be
//! wrong in the loud direction, which is the survivable one, but it would be
//! wrong for a reason no `with input as` case can see.
//!
//! `rules/policy-modules.md` records the class: a module copied from `policy.rs`'s
//! own doc iterated a tree key the engine never built, and OpenTelemetry's
//! `weaver` printed "No policy violation", exit 0, over a knowingly-broken
//! registry. Both live instances in this tree were found by adding this tier.
//!
//! # What the rule is for
//!
//! A capability that ships without a caller is indistinguishable from one that
//! works: it gets a man page, completions, a module row and a layer, and every
//! gate in the set reads clean over it. Measured once at ~4,000 lines across two
//! pull requests. The rule is a RATCHET rather than a state check: 61 of this
//! tree's 154 declared verbs have no in-tree caller and are overwhelmingly
//! operator verbs a human invokes, so a gate refusing those on its first run is
//! one an author switches off.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares — NOT the `[[rule]]` id, which is
/// `verb reach other`. The two differ, and the difference is load-bearing for the
/// same reason `cfg_gated_test.rs` records it: an admission resolves its anchor
/// by the FINDING's rule, so minting against the config id silently produces a
/// `call:<head>` anchor that suppresses nothing (CLOUD-1551).
const UNREACHED: &str = "verb reach missing";

/// The `CommandDecl` block the module reads, at the indentation rustfmt gives it.
///
/// The indentation is not decoration: the module matches `path: "…"` on a trimmed
/// line, and `a_surface_declaring_no_verb_is_reported_rather_than_read_clean`
/// below is what stops a formatting change from emptying the verb set silently.
fn decl(verb: &str) -> Vec<String> {
    vec![
        "    CommandDecl {".to_owned(),
        format!("        path: \"{verb}\","),
        "        id: \"probe\",".to_owned(),
        "    },".to_owned(),
    ]
}

/// A fixture repository whose base commit carries `before` at the surface file
/// and whose working tree carries `after`, plus whatever caller files `callers`
/// names.
///
/// The pair is the point: the engine has to resolve the committed side from git
/// as `base-lines` and read the working side as `lines`, and a ratchet that got
/// either from a harness would pass over a branch it never compared.
///
/// `origin/main` is a local ref pointed at the base commit, written by
/// [`common::pin_origin_main`] — `base_delta` resolves a rev, and configuring a
/// remote would make an entirely local question depend on the network.
///
/// NO HAND-ROLLED `git init` — [`common::init_repo`] copies the one template the
/// whole suite shares (CLOUD-1419).
fn repo(name: &str, before: &[String], after: &[String], callers: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);

    let surface = root.join("crates/batten/src/surface.rs");
    fs::create_dir_all(surface.parent().expect("a parent")).expect("scratch parent");
    fs::write(&surface, join(before)).expect("seed the committed side");
    for (path, body) in callers {
        let at = root.join(path);
        fs::create_dir_all(at.parent().expect("a parent")).expect("caller parent");
        fs::write(&at, body).expect("seed a caller");
    }
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    common::pin_origin_main(&root);

    fs::write(&surface, join(after)).expect("write the working side");

    install_module(&root);
    root
}

fn join(lines: &[String]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/dead-capability.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/dead-capability.rego")).expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here — including `line_sources`, without which the caller arm reads an
/// empty map and every added verb is refused.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "verb reach other",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["crates/batten/src/surface.rs"],
        "line_sources": [
            "crates/batten/src/surface.rs",
            "mise-tasks/**",
            ".github/workflows/*.yml",
            ".claude/**",
            "mise.toml",
        ],
        "module": "policy/dead-capability.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn predicates(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

fn classes(root: &Path) -> Vec<String> {
    let scanned = scan(root);
    scanned
        .findings
        .iter()
        .filter_map(|finding| {
            scanned
                .classes
                .get(&finding.identity.fingerprint.to_hex())
                .cloned()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

/// THE RATCHET PROPERTY, and the case that separates this rule from the 61-verb
/// state check grooming rejected. The surface file is untouched; an unreached
/// verb that was already there is nobody's finding.
///
/// `#MUTANT ratchet-may-read-untouched` reddens here.
#[test]
fn a_pre_existing_unreached_verb_survives_an_unrelated_edit() {
    let surface = decl("lease acquire");
    let root = repo(
        "dead-capability-untouched",
        &surface,
        &surface,
        &[("README.md", "prose\n")],
    );
    fs::write(root.join("README.md"), "prose, edited\n").expect("edit an unrelated path");
    assert!(
        predicates(&root).is_empty(),
        "an edit that touches no verb declaration is not this rule's business"
    );
}

/// The surface file IS edited, and the verb was already on the base side. A
/// ratchet asks only whether the branch ADDED one.
///
/// `#MUTANT base-may-read-as-empty` reddens here: without the base comparison
/// every declared verb reads as added.
#[test]
fn a_pre_existing_unreached_verb_survives_an_edit_to_the_surface() {
    let before = decl("lease acquire");
    let mut after = before.clone();
    after.push("// a new comment".to_owned());
    let root = repo("dead-capability-edited", &before, &after, &[]);
    assert!(
        predicates(&root).is_empty(),
        "a verb the base already declared is not added by this branch"
    );
}

/// An ADDED verb with a caller. The caller is spelled the way this repository
/// actually spells one — the program, then flags, then the verb, across a shell
/// continuation — because the adjacency spelling fails on the live invocation at
/// `.github/workflows/test.yml:181-183`.
///
/// `#MUTANT reach-may-read-as-absent` reddens here.
#[test]
fn a_branch_that_adds_a_wired_verb_is_clean() {
    let root = repo(
        "dead-capability-wired",
        &[],
        &decl("lease guard"),
        &[(
            ".github/workflows/ci.yml",
            "      run: |\n        \"$BIN/batten\" --config-in \"$CFG\" \\\n          lease guard \\\n          \"$SHA\"\n",
        )],
    );
    assert!(
        predicates(&root).is_empty(),
        "a verb a workflow invokes is reached, continuation line and all"
    );
}

/// An ADDED verb with no caller but a declaration. This is the parallel-verb
/// state CLOUD-1335 argued for, and refusing it outright is what would push an
/// author to wire a fake caller.
///
/// `#MUTANT declaration-arm-dropped` reddens here.
#[test]
fn a_branch_that_adds_a_verb_with_a_declaration_is_clean() {
    let mut after = vec![
        "    // unreached: \"lease acquire\" CLOUD-1338 driven by land lap in process".to_owned(),
    ];
    after.extend(decl("lease acquire"));
    let root = repo("dead-capability-declared", &[], &after, &[]);
    assert!(
        predicates(&root).is_empty(),
        "a declared parallel verb is a legitimate state"
    );
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

/// THE DEFECT, over the engine's own `base-lines` rather than a harness's.
#[test]
fn a_branch_that_adds_an_unreached_verb_is_refused() {
    let root = repo("dead-capability-added", &[], &decl("lease acquire"), &[]);
    assert_eq!(
        predicates(&root),
        vec![UNREACHED.to_owned()],
        "a verb this branch declares and nothing reaches is refused"
    );
    assert_eq!(
        classes(&root),
        vec![UNREACHED.to_owned()],
        "under its own declared class"
    );
}

/// A COMMENT IS NOT A CALL SITE. The row's own measurement is that every textual
/// hit over `land` and `lease` was prose or a comment; counting those as callers
/// is the dead-gate direction, where the gate reads clean over the exact defect
/// it was written for.
#[test]
fn a_commented_invocation_is_not_a_caller() {
    let root = repo(
        "dead-capability-comment",
        &[],
        &decl("lease acquire"),
        &[(
            "mise.toml",
            "# batten lease acquire is what land lap calls\n",
        )],
    );
    assert_eq!(
        predicates(&root),
        vec![UNREACHED.to_owned()],
        "prose naming the verb is not an invocation of it"
    );
}

/// THE STALE DIRECTION, which is the one that rots quietly: the verb is wired,
/// the declaration still says nothing reaches it, and the next reader believes
/// the line.
#[test]
fn a_declaration_left_on_a_wired_verb_is_refused() {
    let mut after = vec![
        "    // unreached: \"lease guard\" CLOUD-1338 driven by land lap in process".to_owned(),
    ];
    after.extend(decl("lease guard"));
    let root = repo(
        "dead-capability-stale",
        &[],
        &after,
        &[("mise.toml", "run = 'batten lease guard --sha x'\n")],
    );
    assert_eq!(
        classes(&root),
        vec!["verb reach stale".to_owned()],
        "a declaration that outlived its reason is refused, not reported"
    );
}

/// A DECLARATION'S PROSE DOES NOT DECLARE OTHER VERBS, and the first spelling of
/// the arm got this wrong. `declared_unreached` matched the verb as a bare
/// substring, so an ordinary reason — "lease acquire is driven by land lap in
/// process" — also contained `land lap`, a WIRED verb, and the stale arm fired on
/// a verb nobody had declared. Quoting is what binds a declaration to one verb.
///
/// The fixture is the exact sentence that found it: `land lap` is declared in the
/// surface, invoked from `mise.toml`, and named only in the other verb's reason.
#[test]
fn a_declarations_prose_does_not_declare_the_verbs_it_mentions() {
    let mut after = vec![
        "    // unreached: \"lease acquire\" CLOUD-1338 driven by land lap in process".to_owned(),
    ];
    after.extend(decl("lease acquire"));
    after.extend(decl("land lap"));
    let root = repo(
        "dead-capability-prose",
        &decl("land lap"),
        &after,
        &[("mise.toml", "run = 'batten land lap'\n")],
    );
    assert!(
        predicates(&root).is_empty(),
        "the wired `land lap` is named in another verb's reason, not declared by it"
    );
}

/// THE ANTI-VACUITY ARM, and it guards a dependency this module really has. The
/// verb set is read from `path: "…"` literals at rustfmt's indentation; a
/// formatting change that moves them yields an EMPTY set, every downstream clause
/// goes undefined, and the module reports clean over a surface it could not read.
/// That is byte-identical to a tree with no verbs — the dead-gate class this row
/// exists to close, arriving inside the gate that closes it.
#[test]
fn a_surface_declaring_no_verb_is_reported_rather_than_read_clean() {
    let root = repo(
        "dead-capability-unparsed",
        &[],
        &["fn main() {}".to_owned()],
        &[],
    );
    assert_eq!(
        classes(&root),
        vec!["diff read absent".to_owned()],
        "a surface this rule cannot read is a read failure, never a clean tree"
    );
}
