//! The delay inventory, as a gate rather than a table (CLOUD-1177).
//!
//! AGENTS.md refuses a timer on the agent surface — *"never a foreground
//! `sleep`, a timer where an exit condition belongs"* — and until this row the
//! Rust half had no mechanism at all: `clippy.toml` banned a spawn and a
//! multi-thread runtime, and neither is a delay. The retirements moving bash
//! waiters into the engine are precisely the changes that introduce one, and a
//! timer is harder to see in Rust than in bash rather than easier.
//!
//! **What is banned is the CALL, and what is refused is a wall-clock guess.** A
//! conditional poll against a real exit condition is legitimate work; `sleep` as
//! a scheduling device — pacing a loop by guessing when the world changes — is
//! not. clippy cannot tell those apart, so every sound site carries an
//! annotation, exactly as a spawn does in `spawn_census.rs`.
//!
//! The obligation on that annotation is where this gate earns its keep. A waiver
//! is satisfied by any prose; an inventory row is not. So the reason must **name
//! the bound the delay comes from** — the header that set the interval, the
//! terminal state the loop exits on, the count that exhausts — and this file
//! holds each named bound to one that actually RESOLVES in the same file. A
//! timer has no bound to name, which is what makes the predicate discriminate
//! rather than decorate.
//!
//! What this file deliberately does not re-assert: that `disallowed_methods` and
//! `unfulfilled_lint_expectations` are `deny` in the workspace manifest.
//! `spawn_census.rs` owns both, for both inventories, and a second copy here
//! would be a second authority over one line.
//!
//! Two tiers, and the second is the one CLOUD-418 asks for. The shape assertions
//! below all pass over a tree where the ban does nothing at all, so the toy-crate
//! cases drive real clippy and make each arm go red on purpose: an unannotated
//! delay refused, an annotated one passing, and a stale annotation over a delay
//! that is gone refused too — the direction a count table is blind to and the
//! whole reason the annotation is `expect` rather than `allow`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;

use std::fs;
use std::path::{Path, PathBuf};

use batten::facts::{Format, Look, Node};
use common::{annotation_reason, annotations_naming, at_root, rust_sources};

/// The lint whose level carries this inventory.
const LINT: &str = "clippy::disallowed_methods";

/// The call the ban is about.
const SLEEP: &str = "std::thread::sleep";

/// Its async spelling, banned on the same terms and live for a different reason.
const ASYNC_SLEEP: &str = "tokio::time::sleep";

/// The tokio feature that makes [`ASYNC_SLEEP`] resolve.
const TIME: &str = "time";

/// `clippy.toml`, read once per case.
fn clippy_toml() -> String {
    fs::read_to_string(at_root("clippy.toml")).expect("clippy.toml is committed")
}

/// The workspace manifest, through the fact the engine already owns rather than
/// a second TOML reader.
fn manifest() -> Node {
    let text = fs::read_to_string(at_root("Cargo.toml")).expect("the workspace manifest is here");
    match Format::Toml.read(&text) {
        Look::Is(node) => node,
        other => panic!("the workspace manifest did not parse: {other:?}"),
    }
}

/// The row for `path` in `clippy.toml`, as its single line.
///
/// Anchored on the `path =` KEY rather than on the bare path, because the
/// comment block above the table names both banned calls in prose — a bare
/// search finds the sentence, and the assertions below would then be reading a
/// comment and reporting on a row.
fn row_for(clippy: &str, path: &str) -> String {
    // Assembled from `QUOTED` rather than written as one interpolation, because
    // `primitives.rs::every_path_valued_toml_key_uses_a_literal_string` refuses
    // the shape `path = "{…}"` on sight — deliberately keyed on the KEY and never
    // on the value, since "can this value be a path?" is a judgement it got wrong
    // twice. Here the key belongs to `clippy.toml`'s dialect and its value is a
    // Rust type path, so no escape can bite; and the audit's own remedy (a TOML
    // literal string) cannot apply, because this READS bytes clippy.toml already
    // spells with basic strings. Dodging the shape is the honest repair: the
    // audit stays exactly as strict about the class it was written for.
    const QUOTED: &str = "path = \"";
    let key = format!("{QUOTED}{path}\"");
    let at = clippy
        .find(&key)
        .unwrap_or_else(|| panic!("clippy.toml must carry a row for `{path}`"));
    let start = clippy[..at].rfind('\n').map_or(0, |nl| nl + 1);
    let end = clippy[at..].find('\n').map_or(clippy.len(), |nl| at + nl);
    clippy[start..end].to_owned()
}

/// Every backticked span in `reason`, which is how a bound is named.
///
/// Backticks rather than a bare-word scan, because the assertion is that the
/// author pointed at a THING: prose naming a duration in words has no span to
/// resolve, and that is the shape this gate exists to refuse.
fn bounds_named(reason: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = reason;
    while let Some((_, after)) = rest.split_once('`') {
        let Some((span, tail)) = after.split_once('`') else {
            break;
        };
        if !span.is_empty() {
            found.push(span.to_owned());
        }
        rest = tail;
    }
    found
}

#[test]
fn clippy_toml_bans_both_spellings_of_a_delay() {
    // The subject half. The severity is the manifest's and `spawn_census.rs`
    // asserts it; this says WHAT is refused, and both spellings are asked for
    // because banning only the blocking one leaves the async door open the day
    // an `async fn` arrives — which the vendored HTTP client has already made
    // reachable.
    let clippy = clippy_toml();
    assert!(
        clippy.contains("disallowed-methods"),
        "clippy.toml must carry a `disallowed-methods` table"
    );
    for path in [SLEEP, ASYNC_SLEEP] {
        let row = row_for(&clippy, path);
        assert!(
            row.contains("reason ="),
            "the `{path}` row must carry a `reason`: clippy prints it at the deny site, and a \
             deny that does not say what to do is the CLOUD-437 defect"
        );
    }
    // The remedy has to be IN the refusal, because the refusal is where an author
    // meets this rule — a deny naming the ban and not the annotation sends them
    // to delete the delay, which is the wrong fix for twelve of the thirteen
    // sites in this crate.
    let row = row_for(&clippy, SLEEP);
    assert!(
        row.contains(LINT) && row.contains("bound"),
        "the `{SLEEP}` row's reason must name `{LINT}` and the BOUND an annotation owes, so the \
         deny an author actually reads carries the remedy rather than only the refusal"
    );
}

#[test]
fn the_async_row_is_live_exactly_while_the_time_feature_is_on() {
    // THE ASYMMETRY WITH THE TOKIO ROWS ABOVE IT, and it runs the other way.
    //
    // `tokio::signal::*` and `new_multi_thread` carry `allow-invalid = true`
    // because the features that would compile them are OFF, so reaching for
    // either is a compile error — strictly stronger than a lint, and the flag
    // records that rather than waiving anything. `tokio::time::sleep` has no such
    // bound: the workspace `tokio` entry ENABLES `time`, so the path resolves and
    // the lint is the whole of the refusal. Carrying `allow-invalid` there would
    // record a guarantee this row does not have.
    //
    // So the two halves are asserted together, and dropping `time` from the
    // feature list turns this red pointing at the row that must then gain the
    // flag — otherwise clippy rejects an unresolvable path and the config fails
    // to load at all, which is a red gate saying nothing about the ban.
    let manifest = manifest();
    let features = manifest.at("workspace.dependencies.tokio.features");
    let Look::Is(Node::List(features)) = features else {
        panic!("[workspace.dependencies] must declare tokio with an explicit feature list")
    };
    let enabled: Vec<&str> = features
        .iter()
        .filter_map(|node| match node {
            Node::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let row = row_for(&clippy_toml(), ASYNC_SLEEP);
    if enabled.contains(&TIME) {
        assert!(
            !row.contains("allow-invalid"),
            "tokio enables `{TIME}`, so `{ASYNC_SLEEP}` RESOLVES and the ban is live. \
             `allow-invalid = true` on a row that resolves records a guarantee it does not have — \
             drop it, and leave the flag to the rows whose feature is genuinely off."
        );
    } else {
        assert!(
            row.contains("allow-invalid = true"),
            "tokio no longer enables `{TIME}`, so `{ASYNC_SLEEP}` cannot resolve and clippy will \
             reject the whole config rather than the path. Add `allow-invalid = true` to that row \
             and record in its comment that the feature being off is now the stronger bound."
        );
    }
}

#[test]
fn every_delay_carries_an_expect_naming_a_bound_that_resolves() {
    // THE PREDICATE THIS ROW IS ABOUT. Every other assertion here is about the
    // config; this one is about the annotations the config forced into
    // existence.
    //
    // **AND IT IS NOT WHAT STOPS THE BAN BEING SATISFIED BY WAIVERS, WHICH IS
    // WHAT THIS COMMENT USED TO CLAIM** (CLOUD-1148). Measured 2026-09-06: 11
    // `#[expect(clippy::disallowed_methods, …)]` stand over 13
    // `std::thread::sleep` sites, so the ban is waived at essentially every site
    // it governs — the state the claim said this test prevents.
    //
    // The reason it cannot is structural rather than a gap to close here. Every
    // clause below is a property of the SENTENCE: `expect` not `allow`, a reason
    // present, a backticked token, that token resolving elsewhere in the file.
    // None of them asks whether the delay was NECESSARY, because neither clippy
    // nor a text scan can — so what this decides is whether an author pointed at
    // something real, which is a proxy for having thought about it. Measured
    // against the agent that wrote this amendment: it was satisfied in about
    // thirty seconds by copying the shape of a neighbouring annotation, over a
    // grace loop that was then found unnecessary and deleted outright. A gate
    // that certifies a delay which should not exist is estimating, and
    // non-negotiable rule 3 forbids that.
    //
    // What DOES stop a twelfth waiver is `waiver add refused` in
    // `batten.toml` — a ratchet over the COUNT, which is a real object with a
    // real exit code and no judgement in it. This test keeps its narrower and
    // honest job: the annotations that exist point at something that resolves.
    //
    // "Names a bound that resolves" is deliberately ONE span rather than all of
    // them: a reason names the exit condition, the interval and often the
    // enclosing deadline, and only some of those are spelled as identifiers in
    // the file — an HTTP header is a bound and is not a symbol. Demanding all
    // would push authors toward naming only what is greppable, which is the
    // narrower claim. Demanding one is the assertion that the author pointed at
    // something really there.
    //
    // Pointer-only per non-negotiable rule 4: a path, a line and a class, never
    // the annotated source.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let shown = path.display().to_string();
        let found = annotations_naming(&source, LINT);
        // The annotation cannot resolve its own bound: a reason naming a token
        // that appears nowhere but inside the reason is prose with backticks.
        let mut elsewhere = source.clone();
        for (_, attribute) in &found {
            elsewhere = elsewhere.replace(attribute.as_str(), "");
        }
        for (line, attribute) in &found {
            if attribute.contains("allow(") {
                problems.push(format!("{shown}:{line} allow — must be expect"));
                continue;
            }
            if !attribute.contains("expect(") {
                problems.push(format!("{shown}:{line} not-an-expect"));
                continue;
            }
            let Some(reason) = annotation_reason(attribute) else {
                problems.push(format!("{shown}:{line} no-reason"));
                continue;
            };
            let named = bounds_named(&reason);
            if named.is_empty() {
                problems.push(format!("{shown}:{line} names-no-bound"));
                continue;
            }
            if !named.iter().any(|bound| elsewhere.contains(bound.as_str())) {
                problems.push(format!("{shown}:{line} bound-does-not-resolve"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "every delay is an inventory row and must name, in backticks, a bound that resolves in \
         its own file — the header that set the interval, the condition the loop exits on, or the \
         count that exhausts:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_inventory_is_not_empty() {
    // The anti-vacuity arm, and it is not a formality: every assertion above
    // passes trivially over a crate carrying no annotation at all, which is
    // exactly what a ban silently scoped to nothing would produce. A floor rather
    // than a count — the number is clippy's to maintain, and pinning one here
    // rebuilds the table this shape exists to replace.
    let annotated: usize = rust_sources()
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).expect("read a crate source file");
            annotations_naming(&source, LINT).len()
        })
        .sum();
    // FIVE, NOT EIGHT (CLOUD-2789): test code carries no delay verdict any
    // more — every test wait is on its event — so what is left is production's
    // own rows, seven today. The floor still says what it said: a sweep that
    // reads nothing finds none.
    assert!(
        annotated >= 5,
        "only {annotated} delay verdicts found — the sweep is not reaching the crate"
    );
}

/// The 1-based line of every attribute in `source` standing in `#[cfg(test)]`
/// code: on, or inside, an item that carries it. Read off the parsed tree by the
/// module graph's own `cfg_test`, so a test module is never told from the
/// library by a text scan for the marker.
fn test_code_lines(source: &str) -> std::collections::BTreeSet<usize> {
    use ra_ap_syntax::AstNode as _;
    let file = ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024).tree();
    file.syntax()
        .descendants()
        .filter_map(ra_ap_syntax::ast::Attr::cast)
        .filter(|attr| batten_base::module_graph::cfg_test(attr.syntax()))
        .map(|attr| {
            source[..usize::from(attr.syntax().text_range().start())]
                .matches('\n')
                .count()
                + 1
        })
        .collect()
}

/// Whether `path` is a test target's source: under a member's `tests/`.
fn under_tests(path: &Path) -> bool {
    path.strip_prefix(at_root("crates"))
        .ok()
        .and_then(|rest| rest.components().nth(1))
        .is_some_and(|dir| dir.as_os_str() == "tests")
}

#[test]
fn test_code_carries_no_time_wait_verdict() {
    // THE OWNER'S RULE, AS A GATE (CLOUD-2789): a test waits for the EVENT it is
    // about — a child's exit, a pipe's EOF, a channel or condvar the code under
    // test signals — and never on a clock. A mutant that suppresses the event
    // then hangs the case, and the mutation judge's per-case cut files that
    // honestly as a timeout; a clock in the case only races that cut, or passes
    // a late arrival as an on-time one.
    //
    // So in test code the annotation is not a verdict to be judged on its bound,
    // as it is in production: there is no bound a test owns. Test code is a
    // member's `tests/` and every `#[cfg(test)]` item, the latter read off the
    // parsed tree ([`test_code_lines`]), never off the marker's text.
    //
    // EVERY `disallowed_methods` row the table carries outside the timers has a
    // door a test uses instead (`streamed_output`, `stream::pump`), so the
    // predicate is the whole lint rather than a guess at which row an
    // annotation was written for: a reason cannot be trusted to say.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let tests = under_tests(&path);
        let in_test = test_code_lines(&source);
        for found in
            batten::codemod::lint_attributes(&source, batten::codemod::Edition::E2024, LINT)
        {
            if tests || in_test.contains(&found.line) {
                problems.push(format!("{}:{} {}", path.display(), found.line, found.level));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "test code waits on the event, never on a clock, so it carries no `{LINT}` verdict — \
         rewrite the wait to block on the exit, EOF, channel or condvar it is about:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_test_code_reader_tells_a_test_module_from_the_library() {
    // The anti-vacuity arm for the case above: a reader that called nothing
    // test code would pass it over any tree. One verdict in the library, one in
    // a `#[cfg(test)]` module, and only the second is test code.
    let source = format!(
        "{}\npub fn library() {{}}\n\n#[cfg(test)]\nmod tests {{\n    {}\n    \
         fn case() {{}}\n}}\n",
        annotated("library"),
        annotated("test")
    );
    let found = batten::codemod::lint_attributes(&source, batten::codemod::Edition::E2024, LINT);
    let in_test = test_code_lines(&source);
    let read: Vec<bool> = found
        .iter()
        .map(|found| in_test.contains(&found.line))
        .collect();
    assert_eq!(read, vec![false, true], "{found:?}");
}

/// Every `sleep` a source spawns as a CHILD, as `path:line`: the timer
/// clippy cannot see, because it is a program and not a method (CLOUD-2789).
///
/// Read off the parsed tree, so a `sleep` inside a hook fixture's command TEXT
/// — a string the judge reads and nothing runs — is no row. Three shapes:
/// `Command::new("sleep")`; an argument list or array holding `"--"` then
/// `"sleep"`, the argv a wrapper runs; and one holding `"-c"` then a literal
/// script that runs `sleep N`. A script assembled at run time is out of a
/// syntax reader's sight, and that gap is stated rather than discovered.
fn sleep_children(source: &str) -> Vec<usize> {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast;

    let file = ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024).tree();
    let line_of = |node: &ra_ap_syntax::SyntaxNode| {
        source[..usize::from(node.text_range().start())]
            .matches('\n')
            .count()
            + 1
    };
    let text_of = |expr: &ast::Expr| match expr {
        ast::Expr::Literal(literal) => match literal.kind() {
            ast::LiteralKind::String(text) => text.value().ok().map(std::borrow::Cow::into_owned),
            _ => None,
        },
        _ => None,
    };
    let runs_sleep = |script: &str| {
        let words: Vec<&str> = script
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')'))
            .filter(|word| !word.is_empty())
            .collect();
        words
            .windows(2)
            .any(|pair| pair[0] == "sleep" && pair[1].starts_with(|c: char| c.is_ascii_digit()))
    };
    let mut found = Vec::new();
    for node in file.syntax().descendants() {
        let elements: Vec<ast::Expr> = if let Some(list) = ast::ArgList::cast(node.clone()) {
            list.args().collect()
        } else if let Some(array) = ast::ArrayExpr::cast(node.clone()) {
            array.exprs().collect()
        } else {
            continue;
        };
        let texts: Vec<Option<String>> = elements.iter().map(text_of).collect();
        let call_new = node
            .parent()
            .and_then(ast::CallExpr::cast)
            .and_then(|call| call.expr())
            .is_some_and(|callee| callee.syntax().text().to_string().ends_with("Command::new"));
        let spawned = (call_new
            && texts
                .first()
                .is_some_and(|first| first.as_deref() == Some("sleep")))
            || texts.windows(2).any(|pair| match (&pair[0], &pair[1]) {
                (Some(flag), Some(next)) => {
                    (flag == "--" && next == "sleep") || (flag == "-c" && runs_sleep(next))
                }
                _ => false,
            });
        if spawned {
            found.push(line_of(&node));
        }
    }
    found
}

#[test]
fn no_source_spawns_sleep_as_a_child() {
    // The half of the delay inventory clippy is blind to: `sleep` run as a
    // PROGRAM, directly or inside a shell script, is a timer all the same, and
    // a fixture that needs a long-lived child has an event to hold it on
    // instead — `cat` on a stdin pipe the case holds, a FIFO, or a builtin spin
    // on the very condition it waits for.
    let mut problems: Vec<String> = Vec::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        for line in sleep_children(&source) {
            problems.push(format!("{}:{line}", path.display()));
        }
    }
    assert!(
        problems.is_empty(),
        "a `sleep` child is a timer clippy cannot see; hold the child on an event instead:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn the_sleep_child_reader_sees_each_shape_and_no_command_text() {
    // Anti-vacuity, both directions. Assembled from parts so this file's own
    // source holds none of the shapes it asks about and stays clean under the
    // sweep above.
    let program = ["sl", "eep"].concat();
    let spawns = [
        format!("fn a() {{ std::process::Command::new(\"{program}\"); }}"),
        format!("fn b() {{ run(&[\"step\", \"--\", \"{program}\", \"2\"]); }}"),
        format!("fn c() {{ run(&[\"sh\", \"-c\", \"true; {program} 0.3\"]); }}"),
    ];
    for source in &spawns {
        assert_eq!(sleep_children(source).len(), 1, "a spawn: {source}");
    }
    let text = [
        format!("fn d() {{ judged(\"cd /tmp && {program} 1\"); }}"),
        format!("fn e() {{ walked(\"while true; do {program} 1; done\", \"{program}\"); }}"),
        format!("fn f() {{ run(&[\"sh\", \"-c\", \"echo {program}y\"]); }}"),
    ];
    for source in &text {
        assert!(sleep_children(source).is_empty(), "command text: {source}");
    }
}

/// A throwaway crate carrying the ban and `lib` source `body`.
///
/// **No dependencies, for the reason the spawn census records for its own toy
/// crate**: the subject is the MECHANISM, not any real module's coverage, and
/// running against the live tree would make the verdict a function of whichever
/// file someone edited last. It also keeps the case offline — cargo fetches
/// nothing for a crate that declares nothing — and `[workspace]` in its manifest
/// is what stops it being adopted by the workspace it is materialized beside.
fn toy(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-sleep-ban-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).expect("create the toy crate");
    // TOML LITERAL strings, which is the audit's own remedy taken rather than
    // dodged: `every_path_valued_toml_key_uses_a_literal_string` refuses a `path`
    // interpolated into a basic string, and a literal one processes no escapes.
    // Nothing about the toy config needs escaping, so this costs nothing and
    // keeps the fixture inside the rule the rest of the suite lives by.
    fs::write(
        dir.join("clippy.toml"),
        format!(
            "disallowed-methods = [\n  {{ path = '{SLEEP}', reason = 'a delay is an inventory \
             row' }},\n]\n"
        ),
    )
    .expect("write the toy clippy.toml");
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n\n\
         [lints.rust]\nunfulfilled_lint_expectations = \"deny\"\n\n\
         [lints.clippy]\ndisallowed_methods = \"deny\"\n",
    )
    .expect("write the toy manifest");
    fs::write(dir.join("src/lib.rs"), body).expect("write the toy source");
    dir
}

/// Drive clippy over the toy crate, deliberately **without** `-D warnings`: the
/// level under test is the manifest's, and adding the flag would answer a
/// question nobody is asking.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the second tier IS a clippy run over a throwaway crate, and there is no way to observe what clippy decides about a delay without running it"
)]
fn toy_clippy(dir: &Path) -> (bool, String) {
    let cargo = std::env::var("CARGO").expect("cargo names itself to the test harness it runs");
    let out = std::process::Command::new(cargo)
        .args(["clippy", "--quiet"])
        .current_dir(dir)
        // Out of the workspace's own target dir, or every case contends on the
        // lock the gate deliberately serialises.
        .env("CARGO_TARGET_DIR", dir.join("target"))
        // Nor a build directory inherited from a mutant sweep's baseline: two
        // toy crates of one name shared its units, and the second clippy run
        // read as fresh and said nothing (#1276).
        .env_remove("CARGO_BUILD_BUILD_DIR")
        .env_remove("CARGO_INCREMENTAL")
        .streamed_output()
        .expect("run clippy over the toy crate");
    let mut said = String::from_utf8_lossy(&out.stderr).into_owned();
    said.push_str(&String::from_utf8_lossy(&out.stdout));
    (out.status.success(), said)
}

/// An annotation naming [`LINT`], assembled rather than written out.
///
/// Assembled because this file is itself in the corpus
/// `every_delay_carries_an_expect_naming_a_bound_that_resolves` sweeps: a fixture
/// spelling the attribute literally would be scanned as one of the crate's own
/// inventory rows and judged against a bound it has no reason to have. Building
/// it from the same constant the gate reads keeps the fixture and the predicate
/// in agreement and keeps the fixture out of the sweep.
fn annotated(reason: &str) -> String {
    format!("#[expect({LINT}, reason = \"{reason}\")]")
}

#[test]
fn an_unannotated_delay_is_refused() {
    // (a) — the ban itself. Without this the row is a config edit nobody has
    // watched fire.
    let dir = toy(
        "unannotated",
        "pub fn pace() {\n    std::thread::sleep(std::time::Duration::from_secs(1));\n}\n",
    );
    let (passed, said) = toy_clippy(&dir);
    assert!(
        !passed,
        "an unannotated delay must be refused; clippy said: {said}"
    );
    assert!(
        said.contains("disallowed"),
        "the refusal must be the disallowed-method one rather than some other error: {said}"
    );
}

#[test]
fn an_annotated_delay_passes() {
    // (b) — the other side of (a), and without it the ban is satisfied by
    // something nothing can ever legitimately pass. This is what makes the
    // refusal above a statement about the MISSING VERDICT rather than about the
    // call.
    let body = format!(
        "pub fn poll(done: &dyn Fn() -> bool) {{\n    \
         while !done() {{\n        {}\n        \
         std::thread::sleep(std::time::Duration::from_millis(20));\n    }}\n}}\n",
        annotated("the interval of a poll whose exit condition is `done`")
    );
    let dir = toy("annotated", &body);
    let (passed, said) = toy_clippy(&dir);
    assert!(
        passed,
        "an annotated delay must pass — the ban is on the unremarked arrival, not on the call; \
         clippy said: {said}"
    );
}

#[test]
fn a_stale_annotation_over_a_deleted_delay_is_refused() {
    // (c) — WHY `expect` AND NOT `allow`, as a decision rather than a claim. The
    // delay is gone and the annotation was left behind; under `allow` that is
    // silent forever and the inventory accumulates rows describing code that is
    // not there. A count catches additions only; this is the other direction, and
    // it is what makes the inventory self-clean without anybody maintaining it.
    let body = format!(
        "{}\npub fn poll() {{}}\n",
        annotated("the interval of a poll that no longer exists")
    );
    let dir = toy("stale", &body);
    let (passed, said) = toy_clippy(&dir);
    assert!(
        !passed,
        "a stale delay verdict must be refused; clippy said: {said}"
    );
    assert!(
        said.contains("unfulfilled"),
        "the refusal must be `unfulfilled_lint_expectations` — that lint is warn-by-default, so \
         the workspace denies it explicitly rather than leaning on `-D warnings`: {said}"
    );
}

/// The four timed waits `clippy.toml` deliberately carries no row for, as
/// `(line, call)`: the method calls `recv_timeout`, `shutdown_timeout` and
/// `set_connect_timeout`, and a call or `use` of a path ending `time::timeout`.
///
/// Read off the parsed tree, so a comment or string naming one is no row. A
/// `timeout` imported under another name is out of a syntax reader's sight;
/// that gap is stated rather than discovered.
fn bounded_waits(source: &str) -> Vec<(usize, &'static str)> {
    use ra_ap_syntax::AstNode as _;
    use ra_ap_syntax::ast;

    const METHODS: [&str; 3] = ["recv_timeout", "shutdown_timeout", "set_connect_timeout"];
    const TIMEOUT: &str = "time::timeout";
    let file = ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2024).tree();
    let line_of = |node: &ra_ap_syntax::SyntaxNode| {
        source[..usize::from(node.text_range().start())]
            .matches('\n')
            .count()
            + 1
    };
    let mut found = Vec::new();
    for node in file.syntax().descendants() {
        if let Some(call) = ast::MethodCallExpr::cast(node.clone()) {
            let name = call.name_ref().map(|name| name.text().to_string());
            if let Some(method) = METHODS.iter().find(|m| name.as_deref() == Some(**m)) {
                found.push((line_of(&node), *method));
            }
        } else if let Some(call) = ast::CallExpr::cast(node.clone()) {
            if call
                .expr()
                .is_some_and(|callee| callee.syntax().text().to_string().ends_with(TIMEOUT))
            {
                found.push((line_of(&node), TIMEOUT));
            }
        } else if let Some(used) = ast::UseTree::cast(node.clone())
            && used.use_tree_list().is_none()
            && used
                .path()
                .is_some_and(|path| path.syntax().text().to_string().ends_with(TIMEOUT))
        {
            found.push((line_of(&node), TIMEOUT));
        }
    }
    found
}

/// Where each of [`bounded_waits`]' calls stands today, and how many times:
/// every one is a bound that IS the design, named at its site.
const BOUNDED_WAIT_SITES: [(&str, &str, usize); 5] = [
    // `fetch::bound`: the connect, total and drain bounds of one HTTP fetch.
    ("crates/batten-base/src/fetch.rs", "set_connect_timeout", 1),
    ("crates/batten-base/src/fetch.rs", "time::timeout", 1),
    ("crates/batten-base/src/fetch.rs", "shutdown_timeout", 1),
    // `Pumping::finished`: the drain grace each caller names.
    ("crates/batten-stream/src/lib.rs", "recv_timeout", 1),
    // The forge notice's fail-open budget, `NOTICE_LOOKUP`.
    ("crates/batten/src/lib.rs", "recv_timeout", 1),
];

#[test]
fn a_timed_wait_without_a_row_stands_only_where_its_bound_is_the_design() {
    // THE ROWS `clippy.toml` LEAVES OUT, HELD AS SOURCE (CLOUD-2789). Four timed
    // waits carry no `disallowed_methods` row, because each one's production
    // calls are a bound by design and a row would buy each a waiver the
    // `waiver add refused` ratchet does not grant. So every call of the four is
    // pinned to the file it stands in today, with its count: a fifth call, a call
    // in any other file, or ANY call in test code (no test file is pinned, and a
    // `#[cfg(test)]` call in a pinned file moves its count) is refused here, as
    // the row would have refused it.
    let root = fs::canonicalize(at_root("")).expect("resolve the repository root");
    let mut seen: std::collections::BTreeMap<(String, &str), usize> =
        std::collections::BTreeMap::new();
    for path in rust_sources() {
        let source = fs::read_to_string(&path).expect("read a crate source file");
        let resolved = fs::canonicalize(&path).expect("resolve a crate source file");
        let shown = resolved
            .strip_prefix(&root)
            .expect("a crate source sits under the repository root")
            .display()
            .to_string();
        for (_, call) in bounded_waits(&source) {
            *seen.entry((shown.clone(), call)).or_default() += 1;
        }
    }
    let pinned: std::collections::BTreeMap<(String, &str), usize> = BOUNDED_WAIT_SITES
        .iter()
        .map(|(file, call, count)| (((*file).to_owned(), *call), *count))
        .collect();
    assert_eq!(
        seen, pinned,
        "a timed wait with no clippy row stands only at its pinned site: wait on the event \
         instead, or, for a bound that is the design, pin the site here and name the bound there"
    );
}

#[test]
fn the_bounded_wait_reader_sees_each_call_and_no_text() {
    // Anti-vacuity, both directions, assembled from parts so this file's own
    // source holds none of the calls it asks about.
    let timeout = ["time", "out"].concat();
    let calls = [
        format!("fn a() {{ rx.recv_{timeout}(d); }}"),
        format!("fn b() {{ runtime.shutdown_{timeout}(d); }}"),
        format!("fn c() {{ connector.set_connect_{timeout}(Some(d)); }}"),
        format!("async fn d() {{ tokio::time::{timeout}(d, work).await; }}"),
        format!("use tokio::time::{timeout};"),
    ];
    for source in &calls {
        assert_eq!(bounded_waits(source).len(), 1, "a call: {source}");
    }
    let text = [
        format!("// rx.recv_{timeout}(d)"),
        format!("fn e() {{ say(\"tokio::time::{timeout}(d, work)\"); }}"),
        format!("fn f() {{ rx.recv(); runtime.shutdown_background(); {timeout}(); }}"),
    ];
    for source in &text {
        assert!(bounded_waits(source).is_empty(), "no call: {source}");
    }
}
