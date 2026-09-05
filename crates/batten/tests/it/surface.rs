//! End-to-end tests over the compiled binary for the command surface as data
//! (CLOUD-27).
//!
//! `surface.rs`'s own unit tests assert that the declaration and the built
//! `clap` tree agree. These assert the half a consumer actually depends on: that
//! the binary emits completions derived from that surface, byte-stably, and that
//! the scripts committed to this repository are the ones it emits.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! CLOUD-1145. `derived-check` was 289.8s — 23.8% of the bats corpus — spent
//! re-answering a question this file already answers over the compiled binary.
//! The disposition is SUBSUMED rather than a port: `:66` and `:222` held the
//! drift half for both artifact families before this row existed, and what was
//! genuinely missing is the SET half, which arrives here as
//! `the_committed_artifacts_are_exactly_the_ones_the_surface_declares`.

// subsumed: mise-tasks/derived-check.sh crates/batten/src/surface.rs kind:mechanism crates/batten/tests/it/surface.rs
// subsumed: mise-tasks/man-pages.sh crates/batten/src/spec.rs kind:mechanism crates/batten/tests/it/surface.rs
// carried: tests/derived-check.bats crates/batten/src/surface.rs kind:mechanism crates/batten/tests/it/surface.rs

//! # RETIREMENT LEDGER — `tests/derived-check.bats`, 10 cases
//!
//! SUBSUMED — the assertion already stood here before the gate died.

// subsumed: "committed artifacts matching the surface exit 0" crates/batten/tests/it/surface.rs
// subsumed: "a drifted completion is reported with a pointer" crates/batten/tests/it/surface.rs
// subsumed: "a drifted man page is reported with a pointer" crates/batten/tests/it/surface.rs
// subsumed: "the gate leaves the tree it judges unmodified" crates/batten/tests/it/surface.rs
// subsumed: "every committed page's filename matches the .TH title inside it" crates/batten/tests/it/surface.rs
// subsumed: "this repo's committed artifacts match its surface — the gate on the real tree" crates/batten/tests/it/surface.rs

//! CARRIED — the three cells the existing tier was blind to, closed by the one
//! new assertion this row writes.

// carried: "a missing artifact is reported rather than silently skipped" crates/batten/tests/it/surface.rs
// carried: "a page the surface no longer derives is reported as an orphan" crates/batten/tests/it/surface.rs
// carried: "the derived page list names the root page with an empty command path" crates/batten/tests/it/surface.rs

//! CHANGED — behaviour that diverges deliberately, with its reason.

// changed: "output is pointer-only — no artifact body echoed" crates/batten/tests/it/surface.rs the gate wrote findings to stderr, where non-negotiable rule 4 binds and a page body would have been the payload; a failing assertion here is a developer diagnostic on a local run rather than a finding a gate emits, and `assert_eq!` over the bytes is what makes a drift readable at all. The SET assertion below is pointer-only in the rule's own sense — it names paths and never opens a file

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

use common::{at_root, batten, git_in, scratch};

/// The shells the repository commits a completion script for.
const SHELLS: [&str; 3] = ["bash", "zsh", "fish"];

fn generate(shell: &str) -> Output {
    batten()
        .args(["generate", "completions", "--shell", shell])
        .output()
        .expect("run batten generate completions")
}

/// The committed completion script for `shell`, located from this crate's
/// manifest directory.
///
/// Deliberately not a repo-root resolver: `git::repo_root` is the one
/// implementation of that (CLOUD-34), and a test helper that rediscovered the
/// root would be a second one. This only needs a fixed relative path.
fn committed_completion(shell: &str) -> PathBuf {
    at_root(&format!("completions/batten.{shell}"))
}

#[test]
fn completions_are_emitted_for_every_committed_shell() {
    for shell in SHELLS {
        let output = generate(shell);
        assert_eq!(output.status.code(), Some(0), "{shell} completions");
        assert!(!output.stdout.is_empty(), "{shell} completions were empty");
    }
}

#[test]
fn completions_are_byte_stable_across_runs() {
    // §6: identical input, identical bytes. Without this the drift gate would
    // fail at random and teach everyone to re-run it until it passed.
    for shell in SHELLS {
        assert_eq!(
            generate(shell).stdout,
            generate(shell).stdout,
            "{shell} completions were not byte-stable"
        );
    }
}

#[test]
fn the_committed_completions_are_the_ones_the_binary_emits() {
    // DoR §4's byte-for-byte drift assertion, over the compiled binary rather
    // than through the shell gate — so a stale committed script fails the Rust
    // suite too, and cannot land while only `hk` is skipped.
    for shell in SHELLS {
        let committed = committed_completion(shell);
        let bytes = fs::read(&committed)
            .unwrap_or_else(|err| panic!("read {}: {err}", committed.display()));
        assert_eq!(
            bytes,
            generate(shell).stdout,
            "completions/batten.{shell} differs from the surface; run `mise run completions`"
        );
    }
}

#[test]
fn generate_writes_no_file() {
    // What makes `generate`'s `read` effect structurally honest (§5) rather than
    // a promise about behaviour: the verb emits on stdout and touches nothing.
    // Asserted by running it from a scratch directory and finding that
    // directory still empty.
    let dir = scratch("generate-writes-no-file");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    let output = batten()
        .args(["generate", "completions", "--shell", "bash"])
        .current_dir(&dir)
        .output()
        .expect("run batten generate completions");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read_dir(&dir).expect("read scratch dir").count(),
        0,
        "a read-effect verb wrote to the working directory"
    );
}

#[test]
fn an_unknown_shell_is_a_usage_error() {
    // Exit 1 is the config-or-usage code; 2 is the policy verdict and must not
    // be reachable from a malformed invocation (§7).
    let output = generate("klingon");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
}

#[test]
fn a_bare_noun_lists_its_sub_verbs_and_performs_no_action() {
    // §2: a noun never performs a default action. `clap` renders the listing on
    // its error path, so this is a usage error with an empty stdout.
    let output = batten()
        .arg("generate")
        .output()
        .expect("run batten generate");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("completions"),
        "the listing must name the sub-verb"
    );
}

#[test]
fn the_spec_carries_the_new_verbs_with_their_declared_effects() {
    // The surface is the source; `batten spec` is the derivation an agent reads.
    // A verb that exists but is absent from (or misclassified in) the spec is
    // the drift the one-declaration design exists to prevent.
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0));
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");

    let generate = spec["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "generate")
        .expect("generate is in the spec");
    assert_eq!(generate["effect"], "read");

    let completions = generate["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "generate completions")
        .expect("generate completions is in the spec");
    assert_eq!(completions["effect"], "read");
    assert_eq!(completions["flags"][0]["long"], "shell");
    assert_eq!(completions["flags"][0]["takes_value"], true);
}

// --- the two human renderings (CLOUD-69) -------------------------------------
//
// The same three properties the completions above are held to — emitted,
// byte-stable, and identical to the committed copy — asserted over the man
// pages, plus the non-emptiness smoke the markdown reference gets instead of a
// byte-for-byte diff (it is deliberately not committed: it is the CLI reference
// CLOUD-171 renders at publish time, so there is no second copy to diff).

/// The command paths whose pages this repository COMMITS, read off the `man/`
/// directory.
///
/// **This is the committed set, never the declared one, and the distinction is
/// the whole reason the assertion below exists** (CLOUD-1145). The doc comment
/// here used to name `mise-tasks/man-pages.sh` as "the one authority for which
/// pages exist" — which was false in two directions at once. That script was a
/// derivation of `batten spec`, so it was never an authority; and this function
/// never read it, so the crate's own comment described a derivation that did not
/// happen. Retiring the script is what surfaced it.
///
/// So the pairing is explicit: this side is what the tree HAS, and
/// [`declared_pages`] is what the surface SAYS. Every test below diffs one page's
/// bytes and is therefore blind to a page the surface declares and the tree does
/// not carry — that direction is
/// `the_committed_artifacts_are_exactly_the_ones_the_surface_declares`'s.
fn committed_pages() -> Vec<(PathBuf, String)> {
    let dir = at_root("man");
    let mut pages: Vec<(PathBuf, String)> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| {
            let path = entry.expect("read a man/ entry").path();
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("a page filename is UTF-8")
                .to_owned();
            // The filename is the hyphen-joined command path prefixed by the
            // program name; the argv the page is emitted from is the spaced form.
            // RESOLVED AGAINST THE DECLARATION, never guessed back out of the
            // filename. The page name hyphen-joins a command PATH, and `-` is
            // also legal INSIDE a segment — `land fast-forward` commits as
            // `batten-land-fast-forward.1` — so `replace('-', " ")` recovers
            // `land fast forward`, which is no command at all. That spelling was
            // correct for as long as no verb carried a hyphen, and it fails
            // closed rather than silently: the argv does not resolve, the page
            // "did not render", and three cases here name it.
            //
            // The fallback keeps an ORPHAN reaching a failure: a committed page
            // the surface never declared resolves to nothing here, renders
            // nothing, and reddens — which is the direction
            // `the_committed_artifacts_are_exactly_the_ones_the_surface_declares`
            // owns, and this must not quietly pass it.
            let command = declared_commands().get(&stem).cloned().unwrap_or_else(|| {
                stem.strip_prefix("batten-")
                    .map(|rest| rest.replace('-', " "))
                    .unwrap_or_default()
            });
            (path, command)
        })
        .collect();
    pages.sort();
    pages
}

/// Every man page path the COMMAND SURFACE declares, derived from
/// `batten spec --format json` rather than from the directory.
///
/// This is the authority half of the pair [`committed_pages`] describes, and it
/// is derived from the binary's own emitted spec for the reason house style §11
/// gives: completions, man pages and markdown are all derivations of that one
/// runtime-emittable spec. Reading it through the compiled binary rather than
/// through `surface::SURFACE` in-process is deliberate — the shipped binary is
/// what a consumer installs, so a spec that disagreed with the declaration would
/// be caught here rather than assumed away.
///
/// The filename rule is the man convention and matches `render::page_name`: the
/// root page is `man/batten.1`, and every other command path is hyphen-joined
/// under the program name. It is spelled here exactly once, which is what the
/// retired `mise-tasks/man-pages.sh` was for.
fn declared_pages() -> BTreeSet<String> {
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0), "batten spec did not emit");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("the spec is JSON");

    let program = spec["path"]
        .as_str()
        .expect("the spec's root carries the program name");

    // The root page carries the program's own name and no command path, which is
    // the one row `man-pages.sh` emitted with an empty second field.
    let mut pages = BTreeSet::from([format!("man/{program}.1")]);
    collect_pages(&spec, program, &mut pages);
    pages
}

/// Every declared page STEM, mapped to the argv that renders it.
///
/// The inverse of the filename rule, taken from the declaration rather than
/// reconstructed from the name — because the rule is not invertible. Hyphen-
/// joining a command path is lossy the moment a segment contains a hyphen, and
/// two different paths can produce one filename: `land fast-forward` and a
/// hypothetical `land fast forward` both commit as `batten-land-fast-forward.1`.
/// That collision is currently unreachable — no two declared paths collide, and
/// `the_committed_artifacts_are_exactly_the_ones_the_surface_declares` compares
/// the sets — but the ambiguity is in the scheme rather than in this test.
fn declared_commands() -> std::collections::BTreeMap<String, String> {
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0), "batten spec did not emit");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("the spec is JSON");
    let program = spec["path"]
        .as_str()
        .expect("the spec's root carries the program name");
    let mut commands = std::collections::BTreeMap::new();
    collect_commands(&spec, program, &mut commands);
    commands
}

/// Walk every `subcommands` level, recording stem → argv.
fn collect_commands(
    node: &serde_json::Value,
    program: &str,
    into: &mut std::collections::BTreeMap<String, String>,
) {
    let Some(children) = node["subcommands"].as_array() else {
        return;
    };
    for child in children {
        if let Some(path) = child["path"].as_str() {
            into.insert(
                format!("{program}-{}", path.replace(' ', "-")),
                path.to_owned(),
            );
        }
        collect_commands(child, program, into);
    }
}

/// Walk every `subcommands` level, adding one page path per command path.
fn collect_pages(node: &serde_json::Value, program: &str, into: &mut BTreeSet<String>) {
    let Some(children) = node["subcommands"].as_array() else {
        return;
    };
    for child in children {
        if let Some(path) = child["path"].as_str() {
            into.insert(format!("man/{program}-{}.1", path.replace(' ', "-")));
        }
        collect_pages(child, program, into);
    }
}

/// The files a directory actually carries, as repository-relative paths.
fn committed_under(dir: &str) -> BTreeSet<String> {
    let root = at_root(dir);
    fs::read_dir(&root)
        .unwrap_or_else(|err| panic!("read {}: {err}", root.display()))
        .map(|entry| {
            let name = entry.expect("read a directory entry").file_name();
            format!("{dir}/{}", name.to_str().expect("a filename is UTF-8"))
        })
        .collect()
}

/// **The set half, in both directions, over both artifact families**
/// (CLOUD-1145).
///
/// # What this catches that nothing else does
///
/// Every other assertion in this file walks one artifact and diffs its bytes, so
/// each is anchored on a set somebody else chose — and the two families are blind
/// in OPPOSITE directions, which is why one assertion replaces two:
///
/// * `completions/` — the expected set is the fixed [`SHELLS`] const, so a
///   declared-but-uncommitted script fails at `fs::read`, and an EXTRA committed
///   file is never looked at. A stray `completions/batten.elvish` was invisible.
/// * `man/` — the expected set is [`committed_pages`], which reads the
///   directory, so an extra file must render and match, and a page the surface
///   DECLARES with no committed file was invisible.
///
/// Set equality closes all four cells at once rather than patching two of them.
/// It is what `mise-tasks/derived-check.sh`'s `comm -23` reverse scan did, and
/// this is the assertion that carries it.
///
/// # The completions half stays anchored on `SHELLS`, and that is stated rather
/// than hidden
///
/// The spec's `generate completions` row carries the `--shell` flag but **not its
/// value set** — `flags[0]` has `name`/`long`/`takes_value`/`help` and no
/// enumeration. So this asserts that `completions/` holds exactly the files
/// [`SHELLS`] names. That closes the orphan cell honestly; it does not make the
/// const spec-derived, and nothing here claims it does. The man half IS
/// spec-derived, via [`declared_pages`].
///
/// # Pointer-only
///
/// It compares PATHS and never opens a file, so a failure names the artifacts and
/// never a byte of one — non-negotiable rule 4 structurally rather than by
/// habit.
#[test]
fn the_committed_artifacts_are_exactly_the_ones_the_surface_declares() {
    let declared_completions: BTreeSet<String> = SHELLS
        .iter()
        .map(|shell| format!("completions/batten.{shell}"))
        .collect();

    for (family, declared) in [
        ("completions", declared_completions),
        ("man", declared_pages()),
    ] {
        let committed = committed_under(family);

        // Anti-vacuity: an empty expected set would make equality trivially
        // satisfiable by an empty directory, so a wipe of both sides would pass.
        assert!(
            !declared.is_empty(),
            "the surface declares no {family} artifacts, so this assertion would decide nothing"
        );

        let missing: Vec<&String> = declared.difference(&committed).collect();
        assert!(
            missing.is_empty(),
            "the surface declares {family} artifacts the repository does not commit: {missing:?} \
             — run `mise run fix`"
        );

        let orphaned: Vec<&String> = committed.difference(&declared).collect();
        assert!(
            orphaned.is_empty(),
            "the repository commits {family} artifacts the surface does not declare: \
             {orphaned:?} — delete them, or declare the command they belong to"
        );
    }
}

fn generate_man(command: &str) -> Output {
    let mut batten = batten();
    batten.args(["generate", "man"]);
    if !command.is_empty() {
        batten.arg(command);
    }
    batten.output().expect("run batten generate man")
}

#[test]
fn a_page_is_emitted_for_every_command_and_none_is_empty() {
    let pages = committed_pages();
    assert!(!pages.is_empty(), "the repository commits no man pages");
    for (path, command) in pages {
        let output = generate_man(&command);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{} did not render",
            path.display()
        );
        assert!(
            !output.stdout.is_empty(),
            "{} rendered empty",
            path.display()
        );
    }
}

#[test]
fn the_committed_pages_are_the_ones_the_binary_emits() {
    // DoR §4 over the compiled binary, so a stale page fails the Rust suite too
    // and cannot land while only `hk` is skipped.
    for (path, command) in committed_pages() {
        let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        assert_eq!(
            bytes,
            generate_man(&command).stdout,
            "{} differs from the surface; run `mise run man`",
            path.display()
        );
    }
}

#[test]
fn a_page_is_titled_by_the_filename_it_is_committed_as() {
    // man(1) resolves a page by its `.TH` title, so a page whose title and
    // filename disagree is unfindable — and both sides would still be
    // byte-stable and pass every diff above.
    for (path, command) in committed_pages() {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("UTF-8");
        let page = String::from_utf8(generate_man(&command).stdout).expect("roff is UTF-8");
        assert!(
            page.contains(&format!(".TH {stem} 1")),
            "{} is not titled {stem}",
            path.display()
        );
    }
}

#[test]
fn a_page_synopsis_spells_the_invocation_that_parses() {
    // The leaf name is what clap knows a subcommand as, so an unqualified page
    // would document `show` — an invocation that does not parse. Checked on a
    // nested verb, which is the only place the distinction exists.
    let page = String::from_utf8(generate_man("config show").stdout).expect("roff is UTF-8");
    assert!(
        page.contains("batten config show"),
        "the synopsis must spell the full invocation"
    );
}

#[test]
fn an_undeclared_command_is_a_usage_error_not_an_empty_page() {
    // Exit 1 is the config-or-usage code; a page that rendered empty would be
    // committed as a valid artifact by the refresh task.
    let output = generate_man("no-such-verb");
    assert_ne!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
}

#[test]
fn the_markdown_reference_is_emitted_whole_and_byte_stably() {
    // §7's smoke clause for the format that carries no committed copy, plus the
    // §6 stability the publish-time render depends on: the reference is
    // regenerated on every release, and a renderer that varied would make each
    // release's asset differ for no reason.
    let output = batten()
        .args(["generate", "markdown"])
        .output()
        .expect("run batten generate markdown");
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "the reference rendered empty");

    let again = batten()
        .args(["generate", "markdown"])
        .output()
        .expect("run batten generate markdown");
    assert_eq!(
        output.stdout, again.stdout,
        "the reference was not byte-stable"
    );

    let rendered = String::from_utf8(output.stdout).expect("markdown is UTF-8");
    for verb in ["batten check", "batten config show", "batten generate man"] {
        assert!(
            rendered.contains(verb),
            "the reference must document `{verb}`"
        );
    }
}

#[test]
fn the_markdown_reference_is_not_committed() {
    // The whole point of CLOUD-171: a reference derived at publish time is
    // current by construction. A committed copy would be the second authority
    // this design removes, and it would need a drift gate nothing here provides.
    //
    // TRACKED, not PRESENT. This asserted `!exists()` when it landed with
    // CLOUD-69, which was the wrong predicate and only looked right because
    // nothing rendered the file yet: `mise run render:cli` writes it into a
    // git-ignored directory on every release and on every `reference-check`
    // run, so "present" became the ordinary state and the case failed on a
    // tree doing exactly what it should. Committed is a question for git.
    let root = at_root(".");
    for candidate in ["reference/batten-cli-reference.md", "docs/cli.md", "CLI.md"] {
        assert!(
            git_in(&root, &["ls-files", "--", candidate]).is_empty(),
            "{candidate} is tracked; the reference is rendered at publish time"
        );
    }
}
