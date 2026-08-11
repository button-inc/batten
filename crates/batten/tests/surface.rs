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

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use common::{at_root, batten, scratch};

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

/// The command paths whose pages this repository commits, read from the derived
/// list rather than enumerated: `mise-tasks/man-pages` is the one authority for
/// which pages exist, and a list re-typed here would be a second one.
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
            let command = stem
                .strip_prefix("batten-")
                .map(|rest| rest.replace('-', " "))
                .unwrap_or_default();
            (path, command)
        })
        .collect();
    pages.sort();
    pages
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
    for candidate in ["reference/batten-cli-reference.md", "docs/cli.md", "CLI.md"] {
        assert!(
            !at_root(candidate).exists(),
            "{candidate} is committed; the reference is rendered at publish time"
        );
    }
}
