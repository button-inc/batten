//! `policy/run-shape.rego` decides over the compiled binary (CLOUD-843 track 2).
//!
//! # Where this came from, and why it is Rust
//!
//! This file is the successor to `tests/run-shape.bats`, retired under
//! CLOUD-1059. The suite's own subject was `policy/run-shape.rego`, which
//! CLOUD-1050 rewrote: the module's refusal stopped being prose and became a
//! declared class. Its cases asserted the prose, so they went red — and
//! `shell-retirement` refuses editing a bats suite in place, which is the whole
//! point of that gate. Both doors shut on an edit; the open one is the
//! migration, and this is it. Every case below carries a `// carried:` arm.
//!
//! # What it keeps, unchanged
//!
//! **It drives the compiled binary over a real envelope**, which is the reason
//! the suite existed at all rather than a convenience. `batten policy test` is
//! established as insufficient evidence (CLOUD-845): `with input as` lets a
//! module's own test fabricate a shape the engine cannot produce, so a module
//! can pass its suite green and gate nothing. Every case here goes in through
//! `batten hook` — the same door a mediated call comes through — and reads the
//! permission decision the host would read.
//!
//! The fixture is a throwaway repository carrying ONE row and a copy of the
//! COMMITTED module, so the predicate is exercised in isolation from this
//! repository's other rules and cannot drift from the module that ships.
//!
//! # The status assertion is load-bearing, and it was a defect once
//!
//! `batten hook` prints NOTHING on an allow — the JSON is emitted only to deny —
//! and exits 0 either way, because the contract is that the harness reads the
//! decision and not the code. So a check of the form "the output does not
//! contain `deny`" is true over an EMPTY string, and every allow case in the
//! retired suite went green on any output at all, including the output of a
//! binary that died before it judged anything. That was CLOUD-251's vacuous pass
//! wearing a test's clothes, suite-wide. Both helpers below assert the status.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). See the sibling note in
// `privileged_lane.rs` for why one marker carries two disjoint ledgers.
//
// carried: tests/run-shape.bats policy/run-shape.rego crates/batten/tests/run_shape.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

/// A throwaway repository carrying the committed module and the one row that
/// enables it, plus the `[[pattern]]` and `[[verdict]]` rows it needs.
///
/// The pattern row is not decoration: an inline regex is refused at load, so
/// without it the module's reference is undefined and every allow case flips to
/// a denial — the silent disarm the engine refuses outright (CLOUD-885). The
/// verdict row is its sibling under CLOUD-1050: a token no row declares is
/// refused at load, so a fixture without it would be testing that refusal.
///
/// # One scratch tree PER CASE, and the shared one was a real race
///
/// `name` is not decoration. Every case here built `scratch("run-shape")`, and
/// `nextest` runs each case in its own process concurrently — so one case was
/// recreating the tree while another was reading it, and the reader got a
/// directory with no `batten.toml` in it. It surfaced as
/// `a_git_commit_naming_no_message_source_is_denied` failing on its SECOND
/// assertion with empty output, intermittently, which is exactly what a
/// half-written fixture looks like from the outside. The sibling
/// `privileged_lane.rs` had the per-case shape from the start; this file did not,
/// and the difference is why only this one flaked.
fn fixture(name: &str) -> PathBuf {
    let root = common::scratch(&format!("run-shape-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    let module = common::at_root("policy/run-shape.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/run-shape.rego")).expect("install committed module");
    fs::write(
        root.join("batten.toml"),
        concat!(
            "version = 1\n\n",
            "[[rule]]\n",
            "id = \"commit-message-obtainable\"\n",
            "kind = \"policy\"\n",
            "scope = \"mediated_call\"\n",
            "module = \"policy/run-shape.rego\"\n",
            "severity = \"deny\"\n\n",
            "[[pattern]]\n",
            "id = \"short-message-flag-cluster\"\n",
            "regex = \"^-[A-Za-z]*[mFCc]\"\n\n",
            "[[verdict]]\n",
            "id = \"V-COMMIT-WITHOUT-A-MESSAGE-SOURCE\"\n",
            "gloss = \"a `git commit` names no message source, so git opens $EDITOR and blocks\"\n",
            "class = \"\"\"\n",
            "No `-m`, `-F`, `-C`, `--no-edit`, `--fixup` or `--squash`. Git opens $EDITOR and \\\n",
            "blocks, AFTER `pre-commit` has already spent the whole gate. Write the message to \\\n",
            "a file and use `git commit -F <path>`, the one form that cannot rebind.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"R-COMMIT-FROM-A-FILE\"\n",
            "kind = \"command\"\n",
            "target = \"git commit -F <path>\"\n",
        ),
    )
    .expect("write the fixture authority");
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
}

/// Hand `command` to the engine as a Claude Code `PreToolUse` envelope.
fn hook(root: &Path, command: &str) -> (bool, String) {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let output = common::run_with_stdin(root, &["hook", "--harness", "claude-code"], &envelope);
    // THE STATUS IS PART OF THE ANSWER. Allow and deny both exit 0, so a
    // non-zero status is exactly and only the crash — and without this check an
    // allow assertion passes over a binary that died before judging anything.
    assert_eq!(
        output.status.code(),
        Some(0),
        "the engine decided rather than crashed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    (text.contains(r#""permissionDecision":"deny""#), text)
}

fn denied(root: &Path, command: &str) {
    let (deny, text) = hook(root, command);
    assert!(deny, "`{command}` should be refused: {text}");
}

fn allowed(root: &Path, command: &str) {
    let (deny, text) = hook(root, command);
    assert!(!deny, "`{command}` should be allowed: {text}");
}

// ---------------------------------------------------------------------------
// The predicate.
// ---------------------------------------------------------------------------

// carried: "THE MEASURED SHAPE: a git commit naming no message source is denied" crates/batten/tests/run_shape.rs
#[test]
fn a_git_commit_naming_no_message_source_is_denied() {
    // `pre-commit` runs before git asks for a message, so this spends the whole
    // gate and then blocks on $EDITOR with nobody to close it (CLOUD-488).
    let root = fixture("no-message-source");
    denied(&root, "git commit");
    denied(&root, "git commit -a");
}

// carried: "every form that CAN obtain a message stays allowed" crates/batten/tests/run_shape.rs
#[test]
fn every_form_that_can_obtain_a_message_stays_allowed() {
    // The load-bearing half. A predicate that only ever denied would satisfy the
    // case above and be useless (CLOUD-418).
    let root = fixture("obtainable");
    for command in [
        "git commit -F /tmp/msg.txt",
        "git commit -m \"a message\"",
        "git commit -am \"a message\"",
        "git commit --amend --no-edit",
        "git commit --fixup HEAD",
        "git commit -C HEAD@{1}",
        "git commit --message=hello",
        "git commit -F -",
    ] {
        allowed(&root, command);
    }
}

// carried: "THE MEASURED SHAPE: a token carrying an m is not a flag cluster" crates/batten/tests/run_shape.rs
#[test]
fn a_token_carrying_an_m_is_not_a_flag_cluster() {
    // CLOUD-885. The rule reads "one `-`, then LETTERS, at least one of which
    // selects a message source". Before `regex.match` it was spelled as
    // `contains` over the flag's tail, which cannot say "letters" — so `-x=mfoo`
    // carried an `m`, read as naming a message source, and a commit that still
    // blocks on $EDITOR went through.
    //
    // This is the discriminating case rather than another `-m`: the suite as it
    // stood covered `-m`, `-am`, `-F`, `-C` and the long forms, and every one of
    // them passes under BOTH spellings.
    let root = fixture("short-cluster");
    denied(&root, "git commit -x=mfoo");
    // The other direction, so the anchor is proven and not just the class: a
    // message flag must be reached from the START of the cluster. `-vm` is one.
    allowed(&root, "git commit -vm \"a message\"");
}

// ---------------------------------------------------------------------------
// The list, which is where a raw-string module goes silent.
// ---------------------------------------------------------------------------

// carried: "a compound list is judged per element, not by its first word" crates/batten/tests/run_shape.rs
#[test]
fn a_compound_list_is_judged_per_element() {
    // THE SHAPE A RAW-STRING MODULE MISSES. The vendored `no-force-push` preset
    // anchors on `words[0] == "git"` over the whole command, so `cd /tmp && git
    // push --force` reaches it as `cd` and is allowed — green tests, silent
    // gate. Every element is a command here.
    let root = fixture("list-element");
    denied(&root, "cd /tmp && git commit");
    allowed(&root, "git add -A && git commit -m x");
}

// carried: "a pipe stage is judged too" crates/batten/tests/run_shape.rs
#[test]
fn a_pipe_stage_is_judged_too() {
    denied(&fixture("pipe-stage"), "echo hi | git commit");
}

// carried: "a wrapper is looked through to the program it runs" crates/batten/tests/run_shape.rs
#[test]
fn a_wrapper_is_looked_through_to_the_program_it_runs() {
    let root = fixture("wrapper");
    denied(&root, "timeout 300 git commit");
    allowed(&root, "timeout 300 git commit -m x");
}

// ---------------------------------------------------------------------------
// Scrubbing: prose is not a call.
// ---------------------------------------------------------------------------

// carried: "a git commit inside a quoted span is prose, not a call" crates/batten/tests/run_shape.rs
#[test]
fn a_git_commit_inside_a_quoted_span_is_prose() {
    // This repository writes the shape down constantly — in commit messages, in
    // issue bodies, in this file. A module judging the raw string would refuse
    // its own documentation.
    let root = fixture("quoted-span");
    allowed(&root, "echo \"git commit\"");
    allowed(&root, "echo 'git commit'");
}

// carried: "a quoted span carrying a list separator is not a list" crates/batten/tests/run_shape.rs
#[test]
fn a_quoted_span_carrying_a_list_separator_is_not_a_list() {
    // THE CASE THAT DISCRIMINATES the quote scrub. A quoted mention with no
    // separator in it is already safe by the program anchoring above; what needs
    // the scrub is a message that carries a `;` or `&&`, because the list split
    // would otherwise turn the tail of a commit message into its own command.
    // Both quote characters, because they are two passes.
    let root = fixture("quoted-separator");
    allowed(&root, "echo \"step one; git commit -x\"");
    allowed(&root, "echo 'step one; git commit -x'");
}

// carried: "a git commit inside a heredoc body is prose, not a call" crates/batten/tests/run_shape.rs
#[test]
fn a_git_commit_inside_a_heredoc_body_is_prose() {
    allowed(
        &fixture("heredoc-body"),
        "cat > t.bats <<BATS\ngit commit\nBATS\n",
    );
}

// carried: "an unquoted mention does not resolve to git" crates/batten/tests/run_shape.rs
#[test]
fn an_unquoted_mention_does_not_resolve_to_git() {
    // The anchoring, without which `echo git commit` reads as a call.
    allowed(&fixture("unquoted-mention"), "echo git commit");
}

// carried: "a heredoc or redirect bound to this element is a message source" crates/batten/tests/run_shape.rs
#[test]
fn a_heredoc_or_redirect_bound_to_this_element_is_a_message_source() {
    let root = fixture("bound-source");
    allowed(&root, "git commit -F - <<'EOF'\nmsg\nEOF\n");
    allowed(&root, "git commit -F - < /tmp/msg.txt");
}

// ---------------------------------------------------------------------------
// The refusal itself.
// ---------------------------------------------------------------------------

// changed: "the refusal names its predicate and the remedy that cannot rebind" crates/batten/tests/run_shape.rs the remedy moved from the module's prose into the declared class, so the assertion is over the token and the route rather than over three substrings of a sentence (CLOUD-1050)
#[test]
fn the_refusal_names_its_predicate_its_class_and_the_route_out() {
    // A migrated gate keeps its remedy (CLOUD-437): a refusal that lost it in
    // translation is a regression no `policy test` would catch. What CHANGED is
    // where the remedy lives. It used to be three substrings of the module's own
    // prose — `-F <path>`, `pre-commit`, the predicate id — and a policy deny
    // carried `Fix::None`, so the module had to remember to write them.
    //
    // Now the class is declared: `Fix` comes off the class's first `command`
    // route, so "a refusal names a way out" holds by construction rather than by
    // each module's care, and `verdict::validate` refuses a class that declares
    // none. So this asserts the token, the gloss and the route — the three
    // things a reader acts on — rather than a sentence that may be reworded.
    let root = fixture("refusal-class");
    let (deny, text) = hook(&root, "git commit");
    assert!(deny, "the shape is still refused: {text}");
    assert!(
        text.contains("commit-names-no-message-source"),
        "the predicate id: {text}"
    );
    assert!(
        text.contains("V-COMMIT-WITHOUT-A-MESSAGE-SOURCE"),
        "the declared class: {text}"
    );
    assert!(
        text.contains("git commit -F <path>"),
        "the route out, taken off the class rather than out of the module: {text}"
    );
}

// carried: "git -C <path> commit is a deliberate false negative, carried over" crates/batten/tests/run_shape.rs
#[test]
fn git_c_path_commit_is_a_deliberate_false_negative() {
    // The bash guard resolved `sub1` to the path and let it through, because a
    // guard with false positives gets bypassed (CLOUD-199) and this repository
    // commits from its own root. A migration that silently fixed it would be
    // changing the predicate, not moving it.
    allowed(&fixture("dash-c"), "git -C /some/path commit");
}

// carried: "a command with no git commit in it at all is untouched" crates/batten/tests/run_shape.rs
#[test]
fn a_command_with_no_git_commit_in_it_is_untouched() {
    let root = fixture("untouched");
    allowed(&root, "ls -la");
    allowed(&root, "hg commit");
}
