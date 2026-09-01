//! The lockfile has no partial or bogus entry, over the compiled binary
//! (CLOUD-223/227/281/333/593, ported under CLOUD-843).
//!
//! **This is the tier `policy/lock-complete.rego`'s own `test_` rules cannot
//! be**, and here that is not a formality. The whole design of this gate is
//! WHICH SIDE OF THE INDEX the bytes came from: a `with input as` block writes
//! the staged map it then reads, so it is green whether the engine handed over
//! the index, the checkout, or nothing at all. `the_index_answers_not_the_
//! worktree_for_the_committed_rule` is the case that discriminates, and it is
//! the property the predecessor claimed in its header and did not have.
//!
//! **A second engine property is decidable only here**: `mise.lock` carries an
//! extension no `Format` owns, so `Format::for_path` refuses it before a byte is
//! read and the row DECLARES the format instead. A module reaching for
//! `input.tree.staged["mise.lock"]` without that declaration gets undefined,
//! denies nothing, and loads clean — which is the class
//! `.claude/rules/policy-modules.md` opens with, and which
//! `policy/lock-entry-complete.rego` was a live instance of on `main`.
//!
//! The ledger for this member: two deleted paths and thirty-seven deleted
//! `@test` cases. The successor is a consumer module, so no `kind:` field is
//! owed. A THIRD path goes with them and owes no arm —
//! `policy/lock-entry-complete.rego` is neither a `mise-tasks/` program nor a
//! `.bats` suite, so `shell-retirement` does not govern it; the note below says
//! where its predicate went anyway, because a reader looking for it should not
//! have to reconstruct that from the absence of a row.
//
// carried: mise-tasks/lock-complete.sh policy/lock-complete.rego crates/batten/tests/it/lock_complete.rs
// carried: tests/lock-complete.bats policy/lock-complete.rego crates/batten/tests/it/lock_complete.rs
//
// carried: "the repo's real lockfile is complete today" policy/lock-complete.rego
// carried: "the shipped residue: a platform key mise does not emit is caught" policy/lock-complete.rego
// carried: "a required platform with a block but no url is caught" policy/lock-complete.rego
// carried: "a required platform missing entirely is caught" policy/lock-complete.rego
// carried: "a url-less stub on a NON-required platform passes — mise emits those, upstream ships no artifact" policy/lock-complete.rego
// carried: "a tool that locks no platform is exempt only if its backend cannot lock one" policy/lock-complete.rego
// carried: "an asset-fetching backend that locks no platform is unlocked, not exempt" policy/lock-complete.rego
// carried: "the exemption is an allowlist, so an unrecognised backend must lock" policy/lock-complete.rego
// carried: "a tool that locks no platform and declares no backend is a failure" policy/lock-complete.rego
// carried: "quoted and unquoted tool names are both parsed" policy/lock-complete.rego
// carried: "output is a pointer — file:line, never a checksum or url" policy/lock-complete.rego
// carried: "with no argument it gates the index, not the working tree" policy/lock-complete.rego
// carried: "with no argument a residue key that IS staged still fails" policy/lock-complete.rego
// carried: "mise.toml re-enabling lockfile writes is a violation" policy/lock-complete.rego
// carried: "a lockfile key outside [settings] is not the setting" policy/lock-complete.rego
// carried: "the shape that escaped: a [tools] entry with no mise.lock entry is caught" policy/lock-complete.rego
// carried: "a declared tool that IS locked passes — the clause fires on the gap, not on the table" policy/lock-complete.rego
// carried: "npm, pipx and rust are exempt from the presence rule too" policy/lock-complete.rego
// carried: "the presence exemption is an allowlist, so a bare name other than rust must lock" policy/lock-complete.rego
// carried: "unlocked-tool output is a pointer — no checksum, no url" policy/lock-complete.rego
// carried: "a workflow using mise-action without MISE_LOCKFILE is caught" policy/lock-complete.rego
// carried: "the same workflow with MISE_LOCKFILE set passes" policy/lock-complete.rego
// carried: "a workflow that does not use mise-action needs nothing" policy/lock-complete.rego
// carried: "a partial pin the lock EXTENDS passes — satisfaction, not equality" policy/lock-complete.rego
// carried: "the extension must be at a component boundary, not a string prefix" policy/lock-complete.rego
// carried: "an inline-table pin is read, not only the bare-string form" policy/lock-complete.rego
// carried: "a pin that is not a plain dotted version is skipped rather than guessed at" policy/lock-complete.rego
// carried: "stale-lock output is a pointer — no checksum, no url" policy/lock-complete.rego
//
// THE NINE CASES THAT CANNOT BE CARRIED VERBATIM, each with what changed and
// why. None is a coverage loss the ledger is hiding: every one is a property of
// the PROGRAM's interface rather than of the predicate, and the interface is
// exactly what a `[[rule]]` replaces.
//
// changed: "the required set is overridable, and actually changes the verdict" policy/lock-complete.rego `BATTEN_LOCK_PLATFORMS` is gone rather than ported. A module reads no environment, and the set a repository installs on is committed config that belongs in a reviewed diff rather than in a knowable string anyone can spend to make the gate agree with them — the reasoning CLOUD-1051 applied to two override passwords one campaign over. `required_platforms` is a literal in the module now and changing it is a diff
// changed: "it makes no network call and does not touch the lockfile" policy/lock-complete.rego a grep over the program's executable lines has no successor and needs none: `kind = "policy"` is declared `read`, so the engine's effect model refuses a module a spawn or a write structurally rather than by asserting the absence of a string. house-style §5's read-only allowlist is the mechanism, and it is stronger than the assertion it replaces because it cannot be satisfied by spelling the call differently
// changed: "a missing lockfile exits 2, distinct from an incomplete one" policy/lock-complete.rego both are exit 2 now, and that is the house contract rather than a regression: AGENTS.md non-negotiable rule 5 and house-style §6-7 give one exit table with no per-verb exception, where 2 is the policy verdict for a check violation and a hook deny alike. The DISTINCTION survives where it is read — `V-LOCK-UNREADABLE` is its own verdict token with its own remedy, so could-not-look and incomplete are still two classes
// changed: "with no argument and no mise.lock in the index, exit 2" policy/lock-complete.rego the same exit change, plus a narrowing that is the whole of CLOUD-1164's lesson: a `[[rule]]` has no call site, so an unconditional refusal over an absent lockfile would speak in every fixture repository inheriting this config. It is conditioned on a staged `mise.toml` declaring a `[tools]` table — the repository saying it locks something — and is silent where there is no subject
// changed: "lockfile = false passes, and the lockfile clauses keep their own header" policy/lock-complete.rego there are no headers. The predecessor printed one `::error::` banner per clause and tracked a `reported` flag so an earlier clause could not swallow a later one; findings are one pointer line each here, so the failure mode that case existed for is unspellable. The half of it that survives is that both classes are reported at once, which every multi-finding case below exercises
// changed: "fixture mode does not consult mise.toml at all" policy/lock-complete.rego there is no fixture mode: a rule takes no argument, so the program's `$1` path and the boundary it kept between "these bytes" and "this repository" have no successor. The distinction it protected is preserved differently and better — every case in this file is a whole repository, so a run makes exactly the claims that repository's own index supports
// changed: "fixture mode does not consult mise.toml for the presence rule either" policy/lock-complete.rego the same, one clause over
// changed: "a pin naming a version its lock entry does not is caught, and both are named" policy/lock-complete.rego the finding names the tool and the pin's line, and no longer echoes the two version strings. `subjects` is a tagged pointer — `{path}`, `{path, line}`, `{count}`, `{artifact}` — so a bare string has nowhere to go, and non-negotiable rule 4 is structural here rather than a habit. What a reader loses is one round trip; what the class gains is that no finding over this file can ever carry a lockfile byte
// subsumed: "a comment inside [tools] is not a tool" policy/lock-complete.rego crates/batten/tests/it/policy_input_schema.rs
//
// AND ONE MODULE IS SUBSUMED RATHER THAN LEFT BESIDE THIS ONE.
// `policy/lock-entry-complete.rego` decided a strict subset of predicate 2 — a
// platform block carrying a checksum and no url — and two rows over one question
// is the second authority this repository refuses everywhere else. Its verdict
// token `V-LOCK-ENTRY-PARTIAL` is raised here now, so the registry row is
// conserved rather than retired, and its two cases in `staged_facts.rs` are
// repointed at this module.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{git_in, run, scratch, stdout, write};

/// The rule ids this module publishes, which is also what `--rule` selects.
const RULE: &str = "lock-complete";

/// A lockfile entry for one tool, complete for whichever platforms are named.
fn tool_with(name: &str, platforms: &[&str]) -> String {
    let mut out = format!("[[tools.\"{name}\"]]\nversion = \"1.0.0\"\nbackend = \"aqua:x/t\"\n\n");
    for platform in platforms {
        // Bound to a local first: `push_str` of a `format!` is
        // `clippy::format_push_string`, which the workspace denies.
        let block = format!(
            "[tools.\"{name}\".\"platforms.{platform}\"]\nchecksum = \"sha256:abc\"\nurl = \"https://example.invalid/{platform}\"\n\n"
        );
        out.push_str(&block);
    }
    out
}

/// The three platforms this repository installs on, complete.
fn complete_lock() -> String {
    tool_with("t", &["linux-x64", "linux-arm64", "macos-arm64"])
}

/// A manifest pinning `t` and nothing else, with the write setting off.
fn manifest(tools: &str) -> String {
    format!("[settings]\nlockfile = false\n\n[tools]\n{tools}")
}

/// Materialize a repository carrying the committed module and this row.
///
/// **The module is COPIED from the tree rather than restated inline**, on
/// `rules_drift.rs`' precedent: a fixture that re-typed the predicate would be a
/// second implementation, and it would pass over a module the engine can no
/// longer load. The `[[pattern]]` and `[[verdict]]` rows are restated, because
/// they are CONSUMER config and the engine refuses at load a module raising a
/// token no row declares.
fn fixture(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = scratch(name);
    let module = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy/lock-complete.rego"),
    )
    .expect("the committed module");
    write(&dir, "policy/lock-complete.rego", &module);
    write(&dir, "batten.toml", CONFIG);
    for (path, body) in files {
        write(&dir, path, body);
    }
    git_in(&dir, &["init", "--initial-branch=main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-m", "fixture"]);
    dir
}

/// Judge the fixture on this one rule, and return what it said.
fn judge(dir: &Path) -> (Option<i32>, String) {
    let out = run(dir, &["check", "--rule", RULE]);
    (out.status.code(), stdout(&out))
}

/// The common shape: a lockfile, a manifest, and whatever else a case adds.
fn judge_repo(name: &str, lock: &str, mise: &str, extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut files: Vec<(&str, &str)> = vec![("mise.lock", lock), ("mise.toml", mise)];
    files.extend_from_slice(extra);
    judge(&fixture(name, &files))
}

#[test]
fn a_complete_lockfile_is_clean() {
    // THE ANTI-VACUITY MIRROR for every case below. Without it a rule that
    // refused everything would satisfy each of them, and the failure this whole
    // file exists for is the one that is invisible.
    let (code, said) = judge_repo(
        "lock-complete-clean",
        &complete_lock(),
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(0), "a complete lockfile is clean\n{said}");
}

#[test]
fn a_platform_key_mise_does_not_emit_is_reported() {
    // THE SHIPPED RESIDUE. `ubi:rust-cross/cargo-zigbuild` carried
    // `linux-x64-cargo-zigbuild` with a checksum and no url for its whole life,
    // and `lock-check` reported "complete and current" over it on every run.
    let lock = format!(
        "{}[tools.\"t\".\"platforms.linux-x64-t\"]\nchecksum = \"blake3:abc\"\n",
        complete_lock()
    );
    let (code, said) = judge_repo(
        "lock-complete-residue",
        &lock,
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(2), "install-time residue is a finding\n{said}");
    assert!(
        said.contains("lock-platform-residue"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_url_less_stub_on_a_non_required_platform_is_untouched() {
    // THE NEAR-MISS this gate was nearly built with. mise emits a
    // provenance-only stub where upstream ships no artifact — zizmor's two musl
    // entries are exactly that, and `mise lock` regenerates them — so failing on
    // every url-less block would fail this repo for a decision upstream made.
    let lock = format!(
        "{}[tools.\"t\".\"platforms.linux-x64-musl\"]\nprovenance = \"github-attestations\"\n",
        complete_lock()
    );
    let (code, said) = judge_repo(
        "lock-complete-stub",
        &lock,
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(0), "a non-required stub is not a defect\n{said}");
}

#[test]
fn a_required_platform_missing_entirely_is_reported() {
    let (code, said) = judge_repo(
        "lock-complete-missing-platform",
        &tool_with("t", &["linux-x64", "linux-arm64"]),
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(2), "an unlocked platform is a finding\n{said}");
    assert!(
        said.contains("lock-platform-uninstallable"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn an_asset_backend_that_locks_no_platform_is_reported() {
    // CLOUD-281 VERBATIM: the entry that passed for its whole life. Keying the
    // exemption on the ABSENCE rather than on the backend is what let the one
    // tool here installed from an unverified download sit with a bare version.
    let lock = "[[tools.\"ubi:rust-cross/cargo-zigbuild\"]]\nversion = \"0.23.0\"\nbackend = \"ubi:rust-cross/cargo-zigbuild\"\n";
    let (code, said) = judge_repo("lock-complete-unlocked", lock, &manifest(""), &[]);
    assert_eq!(code, Some(2), "an unverified download is a finding\n{said}");
    assert!(
        said.contains("lock-tool-unlocked"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_backend_that_cannot_lock_a_url_is_exempt() {
    // THE ANTI-VACUITY MIRROR for the case above: npm, pipx and core:rust
    // resolve through their own package manager and lock no URLs, so locking
    // nothing is the whole truth about them.
    let lock = "[[tools.\"core:rust\"]]\nversion = \"1.85.0\"\nbackend = \"core:rust\"\n\n\
                [[tools.\"npm:prettier\"]]\nversion = \"3.0.0\"\nbackend = \"npm:prettier\"\n";
    let (code, said) = judge_repo("lock-complete-exempt", lock, &manifest(""), &[]);
    assert_eq!(
        code,
        Some(0),
        "a backend that locks nothing is exempt\n{said}"
    );
}

#[test]
fn a_declared_tool_with_no_lock_entry_is_reported() {
    // CLOUD-333, and the one failure a local run structurally cannot see:
    // `[settings] lockfile = false` means nothing here installs `--locked`, so
    // an unlocked tool installs fine on this machine forever while CI dies at
    // the INSTALL step, before a single gate runs. Measured on PR #272.
    let (code, said) = judge_repo(
        "lock-complete-unlocked-tool",
        &complete_lock(),
        &manifest("\"t\" = \"1.0.0\"\n\"aqua:foresterre/cargo-msrv\" = \"0.18.0\"\n"),
        &[],
    );
    assert_eq!(
        code,
        Some(2),
        "a declared tool with no entry is a finding\n{said}"
    );
    assert!(
        said.contains("lock-tool-missing"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_pin_its_entry_does_not_name_is_reported() {
    // CLOUD-593. The row being PRESENT is exactly what makes a stale one
    // invisible, and `--locked` validates the whole file, so every job goes red
    // at the install step rather than the ones that use the tool.
    let (code, said) = judge_repo(
        "lock-complete-stale",
        &complete_lock(),
        &manifest("\"t\" = \"2.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(2), "a stale pin is a finding\n{said}");
    assert!(
        said.contains("lock-pin-stale"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_partial_pin_the_lock_extends_is_untouched() {
    // SATISFACTION, NOT EQUALITY, and it is the majority of this repo's table:
    // `node = "24"` locks 24.19.0. A raw comparison would refuse the real tree
    // on most of its own pins.
    let (code, said) = judge_repo(
        "lock-complete-satisfied",
        &complete_lock(),
        &manifest("\"t\" = \"1.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(0), "an extended pin is satisfied\n{said}");
}

#[test]
fn re_enabled_lockfile_writes_are_reported() {
    // CLOUD-223: the other half of the residue predicate rather than a separate
    // concern. Every residue key this gate rejects was written by an install, so
    // the gate is half a mechanism while any `mise install` can produce one.
    let (code, said) = judge_repo(
        "lock-complete-writes",
        &complete_lock(),
        "[settings]\nlockfile = true\n\n[tools]\n\"t\" = \"1.0.0\"\n",
        &[],
    );
    assert_eq!(code, Some(2), "re-enabled writes are a finding\n{said}");
    assert!(
        said.contains("lockfile-writes-enabled"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn a_workflow_installing_without_the_lockfile_env_is_reported() {
    // The workflow clause is the one predicate here reading the LINE surface
    // rather than the index, and this is where that reaches the engine: a glob,
    // because `staged` takes literal paths and a hand-maintained inventory of
    // workflows would be a silent hole in exactly the gate that closes one.
    let (code, said) = judge_repo(
        "lock-complete-workflow",
        &complete_lock(),
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[(
            ".github/workflows/w.yml",
            "jobs:\n  a:\n    steps:\n      - uses: jdx/mise-action@abc\n",
        )],
    );
    assert_eq!(code, Some(2), "an unlocked install is a finding\n{said}");
    assert!(
        said.contains("workflow-installs-unlocked"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn the_same_workflow_setting_the_env_is_untouched() {
    let (code, said) = judge_repo(
        "lock-complete-workflow-ok",
        &complete_lock(),
        &manifest("\"t\" = \"1.0.0\"\n"),
        &[(
            ".github/workflows/w.yml",
            "env:\n  MISE_LOCKFILE: \"true\"\njobs:\n  a:\n    steps:\n      - uses: jdx/mise-action@abc\n",
        )],
    );
    assert_eq!(code, Some(0), "a locked install is clean\n{said}");
}

#[test]
fn the_index_answers_not_the_worktree_for_the_committed_rule() {
    // THE DISCRIMINATING CASE, and the property the predecessor's header claimed
    // and did not have (CLOUD-227). A cold `mise install` writes the residue key
    // itself, so a gate reading the checkout was red in every agent sandbox and
    // green in the one CI job that runs it — for the same commit. The fixture
    // commits a clean lockfile and then leaves the residue UNSTAGED.
    let dir = fixture(
        "lock-complete-index",
        &[
            ("mise.lock", &complete_lock()),
            ("mise.toml", &manifest("\"t\" = \"1.0.0\"\n")),
        ],
    );
    write(
        &dir,
        "mise.lock",
        &format!(
            "{}[tools.\"t\".\"platforms.linux-x64-t\"]\nchecksum = \"blake3:abc\"\n",
            complete_lock()
        ),
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(0),
        "the bytes a commit would carry are what is judged\n{said}"
    );

    // AND THE MIRROR, without which the case above passes over a module that
    // read nothing at all: stage the same residue and it must be reported.
    git_in(&dir, &["add", "mise.lock"]);
    let (staged, also) = judge(&dir);
    assert_eq!(staged, Some(2), "a staged residue key still fails\n{also}");
    assert!(
        also.contains("lock-platform-residue"),
        "the finding names its rule\n{also}"
    );
}

#[test]
fn an_unreadable_lockfile_a_manifest_depends_on_is_refused() {
    // COULD-NOT-LOOK, and it reaches the module through `input.tree.missing` —
    // the channel CLOUD-1049 made live. A declared `staged` path with no index
    // entry is `Absent` there rather than an empty node, so this is a finding
    // rather than a clean tree over a lockfile nobody could read.
    let (code, said) = judge(&fixture(
        "lock-complete-unreadable",
        &[("mise.toml", &manifest("\"t\" = \"1.0.0\"\n"))],
    ));
    assert_eq!(code, Some(2), "an unreadable lockfile is a finding\n{said}");
    assert!(
        said.contains("lock-unreadable"),
        "the finding names its rule\n{said}"
    );
}

#[test]
fn an_unreadable_lockfile_no_manifest_depends_on_is_silent() {
    // THE SCOPE MIRROR, and it is Finding 7's class from `tree-clean` avoided
    // rather than survived: a `[[rule]]` has no call site, so an unconditional
    // refusal here would speak in every fixture repository inheriting this
    // config. A repository declaring no tools has no subject.
    let (code, said) = judge(&fixture(
        "lock-complete-no-subject",
        &[("mise.toml", "[settings]\nlockfile = false\n")],
    ));
    assert_eq!(code, Some(0), "no subject means nothing to report\n{said}");
}

#[test]
fn the_finding_is_a_pointer_and_never_a_checksum_or_a_url() {
    // Non-negotiable rule 4, and the specific hazard: everything this gate reads
    // is a checksum or a download URL, so a finding echoing the offending value
    // would put the payload on the channel the pointer contract reserves.
    let lock = format!(
        "{}[tools.\"t\".\"platforms.linux-x64-t\"]\nchecksum = \"blake3:deadbeef\"\nurl = \"https://example.invalid/leak\"\n",
        complete_lock()
    );
    let (code, said) = judge_repo(
        "lock-complete-pointer",
        &lock,
        &manifest("\"t\" = \"2.0.0\"\n"),
        &[],
    );
    assert_eq!(code, Some(2), "the fixture is meant to be refused\n{said}");
    assert!(!said.contains("blake3:"), "no checksum is echoed\n{said}");
    assert!(!said.contains("https://"), "no url is echoed\n{said}");
}

/// The row, its one pattern and every verdict token the module raises.
///
/// `pub(crate)` for `staged_facts.rs`, which drives this same committed module to
/// assert the ENGINE property it owns — that a declared `staged` path reaches a
/// registered row at all. A second copy of the verdict registry there is how the
/// two would come to disagree about which tokens the module may raise, and the
/// engine refuses at load a module raising one no row declares.
pub(crate) const CONFIG: &str = r#"version = 1

[[pattern]]
id = "plain-dotted-version"
regex = '^[0-9]+(\.[0-9]+)*$'

[[rule]]
id = "lock-complete"
kind = "policy"
scope = "tree"
module = "policy/lock-complete.rego"
severity = "deny"
staged = ["mise.lock", "mise.toml"]
format = "toml"
line_sources = ["mise.lock", "mise.toml", ".github/workflows/*.yml"]

[[verdict]]
id = "V-LOCK-PLATFORM-RESIDUE"
gloss = "a platform key mise does not emit"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-RESIDUE"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-PLATFORM-UNINSTALLABLE"
gloss = "a required platform nothing can be installed from"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-UNINSTALLABLE"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-ENTRY-PARTIAL"
gloss = "a platform block with a checksum and nothing to fetch"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-PARTIAL"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-TOOL-UNLOCKED"
gloss = "an asset-fetching backend that locks no platform"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-TOOL-UNLOCKED"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-TOOL-UNDECLARED"
gloss = "a tool locking nothing and declaring no backend"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-TOOL-UNDECLARED"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-TOOL-MISSING"
gloss = "a declared tool with no lockfile entry at all"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-TOOL-MISSING"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-PIN-STALE"
gloss = "a pin its lockfile entry does not name"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-PIN-STALE"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCKFILE-WRITES-ENABLED"
gloss = "the manifest re-enables install-time lockfile writes"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-WRITES"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-WORKFLOW-INSTALLS-UNLOCKED"
gloss = "a workflow installs with mise-action and does not set MISE_LOCKFILE"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-WORKFLOW"
kind = "document"
target = "policy/lock-complete.rego"

[[verdict]]
id = "V-LOCK-UNREADABLE"
gloss = "a manifest declares tools and the lockfile could not be read"
class = "A fixture class, restated because the engine refuses an undeclared token."

[[verdict.route]]
id = "R-FIXTURE-UNREADABLE"
kind = "document"
target = "policy/lock-complete.rego"
"#;
