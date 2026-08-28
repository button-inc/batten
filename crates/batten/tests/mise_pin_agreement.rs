//! `policy/mise-pin-agreement.rego` decides over the compiled engine (CLOUD-910).
//!
//! # Where this came from
//!
//! The successor to `mise-tasks/mise-pin-agreement.sh` and
//! `tests/mise-pin-agreement.bats`, the first gate of CLOUD-910's wave 1. The
//! bash asked two questions of two files — does every `backend:tool@version`
//! reference in `.mcp.json` agree with `mise.toml`'s pin, and is every `mise
//! exec` launch scoped — with `jq` for the first document and a `sed` expression
//! for the second. Both are questions about PARSED structure, which is what makes
//! the row a `documents` row rather than a `lines` one.
//!
//! # Why this tier is not a duplicate of the module's own `test_` rules
//!
//! A `with input as` block writes the shape it then reads, so it is green over a
//! key the engine never fills — CLOUD-845's defect, and
//! `.claude/rules/policy-modules.md` records both live instances of it being
//! found by adding this tier rather than by reading. Every case below goes in
//! through `batten check`, the same door `verify` and the hk gate come through,
//! and reads the verdict a caller would read. The module's rules pin the
//! PREDICATE; this file pins that the ENGINE builds the input the predicate
//! reads — here specifically that `input.tree.documents` carries a parsed
//! `.mcp.json` and a parsed `mise.toml`, and that `data.batten.patterns` reaches
//! the module from a `[[pattern]]` row.
//!
//! # Destination: an in-repo module, and why not a preset
//!
//! The predicate names a task RUNNER's pin table and a specific host's server
//! manifest. Pull the consumer's facts out and what remains is "two documents
//! agree about a string", which decides nothing — so there is no generic
//! predicate to split off, and CLOUD-910's Split-checked arm is VACUOUS for this
//! gate rather than unaddressed.

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Their grammar is disjoint
// from CLOUD-908's case arms below by construction: a case arm's first field
// after the marker is a QUOTED case name, and a file arm's is a path.
//
// carried: mise-tasks/mise-pin-agreement.sh policy/mise-pin-agreement.rego crates/batten/tests/mise_pin_agreement.rs
// carried: tests/mise-pin-agreement.bats policy/mise-pin-agreement.rego crates/batten/tests/mise_pin_agreement.rs

// THE REPLAY DECLARATION (CLOUD-909), beside the mapping because the two
// describe one migration and a translation in a second file is a second
// authority that drifts.
//
// THE TRANSLATION IS NOT AN IDENTITY, and stating it is the whole point: the
// shell tasks spell `1 = violation` and batten's contract is the inverse
// (house-style §7), so `0=0 1=2` is the real pair. `2` appears on neither side
// of it deliberately — the two cases where the bash exited 2 are declared
// `changed` below, because the bash's `2` means could-not-look while the
// engine's `2` is the policy verdict, and `2=2` is exactly the carry-over
// `replay` refuses.
//
// replay: tests/mise-pin-agreement.bats c9aaa5dcc43b159f1bcee7fd5a6f50b6eb0280e3 mise-tasks/mise-pin-agreement.sh mise-pin-agreement 0=0 1=2

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

/// The authority a fixture carries: this row, the pattern it reads, and the four
/// classes it raises.
///
/// Hand-built rather than copied from the committed `batten.toml`, for
/// `privileged_lane.rs`'s reason: copying the whole authority drags every other
/// row's module into a tree that does not have one, and the finding then reports
/// about rows this migration is not answering for.
const AUTHORITY: &str = r#"version = 1

[[pattern]]
id = "mise-tool-reference"
regex = '^[a-z0-9]+:.+@.+$'

[[rule]]
id = "mise-pin-agreement"
kind = "policy"
scope = "tree"
documents = [".mcp.json", "mise.toml"]
module = "policy/mise-pin-agreement.rego"
severity = "deny"
reason = "mise.toml owns the pin and .mcp.json's copy is a reference to it."

[[verdict]]
id = "V-MCP-PIN-DISAGREES"
gloss = "a tool version .mcp.json names is not the version mise.toml pins"
class = """
The second place a pin is written cannot drift from the first.
"""

[[verdict.route]]
id = "R-REPEAT-THE-AUTHORITATIVE-PIN"
kind = "document"
target = ".mcp.json"

[[verdict]]
id = "V-MCP-PIN-UNDECLARED"
gloss = "a tool .mcp.json launches has no plain-string pin in mise.toml at all"
class = """
A reference with no authority behind it is not a pin.
"""

[[verdict.route]]
id = "R-PIN-THE-TOOL"
kind = "document"
target = "mise.toml"

[[verdict]]
id = "V-MCP-EXEC-UNSCOPED"
gloss = "a `mise exec` launch names no tool before `--`"
class = """
A bare exec provisions the whole toolchain and dies with any one of it.
"""

[[verdict.route]]
id = "R-SCOPE-THE-EXEC"
kind = "document"
target = ".mcp.json"

[[verdict]]
id = "V-PIN-AUTHORITY-UNREADABLE"
gloss = "mise.toml could not be read, so no pin reference could be compared"
class = """
Could-not-look, kept loud.
"""

[[verdict.route]]
id = "R-RESTORE-THE-AUTHORITY"
kind = "document"
target = "mise.toml"
"#;

/// The pin table every fixture is judged against, unless the case is about its
/// absence. Deliberately the shape `mise.toml` really uses, including a
/// table-valued entry: that is the form the bash read as "no pin at all".
const PINS: &str = "[tools]\n\"pipx:serena-agent\" = \"1.6.1\"\nuv = \"0.8\"\n";

/// A throwaway repository carrying the committed module, the authority above,
/// and whatever documents the case is about.
///
/// The module read here is the COMMITTED one, copied in rather than restated
/// inline — an inline copy would drift from the shipped module and pass while
/// the real gate was broken, which is the two-authorities defect the campaign is
/// about.
fn fixture(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(&format!("mise-pin-agreement-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    let module = common::at_root("policy/mise-pin-agreement.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/mise-pin-agreement.rego"))
        .expect("install committed module");
    fs::write(root.join("batten.toml"), AUTHORITY).expect("write the fixture authority");
    for (path, body) in files {
        fs::write(root.join(path), body).expect("write a fixture document");
    }
    // No global or system config: a contributor's own git settings must not be
    // able to change a verdict here (CLOUD-282).
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
}

/// A `.mcp.json` launching one server through a scoped `mise exec`, with the
/// command spelled as CLOUD-714's shim rather than as `mise` — the selector is
/// argv, and a fixture that used the bare command would not say so.
fn scoped(version: &str) -> String {
    format!(
        r#"{{"mcpServers":{{"serena":{{"command":"mise-tasks/serena-mcp.sh","args":["exec","pipx:serena-agent@{version}","--","serena","start-mcp-server"]}}}}}}"#
    )
}

/// The exit contract, asserted by NAME rather than by integer
/// (`.claude/rules/rust.md`): `2` is the policy verdict, `0` is clean. A case
/// asserting `1` here would be asserting "unreadable input" while meaning
/// "violation", and it would pass — which is the carry-over CLOUD-909 exists to
/// catch.
fn denied(root: &Path) {
    let output = common::run(root, &["check"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "expected the policy verdict: {text}{err}"
    );
    // THE RULE AND THE POINTER ARE THE WHOLE OBSERVABLE, and that is rule 4
    // rather than a thin assertion. Measured on this tree: `batten check` renders
    // `.mcp.json mise-pin-agreement` and `check -J` carries
    // `{rule, path, severity, report, identity}` — the verdict TOKEN reaches
    // neither. So which class fired is pinned by the module's own `test_` rules,
    // where the class is nameable, and this tier pins that the engine builds the
    // input at all. A case here asserting a token would have been asserting the
    // renderer, and it would have been red.
    assert!(
        text.contains("mise-pin-agreement"),
        "the finding names the rule: {text}"
    );
    assert!(
        text.contains(".mcp.json"),
        "the finding points at the manifest: {text}"
    );
}

fn clean(root: &Path) {
    let output = common::run(root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "expected a clean tree: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// The positive arm first: without it every refusal below is satisfied by a
// module that refuses everything.
// ---------------------------------------------------------------------------

// carried: "a scoped launch whose version matches mise.toml passes" crates/batten/tests/mise_pin_agreement.rs
// carried: "a shimmed launch that IS scoped passes, and its pin is still read" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_scoped_launch_whose_version_matches_the_authority_passes() {
    // The two bats cases collapse into one here because they were already one
    // input: the suite's `scoped_mcp` helper spells `command: mise` and the
    // shimmed case spells the shim, and the predicate never reads `command` at
    // all. Both arms are declared rather than one, so neither case is silently
    // absorbed.
    let root = fixture(
        "agrees",
        &[(".mcp.json", &scoped("1.6.1")), ("mise.toml", PINS)],
    );
    clean(&root);
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

// carried: "a version .mcp.json names that mise.toml does not pin fails, naming both" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_version_the_authority_pins_differently_is_refused() {
    let root = fixture(
        "disagrees",
        &[(".mcp.json", &scoped("9.9.9")), ("mise.toml", PINS)],
    );
    denied(&root);
}

// carried: "a tool mise.toml does not carry at all fails" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_tool_the_authority_does_not_carry_is_refused() {
    let root = fixture(
        "undeclared",
        &[
            (
                ".mcp.json",
                r#"{"mcpServers":{"other":{"command":"mise","args":["exec","pipx:nothing@1.0","--","x"]}}}"#,
            ),
            ("mise.toml", PINS),
        ],
    );
    denied(&root);
}

// THE REGRESSION THE GATE EXISTS FOR. It must not read as "nothing to check":
// reverting to a bare exec removes every version reference, so a version-only
// predicate would pass the defect it was written for.
// THE ARM IS SPELLED AS THE SUITE'S SOURCE SPELLS IT, backslashes included.
// `conserves` extracts a case name from the file text between `@test "` and the
// next `"`, so the name it keys on is `a bare \`mise exec\` ...` with the shell
// escapes intact. `replay` keys on `$BATS_TEST_DESCRIPTION`, which is the
// INTERPRETED name and carries no backslashes — so one ledger row cannot satisfy
// both readers, and this is CLOUD-1037's "two readers disagree on its grammar"
// reaching the tree arm. Spelled for `conserves`, which is the deny gate on the
// landing path; recorded on CLOUD-1115, which owns the other reader.
// carried: "a bare \`mise exec\` fails even though it names no version to compare" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_bare_exec_is_refused_even_though_it_names_no_version() {
    let root = fixture(
        "bare-exec",
        &[
            (
                ".mcp.json",
                r#"{"mcpServers":{"serena":{"command":"mise","args":["exec","--","serena","start-mcp-server"]}}}"#,
            ),
            ("mise.toml", PINS),
        ],
    );
    denied(&root);
}

// THE SELECTOR IS ARGV, NOT THE COMMAND NAME (CLOUD-714). Keying the scoped-exec
// check on `command == "mise"` would have made every shimmed server exempt — the
// gate green while the property it exists for went unchecked.
// carried: "A SHIMMED LAUNCH IS STILL CHECKED — the selector is argv, not the command name" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_shimmed_bare_exec_is_still_refused() {
    let root = fixture(
        "shimmed-bare",
        &[
            (
                ".mcp.json",
                r#"{"mcpServers":{"serena":{"command":"mise-tasks/serena-mcp.sh","args":["exec","--","serena","start-mcp-server"]}}}"#,
            ),
            ("mise.toml", PINS),
        ],
    );
    denied(&root);
}

// ---------------------------------------------------------------------------
// The boundaries, which is where a gate nobody can keep green comes from.
// ---------------------------------------------------------------------------

// carried: "a server not launched through mise is left alone" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn a_server_not_launched_through_mise_is_left_alone() {
    let root = fixture(
        "npx",
        &[
            (
                ".mcp.json",
                r#"{"mcpServers":{"thing":{"command":"npx","args":["-y","some-server"]}}}"#,
            ),
            ("mise.toml", PINS),
        ],
    );
    clean(&root);
}

// carried: "a missing .mcp.json is nothing to check" crates/batten/tests/mise_pin_agreement.rs
#[test]
fn an_absent_server_manifest_is_nothing_to_check() {
    // A tree with no server manifest has nothing to check — the bash's own
    // `exit 0`, and not-applicable rather than could-not-look. This is the arm
    // that keeps the rule from firing on every tree that merely HOLDS a copy of
    // this config, which is the false red CLOUD-614 records.
    let root = fixture("no-manifest", &[("mise.toml", PINS)]);
    clean(&root);
}

// THE TWO CASES THIS FILE DELIBERATELY DOES NOT CARRY, and the reason is a
// finding rather than an omission.
//
// The module's could-not-look clause reads `input.tree.missing`, which
// `.claude/rules/policy-modules.md` requires every module to write. MEASURED on
// this tree with a throwaway probe module that raises on ANY entry in that set,
// three inputs, all exit 0 with no finding and no diagnostic:
//
//   * a `documents` row naming a path the tree does not have;
//   * a `sources` row naming a path the tree does not have;
//   * a `documents` row naming a path that EXISTS and does not parse.
//
// So the channel is not merely unfilled for a parse failure — it is unfilled on
// the tree surface entirely, which is wider than CLOUD-1049 records and is
// measured onto that row rather than filed a second time. The clause stays in the
// module, because it is right and the engine is what has to catch up; what cannot
// stay here is a case asserting it.
//
// Not shipped red, and not shipped asserting the current behaviour either — that
// would bake the defect in as the contract and go green forever, which is exactly
// what `crates/batten/tests/privileged_lane.rs` records for the same channel. The
// anti-vacuity partner ("no manifest either, so stay silent") goes with it: with
// the channel dead both inputs are silent, so it would pass against a module that
// decides nothing.
//
// The bats cases these two would have carried are declared `changed` at the foot
// of this file with the same reason.

/// A table-valued `[tools]` entry is not a pin this rule compares, preserved
/// from the bash's quoted-string-only read rather than widened in a migration.
#[test]
fn a_table_valued_pin_reads_as_undeclared() {
    let root = fixture(
        "table-pin",
        &[
            (
                ".mcp.json",
                r#"{"mcpServers":{"r":{"command":"mise","args":["exec","npm:renovate@41.173.1","--","renovate"]}}}"#,
            ),
            (
                "mise.toml",
                "[tools]\n\"npm:renovate\" = { version = \"41.173.1\" }\n",
            ),
        ],
    );
    denied(&root);
}

// ---------------------------------------------------------------------------
// The two `changed` arms, and neither is a divergence anyone chose.
// ---------------------------------------------------------------------------

// THE CONTRACT INVERSION, and it is why `replay`'s translation may not be an
// identity. The bash exits 2 for "I could not read the authority"; the engine
// exits 2 for "there is a finding". The two coincide numerically and mean
// different things, so a `2=2` pair in the replay row would assert the migration
// preserved the very contract it exists to fix, and it would pass.
//
// The successor is the module's `V-PIN-AUTHORITY-UNREADABLE` clause, which is
// written and correct and which the engine cannot currently reach: measured
// above, `input.tree.missing` is empty for an absent declared path. So this case
// diverges twice over — once by contract, once because the channel is unfilled —
// and both reasons are on the row.
// changed: "a missing mise.toml cannot be compared against — exit 2" crates/batten/tests/mise_pin_agreement.rs the shell's exit 2 is could-not-look and the engine's 2 is the policy verdict (house-style §7), so the code cannot be carried through an identity; and the successor clause `V-PIN-AUTHORITY-UNREADABLE` is unreachable today because `input.tree.missing` is never populated for an absent declared path — measured here, recorded on CLOUD-1049, which owns restoring the case
//
// THE SAME CHANNEL, THE OTHER INPUT. An unparseable `.mcp.json` is today
// indistinguishable from an absent one and is silent, where the bash exited 2.
// changed: "an unparseable .mcp.json is exit 2, never a clean pass" crates/batten/tests/mise_pin_agreement.rs CLOUD-1049: `input.tree.missing` is not populated for a declared document that exists and fails to parse, so the could-not-look clause the module already carries cannot see this input. Not shipped red and not shipped asserting the current behaviour; CLOUD-1049 owns restoring it here
