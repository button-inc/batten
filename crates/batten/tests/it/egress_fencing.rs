//! `policy/egress-fencing.rego` decides over the compiled engine (CLOUD-1399).
//!
//! # Why this tier exists and is not a duplicate of the module's `test_` rules
//!
//! A `with input as` block writes the shape it then reads, so it stays green over
//! a key the engine never fills — CLOUD-845's defect, and
//! `rules/policy-modules.md` records both live instances of it being
//! found by adding this tier rather than by reading. Every case below goes in
//! through `batten check`, the same door `verify` and the hk gate come through.
//!
//! What it pins specifically: that `input.tree.documents` carries a **parsed**
//! `mise.toml` whose `[env]` table is reachable as `.env`, and that
//! `data.batten.patterns` reaches the module from a consumer's `[[pattern]]` row.
//! The module's own rules pin the predicate; this pins that the engine builds the
//! input the predicate reads.
//!
//! # What the gate does NOT claim
//!
//! It protects a mitigation, not the decision. Whether this container is actually
//! unproxied is `batten doctor egress`'s subject and is read from the live
//! environment; the tree owns only the `[env]` block that fences the resolver
//! host. Stating that narrowly is deliberate — a suite implying the broader claim
//! would be the defect `rules/scanning.md` records for its own case.

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The fixture's own committed authority: the rule, the pattern the module reads,
/// and a declared row for every verdict it raises.
///
/// The `[[pattern]]` row is CONSUMER config and has to be here rather than
/// assumed: a module reads `data.batten.patterns["…"]`, which resolves to
/// undefined where no row supplies it, and Rego reads undefined as *does not
/// hold* — so a fixture that omitted it would run a module that decides nothing
/// and call the tree clean.
const AUTHORITY: &str = r#"
version = 1

[[rule]]
id = "egress-fencing"
kind = "policy"
scope = "tree"
documents = ["mise.toml"]
module = "policy/egress-fencing.rego"
severity = "deny"
reason = "mise.toml's [env] fences the resolver host out of the agent proxy so mise can resolve a release at all. Removing it restores the 403 the block exists for."

[[pattern]]
id = "egress-resolver-host"
regex = 'api\.github\.com'

[[verdict]]
id = "task declare dropped"
gloss = "mise.toml's [env] carries no no-proxy key, so nothing is fenced out of the proxy"
class = """
A deleted fence is not a narrower fence.
"""

[[verdict.route]]
id = "task read first"
kind = "document"
target = "mise.toml"

[[verdict]]
id = "task declare partial"
gloss = "the no-proxy value no longer names the host mise's release resolver calls"
class = """
A fence that does not name the host it exists for fences nothing.
"""

[[verdict.route]]
id = "task read first"
kind = "document"
target = "mise.toml"

[[verdict]]
id = "task read unread"
gloss = "mise.toml could not be read, so no fence could be judged"
class = """
Could-not-look, kept loud.
"""

[[verdict.route]]
id = "task read first"
kind = "document"
target = "mise.toml"
"#;

/// A `mise.toml` whose `[env]` fences both spellings, as the committed one does.
///
/// The value is the real Tera template rather than a resolved list, which is the
/// shape the predicate has to cope with: the host appears literally in the
/// template's own text, so the tree can see the intent without evaluating it.
const FENCED: &str = r#"
[tools]
uv = "0.8"

[env]
NO_PROXY = "{% set cur = get_env(name='NO_PROXY', default='') %}{% if 'api.github.com' in cur %}{{ cur }}{% else %}api.github.com,objects.githubusercontent.com{% if cur %},{{ cur }}{% endif %}{% endif %}"
no_proxy = "{% set cur = get_env(name='no_proxy', default='') %}{% if 'api.github.com' in cur %}{{ cur }}{% else %}api.github.com,objects.githubusercontent.com{% if cur %},{{ cur }}{% endif %}{% endif %}"
"#;

fn fixture(name: &str, mise_toml: &str) -> PathBuf {
    let root = common::scratch(&format!("egress-fencing-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    // The COMMITTED module, copied rather than restated: an inline copy drifts
    // from the shipped one and passes while the real gate is broken, which is the
    // two-authorities defect this whole tier is about.
    let module = common::at_root("policy/egress-fencing.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/egress-fencing.rego")).expect("install committed module");
    fs::write(root.join("batten.toml"), AUTHORITY).expect("write the fixture authority");
    fs::write(root.join("mise.toml"), mise_toml).expect("write the fixture mise.toml");
    // No global or system config: a contributor's own git settings must not be
    // able to change a verdict here (CLOUD-282).
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
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

fn denied(root: &Path) {
    let output = common::run(root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "expected a refusal: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The RULE id and the pointer, never the verdict token: the finding renderer
    // carries neither the token nor the class, so a case asserting one would be
    // asserting the renderer. Which class fired is the module's own rules' job.
    assert!(
        text.contains("egress-fencing"),
        "the finding names the rule: {text}"
    );
    assert!(
        text.contains("mise.toml"),
        "the finding points at the authority: {text}"
    );
}

// ---------------------------------------------------------------------------
// The positive arm first: without it every refusal below is satisfied by a
// module that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_fence_naming_the_resolver_host_in_both_spellings_passes() {
    let root = fixture("fenced", FENCED);
    clean(&root);
}

// ---------------------------------------------------------------------------
// The refusals.
// ---------------------------------------------------------------------------

#[test]
fn a_deleted_fence_is_refused() {
    // THE REGRESSION THIS GATE EXISTS FOR. `65757c86` removed the fencing on the
    // reasoning that honouring the environment's CA bundle made it unnecessary —
    // which conflates TLS re-termination with the proxy's injected-token 403.
    // Nothing refused it. `[env]` stays present and non-empty so the module's
    // `env` binding still resolves: the case is about the KEY being gone, not the
    // table.
    let root = fixture(
        "dropped",
        "[tools]\nuv = \"0.8\"\n\n[env]\nGH_TOKEN = \"x\"\n",
    );
    denied(&root);
}

#[test]
fn a_fence_that_no_longer_names_the_resolver_host_is_refused() {
    // Gutted rather than deleted: the keys survive and fence something else, so a
    // predicate that only asked whether the keys existed would pass this.
    let root = fixture(
        "narrowed",
        "[tools]\nuv = \"0.8\"\n\n[env]\nNO_PROXY = \"localhost,127.0.0.1\"\nno_proxy = \"localhost,127.0.0.1\"\n",
    );
    denied(&root);
}

#[test]
fn fencing_only_the_upper_case_spelling_is_refused() {
    // Every client in this class resolves the lower-case name FIRST, so a change
    // that gutted `no_proxy` alone would break the tool that reads it while a
    // gate watching only `NO_PROXY` stayed green. Both spellings are checked as a
    // set precisely so neither is the one somebody remembers to widen.
    let root = fixture(
        "upper-only",
        "[tools]\nuv = \"0.8\"\n\n[env]\nNO_PROXY = \"api.github.com\"\nno_proxy = \"localhost\"\n",
    );
    denied(&root);
}

#[test]
fn fencing_only_the_lower_case_spelling_is_refused() {
    let root = fixture(
        "lower-only",
        "[tools]\nuv = \"0.8\"\n\n[env]\nNO_PROXY = \"localhost\"\nno_proxy = \"api.github.com\"\n",
    );
    denied(&root);
}
