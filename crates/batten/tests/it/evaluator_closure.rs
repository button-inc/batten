//! `layer reach unsafe` over the compiled binary and the real walk (CLOUD-831,
//! CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/evaluator-closure.rego` carries five load-time cases and every one
//! fabricates its input with `with input as`. That is the shape
//! `rules/policy-modules.md` warns about: the case asserts over a record the
//! engine may be unable to project, and the module stays green while the row
//! decides nothing on any real checkout. `branch-age` spent a whole session in
//! exactly that state (CLOUD-1810).
//!
//! # And why the WALK is driven here rather than described
//!
//! Four of the dying suite's eight cases are about the walk, not the verdict —
//! the activation filter in both directions, a dev-dependency, and the
//! workspace-versus-evaluator scope. They are the security-critical half: the
//! obvious spelling of this predicate walks from the workspace members, finds
//! `jsonschema` and `globset` (direct dependencies of `batten` itself), and would
//! deny on `main` forever.
//!
//! Had the walk gone into the task body they would have become `// changed:` arms
//! pointing at `mise.toml` with nothing asserting them. It is
//! `crates/batten/src/cargo_graph.rs` instead, and these cases run it, so all
//! eight CARRY. `.py` is outside `under_mise_tasks` (`shell-retirement.rego:159`)
//! so that file adds no shell rule.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The program's successor is `policy/evaluator-closure.rego` for the decision
//! and `[tasks.evaluator-closure-record]` for the two things that are not
//! decisions: the `cargo metadata` spawn and the graph walk. That split is forced
//! rather than chosen — §5 makes `check` `read` and structurally incapable of
//! spawning, and a reachability closure is not expressible in Rego at all, since
//! a self-referential rule is a compile error and `graph.reachable` is not in
//! this build's regorus feature set.
//!
// carried: mise-tasks/evaluator-closure-check.sh policy/evaluator-closure.rego kind:mechanism crates/batten/tests/it/evaluator_closure.rs
// carried: tests/evaluator-closure-check.bats policy/evaluator-closure.rego kind:mechanism crates/batten/tests/it/evaluator_closure.rs
// carried: "the repo's real graph is clean today" policy/evaluator-closure.rego kind:mechanism
// carried: "an IO crate reachable from the evaluator is refused at exit 2" policy/evaluator-closure.rego kind:mechanism
// carried: "an IO crate the workspace depends on directly, but the evaluator does not, is not the evaluator's" policy/evaluator-closure.rego kind:mechanism
// carried: "an unactivated optional IO dependency of the evaluator is not reported" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/evaluator_closure.rs
// carried: "the same optional dependency, activated, IS reported" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/evaluator_closure.rs
// carried: "no evaluator node at all is could-not-look, not a clean bill" policy/evaluator-closure.rego kind:mechanism
// carried: "the refusal is pointer-only: the crate name, never the path that reached it" policy/evaluator-closure.rego kind:mechanism
// carried: "a dev-dependency of the evaluator is not in the built closure" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/evaluator_closure.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against the declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("evaluator-closure-{name}"));
    let module = std::fs::read_to_string("../../policy/evaluator-closure.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/evaluator-closure.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "layer carry unsafe"
gloss = "an IO-bearing crate is reachable from the evaluator's node"
class = "The claim that admits consumer-authored code to the mediated call, failing."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/evaluator-closure.rego"

[[verdict]]
id = "layer read absent"
gloss = "the graph resolved and carries no evaluator node"
class = "Could-not-look, and loud: the question was never asked."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run evaluator-closure-record"

[[rule]]
id = "layer reach unsafe"
kind = "policy"
scope = "tree"
module = "policy/evaluator-closure.rego"
severity = "deny"

[[record]]
record = "evaluator-closure"
writer = "mise run evaluator-closure-record"

# THE TWO CONSUMER FACTS THE VERB RESOLVES, declared here rather than compiled
# into the engine (non-negotiable rule 1). A fixture that omitted them would
# make `record derive` refuse — which is itself asserted below, because a gate
# whose consumer facts are undeclared must say so rather than answer over none.
[[pattern]]
id = "evaluator-package"
regex = '^regorus$'

[[pattern]]
id = "evaluator-io-crate"
regex = '^(reqwest|jsonschema|hyper|rustls|openssl-sys|native-tls|ring|globset|glob)$'
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write the producer's record, as `mise run evaluator-closure-record` would.
fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "evaluator-closure"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// Drive the REAL walk over a `cargo metadata` document, through the REAL verb.
///
/// The activated-edge reachability itself lives in
/// `crates/batten/src/cargo_graph.rs` and is asserted directly by that module's
/// own `#[cfg(test)] mod tests` — one walk, shared with `macos-link`, so the two
/// gates cannot drift apart the way their two copies did.
///
/// What THIS tier drives is the COMPOSITION: the roots the consumer's
/// `evaluator-package` row selects, and the names its `evaluator-io-crate` row
/// looks for once there. That composition is the gate, and it is per-consumer.
fn walk(dir: &std::path::Path, metadata: &str) -> String {
    let written = run_with_stdin(dir, &["record", "derive", "evaluator-closure"], metadata);
    assert!(
        written.status.success(),
        "the walk reads its graph: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    String::from_utf8_lossy(&written.stdout).into_owned()
}

/// A graph where `batten` depends on `regorus`, and `regorus` on `edge`.
fn chain(edge: &str, kind: &str, optional: bool, regorus_features: &str) -> String {
    let optional_decl = if optional {
        r#", "optional": true"#
    } else {
        ""
    };
    format!(
        r#"{{
  "packages": [
    {{"id": "batten", "name": "batten", "features": {{}},
     "dependencies": [{{"name": "regorus"}}]}},
    {{"id": "regorus", "name": "regorus", "features": {{"http": ["dep:{edge}"]}},
     "dependencies": [{{"name": "{edge}"{optional_decl}}}]}},
    {{"id": "{edge}", "name": "{edge}", "features": {{}}, "dependencies": []}}
  ],
  "workspace_members": ["batten"],
  "resolve": {{"nodes": [
    {{"id": "batten", "features": [], "deps": [{{"pkg": "regorus", "dep_kinds": [{{"kind": null}}]}}]}},
    {{"id": "regorus", "features": [{regorus_features}], "deps": [{{"pkg": "{edge}", "dep_kinds": [{{"kind": {kind}}}]}}]}},
    {{"id": "{edge}", "features": [], "deps": []}}
  ]}}
}}"#
    )
}

// --- the decision, over the engine's own projection --------------------------

#[test]
fn an_io_crate_in_the_recorded_closure_is_refused() {
    // THE CASE NO `with input as` CAN REACH: the module deciding over a record
    // the real verb wrote, read through the engine's own projection.
    let dir = repo("reachable");
    record(&dir, "closure 41\ncrate reqwest\n");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "an IO crate in the closure decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    );
    assert!(
        said.contains("reqwest"),
        "the finding names the crate\n{said}"
    );
}

#[test]
fn the_refusal_is_pointer_only_the_crate_name_never_the_path_that_reached_it() {
    // Non-negotiable rule 4. The producer records only the crate NAME, so there
    // is structurally no path for a dependency chain to reach a finding — this
    // asserts the intermediate never appears.
    let dir = repo("pointer");
    let reached = walk(
        &dir,
        r#"{
  "packages": [
    {"id": "batten", "name": "batten", "features": {}, "dependencies": [{"name": "regorus"}]},
    {"id": "regorus", "name": "regorus", "features": {}, "dependencies": [{"name": "secret-middle"}]},
    {"id": "secret-middle", "name": "secret-middle", "features": {}, "dependencies": [{"name": "ring"}]},
    {"id": "ring", "name": "ring", "features": {}, "dependencies": []}
  ],
  "workspace_members": ["batten"],
  "resolve": {"nodes": [
    {"id": "batten", "features": [], "deps": [{"pkg": "regorus", "dep_kinds": [{"kind": null}]}]},
    {"id": "regorus", "features": [], "deps": [{"pkg": "secret-middle", "dep_kinds": [{"kind": null}]}]},
    {"id": "secret-middle", "features": [], "deps": [{"pkg": "ring", "dep_kinds": [{"kind": null}]}]},
    {"id": "ring", "features": [], "deps": []}
  ]}
}"#,
    );
    record(&dir, &reached);

    let decided = run(&dir, &["check"]);
    assert_eq!(decided.status.code(), Some(2), "the chain decides");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    );
    assert!(said.contains("ring"), "the crate is named\n{said}");
    assert!(
        !said.contains("secret-middle"),
        "and the path that reached it is not\n{said}"
    );
}

#[test]
fn no_evaluator_node_at_all_is_could_not_look_not_a_clean_bill() {
    // Reporting "nothing found" when the evaluator is not in the graph is
    // CLOUD-251's vacuous pass in the one place it would be least visible.
    let dir = repo("absent");
    let reached = walk(
        &dir,
        r#"{"packages": [{"id": "batten", "name": "batten", "features": {}, "dependencies": []}],
            "workspace_members": ["batten"],
            "resolve": {"nodes": [{"id": "batten", "features": [], "deps": []}]}}"#,
    );
    assert_eq!(reached.trim(), "absent", "the walk says so\n{reached}");
    record(&dir, &reached);

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "and the module is loud about it\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    // COULD NOT LOOK IS NOT A PASS, and on this surface it is also not a refusal.
    // The producer writes nothing when `cargo metadata` will not resolve, so a
    // module that refused here would refuse every checkout with no toolchain.
    let dir = repo("unrecorded");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

// --- the walk itself ---------------------------------------------------------

#[test]
fn an_io_crate_reachable_from_the_evaluator_is_refused_at_exit_2() {
    let dir = repo("walk-reaches");
    let reached = walk(&dir, &chain("reqwest", "null", false, ""));
    assert!(
        reached.contains("crate reqwest"),
        "the walk reaches it\n{reached}"
    );
}

#[test]
fn an_io_crate_the_workspace_depends_on_directly_but_the_evaluator_does_not_is_not_the_evaluators()
{
    // THE LOAD-BEARING CASE. The obvious spelling walks from the workspace
    // members, and on the real tree that finds `jsonschema` and `globset` —
    // direct dependencies of `batten` itself, entering by paths that have nothing
    // to do with the evaluator. It would deny on `main` forever. This fixture is
    // that exact topology and the walk must be silent on it.
    let dir = repo("not-the-evaluators");
    let reached = walk(
        &dir,
        r#"{
  "packages": [
    {"id": "batten", "name": "batten", "features": {},
     "dependencies": [{"name": "regorus"}, {"name": "jsonschema"}, {"name": "globset"}]},
    {"id": "regorus", "name": "regorus", "features": {}, "dependencies": []},
    {"id": "jsonschema", "name": "jsonschema", "features": {}, "dependencies": []},
    {"id": "globset", "name": "globset", "features": {}, "dependencies": []}
  ],
  "workspace_members": ["batten"],
  "resolve": {"nodes": [
    {"id": "batten", "features": [], "deps": [
      {"pkg": "regorus", "dep_kinds": [{"kind": null}]},
      {"pkg": "jsonschema", "dep_kinds": [{"kind": null}]},
      {"pkg": "globset", "dep_kinds": [{"kind": null}]}]},
    {"id": "regorus", "features": [], "deps": []},
    {"id": "jsonschema", "features": [], "deps": []},
    {"id": "globset", "features": [], "deps": []}
  ]}
}"#,
    );
    assert!(
        !reached.contains("crate "),
        "nothing the evaluator does not reach is reported\n{reached}"
    );
}

#[test]
fn an_unactivated_optional_io_dependency_of_the_evaluator_is_not_reported() {
    // `macos-link-check`'s `defmt` lesson applied here: an optional dependency
    // nobody enabled is in the resolve and is not in the build, and a gate that
    // fails on a crate the compiler never sees is not measuring what it names.
    let dir = repo("dormant");
    let reached = walk(&dir, &chain("reqwest", "null", true, r#""std""#));
    assert!(
        !reached.contains("crate reqwest"),
        "an unactivated optional dep is dormant\n{reached}"
    );
}

#[test]
fn the_same_optional_dependency_activated_is_reported() {
    // The other direction of the same filter. Without it the case above passes on
    // a walk that reports nothing at all.
    let dir = repo("activated");
    let reached = walk(&dir, &chain("reqwest", "null", true, r#""std", "http""#));
    assert!(
        reached.contains("crate reqwest"),
        "activating the feature reaches it\n{reached}"
    );
}

#[test]
fn a_dev_dependency_of_the_evaluator_is_not_in_the_built_closure() {
    // A dev-dependency of a DEPENDENCY is never built, so it is not in the
    // closure a policy module could reach. (A workspace member's dev-dependency
    // is built — the test binaries link — but that is the members' walk.)
    let dir = repo("dev-edge");
    let reached = walk(&dir, &chain("reqwest", r#""dev""#, false, ""));
    assert!(
        !reached.contains("crate reqwest"),
        "a dev edge is not in the built closure\n{reached}"
    );
}

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays: resolving the REAL graph is the whole of this case, and it is the only evidence that the fixtures above agree with the tree `Cargo.toml`'s pin comment makes its claim about. The spawn is `cargo metadata` — the producer's own effect, which house-style §5 keeps outside the engine — and never a reading this tier re-implements"
)]
fn the_repos_real_graph_is_clean_today() {
    // The anti-vacuity arm, against the tree as it actually resolves. Every case
    // above drives a fixture; this one is the only evidence that the pair agrees
    // with reality, which is the claim `Cargo.toml`'s pin comment rests on.
    let metadata = std::process::Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir("../..")
        .output()
        .expect("cargo metadata runs");
    assert!(metadata.status.success(), "the lockfile is current");

    let dir = repo("real-graph");
    let reached = walk(&dir, &String::from_utf8_lossy(&metadata.stdout));
    assert!(
        reached.contains("closure "),
        "the evaluator is in the graph\n{reached}"
    );
    assert!(
        !reached.contains("crate "),
        "and none of the nine IO crates is in its closure\n{reached}"
    );
}
