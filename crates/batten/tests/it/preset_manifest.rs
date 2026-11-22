//! End-to-end tests over the compiled binary for the preset manifests
//! (CLOUD-1181).
//!
//! The manifest's own `#[cfg(test)]` tier holds the two registry directions over
//! the tables. These drive the ENGINE, which is what proves a manifest field is
//! read at load rather than merely declared — the distinction
//! `rules/policy-modules.md` opens on.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::preset::ManifestExt as _;

use common::Fixture;

/// Enabling a preset at the wrong scope is refused at load, naming the preset.
///
/// # What this does and does not claim
///
/// It does NOT claim to close a silent dead gate. Measured with the check
/// disabled and the binary rebuilt, this same config already failed to load:
/// the module-level input-key check catches `trunk-based` reading `input.call`
/// on the tree surface. What the manifest buys is that the refusal precedes
/// compilation and names the PRESET a consumer enabled, rather than a module
/// inside the binary they never wrote and cannot open.
#[test]
fn a_preset_enabled_at_the_wrong_scope_is_refused_naming_the_preset() {
    let root = Fixture::new("preset-wrong-scope")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"wrong-scope\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             sources = [\"**/*.md\"]\n\
             preset = \"trunk-based\"\n\
             severity = \"deny\"\n",
        )
        .build();
    let output = common::run(&root, &["check"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Exit 1: a config that will not load is a statement about the invocation,
    // never a verdict about the repository.
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "a scope mismatch is a config fault: {stderr}"
    );
    assert!(
        stderr.contains("trunk-based") && stderr.contains("mediated_call"),
        "the refusal names the preset and the scope its modules decide: {stderr}"
    );
}

/// The anti-vacuity mirror: the same preset at its own scope loads.
///
/// Without this the case above is satisfied by a build that refuses every
/// preset, which would name the right one every time and prove nothing.
#[test]
fn the_same_preset_at_its_declared_scope_loads() {
    let root = Fixture::new("preset-right-scope")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"right-scope\"\n\
             kind = \"policy\"\n\
             scope = \"mediated_call\"\n\
             preset = \"trunk-based\"\n\
             severity = \"deny\"\n",
        )
        .build();
    let output = common::run(&root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "the preset must load at the scope its manifest declares: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Every preset a manifest declares can actually be enabled.
///
/// The reachability arm. A manifest naming a preset the loader cannot resolve
/// would be a declaration with nothing behind it, and `preset_names()` is now
/// derived from these — so the published schema would offer a consumer a name
/// that fails at load.
#[test]
fn every_declared_preset_can_be_enabled_at_its_own_scope() {
    // EVERY SCOPE, NOT THE MANIFEST'S ONE SCOPE (CLOUD-1672). A manifest declares
    // a scope per module now, so a preset spanning two surfaces has two ways to be
    // enabled and both must resolve. Looping the pair rather than a single value
    // is what keeps the reachability claim honest for such a preset: enabling the
    // half a consumer happens not to want must not be the half that fails.
    for manifest in batten::preset_catalog::MANIFESTS {
        for scope in manifest.scopes() {
            let root = Fixture::new(&format!(
                "preset-enable-{}-{}",
                manifest.name,
                scope.as_str()
            ))
            .config(&format!(
                "version = 1\n\n\
                 [[rule]]\n\
                 id = \"enable\"\n\
                 kind = \"policy\"\n\
                 scope = \"{}\"\n\
                 {}\
                 preset = \"{}\"\n\
                 {}\
                 severity = \"deny\"\n",
                scope.as_str(),
                if scope == batten::preset_catalog::RuleScope::Tree {
                    "sources = [\"**/*.md\"]\n"
                } else {
                    ""
                },
                manifest.name,
                // DERIVED FROM THE MANIFEST, never hardcoded (CLOUD-1625). A
                // preset whose modules at this scope read a CI provider needs the
                // row to declare it, and asking the manifest is what keeps this
                // reachability claim honest as presets change: a provider added
                // to a module later is covered without editing this test, and a
                // literal here would have to be found and updated instead.
                manifest
                    .providers_at(scope)
                    .into_iter()
                    .find(|reads| *reads != "no provider")
                    .map_or_else(String::new, |reads| format!("provider = \"{reads}\"\n")),
            ))
            .build();
            let output = common::run(&root, &["check"]);
            assert_ne!(
                output.status.code(),
                Some(batten::exit::ExitCode::Usage.code()),
                "`{}` is declared but cannot be enabled at `{}`: {}",
                manifest.name,
                scope.as_str(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

/// A preset whose modules read one CI provider is refused where the row names
/// none, and the refusal names BOTH sides (CLOUD-1625).
///
/// # What this DOES claim, unlike its scope sibling above
///
/// The scope case is careful to say it closes no dead gate — the input-key check
/// catches a wrong-surface module anyway. **This one does.** Nothing downstream
/// notices a consumer on another CI provider: `ci-hygiene`'s modules key on
/// documents carrying a `jobs:` mapping, which GitLab, Buildkite and a
/// Jenkinsfile all fail to produce, so the rule set evaluates over an empty
/// document set, refuses nothing, and reports a clean tree it never read.
#[test]
fn a_preset_reading_a_provider_is_refused_where_the_row_names_none() {
    let root = Fixture::new("preset-no-provider")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"no-provider\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             sources = [\"**/*.yml\"]\n\
             preset = \"ci-hygiene\"\n\
             severity = \"deny\"\n",
        )
        .build();
    let output = common::run(&root, &["check"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "an undeclared provider is a config fault: {stderr}"
    );
    assert!(
        stderr.contains("ci-hygiene") && stderr.contains("github-actions"),
        "the refusal names the preset and what its modules read: {stderr}"
    );
    assert!(
        stderr.contains("no provider"),
        "and names what the row declared, so a reader sees which half to change: {stderr}"
    );
    // CLOUD-2658: and the repair, spelled as the column takes it.
    assert!(
        stderr.contains("provider = \"github-actions\""),
        "the refusal names the key that repairs it: {stderr}"
    );
}

/// The same preset loads once the row declares the provider its modules read.
///
/// **The first half of the anti-vacuity pair.** Without it the case above is
/// satisfied by a build that refuses `ci-hygiene` unconditionally.
#[test]
fn the_same_preset_loads_once_the_row_declares_the_provider() {
    let root = Fixture::new("preset-matching-provider")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"matching-provider\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             sources = [\"**/*.yml\"]\n\
             preset = \"ci-hygiene\"\n\
             provider = \"github-actions\"\n\
             severity = \"deny\"\n",
        )
        .build();
    let output = common::run(&root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "the preset must load where the row names the provider it reads: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// **The second half, and the one a manifest-level field would have failed.**
///
/// `mise` ships two modules: `action-version-matches-the-pin` matches a step's
/// `uses:` coordinate, and `task-over-executable` decides task argv and reads no
/// provider at all. At `mediated_call` only the second is compiled, so the row
/// needs no provider and must load without one — where a declaration on the
/// MANIFEST would have called the whole preset GitHub-specific and switched off
/// a module that works on every host.
#[test]
fn a_module_reading_no_provider_loads_with_no_provider_declared() {
    let root = Fixture::new("preset-agnostic-module")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"agnostic-module\"\n\
             kind = \"policy\"\n\
             scope = \"mediated_call\"\n\
             preset = \"mise\"\n\
             severity = \"deny\"\n",
        )
        .build();
    let output = common::run(&root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "a provider-agnostic module must load with no provider declared: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// CLOUD-2812: `rust`, the first preset moved in, carries the crate-reach
// module (CLOUD-2798) and its executable remedy as a verdict route.
/// The vendored module, as the binary carries it.
const MODULE: &str = include_str!("../../src/policy/presets/rust/crate-reach.rego");

/// Run the binary at `dir` with `args`; stdout and stderr together.
fn said_by(dir: &std::path::Path, args: &[&str]) -> String {
    let ran = common::batten()
        .current_dir(dir)
        .args(args)
        .streamed_output()
        .expect("run batten");
    format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    )
}

/// Fails by: the unlisted arm or the undeclared arm unread, which reddens one
/// of the module's three cases (`#MUTANT unlisted-admitted`).
#[test]
fn the_rust_preset_suite_passes() {
    let dir = common::scratch("rust-preset-suite");
    let mut config = String::from(
        "version = 1\n\n[[rule]]\nid = \"crate reach unsafe\"\nkind = \"policy\"\n\
         scope = \"tree\"\nmodule = \"policy/crate-reach.rego\"\nseverity = \"deny\"\n",
    );
    for class in ["crate reach unsafe", "crate declare absent"] {
        config.push_str(&format!(
            "\n[[verdict]]\nid = \"{class}\"\ngloss = \"fixture\"\nclass = \"\"\"\n\
             A fixture verdict for the vendored module's own cases.\n\"\"\"\n\
             [[verdict.route]]\nid = \"module read first\"\nkind = \"document\"\n\
             target = \"policy/crate-reach.rego\"\n"
        ));
    }
    common::write(&dir, "batten.toml", &config);
    common::write(&dir, "policy/crate-reach.rego", MODULE);
    common::init_repo(&dir);
    let out = said_by(&dir, &["policy", "test"]);
    assert!(out.contains("3 passed, 0 failed"), "{out}");
}

/// Fails by: a vendored verdict's command route not reaching `policy
/// explain`, so a consumer enabling the preset is told the refusal but not
/// the executable remedy.
#[test]
fn a_preset_remedy_is_a_verdict_route() {
    let dir = common::scratch("rust-preset-explain");
    common::write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"crate graph wrong\"\nkind = \"policy\"\n\
         scope = \"tree\"\npreset = \"rust\"\nseverity = \"deny\"\n",
    );
    common::init_repo(&dir);
    let out = said_by(&dir, &["policy", "explain", "crate reach unsafe"]);
    assert!(
        out.contains("batten modules cut --dry-run <from> <name> <module>"),
        "the remedy argv must be printed\n{out}"
    );
}
