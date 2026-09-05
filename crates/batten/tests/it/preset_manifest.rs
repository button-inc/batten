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
    for manifest in batten::preset::MANIFESTS {
        let root = Fixture::new(&format!("preset-enable-{}", manifest.name))
            .config(&format!(
                "version = 1\n\n\
                 [[rule]]\n\
                 id = \"enable\"\n\
                 kind = \"policy\"\n\
                 scope = \"{}\"\n\
                 {}\
                 preset = \"{}\"\n\
                 severity = \"deny\"\n",
                manifest.scope.as_str(),
                if manifest.scope == batten::rules::RuleScope::Tree {
                    "sources = [\"**/*.md\"]\n"
                } else {
                    ""
                },
                manifest.name,
            ))
            .build();
        let output = common::run(&root, &["check"]);
        assert_ne!(
            output.status.code(),
            Some(batten::exit::ExitCode::Usage.code()),
            "`{}` is declared but cannot be enabled: {}",
            manifest.name,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
