//! `mise.toml`'s `GITHUB_TOKEN` must not let its internal chain outrank an
//! explicit ambient credential (CLOUD-1789).
//!
//! THE DEFECT THIS REFUSES, AND WHY A COMMENT WAS NOT ENOUGH. `[env]` composes
//! `GITHUB_TOKEN` from two sources: `ours` — the PAT variables, whose last leg is
//! `MISE_GITHUB_TOKEN` — and `ambient`, whatever the caller already exported. The
//! shipped form preferred `ours`, and in CI that is the wrong half: the mise setup
//! action SETS `MISE_GITHUB_TOKEN` to the default job token, so `ours` is never empty
//! there and the job's own `GITHUB_TOKEN` was overwritten. `release-plz.yml`
//! exports `RELEASE_PLZ_TOKEN` under that name, so `mise run release` cut the tag
//! with the job token instead: v0.0.159 and v0.0.160 are tagged
//! `github-actions[bot]`, and a release published by the job token fires no
//! `release` event, so `release-artifacts.yml` never ran and both went out with
//! missing binaries and no `SHA256SUMS`.
//!
//! The original change verified three arms BY HAND and recorded them in a commit
//! message. All three passed. None of them was the CI arm, because reproducing it
//! needs `MISE_GITHUB_TOKEN` set by something other than the author — which is
//! exactly the condition a machine reproduces and a person forgets. That is the
//! escape this file closes: the arms are now a case, run every lap.
//!
//! THE TEMPLATE IS EVALUATED, NOT PATTERN-MATCHED. Asserting the branch order in
//! the template text would pass over any rewrite that preserved the spelling and
//! changed the meaning, and would fail on a rewrite that changed the spelling and
//! kept it. `mise env` is the same resolver CI runs, so what is asserted here is
//! the behaviour rather than a proxy for it.
//!
//! AND IT IS READ AS JSON, WHICH IS THE PORTABLE QUESTION. The first version
//! parsed the default output for an `export NAME=` prefix, and that is a bash
//! spelling: on the `windows` leg `mise env` emits a different shell's syntax, no
//! line matched, and every arm resolved `None`. The two arms expecting a value
//! failed — but the two expecting `None` PASSED, on a reading that had learned
//! nothing, which is the well-formed-and-false shape `rules/scanning.md` names.
//! A `#[cfg(unix)]` would have been the wrong repair for the same reason CLOUD-1704
//! retired the waiver that bought one: the question — what does this manifest
//! resolve `GITHUB_TOKEN` to — is not platform-specific, only the spelling I first
//! reached for was. `--json` is shell-independent, so one case answers it on every
//! target.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// `GITHUB_TOKEN` as `mise env` resolves it at the repository root, under an
/// environment holding only the pairs given.
///
/// Every variable the template reads is cleared first, so a case states its whole
/// input and cannot pass from a value the host happened to export — the failure
/// mode that let the CI arm go unmeasured in the first place.
fn resolved(pairs: &[(&str, &str)]) -> Option<String> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — the subject IS mise's own template resolution, so the gate has to run the resolver; `hk_fix_selection` resolves its pinned tool the same way"
    )]
    let mut command = std::process::Command::new("mise");
    command
        .args(["env", "--json"])
        .current_dir(common::at_root("."));
    for name in [
        "GITHUB_TOKEN",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "BATTEN_GITHUB_TOKEN",
        "MISE_GITHUB_TOKEN",
    ] {
        command.env_remove(name);
    }
    for (name, value) in pairs {
        command.env(name, value);
    }
    let output = command.output().expect("mise resolves the environment");
    assert!(
        output.status.success(),
        "mise env exits 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resolved: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("mise env --json is json");
    resolved
        .get("GITHUB_TOKEN")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
}

#[test]
fn a_job_supplied_token_outranks_the_one_mise_action_sets() {
    // THE RELEASE ARM. `release-plz.yml` exports RELEASE_PLZ_TOKEN as
    // GITHUB_TOKEN; mise-action independently sets MISE_GITHUB_TOKEN to the job
    // token. Resolving to the latter is what tagged two releases as the bot.
    assert_eq!(
        resolved(&[("GITHUB_TOKEN", "pat"), ("MISE_GITHUB_TOKEN", "job")]),
        Some("pat".to_owned()),
        "the credential the job chose reaches `mise run release`"
    );
}

#[test]
fn the_proxy_placeholder_is_still_dropped_for_a_real_credential() {
    // CLOUD-1704's arm, unchanged: the sandbox exports a `proxy-` placeholder that
    // authenticates as nobody, and the PAT variables carry the only usable token.
    // Ambient winning must NOT mean ambient winning when it is the placeholder.
    assert_eq!(
        resolved(&[
            ("GITHUB_TOKEN", "proxy-placeholder"),
            ("BATTEN_GITHUB_TOKEN", "pat"),
        ]),
        Some("pat".to_owned()),
        "a placeholder loses to a real credential"
    );
}

#[test]
fn an_ordinary_ci_job_still_resolves_tools_with_the_action_token() {
    // The arm that makes this a precedence change rather than a removal: a job
    // that exports no GITHUB_TOKEN of its own must still reach mise-action's, or
    // every `[tools]` resolution drops to unauthenticated.
    assert_eq!(
        resolved(&[("MISE_GITHUB_TOKEN", "job")]),
        Some("job".to_owned()),
        "tool resolution keeps its credential"
    );
}

#[test]
fn a_placeholder_alone_resolves_to_nothing_rather_than_a_401() {
    // Unauthenticated is 60 requests an hour; the placeholder is a 401. With no
    // real credential anywhere, the empty string is the better of the two.
    assert_eq!(
        resolved(&[("GITHUB_TOKEN", "proxy-placeholder")]),
        None,
        "a placeholder is dropped rather than forwarded"
    );
}
