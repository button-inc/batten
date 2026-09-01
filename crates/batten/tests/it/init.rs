//! `batten init` end-to-end over the compiled binary (CLOUD-206).
//!
//! Every assertion here is over the process, not the library: `init`'s whole
//! contract is what a first-contact caller observes — an exit code, a pointer on
//! stdout, and a file that the *next* command accepts. A unit test over
//! [`batten::init::apply`] can prove the write happened; only these can prove the
//! thing written is a config the rest of the binary agrees with.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::{Fixture, run, scratch, stderr, stdout};

/// The issue's own clause-2 obligation, in its strongest form: the scaffolded
/// config is not merely present, it is one every read verb accepts. `config
/// show` proves the loader takes it, `check` proves the rule engine does, and
/// `config lint` proves it carries none of the smells the retired
/// `batten.example.toml` did — `unlanded = []` failed exactly this.
#[test]
fn init_writes_a_config_every_read_verb_accepts() {
    let dir = Fixture::new("init-accepted").git().build();

    let init = run(&dir, &["init"]);
    assert!(init.status.success(), "init: {}", stderr(&init));

    for verb in [
        vec!["config", "show"],
        vec!["check"],
        vec!["config", "lint"],
        vec!["doctor"],
    ] {
        let output = run(&dir, &verb);
        assert!(
            output.status.success(),
            "{verb:?} rejected what init wrote: {}{}",
            stdout(&output),
            stderr(&output)
        );
    }
}

/// A repository is not a precondition. §8 loads the authority from the working
/// directory with no upward walk, so `init` has nothing to discover — and the
/// empty-directory case is the one a first-contact user actually runs.
#[test]
fn init_needs_no_repository() {
    let dir = scratch("init-no-repo");

    let output = run(&dir, &["init"]);

    assert!(output.status.success(), "init: {}", stderr(&output));
    assert_eq!(stdout(&output), "batten.toml\n");
    assert!(dir.join("batten.toml").is_file());
}

/// The emitted bytes are the committed template, not a copy assembled at
/// runtime. This is what keeps `crates/batten/src/starter.toml` the single
/// authority the plan traded `batten.example.toml` away for.
#[test]
fn init_emits_the_committed_starter_verbatim() {
    let dir = scratch("init-verbatim");

    assert!(
        run(&dir, &["init"]).status.success(),
        "the fixture's own scaffold must succeed"
    );

    assert_eq!(
        fs::read_to_string(dir.join("batten.toml")).expect("read the scaffolded config"),
        batten::init::STARTER
    );
}

/// The refusal, and the two properties that make it one. Exit `2` is the policy
/// verdict (§7) rather than a usage error: `batten.toml` is the committed
/// authority, and declining to overwrite it is an answer about the repository,
/// not about the invocation. The reason therefore rides stderr **unprefixed** —
/// a `batten: ` prefix belongs to `1` and `3`.
#[test]
fn a_second_init_refuses_and_leaves_the_file_untouched() {
    let dir = scratch("init-twice");
    assert!(
        run(&dir, &["init"]).status.success(),
        "the fixture's own scaffold must succeed"
    );
    fs::write(dir.join("batten.toml"), "version = 1\n").expect("author over the starter");

    let output = run(&dir, &["init"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "", "a refusal emits no pointer");
    let reason = stderr(&output);
    assert!(reason.contains("batten.toml"), "the reason names the file");
    assert!(
        !reason.starts_with("batten:"),
        "a verdict must not read as a crash: {reason}"
    );
    // CLOUD-122: a deny points to the fix. Asserted over the rendered text
    // because that is the whole of what a caller gets back from this verb — the
    // `Refusal` type makes the clause impossible to omit, and this proves the
    // projection reaches the channel rather than stopping at the constructor.
    assert!(
        reason.contains(batten::init::CONFIG_EXISTS) && reason.contains("Fix:"),
        "the refusal must name its rule and its fix: {reason}"
    );
    assert_eq!(
        fs::read_to_string(dir.join("batten.toml")).expect("read the config"),
        "version = 1\n",
        "the caller's config was overwritten"
    );
}

/// `-n` writes nothing at all — the shape `tests/surface.rs` uses to hold
/// `generate`'s `read` effect honest, applied to the preview path of a `write`
/// verb.
#[test]
fn a_dry_run_writes_nothing() {
    let dir = scratch("init-dry-run");

    let output = run(&dir, &["init", "--dry-run"]);

    assert!(output.status.success(), "init -n: {}", stderr(&output));
    assert_eq!(stdout(&output), "batten.toml\n");
    assert_eq!(
        fs::read_dir(&dir).expect("read scratch dir").count(),
        0,
        "a preview wrote to the working directory"
    );
}

/// Existence is decided before `--dry-run`. A preview of a write that would
/// never happen is not a preview, so `-n` over an existing config reports the
/// same refusal the real run would — which is what makes `-n` a safe rehearsal
/// rather than a second answer.
#[test]
fn a_dry_run_over_an_existing_config_still_refuses() {
    let dir = scratch("init-dry-run-exists");
    assert!(
        run(&dir, &["init"]).status.success(),
        "the fixture's own scaffold must succeed"
    );

    let output = run(&dir, &["init", "-n"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "");
}

/// §6: identical input, identical bytes. Both channels, since the messaging half
/// is what a `--dry-run` caller reads.
#[test]
fn init_output_is_byte_stable_across_runs() {
    let first = {
        let dir = scratch("init-stable-a");
        run(&dir, &["init", "-n"])
    };
    let second = {
        let dir = scratch("init-stable-b");
        run(&dir, &["init", "-n"])
    };

    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}

/// The ladder governs the messaging channel and never the answer (§3/§4). `-q`
/// suppresses the "run `batten check` next" line; the pointer on stdout is
/// untouched, and so is the exit code.
#[test]
fn the_ladder_silences_the_hint_and_not_the_pointer() {
    let dir = scratch("init-quiet");

    let output = run(&dir, &["--quiet", "init"]);

    assert!(output.status.success());
    assert_eq!(stdout(&output), "batten.toml\n");
    assert_eq!(stderr(&output), "");
}

/// A refusal is never gated. `--silent` asked for less chatter, not for a bare
/// `2` explaining nothing — the same reason exit `1` is fail-loud.
#[test]
fn the_refusal_survives_silent() {
    let dir = scratch("init-silent-refusal");
    assert!(
        run(&dir, &["init"]).status.success(),
        "the fixture's own scaffold must succeed"
    );

    let output = run(&dir, &["--silent", "init"]);

    assert_eq!(output.status.code(), Some(2));
    // The whole refusal survives, fix clause included: `--silent` asked for less
    // chatter, and a deny stripped of its remedy is the bare "no" the contract
    // exists to prevent — which would make the ladder able to void it.
    let reason = stderr(&output);
    assert!(reason.contains("batten.toml"));
    assert!(
        reason.contains("Fix:"),
        "the fix clause is not chatter: {reason}"
    );
}

/// The `write` effect is declared, so `init` is absent from the derived
/// read-only allowlist. Asserted over the emitted spec rather than the source
/// table, because the allowlist an agent consumes is the emitted one.
#[test]
fn init_is_declared_write_and_stays_off_the_read_only_allowlist() {
    let dir = scratch("init-effect");

    let spec = run(&dir, &["spec"]);
    let value: serde_json::Value = serde_json::from_slice(&spec.stdout).expect("the spec is JSON");

    let init = value["subcommands"]
        .as_array()
        .expect("the spec lists subcommands")
        .iter()
        .find(|command| command["path"] == "init")
        .expect("the spec declares init");
    assert_eq!(init["effect"], "write");
}
