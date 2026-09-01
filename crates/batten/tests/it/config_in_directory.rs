//! WHICH repository supplies the committed authority is separable from WHERE
//! the run is (CLOUD-1228), over the compiled binary.
//!
//! # The defect, measured rather than predicted
//!
//! A governed shell program resolves everything from `$0` and carries its
//! grammar inline, so it ran correctly from any directory. Its compiled
//! successor reads the grammar from this repository's `[[pattern]]` rows and
//! discovers the repository from the working directory. **50 of 144
//! `tests/*.bats` suites `git init` a throwaway repository and run the program
//! inside it** — they do it to keep the board-move receipts CLOUD-512's guard
//! reads off the real checkout, which is correct and stays. The side effect
//! nobody intended is that the sandbox also removes the committed config every
//! successor needs, so an inherited suite goes red over a successor that is
//! behaving perfectly. Retiring `mise-tasks/ready-lint.sh` was built in full and
//! 44 of `tests/graph-check.bats`'s 86 cases failed exactly this way.
//!
//! # Why `--config-from` could not already do it
//!
//! `--config-from <ref>` names a git ref, resolved inside the repository the run
//! discovered. A bare scratch repository has no ref to name and no `batten.toml`
//! at any ref, so no spelling of the existing flag reaches the case. This is the
//! other axis: a **directory**.
//!
//! # The discriminating pair (§7, CLOUD-418)
//!
//! Neither half is evidence alone.
//!
//! * [`a_scratch_repo_told_where_the_config_lives_answers_as_the_checkout_does`]
//!   is the capability.
//! * [`the_same_scratch_repo_not_told_is_still_could_not_look`] is what stops it
//!   being a silent fallback — the failure mode a "helpfully find the config"
//!   implementation would have shipped as a feature.
//!
//! And [`a_named_directory_with_no_authority_is_could_not_look_never_defaults`]
//! is the same discrimination for the flag's own strictness, which is
//! `--config-from`'s asymmetry for `--config-from`'s reason: a caller who named
//! where the authority lives asked to be judged by what it declares.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, declared_patterns, run, run_with_stdin, stderr, stdout};

/// A checkout that declares a Ready grammar — the "repository under test" half.
///
/// The rows come from the committed `batten.toml` rather than being retyped, for
/// [`declared_patterns`]'s own reason: a suite carrying a second spelling of the
/// grammar tests the spelling.
fn checkout(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!("version = 1\n\n{}", declared_patterns()))
        .file(
            "Cargo.toml",
            "[workspace.package]\nversion = \"0.0.125\"\n\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .git()
        .base_commit()
        .build()
}

/// A bare `git init`-ed repository with no authority of its own.
///
/// This is what those 50 suites build. The one file exists only because a first
/// commit needs something to commit; nothing here declares any policy.
fn sandbox(name: &str) -> PathBuf {
    Fixture::new(name)
        .file("README.md", "a throwaway repository\n")
        .git()
        .base_commit()
        .build()
}

/// A well-formed Ready block, so the verb's answer turns on the GRAMMAR being
/// available rather than on the block being good.
fn payload() -> String {
    serde_json::json!({
        "id": "CLOUD-999",
        "description": "**Why**\nSomething needs doing.\n\n\
                        **Refinement — Ready (a summary)**\n\n\
                        * **Source of truth (§1).** One authoritative artifact.\n",
        "relations": { "blockedBy": [] },
    })
    .to_string()
}

fn lint(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["ready", "lint"];
    args.extend_from_slice(extra);
    run_with_stdin(dir, &args, &payload())
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

// ---------------------------------------------------------------------------
// The pair.
// ---------------------------------------------------------------------------

#[test]
fn a_scratch_repo_told_where_the_config_lives_answers_as_the_checkout_does() {
    // THE ACCEPTANCE, and it is an equality rather than a "passes": the fidelity
    // argument the retirement campaign rests on is that an inherited suite goes
    // green over an UNCHANGED consumer, so "the sandboxed run also exits 0" is
    // not enough — it has to be the same answer, byte for byte.
    let repo = checkout("config-in-checkout");
    let scratch = sandbox("config-in-scratch");

    let native = lint(&repo, &[]);
    let sandboxed = lint(&scratch, &["--config-in", repo.to_str().unwrap()]);

    assert_eq!(
        code(&native),
        0,
        "the fixture must be judgeable from its own checkout first: {}",
        stderr(&native)
    );
    assert_eq!(
        stdout(&sandboxed),
        stdout(&native),
        "the sandboxed run's stdout diverged: {}",
        stderr(&sandboxed)
    );
    assert_eq!(
        stderr(&sandboxed),
        stderr(&native),
        "the sandboxed run's stderr diverged"
    );
    assert_eq!(code(&sandboxed), code(&native));
}

#[test]
fn the_same_scratch_repo_not_told_is_still_could_not_look() {
    // THE OTHER HALF, and the one that stops this shipping as a silent fallback.
    // The implementation that "helpfully" walks up to a config, or falls back to
    // a built-in grammar, passes the test above and fails this one — and a
    // built-in grammar would put consumer vocabulary in the core, which is
    // non-negotiable rule 1.
    //
    // Could-not-look is exit 1 and NEVER the verb's "satisfies" line: a clean
    // verdict over a grammar nothing supplied is precisely the dead-gate reading
    // `ready.rs` exists to refuse.
    let scratch = sandbox("config-in-untold");
    let output = lint(&scratch, &[]);

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("satisfies"),
        "a repository that declared no grammar must not read as clean: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("ready-opener"),
        "and it must name the row it could not find: {}",
        stderr(&output)
    );
}

#[test]
fn a_named_directory_with_no_authority_is_could_not_look_never_defaults() {
    // The flag's OWN strictness, shown able to fail. Without `load_site`'s
    // check this run resolves to `config::defaults()` — CLOUD-70's zero-config
    // path — and reports whatever the built-in defaults say about a repository
    // the caller explicitly pointed somewhere else. That is a caller pointing at
    // an empty directory picking its own policy, which is the weakening
    // `--config-from`'s identical asymmetry exists to prevent.
    let scratch = sandbox("config-in-strict-subject");
    let empty = sandbox("config-in-strict-authority");
    let output = lint(&scratch, &["--config-in", empty.to_str().unwrap()]);

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("batten.toml"),
        "the refusal names what was missing: {text}"
    );
    assert!(
        !stdout(&output).contains("satisfies"),
        "and it is never a verdict: {}",
        stdout(&output)
    );
}

// ---------------------------------------------------------------------------
// What must NOT move with it.
// ---------------------------------------------------------------------------

#[test]
fn the_subject_stays_the_directory_being_judged() {
    // The whole reason the sandbox exists: writes and reads about the TREE stay
    // in the scratch repository. A change that moved the subject along with the
    // authority would isolate nothing, which is CLOUD-512's guard defeated by
    // the fix for CLOUD-1228.
    //
    // Both trees carry a file matching the row, with different names, so a
    // finding names which tree was walked and cannot be satisfied by either
    // answer accidentally.
    let policy = "version = 1\n\
                  \n\
                  [[rule]]\n\
                  id = \"no-appeal\"\n\
                  kind = \"forbid\"\n\
                  glob = \"**\"\n\
                  pattern = \"blessed-by\"\n\
                  severity = \"warn\"\n\
                  scope = \"tree\"\n\
                  no_fix_reason = \"say who decided, not who blessed it\"\n";
    let authority = Fixture::new("config-in-subject-authority")
        .config(policy)
        .file("only-in-the-authority.md", "blessed-by the architect\n")
        .git()
        .base_commit()
        .build();
    let subject = Fixture::new("config-in-subject-tree")
        .file("only-in-the-subject.md", "blessed-by the architect\n")
        .git()
        .base_commit()
        .build();

    let output = run(
        &subject,
        &["check", "--config-in", authority.to_str().unwrap()],
    );
    let found = stdout(&output);
    assert!(
        found.contains("only-in-the-subject.md"),
        "the authority's rule must run over the subject's tree: {found}"
    );
    assert!(
        !found.contains("only-in-the-authority.md"),
        "and never over the authority's own: {found}"
    );
}

#[test]
fn the_named_authority_replaces_the_subjects_rather_than_merging_with_it() {
    // House-style §8 keeps ONE committed authority. A merge would make this run
    // report both rows, and a fallback chain would report the subject's when the
    // named one said nothing about it. Exactly one config is read.
    let named = "version = 1\n\
                 \n\
                 [[rule]]\n\
                 id = \"named-row\"\n\
                 kind = \"forbid\"\n\
                 glob = \"**\"\n\
                 pattern = \"blessed-by\"\n\
                 severity = \"warn\"\n\
                 scope = \"tree\"\n\
                 no_fix_reason = \"say who decided\"\n";
    let local = "version = 1\n\
                 \n\
                 [[rule]]\n\
                 id = \"subject-row\"\n\
                 kind = \"forbid\"\n\
                 glob = \"**\"\n\
                 pattern = \"rubber-stamped\"\n\
                 severity = \"warn\"\n\
                 scope = \"tree\"\n\
                 no_fix_reason = \"say who decided\"\n";
    let authority = Fixture::new("config-in-merge-authority")
        .config(named)
        .git()
        .base_commit()
        .build();
    let subject = Fixture::new("config-in-merge-subject")
        .config(local)
        .file("notes.md", "blessed-by and rubber-stamped\n")
        .git()
        .base_commit()
        .build();

    let output = run(
        &subject,
        &["check", "--config-in", authority.to_str().unwrap()],
    );
    let found = stdout(&output);
    assert!(
        found.contains("named-row"),
        "the named authority governs: {found}"
    );
    assert!(
        !found.contains("subject-row"),
        "and the subject's own config is not layered underneath it: {found}"
    );
}

#[test]
fn the_declared_environment_variable_actually_reads() {
    // CLOUD-31's measured defect, on the sibling flag: `BATTEN_CONFIG_FROM` was
    // declared and read nowhere, and only an end-to-end run noticed. `EnvDecl`
    // makes that unrepresentable for the clap half; this is the run that proves
    // the declaration reaches the resolver.
    let repo = checkout("config-in-env-checkout");
    let scratch = sandbox("config-in-env-scratch");

    let output = batten()
        .args(["ready", "lint"])
        .env("BATTEN_CONFIG_IN", &repo)
        .current_dir(&scratch)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin is piped")
                .write_all(payload().as_bytes())?;
            child.wait_with_output()
        })
        .expect("run batten");

    assert_eq!(
        output.status.code(),
        Some(0),
        "the env equivalent must reach the resolver: {}",
        stderr(&output)
    );
    assert!(stdout(&output).contains("satisfies"), "{}", stdout(&output));
}
