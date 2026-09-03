//! The API-compatibility gate, as a delegated-analyser adapter (CLOUD-1050).
//!
//! Ported from `mise-tasks/semver.sh` under CLOUD-1059, which is the rule
//! working on its author: repairing that gate meant editing it, an edit is
//! `shell edit refused`, and that verdict declares no override route. So the
//! maintenance was completed by migrating it, which is the campaign's whole
//! claim.
//!
//! # Generalised from `symbols.rs`, which generalised from `secrets.rs`
//!
//! The SHAPE carries across — a pinned binary, its flags pinned beside the
//! parser, and an exit status reconciled against what the output says — along
//! with the invariant those two state: **clean is never inferred from a stream
//! that failed to parse.** Here that is the vacuous-run refusal below.
//!
//! What is new is the baseline, and it is the reason this module exists at all.
//!
//! # The baseline can stop resolving with no commit, and did
//!
//! `cargo-semver-checks` generates a scratch crate for the baseline and runs
//! `cargo update` in it, so it **discards `Cargo.lock` by construction**. Its
//! verdict is therefore a function of the registry index at the moment it runs,
//! not of the tree — the only gate in this repository with that property, every
//! other one being pinned.
//!
//! Measured on 2026-08-26: the gate passed in CI at 19:18:19Z, `bisync 0.3.0`
//! was yanked at 19:25:45Z, and every commit from v0.0.89 on became unresolvable
//! seven minutes later — `gix 0.86` reaches it through `gix-protocol ^0.64.0`.
//! Nothing about the baseline was unbuildable: `origin/main`'s own `Cargo.lock`
//! pins `bisync 0.3.0`, and a yank does not invalidate an existing lock. Only
//! the re-resolve could not be satisfied.
//!
//! So [`baseline_rustdoc`] builds the baseline the way the repository's own
//! discipline says to — from the lock it committed — and hands the result over
//! through `--baseline-rustdoc`. That applies MORE of the gate than the rev
//! route, not less: the comparison is against the true baseline either way, and
//! this one survives a registry that has moved underneath it.
//!
//! **It is a FALLBACK and must stay one.** The rev route is the tool's own
//! well-tested path; taking it away would leave this module's own tree
//! materialization and doc build as the only thing anyone exercises. [`Route`] is what the
//! caller reports, so a green never hides which baseline produced it.

use std::path::{Path, PathBuf};

use crate::exit::ExitCode;

/// The analyser this module delegates to.
///
/// The core names the TOOL, never where a consumer pins it: which file carries
/// the pin is the consumer's business, and naming it here is non-negotiable
/// rule 1's violation — `no_artifact_name_reaches_the_core` said so about this
/// very line.
const ANALYSER: &str = "cargo";

/// What the tool prints when it graded nothing. A run that graded nothing has
/// not answered, and reading it as a pass is how this gate would quietly die —
/// measured, when an inherited `CARGO_TERM_COLOR=always` put escape sequences
/// between the anchor and the word and the refusal below never fired.
const VACUOUS: &str = " 0 checks:";

/// What a `cargo update` that could not resolve says. Either spelling is the
/// registry refusing, never an API verdict.
///
/// The third is the same class reached one step later, and it was measured
/// rather than predicted (2026-09-03). The first two are a resolve that could not
/// pick a version; this is a resolve that picked one and then could not BUILD it
/// — `tinyvec 1.13.0` published after this repository's lock pinned 1.12.0, and
/// it does not compile under the feature set the tool synthesises for its rustdoc
/// build. The tool re-resolves rather than reading `Cargo.lock`, so the lock that
/// makes every other build reproducible does not reach it, and the BASELINE side
/// has no manifest of ours to pin: it is whatever `origin/main` carried.
///
/// All three are the registry having moved underneath the comparison, which is
/// the whole reason [`Route::Lock`] exists — the baseline is still buildable from
/// the lock it committed. Reading only the first two left that fallback
/// unreachable for the one spelling that actually arrived, and the gate reported
/// could-not-look where it had a route it never took.
///
/// It does not weaken the gate: a genuine compilation failure in this crate
/// reaches the lock route too and fails there, so the refusal survives. What
/// changes is that a broken THIRD-PARTY resolve stops being reported as our
/// unanswerable comparison.
const UNRESOLVABLE: [&str; 3] = [
    "is yanked",
    "failed to select a version",
    "failed to build rustdoc",
];

/// Which baseline produced the verdict.
///
/// Reported rather than inferred: the two routes answer the same question and a
/// reader who cannot tell them apart cannot tell a normal run from one that
/// worked around a moved registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `--baseline-rev`, the tool's own path.
    Rev,
    /// `--baseline-rustdoc`, built from the baseline's committed lock.
    Lock,
}

impl Route {
    /// The stable token (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Route::Rev => "rev",
            Route::Lock => "lock",
        }
    }
}

/// One comparison's outcome, before it is reconciled against the declarations.
#[derive(Debug)]
pub struct Compared {
    /// The tool's own exit code: `0` compatible, `100` a bump larger than
    /// claimed, anything else a run that did not complete.
    pub code: Option<i32>,
    /// The report, read for the vacuous-run refusal and the failing lint ids.
    pub report: String,
    /// Which baseline answered.
    pub route: Route,
}

impl Compared {
    /// The failing lint ids, sorted and deduplicated.
    ///
    /// Pointer, never payload (non-negotiable rule 4): the ids the tool named,
    /// never the rustdoc it read them from.
    #[must_use]
    pub fn lints(&self) -> Vec<String> {
        let mut found: Vec<String> = self
            .report
            .lines()
            .filter_map(|line| line.strip_prefix("--- failure "))
            .filter_map(|rest| rest.split_whitespace().next())
            .map(|id| id.trim_end_matches(':').to_owned())
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// The SUBJECTS behind those ids: what changed, and where.
    ///
    /// A lint id alone names a CLASS and not an instance, so the refusal that
    /// carries only ids says a break exists and not what broke. Measured on this
    /// branch: `function_parameter_count_changed` was the whole refusal, and
    /// finding `recorder::record_path` meant running the delegated tool by hand —
    /// with the answer already sitting in `report`, unread.
    ///
    /// Still a pointer and never the payload (non-negotiable rule 4): the item's
    /// path, its line, and the tool's own one-line summary of the delta. No
    /// rustdoc, no signature, no source.
    ///
    /// **The path is relativised against `root`, and that is byte-stability rather
    /// than tidiness** (house-style §6): the tool prints an absolute path, so
    /// emitting it unchanged would make this gate's output differ between a
    /// developer's clone and a runner's.
    #[must_use]
    pub fn subjects(&self, root: &Path) -> Vec<String> {
        let prefix = format!("{}/", root.display());
        let mut found: Vec<String> = self
            .report
            .lines()
            .map(str::trim)
            // The tool writes one indented line per failing item under a
            // `Failed in:` header, each ending `, in <path>:<line>`. Keying on
            // that tail rather than on the header means a format change drops
            // subjects rather than silently pairing them with the wrong lint.
            .filter_map(|line| line.rsplit_once(", in "))
            .map(|(what, whence)| {
                let whence = whence.strip_prefix(&prefix).unwrap_or(whence);
                format!("{whence}  {what}")
            })
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Whether the run graded nothing.
    #[must_use]
    pub fn graded_nothing(&self) -> bool {
        self.report
            .lines()
            .any(|line| line.trim_start().starts_with("Checked") && line.contains(VACUOUS))
    }

    /// Whether the rev route's scratch resolve produced a tree that could not be
    /// resolved or could not be built.
    ///
    /// This is the could-not-look that the lock route answers, and it is read
    /// from the report rather than from the exit code because the tool reports
    /// the same code for every kind of broken run.
    ///
    /// **Named for the resolve rather than for the registry**, because CLOUD-1399
    /// measured the third way one fails: a resolve that succeeds and yields a
    /// dependency the pinned toolchain cannot compile is the same defect as one
    /// that never resolved, and the committed lock is the answer to both.
    #[must_use]
    pub fn unresolvable(&self) -> bool {
        UNRESOLVABLE.iter().any(|tell| self.report.contains(tell))
    }
}

/// Run the comparison against a git rev — the tool's own path.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays: this module IS the cargo-semver-checks adapter, which is what `policy/spawn-adapters.rego` places it for. The delegated tool is the whole mechanism (CLOUD-1050)"
)]
pub fn against_rev(
    root: &Path,
    toolchain: &str,
    package: &str,
    baseline: &str,
    release_type: &str,
) -> Option<Compared> {
    let output = std::process::Command::new(ANALYSER)
        .arg(format!("+{toolchain}"))
        .args(["semver-checks", "check-release"])
        .args(["--package", package])
        .args(["--baseline-rev", baseline])
        .args(["--release-type", release_type])
        // Overriding whatever the caller's environment set, and load-bearing rather than
        // cosmetic: the report below is PARSED, and a gate that parses colour is
        // CLOUD-199's defect — an anchored pattern that can never match because
        // escape sequences sit between the anchor and the word.
        .env("CARGO_TERM_COLOR", "never")
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    Some(Compared {
        code: output.status.code(),
        report: merged(&output),
        route: Route::Rev,
    })
}

/// Run the comparison against a rustdoc JSON built from the baseline's own lock.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays: the adapter's second invocation, for the same reason as the first — the fallback exists because the tool's own baseline generation discards the lock (CLOUD-1050)"
)]
pub fn against_rustdoc(
    root: &Path,
    toolchain: &str,
    package: &str,
    rustdoc: &Path,
    current: Option<&Path>,
    release_type: &str,
) -> Option<Compared> {
    let mut command = std::process::Command::new(ANALYSER);
    // `+toolchain` FIRST, always: cargo reads it as argv[1] and nowhere else, so
    // an option pushed ahead of it silently runs the default toolchain — the
    // failure that has no symptom until a version-dependent build breaks.
    command
        .arg(format!("+{toolchain}"))
        .args(["semver-checks", "check-release"])
        .args(["--package", package])
        .arg("--baseline-rustdoc")
        .arg(rustdoc);
    // `--current-rustdoc` only when one was built. Absent, the tool generates the
    // head side itself through the scratch resolve — which is the path CLOUD-1399
    // measured failing, so this is the arm that matters here; it stays optional
    // because a caller that could not build the head side is still better served
    // by the tool's own generation than by no comparison at all.
    if let Some(current) = current {
        command.arg("--current-rustdoc").arg(current);
    }
    let output = command
        .args(["--release-type", release_type])
        .env("CARGO_TERM_COLOR", "never")
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    Some(Compared {
        code: output.status.code(),
        report: merged(&output),
        route: Route::Lock,
    })
}

/// The pinned toolchain, read from the compiler that is actually active.
///
/// A READ of the one authority rather than a fourth copy of the number: mise
/// puts the pin on PATH, and the copies are what `msrv-pin-agreement` exists to
/// hold together. `SEMVER_TOOLCHAIN` overrides it, which is the seam the retired
/// suite drove and the one thing about it that had to survive the port.
///
/// **It lives here rather than beside its caller because `spawn-adapters` places
/// spawns by MODULE.** It sat in `lib.rs` first, on the reasoning that asking the
/// compiler its version is the caller's business — and `lib.rs` is not a placed
/// adapter, so the rule refused it. The reasoning was wrong anyway: this spawn
/// belongs to the same delegated analyser as the two below, and `current_dir` is
/// how the caller's root reaches it, exactly as it does for them.
#[must_use]
#[expect(
    clippy::disallowed_types,
    reason = "stays: asking the active compiler its version is how the pin is READ rather than restated, and it is the same delegated toolchain the two comparisons below invoke (CLOUD-1050)"
)]
pub fn toolchain(root: &Path) -> Option<String> {
    if let Ok(named) = std::env::var("SEMVER_TOOLCHAIN")
        && !named.is_empty()
    {
        return Some(named);
    }
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let version = text.split_whitespace().nth(1)?;
    (!version.is_empty()).then(|| version.to_owned())
}

/// Build the baseline's rustdoc JSON from the lock it committed.
///
/// # Why every flag here is load-bearing
///
/// * `--locked` is the whole point: the baseline's `Cargo.lock` is what a yank
///   cannot invalidate, and re-resolving is exactly what the rev route does that
///   this one must not.
/// * `RUSTC_BOOTSTRAP=1` is how rustdoc JSON is emitted on a pinned stable
///   toolchain. It is the same trick `cargo-semver-checks` performs internally,
///   so this is not a lower standard than the tool's own generation.
/// * `--document-private-items` is not optional and was found by measurement: a
///   baseline without it reported `constructible_struct_adds_private_field`
///   spuriously, because that lint reasons about fields a public API cannot see.
/// * Its own `CARGO_TARGET_DIR` beside the materialized tree, because the main
///   one is already held by whatever else `verify` is running — the same
///   reasoning `perf-pair` records for its two arms.
///
/// # Errors
///
/// Every failure is could-not-look — no baseline tree, no build, no JSON where
/// one was expected — and each carries ONE line saying which. A caller must not
/// read any of them as a clean comparison, and a gate that cannot say why it
/// could not look is the shape this repository refuses to ship.
#[expect(
    clippy::disallowed_types,
    reason = "stays: building the baseline is this adapter's own work, and the doc build is what the lock route IS (CLOUD-1050)"
)]
pub fn baseline_rustdoc(
    root: &Path,
    toolchain: &str,
    package: &str,
    baseline: &str,
    at: &Path,
) -> Result<PathBuf, String> {
    // ABSOLUTE, and this is not tidiness. The caller's root can be relative —
    // `.` is what it resolves to under `cargo run` — and the doc build runs with
    // its cwd set to the WORKTREE, so a relative `CARGO_TARGET_DIR` resolves
    // against that instead. Measured: the build reported success having written
    // into `tree/target/semver-baseline/target/`, and the JSON check then looked
    // where nobody had written. A build that succeeds into the wrong directory is
    // the worst shape available — it is a pass nobody can find.
    let at = &at
        .canonicalize()
        .map_err(|err| format!("the baseline scratch directory could not be resolved: {err}"))?;
    let worktree = at.join("tree");
    let target = at.join("target");
    // MATERIALIZED THROUGH gix, never `git worktree add`. CLOUD-740's terminal
    // assertion forbids naming `git` as a literal program anywhere in this
    // crate, and a source tree at a rev is exactly what `git::materialize_rev`
    // writes. It also removes the failure the spawn version shipped with: a
    // worktree keeps a registration outside the directory, so removing the
    // scratch stranded a stale entry and the next run refused over a path that
    // was no longer there.
    //
    // THE BASELINE, never `HEAD`. A tree at the branch's own tip would compare
    // the change to itself and pass unconditionally, which is the vacuous shape
    // this whole gate exists against.
    crate::git::materialize_rev(root, baseline, &worktree)
        .map_err(|err| format!("the baseline tree could not be materialized: {err}"))?;
    let built = std::process::Command::new(ANALYSER)
        .arg(format!("+{toolchain}"))
        .args([
            "doc",
            "--locked",
            "--no-deps",
            "--lib",
            "--package",
            package,
        ])
        .env("RUSTC_BOOTSTRAP", "1")
        .env(
            "RUSTDOCFLAGS",
            "-Z unstable-options --output-format json --document-private-items",
        )
        .env("CARGO_TARGET_DIR", &target)
        .env("CARGO_TERM_COLOR", "never")
        // THE OUTER CARGO'S ENVIRONMENT IS NOT THIS BUILD'S. When the binary
        // itself is launched through `cargo run`, cargo exports its own manifest
        // and toolchain into the child, and a nested `cargo doc` reads them as
        // instructions about a package that is not the one in front of it. Every
        // one is removed rather than overridden, because overriding requires
        // knowing the whole set and removal does not.
        .env_remove("CARGO")
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_MANIFEST_PATH")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_PKG_VERSION")
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .current_dir(&worktree)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|err| format!("the baseline doc build could not be run: {err}"))?;
    if !built.status.success() {
        return Err(format!(
            "the baseline doc build failed: {}",
            last_line(&built.stderr)
        ));
    }
    let json = target.join("doc").join(format!("{package}.json"));
    if json.is_file() {
        Ok(json)
    } else {
        Err(format!(
            "the baseline doc build reported success but emitted no rustdoc JSON at {}: {}",
            json.display(),
            last_line(&built.stdout)
        ))
    }
}

/// Build the CURRENT tree's rustdoc JSON from the lock this repository committed.
///
/// # Why the lock route needs both sides, which it did not have
///
/// [`baseline_rustdoc`] replaced the baseline half when the rev route's scratch
/// resolve fails. That was half a fallback, and CLOUD-1399 measured the other
/// half failing: `cargo-semver-checks` builds the CURRENT crate the same way it
/// builds the baseline — as a path dependency of a scratch package carrying no
/// lock — so a registry index ahead of the committed lock breaks the head side
/// too, and no baseline route can rescue it.
///
/// Measured in this container: the fresh resolve chose `tinyvec 1.13.0`, which
/// does not compile on the pinned toolchain, so the tool aborted with
/// `failed to build rustdoc for crate batten`. The committed lock names a version
/// that builds, and `--locked` is what makes the resolve read it instead.
///
/// # The differences from the baseline twin, and there are only two
///
/// No tree is materialized — the working tree IS the current side, so the build
/// runs in `root`. And the scratch directory is its own, because both halves can
/// be in flight in one run and a shared `CARGO_TARGET_DIR` would have them
/// overwrite each other's `{package}.json`. Every other flag is
/// [`baseline_rustdoc`]'s and is load-bearing for the reasons stated there.
///
/// # Errors
///
/// Could-not-look, one line saying which — never a clean comparison.
#[expect(
    clippy::disallowed_types,
    reason = "stays: the current half of the lock route, and the same delegated doc build its baseline twin performs (CLOUD-1399)"
)]
pub fn current_rustdoc(
    root: &Path,
    toolchain: &str,
    package: &str,
    at: &Path,
) -> Result<PathBuf, String> {
    // ABSOLUTE, for the baseline twin's measured reason: a relative
    // `CARGO_TARGET_DIR` resolves against the build's cwd, and a build that
    // succeeds into the wrong directory is a pass nobody can find.
    let target = at
        .canonicalize()
        .map_err(|err| format!("the current scratch directory could not be resolved: {err}"))?
        .join("target");
    let built = std::process::Command::new(ANALYSER)
        .arg(format!("+{toolchain}"))
        .args([
            "doc",
            "--locked",
            "--no-deps",
            "--lib",
            "--package",
            package,
        ])
        .env("RUSTC_BOOTSTRAP", "1")
        .env(
            "RUSTDOCFLAGS",
            "-Z unstable-options --output-format json --document-private-items",
        )
        .env("CARGO_TARGET_DIR", &target)
        .env("CARGO_TERM_COLOR", "never")
        .env_remove("CARGO")
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_MANIFEST_PATH")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_PKG_VERSION")
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|err| format!("the current doc build could not be run: {err}"))?;
    if !built.status.success() {
        return Err(format!(
            "the current doc build failed: {}",
            last_line(&built.stderr)
        ));
    }
    let json = target.join("doc").join(format!("{package}.json"));
    if json.is_file() {
        Ok(json)
    } else {
        Err(format!(
            "the current doc build reported success but emitted no rustdoc JSON at {}: {}",
            json.display(),
            last_line(&built.stdout)
        ))
    }
}

/// The last non-empty line of a child's stderr.
///
/// A POINTER rather than the payload (non-negotiable rule 4): one line names why
/// the gate could not look, and the whole stream is a build log nobody asked to
/// have quoted back at them.
fn last_line(stream: &[u8]) -> String {
    String::from_utf8_lossy(stream)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("no output")
        .trim()
        .to_owned()
}

/// Whether any commit in `base..head` DECLARES a breaking change.
///
/// Conventional Commits spells it two ways and both count: a `!` before the
/// colon, or a `BREAKING CHANGE:` footer. The range is the branch's own
/// commits, so a declaration that already landed on the baseline does not
/// license a break this branch introduced.
#[must_use]
pub fn declared_break(commits: &[Commit]) -> Option<String> {
    commits
        .iter()
        .find(|commit| declares(&commit.subject, &commit.body))
        .map(|commit| commit.sha.clone())
}

/// One commit, as the caller reads it out of git.
///
/// Three fields rather than two, because the sha is the POINTER a refusal
/// carries and the subject is what the predicate reads — collapsing them made
/// the first draft of this module report a subject where a reader expected a
/// sha.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The commit this is, reported as its short form.
    pub sha: String,
    /// `%s`.
    pub subject: String,
    /// `%B`.
    pub body: String,
}

/// The two Conventional Commits spellings, over one commit.
fn declares(subject: &str, body: &str) -> bool {
    body.lines()
        .any(|line| line.starts_with("BREAKING CHANGE:") || line.starts_with("BREAKING-CHANGE:"))
        || bang_before_colon(subject)
}

/// A `type(scope)!:` or `type!:` prefix.
///
/// Hand-scanned rather than a regex for `pattern.rs`'s reason: the shape is
/// three tokens and a literal, and a pattern here would be a second spelling of
/// something `commit.rs` already owns.
fn bang_before_colon(subject: &str) -> bool {
    let Some(colon) = subject.find(':') else {
        return false;
    };
    let head = &subject[..colon];
    let Some(head) = head.strip_suffix('!') else {
        return false;
    };
    let name = head.split_once('(').map_or(head, |(before, _)| before);
    !name.is_empty() && name.chars().all(|character| character.is_ascii_lowercase())
}

/// Both streams, because the tool splits its report across them and the
/// predicates below read one document.
fn merged(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// The verdict a caller renders, and the one contract (§7).
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The delta is compatible with the claim.
    Compatible,
    /// It breaks the API and a commit declares it.
    Declared(String),
    /// It breaks the API and nothing declares it.
    Undeclared,
    /// The comparison did not complete. Never a pass.
    CouldNotLook,
}

impl Verdict {
    /// The exit code this verdict maps to.
    ///
    /// `1` is an undeclared break and `2` is could-not-look, matching every
    /// other `*-check` program so a caller can tell "this branch breaks the
    /// contract" from "this gate never ran".
    #[must_use]
    pub const fn code(&self) -> ExitCode {
        match self {
            Verdict::Compatible | Verdict::Declared(_) => ExitCode::Success,
            Verdict::Undeclared => ExitCode::Violation,
            Verdict::CouldNotLook => ExitCode::Usage,
        }
    }
}

/// Reconcile a completed comparison against the branch's declarations.
///
/// `100` is cargo-semver-checks' own "required bump is larger than claimed";
/// anything that is neither `0` nor `100` is a broken run, which is
/// could-not-look rather than a verdict.
#[must_use]
pub fn reconcile(compared: &Compared, commits: &[Commit]) -> Verdict {
    if compared.graded_nothing() {
        return Verdict::CouldNotLook;
    }
    match compared.code {
        Some(0) => Verdict::Compatible,
        Some(100) => declared_break(commits).map_or(Verdict::Undeclared, Verdict::Declared),
        _ => Verdict::CouldNotLook,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(body: &str) -> Compared {
        Compared {
            code: Some(100),
            report: body.to_owned(),
            route: Route::Rev,
        }
    }

    #[test]
    fn a_graded_zero_run_is_never_a_pass() {
        let compared = report("     Checked [   0.1s] 0 checks: 0 pass, 0 fail\n");
        assert!(compared.graded_nothing());
        assert_eq!(reconcile(&compared, &[]), Verdict::CouldNotLook);
    }

    #[test]
    fn a_run_that_graded_something_is_not_vacuous() {
        // ANTI-VACUITY for the case above: the refusal must key on the COUNT
        // rather than on the word, or every run reads as vacuous.
        let compared = report("     Checked [   0.2s] 223 checks: 217 pass, 5 fail\n");
        assert!(!compared.graded_nothing());
    }

    #[test]
    fn a_baseline_that_will_not_build_takes_the_lock_route() {
        // Measured 2026-09-03: `tinyvec 1.13.0` published after this repository's
        // lock pinned 1.12.0 and does not compile under the feature set the tool
        // synthesises, so the BASELINE side — whatever `origin/main` carried, with
        // no manifest of ours to pin it — failed to build. The registry had moved
        // underneath the comparison, which is exactly what the lock route answers,
        // and reading only the two resolve spellings left it unreachable.
        let compared = report(
            "error: running cargo-doc on crate 'batten' failed with output:\n\
             error: cannot find macro `vec` in this scope\n\
             error: failed to build rustdoc for crate batten v0.0.139\n",
        );
        assert!(compared.unresolvable());
    }

    #[test]
    fn an_api_refusal_is_not_a_could_not_look() {
        // THE ARM THAT MAKES THE ONE ABOVE DISCRIMINATE. A widened tell that also
        // matched an ordinary verdict would route every refusal to the lock route
        // and grade the branch twice against a baseline it already judged — the
        // gate reporting could-not-look over an answer it had.
        let compared = report(
            "--- failure enum_variant_added: pub enum variant added ---\n\
             Checked [   0.2s] 223 checks: 222 pass, 1 fail\n",
        );
        assert!(!compared.unresolvable());
    }

    #[test]
    fn the_lints_are_ids_and_never_the_rustdoc() {
        let compared = report(
            "--- failure enum_variant_added: pub enum variant added ---\n\
             --- failure struct_pub_field_missing: field removed ---\n\
             --- failure enum_variant_added: again ---\n",
        );
        assert_eq!(
            compared.lints(),
            vec![
                String::from("enum_variant_added"),
                String::from("struct_pub_field_missing")
            ]
        );
    }

    #[test]
    fn a_subject_is_a_relative_pointer_and_never_the_source() {
        // The tool's own shape, absolute path and all — which is exactly what
        // must NOT reach the output, since it differs per clone.
        let compared = report(
            "--- failure function_parameter_count_changed: pub fn parameter count changed ---\n\
             \n\
             Failed in:\n  \
             batten::recorder::record_path now takes 4 parameters instead of 3, in \
             /home/user/batten/crates/batten/src/recorder.rs:1035\n",
        );
        assert_eq!(
            compared.subjects(Path::new("/home/user/batten")),
            vec![String::from(
                "crates/batten/src/recorder.rs:1035  batten::recorder::record_path now takes 4 parameters instead of 3"
            )]
        );
    }

    #[test]
    fn a_subject_outside_the_root_keeps_the_path_the_tool_gave() {
        // Shown able to fail the other way: stripping unconditionally would
        // mangle a path the prefix does not match, and a mangled pointer is
        // worse than a long one.
        let compared = report("Failed in:\n  batten::x::y changed, in /elsewhere/src/y.rs:7\n");
        assert_eq!(
            compared.subjects(Path::new("/home/user/batten")),
            vec![String::from("/elsewhere/src/y.rs:7  batten::x::y changed")]
        );
    }

    #[test]
    fn a_report_with_no_failed_in_block_yields_no_subjects() {
        // The empty answer is a real one: a lint can fail with no per-item
        // block, and a reader must not be handed a fabricated pointer.
        let compared = report("--- failure enum_variant_added: pub enum variant added ---\n");
        assert!(compared.subjects(Path::new("/home/user/batten")).is_empty());
    }

    #[test]
    fn a_bang_declares_a_break_and_a_bare_type_does_not() {
        assert!(bang_before_colon("feat(policy)!: a typed refusal"));
        assert!(bang_before_colon("feat!: a typed refusal"));
        assert!(!bang_before_colon("feat(policy): a typed refusal"));
        assert!(!bang_before_colon("no colon here"));
        // A `!` that is not the type's own is not a declaration.
        assert!(!bang_before_colon("fix: it broke! badly: really"));
    }

    #[test]
    fn a_breaking_change_footer_declares_too() {
        assert!(declares(
            "fix(policy): a repair",
            "BREAKING CHANGE: the ABI\n"
        ));
        assert!(declares(
            "fix(policy): a repair",
            "BREAKING-CHANGE: the ABI\n"
        ));
        assert!(!declares("fix(policy): a repair", "an ordinary body\n"));
    }

    fn commit(sha: &str, subject: &str, body: &str) -> Commit {
        Commit {
            sha: sha.to_owned(),
            subject: subject.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn an_undeclared_break_is_exit_one_and_a_declared_one_passes() {
        let compared = report("     Checked [] 223 checks: 217 pass, 5 fail\n");
        assert_eq!(reconcile(&compared, &[]), Verdict::Undeclared);
        assert_eq!(reconcile(&compared, &[]).code(), ExitCode::Violation);

        // THE POINTER IS THE SHA, not the subject. Collapsing the two is the
        // defect this shape exists to prevent: a refusal naming a commit message
        // where a reader expected a commit is a pointer nobody can follow.
        let declaring = [commit("abc1234", "feat(policy)!: the ABI", "the body\n")];
        assert_eq!(
            reconcile(&compared, &declaring),
            Verdict::Declared(String::from("abc1234"))
        );
        assert_eq!(reconcile(&compared, &declaring).code(), ExitCode::Success);
    }

    #[test]
    fn a_declaration_on_an_ordinary_commit_does_not_license_the_break() {
        // ANTI-VACUITY: without this the arm above passes for any commit at all,
        // and the range the caller hands over stops meaning anything.
        let compared = report("     Checked [] 223 checks: 217 pass, 5 fail\n");
        let ordinary = [commit("def5678", "fix(policy): a repair", "the body\n")];
        assert_eq!(reconcile(&compared, &ordinary), Verdict::Undeclared);
    }

    #[test]
    fn a_broken_run_is_could_not_look_rather_than_a_verdict() {
        let mut compared = report("     Checked [] 223 checks: 223 pass, 0 fail\n");
        compared.code = Some(101);
        assert_eq!(reconcile(&compared, &[]), Verdict::CouldNotLook);
        assert_eq!(reconcile(&compared, &[]).code(), ExitCode::Usage);
    }

    #[test]
    fn a_registry_that_could_not_resolve_is_told_apart_from_a_verdict() {
        // The tell the lock route keys on. Both spellings, because cargo uses
        // one or the other depending on which half of the resolve failed.
        let yanked = report("error: failed to select a version for `bisync`\n  0.3.0 is yanked\n");
        assert!(yanked.unresolvable());
        let ordinary = report("--- failure enum_variant_added: added ---\n");
        assert!(!ordinary.unresolvable());
    }

    #[test]
    fn a_scratch_resolve_that_will_not_build_is_told_apart_from_a_verdict() {
        // THE THIRD WAY THE REV ROUTE FAILS, measured on this repository in a
        // container whose registry index was ahead of the committed lock
        // (CLOUD-1399). The resolve SUCCEEDS and hands the scratch package a
        // transitive dependency the pinned toolchain cannot compile, so the tool
        // aborts at rustdoc generation with exit 101 — and neither tell above
        // appears anywhere in its report, so the lock route never engaged and the
        // gate reported could-not-look over a comparison the committed lock can
        // make.
        let unbuildable = report(
            "error: failed to build rustdoc for crate batten v0.0.139\nnote: this is usually due \
             to a compilation error in the crate\n",
        );
        assert!(unbuildable.unresolvable());
    }

    #[test]
    fn the_route_is_reportable_so_a_green_names_its_baseline() {
        assert_eq!(Route::Rev.as_str(), "rev");
        assert_eq!(Route::Lock.as_str(), "lock");
    }
}
