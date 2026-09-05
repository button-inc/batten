//! Resolved-symbol facts, from a delegated analyser's structured output
//! (CLOUD-760).
//!
//! **The first occupant of [`Cost::Effect`]**, and the reserved variant's first
//! occupant owes an account of itself. `facts.rs` declared `Effect` and
//! `Surface::VerifyOnly` unoccupied on purpose — *"naming it is what keeps the
//! first fact that needs it from inventing its own"* — so this module states the
//! boundary rather than assuming one.
//!
//! # What the cheaper tiers cannot answer
//!
//! Three tiers can be asked *where does this crate use* `std::process::Command`,
//! and they answer differently. CLOUD-760 states the difference as three counts —
//! 14 from a byte scan, 11 from a syntax matcher, 9 from name resolution — and
//! **measured on this tree the counts are the wrong comparison**, because the
//! byte tier and the resolved tier both report 16 while agreeing about almost
//! nothing.
//!
//! The disagreement is in the SET, in both directions:
//!
//! * `surface.rs` is in the byte set and not the resolved one — it calls
//!   `clap::Command::new` twice, which is the collision the fact exists to
//!   separate;
//! * `exec.rs` carries more resolved usages than `::new` occurrences, because an
//!   import and a type annotation are usages a byte scan cannot see.
//!
//! So the discriminator is membership rather than arithmetic, and
//! `tests/symbols.rs` asserts it that way. A coinciding total is exactly the
//! shape CLOUD-418 warns about: a test that passes for the wrong reason.
//!
//! The cheaper tiers are not approximations of this one; they answer different
//! questions. Only a tool that has performed name resolution can separate
//! `clap::Command` from `std::process::Command`, and Batten must not compute that
//! itself (CLOUD-756: *"Batten must not COMPUTE symbol resolution. It should
//! CONSUME resolved facts — and an exit code is one bit, not resolved facts."*).
//!
//! **What this tier reports is TYPE USAGES, not call sites**, stated because the
//! two are easily confused: `clippy::disallowed_types` fires wherever the type is
//! named, so an import counts. That is the honest reading of "where does this
//! crate use a spawn type", and it is a superset of "where does it call `::new`".
//!
//! # `--force-warn` is what makes the fact possible
//!
//! Every spawn site in this crate already carries an `#[expect(clippy::
//! disallowed_types, reason = …)]`, so under an ordinary run the lint is
//! *fulfilled* and clippy emits nothing. Reading the diagnostics would then count
//! zero — not because there are no spawns, but because they are all accounted
//! for.
//!
//! `--force-warn` overrides `allow` and `expect` alike, so the lint fires at
//! every site regardless of its annotation. That turns an ENFORCEMENT mechanism
//! into an ACQUISITION one: the same lint that refuses a new spawn at
//! `lint:clippy` is, under this flag, an inventory of every spawn there is. The
//! two readings must not be confused, which is why this module never uses
//! `-D warnings` — a run that aborts on the first diagnostic cannot enumerate.
//!
//! # Generalised from `secrets.rs`, not copied from it
//!
//! `secrets.rs` is this crate's prior art for adopting a delegated analyser, and
//! CLOUD-760 says to mine it rather than mirror it. What carries across is the
//! SHAPE — a pinned binary, flags pinned beside the parser, and an exit status
//! reconciled against the parse — and one invariant carried verbatim:
//!
//! > **clean is never inferred from a stream that failed to parse.**
//!
//! What does not carry across is the parsing itself. ripsecrets emits
//! colon-delimited text and performs no name resolution at all; clippy emits JSON
//! carrying spans, lint names and resolved paths. That difference is the whole
//! reason this tier exists, and it is why this is a second adopter of one shape
//! rather than a second copy of one parser.
//!
//! # Pointer-only, and here it is load-bearing
//!
//! A diagnostic carries a rendered message, a span, and the source text that
//! matched. None of that may escape (non-negotiable rule 4), and [`Site`] is
//! shaped so it cannot: it holds a repo-relative path, a line, and the lint's
//! name. The message and the source excerpt are dropped at the parse boundary and
//! never stored, which is `secrets.rs`'s discipline of wrapping a span at the
//! pipe rather than trusting every later caller not to print it.

use std::path::Path;

use crate::facts::Look;

/// The delegated analyser, pinned.
///
/// `cargo` rather than `clippy-driver`: the driver needs a target directory, a
/// sysroot and the crate's own dependency closure resolved, and reproducing that
/// would be writing the analyser rather than adopting one.
pub const ANALYSER: &str = "cargo";

/// The flags, pinned **beside the parser** that reads their output
/// (`secrets.rs`'s discipline).
///
/// `--message-format=json` is the fact; `--quiet` keeps cargo's own progress off
/// the stream being parsed. `--force-warn` follows `--` so it reaches the lint
/// driver rather than cargo, and it is what surfaces the `#[expect]`ed sites —
/// see the module doc.
pub const ANALYSER_FLAGS: &[&str] = &[
    "clippy",
    "--quiet",
    "--message-format=json",
    "--",
    "--force-warn",
    "clippy::disallowed_types",
];

/// Where this analyser is installed from, named so a missing one points at the
/// remedy rather than at a bare "not found".
const PROVISION_HINT: &str = "mise install";

/// How to reach the analyser: the program to spawn, and the arguments that must
/// precede its own.
///
/// **Resolved by the CALLER, which is the direction this module is placed in**
/// (CLOUD-1324). A toolchain pin is what decides whether [`ANALYSER`] means the
/// binary a bare `PATH` lookup finds or a pinned build reached through a runner,
/// and the engine already owns that ladder — one authority over an argv, which
/// `rules/policy-modules.md` states for its own surface and which holds
/// here for the same reason. Reaching back for it would be the `symbols -> rules`
/// back-edge `policy/module-layering.rego` forbids by name, so the launcher
/// arrives already resolved and this module only spawns it.
///
/// MEASURED, and it is why the field exists at all: this container carried a
/// version manager's build of the analyser AND an older one earlier on `PATH`
/// than it. The bare spawn found the older one, which refused the crate's own
/// `rust-version` and exited non-zero, so the census was `CouldNotLook` and
/// `spawn-adapters` correctly refused a tree with nothing wrong in it. A gate
/// that cannot look reports the same way whatever the cause, which is the whole
/// value of the class and also why the cause took a while to find.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Launcher {
    /// The program to spawn.
    pub program: String,
    /// Arguments placed before the analyser's own flags.
    pub prefix: Vec<String>,
}

impl Launcher {
    /// A launcher over a program and the arguments that precede the analyser's
    /// own.
    ///
    /// A constructor rather than public fields on a `#[non_exhaustive]` struct,
    /// so the fact's own suite can compose the two shapes the container actually
    /// produces — a bare program, and one reached through a runner.
    #[must_use]
    pub fn new(program: &str, prefix: &[String]) -> Self {
        Self {
            program: program.to_owned(),
            prefix: prefix.to_vec(),
        }
    }

    /// The analyser's flags with this launcher's prefix in front.
    ///
    /// Extracted rather than inlined at the two spawn sites for
    /// `rules/rust.md`'s reason: the failing condition is an ARGV
    /// composition, which a test can create, rather than a container whose
    /// `PATH` a test cannot rearrange without `unsafe`.
    #[must_use]
    pub fn argv(&self, args: &[&str]) -> Vec<String> {
        self.prefix
            .iter()
            .cloned()
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect()
    }
}

/// One resolved call site: a pointer, and nothing the analyser said about it.
///
/// The lint NAME is kept because it is what distinguishes one census from
/// another; the lint's rendered MESSAGE is not, because it quotes the source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Site {
    /// Repo-relative and `/`-separated, so the fact is byte-stable across
    /// checkouts — a diagnostic's own `file_name` is relative to the workspace
    /// cargo ran in, which is not the same guarantee.
    pub path: String,
    /// 1-indexed, as the analyser reports it.
    pub line: u32,
    /// The lint that fired, e.g. `clippy::disallowed_types`.
    pub lint: String,
}

/// Which tool produced a fact, and how.
///
/// **Part of the fact rather than beside it**, because a fact whose meaning
/// depends on an unrecorded tool version is not canonical: two runs that
/// disagree because the analyser changed are indistinguishable from two runs
/// that disagree because the tree changed, and §6 byte-stability cannot hold
/// across that. Recording the version makes a differing analyser VISIBLE rather
/// than silently absorbed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Provenance {
    /// The program, as invoked.
    pub tool: String,
    /// Its self-reported version string.
    pub version: String,
    /// The exact flags, so a reader can tell which question was asked.
    pub invocation: Vec<String>,
}

/// What one analyser run resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// Which tool, which version, which invocation.
    pub provenance: Provenance,
    /// Every site the run reported, sorted — a diagnostic stream's order is the
    /// compiler's scheduling and is not stable across runs.
    pub sites: Vec<Site>,
}

/// The analyser's own version, as provenance.
///
/// Its own spawn rather than a field parsed out of the diagnostic stream,
/// because the stream carries no version at all — and inferring one from the
/// diagnostics would be exactly the unrecorded dependency this guards against.
fn version(root: &Path, launcher: &Launcher) -> Look<String> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this fact IS Cost::Effect — resolving it runs a program, which is the classification, not an accident of it. The version is provenance and a fact without it is not canonical (CLOUD-760)"
    )]
    let spawned = std::process::Command::new(&launcher.program)
        .args(launcher.argv(&["clippy", "--version"]))
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let Ok(output) = spawned else {
        return Look::CouldNotLook;
    };
    if !output.status.success() {
        return Look::CouldNotLook;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(text)
    }
}

/// Resolve the symbol fact by running the analyser over `root`.
///
/// # Three answers, and the third is why this is not a `bool`
///
/// [`Look::Is`] carries what the analyser resolved. [`Look::IsNot`] is never
/// produced here — an analyser that ran and found nothing still produces a
/// `Resolved` with an empty site list, which is a different statement from
/// having failed to look. [`Look::CouldNotLook`] is every way the run did not
/// yield a trustworthy answer, and it is deliberately wide:
///
/// * the analyser is not installed, or could not be spawned;
/// * its version could not be read, so the fact would not be canonical;
/// * a diagnostic line is not JSON this build can read;
/// * the exit status and the parse disagree.
///
/// That last one is `secrets.rs`'s invariant, carried verbatim: **clean is never
/// inferred from a stream that failed to parse.** A run that exits non-zero
/// having emitted nothing parseable is not a clean tree — it is an analyser that
/// failed, and reporting zero sites from it would be the silent false green the
/// whole discipline exists to prevent.
#[must_use]
pub fn resolve(root: &Path, launcher: &Launcher) -> Look<Resolved> {
    let Look::Is(version) = version(root, launcher) else {
        return Look::CouldNotLook;
    };

    #[expect(
        clippy::disallowed_types,
        reason = "stays: this fact IS Cost::Effect — resolving it runs the delegated analyser, which is the classification. Adopting clippy rather than computing name resolution is CLOUD-756's decision"
    )]
    let spawned = std::process::Command::new(&launcher.program)
        .args(launcher.argv(ANALYSER_FLAGS))
        .current_dir(root)
        // Both streams captured, NEITHER forwarded: stdout is the fact and
        // stderr can carry a path the analyser failed to read. Echoing a child's
        // stream would put output Batten never shaped onto Batten's own.
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    let Ok(output) = spawned else {
        return Look::CouldNotLook;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    match sites_in(&stdout, root) {
        Look::Is(sites) => {
            // THE CROSS-CHECK, in the one direction that exists here. clippy
            // exits 0 under `--force-warn` however many diagnostics it emits —
            // the flag warns rather than denies — so a non-zero status means the
            // analyser itself failed, and the sites parsed out of a failed run
            // describe a compilation that did not finish. Reporting them would be
            // reporting a census of a tree that did not build.
            if output.status.success() {
                Look::Is(Resolved {
                    provenance: Provenance {
                        tool: ANALYSER.to_owned(),
                        version,
                        invocation: ANALYSER_FLAGS
                            .iter()
                            .map(|flag| (*flag).to_owned())
                            .collect(),
                    },
                    sites,
                })
            } else {
                Look::CouldNotLook
            }
        }
        _ => Look::CouldNotLook,
    }
}

/// Parse an analyser stream into sites.
///
/// Separated from the spawn for `secrets.rs`'s `parse_line` reason and
/// `rules/rust.md`'s: the failing condition is a STREAM SHAPE rather than
/// a repository state, so the decision is extracted and tested directly rather
/// than through a fixture that has to make a real analyser misbehave.
///
/// A line that is not JSON at all is skipped rather than refused — cargo
/// interleaves its own non-JSON progress on some paths, and refusing those would
/// make the fact unresolvable for a reason that has nothing to do with the
/// analyser. A line that IS JSON and IS a compiler message but cannot be read as
/// one is [`Look::CouldNotLook`]: that is a diagnostic this build does not
/// understand, and skipping it would undercount silently.
#[must_use]
pub fn sites_in(stream: &str, root: &Path) -> Look<Vec<Site>> {
    let mut sites = Vec::new();
    for emitted in stream.lines() {
        let emitted = emitted.trim();
        if emitted.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<serde_json::Value>(emitted) else {
            // Not JSON: cargo's own chatter, not a diagnostic.
            continue;
        };
        if record.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(message) = record.get("message") else {
            return Look::CouldNotLook;
        };
        let Some(lint) = message
            .get("code")
            .and_then(|code| code.get("code"))
            .and_then(serde_json::Value::as_str)
        else {
            // A compiler message with no lint code is a plain error or warning
            // and names no census.
            continue;
        };
        let Some(spans) = message.get("spans").and_then(serde_json::Value::as_array) else {
            return Look::CouldNotLook;
        };
        for span in spans {
            if span.get("is_primary").and_then(serde_json::Value::as_bool) != Some(true) {
                continue;
            }
            let (Some(file), Some(line_start)) = (
                span.get("file_name").and_then(serde_json::Value::as_str),
                span.get("line_start").and_then(serde_json::Value::as_u64),
            ) else {
                return Look::CouldNotLook;
            };
            let Ok(line_start) = u32::try_from(line_start) else {
                return Look::CouldNotLook;
            };
            sites.push(Site {
                path: canonical(file, root),
                line: line_start,
                lint: lint.to_owned(),
            });
        }
    }
    // Sorted, because a diagnostic stream's order is the compiler's scheduling
    // and two runs over identical bytes must produce identical output (§6).
    sites.sort();
    Look::Is(sites)
}

/// A diagnostic's path, as a repo-relative `/`-separated string.
///
/// The analyser reports paths relative to the workspace it ran in, which is not
/// the same guarantee as repo-relative — and an absolute one would make the fact
/// vary by checkout location, which §6 forbids.
fn canonical(file: &str, root: &Path) -> String {
    let normalised = file.replace('\\', "/");
    let root = root.to_string_lossy().replace('\\', "/");
    let trimmed = normalised
        .strip_prefix(&format!("{}/", root.trim_end_matches('/')))
        .unwrap_or(&normalised);
    trimmed.to_owned()
}

/// How many sites one lint reported.
///
/// The census predicate, as a function over the fact rather than over a stream:
/// a caller asking "how many `std::process::Command` sites are there" is asking
/// about the resolved fact, and giving it the stream would be handing back the
/// parsing problem this module exists to solve.
#[must_use]
pub fn count_of(resolved: &Resolved, lint: &str) -> usize {
    resolved
        .sites
        .iter()
        .filter(|site| site.lint == lint)
        .count()
}

/// The missing-analyser message, naming the remedy.
#[must_use]
pub fn unavailable() -> String {
    format!(
        "the delegated analyser `{ANALYSER} clippy` is not available; install it with `{PROVISION_HINT}`"
    )
}
