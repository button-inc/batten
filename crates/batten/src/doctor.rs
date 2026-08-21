//! `batten doctor` — the designated post-install self-check (house-style §12).
//!
//! It answers one question: **can Batten do its job in this repository?** Not
//! "is the policy any good" — that is `config lint`'s question and it renders a
//! verdict. Keeping the two apart is what lets `doctor` promise something
//! stronger than a convention.
//!
//! # `doctor` never returns a policy verdict
//!
//! Every failure it can report — no config, an unparseable one, a working
//! directory that is not a repository — is the *config or usage* class, so
//! `doctor` returns [`ExitCode::Success`] or [`ExitCode::Usage`] and never
//! [`ExitCode::Violation`]. That is deliberate rather than incidental: a
//! diagnostic that could emit `2` would be read by a mediating harness as a
//! deny, and "your checkout is misconfigured" is not "policy says no" (§7).
//! [`crate::doctor::tests`] and the end-to-end suite both pin it.
//!
//! This is also why `config lint` is *not* one of the diagnostics, tempting as
//! it is: a smell is exit `2` when `config lint` reports it, and folding it in
//! here would force either a code collision or two different answers to the same
//! question.
//!
//! # Output is byte-stable and carries no paths
//!
//! A check reports a name, a boolean, and — when it fails — a **stable reason
//! id**, never the underlying message. Messages carry absolute paths, which
//! differ per machine and would defeat byte-stability (§6) while leaking the
//! layout of someone's disk into a log (rule 4).
//!
//! Not to be confused with `mise-tasks/doctor.sh`, which gates *this repository's*
//! own provisioning (the bats submodule, rustup cross targets). That one is
//! repo tooling; this is the product verb.

use std::borrow::Cow;
use std::path::Path;

use crate::exit::ExitCode;
use crate::rules::Rule;
use crate::{config, git, hook, resolve};

/// One diagnostic's outcome.
///
/// The reason is a stable id rather than the error text, so the report is
/// byte-stable across machines and never carries a path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    /// The diagnostic's stable name.
    pub name: &'static str,
    /// Whether it passed.
    pub ok: bool,
    /// A stable reason id when it failed; absent when it passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl Check {
    const fn passed(name: &'static str) -> Self {
        Check {
            name,
            ok: true,
            reason: None,
        }
    }

    const fn failed(name: &'static str, reason: &'static str) -> Self {
        Check {
            name,
            ok: false,
            reason: Some(reason),
        }
    }

    /// The pointer line this check renders as (§6), without a trailing newline.
    #[must_use]
    pub fn line(&self) -> String {
        match self.reason {
            Some(reason) => format!("{} failed {reason}", self.name),
            None => format!("{} ok", self.name),
        }
    }
}

/// The whole diagnosis, as the `-J` data channel renders it.
///
/// Deliberately carries no timestamp, no duration and no path: identical input
/// must yield identical bytes (§6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    /// The running binary's version.
    pub version: &'static str,
    /// The content hash of the governing config surface (CLOUD-32), when it
    /// could be computed.
    ///
    /// Absent rather than empty when the config did not load or a tracked path
    /// is unreadable: a placeholder would be a *stable* value over an unknown
    /// surface, which is exactly what the epoch exists to prevent. `doctor` does
    /// not fail on that — the `config` check above already names the cause, and
    /// a diagnostic that could exit 3 for a missing file would stop being the
    /// config-or-usage-only verb §7 needs it to be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_epoch: Option<String>,
    /// Whether every diagnostic passed.
    pub ok: bool,
    /// Each diagnostic, in a fixed order.
    pub checks: Vec<Check>,
}

impl Report {
    /// The exit code this report maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable by construction — see the module
    /// docs. The range is the guarantee, not the branch.
    #[must_use]
    pub fn code(&self) -> ExitCode {
        if self.ok {
            ExitCode::Success
        } else {
            ExitCode::Usage
        }
    }
}

/// The committed authority is present, parses, and resolves through the §8
/// chain — including the `min_batten_version` gate (CLOUD-33).
const CONFIG: &str = "config";
/// The working directory is inside a git repository with a derivable root.
///
/// Not cosmetic: `--config-from` (CLOUD-31) and the receipt verbs both resolve
/// against it, so a checkout where this fails is one where those silently have
/// nothing to stand on.
const GIT_REPO: &str = "git-repo";
/// Every `command`-kind rule names a program that resolves on `PATH`.
///
/// A missing binary is otherwise discovered at `enforce` time, mid-run, as a
/// failure of the gate rather than of the setup. §9 is explicit that a rule
/// "names a command already on the operator's PATH" — this is the probe that
/// says whether that premise holds, before anything depends on it.
const COMMAND_PROGRAMS: &str = "command-programs";

/// Whether `program` resolves to an existing file on `PATH`.
///
/// **Stats, never executes.** Running the program to see whether it exists is
/// precisely what a `read` verb may not do (§5, CLOUD-170): it would reach
/// user-supplied code from the read-only surface. A path-bearing token
/// (`./bin/tool`) is checked where it points; a bare name is looked up across
/// `PATH` entries.
/// **One lookup, shared with the spawn path.** This carried its own copy, and
/// the copy searched only the verbatim name — so on Windows it reported
/// `program-not-on-path` for `sh` while `sh.exe` sat on PATH, and this
/// repository failed its own `doctor` (CLOUD-617). Two answers to "is this
/// program on PATH" is one too many: the probe must agree with the spawn it is
/// predicting, or it diagnoses a run that would have worked.
fn on_path(program: &str) -> bool {
    if program.contains(std::path::MAIN_SEPARATOR) || program.contains('/') {
        return Path::new(program).is_file();
    }
    crate::rules::on_path_verbatim(program).is_some()
}

/// Diagnose the repository rooted at `dir`.
///
/// Infallible by construction: every failure becomes a [`Check`] rather than an
/// error, because a diagnostic that aborts on the first problem reports one
/// symptom when the operator wants the list.
#[must_use]
pub fn diagnose(dir: &Path) -> Report {
    let mut checks = Vec::new();

    checks.push(match config::load(&dir.join(config::CONFIG_FILE)) {
        // Loading proves the file parses and the version gates pass; resolving
        // proves the §8 chain (including a `batten.local.toml`) is coherent too.
        // Both are wanted — a config that parses but whose local override is
        // refused is not a working setup.
        Ok(_) => match resolve::resolve(dir, &crate::Overrides::default()) {
            Ok(_) => Check::passed(CONFIG),
            Err(_) => Check::failed(CONFIG, "config-unresolvable"),
        },
        Err(_) if !dir.join(config::CONFIG_FILE).exists() => {
            Check::failed(CONFIG, "config-missing")
        }
        Err(_) => Check::failed(CONFIG, "config-invalid"),
    });

    checks.push(match git::repo_root(dir) {
        Ok(_) => Check::passed(GIT_REPO),
        Err(_) => Check::failed(GIT_REPO, "not-a-repository"),
    });

    // Probed off the *resolved* rule set, so a rule a local override added is
    // covered too — those are gates a run actually applies. A config that did
    // not load reports no rules rather than a second failure: `config` above
    // already named that, and repeating it would double-count one problem.
    let rules = resolve::resolve(dir, &crate::Overrides::default())
        .map(|resolved| resolved.rules)
        .unwrap_or_default();
    let missing = rules
        .iter()
        .filter_map(Rule::program)
        .any(|program| !on_path(program));
    checks.push(if missing {
        Check::failed(COMMAND_PROGRAMS, "program-not-on-path")
    } else {
        Check::passed(COMMAND_PROGRAMS)
    });

    // The working-tree authority: `doctor` diagnoses the checkout in front of
    // it, so it does not take a base ref.
    let config_epoch = crate::epoch::compute(dir, None).ok();

    Report {
        version: config::VERSION,
        config_epoch,
        ok: checks.iter().all(|check| check.ok),
        checks,
    }
}

/// One wiring finding: the event it is about, and a stable reason id.
///
/// The event is a HOST TOKEN — `PreToolUse`, `preToolUse`, `BeforeTool` — read
/// off the derivation or off the committed file's own keys. It is not a path,
/// which is the property §5 constrains: `a_reason_id_never_carries_a_path` holds
/// over `reason`, and a hook event name has no directory in it to leak.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WiringFinding {
    /// The host's spelling of the event this is about.
    pub event: String,
    /// The stable reason id.
    pub reason: &'static str,
}

/// One harness's wiring diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HarnessWiring {
    /// The harness's stable token.
    pub harness: &'static str,
    /// How many committed registrations claim to be batten's.
    pub registrations: usize,
    /// How many commands on this surface are **not** batten's.
    ///
    /// A COUNT, never a name, and never a failure. Two separate reasons, and the
    /// second is the one that decides the boolean:
    ///
    /// * rule 4 — a sibling is a command line, which carries a path; reporting it
    ///   would put a consumer's disk layout in a diagnostic that promises not to.
    /// * whether a hook beside batten's is legitimate is a CONSUMER's judgement.
    ///   This repository refuses them and says so in `hooks-wiring-check`'s
    ///   `DECLARED` table, which names the issue retiring each — that is a fact
    ///   about this repository, not about the engine, and non-negotiable rule 1
    ///   is why it cannot move in here.
    pub siblings: usize,
    /// How many commands sit on this host's **merged** surfaces — the files it
    /// combines hook config from beyond the committed one (CLOUD-525).
    ///
    /// A COUNT, and here that is a **portability** property as well as rule 4's:
    /// a merged path is under the user's home directory and differs per machine,
    /// so emitting one would defeat §6 byte-stability and leak the layout of
    /// somebody's disk. The count is what makes an undeclared registration
    /// *visible*; deciding whether it is legitimate is a consumer's judgement,
    /// for the reason [`HarnessWiring::siblings`] gives.
    ///
    /// **This is the number the committed surface cannot see.** Measured in one
    /// container 2026-08-21, Claude Code ran three `Stop` handlers and four on
    /// `SessionStart` while every gate read two and three.
    pub merged: usize,
    /// How many of this host's merged surfaces were readable.
    ///
    /// Three-valued rather than two: a merged file that is absent is the
    /// ordinary case (most machines have no launcher file), and one that exists
    /// and cannot be parsed is a different claim. Reporting only `merged` would
    /// make "no extra registrations" and "could not look" the same number, which
    /// is the collapse `Look` exists to prevent.
    pub merged_surfaces_read: usize,
    /// What is wrong, in derivation order.
    pub findings: Vec<WiringFinding>,
    /// Whether this harness's wiring matches the derivation.
    pub ok: bool,
}

/// The whole hook-wiring diagnosis, as the `-J` data channel renders it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WiringReport {
    /// The running binary's version.
    pub version: &'static str,
    /// Whether every harness's wiring matches.
    pub ok: bool,
    /// One row per harness with a hook-config surface, in `Harness::ALL` order.
    pub harnesses: Vec<HarnessWiring>,
}

impl WiringReport {
    /// The exit code this report maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable here for the reason it is
    /// unreachable for [`Report`]: a sub-verb of `doctor` is a diagnosis, and a
    /// mediating harness reads `2` as a deny. "Your wiring is wrong" is not
    /// "policy says no".
    #[must_use]
    pub fn code(&self) -> ExitCode {
        if self.ok {
            ExitCode::Success
        } else {
            ExitCode::Usage
        }
    }
}

/// A derived event has no registration at all — a surface the decision says must
/// be covered and is not.
const EVENT_UNREGISTERED: &str = "hook-wiring-event-unregistered";
/// A derived event carries more than one batten registration.
///
/// The `n` is a literal token rather than the count. A reason id is
/// `&'static str` and must be byte-stable across runs and machines (§6); the
/// count is in `registrations` for a reader who wants it.
const EVENT_REGISTERED_N_TIMES: &str = "hook-wiring-event-registered-n-times";
/// A batten registration sits under an event the derivation does not emit — a
/// hook that can never fire: installed, green to every other check, enforcing
/// nothing.
const EVENT_UNDERIVED: &str = "hook-wiring-event-underived";
/// A batten registration carries a matcher.
///
/// Not "a matcher we disagree with" — any at all. The derivation emits none
/// deliberately, so that `batten.toml`'s `mediated_call` rows are the only
/// narrowing; a matcher here narrows in a second place, and a wrong one narrows
/// enforcement silently.
const MATCHER_NARROWS: &str = "hook-wiring-matcher-narrows";
/// A registration claims to be batten's and does not invoke the engine.
const COMMAND_DRIFT: &str = "hook-wiring-command-drift";
/// The harness declares a wiring file and the checkout has none.
const FILE_MISSING: &str = "hook-wiring-file-missing";
/// A batten registration sits on a MERGED surface as well as the committed one
/// (CLOUD-525).
///
/// A second authority for one decision, arriving from a file the repository does
/// not own — so it cannot be fixed by editing the committed wiring, which is
/// exactly why it needs its own id rather than folding into
/// `event-registered-n-times`.
const MERGED_REGISTRATION: &str = "hook-wiring-merged-registration";
/// The wiring file is there and is not readable as the JSON object it must be.
///
/// Distinct from missing on purpose: two different remedies — write one, or fix
/// one — so a single reason id would send the reader to the wrong place.
const FILE_UNREADABLE: &str = "hook-wiring-file-unreadable";

/// The event map inside a committed wiring file.
///
/// One expression for both shapes of [`hook::WiringFile`], read from the
/// harness's own declaration rather than from a `(.hooks // .)` guess. The bash
/// gate carried that guess as a second copy of the Key/Whole split; deleting the
/// copy is the point of moving this in-process, not a side effect.
fn committed_events(
    document: &serde_json::Value,
    file: hook::WiringFile,
) -> Option<Cow<'_, serde_json::Map<String, serde_json::Value>>> {
    let key = match file {
        hook::WiringFile::Key { key, .. } => key,
        // A hooks-only file is what `render_wiring` emits whole, and what it
        // emits is `{"hooks": {…}}`.
        hook::WiringFile::Whole(_) => "hooks",
    };
    // AN ABSENT KEY IS AN EMPTY MAP, NEVER UNREADABLE, and the distinction is a
    // verdict rather than a detail. A settings file carrying `permissions` and no
    // `hooks` parses perfectly and registers batten nowhere — which under
    // "registered on every surface" is the MAXIMAL disagreement, one
    // `event-unregistered` per event. Reading it as "could not look" would answer
    // a question nobody asked and hide the one that was.
    //
    // What is genuinely unreadable is a document that is not an object, or a
    // `hooks` that is not one.
    match document.get(key) {
        None => document
            .is_object()
            .then(|| Cow::Owned(serde_json::Map::new())),
        Some(value) => value.as_object().map(Cow::Borrowed),
    }
}

/// Every `{matcher, command}` pair registered under one event.
fn entries_under(value: &serde_json::Value) -> Vec<(Option<&str>, &str)> {
    let mut pairs = Vec::new();
    for entry in value.as_array().into_iter().flatten() {
        let matcher = entry.get("matcher").and_then(serde_json::Value::as_str);
        for hook in entry
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(command) = hook.get("command").and_then(serde_json::Value::as_str) {
                pairs.push((matcher, command));
            }
        }
    }
    pairs
}

/// Diagnose one harness's committed wiring against what the binary derives.
///
/// **Selected broadly, judged narrowly**, which is a false green this predicate's
/// bash predecessor had while it was being written. Selecting batten's entries on
/// "does this command reach the engine" makes the selector and the check one
/// predicate: a renamed command stops being *wrong* and becomes *invisible*, and
/// the run reports zero registrations and passes. So the selector asks only
/// whether a command mentions batten at all, and whether it actually reaches the
/// engine is decided below, where a wrong answer is a finding rather than a
/// silence.
#[allow(
    clippy::too_many_lines,
    reason = "one harness's diagnosis reads as one sequence: locate the file, judge               batten's entries per derived event, then the rest of the surface. Splitting               it would thread `findings`, `registrations` and `siblings` through helpers               that exist only to satisfy a line count, and each of the three phases is               already commented as its own step."
)]
fn diagnose_harness(dir: &Path, harness: hook::Harness) -> Option<HarnessWiring> {
    let wiring = harness.wiring()?;
    let path = match wiring.file {
        hook::WiringFile::Key { path, .. } | hook::WiringFile::Whole(path) => path,
    };
    let derived = wiring.registrations(harness);
    let command = hook::wiring_command(harness);
    let mut findings = Vec::new();
    let mut registrations = 0;
    let mut siblings = 0;

    let row = |findings: Vec<WiringFinding>, registrations, siblings| HarnessWiring {
        harness: harness.as_str(),
        registrations,
        siblings,
        merged: 0,
        merged_surfaces_read: 0,
        ok: findings.is_empty(),
        findings,
    };

    // ABSENT IS A FINDING, NEVER A PASS. A harness that declares a surface and
    // has no file on it is unwired, which is the state this check exists to
    // report — reading "nothing to compare" as "nothing wrong" is the shape the
    // gate keeps re-meeting.
    let Ok(raw) = std::fs::read_to_string(dir.join(path)) else {
        return Some(row(
            vec![WiringFinding {
                event: String::new(),
                reason: FILE_MISSING,
            }],
            0,
            0,
        ));
    };
    let unreadable = || {
        Some(row(
            vec![WiringFinding {
                event: String::new(),
                reason: FILE_UNREADABLE,
            }],
            0,
            0,
        ))
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return unreadable();
    };
    let Some(events) = committed_events(&document, wiring.file) else {
        return unreadable();
    };

    // Batten's own entries, judged per derived event.
    for (event, spelling) in &derived {
        let _ = event;
        let mut here = 0;
        for (matcher, entry) in events
            .get(*spelling)
            .map(entries_under)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, entry)| entry.contains("batten"))
        {
            here += 1;
            registrations += 1;
            if matcher.is_some() {
                findings.push(WiringFinding {
                    event: (*spelling).to_owned(),
                    reason: MATCHER_NARROWS,
                });
            }
            // CONTAINS, not equality: a consumer may name an absolute path to the
            // binary, and the claim being checked is that the engine is reached,
            // not how the operator spelled the way there.
            if !entry.contains(&command) {
                findings.push(WiringFinding {
                    event: (*spelling).to_owned(),
                    reason: COMMAND_DRIFT,
                });
            }
        }
        // EXACTLY ONE, IN BOTH DIRECTIONS. The engine emits one registration per
        // event, so a second is a second authority for one decision, and a zero
        // is a surface the decision says must be covered and is not.
        if here == 0 {
            findings.push(WiringFinding {
                event: (*spelling).to_owned(),
                reason: EVENT_UNREGISTERED,
            });
        } else if here > 1 {
            findings.push(WiringFinding {
                event: (*spelling).to_owned(),
                reason: EVENT_REGISTERED_N_TIMES,
            });
        }
    }

    // Everything else on the surface: a batten entry under an event the
    // derivation does not emit, and the sibling count.
    let spellings: Vec<&str> = derived.iter().map(|(_, spelling)| *spelling).collect();
    for (event, value) in events.iter() {
        for (_, entry) in entries_under(value) {
            if !entry.contains("batten") {
                siblings += 1;
            } else if !spellings.contains(&event.as_str()) {
                registrations += 1;
                findings.push(WiringFinding {
                    event: event.clone(),
                    reason: EVENT_UNDERIVED,
                });
            }
        }
    }

    // The MERGED surfaces (CLOUD-525). Read after the committed one and folded
    // into the same row, because "what does this host run" is one question — the
    // committed file is a partial answer to it, not a different question.
    //
    // Absent is the ordinary case and never a finding: most machines carry no
    // launcher file, and a check that went red for its absence would be red on
    // every developer's box for a state nobody can fix.
    let (merged, merged_surfaces_read, merged_findings) = diagnose_merged(dir, harness, &command);
    findings.extend(merged_findings);

    Some(HarnessWiring {
        harness: harness.as_str(),
        registrations,
        siblings,
        merged,
        merged_surfaces_read,
        ok: findings.is_empty(),
        findings,
    })
}

/// Whether two paths name the same file on disk.
///
/// Compared by CANONICAL path rather than by string: a checkout reached through
/// a symlink, or spelled with a `.`, is still the same file, and a string
/// comparison would miss it and report the committed wiring as a merged second
/// authority. A path that does not canonicalize does not exist, and a file that
/// does not exist collides with nothing.
///
/// The collision is real rather than theoretical: several hosts spell their
/// user-level surface and their project-level one identically, differing only in
/// which directory they are resolved against, so a checkout that sits AT the
/// home directory resolves both to one file.
fn same_file(one: &Path, two: &Path) -> bool {
    match (one.canonicalize(), two.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Count what this host merges beyond its committed wiring (CLOUD-525).
///
/// Returns `(commands, surfaces_read, findings)`. **No path leaves this
/// function**, on either channel: the home directory it resolves differs per
/// machine, and a reason id carrying one would defeat both §6 byte-stability and
/// rule 4. `a_wiring_reason_id_never_carries_a_path` is the assertion.
///
/// A batten registration found here IS a finding — a second authority for a
/// decision the committed file already makes, arriving from a file the
/// repository cannot edit. A non-batten one is only counted: whether a sibling
/// is legitimate is a consumer's judgement, and this repository answers it in
/// `hooks-wiring-check`'s `DECLARED` table rather than in the engine
/// (non-negotiable rule 1).
fn diagnose_merged(
    dir: &Path,
    harness: hook::Harness,
    command: &str,
) -> (usize, usize, Vec<WiringFinding>) {
    use etcetera::BaseStrategy as _;

    let surfaces = harness.merge_surfaces();
    if surfaces.is_empty() {
        return (0, 0, Vec::new());
    }
    let Ok(strategy) = etcetera::choose_base_strategy() else {
        // No resolvable home is COULD NOT LOOK, and it reports zero surfaces
        // read rather than zero registrations found — the distinction the
        // `merged_surfaces_read` field exists to carry.
        return (0, 0, Vec::new());
    };
    let home = strategy.home_dir().to_path_buf();

    let mut merged = 0;
    let mut read = 0;
    let mut findings = Vec::new();
    for surface in surfaces {
        let path = home.join(surface);
        // THE SAME FILE IS NOT A SECOND AUTHORITY. Several hosts spell their
        // user-level surface and their project-level one identically, differing
        // only in the directory each is resolved against, so a checkout sitting
        // AT the home directory resolves both to one file. Counting it twice
        // would report every one of batten's own registrations as a merged
        // second authority — a finding about the reader rather than the wiring.
        if same_file(&path, &dir.join(surface)) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        read += 1;
        // Every host that merges keys its hooks under the same word its
        // committed file does, which `WiringFile` already states.
        let Some(events) = committed_events(
            &document,
            harness
                .wiring()
                .map_or(hook::WiringFile::Whole(""), |w| w.file),
        ) else {
            continue;
        };
        for (event, value) in events.iter() {
            for (_, entry) in entries_under(value) {
                merged += 1;
                if entry.contains(command) || entry.contains("batten") {
                    findings.push(WiringFinding {
                        event: event.clone(),
                        reason: MERGED_REGISTRATION,
                    });
                }
            }
        }
    }
    (merged, read, findings)
}

/// Diagnose the hook wiring of every harness the core knows (CLOUD-777).
///
/// **Ranged over [`hook::Harness::ALL`], never a table.** Which harnesses exist
/// is the core's own answer, so a seventh adapter is diagnosed the day it lands
/// rather than silently omitted — the shape a hand-kept list answers "no" to.
/// `exit-code` declares no wiring surface and [`hook::Harness::wiring`] returns
/// `None` for it, which is what excludes it: the neutral contract is an envelope
/// in and a decision as an exit status out, with no file to register in.
#[must_use]
pub fn diagnose_hooks(dir: &Path) -> WiringReport {
    let harnesses: Vec<HarnessWiring> = hook::Harness::ALL
        .iter()
        .filter_map(|harness| diagnose_harness(dir, *harness))
        .collect();
    WiringReport {
        version: config::VERSION,
        ok: harnesses.iter().all(|harness| harness.ok),
        harnesses,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("batten-doctor-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_config_is_named_rather_than_lumped_in() {
        let dir = scratch("missing-config");
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert!(!config.ok);
        assert_eq!(config.reason, Some("config-missing"));
    }

    #[test]
    fn an_invalid_config_is_named_distinctly_from_a_missing_one() {
        // Two different remedies — write one, or fix one — so one reason id for
        // both would send the reader to the wrong place.
        let dir = scratch("invalid-config");
        fs::write(dir.join("batten.toml"), "this is not toml\n").unwrap();
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert_eq!(config.reason, Some("config-invalid"));
    }

    #[test]
    fn a_failing_diagnosis_is_never_a_policy_verdict() {
        // The load-bearing guarantee: a harness reads `2` as deny, and "your
        // checkout is misconfigured" must never say that.
        let dir = scratch("never-a-verdict");
        let report = diagnose(&dir);
        assert!(!report.ok);
        assert_ne!(report.code(), ExitCode::Violation);
        assert_eq!(report.code(), ExitCode::Usage);
    }

    #[test]
    fn every_check_is_reported_not_just_the_first_failure() {
        // A diagnostic that stops at the first problem reports one symptom when
        // the operator wants the list.
        let dir = scratch("all-checks");
        let report = diagnose(&dir);
        // Asserted on the named checks rather than a count, so adding a
        // diagnostic does not turn this into a bookkeeping edit — what matters
        // is that a later check still runs after an earlier one failed.
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert_eq!(failed, vec![CONFIG, GIT_REPO]);
    }

    #[test]
    fn a_reason_id_never_carries_a_path() {
        // Rule 4 and §6 together: a message would embed an absolute path, which
        // differs per machine and leaks disk layout into a log.
        let dir = scratch("no-paths");
        for check in diagnose(&dir).checks {
            let Some(reason) = check.reason else { continue };
            assert!(!reason.contains('/'), "{reason} looks like a path");
        }
    }

    // --- `doctor hooks` (CLOUD-777) ------------------------------------------
    //
    // Shown able to fail (CLOUD-418): a matcher, a second command on one event,
    // and a missing event each turn the check red with their OWN reason id. A
    // fixture wiring is written into a scratch directory and diagnosed there, so
    // each case states its whole world rather than depending on the checkout.

    /// Claude Code's eight events, each carrying the derived command once.
    fn complete_wiring() -> serde_json::Value {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let mut events = serde_json::Map::new();
        for spelling in claude_spellings() {
            events.insert(
                spelling,
                serde_json::json!([{ "hooks": [{ "type": "command", "command": command }] }]),
            );
        }
        serde_json::json!({ "hooks": events })
    }

    /// The events the derivation registers for Claude Code, in its order.
    fn claude_spellings() -> Vec<String> {
        let wiring = hook::Harness::ClaudeCode
            .wiring()
            .expect("claude-code declares a wiring surface");
        wiring
            .registrations(hook::Harness::ClaudeCode)
            .into_iter()
            .map(|(_, spelling)| spelling.to_owned())
            .collect()
    }

    /// Where a harness reads its wiring, taken from its own declaration.
    ///
    /// **Not typed here**, for two reasons that point the same way. A consumer's
    /// artifact name in `crates/batten` is what non-negotiable rule 1 forbids and
    /// `document_facts::no_artifact_name_reaches_the_core` computes — a hook
    /// config path is the HOST's vocabulary rather than a consumer's, which is
    /// why `hook.rs` carries it, but a copy over here would be a second place it
    /// lives. And a fixture that hardcoded the path would keep passing if
    /// `Harness::wiring` moved, testing a file the binary no longer reads.
    fn surface_of(harness: hook::Harness) -> &'static str {
        match harness
            .wiring()
            .expect("the harness declares a surface")
            .file
        {
            hook::WiringFile::Key { path, .. } | hook::WiringFile::Whole(path) => path,
        }
    }

    /// Write `wiring` where Claude Code's surface lives, and diagnose that row.
    fn claude_row(name: &str, wiring: &serde_json::Value) -> HarnessWiring {
        let dir = write_surface(
            name,
            hook::Harness::ClaudeCode,
            &serde_json::to_string_pretty(wiring).unwrap(),
        );
        diagnose_hooks(&dir)
            .harnesses
            .into_iter()
            .find(|harness| harness.harness == "claude-code")
            .expect("claude-code is diagnosed")
    }

    /// A scratch directory carrying `body` at `harness`'s declared surface.
    fn write_surface(name: &str, harness: hook::Harness, body: &str) -> std::path::PathBuf {
        let dir = scratch(name);
        let path = dir.join(surface_of(harness));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
        dir
    }

    fn reasons(row: &HarnessWiring) -> Vec<&'static str> {
        row.findings.iter().map(|finding| finding.reason).collect()
    }

    #[test]
    fn a_complete_wiring_is_the_baseline_every_mutation_departs_from() {
        // The baseline's completeness is the point: under CLOUD-777 a partial
        // wiring is not a smaller green, it is red — so a case that passed over
        // one would prove nothing about the mutations below.
        let row = claude_row("hooks-complete", &complete_wiring());
        assert!(row.ok, "{:?}", row.findings);
        assert_eq!(row.registrations, claude_spellings().len());
        assert_eq!(row.siblings, 0);
    }

    #[test]
    fn a_matcher_on_battens_own_entry_is_a_second_narrowing() {
        // Not "a matcher we disagree with" — any at all. The host's
        // absent-matcher default is every tool, which is what lets
        // `batten.toml`'s `mediated_call` rows be the only narrowing.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["matcher"] = serde_json::json!("Bash");
        let row = claude_row("hooks-matcher", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![MATCHER_NARROWS]);
        assert_eq!(row.findings[0].event, "PreToolUse");
    }

    #[test]
    fn a_second_command_on_one_event_is_a_second_authority() {
        let mut wiring = complete_wiring();
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        wiring["hooks"]["Stop"] = serde_json::json!([
            { "hooks": [{ "type": "command", "command": command }] },
            { "hooks": [{ "type": "command", "command": command }] },
        ]);
        let row = claude_row("hooks-twice", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_REGISTERED_N_TIMES]);
    }

    #[test]
    fn a_missing_event_is_refused_rather_than_read_as_a_smaller_green() {
        let mut wiring = complete_wiring();
        wiring["hooks"]
            .as_object_mut()
            .unwrap()
            .remove("UserPromptSubmit")
            .expect("the baseline carries the eighth event");
        let row = claude_row("hooks-missing", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_UNREGISTERED]);
        assert_eq!(row.findings[0].event, "UserPromptSubmit");
    }

    #[test]
    fn a_command_that_reaches_nothing_is_drift_rather_than_silence() {
        // THE FALSE GREEN THIS SELECTOR EXISTS FOR. Selecting batten's entries on
        // "does this reach the engine" would make a renamed command INVISIBLE
        // rather than wrong, and the row would report zero registrations and
        // pass. So the selector asks only whether a command mentions batten.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
            serde_json::json!(".claude/hooks/batten-hook-typo.sh");
        let row = claude_row("hooks-drift", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![COMMAND_DRIFT]);
    }

    #[test]
    fn an_entry_under_an_event_the_derivation_never_emits_can_never_fire() {
        let mut wiring = complete_wiring();
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        wiring["hooks"]["SomethingThisHostDoesNotEmit"] =
            serde_json::json!([{ "hooks": [{ "type": "command", "command": command }] }]);
        let row = claude_row("hooks-underived", &wiring);
        assert!(!row.ok);
        assert_eq!(reasons(&row), vec![EVENT_UNDERIVED]);
    }

    #[test]
    fn a_sibling_is_counted_and_never_named_and_never_a_failure() {
        // Rule 4 — a sibling is a command line, which carries a path. And whether
        // a hook beside batten's is legitimate is a CONSUMER's judgement:
        // `hooks-wiring-check`'s `DECLARED` table is where this repository
        // refuses them, which is a fact about this repository (non-negotiable
        // rule 1).
        let mut wiring = complete_wiring();
        wiring["hooks"]["Stop"] = serde_json::json!([
            { "hooks": [{ "type": "command", "command": hook::wiring_command(hook::Harness::ClaudeCode) }] },
            { "hooks": [{ "type": "command", "command": "/home/someone/mise-tasks/stop-guard.sh" }] },
        ]);
        let row = claude_row("hooks-sibling", &wiring);
        assert!(
            row.ok,
            "a sibling is reported, not refused: {:?}",
            row.findings
        );
        assert_eq!(row.siblings, 1);
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(
            !rendered.contains("stop-guard") && !rendered.contains("/home/someone"),
            "a sibling is a count, never a name: {rendered}"
        );
    }

    #[test]
    fn an_absent_wiring_file_is_a_finding_never_a_pass() {
        // "Nothing to compare" read as "nothing wrong" is the shape this gate
        // keeps re-meeting. A harness that declares a surface and has no file on
        // it is unwired.
        let dir = scratch("hooks-absent");
        let report = diagnose_hooks(&dir);
        assert!(!report.ok);
        for harness in &report.harnesses {
            assert_eq!(reasons(harness), vec![FILE_MISSING], "{}", harness.harness);
        }
    }

    #[test]
    fn an_unparseable_wiring_file_is_named_distinctly_from_an_absent_one() {
        // Two different remedies — write one, or fix one.
        let dir = write_surface(
            "hooks-unparseable",
            hook::Harness::ClaudeCode,
            "not json at all\n",
        );
        let row = diagnose_hooks(&dir)
            .harnesses
            .into_iter()
            .find(|harness| harness.harness == "claude-code")
            .unwrap();
        assert_eq!(reasons(&row), vec![FILE_UNREADABLE]);
    }

    #[test]
    fn every_harness_the_core_knows_is_diagnosed_or_declares_no_surface() {
        // Ranged over `Harness::ALL`, so a seventh adapter is diagnosed the day
        // it lands rather than silently omitted — the question a hand-kept table
        // answers "no" to. `exit-code` is the one exemption and it is structural:
        // it declares no wiring surface at all.
        let report = diagnose_hooks(&scratch("hooks-census"));
        let diagnosed: Vec<&str> = report.harnesses.iter().map(|row| row.harness).collect();
        for harness in hook::Harness::ALL {
            let expected = harness.wiring().is_some();
            assert_eq!(
                diagnosed.contains(&harness.as_str()),
                expected,
                "{} declares a wiring surface: {expected}",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_failing_wiring_diagnosis_is_never_a_policy_verdict() {
        // The case that pins §5, and the sub-verb inherits the parent's promise:
        // a harness reads `2` as a deny, and "your wiring is wrong" must never
        // say that.
        let report = diagnose_hooks(&scratch("hooks-never-a-verdict"));
        assert!(!report.ok);
        assert_ne!(report.code(), ExitCode::Violation);
        assert_eq!(report.code(), ExitCode::Usage);
    }

    #[test]
    fn a_wiring_reason_id_never_carries_a_path() {
        // The sibling of `a_reason_id_never_carries_a_path`, over the type that
        // makes CLOUD-525's `$HOME` surface reportable without leaking one.
        let mut wiring = complete_wiring();
        wiring["hooks"]["PreToolUse"][0]["matcher"] = serde_json::json!("Bash");
        wiring["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
            serde_json::json!("/home/someone/.claude/hooks/batten-hook.sh");
        let mut rows = vec![claude_row("hooks-no-paths", &wiring)];
        rows.extend(diagnose_hooks(&scratch("hooks-no-paths-absent")).harnesses);
        for row in rows {
            for finding in &row.findings {
                assert!(
                    !finding.reason.contains('/'),
                    "{} looks like a path",
                    finding.reason
                );
                assert!(
                    !finding.event.contains('/'),
                    "{} looks like a path",
                    finding.event
                );
            }
        }
    }

    #[test]
    fn the_bare_diagnosis_is_unchanged_by_the_sub_verb() {
        // House style §8 promises what bare `batten doctor` does, so adding a
        // sub-verb must not move it. Asserted on the named checks rather than a
        // count, matching `every_check_is_reported_not_just_the_first_failure`.
        let names: Vec<&str> = diagnose(&scratch("bare-unchanged"))
            .checks
            .iter()
            .map(|check| check.name)
            .collect();
        assert_eq!(names, vec![CONFIG, GIT_REPO, COMMAND_PROGRAMS]);
    }

    #[test]
    fn a_check_line_is_pointer_shaped() {
        assert_eq!(Check::passed("config").line(), "config ok");
        assert_eq!(
            Check::failed("config", "config-missing").line(),
            "config failed config-missing"
        );
    }
}
