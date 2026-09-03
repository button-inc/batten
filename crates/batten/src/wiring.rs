//! `batten wiring` — the one write path over a host's hook registrations.
//!
//! [`crate::doctor`] answers *is there a hook here that is not mine*. This module
//! is the half that can do something about it, and it is a separate module for
//! the reason `doctor`'s own header gives: that verb promises never to return a
//! policy verdict and never to act, and a destructive write inside it would make
//! both promises conditional on which subcommand you typed.
//!
//! # Record, then repair — and never the other way round
//!
//! A harness reads its hook wiring once, when a session starts. So a repair
//! performed mid-session changes what is on DISK and cannot change what the
//! running host has already loaded, and a census taken after the repair reports
//! `merged_siblings: 0` over a runtime still dispatching the siblings it just
//! deleted. That is a manufactured false green, and strictly worse than the
//! expiring waiver table this capability replaced: a waiver at least says which
//! reductions it excuses.
//!
//! So [`reclaim`] writes the AT-LOAD record before it edits a byte, and the
//! consumer's gate reads that record rather than the disk. Two numbers
//! disagreeing is the honest answer — *this session is running wiring that no
//! longer exists; restart to pick up the repair* — and one number agreeing at
//! zero is the honest green.
//!
//! # Why the record is not session-keyed, and what clears it
//!
//! There is no portable session identity to key on, and a timestamp would only
//! move the question. What there IS, exactly once per session, is the moment the
//! host re-reads its wiring: [`crate::hook::Event::SessionStart`]. At that
//! instant live and at-load are the same by definition, so the record is
//! **cleared** there ([`clear_at_load`]) and written only by [`reclaim`].
//!
//! **Which is why reclaim is not run from a session-start handler.** The plan
//! this implements wanted the merged arm repaired automatically on
//! `SessionStart`. It cannot be: the clear and the record would then both happen
//! inside one unordered batch of handlers, and whichever landed second would
//! decide — a coin toss between the honest red and exactly the false green the
//! record exists to prevent. An unorderable pair is not a race to tune, so the
//! verb stays explicitly invoked and the clear keeps its one writer.
//!
//! # Scope: the merged surfaces, never the committed one
//!
//! [`reclaim`] edits only files under the caller's home directory. A committed
//! surface is version-controlled, reviewed, and the subject of `doctor hooks`'s
//! own findings; rewriting it from here would fight `tree-clean` on every run.
//! The `same_file` arm is what enforces that, and it is a correctness property
//! rather than an optimisation: several hosts spell their user-level surface and
//! their project-level one identically, so a checkout sitting AT the home
//! directory resolves both to one file.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::{git, hook};

/// The event map inside a wiring file.
///
/// One expression for both shapes of [`hook::WiringFile`], read from the
/// harness's own declaration rather than from a `(.hooks // .)` guess. The bash
/// gate carried that guess as a second copy of the Key/Whole split; deleting the
/// copy is the point of moving this in-process, not a side effect.
///
/// Lives here rather than in [`crate::doctor`] so that the reader and the writer
/// cannot disagree about what a registration IS. `merged_under`'s own comment
/// asks for exactly that — "a sibling count that disagreed with the committed one
/// about what a sibling is could not be summed with it" — and a second copy in
/// the write path would be the same defect one layer over.
pub(crate) fn committed_events(
    document: &serde_json::Value,
    file: hook::WiringFile,
) -> Option<Cow<'_, serde_json::Map<String, serde_json::Value>>> {
    let key = event_key(file);
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

/// Which key a wiring file's events live under.
///
/// Extracted so the mutable walk in [`prune_siblings`] and the immutable read in
/// [`committed_events`] cannot pick different keys — the one way those two could
/// silently stop describing the same document.
const fn event_key(file: hook::WiringFile) -> &'static str {
    match file {
        hook::WiringFile::Key { key, .. } => key,
        // A hooks-only file is what `render_wiring` emits whole, and what it
        // emits is `{"hooks": {…}}`.
        hook::WiringFile::Whole(_) => "hooks",
    }
}

/// Every `{matcher, command}` pair registered under one event.
pub(crate) fn entries_under(value: &serde_json::Value) -> Vec<(Option<&str>, &str)> {
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
pub(crate) fn same_file(one: &Path, two: &Path) -> bool {
    match (one.canonicalize(), two.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Whether one registered command is batten's own.
///
/// **The same selector both sides of the census use**, and deliberately broader
/// than "does this reach the engine": asking the narrow question would make a
/// renamed command *invisible* rather than *wrong*, so a mis-registered batten
/// would be reclaimed as somebody else's hook. Selected broadly, judged
/// narrowly, which is `diagnose_harness`'s rule and has to be this path's too.
fn is_batten(entry: &str, command: &str) -> bool {
    entry.contains(command) || entry.contains("batten")
}

/// One `(harness, event)` pair and how many non-batten registrations it carried.
///
/// **Pointer-only, and the omission is the point** (non-negotiable rule 4): no
/// path, no `$HOME`, and not even the offending command's basename. A basename is
/// a filename off somebody's disk, and the gate that consumes this needs only to
/// know that the count was non-zero — so carrying one would buy a nicer message
/// with a leak. Which command it was is answerable from the file the harness and
/// event name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct AtLoadRow {
    /// The harness whose merged surface carried them.
    pub harness: String,
    /// The event they were registered on, in the host's own spelling.
    pub event: String,
    /// How many of them were not batten's.
    pub siblings: usize,
}

/// What this session's harnesses had loaded before any repair.
///
/// Byte-stable under `-J` for §6's reason: the rows come back in
/// [`hook::Harness::ALL`] order and, within a harness, in the order the host's
/// own document lists its events, so two runs over one disk state serialise
/// identically.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct AtLoad {
    /// One row per `(harness, event)` that carried a non-batten registration.
    pub rows: Vec<AtLoadRow>,
}

impl AtLoad {
    /// Every non-batten registration the record accounts for.
    #[must_use]
    pub fn siblings(&self) -> usize {
        self.rows.iter().map(|row| row.siblings).sum()
    }
}

/// Where the at-load record lives.
///
/// Under `$GIT_DIR`, beside `batten-receipts`, for the three reasons that store
/// picked it: never committed, per-worktree rather than per-checkout, and gone
/// when the container is reclaimed — which is correct here, because a record of
/// what a dead session had loaded is worth nothing to a live one.
fn record_path(git_dir: &Path) -> PathBuf {
    git_dir.join("batten-wiring").join("at-load.json")
}

/// Read the at-load record, or `None` when no repair has been recorded.
///
/// **A record that will not parse reads as absent**, not as an error. The
/// consumer's gate falls back to the live disk when there is no record, and a
/// live read is a strictly better answer than a refusal it cannot act on — the
/// same fail-open direction `diagnose_hooks` takes on an unreadable config.
///
/// # Errors
///
/// Returns an error only when `dir` is not a git repository, since then there is
/// no store to have looked in.
pub fn read_at_load(dir: &Path) -> Result<Option<AtLoad>> {
    let path = record_path(&git::git_dir(dir)?);
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Ok(None);
    };
    Ok(serde_json::from_str(&raw).ok())
}

/// Drop the at-load record, and say whether there was one.
///
/// Called from the `SessionStart` path of [`crate::run_hook`], which is the one
/// moment a host's loaded wiring and its on-disk wiring are the same by
/// definition. Failure to remove is swallowed by the caller rather than reported:
/// a session-start handler that refused a session over a stale bookkeeping file
/// would be a gate on the wrong object.
///
/// # Errors
///
/// Returns an error when `dir` is not a git repository, or when a record exists
/// and cannot be removed.
pub fn clear_at_load(dir: &Path) -> Result<bool> {
    let path = record_path(&git::git_dir(dir)?);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path)?;
    Ok(true)
}

/// What one [`reclaim`] did, or would do.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct Reclaimed {
    /// The non-batten registrations found, per `(harness, event)`.
    pub rows: Vec<AtLoadRow>,
    /// How many merged surfaces were read and judged.
    pub surfaces_read: usize,
    /// How many were rewritten. Zero under a dry run, and zero when nothing was
    /// found — which the row list is what distinguishes.
    pub surfaces_written: usize,
    /// Whether the at-load record was written by this call. `false` when one
    /// already existed, because the FIRST record is the one that describes what
    /// the running session loaded and a second would describe the repair.
    pub recorded: bool,
    /// Whether this environment declared itself disposable, so the repair was
    /// allowed to write (CLOUD-1383).
    ///
    /// Carried on the result rather than inferred from `surfaces_written == 0`,
    /// because those are different answers with different remedies: a
    /// conservative run that found nothing and a conservative run that found two
    /// siblings it may not touch both write nothing, and only the second has
    /// something for a reader to do.
    pub authoritative: bool,
}

impl Reclaimed {
    /// Every non-batten registration this call found.
    #[must_use]
    pub fn siblings(&self) -> usize {
        self.rows.iter().map(|row| row.siblings).sum()
    }
}

/// Remove every non-batten hook registration from this host's merged surfaces.
///
/// The inverse of `doctor`'s merged census, over the same surfaces and with the
/// same selector. Ranged over [`hook::Harness::ALL`] rather than a table, so a
/// seventh adapter is reclaimed the day it lands instead of silently skipped.
///
/// **The at-load record is written before the first byte changes**, and only when
/// none exists. The assertion is `tests/wiring-reclaim.bats`'s `RECORD BEFORE
/// REPAIR: the record carries the pre-repair count`, plus `the record is written
/// ONCE, so a second run cannot report the repair` for the only-when-none-exists
/// half — over the compiled binary and a real `$HOME` on disk, which is the tier
/// that can see this at all. A unit case here would build the document the engine
/// may be unable to locate, which is the shape `.claude/rules/policy-modules.md`
/// names. An earlier draft of this comment cited a Rust test name that was never
/// written; caught in review of #714.
///
/// # Errors
///
/// Returns an error when `dir` is not a git repository, when the record cannot be
/// written, or when a surface that parsed cannot be written back. A surface that
/// could not be READ is not an error — it is a could-not-look, counted out of
/// `surfaces_read` and left alone, because a file this verb cannot parse is one
/// it must not rewrite.
pub fn reclaim(dir: &Path, home: &Path, dry_run: bool) -> Result<Reclaimed> {
    // WHOSE `$HOME` IS THIS (CLOUD-1383). The census below is right about WHAT is
    // a sibling on either kind of machine; what it cannot know is whether removing
    // one is welcome. In a disposable container `$HOME` is provisioned fresh and
    // taking it is the point; on a developer's real machine a registration
    // somebody else put there is theirs, and deleting it is a hostile act by a
    // tool they installed to check their commits.
    //
    // Without this fact the repository had to negotiate the difference in
    // committed config — an exemption table naming each tolerated registration
    // and the row that owns removing it — which is a second authority over the
    // same subject and drifted from this verb within a day. The fact costs one
    // environment variable and deletes the whole negotiation.
    //
    // THE POSTURE RIDES `dry_run` RATHER THAN ADDING A SECOND SWITCH, which keeps
    // the promise the row makes: the two arms agree about what is in scope and
    // differ only in whether it is acted on. A conservative run still reads every
    // surface, still counts every sibling, and still reports them — it simply
    // does not write, which is what `--check` already means here.
    let mut out = Reclaimed {
        authoritative: crate::environment::disposable(),
        ..Reclaimed::default()
    };
    let dry_run = dry_run || !out.authoritative;
    // Planned in full before anything is written, so the record describes the
    // whole pre-repair state even if a later surface refuses the write.
    let mut planned: Vec<(PathBuf, serde_json::Value)> = Vec::new();
    for harness in hook::Harness::ALL {
        let command = hook::wiring_command(*harness);
        let key = harness
            .wiring()
            .map_or(hook::WiringFile::Whole(""), |w| w.file);
        for surface in harness.merge_surfaces() {
            let path = home.join(surface);
            // The committed surface is not this verb's subject; see the module
            // header. Not counted as read either — it was never a merged one.
            if same_file(&path, &dir.join(surface)) {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(mut document) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            if committed_events(&document, key).is_none() {
                continue;
            }
            out.surfaces_read += 1;
            let removed = prune_siblings(&mut document, key, &command);
            if removed.is_empty() {
                continue;
            }
            for (event, siblings) in removed {
                out.rows.push(AtLoadRow {
                    harness: harness.as_str().to_owned(),
                    event,
                    siblings,
                });
            }
            planned.push((path, document));
        }
    }
    if dry_run {
        return Ok(out);
    }
    out.recorded = write_at_load(dir, &out.rows)?;
    for (path, document) in planned {
        // Pretty rather than compact, and a free choice here where it would not
        // be on a committed file: these surfaces are untracked, launcher-owned
        // and rewritten wholesale at provisioning, so there are no bytes of
        // somebody's formatting to conserve and no golden to churn.
        //
        // WRITE-THEN-RENAME RATHER THAN A TRUNCATING WRITE, because of WHOSE bytes
        // these are. `std::fs::write` truncates before it writes, so a kill in
        // between leaves the host a half-file — and this document carries keys this
        // verb never read and does not understand: everything a consumer put in its
        // host settings beside the hook map. Losing them
        // would be this repair destroying configuration outside its own subject,
        // which is the one thing worse than leaving a sibling registered. The
        // temporary sits in the SAME directory so the rename stays within one
        // filesystem and is therefore atomic.
        let staged = path.with_extension("json.batten-tmp");
        std::fs::write(
            &staged,
            format!("{}\n", serde_json::to_string_pretty(&document)?),
        )?;
        std::fs::rename(&staged, &path)?;
        out.surfaces_written += 1;
    }
    Ok(out)
}

/// Write the at-load record unless one is already there.
///
/// Returns whether this call wrote it. **Never overwrites**: the first record is
/// the one that describes the wiring the running session loaded, and a second
/// would describe the state after a repair — which is the false green this whole
/// ordering exists to refuse.
fn write_at_load(dir: &Path, rows: &[AtLoadRow]) -> Result<bool> {
    let path = record_path(&git::git_dir(dir)?);
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let record = AtLoad {
        rows: rows.to_vec(),
    };
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&record)?),
    )?;
    Ok(true)
}

/// Strip every non-batten registration out of one wiring document.
///
/// Returns `(event, count)` for each event that lost one, in document order.
///
/// **Empty containers are removed, not left behind.** A `hooks` array emptied of
/// its last entry, or an event whose array is now empty, is wiring that declares
/// nothing — and a host that iterates it would be handed a shape its own
/// generator never emits. Leaving the husk would also make the census read
/// `read: 1, commands: 0`, which is a real disposition and would now be a lie
/// about how the file got there.
fn prune_siblings(
    document: &mut serde_json::Value,
    file: hook::WiringFile,
    command: &str,
) -> Vec<(String, usize)> {
    let key = event_key(file);
    let Some(events) = document
        .get_mut(key)
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    let mut dead_events = Vec::new();
    for (event, value) in events.iter_mut() {
        let Some(entries) = value.as_array_mut() else {
            continue;
        };
        let mut count = 0;
        for entry in entries.iter_mut() {
            let Some(hooks) = entry
                .get_mut("hooks")
                .and_then(serde_json::Value::as_array_mut)
            else {
                continue;
            };
            hooks.retain(|hook| {
                let Some(cmd) = hook.get("command").and_then(serde_json::Value::as_str) else {
                    // A hook object with no command string registers nothing this
                    // path can judge, so it is left exactly where it is. Removing
                    // it would be this verb deciding about a shape it does not
                    // own.
                    return true;
                };
                let keep = is_batten(cmd, command);
                if !keep {
                    count += 1;
                }
                keep
            });
        }
        if count == 0 {
            continue;
        }
        entries.retain(|entry| {
            entry
                .get("hooks")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|hooks| !hooks.is_empty())
        });
        removed.push((event.clone(), count));
        if entries.is_empty() {
            dead_events.push(event.clone());
        }
    }
    for event in dead_events {
        events.remove(&event);
    }
    removed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a claude-code merged surface carrying `commands` on one event.
    fn surface(commands: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "hooks": {
                "SessionStart": [{
                    "hooks": commands
                        .iter()
                        .map(|command| serde_json::json!({"type": "command", "command": command}))
                        .collect::<Vec<_>>()
                }]
            }
        })
    }

    /// One host's wiring shape, DERIVED from the harness table and never typed.
    ///
    /// Spelling the host's settings path here would be a consumer's artifact name
    /// inside `crates/batten` — non-negotiable rule 1, and
    /// `document_facts::no_artifact_name_reaches_the_core` caught exactly that in
    /// this module's first draft. It is the rule `doctor.rs` already states for
    /// itself: derive the path from the harness table, never type it.
    ///
    /// This comment does not spell the literal either, and that is not fastidious:
    /// the gate is a substring scan over the file, so an explanation naming what
    /// it forbids fires on itself. `.claude/rules/scanning.md` records the same
    /// shape one layer up, and the second draft of this comment is what proved it.
    fn claude() -> hook::WiringFile {
        hook::Harness::ClaudeCode
            .wiring()
            .expect("claude-code declares a wiring surface")
            .file
    }

    /// The load-bearing negative: a broad selector, so a MIS-registered batten is
    /// wrong rather than reclaimed.
    ///
    /// Fails by: narrowing [`is_batten`] to the exact wiring command.
    #[test]
    fn a_renamed_batten_registration_is_not_somebody_elses_hook() {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        // Reaches no engine — the `--harness` flag is gone — so `doctor` reports
        // it as wrong. It must still not be deleted here.
        let mut document = surface(&["/usr/local/bin/batten hook"]);
        assert!(prune_siblings(&mut document, claude(), &command).is_empty());
    }

    /// A sibling goes, and the event it emptied goes with it.
    ///
    /// Fails by: dropping the `dead_events` sweep, which leaves `SessionStart: []`
    /// — a shape no generator emits and one the census cannot tell from a file
    /// that always had none.
    #[test]
    fn an_emptied_event_is_removed_rather_than_left_as_a_husk() {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let mut document = surface(&["session-start-git-identity.sh"]);
        assert_eq!(
            prune_siblings(&mut document, claude(), &command),
            vec![("SessionStart".to_owned(), 1)]
        );
        assert_eq!(document, serde_json::json!({"hooks": {}}));
    }

    /// Batten's own registration survives beside a reclaimed sibling, and the
    /// entry that held both survives with it.
    ///
    /// Fails by: retaining on the entry instead of on its `hooks` array, which
    /// takes batten's registration out with the sibling sharing its matcher.
    #[test]
    fn a_sibling_sharing_an_entry_with_batten_takes_only_itself() {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let mut document = surface(&[&command, "stop-hook-git-check.sh"]);
        assert_eq!(
            prune_siblings(&mut document, claude(), &command),
            vec![("SessionStart".to_owned(), 1)]
        );
        assert_eq!(document, surface(&[&command]));
    }

    /// A hook object with no `command` is left alone rather than swept up.
    ///
    /// Fails by: treating a missing command as a non-batten registration, which
    /// makes this verb delete a shape it does not own.
    #[test]
    fn a_registration_with_no_command_is_not_this_verbs_business() {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let mut document = serde_json::json!({
            "hooks": {"Stop": [{"hooks": [{"type": "command"}]}]}
        });
        let before = document.clone();
        assert!(prune_siblings(&mut document, claude(), &command).is_empty());
        assert_eq!(document, before);
    }

    /// The record and the census agree on what a sibling is, by construction.
    ///
    /// Fails by: giving either side its own selector — the copy `is_batten`
    /// exists to make unwritable.
    #[test]
    fn the_reader_and_the_writer_share_one_selector() {
        let command = hook::wiring_command(hook::Harness::ClaudeCode);
        let document = surface(&[&command, "session-start-git-identity.sh"]);
        let events = committed_events(&document, claude()).expect("a wiring file");
        let counted = events
            .values()
            .flat_map(entries_under)
            .filter(|(_, entry)| !is_batten(entry, &command))
            .count();
        let mut pruned = document;
        let removed: usize = prune_siblings(&mut pruned, claude(), &command)
            .iter()
            .map(|(_, count)| count)
            .sum();
        assert_eq!(counted, removed);
    }

    /// An empty record sums to nothing, so the gate's fallback is unambiguous.
    #[test]
    fn a_record_with_no_rows_carries_no_siblings() {
        assert_eq!(AtLoad::default().siblings(), 0);
    }
}
