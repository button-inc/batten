//! The contract-drift predicate: what moved under a running session, reported
//! once (CLOUD-461, CLOUD-525).
//!
//! Hooks and instruction files are **session-start snapshots** (CLOUD-187), so a
//! contract that lands mid-session binds nothing until it is re-read. This is the
//! feedforward half: it hashes the declared contract surface, compares against
//! what this session was last told, and names the files that moved.
//!
//! # Why this is not a gate
//!
//! It reports and never refuses. `PreToolUse`'s only model-facing channel is
//! exit 2, which **blocks** the call, and CLOUD-97 and CLOUD-219 each ruled a
//! deny out independently — a drift notice is not a refusal. So this rides the
//! advisory channel [`crate::hook::encode_advice`] opened, at a batch boundary,
//! where no host offers a deny channel at all. Nothing here returns a
//! [`crate::hook::Decision`] and nothing here reaches
//! [`crate::hook::adjudicate`], which stays a pure function of config plus argv.
//!
//! # Why it is not a [`crate::facts::Fact`]
//!
//! Stated because the absence looks like an omission. A fact is what
//! `adjudicate` consumes — [`crate::facts::Fact::ALL`] drives the exhaustive
//! projection into the policy input, so classifying this one would oblige a
//! projection no rule could read. The change-set is boundary state feeding a
//! boundary emission, resolved and spent in the same place. It obeys the fact
//! model's *disciplines* — three-valued through [`crate::facts::Look`],
//! pointer-only, resolved at the boundary and passed by value — without claiming
//! a row in a table about something else.
//!
//! # Silence is the default, and the snapshot IS the rate limit
//!
//! A change-set is reported **once**: writing the snapshot is what makes the
//! next comparison quiet, so a surface that stops moving goes quiet by itself
//! with no second state file to keep in step. A suite proving only that it
//! *fires* would pass on a hook that nags every batch, which is how an advisory
//! channel becomes noise and stops being read — so the once-per-change-set bound
//! is the load-bearing case rather than a nicety.
//!
//! # Pointer-only, and here it is the whole predicate
//!
//! The report carries paths and counts, never a byte of a file (non-negotiable
//! rule 4). That is not only §6 style: a reminder carrying the new text is a
//! **mirror**, and a mirror is cleared by reading the hook instead of the file —
//! which is the one outcome this exists to prevent.
//!
//! # The surface is config, because it has to be
//!
//! Which files carry a repository's contract is that repository's business — an
//! agent guide, a rules directory, a hook config, a task tree — so the paths live
//! in `batten.toml`'s `[contract]` table and a grep of `crates/batten` for any
//! consumer's identifiers returns nothing (non-negotiable rule 1).
//!
//! **It is not `[epoch] tracked`, and the reason is a finding rather than a
//! preference.** CLOUD-461 names that table as the source of truth, and the
//! shell task it ports hashes a strictly wider set — a rules *directory* and a
//! task *tree*. Those cannot be expressed there:
//! [`crate::epoch::tracked_paths`] resolves literal repo-relative paths and
//! [`crate::epoch::describe`] reads each as one file, by construction. That
//! construction is right for an epoch — a config epoch must be a function of a
//! **stated** set, or the value moves because of what happens to exist beside it
//! — and exactly wrong here, where a newly added task IS the drift. Reusing the
//! table would have silently narrowed the surface to six files and dropped the
//! two directories that carry the agent contract.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::facts::Look;
use crate::identity::surface_fingerprint;
use crate::rules::{glob_match, tree_files};

/// The directory, under the git dir, holding one snapshot per session.
///
/// Beside `batten-receipts/` and for the same reason: out of the tree, per
/// clone, and keyed through the **worktree's own** git dir rather than the
/// common one — a linked worktree checks out a different contract and must not
/// be told about a sibling's.
const SNAPSHOT_DIR: &str = "batten-contract";

/// The key a payload with no session lands under.
///
/// A session id is what makes the snapshot per-session, and a host that reports
/// none still deserves the notice — one shared key degrades to "this clone" and
/// keeps the predicate working rather than switching it off.
const SHARED_KEY: &str = "shared";

/// What moved under this session, as pointers.
///
/// **There is no field a file's content could occupy**, which is what makes rule
/// 4 structural here rather than a property of the renderer — the same shape
/// [`crate::rules::Finding`] has for matched bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet {
    /// Repo-relative paths whose bytes moved, and which the session read an
    /// older version of at start.
    pub changed: Vec<String>,
    /// Repo-relative paths the session's snapshot did not contain at all
    /// (CLOUD-490).
    ///
    /// **Partitioned out of `changed` rather than computed separately**: git
    /// already labels an added path, so this is the same comparison read one key
    /// further. The split exists because the two need DIFFERENT sentences, and
    /// the wrong one measurably cost a capability.
    ///
    /// A reader filtering a 45-entry list by "what do I need for my next step"
    /// is doing the only reasonable thing, and that filter works for a changed
    /// rule — a changed rule alters something the session already does, so its
    /// name is already in the session's working set. It CANNOT work for a new
    /// capability: the session does not know the path exists, so it has no basis
    /// on which to judge it relevant. The one class the filter is guaranteed to
    /// drop is the class that is pure gain to adopt.
    ///
    /// Measured 2026-08-12: a session resumed to 45 changed files with
    /// `mise-tasks/alive` among them, re-read the two it judged relevant, and
    /// spent the rest of the session hand-rolling `pgrep`/`sleep` pollers —
    /// nine live at once — for the question `mise run alive` answers in one line.
    pub added: Vec<String>,
    /// Repo-relative paths that were in the surface and are no longer.
    pub removed: Vec<String>,
}

impl ChangeSet {
    /// Whether anything moved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }

    /// How many paths moved, however they moved.
    ///
    /// The count the notice's first line carries. Named rather than summed at
    /// the call site so the two partitions cannot drift apart from the total a
    /// reader is shown.
    #[must_use]
    pub fn touched(&self) -> usize {
        self.changed.len() + self.added.len()
    }
}

/// One session's view of the contract surface: path → content fingerprint.
///
/// A `BTreeMap`, so the serialized form is sorted and a snapshot is a function
/// of the set rather than of walk order (§6).
pub type Manifest = BTreeMap<String, String>;

/// Hash the declared contract surface under `root`.
///
/// [`Look::CouldNotLook`] when the surface is undeclared — an absent `[contract]`
/// table means this repository does not use the predicate, which is a different
/// claim from "nothing moved" and must never be reported as one.
///
/// A glob matching nothing is **not** an error here, deliberately, and that is
/// the one place this departs from [`crate::budget::measure`]'s discipline. A
/// budget's dead entry is a defect because it silently lowers a ceiling; a
/// contract surface legitimately names a directory that a consumer has not
/// created yet, and failing the hook over it would turn a reporting path into a
/// refusing one.
///
/// # Errors
///
/// Propagates an I/O failure from the tree walk or a file read.
pub fn surface(root: &Path, tracked: &[String]) -> Result<Look<Manifest>> {
    if tracked.is_empty() {
        return Ok(Look::CouldNotLook);
    }
    let tree = tree_files(root)?;
    let mut manifest = Manifest::new();
    for entry in tracked {
        for path in tree.iter().filter(|path| glob_match(entry, path)) {
            if manifest.contains_key(path) {
                continue;
            }
            let contents = std::fs::read(root.join(path))?;
            // The whole-set fingerprint over ONE entry: the path is hashed
            // alongside the bytes, and the same normalization every other
            // identity in the engine uses, so a CRLF checkout does not report
            // the entire surface as drift on its first batch.
            let hash = surface_fingerprint(&[(path.clone(), contents)]).to_hex();
            manifest.insert(path.clone(), hash);
        }
    }
    Ok(Look::Is(manifest))
}

/// What moved between the snapshot this session was last shown and `current`.
///
/// Pure: two maps in, pointers out. The clock, the disk and the session key are
/// all the caller's, which is what keeps this testable without a fixture.
#[must_use]
pub fn compare(previous: &Manifest, current: &Manifest) -> ChangeSet {
    // ONE PASS, TWO BUCKETS. A path the snapshot never held is ADDED; one it
    // held under a different hash is CHANGED. Deciding it here rather than at
    // render time is what keeps the notice's counts and its sections reading off
    // the same comparison.
    let (added, changed) = current
        .iter()
        .filter(|(path, hash)| previous.get(*path) != Some(*hash))
        .map(|(path, _)| path.clone())
        .partition(|path| !previous.contains_key(path));
    let removed = previous
        .keys()
        .filter(|path| !current.contains_key(*path))
        .cloned()
        .collect();
    ChangeSet {
        changed,
        added,
        removed,
    }
}

/// The snapshot file for `session` under `git_dir`.
///
/// A present session is DIGESTED rather than sanitized, so the key is one path
/// component and is injective. Substituting a separator for every awkward
/// character escapes the store correctly — `../../etc/passwd` becomes a
/// filename — and collides: `a/b` and `a?b` both flatten to `a-b`, and any id
/// spelling the absent-session key would land on it. Two sessions sharing one
/// snapshot suppress or misdirect each other's notices, which is the failure the
/// per-session key exists to prevent, arriving through the sanitizer.
///
/// [`SHARED_KEY`] is therefore reserved for the ABSENT session and unreachable
/// from a present one: a hex digest carries no `s`.
fn snapshot_path(git_dir: &Path, session: Option<&str>) -> PathBuf {
    use sha2::{Digest as _, Sha256};

    let key = match session.filter(|id| !id.is_empty()) {
        Some(id) => {
            let digest = Sha256::digest(id.as_bytes());
            digest.iter().fold(String::new(), |mut hex, byte| {
                use std::fmt::Write as _;
                // `write!` into one buffer rather than a `format!` per byte: the
                // digest is fixed-width, so this is one allocation instead of 32.
                let _ = write!(hex, "{byte:02x}");
                hex
            })
        }
        None => SHARED_KEY.to_owned(),
    };
    git_dir.join(SNAPSHOT_DIR).join(key)
}

/// Read what this session was last shown.
///
/// [`Look::CouldNotLook`] when there is no snapshot — the first batch of a
/// session, which is **seeded silently**: a session that started after a change
/// has already read the new files and must not be nudged about them.
#[must_use]
pub fn previous(git_dir: &Path, session: Option<&str>) -> Look<Manifest> {
    let Ok(text) = std::fs::read_to_string(snapshot_path(git_dir, session)) else {
        return Look::CouldNotLook;
    };
    let mut manifest = Manifest::new();
    for line in text.lines() {
        if let Some((hash, path)) = line.split_once(' ') {
            manifest.insert(path.to_owned(), hash.to_owned());
        }
    }
    Look::Is(manifest)
}

/// Record `manifest` as what this session has now been shown.
///
/// **This write IS the rate limit.** Reporting overwrites the snapshot, so the
/// next comparison is quiet until the surface moves again, and there is no
/// second piece of state that could disagree about whether a notice was already
/// spent.
///
/// # Errors
///
/// Propagates an I/O failure creating the directory or writing the file.
pub fn record(git_dir: &Path, session: Option<&str>, manifest: &Manifest) -> Result<()> {
    let path = snapshot_path(git_dir, session);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = String::new();
    for (tracked, hash) in manifest {
        body.push_str(hash);
        body.push(' ');
        body.push_str(tracked);
        body.push('\n');
    }
    std::fs::write(path, body)?;
    Ok(())
}

/// The advisory text for `change`, pointer-only.
///
/// # The sentence that is NOT here (CLOUD-525)
///
/// The shell task this ports ended with an instruction to *"check whether a hook
/// it adds is in this session's wiring"*. **Nothing can perform that check.**
/// Every reader of the wiring reads the working tree, which answers "what does
/// the file declare" — the question the notice just answered — where the
/// sentence asks "what did this process load at start", and no task, no verb and
/// no harness surface answers it (CLOUD-187's boundary, untouched). An agent
/// following it could only guess, and would guess "not loaded", which is the
/// wrong default whenever the hook did load.
///
/// What replaces it is the computable fact the predicate already has: **the hook
/// wiring is among what moved**. That is derivable from the change-set rather
/// than a claim about session state, and `batten doctor hooks` is the mechanism
/// that reads the wiring itself — named, so the notice points at something that
/// exists.
#[must_use]
pub fn render(change: &ChangeSet, wiring: &[String]) -> String {
    let mut out = format!(
        "contract-drift {} changed, {} removed\n",
        change.touched(),
        change.removed.len()
    );
    // ADDED FIRST, and its own sentence rides with it (CLOUD-490). A new path is
    // an OFFER rather than an obligation, and it is the one class a relevance
    // filter cannot keep: nothing in the session's working set names it. Saying
    // that where the paths are is what stops it being filtered out with the rest.
    //
    // This SHORTENS what a reader must act on rather than lengthening it — the
    // added set is almost always the smaller one, and it is the half worth
    // reading first.
    if !change.added.is_empty() {
        out.push_str("\nadded — you could not have been doing these:\n");
        for path in &change.added {
            out.push_str("  ");
            out.push_str(path);
            out.push('\n');
        }
    }
    if !change.changed.is_empty() {
        out.push_str("\nchanged:\n");
        for path in &change.changed {
            out.push_str("  ");
            out.push_str(path);
            out.push('\n');
        }
    }
    if !change.removed.is_empty() {
        out.push_str("\nno longer tracked:\n");
        for path in &change.removed {
            out.push_str("  ");
            out.push_str(path);
            out.push('\n');
        }
    }
    // TWO SENTENCES, EACH SPEAKING ONLY FOR ITS OWN SECTION. The old single
    // sentence — "read the OLD ones at start" — is FALSE of an added path: there
    // was no old one. Printing it over both sections is what framed a new
    // capability as one more file to re-read.
    if !change.changed.is_empty() {
        out.push_str(
            "\nThese files changed under this session, which read the OLD ones at start and has\n\
             not re-read them. Re-read the ones named above before the next lifecycle step.\n",
        );
    }
    if !change.added.is_empty() {
        out.push_str(
            "\nThe added ones are new capability, not a changed rule: this session never read\n\
             them and has no basis for judging them irrelevant. Read them before deciding they\n\
             are not worth reading.\n",
        );
    }
    // ALL THREE PARTITIONS, and `added` is the one a reader forgets: a wiring file
    // that ARRIVED is the strongest reason to say the wiring moved, and it is
    // exactly the class the notice's first line already counts.
    let touched: Vec<&String> = change
        .changed
        .iter()
        .chain(change.added.iter())
        .chain(change.removed.iter())
        .filter(|path| wiring.iter().any(|w| w == *path))
        .collect();
    if !touched.is_empty() {
        out.push_str(
            "\nThe hook wiring is among them, so what this session is actually running may\n\
             differ from what the tree declares. `batten doctor hooks` reports the wiring;\n\
             what THIS process loaded at start is not answerable from inside (CLOUD-187).\n",
        );
    }
    out.push_str("\nReported once per change-set; silence otherwise.\n");
    out
}

/// The advisory for a session whose `SessionStart` registration never ran
/// (CLOUD-1085).
///
/// # Why a seed at a later event is news, and one at `SessionStart` is not
///
/// [`previous`] returns [`Look::CouldNotLook`] for the first batch of a session,
/// and the caller seeds it silently — correctly, because a session that started
/// after a change has already read the new files and nudging it is the noise that
/// gets an advisory channel ignored.
///
/// **That reasoning holds only at `SessionStart`.** The reporter serves exactly
/// two events, and the snapshot is seeded at the first one to arrive. So a seed
/// happening at `PostToolBatch` means `SessionStart` did not reach this code —
/// and since the host registers the engine by bare name on every event, the
/// overwhelmingly likely cause is that no `batten` resolved when that event
/// fired. Measured on the container that produced CLOUD-1085: the `SessionStart`
/// receipt was written at 04:37:21, the binary appeared at 04:39:58, and the
/// first snapshot landed at 04:40:48 — at `PostToolBatch`, three and a half
/// minutes late, with every mediated call in between failing open in silence.
///
/// **An absent reference monitor and a passing one are indistinguishable from
/// outside**, which is the whole defect: nothing in that session reported
/// anything. This is the one place the difference is observable, and it costs
/// nothing to observe — the per-session snapshot the drift predicate already
/// keeps is the entire mechanism.
///
/// # What it does NOT claim
///
/// Not that the calls before it were unsafe, and not which ones they were: this
/// process cannot see them. It reports the one fact it holds — the engine did not
/// run at this session's start — and names the provisioning step, because a
/// binary that is absent when the first hook fires is a provisioning failure
/// rather than a policy one (CLOUD-824's posture: report it where it can still be
/// fixed).
///
/// Pointer-only by construction: no path, no session id, no count of anything
/// read off the disk. The session id is a host token and would be a poor pointer
/// anyway — the reader has exactly one session.
///
/// Rate-limited by the same write as the drift notice. The caller records the
/// snapshot in the same branch, so this is emitted once per session and never
/// again, which is what keeps it credible rather than a line everybody learns to
/// scroll past.
#[must_use]
pub fn unmediated_session() -> String {
    "contract-drift: this session's SessionStart registration did not run\n\n\
     The per-session snapshot is being seeded at a later event, which means the engine\n\
     was not invoked when this session started. The hosts register it by BARE NAME, so\n\
     the usual cause is that no `batten` resolved on PATH at that moment — in which case\n\
     every mediated call until it appeared failed open and said nothing.\n\n\
     This is a provisioning failure rather than a policy one: `mise run deps-install`\n\
     installs the released binary, and `mise run deps` reports which one PATH finds.\n\n\
     Which calls preceded this is not answerable from here, and is not claimed.\n\
     Reported once per session; silence otherwise.\n"
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn manifest(rows: &[(&str, &str)]) -> Manifest {
        rows.iter()
            .map(|(path, hash)| ((*path).to_owned(), (*hash).to_owned()))
            .collect()
    }

    #[test]
    fn an_unchanged_surface_reports_nothing() {
        let one = manifest(&[("guide.md", "aa"), ("gate.config", "bb")]);
        assert!(compare(&one, &one).is_empty());
    }

    #[test]
    fn a_moved_file_is_changed_an_unseen_one_is_added_and_a_dropped_one_is_removed() {
        // CLOUD-490 partitioned `changed`: this asserted `new.md` among the
        // changed, which is the framing the row removes. Rewritten rather than
        // deleted — the guarantee it protects (every moved path is reported
        // exactly once, under exactly one heading) is still wanted.
        let before = manifest(&[("guide.md", "aa"), ("gone.md", "cc")]);
        let after = manifest(&[("guide.md", "zz"), ("new.md", "dd")]);
        let change = compare(&before, &after);
        assert_eq!(change.changed, vec!["guide.md"]);
        assert_eq!(change.added, vec!["new.md"]);
        assert_eq!(change.removed, vec!["gone.md"]);
        // The partition is exhaustive and disjoint: the count a reader is shown
        // is still every path that moved.
        assert_eq!(change.touched(), 2);
    }

    /// An undeclared surface is **could not look**, never "nothing moved".
    ///
    /// Fails by: returning `Look::Is(Manifest::new())` for an empty `tracked`.
    /// That collapses the two answers, and the collapsed value is the quiet one
    /// — a repository that never declared the table would be reported as stable
    /// forever rather than as unmeasured.
    #[test]
    fn an_undeclared_surface_is_could_not_look_rather_than_empty() {
        let looked = surface(Path::new("."), &[]).unwrap();
        assert!(matches!(looked, Look::CouldNotLook));
        assert_ne!(looked, Look::Is(Manifest::new()));
    }

    /// The report carries pointers and never a byte of a file.
    ///
    /// Fails by: rendering the content beside the path. A reminder carrying the
    /// new text is a mirror, and a mirror is cleared by reading the hook instead
    /// of the file — the one outcome the predicate exists to prevent.
    #[test]
    fn the_report_is_pointer_only() {
        let secret = "ghp_thisIsTheSortOfThingAContractFileMustNeverEcho";
        let change = ChangeSet {
            changed: vec!["wiring.json".to_owned()],
            added: Vec::new(),
            removed: Vec::new(),
        };
        let text = render(&change, &["wiring.json".to_owned()]);
        assert!(text.contains("wiring.json"));
        assert!(!text.contains(secret));
        assert!(
            !text.contains("+++") && !text.contains("@@"),
            "no diff of any kind"
        );
    }

    /// The wiring line is derived from the change-set, and says nothing about
    /// what this session loaded (CLOUD-525).
    ///
    /// Fails by: emitting the line unconditionally, or restoring a clause whose
    /// subject is the session's loaded hook set — an instruction no mechanism
    /// can answer, which an agent can only guess at.
    #[test]
    fn the_wiring_line_is_computable_and_claims_nothing_about_the_session() {
        let wiring = vec!["wiring.json".to_owned()];

        let touched = render(
            &ChangeSet {
                changed: vec!["wiring.json".to_owned()],
                added: Vec::new(),
                removed: Vec::new(),
            },
            &wiring,
        );
        assert!(touched.contains("The hook wiring is among them"));
        // And an ADDED wiring file says so too (CLOUD-490). Partitioning `added`
        // out of `changed` silently dropped this arm until a review caught it:
        // the notice counted the path and then reported the wiring as untouched.
        let arrived = render(
            &ChangeSet {
                changed: Vec::new(),
                added: vec!["wiring.json".to_owned()],
                removed: Vec::new(),
            },
            &wiring,
        );
        assert!(arrived.contains("The hook wiring is among them"));
        assert!(touched.contains("batten doctor hooks"));
        assert!(
            !touched.contains("self-enforced"),
            "the unactionable clause must not come back"
        );

        let untouched = render(
            &ChangeSet {
                changed: vec!["guide.md".to_owned()],
                added: Vec::new(),
                removed: Vec::new(),
            },
            &wiring,
        );
        assert!(
            !untouched.contains("The hook wiring is among them"),
            "a change-set that did not touch the wiring says nothing about it"
        );
    }

    /// A session id cannot escape the snapshot store.
    ///
    /// The property is **one path component that cannot traverse**, not the
    /// absence of a `..` substring: `../../escape` sanitizes to the literal
    /// filename `..-..-escape`, which contains two dots and traverses nothing.
    /// Asserting on the substring would have been a check that looks like it
    /// discriminates and does not — it would fail on a safe name and pass on any
    /// escape spelled without dots.
    #[test]
    fn a_traversing_session_id_stays_one_component() {
        let dir = Path::new("/tmp/gd");
        let path = snapshot_path(dir, Some("../../escape"));
        assert_eq!(path.parent().unwrap(), dir.join(SNAPSHOT_DIR));
        let file = path.file_name().expect("a snapshot is a file");
        assert_ne!(file, std::ffi::OsStr::new(".."));
        assert_ne!(file, std::ffi::OsStr::new("."));
        assert!(
            !file.to_string_lossy().contains('/') && !file.to_string_lossy().contains('\\'),
            "a session id never becomes a separator"
        );
        assert_eq!(
            path.components().count(),
            dir.components().count() + 2,
            "the store dir plus exactly one component for the session"
        );
        // The absent session is the ONE holder of the shared key, and no present
        // id can reach it: two sessions on one snapshot suppress or misdirect
        // each other's notices, which is what the per-session key is for.
        assert_eq!(
            snapshot_path(dir, None),
            dir.join(SNAPSHOT_DIR).join(SHARED_KEY)
        );
        assert_ne!(
            snapshot_path(dir, Some(SHARED_KEY)),
            dir.join(SNAPSHOT_DIR).join(SHARED_KEY),
            "an id spelling the absent-session key must not land on it"
        );
        assert_ne!(
            snapshot_path(dir, Some("a/b")),
            snapshot_path(dir, Some("a?b")),
            "two ids a sanitizer would flatten together stay apart"
        );
        assert_eq!(
            snapshot_path(dir, Some("a/b")),
            snapshot_path(dir, Some("a/b")),
            "and one id keys the same snapshot every call"
        );
    }
}
