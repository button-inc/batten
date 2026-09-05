//! Writes to a local git repository: loose objects, refs, and the replay of a
//! branch onto a base that moved.
//!
//! # Why this is not `git.rs`
//!
//! `git.rs` is READ-ONLY over `gix` and says so in its own header and in
//! `mem:core`; the only write to a remote anywhere in the crate is
//! [`crate::lease::swap`]. Adding writes there would have made a documented
//! property false rather than changing it on purpose, so the writes live here and
//! `git.rs` keeps its character. The split is by EFFECT, not by subject: reading
//! which objects a push must carry is `git::objects_to_send`, and putting a
//! fetched object into the odb is this module's.
//!
//! # Why loose objects rather than a pack
//!
//! A received pack could be indexed into `.git/objects/pack`, and `gix-pack` can
//! do it — but `write_to_directory` sits behind the `streaming-input` feature,
//! which is not enabled here and which pulls `parking_lot` and `gix-tempfile` to
//! turn on. A lap's fetch is a handful of commits, so writing them loose costs a
//! few files and no dependency at all. **Loose is not a lesser form**: it is what
//! git itself writes for new objects, and the odb reads both without caring.
//!
//! The trade is stated rather than assumed: a fetch of thousands of objects would
//! want a pack, and this repository never clones — it fetches a lap's worth of
//! trunk. Bring a number over a slow fetch and the pack path is the answer.
//!
//! # Layering
//!
//! `policy/module-layering.rego` forbids `hook -> gitwrite` and
//! `check -> gitwrite` for the reason it forbids the same edges into `lease`: a
//! gate declared `read` must not reach a write, and the read-only allowlist is
//! DERIVED from that declaration rather than reviewed.
//!
//! # The rebase, and the one thing it must never do
//!
//! `mem:workflow/landing-loop` states the loop's only human stop: *"the only stop
//! is a rebase that conflicts."* `gix-merge` offers auto-resolution — a
//! `ResolveWith` strategy that picks a side and reports success — and taking it
//! would delete that stop, which is the whole reason the loop is safe to leave
//! running. So [`rebase`] asks
//! [`TreatAsUnresolved::forced_resolution`](gix::merge::tree::TreatAsUnresolved::forced_resolution),
//! the STRICTEST reading available: an entry a strategy resolved still counts as
//! unresolved. A conflict is then a returned [`Rebase::Conflicted`] rather than
//! an `Err`, because it is an answer about the branch and its caller must report
//! it with a pointer, not swallow it as an internal failure.
//!
//! **Nothing moves on a conflict.** The ref is written and the worktree touched
//! only after every commit in the range has replayed, so a refusal leaves the
//! clone exactly as it was — no detached HEAD, no `rebase --abort` to remember,
//! no half-replayed state for the next lap to discover.

use std::path::Path;

use anyhow::Result;

use gix::objs::Write as _;

use crate::lease::Object;

/// Write objects into the repository's odb, skipping any it already carries.
///
/// **Idempotent, because a fetch can overlap what is already held.** An object
/// the odb has is not rewritten — git addresses by content, so a rewrite would
/// produce the identical bytes at the identical path and only cost IO.
///
/// # Errors
///
/// A repository that will not open, or an object the odb refuses. **A refused
/// write is an error rather than a skip**: an object that did not land is one a
/// later read will not find, and discovering that at the read is discovering it
/// far from the cause.
pub fn write_objects(dir: &Path, objects: &[Object]) -> Result<usize> {
    if objects.is_empty() {
        return Ok(0);
    }
    let repo = crate::git::open_for_write(dir)?;
    let mut written = 0;
    for object in objects {
        let id = gix::ObjectId::from_hex(object.id.as_bytes())
            .map_err(|err| anyhow::anyhow!("gitwrite: {} is not an object id: {err}", object.id))?;
        if repo.find_object(id).is_ok() {
            continue;
        }
        // THROUGH THE ODB HANDLE, because `Repository::write_object` takes a typed
        // `WriteTo` value and re-serialises it — which would round-trip bytes the
        // pack reader already produced and hashed, through a second encoder. The
        // handle takes the payload and the kind it was hashed as, so what lands
        // is exactly what was read.
        let landed = repo
            .objects
            .write_buf(object.kind, &object.body)
            .map_err(|err| anyhow::anyhow!("gitwrite: {} will not write: {err}", object.id))?;
        // THE ODB'S OWN ID MUST MATCH THE ONE THE READER DERIVED. They are
        // computed the same way, so a disagreement means the bytes changed
        // between the pack reader and here — which is exactly the corruption a
        // delta applied wrongly produces, and it must not become an object under
        // a plausible-looking name.
        if landed != id {
            return Err(anyhow::anyhow!(
                "gitwrite: {} landed as {landed}, so its bytes are not what was read",
                object.id
            ));
        }
        written += 1;
    }
    Ok(written)
}

/// Point `reference` at `id`.
///
/// **Unconditional, and that is the caller's decision to make.** A fetch writes
/// a remote-tracking ref, which is a record of what the remote said rather than a
/// claim anyone races for — the compare-and-swap that matters is the REMOTE one,
/// and that is [`crate::lease::swap`]'s. A local ref two processes contend for
/// would need a different function, and there is no such caller.
///
/// # Errors
///
/// A repository that will not open, an id that will not parse, or a ref the
/// backend refuses to move.
pub fn set_ref(dir: &Path, reference: &str, id: &str) -> Result<()> {
    let repo = crate::git::open_for_write(dir)?;
    let target = gix::ObjectId::from_hex(id.as_bytes())
        .map_err(|err| anyhow::anyhow!("gitwrite: {id} is not an object id: {err}"))?;
    let name: gix::refs::FullName = reference
        .try_into()
        .map_err(|err| anyhow::anyhow!("gitwrite: {reference} is not a ref name: {err}"))?;
    repo.edit_reference(gix::refs::transaction::RefEdit {
        change: gix::refs::transaction::Change::Update {
            log: gix::refs::transaction::LogChange {
                mode: gix::refs::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: "batten: fetch".into(),
            },
            expected: gix::refs::transaction::PreviousValue::Any,
            new: gix::refs::Target::Object(target),
        },
        name,
        deref: false,
    })
    .map_err(|err| anyhow::anyhow!("gitwrite: {reference} will not move: {err}"))?;
    Ok(())
}

/// A commit's tree, as a detached id.
///
/// A free function rather than a closure because both halves of the replay ask
/// it and a closure would have to be threaded through or written twice.
fn tree_of(repo: &gix::Repository, id: gix::ObjectId) -> Result<gix::ObjectId> {
    let commit = repo
        .find_commit(id)
        .map_err(|err| anyhow::anyhow!("gitwrite: {id} will not read: {err}"))?;
    Ok(commit
        .tree_id()
        .map_err(|err| anyhow::anyhow!("gitwrite: {id} has no tree: {err}"))?
        .detach())
}

/// What a replay of a branch onto a moved base did.
///
/// Three answers rather than two, because "already there" is not a degenerate
/// success: a lap whose base did not move must not mint new SHAs, since every
/// receipt in the loop is keyed to the commit it validated and a gratuitous
/// rewrite throws all of them away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rebase {
    /// The branch already descends from the base. Nothing was replayed, no ref
    /// moved, and no file was touched.
    Current,
    /// Every commit replayed. The branch now points at `head`.
    Replayed {
        /// The new tip.
        head: String,
        /// How many commits were replayed onto the new base.
        commits: usize,
    },
    /// A commit would not replay. **Nothing was moved** — see this module's
    /// header for why that is the design rather than an implementation detail.
    Conflicted {
        /// The ORIGINAL commit that would not replay, as a full sha.
        commit: String,
        /// The paths it conflicts at — pointers, per non-negotiable rule 4,
        /// never a byte of either side's content.
        paths: Vec<String>,
    },
}

/// Remove `reference`, whatever it points at.
///
/// **`Any` for the expected value, matching [`set_ref`]'s reasoning**: the only
/// caller deletes a remote-TRACKING ref, which is this clone's record of what a
/// remote said rather than a claim anyone races for. The compare-and-swap that
/// matters is the remote one, and that is [`crate::lease::swap`]'s.
///
/// # Errors
///
/// A repository that will not open, a name that will not parse, or a backend
/// that refuses the edit.
pub fn delete_ref(dir: &Path, reference: &str) -> Result<()> {
    let repo = crate::git::open_for_write(dir)?;
    let name: gix::refs::FullName = reference
        .try_into()
        .map_err(|err| anyhow::anyhow!("gitwrite: {reference} is not a ref name: {err}"))?;
    repo.edit_reference(gix::refs::transaction::RefEdit {
        change: gix::refs::transaction::Change::Delete {
            expected: gix::refs::transaction::PreviousValue::Any,
            log: gix::refs::transaction::RefLog::AndReference,
        },
        name,
        deref: false,
    })
    .map_err(|err| anyhow::anyhow!("gitwrite: {reference} will not delete: {err}"))?;
    Ok(())
}

/// Does `tip` already carry `candidate`?
///
/// # Why it lives here rather than in `git.rs`
///
/// [`rebase`] below asks this same question inline and says why: **CLOUD-36
/// refuses ancestry as a MERGED-NESS answer**, because landing rebases and a
/// branch that landed is not an ancestor of anything. That refusal stands. What
/// is asked here is the other question — whether a tree really is built on a
/// commit — and for that, ancestry is exactly the predicate.
///
/// So the primitive lives beside the one caller that had already justified it,
/// where the misuse CLOUD-36 names cannot spread by looking like a general
/// utility in the module a reader browses for reads.
///
/// It is public because `speculation` needs the same question and must not open
/// the backend itself: `gix_is_confined_to_the_git_modules` refuses a fourth
/// module reaching `gix`, and it caught that module's first draft doing so. The
/// alternative — widening the confinement list for a predicate this file already
/// contains — would have bought a second place to get ancestry wrong.
///
/// `false` for anything that will not resolve, which is the fail-closed
/// direction every caller of this wants: a bet whose base cannot be read is not
/// a bet whose base is present.
#[must_use]
pub fn carries(dir: &Path, candidate: &str, tip: &str) -> bool {
    let Ok(repo) = crate::git::open_for_write(dir) else {
        return false;
    };
    let resolve = |rev: &str| repo.rev_parse_single(rev).ok().map(gix::Id::detach);
    let (Some(base), Some(head)) = (resolve(candidate), resolve(tip)) else {
        return false;
    };
    repo.merge_base(base, head)
        .is_ok_and(|found| found.detach() == base)
}

/// Replay `branch` onto `onto`, and update the worktree to match.
///
/// The commits in `onto..branch` are replayed oldest first, each as a three-way
/// merge of the running result against that commit's own tree with its first
/// parent's tree as the base — which is what `git rebase` does, spelled out.
///
/// **A merge commit in the range is refused rather than flattened.** `git rebase`
/// without `--rebase-merges` silently drops one, and a landing branch that grew
/// one is a branch whose author did something this loop does not model; guessing
/// is the wrong direction when the whole point of the range is that its patches
/// reach `main` unchanged.
///
/// **A replayed commit loses its signature, exactly as `git rebase` without `-S`
/// does.** A rebase mints new bytes, so a carried-over `gpgsig` would be a
/// signature over a commit that no longer exists — worse than none, because it
/// looks like provenance. The header is dropped; re-signing is the caller's, and
/// there is no caller that wants a signature over a commit it is about to rewrite
/// again on the next lap.
///
/// # Errors
///
/// A repository that will not open, a ref or rev that will not resolve, a merge
/// the engine cannot compute, or a worktree write that fails. A CONFLICT is not
/// an error — it is [`Rebase::Conflicted`].
pub fn rebase(dir: &Path, branch: &str, onto: &str) -> Result<Rebase> {
    // The range and the graft point are the same rev, which is what an ordinary
    // rebase means: replay everything this branch has that `onto` does not.
    replay_onto(dir, branch, onto, onto)
}

/// Replay `upstream..branch` onto `onto`, and update the worktree to match.
///
/// **`git rebase --onto`, and the third argument is the whole of it.** [`rebase`]
/// bounds the range by the place it grafts to, which is right when they are the
/// same rev and wrong when they are not — and the case that needs them apart is
/// unwinding a bet this process ADOPTED (CLOUD-862). Such a bet has no undo
/// point, because the process that recorded one is gone; what it has is the
/// borrowed base, and `origin/main..HEAD` minus the borrowed range is precisely
/// this branch's own commits. Bounding by `onto` there would replay the borrowed
/// commits too, which is the tree the unwind exists to get rid of.
///
/// Everything else is [`rebase`]'s and is documented there: merge commits
/// refused, signatures dropped, a conflict returned rather than raised.
///
/// # Errors
///
/// As [`rebase`].
pub fn replay_onto(dir: &Path, branch: &str, upstream: &str, onto: &str) -> Result<Rebase> {
    let repo = crate::git::open_for_write(dir)?;
    let resolve = |rev: &str| {
        repo.rev_parse_single(rev)
            .map_err(|err| anyhow::anyhow!("gitwrite: {rev} will not resolve: {err}"))
            .map(gix::Id::detach)
    };
    let base = resolve(onto)?;
    let bound = resolve(upstream)?;
    let tip = resolve(branch)?;

    // "Does this branch already sit on the base" is an ancestry question, and it
    // is asked HERE rather than added to `git.rs` as an `is_ancestor`. CLOUD-36's
    // refusal stands and is about a different question: whether a LANDED branch
    // is on `main`, which ancestry answers wrongly because landing rebases. What
    // is asked here is whether there is anything to replay, and for that ancestry
    // is exactly the predicate — the base is an ancestor of the tip iff the tip
    // already carries it.
    // ASKED OF THE GRAFT POINT AND THE BOUND ALIKE, and both are needed once
    // they can differ: there is nothing to replay when the tip already carries
    // `onto` AND the range is empty. An adopted bet's unwind has a tip that
    // carries its bound and NOT its graft point, which is exactly the case that
    // must not short-circuit.
    if bound == base
        && repo
            .merge_base(base, tip)
            .is_ok_and(|found| found.detach() == base)
    {
        return Ok(Rebase::Current);
    }

    let walk = repo
        .rev_walk([tip])
        .with_hidden([bound])
        .all()
        .map_err(|err| anyhow::anyhow!("gitwrite: {upstream}..{branch} will not walk: {err}"))?;
    let mut range = Vec::new();
    for step in walk {
        let info = step.map_err(|err| {
            anyhow::anyhow!("gitwrite: {upstream}..{branch} will not walk: {err}")
        })?;
        if info.parent_ids().count() > 1 {
            return Err(anyhow::anyhow!(
                "gitwrite: {} is a merge, and this replay does not model one",
                info.id()
            ));
        }
        range.push(info.id().detach());
    }
    // The walk is newest first and a replay is oldest first.
    range.reverse();

    let options = repo
        .tree_merge_options()
        .map_err(|err| anyhow::anyhow!("gitwrite: no merge options: {err}"))?;
    let committer = repo
        .committer()
        .ok_or_else(|| anyhow::anyhow!("gitwrite: this repository has no configured committer"))?
        .map_err(|err| anyhow::anyhow!("gitwrite: the configured committer will not parse: {err}"))?
        .to_owned()
        .map_err(|err| {
            anyhow::anyhow!("gitwrite: the configured committer will not parse: {err}")
        })?;

    let empty = gix::ObjectId::empty_tree(repo.object_hash());
    let mut cursor = base;
    for original in &range {
        match replay(&repo, cursor, *original, &options, &committer, empty)? {
            Step::Landed(id) => cursor = id,
            Step::Conflicted(paths) => {
                return Ok(Rebase::Conflicted {
                    commit: original.to_hex().to_string(),
                    paths,
                });
            }
        }
    }

    let now = cursor.to_hex().to_string();
    set_ref(dir, branch, &now)?;
    update_worktree(&repo, tip, cursor)?;
    Ok(Rebase::Replayed {
        head: now,
        commits: range.len(),
    })
}

/// Move `branch` to `to` and make the worktree match — `git reset --hard`.
///
/// **The EXACT unwind, and it is a different operation from a replay.** A bet
/// this process placed recorded the branch's own last non-speculative HEAD, so
/// undoing it is not "recompute what this branch should be" but "go back to what
/// it was" — no merge, no new commits, nothing to conflict. Where that undo point
/// is absent, [`replay_onto`] is the other unwind and its header says why.
///
/// The worktree update is [`rebase`]'s, so a reset writes the same bytes a replay
/// would and leaves an index with the stat data git needs to read the tree as
/// clean. Without that this is a reset that leaves every tracked file looking
/// modified, which the next lap's `tree-clean` would refuse.
///
/// # Errors
///
/// A repository that will not open, a rev that will not resolve, or a worktree
/// write that fails.
pub fn reset_hard(dir: &Path, branch: &str, to: &str) -> Result<String> {
    let repo = crate::git::open_for_write(dir)?;
    let resolve = |rev: &str| {
        repo.rev_parse_single(rev)
            .map_err(|err| anyhow::anyhow!("gitwrite: {rev} will not resolve: {err}"))
            .map(gix::Id::detach)
    };
    let was = resolve(branch)?;
    let now = resolve(to)?;
    let id = now.to_hex().to_string();
    set_ref(dir, branch, &id)?;
    update_worktree(&repo, was, now)?;
    Ok(id)
}

/// What replaying ONE commit produced.
enum Step {
    /// The rewritten commit's id.
    Landed(gix::ObjectId),
    /// The paths it conflicts at.
    Conflicted(Vec<String>),
}

/// Replay one commit onto `cursor`, three-way merging its own change in.
///
/// Split out of [`rebase`] because the loop and the merge fail for entirely
/// different reasons, and because a lap's whole decision — take the conflict or
/// resolve it — lives in six lines here rather than buried in a walk.
fn replay(
    repo: &gix::Repository,
    cursor: gix::ObjectId,
    original: gix::ObjectId,
    options: &gix::merge::tree::Options,
    committer: &gix::actor::Signature,
    empty: gix::ObjectId,
) -> Result<Step> {
    let commit = repo
        .find_commit(original)
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not read: {err}"))?;
    let theirs = commit
        .tree_id()
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} has no tree: {err}"))?
        .detach();
    // A root commit has no parent, so its base is the empty tree — which is the
    // same statement as "everything it introduces is an addition".
    let ancestor = match commit.parent_ids().next() {
        Some(parent) => tree_of(repo, parent.detach())?,
        None => empty,
    };
    let ours = tree_of(repo, cursor)?;

    let mut outcome = repo
        .merge_trees(
            ancestor,
            ours,
            theirs,
            gix::merge::blob::builtin_driver::text::Labels::default(),
            options.clone(),
        )
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not merge: {err}"))?;
    // THE STRICTEST READING, and the module header says why: a lenient one would
    // let a resolution strategy quietly pick a side, which deletes the loop's
    // only human stop.
    let strict = gix::merge::tree::TreatAsUnresolved::forced_resolution();
    if outcome.has_unresolved_conflicts(strict) {
        let mut paths: Vec<String> = outcome
            .conflicts
            .iter()
            .filter(|conflict| conflict.is_unresolved(strict))
            .map(|conflict| conflict.ours.location().to_string())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        return Ok(Step::Conflicted(paths));
    }

    let tree = outcome
        .tree
        .write()
        .map_err(|err| anyhow::anyhow!("gitwrite: {original}'s merged tree: {err}"))?
        .detach();
    let mut replayed = commit
        .decode()
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not decode: {err}"))?
        .into_owned()
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not decode: {err}"))?;
    replayed.tree = tree;
    replayed.parents = std::iter::once(cursor).collect();
    replayed.committer.clone_from(committer);
    replayed
        .extra_headers
        .retain(|(name, _)| name.as_slice() != b"gpgsig");
    Ok(Step::Landed(
        repo.write_object(&replayed)
            .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not rewrite: {err}"))?
            .detach(),
    ))
}

/// Bring the worktree from the tree of `was` to the tree of `now`.
///
/// **Only the paths that differ are touched**, and that is a requirement rather
/// than an optimisation: the loop runs `verify` after every rebase, so
/// re-materialising every tracked file would reset every mtime and make each lap
/// a cold build.
///
/// # Why this writes the files itself rather than calling gix's checkout
///
/// `gix-worktree-state::checkout` does all of this and more, and it is NOT
/// reachable here: its `Find` bound is `Send + Clone` unconditionally, and this
/// crate's `gix` resolves `OwnShared` to `Rc`, so `repo.objects` is not `Send`.
/// Reaching it means enabling `gix/parallel` — measured, and it did not move the
/// bound; a fuller audit of why belongs with the row that wants a full checkout,
/// which this is not. What a lap needs is a handful of changed paths, and that is
/// small enough to write directly and large enough to be worth not paying a
/// feature for.
///
/// **The filter pipeline is still gix's**, so a repository configuring a
/// clean/smudge driver gets the same bytes git would write. A DELAYED external
/// filter is refused rather than approximated — a long-running driver that
/// promises its answer later has no place in a step the loop blocks on.
///
/// # The index, and the trap in writing one
///
/// An index built from a tree carries ZERO stat data, and git compares size
/// before it compares content — so writing that index straight out would make
/// every tracked file read as modified. Each entry therefore gets a stat: the one
/// the existing index already held, for a path this replay did not touch, and a
/// fresh `stat(2)` for one it wrote.
fn update_worktree(repo: &gix::Repository, was: gix::ObjectId, now: gix::ObjectId) -> Result<()> {
    let Some(workdir) = repo.workdir().map(std::path::Path::to_path_buf) else {
        // A bare repository has nothing to update, and that is a fact about the
        // clone rather than a failure of the replay.
        return Ok(());
    };
    let (before, after) = (tree_of(repo, was)?, tree_of(repo, now)?);
    let read = |id: gix::ObjectId| -> Result<gix::Tree<'_>> {
        repo.find_tree(id)
            .map_err(|err| anyhow::anyhow!("gitwrite: tree {id} will not read: {err}"))
    };
    let (before, after) = (read(before)?, read(after)?);

    let changes = repo
        .diff_tree_to_tree(Some(&before), Some(&after), None)
        .map_err(|err| anyhow::anyhow!("gitwrite: the worktree delta will not compute: {err}"))?;
    let mut touched: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut gone: Vec<Vec<u8>> = Vec::new();
    for change in &changes {
        let path = change.location().to_vec();
        if matches!(
            change,
            gix::object::tree::diff::ChangeDetached::Deletion { .. }
        ) {
            gone.push(path);
        } else {
            touched.insert(path);
        }
    }
    if touched.is_empty() && gone.is_empty() {
        return Ok(());
    }

    // The stats the CURRENT index already holds, so an untouched path keeps the
    // reading git took when it was last written.
    let mut held: std::collections::BTreeMap<Vec<u8>, gix::index::entry::Stat> =
        std::collections::BTreeMap::new();
    if let Ok(current) = repo.index() {
        for entry in current.entries() {
            held.insert(entry.path(&current).to_vec(), entry.stat);
        }
    }

    let mut index = repo
        .index_from_tree(&after.id())
        .map_err(|err| anyhow::anyhow!("gitwrite: no index for {now}: {err}"))?;
    let (mut pipeline, _) = repo
        .filter_pipeline(None)
        .map_err(|err| anyhow::anyhow!("gitwrite: no filter pipeline: {err}"))?;
    {
        let state = &mut *index;
        let mut plan: Vec<(usize, Vec<u8>, gix::ObjectId, gix::index::entry::Mode)> = Vec::new();
        for (position, entry) in state.entries().iter().enumerate() {
            plan.push((position, entry.path(state).to_vec(), entry.id, entry.mode));
        }
        for (position, path, id, mode) in plan {
            if touched.contains(&path) {
                let stat = materialise(repo, &mut pipeline, &workdir, &path, id, mode)?;
                state.entries_mut()[position].stat = stat;
            } else if let Some(stat) = held.get(&path) {
                state.entries_mut()[position].stat = *stat;
            }
        }
    }
    index
        .write(gix::index::write::Options::default())
        .map_err(|err| anyhow::anyhow!("gitwrite: the index will not write: {err}"))?;

    // Writing ADDS and OVERWRITES; nothing above removes. So a path the new tree
    // does not carry has to be unlinked here, or a rebase that deletes a file
    // leaves it on disk and the next `verify` compiles a file that is not in the
    // commit.
    for path in &gone {
        let Ok(relative) = std::str::from_utf8(path) else {
            continue;
        };
        let target = workdir.join(relative);
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "gitwrite: {relative} will not delete: {err}"
                ));
            }
        }
    }
    Ok(())
}

/// Put one path's new content on disk, and report the stat it landed with.
///
/// Modes are handled explicitly rather than by a general routine, because each
/// one fails differently: a regular file is the common case, an executable
/// differs only in a permission bit, a symlink is a different syscall entirely,
/// and a gitlink names a submodule this replay does not enter.
fn materialise(
    repo: &gix::Repository,
    pipeline: &mut gix::filter::Pipeline<'_>,
    workdir: &Path,
    path: &[u8],
    id: gix::ObjectId,
    mode: gix::index::entry::Mode,
) -> Result<gix::index::entry::Stat> {
    let relative = std::str::from_utf8(path)
        .map_err(|_| anyhow::anyhow!("gitwrite: a path in the tree is not UTF-8"))?;
    let target = workdir.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative}'s directory: {err}"))?;
    }
    let blob = repo
        .find_object(id)
        .map_err(|err| anyhow::anyhow!("gitwrite: {relative}'s content: {err}"))?;

    if mode.is_submodule() {
        // A gitlink is a directory this replay never descends into; git itself
        // leaves a submodule's checkout alone on a rebase of the superproject.
        std::fs::create_dir_all(&target)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative}: {err}"))?;
    } else if mode == gix::index::entry::Mode::SYMLINK {
        let destination = std::str::from_utf8(&blob.data).map_err(|_| {
            anyhow::anyhow!("gitwrite: {relative} is a symlink to a non-UTF-8 path")
        })?;
        // REPLACE, never write through: an existing symlink is followed by a
        // write, which would put the new content in whatever it points at.
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(anyhow::anyhow!("gitwrite: {relative}: {err}")),
        }
        link(destination, &target)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not link: {err}"))?;
    } else {
        let mut converted = pipeline
            .convert_to_worktree(
                &blob.data,
                relative.into(),
                gix::filter::plumbing::pipeline::convert::to_worktree::Options::default(),
            )
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not filter: {err}"))?;
        // Same reason as the symlink arm, one step earlier: truncating through an
        // existing link writes the target.
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(anyhow::anyhow!("gitwrite: {relative}: {err}")),
        }
        let mut file = std::fs::File::create(&target)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not open: {err}"))?;
        // `ToWorktreeOutcome` IS the reader. `as_read` is the NARROWER question —
        // "did an external driver hand back a stream" — and it answers `None` for
        // the unfiltered case, which is every path in a repository that configures
        // no driver. Reading that `None` as "cannot be read" turned the common
        // case into a refusal, which is exactly what the clean-replay case caught.
        //
        // The delayed case has to be asked separately, because the `Read` impl
        // PANICS on it rather than erroring.
        if converted.is_delayed() {
            return Err(anyhow::anyhow!(
                "gitwrite: {relative} is behind a delayed filter, which is not supported"
            ));
        }
        std::io::copy(&mut converted, &mut file)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not write: {err}"))?;
        drop(file);
        if mode == gix::index::entry::Mode::FILE_EXECUTABLE {
            make_executable(&target)
                .map_err(|err| anyhow::anyhow!("gitwrite: {relative}'s mode: {err}"))?;
        }
    }

    let landed = gix::index::fs::Metadata::from_path_no_follow(&target)
        .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not stat: {err}"))?;
    // A clock that will not answer is not a reason to refuse the write that
    // already happened: a zero stat costs git a content comparison and nothing
    // else, where an error here would abandon a half-updated worktree.
    Ok(gix::index::entry::Stat::from_fs(&landed).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// The two worktree effects that are not portable, gated rather than assumed.
//
// `cross-check` type-checks this crate against `x86_64-pc-windows-gnu` with
// warnings denied, and it caught both of these unconditional: `std::os::unix`
// does not exist there, so the whole library failed to compile on a target this
// repository claims to support. `.claude/rules/rust.md` states the convention
// the fix takes — platform-specific code is deliberate and `#[cfg]`-gated.
//
// **The non-Unix arms are git's own fallbacks rather than silent no-ops**, and
// each says which: a symlink becomes a regular file holding its target's path,
// which is what git does under `core.symlinks=false`, and the executable bit is
// not modelled by the filesystem at all, so there is nothing to set. Neither is
// exercised here — this crate ships a Linux and a macOS binary — so they are
// written to be obviously right rather than to be measured.

/// Create a symbolic link, or the closest thing the platform has.
#[cfg(unix)]
fn link(destination: &str, target: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(destination, target)
}

/// The `core.symlinks=false` shape: the link's TARGET PATH as file content.
///
/// Not `std::os::windows::fs::symlink_file`, which needs a privilege an ordinary
/// account does not hold, so it would fail rather than degrade.
#[cfg(not(unix))]
fn link(destination: &str, target: &Path) -> std::io::Result<()> {
    std::fs::write(target, destination)
}

/// Set the executable bit.
#[cfg(unix)]
fn make_executable(target: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755))
}

/// There is no executable bit to set, and git does not synthesise one.
#[cfg(not(unix))]
fn make_executable(_target: &Path) -> std::io::Result<()> {
    Ok(())
}
