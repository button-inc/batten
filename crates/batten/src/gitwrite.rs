//! Writes to a local git repository: loose objects, refs, and the replay of a
//! branch onto a base that moved.
//!
//! # Why this is not `git.rs`
//!
//! `git.rs` is READ-ONLY over `gix` and says so in its own header and in
//! `mem:engineering/module-map`; the only write to a remote anywhere in the crate is
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
/// **A merge commit in the range is refused here rather than flattened.** `git
/// rebase` without `--rebase-merges` silently drops one, and guessing is the
/// wrong direction when the whole point of the range is that its patches reach
/// `main` unchanged. `land`'s own entry points ([`rebase_resolving`],
/// [`rebase_proposing`]) answer such a range with a merge of the moved base
/// instead (CLOUD-2054); this one — the speculation bet's — keeps refusing,
/// because a bet merged into a branch could not be shed by its unwind.
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

/// [`rebase`], with the conflict at named paths taken from the WORKTREE.
///
/// # The loop's one human stop had no route to take it (CLOUD-1586)
///
/// `mem:workflow/landing-loop` gives the loop exactly one human stop — a rebase
/// that conflicts — and the module header above states the design that makes the
/// stop safe: **nothing moves on a conflict**, so there is no detached HEAD and
/// no half-replayed state for the next lap to find. That is right, and it left
/// the human nothing to resolve. The predecessor shell lander left an ordinary
/// rebase in progress, where `git add` and `git rebase --continue` are the route;
/// this engine leaves a clean tree and a refusal. For a while the only way back
/// to a resolvable state was re-creating the rebase by hand — which this
/// repository's own hand-stepping row denies, with no `bypass_env` and a general
/// hatch that is only readable in the adjudicating process's environment.
/// Measured on #848 twice: the loop stopped, and no route it named was open.
///
/// **This function is that route, and since CLOUD-1537 the stop names it.**
/// The engine's conflict line and the hand-stepping row's own `reason` both spell
/// `batten land replay <ref> --resolve <path>` now. That mattered because the
/// route had existed since v0.0.153 while its only mention anywhere in the crate
/// was its own flag doc, so a conflicted branch still read as a dead end — a
/// remedy nobody can find is the same as no remedy.
///
/// # Why the resolution comes from the worktree, and why that needs no state
///
/// The alternative is `git rebase`'s: materialise the conflict, remember where
/// the replay got to, and continue. That needs the remainder of the range
/// persisted across invocations, and a half-replayed branch on disk — the exact
/// state the header refuses.
///
/// This is stateless instead. The whole replay re-runs from its base on every
/// invocation, so the caller supplies the merged content UP FRONT: edit the file
/// in the worktree, name it here, and the replay uses those bytes for that path
/// instead of refusing. Nothing is remembered, nothing is left half-done, and a
/// run with no `resolutions` is byte-identical to [`rebase`].
///
/// **It resolves a PATH, never a side.** There is no `--ours`/`--theirs`: those
/// would be the auto-resolution the module header refuses, one strategy pick
/// wearing a flag. What the caller supplies is content they wrote, which is a
/// decision a person made rather than one the engine took for them.
///
/// **EACH RESOLUTION IS SPENT ONCE, AND SINCE CLOUD-1670 THAT IS PER ENTRY
/// RATHER THAN PER PATH.** The rule it enforces is unchanged: one file carries
/// one version of its content, so using it for a second merge OF THAT PATH would
/// be replaying a resolution for a merge nobody looked at. What changed is that
/// the caller can now WRITE a second version. An entry is `<path>` — content
/// from the worktree, spent on the first conflict of that path — or
/// `<path>=<file>`, content from a file authored for one merge of it; entries
/// naming the same path are spent in the order given, one per conflict.
///
/// **The per-path spelling was a permanent stop for a path that conflicts
/// twice, and this branch is where it was measured.** One declared document
/// conflicted at FOUR of #848's commits, because four of them edit a single
/// line the base branch had also moved; a second document conflicted at four
/// more. Every run resolved the first and refused at the second, moved nothing,
/// and the next run re-derived the identical range — which is precisely the
/// shape the paragraph below says the patch-identity drop exists to remove,
/// arrived at through the path rather than through the offer. Naming the path
/// four times did not help, by construction: the offer was a SET of paths.
///
/// The documents are not named here, and that is rule 1 rather than reticence:
/// they are a consumer's own config, `document_facts`'s
/// `no_artifact_name_reaches_the_core` refuses one in this crate, and it caught
/// the first draft of this very paragraph.
///
/// Naming a path more than once is therefore an assertion, not a loophole: the
/// caller is saying they read each of those merges and wrote an answer for each.
/// A different path later in the range is still a different question and may be
/// named in the same run.
///
/// Spending the whole offer at the first conflicting commit enforced the same
/// rule and made a CHAIN unresolvable, which is worse than the case it guarded:
/// nothing moves on a conflict, so a range conflicting at two paths could never
/// complete — every run resolved the first, refused at the second, moved
/// nothing, and the next run re-derived the identical range. That is the
/// permanent-stop shape [`rebase`]'s patch-identity drop exists to remove,
/// reintroduced by its own remedy.
///
/// # Errors
///
/// As [`rebase`], plus a named path that cannot be read from the worktree — that
/// is a usage error rather than a conflict, because the caller asserted a
/// resolution exists there.
pub fn rebase_resolving(
    dir: &Path,
    branch: &str,
    onto: &str,
    resolutions: &[String],
) -> Result<Rebase> {
    replay_range(dir, branch, onto, onto, resolutions, None, true).map(|(rebase, _)| rebase)
}

/// One conflicted path's candidate, if a shape covered every region of it
/// (CLOUD-1956).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The conflicted path, as [`Rebase::Conflicted`] names it.
    pub path: String,
    /// Where the candidate was written and the shapes that made it, or `None`
    /// when any region matched no shape — the path is then the human's alone.
    pub proposal: Option<(std::path::PathBuf, Vec<crate::propose::Shape>)>,
}

/// [`rebase_resolving`], and on a conflict a candidate per conflicted path
/// written under `into` (CLOUD-1956).
///
/// **A candidate is never applied.** The replay stops and moves nothing exactly
/// as without `into`; what differs is that each conflicted path whose every
/// region matches a [`crate::propose::Shape`] gets its merge written to
/// `into/<path>`, for a person to read and pass back as `--resolve
/// <path>=<file>`. The module header's refusal of auto-resolution is untouched:
/// the only act that writes a resolution into a tree is still the caller's.
///
/// A separate entry point rather than a field on [`Rebase::Conflicted`], because
/// that enum is public and a field added to it is a semver break for a feature
/// that adds a capability.
///
/// # Errors
///
/// As [`rebase_resolving`], plus a candidate that cannot be written under `into`.
pub fn rebase_proposing(
    dir: &Path,
    branch: &str,
    onto: &str,
    resolutions: &[String],
    into: &Path,
) -> Result<(Rebase, Vec<Candidate>)> {
    replay_range(dir, branch, onto, onto, resolutions, Some(into), true)
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
    replay_range(dir, branch, upstream, onto, &[], None, false).map(|(rebase, _)| rebase)
}

/// The replay every entry point above funnels into.
///
/// `resolutions` is [`rebase_resolving`]'s and is empty for every other caller,
/// which is what makes the added parameter behaviour-preserving rather than a
/// second replay to keep in step.
fn replay_range(
    dir: &Path,
    branch: &str,
    upstream: &str,
    onto: &str,
    resolutions: &[String],
    propose_into: Option<&Path>,
    merge_ok: bool,
) -> Result<(Rebase, Vec<Candidate>)> {
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
        return Ok((Rebase::Current, Vec::new()));
    }

    let walk = repo
        .rev_walk([tip])
        .with_hidden([bound])
        .all()
        .map_err(|err| anyhow::anyhow!("gitwrite: {upstream}..{branch} will not walk: {err}"))?;
    let mut range = Vec::new();
    let mut merges = false;
    for step in walk {
        let info = step.map_err(|err| {
            anyhow::anyhow!("gitwrite: {upstream}..{branch} will not walk: {err}")
        })?;
        merges |= info.parent_ids().count() > 1;
        range.push(info.id().detach());
    }
    // A REPLAY CANNOT REPRODUCE A MERGE COMMIT, and only `land`'s own catch-up
    // may answer one with a merge instead (CLOUD-2054). A speculative bet merged
    // into a branch could not be shed by the unwind, and the unwind itself
    // (`bound != base`) must drop borrowed commits, which a merge cannot do — so
    // every other shape keeps the refusal, now naming why.
    if merges && (!merge_ok || bound != base) {
        return Err(anyhow::anyhow!(
            "gitwrite: {upstream}..{branch} carries a merge, which only `land`'s rebase brings onto a moved base"
        ));
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
    let context = Replay {
        dir,
        options: &options,
        committer: &committer,
        empty,
        propose_into,
    };

    // A RANGE CARRYING A MERGE IS BROUGHT ONTO THE BASE BY A MERGE (CLOUD-2054).
    //
    // Refusing it left one route open: rewriting the branch by hand to get past
    // the loop, which is lossier than anything this function could do. Measured
    // on #1056: the refusal arrived after a 51-minute `verify`, and the squash
    // that answered it dropped a breaking-change marker, per-commit semver and
    // 211 commits of history. Merging the moved base into the tip keeps every
    // original commit byte for byte — the property the refusal existed to
    // protect — and the result still fast-forwards.
    if merges {
        return merge_onto(&context, &repo, branch, onto, tip, base, resolutions);
    }

    // **A COMMIT WHOSE CHANGE IS ALREADY ON THE BASE IS DROPPED, NOT REPLAYED**
    // (CLOUD-1586). This is `git rebase`'s own behaviour — it builds the list
    // through `git cherry`, which compares patch identities and omits the
    // commits the upstream already carries — and its absence here was a
    // PERMANENT stop rather than a slow path: a change that reached `main` by
    // any route other than this branch's own merge (a cherry-pick, an
    // independent re-implementation, a fix ported ahead of the PR) stays in
    // `upstream..branch` because it is not REACHABLE from the base, gets
    // three-way merged against a base that already contains it, and conflicts.
    // Every later lap re-derives the same range and conflicts identically, so
    // the loop cannot make progress no matter how many times it runs.
    //
    // Measured on this branch: `3f308039` and `main`'s `a7935a7b` share patch
    // identity `f185159e…`, and the replay stopped on it every lap. The
    // resolution needed a hand rebase, which `patch run loose` denies —
    // so the engine's missing drop presented as a policy deadlock and cost a
    // human override to get past.
    //
    // ANCHORED ON `branch..onto`, which is `git cherry`'s comparison side: the
    // commits the base has and this branch does not. `upstream..onto` is the
    // wrong set and is empty in the common case where the graft point IS the
    // bound, which would make this whole guard a no-op.
    //
    // A range that will not read is an EMPTY set, never a refusal: could-not-look
    // here means replay everything, which is the behaviour that existed before
    // and can only conflict, never silently drop work.
    //MUTANT-SUITE crates/batten/tests/it/rebase.rs
    //MUTANT borrowed-upstream-replayed|s@^    if bound != base {$@    if false {@|a_borrowed_commit_the_holder_republished_is_dropped_on_unwind
    let mut already = crate::git::patch_identities(
        dir,
        crate::git::Window::DEFAULT,
        &format!("{branch}..{onto}"),
    )
    .unwrap_or_default();
    // **AND THE UPSTREAM'S OWN CHANGES, WHERE THE UPSTREAM IS NOT THE BASE**
    // (CLOUD-2086). They differ only on a bet's unwind, where `upstream` is the
    // lease holder's published tip. The holder republishes its range under new
    // shas, so this branch's copies of the holder's commits are neither on the
    // trunk nor ancestors of the upstream, and the trunk drop set above kept
    // them: measured on #1065, two of another branch's commits were replayed as
    // this branch's own and voided a fresh verify receipt. Patch identity is the
    // same question `git cherry` asks, asked of the side the commits came from.
    // Could-not-look is an empty set, as above.
    if bound != base {
        already.extend(
            crate::git::patch_identities(
                dir,
                crate::git::Window::DEFAULT,
                &format!("{branch}..{upstream}"),
            )
            .unwrap_or_default(),
        );
    }

    let mut cursor = base;
    let mut replayed = 0usize;
    // THE OFFER, PARSED ONCE AND SPENT PER OCCURRENCE (CLOUD-1670).
    //
    // An entry is `<path>` — content from the worktree, as it always was — or
    // `<path>=<file>`, content from a file the caller wrote for ONE merge of that
    // path. The pair is what makes a path conflicting at several commits
    // resolvable at all, and it is the honest shape rather than reuse: the second
    // occurrence gets bytes somebody authored for it, not the first occurrence's
    // answer applied again to a merge nobody looked at.
    let offer = parse_offer(resolutions);
    let mut used: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for original in &range {
        // `commit_identity` is `None` for a commit that changes nothing, and an
        // absent identity must not match another absent one — so an empty commit
        // is replayed rather than dropped, and stays the caller's to reason about.
        if crate::git::commit_identity(&repo, original)
            .is_some_and(|identity| already.contains(&identity))
        {
            continue;
        }
        // **EACH PATH IS SPENT ONCE, rather than the whole offer at the first
        // conflicting commit.** One worktree file holds one version of its
        // content, so reusing it for a SECOND merge of the same path would be
        // inventing a resolution nobody looked at — that is the rule, and it is
        // about the path rather than about the commit.
        //
        // Spending the whole offer at the first conflict enforced the same rule
        // and made a CHAIN unresolvable, which is worse than the case it
        // guarded. Nothing moves on a conflict, so a range whose commits
        // conflict at two different paths could never complete: every run
        // resolved the first, refused at the second, moved nothing, and the next
        // run re-derived the identical range. Measured on #848 — `fetch.rs` at
        // one commit and `egress-fencing.rego` at another — where it is the
        // permanent-stop shape the patch-identity drop above exists to remove,
        // reintroduced by its own remedy.
        //
        // SPENT PER OCCURRENCE SINCE CLOUD-1670, and the rule above is unchanged
        // by it: what a path may not do is reuse ONE resolution twice. The offer
        // for this commit is, per path, the NEXT unspent entry naming it — so a
        // caller who wrote four files for four merges of one path gets each
        // applied to the merge they wrote it for, and a caller who named the path
        // once still spends it once. Nothing is remembered across invocations;
        // the whole range re-runs and the offer is re-read from argv.
        let offered = next_offer(&offer, &used);
        match replay(&context, &repo, cursor, *original, &offered)? {
            Step::Landed(id) => {
                cursor = id;
                replayed += 1;
            }
            Step::Resolved(id, spent) => {
                cursor = id;
                replayed += 1;
                for path in spent {
                    *used.entry(path).or_insert(0) += 1;
                }
            }
            Step::Conflicted(paths, candidates) => {
                return Ok((
                    Rebase::Conflicted {
                        commit: original.to_hex().to_string(),
                        paths,
                    },
                    candidates,
                ));
            }
        }
    }

    finish(dir, &repo, branch, tip, cursor, replayed).map(|rebase| (rebase, Vec::new()))
}

/// Move `branch` to the replayed head and make the worktree match.
///
/// The count is what was REPLAYED, not what was walked: a dropped commit
/// contributes no commit to the new head, and reporting the range's length
/// would claim a head carries commits it does not.
fn finish(
    dir: &Path,
    repo: &gix::Repository,
    branch: &str,
    tip: gix::ObjectId,
    cursor: gix::ObjectId,
    replayed: usize,
) -> Result<Rebase> {
    let now = cursor.to_hex().to_string();
    set_ref(dir, branch, &now)?;
    update_worktree(repo, tip, cursor)?;
    Ok(Rebase::Replayed {
        head: now,
        commits: replayed,
    })
}

/// Bring a merge-carrying `branch` onto the moved `base` with ONE merge commit
/// (CLOUD-2054).
///
/// **Parents `[tip, base]`, so every original commit keeps its bytes** and the
/// result is still a descendant of the base, which is all a fast-forward needs.
/// The tree is [`Repository::merge_commits`](gix::Repository::merge_commits)'s,
/// which builds a VIRTUAL merge base when the histories have several — a branch
/// that merged trunk in repeatedly is criss-cross, and picking one base there
/// would invent conflicts or hide them.
///
/// **Judged by [`settle`], exactly as a replayed commit is**: the same strict
/// reading, the same `--resolve` offer (one merge spends each path once), the
/// same candidates under `--propose`. A conflict names the TIP, the original
/// commit that would not carry onto the base, and moves nothing.
///
/// The count is zero because nothing was REPLAYED; the head moved by a merge.
fn merge_onto(
    ctx: &Replay<'_>,
    repo: &gix::Repository,
    branch: &str,
    onto: &str,
    tip: gix::ObjectId,
    base: gix::ObjectId,
    resolutions: &[String],
) -> Result<(Rebase, Vec<Candidate>)> {
    let mut outcome = repo
        .merge_commits(
            tip,
            base,
            gix::merge::blob::builtin_driver::text::Labels::default(),
            ctx.options.clone().into(),
        )
        .map_err(|err| anyhow::anyhow!("gitwrite: {onto} will not merge into {branch}: {err}"))?;
    let trees = [
        outcome.merge_base_tree_id,
        tree_of(repo, tip)?,
        tree_of(repo, base)?,
    ];
    let offered = next_offer(
        &parse_offer(resolutions),
        &std::collections::BTreeMap::new(),
    );
    let settled = settle(
        ctx.dir,
        repo,
        &mut outcome.tree_merge,
        trees,
        &offered,
        ctx.propose_into,
    )?;
    if let Settled::Conflicted(paths, candidates) = settled {
        return Ok((
            Rebase::Conflicted {
                commit: tip.to_hex().to_string(),
                paths,
            },
            candidates,
        ));
    }
    let tree = outcome
        .tree_merge
        .tree
        .write()
        .map_err(|err| anyhow::anyhow!("gitwrite: the merge of {onto} into {branch}: {err}"))?
        .detach();
    let short = |name: &str| {
        name.strip_prefix("refs/heads/")
            .or_else(|| name.strip_prefix("refs/remotes/"))
            .unwrap_or(name)
            .to_owned()
    };
    let who = stamped_in_utc(ctx.committer);
    let merged = gix::objs::Commit {
        tree,
        parents: [tip, base].into_iter().collect(),
        author: who.clone(),
        committer: who,
        encoding: None,
        message: format!(
            "chore(merge): carry {} into {}\n",
            short(onto),
            short(branch)
        )
        .into(),
        extra_headers: Vec::new(),
    };
    let minted = repo
        .write_object(&merged)
        .map_err(|err| {
            anyhow::anyhow!("gitwrite: the merge of {onto} into {branch} will not write: {err}")
        })?
        .detach();
    finish(ctx.dir, repo, branch, tip, minted, 0).map(|rebase| (rebase, Vec::new()))
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
    /// The rewritten commit's id, and the paths whose resolution was spent on it.
    ///
    /// A separate arm rather than a flag on [`Step::Landed`] because the caller
    /// must know WHICH paths were spent: each is withdrawn from the offer for
    /// every later commit in the range, and a walk that could not tell would hand
    /// the same worktree bytes to a second merge of that path nobody inspected.
    Resolved(gix::ObjectId, Vec<String>),
    /// The paths it conflicts at, and a candidate per path when asked for one.
    Conflicted(Vec<String>, Vec<Candidate>),
}

/// Replay one commit onto `cursor`, three-way merging its own change in.
///
/// Split out of [`rebase`] because the loop and the merge fail for entirely
/// different reasons, and because a lap's whole decision — take the conflict or
/// resolve it — lives in six lines here rather than buried in a walk.
/// One resolution entry read as `(path, source file)` (CLOUD-1670).
///
/// `<path>` alone reads the content from the path itself, which is every caller
/// before this row and stays byte-identical. `<path>=<file>` names a file the
/// caller authored for ONE merge of that path, which is what makes a path
/// conflicting at several commits resolvable without reusing an answer.
///
/// The split is on the FIRST `=`, so a source file whose own name contains one
/// still resolves; a path containing `=` is not expressible and is not a shape
/// this repository has.
fn parse_offer(resolutions: &[String]) -> Vec<(String, std::path::PathBuf)> {
    resolutions
        .iter()
        .map(|entry| match entry.split_once('=') {
            Some((path, source)) => (path.to_owned(), std::path::PathBuf::from(source)),
            None => (entry.clone(), std::path::PathBuf::from(entry)),
        })
        .collect()
}

/// The resolution on offer for the NEXT conflict, one per path (CLOUD-1670).
///
/// `offer` is the caller's entries in the order given and `used` counts how many
/// of each path's entries earlier commits already spent, so a path's offer here
/// is its `used[path]`-th entry and a path whose entries are exhausted offers
/// nothing — which is what makes the commit after them conflict rather than
/// silently reuse the last answer.
fn next_offer(
    offer: &[(String, std::path::PathBuf)],
    used: &std::collections::BTreeMap<String, usize>,
) -> std::collections::BTreeMap<String, std::path::PathBuf> {
    let mut offered: std::collections::BTreeMap<String, std::path::PathBuf> =
        std::collections::BTreeMap::new();
    for (path, _) in offer {
        if offered.contains_key(path) {
            continue;
        }
        let already = used.get(path).copied().unwrap_or(0);
        let mut queue = offer
            .iter()
            .filter(|(candidate, _)| candidate == path)
            .map(|(_, source)| source);
        if let Some(source) = queue.nth(already) {
            offered.insert(path.clone(), source.clone());
        }
    }
    offered
}

/// A committer signature stamped in UTC (CLOUD-1486).
///
/// **The offset is the whole of the defect and the instant is left alone.**
/// `repo.committer()` resolves its time through gix's `now_local_or_utc()`, so the
/// `+hhmm` a replayed commit carried was the landing host's `TZ` — the one non-UTC
/// value this binary emitted, against `lease.rs`'s deliberately pinned `offset: 0`.
/// Two hosts replaying the same range therefore minted different ids for identical
/// content, which the lap's fast-forward and the lease's CAS both assume cannot
/// happen. Keeping the seconds means an explicitly supplied committer date
/// survives, so this cannot quietly become a second clock.
///
/// **The author is not this function's business**, and a replay leaves it alone:
/// the original author and their time are what the rewritten commit inherits.
///
/// Public because it is the unit under test. A replay resolves its committer from
/// the repository, so no in-process case can hand the end-to-end path a non-UTC
/// signature without setting `TZ` — which needs `std::env::set_var`, `unsafe`, and
/// forbidden workspace-wide. `rules/rust.md` names extracting the decision as the
/// route for exactly that.
#[must_use]
pub fn stamped_in_utc(who: &gix::actor::Signature) -> gix::actor::Signature {
    gix::actor::Signature {
        time: crate::git::utc_at(who.time.seconds),
        ..who.clone()
    }
}

/// What every commit in one replay shares.
///
/// A struct rather than six parameters because the walk computes all of it once
/// and hands the same values to each commit — and because the alternative is a
/// signature clippy refuses at seven.
struct Replay<'a> {
    /// The worktree root, read only to pick up a caller's resolution.
    dir: &'a Path,
    /// The merge options the whole range is judged by.
    options: &'a gix::merge::tree::Options,
    /// The committer every rewritten commit takes.
    committer: &'a gix::actor::Signature,
    /// The empty tree, for a root commit's absent parent.
    empty: gix::ObjectId,
    /// Where to write a candidate per conflicted path (CLOUD-1956); `None`
    /// proposes nothing, which is every caller but `land replay --propose`.
    propose_into: Option<&'a Path>,
}

/// A candidate per conflicted path, written under `into` (CLOUD-1956).
///
/// `trees` is `[ancestor, ours, theirs]`. A path absent from any of the three is
/// an add/delete or rename conflict, which no text shape describes, so it gets no
/// candidate rather than a guess at which side meant to exist.
fn candidates(
    repo: &gix::Repository,
    trees: [gix::ObjectId; 3],
    paths: &[String],
    into: &Path,
) -> Result<Vec<Candidate>> {
    let mut found = Vec::with_capacity(paths.len());
    for path in paths {
        let [ancestor, ours, theirs] = trees.map(|tree| blob_at(repo, tree, path));
        let proposal = match (ancestor, ours, theirs) {
            (Some(ancestor), Some(ours), Some(theirs)) => {
                diff3(&ancestor, &ours, &theirs).and_then(|marked| crate::propose::propose(&marked))
            }
            _ => None,
        };
        let proposal = match proposal {
            Some(proposal) => {
                let file = into.join(path);
                if let Some(parent) = file.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| {
                        anyhow::anyhow!("gitwrite: {} will not create: {err}", parent.display())
                    })?;
                }
                crate::durable::replace(&file, &proposal.bytes).map_err(|err| {
                    anyhow::anyhow!("gitwrite: {} will not write: {err}", file.display())
                })?;
                Some((file, proposal.shapes))
            }
            None => None,
        };
        found.push(Candidate {
            path: path.clone(),
            proposal,
        });
    }
    Ok(found)
}

/// The bytes at `path` in `tree`, or `None` when the path is absent there.
fn blob_at(repo: &gix::Repository, tree: gix::ObjectId, path: &str) -> Option<Vec<u8>> {
    let tree = repo.find_tree(tree).ok()?;
    let entry = tree.lookup_entry_by_path(path).ok()??;
    let object = entry.object().ok()?;
    Some(object.data.clone())
}

fn replay(
    ctx: &Replay<'_>,
    repo: &gix::Repository,
    cursor: gix::ObjectId,
    original: gix::ObjectId,
    resolutions: &std::collections::BTreeMap<String, std::path::PathBuf>,
) -> Result<Step> {
    let Replay {
        dir,
        options,
        committer,
        empty,
        propose_into,
    } = *ctx;
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
    let resolved = match settle(
        dir,
        repo,
        &mut outcome,
        [ancestor, ours, theirs],
        resolutions,
        propose_into,
    )? {
        Settled::Clean(spent) => spent,
        Settled::Conflicted(paths, candidates) => return Ok(Step::Conflicted(paths, candidates)),
    };

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
    replayed.committer = stamped_in_utc(committer);
    replayed
        .extra_headers
        .retain(|(name, _)| name.as_slice() != b"gpgsig");
    let minted = repo
        .write_object(&replayed)
        .map_err(|err| anyhow::anyhow!("gitwrite: {original} will not rewrite: {err}"))?
        .detach();
    Ok(if resolved.is_empty() {
        Step::Landed(minted)
    } else {
        Step::Resolved(minted, resolved)
    })
}

/// What settling one merge's conflicts produced.
enum Settled {
    /// Nothing left unresolved: the paths whose offered resolution was spent,
    /// empty when the merge was clean.
    Clean(Vec<String>),
    /// The paths left unresolved, and a candidate per path when asked for one.
    Conflicted(Vec<String>, Vec<Candidate>),
}

/// Judge a merge outcome strictly, and place every offered resolution.
///
/// **ONE JUDGEMENT FOR BOTH SHAPES OF CATCHING UP (CLOUD-2054).** A replayed
/// commit and a merge of the moved base into a merge-carrying branch must stop
/// on exactly the same conflicts and take exactly the same `--resolve` offer, or
/// the conflict stop `land` prints would name a route that works for one shape
/// and not the other. So the judgement is this function, called by both.
///
/// `trees` is `[ancestor, ours, theirs]`, read only to write candidates.
fn settle(
    dir: &Path,
    repo: &gix::Repository,
    outcome: &mut gix::merge::tree::Outcome<'_>,
    trees: [gix::ObjectId; 3],
    resolutions: &std::collections::BTreeMap<String, std::path::PathBuf>,
    propose_into: Option<&Path>,
) -> Result<Settled> {
    // THE STRICTEST READING, and the module header says why: a lenient one would
    // let a resolution strategy quietly pick a side, which deletes the loop's
    // only human stop.
    let strict = gix::merge::tree::TreatAsUnresolved::forced_resolution();
    let mut resolved: Vec<String> = Vec::new();
    if outcome.has_unresolved_conflicts(strict) {
        let mut paths: Vec<String> = outcome
            .conflicts
            .iter()
            .filter(|conflict| conflict.is_unresolved(strict))
            .map(|conflict| conflict.ours.location().to_string())
            .collect();
        paths.sort_unstable();
        paths.dedup();

        // EVERY conflicting path must be named, never some of them. A partial
        // resolution would write a tree carrying the engine's own pick for the
        // paths the caller did not mention — the auto-resolution this module
        // exists to refuse, arrived at by omission rather than by a flag.
        if paths.is_empty() || !paths.iter().all(|path| resolutions.contains_key(path)) {
            let candidates = match propose_into {
                Some(into) => candidates(repo, trees, &paths, into)?,
                None => Vec::new(),
            };
            return Ok(Settled::Conflicted(paths, candidates));
        }

        for path in &paths {
            // Read the WORKTREE, which is where the caller did the work — at the
            // SOURCE this offer names, which is the path itself unless the caller
            // wrote `<path>=<file>` for this particular merge of it. A path that
            // will not read is an error rather than a conflict: the caller
            // asserted a resolution is there, and replaying their assertion as
            // "still conflicted" would hide the typo in a verdict.
            let source = resolutions
                .get(path)
                .map_or_else(|| std::path::PathBuf::from(path), Clone::clone);
            let bytes = std::fs::read(dir.join(&source)).map_err(|err| {
                anyhow::anyhow!(
                    "gitwrite: {path} carries no resolution to read at {}: {err}",
                    source.display()
                )
            })?;
            let blob = repo
                .write_blob(bytes)
                .map_err(|err| {
                    anyhow::anyhow!("gitwrite: {path}'s resolution will not write: {err}")
                })?
                .detach();
            outcome
                .tree
                .upsert(path.as_str(), gix::objs::tree::EntryKind::Blob, blob)
                .map_err(|err| {
                    anyhow::anyhow!("gitwrite: {path}'s resolution will not place: {err}")
                })?;
        }
        resolved = paths;
    }
    Ok(Settled::Clean(resolved))
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
    let mut gone: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    // A DELETED TREE IS A DIRECTORY, NOT A FILE (CLOUD-1948). The delta reports a
    // removed subtree as one Deletion at the directory's own path, and the loop
    // below used to hand that path to `remove_file` — `EISDIR`, and the error
    // returned before every later deletion, so a base that retired a directory
    // left the rest of what it deleted on disk as untracked files a reader could
    // commit straight back. Measured on #962's base: 50 files stranded.
    let mut gone_trees: Vec<Vec<u8>> = Vec::new();
    for change in &changes {
        let path = change.location().to_vec();
        match change {
            gix::object::tree::diff::ChangeDetached::Deletion { entry_mode, .. }
                if entry_mode.is_tree() =>
            {
                gone_trees.push(path);
            }
            gix::object::tree::diff::ChangeDetached::Deletion { .. } => {
                gone.insert(path);
            }
            _ => {
                touched.insert(path);
            }
        }
    }
    if touched.is_empty() && gone.is_empty() && gone_trees.is_empty() {
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
    // Every TRACKED file under a deleted tree is unlinked, read off the index this
    // clone already holds rather than off a directory walk: a walk would delete
    // whatever is under the path, and an untracked file there is the user's, not
    // the replay's. The delta may or may not also report each child — the set
    // makes that question moot.
    for tree in &gone_trees {
        let mut prefix = tree.clone();
        prefix.push(b'/');
        for path in held.keys() {
            if path.starts_with(&prefix) {
                gone.insert(path.clone());
            }
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
    // does not carry has to be unlinked, or a rebase that deletes a file leaves
    // it on disk and the next `verify` compiles a file that is not in the commit.
    remove_gone(&workdir, &gone, gone_trees)
}

/// Unlink every deleted path, then prune the directories the base deleted.
///
/// ONE UNREMOVABLE PATH DOES NOT STRAND THE REST. Every deletion is attempted and
/// the failures are reported together afterwards: returning on the first is what
/// left 50 files behind (CLOUD-1948), and a partial worktree is worse than a loud
/// one because it reads as the branch's own untracked work.
//MUTANT-SUITE crates/batten/tests/it/rebase.rs
//MUTANT gone-directory-left-on-disk|s@^    gone_trees.sort_by_key(\x7ctree\x7c std::cmp::Reverse(tree.len()));$@    gone_trees.clear();@|a_directory_the_base_deleted_leaves_the_worktree
fn remove_gone(
    workdir: &Path,
    gone: &std::collections::BTreeSet<Vec<u8>>,
    mut gone_trees: Vec<Vec<u8>>,
) -> Result<()> {
    let mut refused: Vec<String> = Vec::new();
    for path in gone {
        let Ok(relative) = std::str::from_utf8(path) else {
            continue;
        };
        let target = workdir.join(relative);
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => refused.push(format!("{relative}: {err}")),
        }
    }
    // Then the emptied directories, DEEPEST FIRST so a parent is only tried once
    // its children are gone. `remove_dir` and never `remove_dir_all`: a directory
    // still holding an untracked file keeps it, which is the user's file and not
    // this replay's to delete — so "not empty" is the honest outcome, not a fault.
    gone_trees.sort_by_key(|tree| std::cmp::Reverse(tree.len()));
    for tree in &gone_trees {
        let Ok(relative) = std::str::from_utf8(tree) else {
            continue;
        };
        match std::fs::remove_dir(workdir.join(relative)) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(err) => refused.push(format!("{relative}: {err}")),
        }
    }
    if let Some(first) = refused.first() {
        return Err(anyhow::anyhow!(
            "gitwrite: {} path(s) will not delete, first {first}",
            refused.len()
        ));
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
        // Same reason as the symlink arm, one step earlier: writing through an
        // existing link writes the target. Only a LINK is removed first; a
        // regular file is replaced atomically below, so a crash never leaves the
        // path missing or half-written.
        if std::fs::symlink_metadata(&target).is_ok_and(|meta| meta.file_type().is_symlink()) {
            std::fs::remove_file(&target)
                .map_err(|err| anyhow::anyhow!("gitwrite: {relative}: {err}"))?;
        }
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
        let mut bytes = Vec::new();
        std::io::copy(&mut converted, &mut bytes)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not filter: {err}"))?;
        crate::durable::replace(&target, bytes)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative} will not write: {err}"))?;
        // BOTH DIRECTIONS, EXPLICITLY. `durable::replace` keeps the replaced
        // file's permission bits, so a path going 100755 -> 100644 would stay
        // executable and disagree with the index it was just written from; the
        // remove-then-create path this replaced came back 0644 by accident.
        set_mode(&target, mode == gix::index::entry::Mode::FILE_EXECUTABLE)
            .map_err(|err| anyhow::anyhow!("gitwrite: {relative}'s mode: {err}"))?;
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
// repository claims to support. `rules/rust.md` states the convention
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
    crate::durable::replace(target, destination)
}

/// Set the executable bit.
#[cfg(unix)]
fn set_mode(target: &Path, executable: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))
}

/// There is no executable bit to set, and git does not synthesise one.
#[cfg(not(unix))]
fn set_mode(_target: &Path, _executable: bool) -> std::io::Result<()> {
    Ok(())
}

/// Make `dir` an empty repository whose `HEAD` names `main`, in-process.
///
/// The one place outside `seed` that initialises a repository, so `gix` stays
/// in the git modules (`gix_is_confined_to_the_git_modules`). `HEAD` is written
/// rather than left to `init.defaultBranch`, so a host's git settings cannot
/// change what a caller measures.
///
/// # Errors
///
/// A directory that will not initialise, or a `HEAD` that will not write.
pub fn init_on_main(dir: &Path) -> Result<()> {
    gix::init(dir).map_err(|err| {
        anyhow::anyhow!("gitwrite: could not initialise {}: {err}", dir.display())
    })?;
    crate::durable::replace(dir.join(".git/HEAD"), "ref: refs/heads/main\n").map_err(|err| {
        anyhow::anyhow!(
            "gitwrite: could not point {}'s HEAD at main: {err}",
            dir.display()
        )
    })
}

/// Commit exactly `paths` under `dir` on `HEAD`, and write the index from that
/// commit's tree — `git init` + `git add` + `git commit --allow-empty`, in-process.
///
/// **A LIST, NOT A WALK.** The caller names what is tracked; a directory walk
/// would hash whatever else lives there — a suite's build directory reached
/// 1.1 GB in `mutate`'s staged tree — and `.gitignore` is not something this
/// function should have to re-implement to avoid it.
///
/// **THE INDEX IS WRITTEN**, which is what `seed` does not do and why this is a
/// second function rather than a flag on it: a suite that asks git what is
/// tracked (`git ls-files`) reads the index, and a commit with no index reads as
/// every file deleted-and-untracked.
///
/// Re-runnable: an existing repository is opened and the new commit takes the
/// current `HEAD` as its parent, whether or not the tree changed.
///
/// # Errors
///
/// A directory that will not initialise or open, a file that will not read, an
/// object the odb refuses, or an index that will not write.
pub fn commit_paths(dir: &Path, paths: &[String], message: &str) -> Result<()> {
    let repo = if dir.join(".git").exists() {
        gix::open(dir)
            .map_err(|err| anyhow::anyhow!("gitwrite: could not open {}: {err}", dir.display()))?
    } else {
        gix::init(dir).map_err(|err| {
            anyhow::anyhow!("gitwrite: could not initialise {}: {err}", dir.display())
        })?
    };
    let mut root = Node::default();
    for path in paths {
        let full = dir.join(path);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let body = std::fs::read(&full)
            .map_err(|err| anyhow::anyhow!("gitwrite: cannot read {}: {err}", full.display()))?;
        let id = repo
            .write_blob(&body)
            .map_err(|err| anyhow::anyhow!("gitwrite: {path} will not write: {err}"))?
            .detach();
        root.insert(path, (executable_kind(&meta), id));
    }
    let tree = root.write(&repo)?;
    let parents: Vec<gix::ObjectId> = repo
        .head_id()
        .ok()
        .map(gix::Id::detach)
        .into_iter()
        .collect();
    let signature = gix::actor::Signature {
        name: "batten".into(),
        email: "batten@localhost".into(),
        time: gix::date::Time::now_utc(),
    };
    repo.commit_as(
        signature.to_ref(&mut gix::date::parse::TimeBuf::default()),
        signature.to_ref(&mut gix::date::parse::TimeBuf::default()),
        "HEAD",
        message,
        tree,
        parents,
    )
    .map_err(|err| anyhow::anyhow!("gitwrite: could not commit {}: {err}", dir.display()))?;
    repo.index_from_tree(&tree)
        .map_err(|err| anyhow::anyhow!("gitwrite: no index for {}: {err}", dir.display()))?
        .write(gix::index::write::Options::default())
        .map_err(|err| anyhow::anyhow!("gitwrite: the index will not write: {err}"))?;
    Ok(())
}

/// One directory level of a tree being assembled from a path list.
#[derive(Default)]
struct Node {
    files: std::collections::BTreeMap<String, (gix::objs::tree::EntryKind, gix::ObjectId)>,
    dirs: std::collections::BTreeMap<String, Node>,
}

impl Node {
    fn insert(&mut self, path: &str, blob: (gix::objs::tree::EntryKind, gix::ObjectId)) {
        match path.split_once('/') {
            Some((head, rest)) => self
                .dirs
                .entry(head.to_owned())
                .or_default()
                .insert(rest, blob),
            None => {
                self.files.insert(path.to_owned(), blob);
            }
        }
    }

    fn write(&self, repo: &gix::Repository) -> Result<gix::ObjectId> {
        let mut entries: Vec<gix::objs::tree::Entry> = Vec::new();
        for (name, (kind, oid)) in &self.files {
            entries.push(gix::objs::tree::Entry {
                mode: (*kind).into(),
                filename: name.as_str().into(),
                oid: *oid,
            });
        }
        for (name, child) in &self.dirs {
            entries.push(gix::objs::tree::Entry {
                mode: gix::objs::tree::EntryKind::Tree.into(),
                filename: name.as_str().into(),
                oid: child.write(repo)?,
            });
        }
        // GIT'S OWN ORDER: a tree entry sorts as its name with a trailing `/`,
        // so `a.rs` precedes the directory `a` only by that rule.
        entries.sort_by(|left, right| {
            let key = |entry: &gix::objs::tree::Entry| {
                let mut name = entry.filename.to_vec();
                if entry.mode.is_tree() {
                    name.push(b'/');
                }
                name
            };
            key(left).cmp(&key(right))
        });
        Ok(repo
            .write_object(gix::objs::Tree { entries })
            .map_err(|err| anyhow::anyhow!("gitwrite: a tree will not write: {err}"))?
            .detach())
    }
}

/// Give a directory a git repository carrying its current contents as one
/// commit.
///
/// **In-process, because CLOUD-740's terminal assertion holds.** Nothing in this
/// crate spawns `git`, and a benchmark fixture is no exception: the previous
/// shape ran `git init`, `git add -A` and `git commit` as three children, which
/// is three spawns of the one program the crate stopped invoking. The subject of
/// `bench tokens` is what a capability COSTS, and seeding its fixture is not
/// part of that measurement — so there is nothing here that must be an external
/// process.
///
/// **Whatever branch `HEAD` already names.** The reference is `HEAD` rather than
/// a literal `refs/heads/main`, so the commit lands on the branch `gix::init`
/// chose from the host's own config. No caller reads the name; what they need is
/// a repository root that resolves and a commit for `HEAD` to point at.
///
/// Idempotent: a directory that already carries `.git` is left alone.
///
/// # Errors
///
/// A directory that will not initialise, a file that will not read, or an object
/// the odb refuses.
pub fn seed(dir: &Path) -> Result<()> {
    if dir.join(".git").exists() {
        return Ok(());
    }
    let repo = gix::init(dir).map_err(|err| {
        anyhow::anyhow!("gitwrite: could not initialise {}: {err}", dir.display())
    })?;
    let tree = tree_from_dir(&repo, dir)?;
    let signature = gix::actor::Signature {
        name: "batten".into(),
        email: "batten@localhost".into(),
        time: gix::date::Time::now_utc(),
    };
    repo.commit_as(
        signature.to_ref(&mut gix::date::parse::TimeBuf::default()),
        signature.to_ref(&mut gix::date::parse::TimeBuf::default()),
        "HEAD",
        "fixture",
        tree,
        gix::commit::NO_PARENT_IDS,
    )
    .map_err(|err| anyhow::anyhow!("gitwrite: could not commit the fixture: {err}"))?;
    Ok(())
}

/// Write `dir`'s contents as a tree object, recursing into subdirectories.
///
/// `.git` is skipped: a repository's own store is not part of what it tracks,
/// and walking into it would hash every object twice.
fn tree_from_dir(repo: &gix::Repository, dir: &Path) -> Result<gix::ObjectId> {
    let mut entries: Vec<gix::objs::tree::Entry> = Vec::new();
    let listing = std::fs::read_dir(dir)
        .map_err(|err| anyhow::anyhow!("gitwrite: cannot read {}: {err}", dir.display()))?;
    for entry in listing {
        let entry = entry
            .map_err(|err| anyhow::anyhow!("gitwrite: cannot read {}: {err}", dir.display()))?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new(".git") {
            continue;
        }
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|err| anyhow::anyhow!("gitwrite: cannot stat {}: {err}", path.display()))?;
        let (mode, oid) = if meta.is_dir() {
            (
                gix::objs::tree::EntryKind::Tree,
                tree_from_dir(repo, &path)?,
            )
        } else {
            let body = std::fs::read(&path).map_err(|err| {
                anyhow::anyhow!("gitwrite: cannot read {}: {err}", path.display())
            })?;
            let id = repo
                .write_blob(&body)
                .map_err(|err| {
                    anyhow::anyhow!("gitwrite: {} will not write: {err}", path.display())
                })?
                .detach();
            (executable_kind(&meta), id)
        };
        entries.push(gix::objs::tree::Entry {
            mode: mode.into(),
            filename: name.to_string_lossy().as_ref().into(),
            oid,
        });
    }
    // GIT'S OWN ORDER, which the odb does not impose: an unsorted tree hashes to
    // an id no other reader agrees with.
    entries.sort_by(|left, right| left.filename.cmp(&right.filename));
    Ok(repo
        .write_object(gix::objs::Tree { entries })
        .map_err(|err| anyhow::anyhow!("gitwrite: the fixture tree will not write: {err}"))?
        .detach())
}

/// A file's blob kind, which is its executable bit and nothing else.
#[cfg(unix)]
fn executable_kind(meta: &std::fs::Metadata) -> gix::objs::tree::EntryKind {
    use std::os::unix::fs::PermissionsExt as _;
    if meta.permissions().mode() & 0o111 == 0 {
        gix::objs::tree::EntryKind::Blob
    } else {
        gix::objs::tree::EntryKind::BlobExecutable
    }
}

/// On a platform with no executable bit, every blob is a plain one — which is
/// what git itself records there.
#[cfg(not(unix))]
fn executable_kind(_meta: &std::fs::Metadata) -> gix::objs::tree::EntryKind {
    gix::objs::tree::EntryKind::Blob
}

/// The conflict-marker width, as the merge driver takes it.
const MARKER_SIZE: std::num::NonZeroU8 = match std::num::NonZeroU8::new(crate::propose::MARKER) {
    Some(size) => size,
    None => unreachable!(),
};

/// The three-way text merge with every conflict kept as diff3 markers, or
/// `None` for a merge with no conflict or bytes that are not UTF-8 (CLOUD-1956).
///
/// Here rather than in `propose` because the git backend is confined to the git
/// modules; `propose` reads the markers as plain text.
#[must_use]
pub fn diff3(ancestor: &[u8], ours: &[u8], theirs: &[u8]) -> Option<String> {
    use gix::merge::blob::builtin_driver::text;
    let mut out = Vec::new();
    let mut input = gix_diff::blob::InternedInput::default();
    let options = text::Options {
        conflict: text::Conflict::Keep {
            style: text::ConflictStyle::Diff3,
            marker_size: MARKER_SIZE,
        },
        ..Default::default()
    };
    let resolution = gix::merge::blob::builtin_driver::text(
        &mut out,
        &mut input,
        text::Labels::default(),
        ours,
        ancestor,
        theirs,
        options,
    );
    if resolution != gix::merge::blob::Resolution::Conflict {
        return None;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replay that moves a path from 100755 to 100644 must leave it 0644:
    /// `durable::replace` keeps the replaced file's bits, so a mode set in one
    /// direction only left the worktree executable where the index said not.
    #[test]
    fn a_path_leaving_the_executable_mode_loses_the_bit() {
        let dir = std::env::temp_dir().join(format!("batten-gitwrite-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("fixture dir: {err}"));
        let path = dir.join("tool");
        std::fs::write(&path, "x").unwrap_or_else(|err| panic!("fixture file: {err}"));
        set_mode(&path, true).unwrap_or_else(|err| panic!("to 755: {err}"));
        set_mode(&path, false).unwrap_or_else(|err| panic!("to 644: {err}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .unwrap_or_else(|err| panic!("stat: {err}"))
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
