//! Writes to a local git repository: loose objects, and refs.
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
