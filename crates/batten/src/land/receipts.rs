//! Published receipts (CLOUD-1544): every proof a gate mints, carried off the
//! container that minted it, to the private state repository.
//!
//! # Why this module exists
//!
//! A receipt lives on one disk. A reclaimed container takes every verify, step,
//! claim and spent-override receipt with it, and the next session re-runs every
//! gate from nothing — measured on 2026-11-24 as 34 cloud sessions re-deriving
//! the same proofs. [`publish`] carries them to a ref in the state repository and
//! [`pull`] brings them back into a fresh checkout, where
//! [`crate::receipt::published_validity`] judges them by what they bind rather
//! than by the checkout that minted them.
//!
//! # Where they go, and where they never go
//!
//! **The remote is the state repository, never origin** (owner ruling,
//! 2026-11-24): receipts are session data and session data is private. The remote
//! is derived as CLOUD-2718 derives it — the project origin's scheme and host,
//! with the path replaced by [`crate::session::STATE_REPO_ENV`] — so no host and
//! no repository name is spelled in the core (non-negotiable rule 1). Unset is
//! inert: [`state_remote`] answers [`Remote::Off`] before it derives anything,
//! and neither verb makes a call or writes a file.
//!
//! The ref is `refs/heads/batten/receipts/<branch>`, one per branch, so sessions
//! on different branches never race one compare-and-swap. `refs/heads` because
//! the agent proxy refuses a push anywhere else (`lease.rs`'s own header).
//!
//! # One parentless commit, never a chain
//!
//! Each publish fetches the ref, unions its tree with the local set, mints a
//! PARENTLESS commit over that union and swaps it in against the head it
//! observed. A lost swap re-fetches and re-unions. Never a chain: each publish
//! orphans the last, and the remote's gc reaps it, so the ref's size is the live
//! set's and not its history's.
//!
//! # What is carried, and what is not
//!
//! The line is re-derivation cost (the row's own): a statement receipt from the
//! canonical store, a step, claim or head-keyed compatibility receipt from
//! `$GIT_DIR/batten-receipts/`, and a SPENT override record. Never a journal,
//! capture or `issue-read` receipt, which cost one re-scan or one tracker call.
//! Never `step.batten-check.*`: its key is input files and its verdict depends
//! on remote state (CLOUD-725), so sharing it would make that defect fleet-wide.
//! The same filter is applied to what [`pull`] reads, so a blob a producer
//! should not have published is never materialised either.
//!
//! # Placement
//!
//! A submodule of `land`, because it is `lease`'s consumer exactly as `land` is:
//! `policy/module-layering.rego` already refuses `hook -> land` and
//! `check -> land`, so no mediated call can come to reach the network through
//! it. `receipt` gains only the validity arm and never an edge to `lease`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;

use crate::error::UsageError;
use crate::lease::{self, Object, Outcome, Service, Update, ZERO};

/// The ref namespace every branch's receipt set lives under, in the state
/// repository.
pub const REF_PREFIX: &str = "refs/heads/batten/receipts/";

/// How many lost compare-and-swaps a publish absorbs before it reports.
///
/// A COUNT, never a clock. Each loss means another session published in the
/// window between a fetch and a swap, and each retry re-unions what it wrote, so
/// a small bound is enough for any fleet that is not publishing to one branch in
/// a tight loop.
const CAS_TRIES: usize = 4;

/// The three directories of a published tree.
const STATEMENT: &str = "statement";
/// `$GIT_DIR/batten-receipts/` files, by name.
const COMPAT: &str = "compat";
/// Spent override records, by name.
const OVERRIDE: &str = "override";

/// Where the state repository is, as this machine sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    /// [`crate::session::STATE_REPO_ENV`] is unset or empty: the feature is off.
    Off,
    /// The variable is set and the project has no `http(s)` origin to derive
    /// the remote from.
    NoHttpOrigin,
    /// The state repository's smart-HTTP URL.
    At(String),
}

/// The state repository's URL: `origin`'s scheme and host, with the path
/// replaced by `value`.
///
/// Carried from 03d50c20 (CLOUD-2718's `offbox::remote_for`) so the two
/// derivations cannot disagree. `None` where `origin` is not `http(s)` or names
/// no host. Any userinfo the origin carries is dropped — the credential is the
/// transport's to attach, and one copied out of a clone's config would travel
/// into every error line that names the remote.
#[must_use]
pub fn remote_for(origin: &str, value: &str) -> Option<String> {
    let (scheme, rest) = origin.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}/{}", value.trim_matches('/')))
}

/// Resolve the state repository from the variable's value and the origin.
///
/// Both passed in, so the decision is a pure function of them: unset decides
/// before anything is derived.
#[must_use]
pub fn state_remote(value: Option<&str>, origin: Option<&str>) -> Remote {
    let value = value.map(str::trim).unwrap_or_default();
    if value.is_empty() {
        return Remote::Off;
    }
    origin
        .and_then(|origin| remote_for(origin, value))
        .map_or(Remote::NoHttpOrigin, Remote::At)
}

/// The ref a branch's receipt set lives at, or a usage error for a branch name
/// git would refuse.
///
/// # Errors
///
/// [`UsageError`] when `branch` does not make a valid ref name.
pub fn reference(branch: &str) -> Result<String> {
    let name = format!("{REF_PREFIX}{branch}");
    gix::refs::FullName::try_from(name.as_str()).map_err(|_| {
        UsageError::raise(format!(
            "receipt: `{branch}` does not make a valid ref name for the receipt set"
        ))
    })?;
    Ok(name)
}

/// Whether `name` is lowercase hex of exactly `len` characters.
fn is_hex(name: &str, len: usize) -> bool {
    name.len() == len
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a file name is one segment a tree entry and a path join both read as
/// that file: no separator, no traversal, nothing hidden.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// Whether a `$GIT_DIR/batten-receipts/` file is carried.
///
/// A step receipt (never `batten-check`'s, CLOUD-725), a branch-keyed claim, or
/// a head-keyed compatibility receipt `<check>.<sha>`. Everything else in that
/// directory — read receipts, punts, histories — costs one call to re-derive
/// and stays local.
fn carried_compat(name: &str) -> bool {
    if !plain(name) {
        return false;
    }
    if name.starts_with("step.") {
        return !name.starts_with("step.batten-check.");
    }
    if name.starts_with("claim.") {
        return true;
    }
    name.rsplit_once('.')
        .is_some_and(|(check, sha)| !check.is_empty() && is_hex(sha, 40))
}

/// The name a statement is published under: `<fingerprint>.<subject>.json`,
/// both halves content keys, so two receipts for one check at two heads are two
/// blobs and a union keeps both.
fn statement_name(statement: &crate::receipt::Statement) -> Option<String> {
    let fingerprint = &statement.predicate.identity.fingerprint;
    let subject = &statement.subject.first()?.digest.git_commit;
    (is_hex(fingerprint, 64) && is_hex(subject, 40))
        .then(|| format!("{fingerprint}.{subject}.json"))
}

/// Whether an override record is spent — the only state carried, because an
/// ISSUED record pulled into a second container would be spendable twice.
fn spent(bytes: &[u8]) -> bool {
    serde_json::from_slice::<crate::admission::Record>(bytes)
        .is_ok_and(|record| record.state == crate::admission::State::Spent)
}

/// The top-level files of `dir`, by name; an absent directory is an empty set.
fn files(dir: &Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<_> = entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| Some((entry.file_name().into_string().ok()?, entry.path())))
        .collect();
    found.sort();
    found
}

/// The receipt set this checkout holds, as `<kind>/<name>` to bytes.
///
/// `receipts_dir` is the canonical store (`<state>/receipts`) and `compat_dir`
/// is `$GIT_DIR/batten-receipts`. A file that cannot be read or parsed is left
/// out rather than refused: one unreadable receipt must not stop the rest
/// travelling, and it would read `Missing` wherever it landed.
#[must_use]
pub fn local_set(receipts_dir: &Path, compat_dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut set = BTreeMap::new();
    for (name, path) in files(receipts_dir) {
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(statement) = serde_json::from_slice::<crate::receipt::Statement>(&bytes) else {
            continue;
        };
        if let Some(key) = statement_name(&statement) {
            set.insert(format!("{STATEMENT}/{key}"), bytes);
        }
    }
    for (name, path) in files(&receipts_dir.join("overrides")) {
        if !plain(&name) {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path)
            && spent(&bytes)
        {
            set.insert(format!("{OVERRIDE}/{name}"), bytes);
        }
    }
    for (name, path) in files(compat_dir) {
        if carried_compat(&name)
            && let Ok(bytes) = std::fs::read(&path)
        {
            set.insert(format!("{COMPAT}/{name}"), bytes);
        }
    }
    set
}

/// Whether a published path is one this module would have written: the filter
/// [`local_set`] applies, applied again to what a remote hands back.
fn admissible(path: &str, bytes: &[u8]) -> bool {
    let Some((kind, name)) = path.split_once('/') else {
        return false;
    };
    match kind {
        STATEMENT => {
            serde_json::from_slice::<crate::receipt::Statement>(bytes)
                .ok()
                .and_then(|statement| statement_name(&statement))
                .as_deref()
                == Some(name)
        }
        OVERRIDE => plain(name) && spent(bytes),
        COMPAT => carried_compat(name),
        _ => false,
    }
}

/// Hash and serialise one object.
fn object(kind: gix::object::Kind, body: Vec<u8>) -> Result<Object> {
    let id = gix::objs::compute_hash(gix::hash::Kind::Sha1, kind, &body)
        .map_err(|err| anyhow::anyhow!("receipt: an object will not hash: {err}"))?;
    Ok(Object {
        id: id.to_string(),
        kind,
        body,
    })
}

/// One tree over `entries`, already in git's order.
fn tree(entries: Vec<gix::objs::tree::Entry>) -> Result<Object> {
    use gix::objs::WriteTo as _;

    let mut body = Vec::new();
    gix::objs::Tree { entries }
        .write_to(&mut body)
        .map_err(|err| anyhow::anyhow!("receipt: a tree will not serialise: {err}"))?;
    object(gix::object::Kind::Tree, body)
}

/// The objects a set is published as: one blob per receipt, one tree per kind,
/// and the root tree LAST, so the caller reads its id off the end.
///
/// # Errors
///
/// An object that will not serialise or hash.
pub fn tree_objects(set: &BTreeMap<String, Vec<u8>>) -> Result<Vec<Object>> {
    let mut objects = Vec::new();
    let mut kinds: BTreeMap<&str, Vec<gix::objs::tree::Entry>> = BTreeMap::new();
    for (path, bytes) in set {
        let Some((kind, name)) = path.split_once('/') else {
            continue;
        };
        let blob = object(gix::object::Kind::Blob, bytes.clone())?;
        kinds.entry(kind).or_default().push(gix::objs::tree::Entry {
            mode: gix::objs::tree::EntryKind::Blob.into(),
            filename: name.into(),
            oid: gix::hash::ObjectId::from_hex(blob.id.as_bytes())?,
        });
        objects.push(blob);
    }
    let mut root = Vec::new();
    // Every root entry is a tree and every kind tree holds only blobs, so plain
    // byte order IS git's order at both levels: the `/` git appends to a tree's
    // name for sorting moves nothing among names that are all trees.
    for (kind, entries) in kinds {
        let sub = tree(entries)?;
        root.push(gix::objs::tree::Entry {
            mode: gix::objs::tree::EntryKind::Tree.into(),
            filename: kind.into(),
            oid: gix::hash::ObjectId::from_hex(sub.id.as_bytes())?,
        });
        objects.push(sub);
    }
    objects.push(tree(root)?);
    Ok(objects)
}

/// The identity a receipt-set commit is authored by — pinned, for
/// `lease::lease_object`'s reason: a commit nobody authored and nothing merges.
const AUTHOR_NAME: &str = "batten";
/// The email half of [`AUTHOR_NAME`].
const AUTHOR_EMAIL: &str = "batten@localhost";

/// Mint the receipt-set commit over `root`.
///
/// **Parentless**, which is the property the row's mutation guards: a chain
/// would make the ref carry every set ever published, and the gc that reaps an
/// orphan could reap nothing. `observed` — the head this commit replaces — is
/// named in the message, so a reader of the ref can see the succession the
/// parent list deliberately does not carry.
///
/// # Errors
///
/// A commit that will not serialise or hash.
pub fn commit_over(root: &Object, count: usize, observed: &str, seconds: i64) -> Result<Object> {
    use gix::objs::WriteTo as _;

    let who = gix::actor::Signature {
        name: AUTHOR_NAME.into(),
        email: AUTHOR_EMAIL.into(),
        time: crate::git::utc_at(seconds),
    };
    let commit = gix::objs::Commit {
        tree: gix::hash::ObjectId::from_hex(root.id.as_bytes())?,
        parents: std::iter::empty().collect(),
        author: who.clone(),
        committer: who,
        encoding: None,
        message: format!("batten receipts: {count} published\n\nreplaces {observed}\n").into(),
        extra_headers: Vec::new(),
    };
    let mut body = Vec::new();
    commit
        .write_to(&mut body)
        .map_err(|err| anyhow::anyhow!("receipt: the commit will not serialise: {err}"))?;
    object(gix::object::Kind::Commit, body)
}

/// What the remote's ref holds: its head and its set.
struct Held {
    /// The head the ref reads, or [`ZERO`] when it does not exist.
    head: String,
    /// The root tree's id, or empty when there is no ref.
    root: String,
    /// The set, filtered by [`admissible`].
    set: BTreeMap<String, Vec<u8>>,
}

/// An object's body, from the fetched pack or, where the odb already had it,
/// from the odb.
fn body_of(
    fetched: &BTreeMap<String, Object>,
    repo: &Path,
    id: &str,
    kind: gix::object::Kind,
) -> Result<Vec<u8>> {
    if let Some(found) = fetched.get(id) {
        if found.kind != kind {
            return Err(anyhow::anyhow!(
                "receipt: {id} is a {} where a {kind} was expected",
                found.kind
            ));
        }
        return Ok(found.body.clone());
    }
    let opened = crate::git::open_fresh(repo)?;
    let oid = gix::hash::ObjectId::from_hex(id.as_bytes())?;
    let found = opened.find_object(oid).map_err(|err| {
        anyhow::anyhow!("receipt: {id} is in neither the answer nor the odb: {err}")
    })?;
    if found.kind != kind {
        return Err(anyhow::anyhow!(
            "receipt: {id} is a {} where a {kind} was expected",
            found.kind
        ));
    }
    Ok(found.data.clone())
}

/// The entries of a tree body, as `(name, id, is_tree)`.
fn entries(body: &[u8]) -> Result<Vec<(String, String, bool)>> {
    let tree = gix::objs::TreeRef::from_bytes(body, gix::hash::Kind::Sha1)
        .map_err(|err| anyhow::anyhow!("receipt: a tree will not parse: {err}"))?;
    Ok(tree
        .entries
        .iter()
        .map(|entry| {
            (
                entry.filename.to_string(),
                entry.oid.to_string(),
                entry.mode.is_tree(),
            )
        })
        .collect())
}

/// Read what `remote` holds at `name`, fetching into `repo`'s transport.
fn held(remote: &str, repo: &Path, name: &str) -> Result<Held> {
    let advertised = lease::advertise(remote, Service::UploadPack)?;
    if advertised.head_of(name) == ZERO {
        return Ok(Held {
            head: ZERO.to_owned(),
            root: String::new(),
            set: BTreeMap::new(),
        });
    }
    let fetched = lease::fetch(remote, repo, name)?;
    let objects: BTreeMap<String, Object> = fetched
        .objects
        .into_iter()
        .map(|object| (object.id.clone(), object))
        .collect();
    let commit = body_of(&objects, repo, &fetched.head, gix::object::Kind::Commit)?;
    let root = gix::objs::CommitRef::from_bytes(&commit, gix::hash::Kind::Sha1)
        .map_err(|err| anyhow::anyhow!("receipt: the published commit will not parse: {err}"))?
        .tree()
        .to_string();
    let mut set = BTreeMap::new();
    for (kind, id, is_tree) in entries(&body_of(&objects, repo, &root, gix::object::Kind::Tree)?)? {
        if !is_tree {
            continue;
        }
        for (name, blob, nested) in
            entries(&body_of(&objects, repo, &id, gix::object::Kind::Tree)?)?
        {
            if nested {
                continue;
            }
            let path = format!("{kind}/{name}");
            let bytes = body_of(&objects, repo, &blob, gix::object::Kind::Blob)?;
            if admissible(&path, &bytes) {
                set.insert(path, bytes);
            }
        }
    }
    Ok(Held {
        head: fetched.head,
        root,
        set,
    })
}

/// What a publish or a pull did, as pointers: the ref, the commit it reads, and
/// a count. Never a receipt body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The ref in the state repository.
    pub reference: String,
    /// The commit the ref reads afterwards, or [`ZERO`] when there is none.
    pub commit: String,
    /// Receipts published (the set's size) or pulled (files written).
    pub count: usize,
}

/// Publish `local` to `name` on `remote`, unioned with what is already there.
///
/// `repo` is the checkout whose odb the fetch negotiates from; nothing is
/// written into it. A set the remote already holds whole is not pushed again:
/// the same tree under a new commit would move the ref for no new fact.
///
/// # Errors
///
/// A transport failure (could-not-look, exit `3`), or [`CAS_TRIES`] swaps lost
/// in a row.
pub fn publish(
    remote: &str,
    repo: &Path,
    name: &str,
    local: &BTreeMap<String, Vec<u8>>,
    seconds: i64,
) -> Result<Moved> {
    for _ in 0..CAS_TRIES {
        let theirs = held(remote, repo, name)?;
        let mut union = theirs.set;
        // Local wins a name both hold: every name is content-keyed but a
        // claim's and a compatibility receipt's, and for those this checkout's
        // reading is the newer one.
        union.extend(
            local
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.clone())),
        );
        let mut objects = tree_objects(&union)?;
        let root = objects
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("receipt: a tree set with no root"))?;
        if root.id == theirs.root {
            return Ok(Moved {
                reference: name.to_owned(),
                commit: theirs.head,
                count: union.len(),
            });
        }
        let commit = commit_over(&root, union.len(), &theirs.head, seconds)?;
        let new = commit.id.clone();
        objects.push(commit);
        let pack = lease::pack_of(&objects)?;
        let update = Update {
            old: theirs.head,
            new: new.clone(),
            name: name.to_owned(),
        };
        match lease::swap(remote, &update, &pack)? {
            Outcome::Applied => {
                return Ok(Moved {
                    reference: name.to_owned(),
                    commit: new,
                    count: union.len(),
                });
            }
            Outcome::Rejected { .. } => {}
        }
    }
    Err(anyhow::anyhow!(
        "receipt publish: {name} moved under each of {CAS_TRIES} swaps; run it again"
    ))
}

/// Where a pulled receipt is materialised, and whether it is written.
///
/// A statement for `head` goes to the published store, replacing what is there
/// (it is the published store, never a local mint). A compatibility file or an
/// override goes where its local twin lives, and only where none is: a local
/// file is this checkout's own reading and a pulled one never displaces it —
/// except an ISSUED override a pulled SPENT one supersedes, which is the
/// direction that can only refuse a re-spend.
fn destination(
    path: &str,
    receipts_dir: &Path,
    compat_dir: &Path,
    head: &str,
) -> Option<std::path::PathBuf> {
    let (kind, name) = path.split_once('/')?;
    match kind {
        STATEMENT => {
            let (fingerprint, rest) = name.split_once('.')?;
            (rest == format!("{head}.json")).then(|| {
                receipts_dir
                    .join(crate::receipt::PUBLISHED_DIR)
                    .join(format!("{fingerprint}.json"))
            })
        }
        COMPAT => {
            let target = compat_dir.join(name);
            (!target.exists()).then_some(target)
        }
        OVERRIDE => {
            let target = receipts_dir.join("overrides").join(name);
            let local = std::fs::read(&target).ok();
            local.is_none_or(|bytes| !spent(&bytes)).then_some(target)
        }
        _ => None,
    }
}

/// Pull `name` from `remote` into this checkout's stores.
///
/// # Errors
///
/// A transport failure (could-not-look, exit `3`), or a store that cannot be
/// written.
pub fn pull(
    remote: &str,
    repo: &Path,
    name: &str,
    receipts_dir: &Path,
    compat_dir: &Path,
    head: &str,
) -> Result<Moved> {
    let theirs = held(remote, repo, name)?;
    let mut count = 0;
    for (path, bytes) in &theirs.set {
        let Some(target) = destination(path, receipts_dir, compat_dir, head) else {
            continue;
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::durable::replace(&target, bytes)?;
        count += 1;
    }
    Ok(Moved {
        reference: name.to_owned(),
        commit: theirs.head,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_is_off_before_any_origin_is_read() {
        assert_eq!(state_remote(None, Some("https://h/o/r")), Remote::Off);
        assert_eq!(state_remote(Some("  "), None), Remote::Off);
    }

    #[test]
    fn the_remote_is_the_origins_host_with_the_state_path() {
        assert_eq!(
            state_remote(Some("o/state"), Some("https://u:p@h.example/o/r")),
            Remote::At("https://h.example/o/state".to_owned())
        );
        assert_eq!(
            state_remote(Some("o/state"), Some("/srv/git/r.git")),
            Remote::NoHttpOrigin
        );
    }

    #[test]
    fn batten_checks_step_receipt_never_travels() {
        assert!(carried_compat("step.cargo-test.abc"));
        assert!(!carried_compat("step.batten-check.abc"));
        assert!(carried_compat("claim.feat-x"));
        assert!(carried_compat(&format!("verify.{}", "a".repeat(40))));
        assert!(!carried_compat("issue-read.CLOUD-1"));
        assert!(!carried_compat("../claim.x"));
    }
}
