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
/// Step receipts from `$GIT_DIR/batten-records/step-receipts/<group>/<key>`,
/// as `<group>.<key>`: both halves digests, so the name is a content key
/// (CLOUD-2784's layout; CLOUD-2789's manual carry moved exactly these).
const STEP: &str = "step";
/// The producer of every other entry, as `<kind>.<name>` holding one
/// `Name <email>` line (row §5): the accountable identity from `[attribution]`
/// that published it, so a consumer policy can narrow which producers it
/// honours before signing lands (CLOUD-877).
const PRODUCER: &str = "producer";

/// Where the state repository is, as this machine sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    /// [`crate::session::STATE_REPO_ENV`] is unset or empty: the feature is off.
    Off,
    /// The variable is set and the project has no `http(s)` origin to derive
    /// the remote from.
    NoHttpOrigin,
    /// The variable names the SAME repository as origin, under some spelling —
    /// case, a `.git` suffix, a URL or an origin-host prefix. Refused: receipts
    /// are session data and session data never reaches origin (owner ruling,
    /// 2026-11-24), and an equal-by-normalisation target is origin.
    IsOrigin,
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

/// A repository URL's `(host, path)`, normalised for comparison: host
/// lowercased with any userinfo dropped, path lowercased with surrounding `/`
/// and any `.git` suffix removed. `http(s)` URLs and scp-style `user@host:path`
/// both parse; a bare local path is `None`.
fn repository_of(url: &str) -> Option<(String, String)> {
    let url = url.trim();
    let (authority, path) = if let Some((_, rest)) = url.split_once("://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        (authority, path)
    } else {
        // scp-style: a `:` before any `/`.
        let (authority, path) = url.split_once(':')?;
        if authority.contains('/') {
            return None;
        }
        (authority, path)
    };
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), normal_path(path)))
}

/// A repository path, lowercased, without query, fragment, surrounding `/` or
/// any `.git` suffix — the spellings a forge resolves to one repository.
fn normal_path(path: &str) -> String {
    let mut path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    loop {
        let trimmed = path.trim_matches('/');
        let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        if trimmed.len() == path.len() {
            return path;
        }
        path = trimmed.to_owned();
    }
}

/// Whether the variable's `value` names `origin`'s own repository, in any
/// spelling: the bare path, a case variant, a `.git` suffix, a full URL, an
/// scp form, or the path prefixed with origin's host.
///
/// Conservative by design: a refusal here costs one misconfigured publish, and
/// a miss pushes session data to origin.
#[must_use]
pub fn names_origin(origin: &str, value: &str) -> bool {
    let Some((host, path)) = repository_of(origin) else {
        return false;
    };
    let value = value.trim();
    let mut candidates = vec![normal_path(value)];
    if let Some((_, named)) = repository_of(value) {
        candidates.push(named);
    }
    // `host/owner/name`, with or without a port on either side.
    let bare_host = host.split(':').next().unwrap_or_default().to_owned();
    for candidate in candidates.clone() {
        if let Some((first, rest)) = candidate.split_once('/')
            && (first == host || first.split(':').next() == Some(bare_host.as_str()))
        {
            candidates.push(normal_path(rest));
        }
    }
    candidates.contains(&path)
}

/// Resolve the state repository from the variable's value and the origin.
///
/// Both passed in, so the decision is a pure function of them: unset decides
/// before anything is derived, and a value naming origin's own repository is
/// [`Remote::IsOrigin`] before any URL is formed — compared on the value AND on
/// the derived remote, so no spelling routes around the check.
#[must_use]
pub fn state_remote(value: Option<&str>, origin: Option<&str>) -> Remote {
    let value = value.map(str::trim).unwrap_or_default();
    if value.is_empty() {
        return Remote::Off;
    }
    let Some(origin) = origin else {
        return Remote::NoHttpOrigin;
    };
    let Some(remote) = remote_for(origin, value) else {
        return Remote::NoHttpOrigin;
    };
    if names_origin(origin, value) || repository_of(&remote) == repository_of(origin) {
        return Remote::IsOrigin;
    }
    Remote::At(remote)
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

/// The claim receipt `branch` keys — `claim`'s own spelling, so the filter and
/// the writer cannot disagree.
fn claim_of(branch: &str) -> String {
    crate::claim::receipt_name(branch)
}

/// Whether a `$GIT_DIR/batten-receipts/` file is carried on the ref whose
/// branch's claim is `claim`.
///
/// A step receipt (never `batten-check`'s, CLOUD-725), THIS branch's claim, or
/// a head-keyed compatibility receipt `<check>.<sha>`. Everything else in that
/// directory — read receipts, punts, histories — costs one call to re-derive
/// and stays local.
///
/// **Only this branch's claim.** Another branch's claim is that branch's
/// state: carried here, a `claim --adopt-from` that moved and deleted it would
/// see the next pull write it back, so the published set could only grow. The
/// same filter on what [`pull`] and [`publish`] read off the ref drops one an
/// older engine published, so the next publish prunes it.
fn carried_compat(name: &str, claim: &str) -> bool {
    if !plain(name) {
        return false;
    }
    if name.starts_with("step.") {
        return !name.starts_with("step.batten-check.");
    }
    if name.starts_with("claim.") {
        return name == claim;
    }
    name.rsplit_once('.')
        .is_some_and(|(check, sha)| !check.is_empty() && is_hex(sha, 40))
}

/// The step-receipt group `batten-check` files under, which never travels: its
/// key is input files and its verdict depends on remote state (CLOUD-725).
fn batten_check_group() -> String {
    crate::tools::digest(b"batten-check")
}

/// Whether `<group>.<key>` names a carried step receipt.
fn carried_step(name: &str) -> bool {
    name.split_once('.').is_some_and(|(group, key)| {
        is_hex(group, 32) && is_hex(key, 32) && group != batten_check_group()
    })
}

/// The directories of `dir`, by name; an absent directory is an empty set.
fn dirs(dir: &Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<_> = entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| Some((entry.file_name().into_string().ok()?, entry.path())))
        .collect();
    found.sort();
    found
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

/// Where one checkout keeps what is carried: every path [`local_set`],
/// [`pull`] and the mutate carry read or write, resolved once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stores {
    /// The canonical statement store, `<state>/receipts`.
    pub receipts: std::path::PathBuf,
    /// `$GIT_DIR/batten-receipts`: step-era compatibility files and claims.
    pub compat: std::path::PathBuf,
    /// `$GIT_DIR/batten-records/step-receipts`: the grouped step receipts.
    pub steps: std::path::PathBuf,
    /// The schema mirror's state, `<state>/mutate/schema`: the verdict journal
    /// and the reach record.
    pub mutate: std::path::PathBuf,
}

// Built by [`crate::receipt_stores`], at the crate root: the step store's
// path is `record`'s and `step`'s to name, and this module reaching either
// would put it in their reach for two constants (CLOUD-2789, the modules
// ratchet's 5268 -> 5277 at 9bc54081c).

/// The receipt set this checkout holds, as `<kind>/<name>` to bytes.
///
/// `branch` is the branch the set is published for, whose claim alone travels.
/// A file that cannot be read or parsed is left out rather than refused: one
/// unreadable receipt must not stop the rest travelling, and it would read
/// `Missing` wherever it landed.
#[must_use]
pub fn local_set(stores: &Stores, branch: &str) -> BTreeMap<String, Vec<u8>> {
    let receipts_dir = stores.receipts.as_path();
    let compat_dir = stores.compat.as_path();
    let claim = claim_of(branch);
    let mut set = BTreeMap::new();
    for (name, path) in files(receipts_dir) {
        if !Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
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
        if carried_compat(&name, &claim)
            && let Ok(bytes) = std::fs::read(&path)
        {
            set.insert(format!("{COMPAT}/{name}"), bytes);
        }
    }
    for (group, dir) in dirs(&stores.steps) {
        for (key, path) in files(&dir) {
            let name = format!("{group}.{key}");
            if carried_step(&name)
                && let Ok(bytes) = std::fs::read(&path)
            {
                set.insert(format!("{STEP}/{name}"), bytes);
            }
        }
    }
    set
}

/// Whether a producer blob is one line naming an identity.
fn producer_line(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        let line = text.strip_suffix('\n').unwrap_or(text);
        !line.trim().is_empty()
            && !line.contains('\n')
            && line.contains(" <")
            && line.ends_with('>')
    })
}

/// The producer entry's path for a receipt's `<kind>/<name>`.
fn producer_path(path: &str) -> Option<String> {
    let (kind, name) = path.split_once('/')?;
    (kind != PRODUCER).then(|| format!("{PRODUCER}/{kind}.{name}"))
}

/// Keep only receipts that carry a producer, and producers whose receipt is
/// present: row §5's "on every published blob", enforced on both what is
/// read and what is written, so a blob with no accountable producer neither
/// travels nor lands.
fn paired(mut set: BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    let present: std::collections::BTreeSet<String> = set.keys().cloned().collect();
    set.retain(|path, _| {
        path.starts_with("producer/")
            || producer_path(path).is_some_and(|producer| present.contains(&producer))
    });
    let wanted: std::collections::BTreeSet<String> =
        set.keys().filter_map(|path| producer_path(path)).collect();
    set.retain(|path, _| !path.starts_with("producer/") || wanted.contains(path));
    set
}

/// `local` with every receipt's producer entry set to `producer`.
///
/// # Errors
///
/// A [`UsageError`] when `producer` is not one `Name <email>` line: a set
/// published with no accountable producer is the one this row refuses.
pub fn produced_by(
    local: &BTreeMap<String, Vec<u8>>,
    producer: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let line = format!("{}\n", producer.trim());
    if !producer_line(line.as_bytes()) {
        return Err(UsageError::raise(
            "receipt publish: no accountable producer identity ([attribution])",
        ));
    }
    let mut set = BTreeMap::new();
    for (path, bytes) in local {
        let Some(producer) = producer_path(path) else {
            continue;
        };
        set.insert(path.clone(), bytes.clone());
        set.insert(producer, line.clone().into_bytes());
    }
    Ok(set)
}

/// Whether a published path is one this module would have written: the filter
/// [`local_set`] applies, applied again to what a remote hands back.
fn admissible(path: &str, bytes: &[u8], claim: &str) -> bool {
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
        COMPAT => carried_compat(name, claim),
        STEP => carried_step(name),
        PRODUCER => {
            plain(name)
                && producer_line(bytes)
                && name
                    .split_once('.')
                    .is_some_and(|(kind, rest)| admissible_name(kind, rest, claim))
        }
        _ => false,
    }
}

/// Whether `<kind>/<name>` names a receipt this module could have written,
/// judged on the name alone — what a producer entry can be checked against.
fn admissible_name(kind: &str, name: &str, claim: &str) -> bool {
    match kind {
        STATEMENT => name
            .strip_suffix(".json")
            .and_then(|stem| stem.split_once('.'))
            .is_some_and(|(fingerprint, subject)| is_hex(fingerprint, 64) && is_hex(subject, 40)),
        OVERRIDE => plain(name),
        COMPAT => carried_compat(name, claim),
        STEP => carried_step(name),
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
    /// Every object id the ref's commit reaches — what the remote already
    /// holds, so a publish sends only what is new. A carried reach record is
    /// tens of megabytes, and re-sending it on every step end would make the
    /// publish cost what the record saves.
    known: std::collections::BTreeSet<String>,
}

/// The local ref a fetched set is kept under, so its objects stay in this
/// clone's odb and the next fetch names it as a `have`: the remote then sends
/// only what changed since, and a ref that has not moved costs no fetch at all
/// (`lease::fetch` answers from the odb). `refs/batten/carried/...`, outside
/// `refs/heads` and `refs/remotes`, so no branch listing and no tracking-ref
/// prune ever reads it.
fn cache_ref(name: &str) -> String {
    format!(
        "refs/batten/carried/{}",
        name.strip_prefix("refs/heads/").unwrap_or(name)
    )
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

/// Read what `remote` holds at `name`, fetching into `repo`'s transport, with
/// `claim` the one claim receipt the ref may carry.
fn held(remote: &str, repo: &Path, name: &str, claim: &str) -> Result<Held> {
    held_by(remote, repo, name, |path, bytes| {
        admissible(path, bytes, claim)
    })
}

/// Read what `remote` holds at `name`, keeping the entries `keep` admits.
fn held_by(
    remote: &str,
    repo: &Path,
    name: &str,
    keep: impl Fn(&str, &[u8]) -> bool,
) -> Result<Held> {
    let advertised = lease::advertise(remote, Service::UploadPack)?;
    if advertised.head_of(name) == ZERO {
        return Ok(Held {
            head: ZERO.to_owned(),
            root: String::new(),
            set: BTreeMap::new(),
            known: std::collections::BTreeSet::new(),
        });
    }
    let fetched = lease::fetch(remote, repo, name)?;
    // KEPT, so the next exchange is a delta (see [`cache_ref`]). Best effort:
    // a clone that will not take the objects still reads them from the answer.
    if !fetched.objects.is_empty() && crate::gitwrite::write_objects(repo, &fetched.objects).is_ok()
    {
        let _ = crate::gitwrite::set_ref(repo, &cache_ref(name), &fetched.head);
    }
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
    let mut known = std::collections::BTreeSet::from([fetched.head.clone(), root.clone()]);
    for (kind, id, is_tree) in entries(&body_of(&objects, repo, &root, gix::object::Kind::Tree)?)? {
        if !is_tree {
            continue;
        }
        known.insert(id.clone());
        for (name, blob, nested) in
            entries(&body_of(&objects, repo, &id, gix::object::Kind::Tree)?)?
        {
            if nested {
                continue;
            }
            known.insert(blob.clone());
            let path = format!("{kind}/{name}");
            let bytes = body_of(&objects, repo, &blob, gix::object::Kind::Blob)?;
            if keep(&path, &bytes) {
                set.insert(path, bytes);
            }
        }
    }
    Ok(Held {
        head: fetched.head,
        root,
        set: paired(set),
        known,
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
/// `repo` is the checkout whose odb the fetch negotiates from; what the ref
/// reads is kept in it under [`cache_ref`], so the next exchange is a delta. `branch` is the branch `name` keys, whose claim alone the
/// ref may carry: what the ref holds is read through that filter, so a claim an
/// older engine published for another branch is PRUNED here rather than
/// carried. `local` is [`produced_by`]'s set: a receipt without its producer
/// entry is not published. A set the remote already holds whole is not pushed
/// again: the same tree under a new commit would move the ref for no new fact.
/// `count` is receipts, never producer entries.
///
/// # Errors
///
/// A transport failure (could-not-look, exit `3`), or [`CAS_TRIES`] swaps lost
/// in a row.
pub fn publish(
    remote: &str,
    repo: &Path,
    name: &str,
    branch: &str,
    local: &BTreeMap<String, Vec<u8>>,
    seconds: i64,
) -> Result<Moved> {
    let claim = claim_of(branch);
    publish_with(
        remote,
        repo,
        name,
        || held(remote, repo, name, &claim),
        (
            |_: &BTreeMap<String, Vec<u8>>| Ok(local.clone()),
            |_: &mut BTreeMap<String, Vec<u8>>| {},
        ),
        seconds,
    )
}

/// Publish this checkout's mutate state — the journal lines and the sealed
/// reach record the ref lacks — to `name` on `remote`, bounded by
/// [`mutate_prune`]. `mutate` is the schema state directory; `producer` is the
/// accountable identity every added entry carries.
///
/// # Errors
///
/// As [`publish`].
pub fn publish_mutate(
    remote: &str,
    repo: &Path,
    name: &str,
    mutate: &Path,
    producer: &str,
    seconds: i64,
) -> Result<Moved> {
    publish_with(
        remote,
        repo,
        name,
        || held_mutate(remote, repo, name),
        (
            |theirs: &BTreeMap<String, Vec<u8>>| {
                mutate_additions(mutate, theirs, producer, seconds)
            },
            |union: &mut BTreeMap<String, Vec<u8>>| mutate_prune(union, producer),
        ),
        seconds,
    )
}

/// A publish: what is added computed against what the ref already holds
/// (`read`), and the union shaped by `prune` before it is minted.
///
/// `additions` sees the remote's set and answers the entries this checkout adds
/// (producer entries included). It is asked again after a lost swap, so an
/// addition computed as "what the remote lacks" stays right when a rival moved
/// the ref. `prune` may drop entries from the union — compaction and a bound —
/// and is the only way anything leaves a ref: a rival's entry that lands between
/// the fetch and the swap makes the swap lose, and the retry re-unions it, so a
/// concurrent publisher's entry is never pruned unseen.
///
/// Only objects the ref does not already reach are sent.
///
/// # Errors
///
/// As [`publish`], or an `additions` that fails.
fn publish_with(
    remote: &str,
    repo: &Path,
    name: &str,
    read: impl Fn() -> Result<Held>,
    (additions, prune): (
        impl Fn(&BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Vec<u8>>>,
        impl Fn(&mut BTreeMap<String, Vec<u8>>),
    ),
    seconds: i64,
) -> Result<Moved> {
    let mut last = String::new();
    for _ in 0..CAS_TRIES {
        let theirs = read()?;
        let local = additions(&theirs.set)?;
        let mut union = theirs.set;
        // Local wins a name both hold: every name is content-keyed but a
        // claim's and a compatibility receipt's, and for those this checkout's
        // reading is the newer one.
        union.extend(local);
        prune(&mut union);
        let union = paired(union);
        let count = union
            .keys()
            .filter(|path| !path.starts_with("producer/"))
            .count();
        // NOTHING TO CARRY MINTS NO REF: an empty tree under a new ref says
        // nothing a reader could use, and would answer every pull with a fetch.
        if union.is_empty() && theirs.head == ZERO {
            return Ok(Moved {
                reference: name.to_owned(),
                commit: ZERO.to_owned(),
                count: 0,
            });
        }
        let objects = tree_objects(&union)?;
        let root = objects
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("receipt: a tree set with no root"))?;
        if root.id == theirs.root {
            return Ok(Moved {
                reference: name.to_owned(),
                commit: theirs.head,
                count,
            });
        }
        let commit = commit_over(&root, count, &theirs.head, seconds)?;
        let new = commit.id.clone();
        // ONE COPY OF EACH OBJECT. Every producer entry is the same line, so
        // a set of N receipts names one producer blob N times, and a pack
        // carrying it N times is refused by a forge (`ng <ref> failed`) where a
        // local `receive-pack` accepts it. And none the ref already reaches.
        let mut seen = theirs.known.clone();
        let mut objects: Vec<Object> = objects
            .into_iter()
            .filter(|object| seen.insert(object.id.clone()))
            .collect();
        objects.push(commit);
        let pack = lease::pack_of(&objects)?;
        let update = Update {
            old: theirs.head,
            new: new.clone(),
            name: name.to_owned(),
        };
        match lease::swap(remote, &update, &pack)? {
            Outcome::Applied => {
                // The pushed set is this clone's newest reading: kept, so the
                // next fetch is answered from the odb.
                if crate::gitwrite::write_objects(repo, &objects).is_ok() {
                    let _ = crate::gitwrite::set_ref(repo, &cache_ref(name), &new);
                }
                return Ok(Moved {
                    reference: name.to_owned(),
                    commit: new,
                    count,
                });
            }
            Outcome::Rejected { reason } => last = reason,
        }
    }
    // THE SERVER'S LAST WORD, carried: a remote that refuses every swap for
    // a reason of its own (a rule, a hook) is not a race, and "run it again"
    // alone would send the reader round the same loop.
    Err(anyhow::anyhow!(
        "receipt publish: {name} refused each of {CAS_TRIES} swaps (last: {last}); run it again"
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
fn destination(path: &str, stores: &Stores, head: &str) -> Option<std::path::PathBuf> {
    let (receipts_dir, compat_dir) = (stores.receipts.as_path(), stores.compat.as_path());
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
        // A step receipt is content-keyed: one already here is the same fact.
        STEP => {
            let (group, key) = name.split_once('.')?;
            let target = stores.steps.join(group).join(key);
            (!target.exists()).then_some(target)
        }
        _ => None,
    }
}

/// Pull `name` from `remote` into this checkout's stores. `branch` is the
/// branch `name` keys: another branch's claim on the ref is never written, so
/// one `claim --adopt-from` deleted stays deleted.
///
/// # Errors
///
/// A transport failure (could-not-look, exit `3`), or a store that cannot be
/// written.
pub fn pull(
    remote: &str,
    repo: &Path,
    name: &str,
    branch: &str,
    stores: &Stores,
    head: &str,
) -> Result<Moved> {
    let theirs = held(remote, repo, name, &claim_of(branch))?;
    let mut count = 0;
    for (path, bytes) in &theirs.set {
        let Some(target) = destination(path, stores, head) else {
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

// ---------------------------------------------------------------------------
// THE MUTATE CARRY (CLOUD-1544 for #1276): the schema sweep's verdict journal
// and its sealed reach record, on a ref of their own.
//
// A REF OF THEIR OWN, `refs/heads/batten/mutate/<branch>`, because of size: the
// receipt set is kilobytes and is published at every step end, while #1276's
// journal held 281,351 lines and its reach record 92,506 files (815 MB). On one
// ref, every step's publish would fetch the whole record.
//
// THE JOURNAL TRAVELS AS CHUNKS, each named by the digest of its bytes and
// holding the lines the ref did not yet hold when it was minted. Two sessions
// each add a chunk; a lost swap re-reads and re-chunks; the union of chunks is
// the union of lines, so concurrent publishers lose nothing. Past
// [`KEPT_CHUNKS`] the union is compacted into one chunk, which is safe for the
// same reason: a chunk a rival adds between the fetch and the swap loses this
// swap, and the retry compacts it too.
//
// THE REACH RECORD TRAVELS SEALED OR NOT AT ALL: one gzipped tar of the
// record's directory, cut into parts under [`PART_BYTES`] (a forge refuses a
// blob over 100 MB), named `<sealed-digest>.<archive-digest>.<i>-of-<n>`, with
// `<sealed-digest>.<archive-digest>.at` holding the second it was sealed. Two
// producers sealing one tree mint two archives under two names, so their parts
// never mix. The newest [`KEPT_REACH`] archives stay.
// ---------------------------------------------------------------------------

/// The ref namespace a branch's mutate state lives under.
pub const MUTATE_PREFIX: &str = "refs/heads/batten/mutate/";
/// Verdict-journal chunks, `<digest>.tsv`.
const VERDICTS: &str = "verdicts";
/// Sealed reach archives, in parts.
const REACH: &str = "reach";
/// The journal's file name under the schema state (`mutate::schema`'s).
const JOURNAL: &str = "verdicts";
/// The reach record's directory under the schema state.
const REACH_DIR: &str = "reach";
/// The file a finished reach run writes, holding the tree digest it sealed.
const SEALED: &str = "sealed";
/// The largest part a reach archive is cut into.
const PART_BYTES: usize = 48 << 20;
/// How many reach archives a ref keeps, newest first.
const KEPT_REACH: usize = 2;
/// How many journal chunks a ref holds before a publish compacts them.
const KEPT_CHUNKS: usize = 32;

/// The ref a branch's mutate state lives at.
///
/// # Errors
///
/// [`UsageError`] when `branch` does not make a valid ref name.
pub fn mutate_reference(branch: &str) -> Result<String> {
    let name = format!("{MUTATE_PREFIX}{branch}");
    gix::refs::FullName::try_from(name.as_str()).map_err(|_| {
        UsageError::raise(format!(
            "receipt: `{branch}` does not make a valid ref name for the mutate carry"
        ))
    })?;
    Ok(name)
}

/// Whether a verdict chunk's name is the digest of its bytes.
fn verdict_chunk(name: &str, bytes: &[u8]) -> bool {
    name.strip_suffix(".tsv")
        .is_some_and(|stem| is_hex(stem, 32) && crate::tools::digest(bytes) == stem)
}

/// A reach entry's `(sealed, archive, part)`, where `part` is `Some((i, n))`
/// for a part and `None` for the `.at` stamp.
type ReachName<'n> = (&'n str, &'n str, Option<(usize, usize)>);

/// The [`ReachName`] of a reach entry's file `name`, or `None` where it names none.
fn reach_name(name: &str) -> Option<ReachName<'_>> {
    let mut halves = name.splitn(3, '.');
    let (sealed, archive, rest) = (halves.next()?, halves.next()?, halves.next()?);
    if !is_hex(sealed, 64) || !is_hex(archive, 32) {
        return None;
    }
    if rest == "at" {
        return Some((sealed, archive, None));
    }
    let (first, last) = rest.split_once("-of-")?;
    let (i, n): (usize, usize) = (first.parse().ok()?, last.parse().ok()?);
    // ONE SPELLING PER PART: `01-of-2` and `1-of-2` would be two names for one
    // part, and a union would keep both.
    (i >= 1 && i <= n && i.to_string() == first && n.to_string() == last).then_some((
        sealed,
        archive,
        Some((i, n)),
    ))
}

/// Whether a mutate entry is admissible, judged as [`admissible`] judges a
/// receipt: on its name, and where the name is a content key, on its bytes.
fn admissible_mutate(path: &str, bytes: &[u8]) -> bool {
    let Some((kind, name)) = path.split_once('/') else {
        return false;
    };
    match kind {
        VERDICTS => verdict_chunk(name, bytes),
        REACH => reach_name(name).is_some_and(|(_, _, part)| {
            part.is_some()
                || std::str::from_utf8(bytes).is_ok_and(|at| at.trim().parse::<i64>().is_ok())
        }),
        PRODUCER => {
            producer_line(bytes)
                && name.split_once('.').is_some_and(|(kind, rest)| match kind {
                    VERDICTS => rest
                        .strip_suffix(".tsv")
                        .is_some_and(|stem| is_hex(stem, 32)),
                    REACH => reach_name(rest).is_some(),
                    _ => false,
                })
        }
        _ => false,
    }
}

/// The lines of a journal text, in order, each with its newline.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
}

/// Every journal line `set`'s chunks hold.
fn held_lines(set: &BTreeMap<String, Vec<u8>>) -> std::collections::BTreeSet<String> {
    set.iter()
        .filter(|(path, _)| path.starts_with("verdicts/"))
        .flat_map(|(_, bytes)| {
            lines(&String::from_utf8_lossy(bytes))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The chunk entry for `text`, as `(path, bytes)`.
fn chunk(text: String) -> (String, Vec<u8>) {
    let bytes = text.into_bytes();
    (
        format!("{VERDICTS}/{}.tsv", crate::tools::digest(&bytes)),
        bytes,
    )
}

/// The sealed reach record under `mutate`, as `(sealed digest, archive bytes)`,
/// or `None` where there is none or it moved while it was read.
///
/// # Errors
///
/// A record that will not archive.
fn sealed_archive(mutate: &Path) -> Result<Option<(String, Vec<u8>)>> {
    let dir = mutate.join(REACH_DIR);
    let Ok(sealed) = std::fs::read_to_string(dir.join(SEALED)) else {
        return Ok(None);
    };
    let sealed = sealed.trim().to_owned();
    if !is_hex(&sealed, 64) {
        return Ok(None);
    }
    let mut paths = Vec::new();
    let mut pending = vec![dir.clone()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)?.filter_map(std::result::Result::ok) {
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                paths.push(entry.path());
            }
        }
    }
    paths.sort();
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tarred = tar::Builder::new(gz);
    for path in &paths {
        let relative = path.strip_prefix(&dir)?;
        let bytes = std::fs::read(path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tarred.append_data(&mut header, relative, bytes.as_slice())?;
    }
    let archive = tarred.into_inner()?.finish()?;
    // MOVED WHILE READ: a sweep that re-sealed under this read made a mixed
    // archive. Left for the next step end, which reads it whole.
    let after = std::fs::read_to_string(dir.join(SEALED)).unwrap_or_default();
    Ok((after.trim() == sealed).then_some((sealed, archive)))
}

/// What the mutate ref gains from this checkout, given what it holds:
/// one chunk of the journal lines it lacks, and the sealed reach record where
/// no archive for that seal is there yet. Producer entries included.
///
/// # Errors
///
/// No accountable producer, or a reach record that will not archive.
pub fn mutate_additions(
    mutate: &Path,
    theirs: &BTreeMap<String, Vec<u8>>,
    producer: &str,
    seconds: i64,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut added = BTreeMap::new();
    let journal = std::fs::read_to_string(mutate.join(JOURNAL)).unwrap_or_default();
    let held = held_lines(theirs);
    let mut seen = std::collections::BTreeSet::new();
    let fresh: String = lines(&journal)
        .filter(|line| !held.contains(*line) && seen.insert(*line))
        .collect();
    if !fresh.is_empty() {
        let (path, bytes) = chunk(fresh);
        added.insert(path, bytes);
    }
    let sealed = std::fs::read_to_string(mutate.join(REACH_DIR).join(SEALED)).unwrap_or_default();
    let sealed = sealed.trim();
    let carried = theirs.keys().any(|path| {
        path.strip_prefix("reach/")
            .and_then(reach_name)
            .is_some_and(|(held, _, _)| held == sealed)
    });
    if is_hex(sealed, 64)
        && !carried
        && let Some((sealed, archive)) = sealed_archive(mutate)?
    {
        let id = crate::tools::digest(&archive);
        let parts: Vec<&[u8]> = archive.chunks(PART_BYTES).collect();
        let n = parts.len();
        for (i, part) in parts.into_iter().enumerate() {
            added.insert(
                format!("{REACH}/{sealed}.{id}.{}-of-{n}", i + 1),
                part.to_vec(),
            );
        }
        added.insert(
            format!("{REACH}/{sealed}.{id}.at"),
            format!("{seconds}\n").into_bytes(),
        );
    }
    produced_by(&added, producer)
}

/// Every complete reach archive in `set`, newest first, as
/// `(seconds, sealed, archive id, part count)`.
fn reach_archives(set: &BTreeMap<String, Vec<u8>>) -> Vec<(i64, String, String, usize)> {
    let mut found = Vec::new();
    for (path, bytes) in set {
        let Some((sealed, id, None)) = path.strip_prefix("reach/").and_then(reach_name) else {
            continue;
        };
        let Some(at) = std::str::from_utf8(bytes)
            .ok()
            .and_then(|at| at.trim().parse::<i64>().ok())
        else {
            continue;
        };
        let prefix = format!("reach/{sealed}.{id}.");
        let parts: Vec<(usize, usize)> = set
            .range(prefix.clone()..)
            .take_while(|(path, _)| path.starts_with(&prefix))
            .filter_map(|(path, _)| reach_name(path.strip_prefix("reach/")?)?.2)
            .collect();
        let Some(&(_, n)) = parts.first() else {
            continue;
        };
        let whole = parts.len() == n && parts.iter().all(|(_, of)| *of == n);
        if whole {
            found.push((at, sealed.to_owned(), id.to_owned(), n));
        }
    }
    found.sort_by(|a, b| b.cmp(a));
    found
}

/// Bound the mutate ref: compact the journal chunks past [`KEPT_CHUNKS`], and
/// keep the newest [`KEPT_REACH`] reach archives. The compacted chunk is this
/// publisher's, so `producer` is its producer.
pub fn mutate_prune(union: &mut BTreeMap<String, Vec<u8>>, producer: &str) {
    let chunks: Vec<String> = union
        .keys()
        .filter(|path| path.starts_with("verdicts/"))
        .cloned()
        .collect();
    if chunks.len() > KEPT_CHUNKS {
        let mut seen = std::collections::BTreeSet::new();
        let mut text = String::new();
        for path in &chunks {
            if let Some(bytes) = union.remove(path) {
                for line in lines(&String::from_utf8_lossy(&bytes)) {
                    if seen.insert(line.to_owned()) {
                        text.push_str(line);
                    }
                }
            }
        }
        let (path, bytes) = chunk(text);
        if let Ok(produced) = produced_by(&BTreeMap::from([(path, bytes)]), producer) {
            union.extend(produced);
        }
    }
    let dropped: Vec<(String, String)> = reach_archives(union)
        .into_iter()
        .skip(KEPT_REACH)
        .map(|(_, sealed, id, _)| (sealed, id))
        .collect();
    union.retain(|path, _| {
        let name = path
            .strip_prefix("reach/")
            .or_else(|| path.strip_prefix("producer/reach."));
        !name.and_then(reach_name).is_some_and(|(sealed, id, _)| {
            dropped
                .iter()
                .any(|(gone, gone_id)| gone == sealed && gone_id == id)
        })
    });
}

/// Read `remote`'s mutate ref `name`, through [`admissible_mutate`].
fn held_mutate(remote: &str, repo: &Path, name: &str) -> Result<Held> {
    held_by(remote, repo, name, admissible_mutate)
}

/// Pull `name`'s mutate state from `remote` into the schema state `mutate`.
///
/// The journal gains every line a chunk holds that it does not: appended, never
/// rewritten, so a line this checkout journaled is never lost and a sweep that
/// is appending as this runs loses nothing either. The reach record is written
/// only where there is none — no `sealed` file and nothing left over — from the
/// newest whole archive, checked against its own digest, unpacked beside the
/// record's directory and moved into place, so a reader sees all of it or none.
///
/// `count` is journal lines appended plus archives unpacked.
///
/// # Errors
///
/// A transport failure (could-not-look, exit `3`), or a store that cannot be
/// written.
pub fn pull_mutate(remote: &str, repo: &Path, name: &str, mutate: &Path) -> Result<Moved> {
    let theirs = held_mutate(remote, repo, name)?;
    let mut count = 0;
    let journal = mutate.join(JOURNAL);
    let local = std::fs::read_to_string(&journal).unwrap_or_default();
    let mut have: std::collections::BTreeSet<String> = lines(&local).map(str::to_owned).collect();
    let mut fresh = String::new();
    for (path, bytes) in &theirs.set {
        if !path.starts_with("verdicts/") {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        for line in lines(&text) {
            if have.insert(line.to_owned()) {
                fresh.push_str(line);
                count += 1;
            }
        }
    }
    if !fresh.is_empty() {
        std::fs::create_dir_all(mutate)?;
        crate::durable::append(&journal, &fresh)?;
    }
    let dir = mutate.join(REACH_DIR);
    let empty = std::fs::read_dir(&dir).map_or(true, |mut entries| entries.next().is_none());
    if !dir.join(SEALED).exists()
        && empty
        && let Some((_, sealed, id, n)) = reach_archives(&theirs.set).into_iter().next()
    {
        let mut archive = Vec::new();
        for part in 1..=n {
            if let Some(bytes) = theirs
                .set
                .get(&format!("reach/{sealed}.{id}.{part}-of-{n}"))
            {
                archive.extend_from_slice(bytes);
            }
        }
        if crate::tools::digest(&archive) == id {
            let staging = mutate.join(format!("{REACH_DIR}.pulling"));
            let _ = std::fs::remove_dir_all(&staging);
            std::fs::create_dir_all(&staging)?;
            tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice())).unpack(&staging)?;
            let _ = std::fs::remove_dir(&dir);
            std::fs::rename(&staging, &dir)?;
            count += 1;
        }
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
        let claim = claim_of("feat/x");
        assert!(carried_compat("step.cargo-test.abc", &claim));
        assert!(!carried_compat("step.batten-check.abc", &claim));
        assert!(carried_compat("claim.feat-x", &claim));
        assert!(carried_compat(
            &format!("verify.{}", "a".repeat(40)),
            &claim
        ));
        assert!(!carried_compat("issue-read.CLOUD-1", &claim));
        assert!(!carried_compat("../claim.x", &claim));
    }

    /// Fails by: a claim keyed to another branch travelling on this one's ref,
    /// so a `claim --adopt-from` that deleted it sees the next pull restore it.
    #[test]
    fn only_this_branchs_claim_travels() {
        let claim = claim_of("feat/x");
        assert!(!carried_compat("claim.other", &claim));
        assert!(!admissible("compat/claim.other", b"base x\n", &claim));
        assert!(admissible("compat/claim.feat-x", b"base x\n", &claim));
    }

    /// Fails by: any spelling of origin's own repository resolving to a remote
    /// (the privacy rule's one escape), one assertion per spelling.
    #[test]
    fn a_state_repo_naming_origin_is_refused_in_every_spelling() {
        // A RESERVED FIXTURE ORIGIN, and every other spelling derived from it:
        // no real owner or repository is named in the core (rule 1).
        let (host, owner, repo) = ("example.invalid", "o", "r");
        let origin = format!("https://{host}/{owner}/{repo}");
        let path = format!("{owner}/{repo}");
        let upper = path.to_uppercase();
        for value in [
            path.clone(),
            upper.clone(),
            format!("{path}.git"),
            format!("{upper}.GIT"),
            format!("/{path}/"),
            format!("{path}.git/"),
            origin.clone(),
            format!("{origin}.git"),
            format!("https://user@{}/{upper}.git", host.to_uppercase()),
            format!("git@{host}:{path}.git"),
            format!("{host}/{path}"),
            format!("{}/{path}.git", host.to_uppercase()),
        ] {
            assert_eq!(
                state_remote(Some(&value), Some(&origin)),
                Remote::IsOrigin,
                "{value}"
            );
        }
        // Origin's own spelling varies too: `.git`, case, userinfo.
        for spelled in [
            format!("{origin}.git"),
            format!(
                "https://x-access-token:t@{}/{upper}.git/",
                host.to_uppercase()
            ),
        ] {
            assert_eq!(
                state_remote(Some(&path), Some(&spelled)),
                Remote::IsOrigin,
                "{spelled}"
            );
        }
        // The control: a state repository beside origin, on the same host,
        // resolves — its name derived from origin's, never written out.
        let state = format!("{path}-state");
        assert_eq!(
            state_remote(Some(&state), Some(&origin)),
            Remote::At(format!("https://{host}/{state}"))
        );
    }

    /// Fails by: a receipt with no producer entry being kept, or a producer
    /// entry outliving its receipt (row §5: a producer on every published blob).
    #[test]
    fn every_kept_receipt_carries_its_producer() {
        let mut local = BTreeMap::new();
        local.insert("compat/claim.feat-x".to_owned(), b"base x\n".to_vec());
        let produced = produced_by(&local, "Alice Example <alice@example.com>");
        assert!(produced.is_ok(), "one `Name <email>` line is a producer");
        let produced = produced.unwrap_or_default();
        assert_eq!(
            produced
                .get("producer/compat.claim.feat-x")
                .map(Vec::as_slice),
            Some(&b"Alice Example <alice@example.com>\n"[..])
        );
        assert!(
            produced_by(&local, "  ").is_err(),
            "no identity, no publish"
        );
        let mut orphaned = produced.clone();
        orphaned.insert("compat/step.x.y".to_owned(), b"z".to_vec());
        orphaned.insert(
            "producer/compat.step.gone.y".to_owned(),
            b"A <a@b>\n".to_vec(),
        );
        let kept = paired(orphaned);
        assert_eq!(kept, produced);
    }

    #[test]
    fn a_step_receipt_travels_and_batten_checks_never_does() {
        let key = "0".repeat(32);
        assert!(carried_step(&format!("{}.{key}", "f".repeat(32))));
        assert!(!carried_step(&format!("{}.{key}", batten_check_group())));
        assert!(!carried_step(&format!("{}.{key}", "F".repeat(32))));
        assert!(!carried_step(&key));
    }

    #[test]
    fn a_reach_part_has_one_spelling() {
        let (sealed, id) = ("a".repeat(64), "b".repeat(32));
        assert_eq!(
            reach_name(&format!("{sealed}.{id}.1-of-2")),
            Some((sealed.as_str(), id.as_str(), Some((1, 2))))
        );
        assert_eq!(
            reach_name(&format!("{sealed}.{id}.at")),
            Some((sealed.as_str(), id.as_str(), None))
        );
        for bad in ["01-of-2", "3-of-2", "0-of-2", "1-of-02", "x"] {
            assert_eq!(reach_name(&format!("{sealed}.{id}.{bad}")), None, "{bad}");
        }
    }

    #[test]
    fn a_verdict_chunk_is_named_by_its_bytes() {
        let (path, bytes) = chunk("k\tcaught\tm\n".to_owned());
        assert!(admissible_mutate(&path, &bytes));
        assert!(!admissible_mutate(&path, b"k\tmissed\tm\n"));
    }

    #[test]
    fn pruning_compacts_every_line_and_keeps_the_newest_reach() {
        let mut union = BTreeMap::new();
        for n in 0..=KEPT_CHUNKS {
            let (path, bytes) = chunk(format!("k{n}\tcaught\tm{n}\n"));
            let produced = produced_by(&BTreeMap::from([(path, bytes)]), PRODUCER);
            assert!(produced.is_ok(), "a chunk under the producer is admitted");
            union.extend(produced.unwrap_or_default());
        }
        for (at, sealed) in [(1, "a"), (2, "b"), (3, "c")] {
            let (sealed, id) = (sealed.repeat(64), "d".repeat(32));
            union.insert(format!("reach/{sealed}.{id}.1-of-1"), vec![0]);
            union.insert(
                format!("reach/{sealed}.{id}.at"),
                format!("{at}\n").into_bytes(),
            );
        }
        mutate_prune(&mut union, PRODUCER);
        let chunks: Vec<_> = union
            .keys()
            .filter(|path| path.starts_with("verdicts/"))
            .collect();
        assert_eq!(chunks.len(), 1, "compacted");
        assert_eq!(held_lines(&union).len(), KEPT_CHUNKS + 1, "no line lost");
        let kept: Vec<_> = reach_archives(&union)
            .into_iter()
            .map(|(at, ..)| at)
            .collect();
        assert_eq!(kept, vec![3, 2], "the newest {KEPT_REACH}");
    }

    const PRODUCER: &str = "Fixture Producer <producer@example.com>";
}
