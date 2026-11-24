//! The `state-push` fact (CLOUD-2887): which blobs a `git push` would carry
//! whose bytes are a private session store's, and to which remote.
//!
//! # Why bytes, not paths
//!
//! Measured 2026-11-24: a dispatched session copied its mutant verdict journal
//! into the project tree as `verdicts/28-of-32.tsv` and pushed it to the public
//! repository. A rule on the pushed path keys on a name a brief chose, so a
//! rename evades it and a project file of that name would be refused. This
//! matches the blob's bytes against the stores Batten itself writes.
//!
//! # Why a named list, not the state directory
//!
//! Most of the state root holds copies of the project's own files — `replay/`,
//! the mutation trees, caches — so a match against all of it fires on every
//! ordinary push (1,240 of 1,499 tracked blobs equal a `replay/` file, measured).
//! [`stores`] is the one list of what is private, built from each writer's own
//! path function so the list moves when a writer does.
//!
//! # Two arms
//!
//! * `equal` — the blob's size equals a store file's, then its bytes do.
//! * `prefix` — the blob holds a newline and is a strict byte prefix of an
//!   append-only store file: a journal or transcript grows after it is copied,
//!   so by push time the copy is only its beginning.
//!
//! # What this does not decide
//!
//! The producer reports every match on every remote, size 0 included. The
//! exemption (`remote` equals `state_repo`) and `size > 0` are the module's, in
//! `policy/presets/state-private/no-state-push.rego`, so each rule has a mutant
//! a case can kill. Pointer-only: a path, a store and an arm, never a byte.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::facts::Look;
use crate::hook::Envelope;

/// How much of an append-only file is compared before the rest is read.
const HEAD_BYTES: usize = 64;

/// The remote git falls back to when nothing names one.
const DEFAULT_REMOTE: &str = "origin";

/// Options to `git push` that consume the next word.
const VALUE_OPTIONS: [&str; 5] = ["-o", "--push-option", "--receive-pack", "--exec", "--repo"];

/// One private file a push may not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreFile {
    /// The store's name, as the fact reports it.
    pub store: &'static str,
    /// The file.
    pub path: PathBuf,
    /// Whether the file only ever grows, so a copy of its beginning is its own.
    pub append_only: bool,
    /// Its size when listed.
    pub size: u64,
}

/// Every private store file for the checkout at `repo_root` whose git directory
/// is `git_dir`, plus each `*.jsonl` transcript under `transcript_dir`.
///
/// THE ONE LIST: each entry is a writer's own path function, so a store that
/// moves moves here too. A store that cannot be resolved contributes nothing.
#[must_use]
pub(crate) fn stores(
    repo_root: &Path,
    git_dir: Option<&Path>,
    transcript_dir: Option<&Path>,
) -> Vec<StoreFile> {
    let mut found = Vec::new();
    if let Ok(state) = crate::state::repo_state_dir(repo_root) {
        let journal = crate::journal::journal_dir(&state);
        let shards = crate::journal::shards_dir(&state);
        let merged = crate::journal::merged_path(&state);
        walk(&mut found, "journal", &journal, &|path| {
            path.starts_with(&shards) || path == merged
        });
        walk(
            &mut found,
            "findings",
            &crate::findings::findings_dir(&state),
            &|_| false,
        );
        walk(
            &mut found,
            "sessions",
            &crate::session::sessions_dir(&state),
            &|_| false,
        );
        walk(
            &mut found,
            "drain",
            &crate::drain::drain_dir(&state),
            &|_| false,
        );
    }
    if let Ok(dir) = crate::receipt::receipts_dir(repo_root) {
        walk(&mut found, "receipts", &dir, &|_| false);
    }
    if let Ok(dir) = crate::capture::captures_dir(repo_root) {
        walk(&mut found, "captures", &dir, &|_| false);
    }
    if let Ok(key) = crate::secrets::key_path(repo_root)
        && let Some(dir) = key.parent()
    {
        let ledger = crate::secrets::ledger_path(repo_root).ok();
        walk(&mut found, "identity", dir, &|path| {
            ledger.as_deref() == Some(path)
        });
    }
    if let Ok(dir) = crate::session_watch::state_dir(repo_root) {
        walk(&mut found, "session-watch", &dir, &|_| false);
    }
    if let Ok(path) = crate::mutate::schema::verdicts_path(repo_root) {
        walk(&mut found, "mutate-verdicts", &path, &|_| true);
    }
    if let Ok(root) = crate::state::state_root() {
        walk(
            &mut found,
            "state-sessions",
            &crate::state::sessions_dir(&root),
            &|_| false,
        );
    }
    if let Some(git_dir) = git_dir {
        walk(
            &mut found,
            "git-receipts",
            &crate::minted::store_path(git_dir),
            &|_| false,
        );
    }
    if let Some(dir) = transcript_dir {
        let mut transcripts = Vec::new();
        walk(&mut transcripts, "transcripts", dir, &|_| true);
        found.extend(
            transcripts
                .into_iter()
                .filter(|file| file.path.extension().is_some_and(|ext| ext == "jsonl")),
        );
    }
    found
}

/// Every regular file at or under `path`, recursively, into `found`. A path
/// that does not exist adds nothing.
fn walk(
    found: &mut Vec<StoreFile>,
    store: &'static str,
    path: &Path,
    grows: &dyn Fn(&Path) -> bool,
) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_file() {
        found.push(StoreFile {
            store,
            path: path.to_path_buf(),
            append_only: grows(path),
            size: meta.len(),
        });
    } else if meta.is_dir()
        && let Ok(entries) = std::fs::read_dir(path)
    {
        for entry in entries.flatten() {
            walk(found, store, &entry.path(), grows);
        }
    }
}

/// One parsed `git push`: where it runs, which remote, what it sends.
#[derive(Debug, Default)]
struct Push {
    dir: PathBuf,
    remote: Option<String>,
    refspecs: Vec<String>,
    all: bool,
    mirror: bool,
    tags: bool,
}

/// `git`'s own options and the push's arguments, read the way git reads them.
fn parse(globals: &[String], arguments: &[String], cwd: &Path) -> Push {
    let mut push = Push {
        dir: cwd.to_path_buf(),
        ..Push::default()
    };
    let mut words = globals.iter();
    while let Some(word) = words.next() {
        if word == "-C"
            && let Some(dir) = words.next()
        {
            push.dir = push.dir.join(dir);
        }
    }
    let mut positional = Vec::new();
    let mut words = arguments.iter();
    let mut options = true;
    while let Some(word) = words.next() {
        if options && word == "--" {
            options = false;
        } else if options && word.starts_with('-') {
            match word.as_str() {
                "--all" | "--branches" => push.all = true,
                "--mirror" => push.mirror = true,
                "--tags" => push.tags = true,
                "--repo" => push.remote = words.next().cloned(),
                _ if VALUE_OPTIONS.contains(&word.as_str()) => {
                    words.next();
                }
                _ => {
                    if let Some(repo) = word.strip_prefix("--repo=") {
                        push.remote = Some(repo.to_owned());
                    }
                }
            }
        } else {
            positional.push(word.clone());
        }
    }
    let mut positional = positional.into_iter();
    if let Some(remote) = positional.next() {
        push.remote = Some(remote);
    }
    push.refspecs = positional.collect();
    push
}

/// The remote a push with none named goes to, in git's own order.
fn default_remote(dir: &Path, branch: Option<&str>) -> String {
    let config = |key: &str| crate::git::config_value(dir, key).ok().flatten();
    branch
        .and_then(|branch| config(&format!("branch.{branch}.pushRemote")))
        .or_else(|| config("remote.pushDefault"))
        .or_else(|| branch.and_then(|branch| config(&format!("branch.{branch}.remote"))))
        .unwrap_or_else(|| DEFAULT_REMOTE.to_owned())
}

/// `(source rev, destination branch name)` for each thing the push sends.
fn sources(
    push: &Push,
    remote: &str,
    branch: Option<&str>,
) -> Option<Vec<(String, Option<String>)>> {
    let short = |name: &str| name.strip_prefix("refs/heads/").unwrap_or(name).to_owned();
    let mut found = Vec::new();
    if push.mirror {
        for prefix in ["refs/heads", "refs/tags"] {
            for name in crate::git::refs_under(&push.dir, prefix).ok()? {
                found.push((name.clone(), Some(short(&name))));
            }
        }
    } else if push.all {
        for name in crate::git::refs_under(&push.dir, "refs/heads").ok()? {
            found.push((name.clone(), Some(short(&name))));
        }
    } else if push.refspecs.is_empty() {
        let matching = crate::git::config_value(&push.dir, "push.default")
            .ok()
            .flatten()
            .is_some_and(|mode| mode == "matching");
        if matching {
            for name in crate::git::refs_under(&push.dir, "refs/heads").ok()? {
                let dst = short(&name);
                if crate::git::resolve_ref(&push.dir, &format!("refs/remotes/{remote}/{dst}"))
                    .ok()
                    .flatten()
                    .is_some()
                {
                    found.push((name, Some(dst)));
                }
            }
        } else {
            found.push(("HEAD".to_owned(), branch.map(ToOwned::to_owned)));
        }
    }
    for spec in &push.refspecs {
        let spec = spec.strip_prefix('+').unwrap_or(spec);
        let (src, dst) = spec
            .split_once(':')
            .map_or((spec, None), |(src, dst)| (src, Some(dst)));
        // `:dst` deletes and sends nothing.
        if src.is_empty() {
            continue;
        }
        let dst = dst.map(short).or_else(|| {
            if src == "HEAD" {
                branch.map(ToOwned::to_owned)
            } else {
                Some(short(src))
            }
        });
        found.push((src.to_owned(), dst));
    }
    if push.tags {
        for name in crate::git::refs_under(&push.dir, "refs/tags").ok()? {
            found.push((name, None));
        }
    }
    Some(found)
}

/// What the remote already has under the push's tip: the destination's
/// tracking ref, else the merge base with the remote's `HEAD` or `main`, else
/// nothing, which walks the whole history.
fn base(dir: &Path, remote: &str, tip: &str, dst: Option<&str>) -> Option<String> {
    if let Some(dst) = dst {
        let tracking = format!("refs/remotes/{remote}/{dst}");
        if crate::git::resolve_ref(dir, &tracking)
            .ok()
            .flatten()
            .is_some()
        {
            return Some(tracking);
        }
    }
    ["HEAD", "main"].iter().find_map(|name| {
        crate::git::merge_base_of(dir, tip, &format!("refs/remotes/{remote}/{name}"))
            .ok()
            .flatten()
    })
}

/// Each store file a blob of `body` matches, and by which arm.
fn matches<'a>(body: &[u8], files: &'a [StoreFile]) -> Vec<(&'a StoreFile, &'static str)> {
    let size = body.len() as u64;
    let mut found = Vec::new();
    for file in files {
        if file.size == size {
            if std::fs::read(&file.path).is_ok_and(|bytes| bytes == body) {
                found.push((file, "equal"));
            }
        } else if file.append_only
            && file.size > size
            && body.contains(&b'\n')
            && starts(file, body)
        {
            found.push((file, "prefix"));
        }
    }
    found
}

/// Whether `file` begins with `body`: its head first, then the rest.
fn starts(file: &StoreFile, body: &[u8]) -> bool {
    use std::io::Read as _;
    let Ok(handle) = std::fs::File::open(&file.path) else {
        return false;
    };
    let mut head = Vec::with_capacity(HEAD_BYTES);
    let mut reader = handle.take(body.len() as u64);
    let head_len = body.len().min(HEAD_BYTES);
    if (&mut reader)
        .take(head_len as u64)
        .read_to_end(&mut head)
        .is_err()
        || head != body[..head_len]
    {
        return false;
    }
    let mut rest = Vec::with_capacity(body.len() - head_len);
    reader.read_to_end(&mut rest).is_ok() && rest == body[head_len..]
}

/// The fact for this call, or could-not-look where it is no push or the push
/// cannot be looked at (git itself would fail it then too).
#[must_use]
pub(crate) fn fact(envelope: &Envelope, authority: &Path) -> Look<serde_json::Value> {
    let pushes = crate::hook::git_pushes(envelope);
    if pushes.is_empty() {
        return Look::CouldNotLook;
    }
    let cwd = envelope
        .cwd
        .clone()
        .filter(|dir| dir.is_dir())
        .unwrap_or_else(|| authority.to_path_buf());
    let transcript_dir = envelope
        .transcript
        .as_deref()
        .and_then(|path| Path::new(path).parent().map(Path::to_path_buf));
    let state_repo = crate::session::state_repo();
    let mut remote_slug = None;
    let mut carried = Vec::new();
    for (globals, arguments) in &pushes {
        let push = parse(globals, arguments, &cwd);
        let Some(found) = judge(&push, authority, transcript_dir.as_deref()) else {
            return Look::CouldNotLook;
        };
        remote_slug = remote_slug.or(found.0);
        carried.extend(found.1);
    }
    Look::Is(serde_json::json!({
        "remote": remote_slug,
        "state_repo": state_repo,
        "carried": carried,
    }))
}

/// One push's remote slug and carried entries, or `None` where it cannot be
/// looked at.
fn judge(
    push: &Push,
    authority: &Path,
    transcript_dir: Option<&Path>,
) -> Option<(Option<String>, Vec<serde_json::Value>)> {
    let root = crate::git::repo_root(&push.dir).ok()?;
    let git_dir = crate::git::git_dir(&root).ok()?;
    let branch = crate::git::current_branch(&root).ok().flatten();
    let remote = push
        .remote
        .clone()
        .unwrap_or_else(|| default_remote(&root, branch.as_deref()));
    let url = crate::git::push_url(&root, &remote)?;
    let slug = crate::race::slug_of(&url);

    // BOTH CHECKOUTS when they differ: the hook's authority and the push's own.
    let mut files = stores(&root, Some(&git_dir), transcript_dir);
    if let Ok(other) = crate::git::repo_root(authority)
        && other != root
    {
        let other_git = crate::git::git_dir(&other).ok();
        files.extend(stores(&other, other_git.as_deref(), None));
    }

    let mut carried = Vec::new();
    for (src, dst) in sources(push, &remote, branch.as_deref())? {
        let tip = crate::git::resolve_ref(&root, &src).ok().flatten()?;
        let base = base(&root, &remote, &tip, dst.as_deref());
        let objects = crate::git::objects_to_send(&root, base.as_deref(), &tip).ok()?;
        let mut names: BTreeMap<String, String> = BTreeMap::new();
        for (id, path) in crate::git::blob_paths_at_rev(&root, &tip).unwrap_or_default() {
            names.entry(id).or_insert(path);
        }
        for object in objects
            .iter()
            .filter(|object| object.kind == gix::object::Kind::Blob)
        {
            for (file, arm) in matches(&object.body, &files) {
                let path = names
                    .get(&object.id)
                    .cloned()
                    .unwrap_or_else(|| object.id.clone());
                let entry = serde_json::json!({
                    "path": path,
                    "store": file.store,
                    "arm": arm,
                    "size": object.body.len(),
                });
                if !carried.contains(&entry) {
                    carried.push(entry);
                }
            }
        }
    }
    Some((slug, carried))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{StoreFile, matches, parse};
    use std::path::Path;

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn a_push_names_its_remote_refspecs_and_directory() {
        let push = parse(
            &strings(&["-C", "sub"]),
            &strings(&["-o", "ci.skip", "--force", "up", "+main:dst", ":gone"]),
            Path::new("/work"),
        );
        assert_eq!(push.dir, Path::new("/work/sub"));
        assert_eq!(push.remote.as_deref(), Some("up"));
        assert_eq!(push.refspecs, strings(&["+main:dst", ":gone"]));

        let bare = parse(&[], &strings(&["--repo=there", "--tags"]), Path::new("/w"));
        assert_eq!(bare.remote.as_deref(), Some("there"));
        assert!(bare.tags && bare.refspecs.is_empty());
    }

    #[test]
    fn a_prefix_needs_a_whole_record_and_an_append_only_file() {
        let dir = std::env::temp_dir().join(format!("state-push-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.jsonl");
        std::fs::write(&path, "{\"a\":1}\n{\"b\":2}\n").unwrap();
        let file = |append_only| StoreFile {
            store: "transcripts",
            path: path.clone(),
            append_only,
            size: 16,
        };
        let grows = [file(true)];
        assert_eq!(matches(b"{\"a\":1}\n", &grows)[0].1, "prefix");
        assert!(matches(b"{", &grows).is_empty(), "no newline, no record");
        assert!(matches(b"{\"a\":2}\n", &grows).is_empty(), "other bytes");
        assert!(
            matches(b"{\"a\":1}\n", &[file(false)]).is_empty(),
            "rewritten files match by equality only"
        );
        assert_eq!(matches(b"{\"a\":1}\n{\"b\":2}\n", &grows)[0].1, "equal");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
