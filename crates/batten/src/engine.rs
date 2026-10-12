//! The engine pin: which batten a config needs, read before the config is
//! parsed (CLOUD-2061).
//!
//! # Why a pin and not the floor
//!
//! `min_batten_version` is a minimum, and it is read only once a load has already
//! failed. Measured: a reclaimed container installed the latest release over a
//! branch build, the release refused a config key the branch had added, and every
//! mediated rule failed open for the session. A floor cannot say "this exact
//! engine", and nothing recorded which SOURCE an installed binary came from.
//!
//! # The two identities
//!
//! - **A release** is `v{VERSION}`, which the binary already carries.
//! - **A source** is the SHA-256 of every tracked engine input — each path under
//!   `crates/`, plus the root `Cargo.toml` and `Cargo.lock` — as path, NUL, bytes,
//!   NUL, in sorted order. Tracked, so `target/` and scratch never enter; the
//!   bytes on disk, so an uncommitted edit to a tracked file does. `batten engine
//!   stamp` writes it beside the running binary as `<binary>.source` once
//!   `install:local` has installed it.
//!
//! # Before the parse, and on every load
//!
//! [`check`] runs at the top of [`crate::config::parse`], over the raw text, so a
//! stale engine is named before a key it cannot read can fail the parse. It scans
//! top-level lines up to the first `[` header and parses only the one beginning
//! `engine`, so a config without a pin pays one line scan. A mismatch is a
//! [`UsageError`]; on the hook path that is the `engine-cannot-adjudicate` deny,
//! which names the update — a stale engine refuses rather than deciding silently.
//!
//! **A missing or unreadable stamp is a mismatch.** Could-not-look never buys a
//! pass: a source pin exists to say "this exact build", and a binary that cannot
//! say what it was built from has not said it.

use std::path::{Path, PathBuf};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The engine a config needs: exactly one of a release tag or a source digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// A published release, spelled as its tag (`v0.0.198`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The digest `batten engine digest` prints for the source tree the engine
    /// must be built from (64 hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The suffix of the stamp written beside an installed binary.
pub const STAMP_SUFFIX: &str = "source";

/// This binary's release identity.
#[must_use]
pub fn release() -> String {
    format!("v{}", crate::config::VERSION)
}

/// The stamp file beside `binary`.
#[must_use]
pub fn stamp_path(binary: &Path) -> PathBuf {
    let mut name = binary.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(STAMP_SUFFIX);
    binary.with_file_name(name)
}

/// Whether a tracked path is an engine input.
fn is_input(path: &str) -> bool {
    path.starts_with("crates/") || path == "Cargo.toml" || path == "Cargo.lock"
}

/// The source digest of the tree at `root`.
///
/// # Errors
///
/// A tree that is not a repository, a tracked input that will not read, or a
/// tree holding no engine input at all.
///
/// NO INPUTS IS COULD-NOT-LOOK, NEVER A DIGEST (CLOUD-2230). Hashing nothing is
/// SHA-256's empty value, `e3b0c442…`, which names no source; measured on #1132,
/// a debug binary carried exactly that stamp and every `cargo run -p batten`
/// task refused under a source pin.
//MUTANT-SUITE crates/batten/tests/it/engine_pin.rs
//MUTANT empty-digest-stamped|s@^    if inputs == 0 {$@    if false {@|a_stamp_over_no_inputs_is_refused
pub fn digest(root: &Path) -> Result<String> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut inputs = 0_usize;
    for path in crate::git::tracked_paths(root)?
        .iter()
        .filter(|path| is_input(path))
    {
        let bytes = std::fs::read(root.join(path))?;
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
        hasher.update([0]);
        inputs += 1;
    }
    if inputs == 0 {
        return Err(UsageError::raise(format!(
            "engine digest: {} tracks no engine input (crates/, Cargo.toml, Cargo.lock), so it names no source",
            root.display()
        )));
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Where a source-pinned build is installed: `running`, and the first `batten`
/// on `path` outside the checkout at `root` (CLOUD-2226) — the installed engine
/// a hook registered as a bare `batten` runs.
///
/// THE FIRST ON `PATH`, NEVER EVERY ONE. A shadowed `batten` further down is not
/// what any hook runs, and replacing it reaches binaries nothing asked for:
/// measured while building this, a test whose `PATH` ended in the caller's own
/// overwrote the session's installed engine with a stub.
///
/// OUTSIDE THE CHECKOUT, for [`crate`]'s `follow_pin` reason (CLOUD-2063): a
/// binary under `root` is cargo's output, not an installed engine. Under
/// `mise exec` that output is first on `PATH`, and the one past it is what the
/// hook runs — the case #1132 measured.
//MUTANT-SUITE crates/batten/tests/it/engine_update.rs
//MUTANT source-update-installs-nothing|s@^        targets.push(resolved);$@@|a_source_pin_update_installs_where_the_hook_resolves
#[must_use]
pub fn install_targets(
    running: &Path,
    path: Option<&std::ffi::OsStr>,
    root: &Path,
) -> Vec<PathBuf> {
    let mut targets = vec![running.to_path_buf()];
    let resolved = path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .map(|dir| crate::git::canonical(&dir.join("batten")))
        .find(|candidate| {
            candidate.is_file() && !candidate.starts_with(crate::git::canonical(root))
        });
    if let Some(resolved) = resolved
        && resolved != crate::git::canonical(running)
    {
        targets.push(resolved);
    }
    targets
}

/// Write `digest` as the stamp beside `binary`.
///
/// # Errors
///
/// The stamp will not write.
pub fn stamp(binary: &Path, digest: &str) -> Result<()> {
    crate::durable::replace(stamp_path(binary), format!("{digest}\n"))?;
    Ok(())
}

/// The pin a config declares, read from its raw text without parsing the rest.
///
/// Top-level keys precede the first table header in TOML, so the scan stops
/// there; an `engine` line past it belongs to some table and is not the pin.
#[must_use]
pub fn declared(text: &str) -> Option<Pin> {
    let line = text
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
        .find(|line| {
            line.trim_start()
                .strip_prefix("engine")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })?;
    let table: toml::Table = toml::from_str(line).ok()?;
    table.get("engine")?.clone().try_into().ok()
}

/// The engine's own repair for a pin this build does not satisfy (CLOUD-2116).
///
/// One spelling for both halves: [`check`]'s refusal names it, and the hook's
/// floor over an unloadable config admits exactly it. A remedy naming a
/// consumer's installer was one the floor refused, so a skewed container could
/// run nothing at all, including the line its own refusal printed.
pub const REPAIR: &str = "batten engine update";

/// [`REPAIR`] run under the project's pinned toolchain (CLOUD-2172).
///
/// A SOURCE pin is repaired by a build, and a bare `cargo` resolves whatever
/// toolchain is ambient: measured, a container whose ambient rustup default was
/// older than the workspace's failed the build and could run nothing else. The
/// floor admits this spelling too, as one whole string for [`REPAIR`]'s reason,
/// so the build can be given the pin's environment without opening a shell to
/// composition.
pub const REPAIR_PINNED: &str = "mise exec -- batten engine update";

/// Whether `command` is one of the repair's two whole spellings: equality, so
/// no shell composition rides either.
//MUTANT floor-admits-a-carried-repair|s@^    command == REPAIR \x7c\x7c command == REPAIR_PINNED$@    command.contains(REPAIR)@|a_command_carrying_the_repair_verb_is_still_refused
#[must_use]
pub fn is_repair(command: &str) -> bool {
    command == REPAIR || command == REPAIR_PINNED
}

/// [`REPAIR`] spelled to run from wherever the shell stands (CLOUD-2218).
///
/// The hook judges by the session's recorded authority when the shell stands
/// outside it (CLOUD-2204), but the verb anchors on its cwd. Measured
/// 2026-10-11: the shell snapped back to the checkouts' parent, the refusal
/// named the bare verb as the one command admitted, and that verb answered
/// "not inside a git repository" — a floor whose only exit could not run.
/// So the refusal names the repair prefixed with the `cd` into the authority
/// it judged by, which also leaves the shell there for the calls after it.
#[must_use]
pub fn repair_at(root: &std::path::Path, repair: &str) -> String {
    format!("cd {} && {repair}", shell_word(&root.to_string_lossy()))
}

/// Whether `command` is a repair spelled whole, bare or rooted at `root`:
/// equality against strings built from the authority, so the `&&` admitted is
/// the one this engine wrote and no other composition rides it.
//MUTANT rooted-repair-refused|s@^            .any(\x7crepair\x7c command == repair_at(root, repair))$@            .any(\x7c_\x7c false)@|a_repair_rooted_at_the_authority_reaches_a_shell_standing_outside_it
#[must_use]
pub fn is_repair_at(command: &str, root: &std::path::Path) -> bool {
    is_repair(command)
        || [REPAIR, REPAIR_PINNED]
            .iter()
            .any(|repair| command == repair_at(root, repair))
}

/// `word` as one POSIX shell word: bare where it carries nothing the shell
/// reads, single-quoted otherwise.
fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@%:,".contains(c))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

//MUTANT-SUITE crates/batten/tests/it/engine_pin.rs
//MUTANT pin-unread|s@^    let Some(pin) = declared(text) else {$@    let Some(pin) = None::<Pin> else {@|a_release_pin_naming_another_build_is_refused_with_its_install
//MUTANT stamp-trusted-when-absent|s@^            if stamp.as_deref() != Some(digest) {$@            if stamp.is_some() \&\& stamp.as_deref() != Some(digest) {@|a_source_pin_without_a_stamp_is_refused

/// The repair for a stale build of the checkout it judges: the build itself,
/// under the project's toolchain for [`REPAIR_PINNED`]'s reason.
pub const REBUILD: &str = "mise exec -- cargo build --release -p batten";

/// Whether the running binary lives inside the tree holding `source`, the
/// config it was refused over — that tree's own build, not an installed engine.
//MUTANT in-tree-build-updated|s@^        .is_some_and(\x7croot\x7c exe.starts_with(root))$@        .is_some_and(\x7c_\x7c false)@|a_stale_build_of_the_checkout_names_the_rebuild
fn built_in(source: &str) -> bool {
    let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) else {
        return false;
    };
    std::fs::canonicalize(source)
        .ok()
        .as_deref()
        .and_then(std::path::Path::parent)
        .is_some_and(|root| exe.starts_with(root))
}

/// The variable that runs this binary as it is under a SOURCE pin.
pub const LOCAL_ENV: &str = "BATTEN_ENGINE";

/// Whether `BATTEN_ENGINE=local` asks for this binary as it is (CLOUD-2232),
/// Go's `GOTOOLCHAIN=local`: a test run of a branch tests the engine it built,
/// and an in-process load names its source by label rather than by a path the
/// in-tree arm could judge. Source pins only — a release pin is a published
/// engine's name, and running another under it is the skew this check refuses.
//MUTANT-SUITE crates/batten/tests/it/engine_pin.rs
//MUTANT local-engine-ignored|s@^    std::env::var_os(LOCAL_ENV).is_some_and(\x7cvalue\x7c value == "local")$@    false@|the_local_engine_runs_under_a_source_pin
fn runs_local() -> bool {
    std::env::var_os(LOCAL_ENV).is_some_and(|value| value == "local")
}

/// The checkout's own release build: the engine a source pin is followed to
/// (CLOUD-2232), rustup's `path` toolchain. ANY DIGEST, for the reason
/// [`check`]'s in-tree arm states: the pin moves with every edit under
/// `crates/`, and following only an exact stamp stranded the hook on every
/// refresh until a release build finished. Whether the pin is current is
/// `engine-pin:check`'s question. One `stat`, so the hook path can take it.
//MUTANT-SUITE crates/batten/tests/it/engine_update.rs
//MUTANT source-pin-unfollowed|s@^    build.is_file().then_some(build)$@    None::<PathBuf>.filter(\x7c_\x7c build.is_file())@|a_source_pin_is_followed_to_the_checkouts_build
#[must_use]
pub fn checkout_build(root: &Path) -> Option<PathBuf> {
    let build = root
        .join("target")
        .join("release")
        .join(crate::surface::BINARY);
    build.is_file().then_some(build)
}

/// Refuse a config whose pin this engine does not satisfy.
///
/// `stamp` yields this binary's recorded source digest, or `None` when it has
/// none. It is asked only for a source pin, so a config pinning a release — or
/// nothing — never touches the disk for it.
///
/// # Errors
///
/// A [`UsageError`] naming both identities and the update, when the pin names
/// another release or another source, names both or neither, or names a source
/// this binary carries no stamp for.
//MUTANT-SUITE crates/batten/tests/it/engine_update.rs
//MUTANT in-tree-build-unaccepted|s@^            if built_in(source) \x7c\x7c runs_local() {$@            if runs_local() {@|the_checkouts_own_build_satisfies_its_source_pin
pub fn check(text: &str, source: &str, stamp: impl FnOnce() -> Option<String>) -> Result<()> {
    let Some(pin) = declared(text) else {
        return Ok(());
    };
    match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), None) => {
            let running = release();
            if tag != running {
                // A BUILD OF THIS CHECKOUT IS REBUILT, NEVER UPDATED (CLOUD-2220).
                // `follow_pin` leaves an in-tree binary alone (CLOUD-2063), so
                // naming the update here sent a session to a verb that runs the
                // same stale build: measured, `mise exec -- batten` resolved
                // `target/release` at 0.0.213 under a 0.0.214 pin.
                let repair = if built_in(source) { REBUILD } else { REPAIR };
                return Err(UsageError::raise(format!(
                    "{source} pins batten {tag} and this engine is {running}: install the pin \
                     with `{repair}`"
                )));
            }
            Ok(())
        }
        (None, Some(digest)) => {
            // THE CHECKOUT'S OWN BUILD ANSWERS FOR THE CHECKOUT'S OWN PIN
            // (CLOUD-2232), rustup's `path` toolchain: a source pin names this
            // tree, and a binary cargo built inside it IS that tree's engine —
            // so `cargo test`, `cargo run` and `target/release` load a branch's
            // source-pinned config without a separate stamp step.
            //
            // NO DIGEST COMPARISON HERE, and the reason is measured: the pin is
            // the digest the tree had when it was written, and every edit under
            // `crates/` moves the tree's — so comparing them refused the tree's
            // own build mid-edit and blamed the binary for a stale PIN. Pin
            // freshness is `engine-pin:check`'s question, asked at commit and in
            // CI. An installed copy outside the checkout still proves itself by
            // its stamp. Stated limit: an in-tree build older than the tree
            // passes until rebuilt, the exposure a release pin's in-tree build
            // already carries.
            if built_in(source) || runs_local() {
                return Ok(());
            }
            let stamp = stamp();
            if stamp.as_deref() != Some(digest) {
                let running = stamp.as_deref().unwrap_or("unstamped");
                return Err(UsageError::raise(format!(
                    "{source} pins the engine built from source {digest} and this engine is \
                     {running}: build and stamp it with `{REPAIR}`"
                )));
            }
            Ok(())
        }
        _ => Err(UsageError::raise(format!(
            "{source}: `engine` names exactly one of `release` or `source`"
        ))),
    }
}

/// This running binary's stamp, or `None` when it carries none.
#[must_use]
pub fn running_stamp() -> Option<String> {
    let binary = std::env::current_exe().ok()?;
    let text = std::fs::read_to_string(stamp_path(&binary)).ok()?;
    let digest = text.trim();
    (!digest.is_empty()).then(|| digest.to_owned())
}

/// The pin, when one is declared and this engine does not satisfy it.
///
/// [`check`]'s question without its refusal, for the caller that would rather
/// update than refuse (CLOUD-2062). `None` covers both "no pin" and "satisfied";
/// a malformed pin is left to [`check`] to name.
#[must_use]
pub fn stale(text: &str, stamp: impl FnOnce() -> Option<String>) -> Option<Pin> {
    stale_as(text, stamp, runs_local())
}

/// [`stale`], with `BATTEN_ENGINE=local`'s answer passed in rather than read,
/// so the decision is a function of its arguments.
fn stale_as(text: &str, stamp: impl FnOnce() -> Option<String>, local: bool) -> Option<Pin> {
    let pin = declared(text)?;
    let satisfied = match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), None) => tag == release(),
        // `BATTEN_ENGINE=local` satisfies a source pin here exactly as it does
        // in [`check`]: one answer to "is this the engine", or a test run of
        // the branch would try to BUILD the pin it was told to run without.
        (None, Some(digest)) => local || stamp().as_deref() == Some(digest),
        _ => true,
    };
    (!satisfied).then_some(pin)
}

/// The target triple this binary was built for, from its own compile-time `cfg`.
///
/// The triple the release matrix names (`dist::archive_stem`), so a release
/// update installs the same platform it replaces. Derived from the build itself
/// rather than probed from the host, which is the question a self-update asks:
/// "the release of ME".
#[must_use]
pub fn running_target() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "linux" if cfg!(target_env = "musl") => format!("{arch}-unknown-linux-musl"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "macos" => format!("{arch}-apple-darwin"),
        "windows" if cfg!(target_env = "gnu") => format!("{arch}-pc-windows-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        os => format!("{arch}-unknown-{os}"),
    }
}

/// The release archive's asset name for `tag` on `target`.
#[must_use]
pub fn release_asset(tag: &str, target: &str) -> String {
    let version = tag.trim_start_matches('v');
    format!(
        "{}{}",
        crate::dist::archive_stem("batten", version, target),
        crate::dist::archive_ext(target)
    )
}

/// Where `tag`'s `file` is published, under the engine's own repository.
#[must_use]
pub fn release_url(repository: &str, tag: &str, file: &str) -> String {
    format!(
        "{}/releases/download/{tag}/{file}",
        repository.trim_end_matches('/')
    )
}

/// The digest `sums` (a `SHA256SUMS` body) publishes for `asset`.
#[must_use]
pub fn published_digest(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset).then(|| digest.to_ascii_lowercase())
    })
}

//MUTANT-SUITE crates/batten/src/engine.rs
//MUTANT digest-unchecked|s@^    if got != want {$@    if false {@|an_archive_whose_digest_disagrees_is_refused

/// Refuse an archive whose SHA-256 is not the one its release published.
///
/// # Errors
///
/// A [`UsageError`] when `sums` names no digest for `asset`, or names another
/// one: the downloaded bytes are not the release's, and nothing is installed.
pub fn verify(archive: &[u8], sums: &str, asset: &str) -> Result<()> {
    let want = published_digest(sums, asset).ok_or_else(|| {
        UsageError::raise(format!(
            "engine update: the release publishes no digest for {asset}, so it cannot be verified"
        ))
    })?;
    let got = crate::receipt::hex_sha256(archive);
    if got != want {
        return Err(UsageError::raise(format!(
            "engine update: {asset} hashes {got}, not the {want} its release published; nothing was installed"
        )));
    }
    Ok(())
}

/// The engine binary of release `tag`, fetched from `repository` for this build's
/// own target and checked against that release's `SHA256SUMS` (CLOUD-2062).
///
/// The one network door this module opens, and only `batten engine update` and
/// the startup update off the hook path reach it.
///
/// # Errors
///
/// Either download answering other than 200, a digest that disagrees, or an
/// archive with no binary at its root — in every case nothing is installed.
pub fn fetch_release(repository: &str, tag: &str) -> Result<Vec<u8>> {
    let target = running_target();
    let asset = release_asset(tag, &target);
    let archive = crate::fetch::get(&release_url(repository, tag, &asset), &[])?;
    let sums = crate::fetch::get(&release_url(repository, tag, "SHA256SUMS"), &[])?;
    if archive.status != 200 || sums.status != 200 {
        return Err(UsageError::raise(format!(
            "engine update: {tag} answered {} for {asset} and {} for SHA256SUMS; nothing was installed",
            archive.status, sums.status
        )));
    }
    verify(&archive.body, &String::from_utf8_lossy(&sums.body), &asset)?;
    extract(&archive.body, &crate::dist::binary_file("batten", &target))
}

/// The release tag `reference`'s workspace manifest names, read off the
/// repository's raw-file host — never the API, whose anonymous budget a shared
/// egress address spends (CLOUD-2203).
///
/// # Errors
///
/// A manifest that does not answer `200`, or names no version. An operator who
/// named a ref asked for THAT release, so a ref that cannot be read is a
/// refusal rather than a quiet install of whatever binary is running.
pub fn ref_release(repository: &str, reference: &str) -> Result<String> {
    let raw = repository.trim_end_matches('/').replacen(
        "https://github.com/",
        "https://raw.githubusercontent.com/",
        1,
    );
    let url = format!("{raw}/{reference}/Cargo.toml");
    let answer = crate::fetch::get(&url, &[])?;
    if answer.status != 200 {
        return Err(UsageError::raise(format!(
            "engine install: {url} answered {}, so the release ref {reference} names is unknown; nothing was installed",
            answer.status
        )));
    }
    String::from_utf8_lossy(&answer.body)
        .lines()
        .find_map(|line| {
            let version = line.strip_prefix("version = \"")?.strip_suffix('"')?;
            Some(format!("v{version}"))
        })
        .ok_or_else(|| {
            UsageError::raise(format!(
                "engine install: {url} names no version; nothing was installed"
            ))
        })
}

/// A release asked for by tag: its verified binary, or the fact that the tag is
/// not published yet.
#[derive(Debug, PartialEq, Eq)]
pub enum Release {
    /// The binary, fetched and checked against the release's `SHA256SUMS`.
    Published(Vec<u8>),
    /// The release host answered `404` for the tag's `SHA256SUMS`.
    Unpublished,
}

/// [`fetch_release`], except that a tag the host does not publish is an answer
/// rather than an error.
///
/// **ONLY A `404` IS "UNPUBLISHED".** release-plz bumps the manifest before it
/// tags, so trunk routinely names a release that does not exist yet, and that is
/// the one case a caller may fall back from. A timeout, a 5xx or a digest that
/// disagrees is the host failing to answer or answering wrongly, and is
/// propagated: falling back from those would install a binary nobody asked for.
///
/// # Errors
///
/// As [`fetch_release`], for any answer but a `404` on `SHA256SUMS`.
pub fn fetch_published(repository: &str, tag: &str) -> Result<Release> {
    let sums = crate::fetch::get(&release_url(repository, tag, "SHA256SUMS"), &[])?;
    if sums.status == 404 {
        return Ok(Release::Unpublished);
    }
    fetch_release(repository, tag).map(Release::Published)
}

/// What `engine install` installs (CLOUD-2203).
#[derive(Debug, PartialEq, Eq)]
pub enum Pick {
    /// The running binary, under its own tag.
    Running,
    /// Another release's binary.
    Fetched {
        /// The release's tag.
        tag: String,
        /// Its verified binary.
        bytes: Vec<u8>,
    },
    /// The running binary, because the release a ref names is not published.
    Unpublished {
        /// The tag the ref named.
        wanted: String,
    },
}

/// Decide which release `engine install` installs, with the network injected so
/// every arm is a unit case.
///
/// - **A named version wins, and the ref is never read.** The bootstrap already
///   fetched and verified the release `BATTEN_VERSION` named, and that is the
///   binary running; replacing it with the ref's would install a version nobody
///   asked for.
/// - With no ref, the running binary.
/// - A ref naming the running release needs no fetch.
/// - A ref naming another release installs that release, or — only when the
///   host answers that it is not published — the running binary, said so.
///
/// # Errors
///
/// Whatever `ref_version` or `fetch` raises: a ref that cannot be read, or a
/// release that cannot be fetched for any reason but not being published.
pub fn pick_release(
    running: &str,
    named: bool,
    ref_version: impl FnOnce() -> Result<Option<String>>,
    fetch: impl FnOnce(&str) -> Result<Release>,
) -> Result<Pick> {
    if named {
        return Ok(Pick::Running);
    }
    let Some(wanted) = ref_version()? else {
        return Ok(Pick::Running);
    };
    if wanted == running {
        return Ok(Pick::Running);
    }
    Ok(match fetch(&wanted)? {
        Release::Published(bytes) => Pick::Fetched { tag: wanted, bytes },
        Release::Unpublished => Pick::Unpublished { wanted },
    })
}

/// The `bin` entry at the root of a `.tar.gz` release archive.
///
/// # Errors
///
/// An archive that will not read, or one with no `bin` at its root.
pub fn extract(archive: &[u8], bin: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut entries = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in entries.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let at_root = path
            .to_str()
            .is_some_and(|name| name.trim_start_matches("./") == bin);
        if at_root {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
    }
    Err(UsageError::raise(format!(
        "engine update: the release archive carries no {bin} at its root"
    )))
}

/// The one config line that declares `pin`.
#[must_use]
pub fn line(pin: &Pin) -> String {
    match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), _) => format!("engine = {{ release = \"{tag}\" }}"),
        (None, Some(digest)) => format!("engine = {{ source = \"{digest}\" }}"),
        (None, None) => String::from("engine = {}"),
    }
}

/// Whether `line` is the top-level `engine` key.
fn is_pin_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("engine")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// `text` with its top-level pin set to `pin` (CLOUD-2063).
///
/// The existing line is replaced in place. With none, the pin goes directly
/// after the first top-level key, so it stays above every table header — where
/// [`declared`] reads it — and no comment block is separated from its table.
/// Every other byte is kept.
#[must_use]
pub fn rewrite(text: &str, pin: &Pin) -> String {
    let wanted = line(pin);
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let header = lines
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    if let Some(at) = lines[..header].iter().position(|line| is_pin_line(line)) {
        lines[at] = wanted;
    } else {
        let key = lines[..header].iter().position(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        });
        lines.insert(key.map_or(0, |at| at + 1), wanted);
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The `batten` verbs a workflow's command lines invoke (CLOUD-2063).
///
/// A command line is one whose trimmed text, less a YAML `- ` list marker,
/// starts `batten ` or `run: batten `;
/// prose and comments that merely mention a verb are not invocations. The verb
/// is the leading lowercase words after `batten`, at most two, so
/// `batten pr ensure "$PR_NUM"` is `pr ensure`. `mise run batten -- …` builds
/// the engine from source and is not a released-binary call, which the rule
/// excludes by construction: the line does not start with `batten`.
#[must_use]
pub fn invoked_verbs(text: &str) -> std::collections::BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            trimmed
                .strip_prefix("run: batten ")
                .or_else(|| trimmed.strip_prefix("batten "))
        })
        .map(|rest| {
            rest.split_whitespace()
                .take_while(|word| {
                    word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                        && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                })
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|verb| !verb.is_empty())
        .collect()
}

/// Where the pinned release's binary is kept once fetched: under the
/// repository's STATE directory, never inside the checkout.
///
/// It was first under git's common directory, and a consumer's own SBOM scan
/// then catalogued the cached binary's embedded crates as the tree's — measured
/// here, `syft scan dir:.` walked into `.git/` and the lockfile count disagreed.
/// A cache is the engine's state, and state lives outside the tree it judges.
#[must_use]
pub fn cached_release(state_dir: &Path, tag: &str) -> PathBuf {
    state_dir
        .join("engine")
        .join(tag)
        .join(crate::dist::binary_file("batten", &running_target()))
}

/// The pinned release's binary, fetched and verified once and cached after.
///
/// # Errors
///
/// As [`fetch_release`], or a cache that will not write.
pub fn pinned_release(state_dir: &Path, repository: &str, tag: &str) -> Result<PathBuf> {
    let path = cached_release(state_dir, tag);
    if path.is_file() {
        return Ok(path);
    }
    let bytes = fetch_release(repository, tag)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(&path, bytes)?;
    make_executable(&path)?;
    Ok(path)
}

#[cfg(unix)]
pub(crate) fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn make_executable(_path: &Path) -> Result<()> {
    // Windows has no executable bit; the extension carries it.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ref_version` a case asserts is never consulted.
    fn unread() -> Result<Option<String>> {
        panic!("the ref must not be read")
    }

    /// A `fetch` a case asserts is never called.
    fn unfetched(_: &str) -> Result<Release> {
        panic!("no release may be fetched")
    }

    #[test]
    fn a_named_version_never_reads_the_ref_or_fetches() -> Result<()> {
        assert_eq!(
            pick_release("v1.0.0", true, unread, unfetched)?,
            Pick::Running
        );
        Ok(())
    }

    #[test]
    fn no_ref_installs_the_running_binary() -> Result<()> {
        assert_eq!(
            pick_release("v1.0.0", false, || Ok(None), unfetched)?,
            Pick::Running
        );
        Ok(())
    }

    #[test]
    fn a_ref_naming_the_running_release_fetches_nothing() -> Result<()> {
        assert_eq!(
            pick_release("v1.0.0", false, || Ok(Some("v1.0.0".into())), unfetched)?,
            Pick::Running
        );
        Ok(())
    }

    #[test]
    fn the_version_comes_from_the_refs_manifest() -> Result<()> {
        let pick = pick_release(
            "v1.0.0",
            false,
            || Ok(Some("v2.0.0".into())),
            |tag| {
                assert_eq!(tag, "v2.0.0", "the ref's version is the one fetched");
                Ok(Release::Published(b"two".to_vec()))
            },
        )?;
        assert_eq!(
            pick,
            Pick::Fetched {
                tag: "v2.0.0".into(),
                bytes: b"two".to_vec()
            }
        );
        Ok(())
    }

    #[test]
    fn an_unpublished_ref_release_falls_back_to_the_running_binary() -> Result<()> {
        let pick = pick_release(
            "v1.0.0",
            false,
            || Ok(Some("v2.0.0".into())),
            |_| Ok(Release::Unpublished),
        )?;
        assert_eq!(
            pick,
            Pick::Unpublished {
                wanted: "v2.0.0".into()
            }
        );
        Ok(())
    }

    #[test]
    fn a_fetch_that_fails_for_any_other_reason_is_never_a_fallback() {
        let pick = pick_release(
            "v1.0.0",
            false,
            || Ok(Some("v2.0.0".into())),
            |_| Err(UsageError::raise("digest disagrees")),
        );
        assert!(
            matches!(&pick, Err(err) if err.to_string().contains("digest disagrees")),
            "a failed fetch is propagated, not read as unpublished: {pick:?}"
        );
    }

    #[test]
    fn a_ref_that_cannot_be_read_is_a_refusal() {
        let pick = pick_release(
            "v1.0.0",
            false,
            || Err(UsageError::raise("manifest answered 500")),
            unfetched,
        );
        assert!(
            matches!(&pick, Err(err) if err.to_string().contains("500")),
            "an unreadable ref installs nothing: {pick:?}"
        );
    }

    #[test]
    fn a_pin_is_rewritten_in_place_or_inserted_above_every_table() {
        let release = Pin {
            release: Some("v0.0.201".into()),
            source: None,
        };
        let pinned = "version = 1\nengine = { source = \"ab\" }\n\n# rows\n[x]\ny = 1\n";
        assert_eq!(
            rewrite(pinned, &release),
            "version = 1\nengine = { release = \"v0.0.201\" }\n\n# rows\n[x]\ny = 1\n"
        );
        let bare = "# head\nversion = 1\n\n# rows\n[x]\nengine = 2\n";
        let inserted = rewrite(bare, &release);
        assert_eq!(
            inserted,
            "# head\nversion = 1\nengine = { release = \"v0.0.201\" }\n\n# rows\n[x]\nengine = 2\n"
        );
        assert_eq!(declared(&inserted), Some(release));
    }

    #[test]
    fn only_command_lines_invoke_a_verb() {
        let workflow = "      # hands them to `batten checks green`, a pure function\n\
                        \x20       run: |\n\
                        \x20         batten pr ensure \"$PR_NUM\"\n\
                        \x20     - run: batten checks green --sha x\n\
                        \x20     - run: mise run batten -- ci step -- true\n";
        let verbs: Vec<_> = invoked_verbs(workflow).into_iter().collect();
        assert_eq!(verbs, ["checks green", "pr ensure"]);
    }

    #[test]
    fn the_release_asset_url_is_the_dist_naming() {
        let asset = release_asset("v0.0.200", "x86_64-unknown-linux-musl");
        assert_eq!(asset, "batten-v0.0.200-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(
            release_url("https://github.com/o/r/", "v0.0.200", &asset),
            "https://github.com/o/r/releases/download/v0.0.200/batten-v0.0.200-x86_64-unknown-linux-musl.tar.gz"
        );
    }

    #[test]
    fn an_archive_whose_digest_disagrees_is_refused() {
        let archive = b"the release bytes";
        let right = crate::receipt::hex_sha256(archive);
        let sums = format!("{right}  a.tar.gz\n{}  b.tar.gz\n", "0".repeat(64));
        assert!(verify(archive, &sums, "a.tar.gz").is_ok());
        assert!(
            verify(archive, &sums, "b.tar.gz").is_err(),
            "a wrong digest"
        );
        assert!(
            verify(archive, &sums, "c.tar.gz").is_err(),
            "no digest at all"
        );
    }

    #[test]
    fn the_binary_is_extracted_from_a_release_archive() -> Result<()> {
        let mut tarred = tar::Builder::new(Vec::new());
        for (name, body) in [("README", &b"docs"[..]), ("batten", &b"\x7fELF engine"[..])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tarred.append_data(&mut header, name, body)?;
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tarred.into_inner()?)?;
        let archive = gz.finish()?;
        assert_eq!(extract(&archive, "batten")?, b"\x7fELF engine");
        assert!(extract(&archive, "missing").is_err());
        Ok(())
    }

    #[test]
    fn a_satisfied_or_absent_pin_is_not_stale() {
        let tag = release();
        let stale =
            |text: &str, stamp: Option<&str>| stale_as(text, || stamp.map(str::to_owned), false);
        assert!(stale("version = 1\n", None).is_none());
        assert!(stale(&format!("engine = {{ release = \"{tag}\" }}\n"), None).is_none());
        assert!(stale("engine = { release = \"v0.0.1\" }\n", None).is_some());
        assert!(stale("engine = { source = \"ab\" }\n", Some("ab")).is_none());
        assert!(stale("engine = { source = \"ab\" }\n", None).is_some());
    }

    /// `BATTEN_ENGINE=local` (CLOUD-2232) answers a source pin and never a
    /// release pin.
    #[test]
    fn the_local_engine_answers_a_source_pin_only() {
        assert!(stale_as("engine = { source = \"ab\" }\n", || None, true).is_none());
        assert!(stale_as("engine = { release = \"v0.0.1\" }\n", || None, true).is_some());
    }
}
