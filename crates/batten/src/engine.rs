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

/// What a [`Pin`] names, decided once (CLOUD-2418): a verb that matches this
/// rather than the two fields reads a malformed pin as every other such verb
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinKind {
    /// A published release, by tag.
    Release(String),
    /// A source build, by digest.
    Source(String),
    /// Both fields, or neither.
    Malformed,
}

/// What every verb says of a [`PinKind::Malformed`] pin.
pub const MALFORMED_PIN: &str = "`engine` names exactly one of `release` or `source`";

impl Pin {
    /// What this pin names.
    #[must_use]
    pub fn kind(self) -> PinKind {
        match (self.release, self.source) {
            (Some(tag), None) => PinKind::Release(tag),
            (None, Some(digest)) => PinKind::Source(digest),
            _ => PinKind::Malformed,
        }
    }
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
//MUTANT-SUITE crates/batten/tests/it/engine_install.rs
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

/// Whether `running` is an installed engine rather than the bootstrap's
/// download (CLOUD-2287): it is the first `batten` on `path`, or it lies under
/// the worktree at `root`, where `mise exec` puts the checkout's build first.
///
/// An installed engine is repaired in place over [`install_targets`]; anything
/// else is a fresh binary to place where `install::destination` says.
#[must_use]
pub fn is_installed(running: &Path, path: Option<&std::ffi::OsStr>, root: Option<&Path>) -> bool {
    let running = crate::git::canonical(running);
    let in_tree = root.is_some_and(|root| running.starts_with(crate::git::canonical(root)));
    let first = path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .map(|dir| dir.join("batten"))
        .find(|candidate| candidate.is_file())
        .map(|candidate| crate::git::canonical(&candidate));
    in_tree || first.as_deref() == Some(running.as_path())
}

/// Whether release `latest` is newer than release `current`, both `v`-prefixed
/// tags (CLOUD-2287): `engine update` only ever moves a pin forward.
///
/// # Errors
///
/// A [`UsageError`] naming a tag that is not a version.
pub fn is_newer(latest: &str, current: &str) -> Result<bool> {
    Ok(release_version(latest)? > release_version(current)?)
}

/// The version a release tag names, with or without its `v` (CLOUD-2279): the
/// one reading of the tag grammar every engine verb shares.
///
/// # Errors
///
/// A [`UsageError`] naming a tag that is not a version.
pub fn release_version(tag: &str) -> Result<semver::Version> {
    semver::Version::parse(tag.trim_start_matches('v'))
        .map_err(|_| UsageError::raise(format!("engine: {tag} is not a release tag (v0.0.201)")))
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
    top_level(text, "engine")?.try_into().ok()
}

/// One top-level key of a config, read from its raw text without parsing the
/// rest (CLOUD-2279): the scan [`declared`] makes, for any key.
///
/// It survives a file that does not parse as a whole, which is what a reader
/// running before the load needs; a key past the first table header is that
/// table's, not the top level's.
#[must_use]
pub fn top_level(text: &str, key: &str) -> Option<toml::Value> {
    let line = text
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
        .find(|line| {
            line.trim_start()
                .strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })?;
    let mut table: toml::Table = toml::from_str(line).ok()?;
    table.remove(key)
}

/// The engine's own repair for a pin this build does not satisfy (CLOUD-2116).
///
/// One spelling for both halves: [`check`]'s refusal names it, and the hook's
/// floor over an unloadable config admits exactly it. A remedy naming a
/// consumer's installer was one the floor refused, so a skewed container could
/// run nothing at all, including the line its own refusal printed.
pub const REPAIR: &str = "batten engine install";

/// [`REPAIR`] run under the project's pinned toolchain (CLOUD-2172).
///
/// A SOURCE pin is repaired by a build, and a bare `cargo` resolves whatever
/// toolchain is ambient: measured, a container whose ambient rustup default was
/// older than the workspace's failed the build and could run nothing else. The
/// floor admits this spelling too, as one whole string for [`REPAIR`]'s reason,
/// so the build can be given the pin's environment without opening a shell to
/// composition.
pub const REPAIR_PINNED: &str = "mise exec -- batten engine install";

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
//MUTANT stamp-trusted-when-absent|s@^            if stamp.as_deref() != Some(digest.as_str()) {$@            if stamp.is_some() \&\& stamp.as_deref() != Some(digest.as_str()) {@|a_source_pin_without_a_stamp_is_refused

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
pub(crate) fn runs_local() -> bool {
    std::env::var_os(LOCAL_ENV).is_some_and(|value| value == "local")
}

/// The checkout's own release build: the engine a source pin is followed to
/// (CLOUD-2232), rustup's `path` toolchain. ANY DIGEST, for the reason
/// [`check`]'s in-tree arm states: the pin moves with every edit under
/// `crates/`, and following only an exact stamp stranded the hook on every
/// refresh until a release build finished. Whether the pin is current is
/// `engine-pin:check`'s question. One `stat`, so the hook path can take it.
///
/// # IT READS NO `CARGO_TARGET_DIR`, BECAUSE `root` MAY NOT BE THIS TREE
///
/// `CARGO_TARGET_DIR` is a fact about where THIS process's cargo writes, so it
/// speaks only for the tree this process would build. Both of this function's
/// callers ask about another one: the hook's load-fault hand-off asks about the
/// envelope's authority, a DIFFERENT checkout in exactly the case it exists for
/// (CLOUD-2204), and `collect` asks so the pruner spares the binary the hook
/// execs. Applying the variable to them would answer about a tree nobody asked
/// about — the hook following a source pin into a stranger's engine.
///
/// So this is the conventional path and nothing else. A caller asking about the
/// tree this process would run cargo in wants [`own_build`], which honours the
/// redirect because for that caller it is true.
///
/// Containment was tried first — honour the redirect while it lands inside
/// `root` — and it was wrong in BOTH directions, which is why the distinction
/// is drawn by caller rather than by path shape: an absolute redirect out of
/// the tree stopped `follow_pin` finding its own build, reinstating the drift
/// CLOUD-2376 closed, while a RELATIVE one resolved under the authority and was
/// honoured for a tree this process never built.
//MUTANT-SUITE crates/batten/tests/it/engine_update.rs
//MUTANT foreign-target-dir-read|s@^        .join("target")$@        .join(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(\x7c\x7c "target".into()))@|the_handoff_reads_no_target_dir_of_this_process
#[must_use]
pub fn checkout_build(root: &Path) -> Option<PathBuf> {
    let build = root
        .join("target")
        .join("release")
        .join(crate::surface::BINARY);
    existing(build)
}

/// A named build, or `None` where nothing is there.
///
/// **ONE LINE, BECAUSE TWO WERE INDISTINGUISHABLE.** Both lookups ended
/// `build.is_file().then_some(build)`, and `source-pin-unfollowed` anchored on
/// that text — but `mutate::substitute` applies a script per LINE across the
/// whole file, so the row rewrote BOTH functions and isolated neither. The gate
/// stayed green while proving less than it read as proving, which is the defect
/// `hand_off` collapsed two hand-offs to fix. Same answer here: one existence
/// rule, one line, one row over it.
//MUTANT-SUITE crates/batten/tests/it/engine_install.rs
//MUTANT build-presence-unchecked|s@^    build.is_file().then_some(build)$@    None::<PathBuf>.filter(\x7c_\x7c build.is_file())@|a_source_pin_is_followed_to_the_checkouts_build
fn existing(build: PathBuf) -> Option<PathBuf> {
    build.is_file().then_some(build)
}

/// [`checkout_build`] for the tree THIS PROCESS would run cargo in, which is
/// the one `CARGO_TARGET_DIR` speaks for (CLOUD-2376).
///
/// `follow_pin`'s source arm is the caller: it resolves its root from the
/// working directory and is the sibling of `install_source`, which builds in
/// that same root with this process's environment inherited. The two ends of
/// one file therefore agree for every value of the variable, absolute or
/// relative — which is the agreement this issue exists to restore.
//MUTANT-SUITE crates/batten/tests/it/engine_update.rs
//MUTANT own-build-ignores-the-target-dir|s@^    existing(release_build(root))$@    existing(root.join("target").join("release").join(crate::surface::BINARY))@|a_source_pin_is_followed_into_a_redirected_target_dir
#[must_use]
pub fn own_build(root: &Path) -> Option<PathBuf> {
    existing(release_build(root))
}

/// Where this checkout's release build LIVES — the one place that names it
/// (CLOUD-2376).
///
/// Two call sites spelled it: the lookup above and the install that produces
/// it. The install honoured `CARGO_TARGET_DIR` and the lookup did not, so with
/// that variable set a source pin was followed to a stale build at
/// `target/release`, or to nothing at all, while the build `engine install`
/// had just written sat somewhere else. A path two functions agree on only by
/// coincidence is the drift this repository refuses everywhere else.
///
/// `CARGO_TARGET_DIR` is resolved AGAINST `root`, because that is how cargo
/// resolves it: the build runs with `root` as its working directory, so a
/// relative value names a directory inside the checkout. An absolute value is
/// taken as it is, which is what [`Path::join`] already does.
///
/// It reads THIS PROCESS's environment, which the signature does not show, and
/// that is right only for the tree this process would run cargo in — which is
/// what `install_source` asks about, its cargo child inheriting the same
/// value. Asking about ANOTHER tree is [`checkout_build`]'s question, which it
/// answers by reading no environment at all; a caller that publishes a target
/// directory to a child instead, as `replay`, `perf` and `mutate` each do for
/// their own spawns, would have to pass it in.
#[must_use]
pub fn release_build(root: &Path) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .filter(|dir| !dir.is_empty())
        .unwrap_or_else(|| "target".into());
    root.join(target)
        .join("release")
        .join(crate::surface::BINARY)
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
//MUTANT-SUITE crates/batten/tests/it/engine_install.rs
//MUTANT in-tree-build-unaccepted|s@^            if built_in(source) \x7c\x7c runs_local() {$@            if runs_local() {@|the_checkouts_own_build_satisfies_its_source_pin
pub fn check(text: &str, source: &str, stamp: impl FnOnce() -> Option<String>) -> Result<()> {
    let Some(pin) = declared(text) else {
        return Ok(());
    };
    match pin.kind() {
        PinKind::Release(tag) => {
            let running = release();
            if tag != running {
                // A RELEASE PIN IS REPAIRED BY THE RELEASE, NEVER BY A BUILD.
                // CLOUD-2220 named `cargo build` here for a stale in-tree binary,
                // and that build reports the tag's version without being the
                // release: the pin is then satisfied by a binary it does not
                // name. The install puts the pinned release over the running
                // binary, in-tree included — measured 2026-10-14, the repair
                // (then spelled `engine update`, CLOUD-2287) replaced
                // `target/release` at 0.0.215 with the published 0.0.216. In-tree, the pinned spelling, so
                // it runs as the binary `_.path` resolves.
                let repair = if built_in(source) {
                    REPAIR_PINNED
                } else {
                    REPAIR
                };
                return Err(UsageError::raise(format!(
                    "{source} pins batten {tag} and this engine is {running}: install the pin \
                     with `{repair}`"
                )));
            }
            Ok(())
        }
        PinKind::Source(digest) => {
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
            if stamp.as_deref() != Some(digest.as_str()) {
                let running = stamp.as_deref().unwrap_or("unstamped");
                return Err(UsageError::raise(format!(
                    "{source} pins the engine built from source {digest} and this engine is \
                     {running}: build and stamp it with `{REPAIR}`"
                )));
            }
            Ok(())
        }
        PinKind::Malformed => Err(UsageError::raise(format!("{source}: {MALFORMED_PIN}"))),
    }
}

/// This running binary's stamp, or `None` when it carries none.
#[must_use]
pub fn running_stamp() -> Option<String> {
    stamp_of(&std::env::current_exe().ok()?)
}

/// `binary`'s stamp, or `None` when it carries none.
#[must_use]
pub fn stamp_of(binary: &Path) -> Option<String> {
    let text = std::fs::read_to_string(stamp_path(binary)).ok()?;
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

/// Every `(digest, asset)` entry of a `SHA256SUMS` body: the one reading of the
/// manifest's line grammar, the digest lowercased and the asset less its `*`
/// binary-mode marker.
fn sums_entries(sums: &str) -> impl Iterator<Item = (String, &str)> {
    sums.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        Some((digest.to_ascii_lowercase(), name))
    })
}

/// The digest `sums` (a `SHA256SUMS` body) publishes for `asset`.
#[must_use]
pub fn published_digest(sums: &str, asset: &str) -> Option<String> {
    sums_entries(sums).find_map(|(digest, name)| (name == asset).then_some(digest))
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
            "engine install: the release publishes no digest for {asset}, so it cannot be verified"
        ))
    })?;
    let got = crate::receipt::hex_sha256(archive);
    if got != want {
        return Err(UsageError::raise(format!(
            "engine install: {asset} hashes {got}, not the {want} its release published; nothing was installed"
        )));
    }
    Ok(())
}

/// The engine binary of release `tag`, fetched from `repository` for this build's
/// own target and checked against that release's `SHA256SUMS` (CLOUD-2062).
///
/// The one network door this module opens, and only `batten engine install`
/// (with `engine update` in front of it) and the startup follow off the hook
/// path reach it.
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
            "engine install: {tag} answered {} for {asset} and {} for SHA256SUMS; nothing was installed",
            archive.status, sums.status
        )));
    }
    verify(&archive.body, &String::from_utf8_lossy(&sums.body), &asset)?;
    extract(&archive.body, &crate::dist::binary_file("batten", &target))
}

/// The release `reference`'s `batten.toml` pins, read off the repository's
/// raw-file host — never the API, whose anonymous budget a shared egress
/// address spends (CLOUD-2203).
///
/// **The pin, never the manifest's version (CLOUD-2033).** The workspace
/// version names a release that may not be published yet — release-plz bumps
/// it first — while `main`'s pin only ever names one that is published,
/// immutable, complete and verified. A ref pinning no release is refused rather
/// than answered with the latest one.
///
/// # Errors
///
/// A `batten.toml` that does not answer `200`, or pins no release. An operator
/// who named a ref asked for THAT release, so a ref that cannot be read is a
/// refusal rather than a quiet install of whatever binary is running.
pub fn ref_release(repository: &str, reference: &str) -> Result<String> {
    let url = raw_url(repository, reference, "batten.toml");
    let answer = crate::fetch::get(&url, &[])?;
    if answer.status != 200 {
        return Err(UsageError::raise(format!(
            "engine install: {url} answered {}, so the release ref {reference} pins is unknown; nothing was installed",
            answer.status
        )));
    }
    declared(&String::from_utf8_lossy(&answer.body))
        .and_then(|pin| pin.release)
        .ok_or_else(|| {
            UsageError::raise(format!(
                "engine install: {url} pins no release, and engine install never installs the \
                 latest one; set BATTEN_VERSION to install a named release"
            ))
        })
}

/// `repository`'s raw-file URL for `path` at `reference`: the host
/// [`ref_release`] reads, never the API.
fn raw_url(repository: &str, reference: &str, path: &str) -> String {
    let raw = repository.trim_end_matches('/').replacen(
        "https://github.com/",
        "https://raw.githubusercontent.com/",
        1,
    );
    format!("{raw}/{reference}/{path}")
}

/// Where the engine's own repository keeps its changelog (CLOUD-2279).
pub const CHANGELOG: &str = "crates/batten/CHANGELOG.md";

/// One release a changelog heading names: `## [x.y.z](…) - YYYY-MM-DD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heading {
    /// The release's version, without the tag's `v`.
    pub version: semver::Version,
    /// The release's date, when the heading carries one.
    pub date: Option<String>,
}

/// Every release heading in a changelog body, in the order it lists them.
///
/// A line that is not a version heading — `## [Unreleased]`, prose, a deeper
/// heading — is not a release and is skipped.
#[must_use]
pub fn changelog_headings(text: &str) -> Vec<Heading> {
    text.lines()
        .filter_map(|line| {
            let (version, tail) = line.strip_prefix("## [")?.split_once(']')?;
            let version = semver::Version::parse(version).ok()?;
            let date = tail
                .rsplit_once(" - ")
                .map(|(_, date)| date.trim())
                .filter(|date| crate::waiver::Date::parse(date).is_ok())
                .map(str::to_owned);
            Some(Heading { version, date })
        })
        .collect()
}

/// The changelog headings `reference` carries, read off the raw-file host
/// beside its pin (CLOUD-2279).
///
/// # Errors
///
/// A changelog that does not answer `200`: the distance from a pin to the
/// latest release cannot be counted without it.
pub fn ref_changelog(repository: &str, reference: &str) -> Result<Vec<Heading>> {
    let url = raw_url(repository, reference, CHANGELOG);
    let answer = crate::fetch::get(&url, &[])?;
    if answer.status != 200 {
        return Err(anyhow::anyhow!(
            "engine outdated: {url} answered {}, so the releases since the pin are unknown",
            answer.status
        ));
    }
    Ok(changelog_headings(&String::from_utf8_lossy(&answer.body)))
}

/// The releases newer than `pin` and no newer than `latest`, oldest first.
///
/// A changelog that lags `latest` still counts it: being behind is never
/// answered as current because a heading is missing.
///
/// # Errors
///
/// A [`UsageError`] naming a tag that is not a version.
pub fn releases_between(headings: &[Heading], pin: &str, latest: &str) -> Result<Vec<Heading>> {
    let (pin, latest) = (release_version(pin)?, release_version(latest)?);
    let mut newer: Vec<Heading> = headings
        .iter()
        .filter(|heading| heading.version > pin && heading.version <= latest)
        .cloned()
        .collect();
    newer.sort_by(|left, right| left.version.cmp(&right.version));
    newer.dedup_by(|left, right| left.version == right.version);
    if latest > pin && newer.last().is_none_or(|heading| heading.version < latest) {
        newer.push(Heading {
            version: latest,
            date: None,
        });
    }
    Ok(newer)
}

/// Whole days from `date` (`YYYY-MM-DD`, UTC midnight) to `now` (Unix
/// seconds), never below zero; `None` for a date that will not parse.
#[must_use]
pub fn days_since(date: &str, now: u64) -> Option<u64> {
    let then = crate::landed::day_of(date)?;
    let today = i64::try_from(now / 86_400).ok()?;
    Some(u64::try_from(today.saturating_sub(then)).unwrap_or(0))
}

/// Every digest a `SHA256SUMS` body publishes, lowercased: the set
/// [`published_digest`] looks one name up in.
#[must_use]
pub fn published_digests(sums: &str) -> std::collections::BTreeSet<String> {
    sums_entries(sums).map(|(digest, _)| digest).collect()
}

/// Whether a `[[provision]]` row provisions batten itself (CLOUD-2279): the one
/// test `engine update` rewrites by and `engine gate` refuses by.
#[must_use]
pub fn is_batten_row(row: &dyn toml_edit::TableLike) -> bool {
    row.get("name").and_then(toml_edit::Item::as_str) == Some("batten")
}

/// The `SHA256SUMS` body release `tag` publishes (CLOUD-2279).
///
/// # Errors
///
/// A manifest that does not answer `200`: nothing can be pinned to a digest
/// the release does not publish.
pub fn release_sums(repository: &str, tag: &str) -> Result<String> {
    let url = release_url(repository, tag, "SHA256SUMS");
    let answer = crate::fetch::get(&url, &[])?;
    if answer.status != 200 {
        return Err(UsageError::raise(format!(
            "engine: {url} answered {}, so {tag}'s digests are unknown",
            answer.status
        )));
    }
    Ok(String::from_utf8_lossy(&answer.body).into_owned())
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
        "engine install: the release archive carries no {bin} at its root"
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

/// The 1-based line `item` starts on in `text`, the document it was parsed
/// from; 0 for an item that carries no span.
fn item_line(text: &str, item: &toml_edit::Item) -> usize {
    item.span()
        .map_or(0, |span| crate::lint::line_of(text, span.start))
}

/// The batten declarations in `text` that disagree with release pin `tag`
/// (CLOUD-2279): a `[[provision]] name = "batten"` row whose `version` is not
/// the pin, and a `min_batten_version` above it. Each is its 1-based line, what
/// it says, and the remedy that clears it: `engine update` moves a provision row
/// to the pin, but never lowers a floor, so a floor above the pin names the two
/// moves that can.
///
/// The document is parsed once, so a row is found however it is spelled, by
/// the same [`is_batten_row`] `engine update` rewrites by; a config that will
/// not parse is the load's to refuse, and has no findings here.
#[must_use]
pub fn disagreements(text: &str, tag: &str) -> Vec<(usize, String, &'static str)> {
    let (Ok(pin), Ok(doc)) = (release_version(tag), toml_edit::Document::parse(text)) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Some(item) = doc.get("min_batten_version")
        && let Some(floor) = item.as_str()
        && semver::Version::parse(floor).is_ok_and(|floor| ahead_of(&floor, &pin))
    {
        found.push((
            item_line(text, item),
            format!("min_batten_version {floor}"),
            PIN_UP,
        ));
    }
    let rows = doc
        .get("provision")
        .and_then(toml_edit::Item::as_array_of_tables)
        .into_iter()
        .flat_map(toml_edit::ArrayOfTables::iter);
    for row in rows.filter(|row| is_batten_row(*row)) {
        let Some(item) = row.get("version") else {
            continue;
        };
        let Some(version) = item.as_str() else {
            continue;
        };
        let parsed = release_version(version).ok();
        if parsed.as_ref() == Some(&pin) {
            continue;
        }
        let remedy = if parsed.is_some_and(|have| ahead_of(&have, &pin)) {
            PIN_UP
        } else {
            "run `batten engine update`"
        };
        found.push((
            item_line(text, item),
            format!("provision batten {version}"),
            remedy,
        ));
    }
    found.sort();
    found
}

/// `url` moved to release `new` (bare, `9.9.9`), or `None` when it names no
/// release download (CLOUD-2418).
///
/// **ONLY THE TWO PLACES A RELEASE URL CARRIES ITS VERSION MOVE:** the download
/// segment (`…/download/v8.8.8/`), whose `v` is kept as written, and the asset
/// name after it. A host, an org or a mirror path that happens to contain the
/// old version is left as it is, which a substring replace was not.
//MUTANT-SUITE crates/batten/src/engine.rs
//MUTANT url-swap-unanchored|s@^    Some(format!("{base}/{prefix}{new}/{asset}"))$@    Some(url.replace(old, new))@|a_moved_url_rewrites_only_its_release
//MUTANT gate-digest-case-sensitive|s@^        if pinned.map(str::to_ascii_lowercase) != published_digest(body, asset) {$@        if pinned.map(str::to_owned) != published_digest(body, asset) {@|an_artifact_at_the_pinned_version_is_judged_by_its_url_and_digest
#[must_use]
pub fn moved_url(url: &str, new: &str) -> Option<String> {
    let (head, asset) = url.rsplit_once('/')?;
    let (base, segment) = head.rsplit_once('/')?;
    let old = segment.strip_prefix('v').unwrap_or(segment);
    semver::Version::parse(old).ok()?;
    let prefix = if segment.starts_with('v') { "v" } else { "" };
    let asset = asset.replacen(old, new, 1);
    Some(format!("{base}/{prefix}{new}/{asset}"))
}

/// The batten provision artifacts in `text` that are not release `tag`'s own
/// (CLOUD-2418): a `url` that is not [`moved_url`] to the pin, or a `sha256`
/// that is not the digest `sums` publishes for the asset the `url` names. Each
/// is its 1-based line and what it says. Checked whatever the row's `version`
/// says, since a row can name the pin and still carry another release's bytes.
///
/// `sums` is asked for only once an artifact is found, so a config with none
/// reaches nothing.
///
/// # Errors
///
/// Whatever `sums` answers when it cannot give the manifest.
pub fn stale_artifacts(
    text: &str,
    tag: &str,
    sums: &dyn Fn() -> Result<String>,
) -> Result<Vec<(usize, String)>> {
    let (Ok(pin), Ok(doc)) = (release_version(tag), toml_edit::Document::parse(text)) else {
        return Ok(Vec::new());
    };
    let bare = pin.to_string();
    // THE MANIFEST IS READ ONCE, at the first artifact that needs it.
    let mut manifest: Option<String> = None;
    let mut found = Vec::new();
    let mut judge = |artifact: &dyn toml_edit::TableLike| -> Result<()> {
        let Some(item) = artifact.get("url") else {
            return Ok(());
        };
        let Some(url) = item.as_str() else {
            return Ok(());
        };
        // A URL LAID OUT AS NO RELEASE DOWNLOAD is not one this can judge, so it
        // is left to its author, as `engine update` leaves it while its row
        // stays put.
        let Some(moved) = moved_url(url, &bare) else {
            return Ok(());
        };
        if moved != url {
            found.push((item_line(text, item), format!("provision batten url {url}")));
            return Ok(());
        }
        let asset = asset_of(url);
        let digest = artifact.get("sha256");
        let body = match &mut manifest {
            Some(body) => body,
            slot @ None => slot.insert(sums()?),
        };
        let pinned = digest.and_then(toml_edit::Item::as_str);
        if pinned.map(str::to_ascii_lowercase) != published_digest(body, asset) {
            found.push((
                item_line(text, digest.unwrap_or(item)),
                format!("provision batten sha256 for {asset}"),
            ));
        }
        Ok(())
    };
    let rows = doc
        .get("provision")
        .and_then(toml_edit::Item::as_array_of_tables)
        .into_iter()
        .flat_map(toml_edit::ArrayOfTables::iter);
    for row in rows.filter(|row| is_batten_row(*row)) {
        judge(row)?;
        // Inline tables too: `engine update` rewrites either spelling.
        let platforms = row
            .get("platforms")
            .and_then(toml_edit::Item::as_table_like)
            .into_iter()
            .flat_map(toml_edit::TableLike::iter);
        for (_, artifact) in platforms {
            if let Some(artifact) = artifact.as_table_like() {
                judge(artifact)?;
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The asset a release download `url` names: its last path segment.
#[must_use]
pub fn asset_of(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or_default()
}

/// The `SHA256SUMS` release `tag` publishes, read once from `repository` and
/// cached beside its binary after (CLOUD-2418), so `engine gate` judges
/// provision digests without the network once the release is cached.
///
/// # Errors
///
/// As [`release_sums`], and an internal error when the cache cannot be written.
pub fn pinned_sums(state_dir: &Path, repository: &str, tag: &str) -> Result<String> {
    let path = release_dir(state_dir, tag).join("SHA256SUMS");
    if let Ok(body) = std::fs::read_to_string(&path) {
        return Ok(body);
    }
    let body = release_sums(repository, tag)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(&path, &body)?;
    Ok(body)
}

/// The remedy for a declaration [`ahead_of`] the pin, which `engine update`
/// never moves back.
const PIN_UP: &str = "pin a release at or above it, or lower it";

/// Whether a declared version is past the pin (CLOUD-2279): the one test of
/// what `engine update` leaves alone, because it moves forward only, and so of
/// which remedy `engine gate` names for it.
#[must_use]
pub fn ahead_of(declared: &semver::Version, pin: &semver::Version) -> bool {
    declared > pin
}

/// `line` less a YAML comment: from the first `#` that opens the line or
/// follows whitespace, outside a quoted string. A quote opens a string only
/// where a value can start — after whitespace, `:`, `=`, `[`, `,` or at the
/// line's start — so the apostrophe in `don't` is prose, not a string.
fn yaml_code(line: &str) -> &str {
    let mut quote = None;
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        let gap = previous.is_whitespace();
        let opens = gap || matches!(previous, ':' | '=' | '[' | ',');
        match quote {
            Some(open) if c == open => quote = None,
            None if matches!(c, '"' | '\'') && opens => quote = Some(c),
            None if c == '#' && gap => return &line[..at],
            Some(_) | None => {}
        }
        previous = c;
    }
    line
}

/// The keys a workflow can carry a copy of the engine's version or digest under.
const LITERAL_KEYS: [&str; 2] = ["BATTEN_VERSION", "BATTEN_SHA256"];

/// Whether `literal`, the value of `key`, is a copy that disagrees with release
/// `want` (bare): a version (`v?X.Y.Z`) other than it, or a 64-hex digest not
/// among `published`. Anything else — an expression, a word — is no copy.
fn literal_differs(
    key: &str,
    literal: &str,
    want: &str,
    published: &std::collections::BTreeSet<String>,
) -> bool {
    let literal = literal.trim();
    if key == "BATTEN_VERSION" {
        let bare = literal.trim_start_matches('v');
        semver::Version::parse(bare).is_ok() && bare != want
    } else {
        literal.len() == 64
            && literal.chars().all(|c| c.is_ascii_hexdigit())
            && !published.contains(&literal.to_ascii_lowercase())
    }
}

/// The `KEY: value` and `KEY=value` copies on one line of text, less a
/// comment: how a shell assignment inside a `run:` scalar carries one.
fn line_literals(line: &str) -> Vec<(&'static str, String)> {
    let line = yaml_code(line);
    let mut found = Vec::new();
    for key in LITERAL_KEYS {
        for (at, _) in line.match_indices(key) {
            let before = line[..at].chars().next_back();
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let rest = line[at + key.len()..].trim_start();
            let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
                continue;
            };
            let literal: String = rest
                .trim_start()
                .trim_start_matches(['"', '\''])
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                .collect();
            found.push((key, literal));
        }
    }
    found
}

/// Every event of `text` with the line it starts on, or `None` when it is not
/// YAML.
fn yaml_events(text: &str) -> Option<Vec<(yaml_rust2::Event, usize)>> {
    struct Events(Vec<(yaml_rust2::Event, usize)>);
    impl yaml_rust2::parser::MarkedEventReceiver for Events {
        fn on_event(&mut self, event: yaml_rust2::Event, mark: yaml_rust2::scanner::Marker) {
            self.0.push((event, mark.line()));
        }
    }
    let mut events = Events(Vec::new());
    yaml_rust2::parser::Parser::new_from_str(text)
        .load(&mut events, true)
        .ok()?;
    Some(events.0)
}

/// The literal `BATTEN_VERSION` / `BATTEN_SHA256` values in a workflow that
/// disagree with release `tag` (CLOUD-2279), as 1-based line and key.
///
/// **THE PARSER READS THE YAML (CLOUD-2418).** A mapping key is a copy's key
/// however it is quoted (`"BATTEN_VERSION": …`), its value is the scalar the
/// parser unquoted and unescaped, and a comment never reaches an event. A
/// scalar's own text is then read line by line for shell assignments
/// (`BATTEN_VERSION=v1.2.3` in a `run:` block), which no parser sees as keys.
/// A workflow that is not YAML is read line by line throughout, so it is never
/// passed as copy-free.
///
/// A value is a literal only when it is a version or a 64-hex digest; an
/// expression (`${{ … }}`) is not one, and a longer key such as
/// `BATTEN_VERSION_FROM_REF` is another key. A digest agrees when it is one of
/// `published`, the release's [`published_digests`].
//MUTANT-SUITE crates/batten/src/engine.rs
//MUTANT workflow-quoted-key-missed|s@^                        .find(\x7ckey\x7c \*key == value)$@                        .find(\x7c_\x7c false)@|a_quoted_workflow_key_is_a_copy
#[must_use]
pub fn workflow_literals(
    text: &str,
    tag: &str,
    published: &std::collections::BTreeSet<String>,
) -> Vec<(usize, &'static str)> {
    /// Where the walk stands inside each open collection.
    #[derive(PartialEq)]
    enum Frame {
        /// A mapping whose next scalar is a key.
        Key,
        /// A mapping whose next node is a value.
        Value,
        /// A sequence.
        Item,
    }
    let want = tag.trim_start_matches('v');
    let differs = |key: &str, literal: &str| literal_differs(key, literal, want, published);
    let mut found = Vec::new();
    let Some(events) = yaml_events(text) else {
        for (index, line) in text.lines().enumerate() {
            for (key, literal) in line_literals(line) {
                if differs(key, &literal) {
                    found.push((index + 1, key));
                }
            }
        }
        return found;
    };
    let mut stack: Vec<Frame> = Vec::new();
    // The copy key whose value comes next, with the key's line.
    let mut pending: Option<(&'static str, usize)> = None;
    // A node that completes a mapping's value turns it back to expecting a key.
    let settle = |stack: &mut Vec<Frame>| {
        if let Some(top) = stack.last_mut()
            && *top == Frame::Value
        {
            *top = Frame::Key;
        }
    };
    // A node where a mapping expects its key IS that key: the mapping now
    // expects the value. Answers whether the node was a key.
    let enter = |stack: &mut Vec<Frame>| {
        if let Some(top @ Frame::Key) = stack.last_mut() {
            *top = Frame::Value;
            true
        } else {
            false
        }
    };
    for (event, line) in events {
        match event {
            yaml_rust2::Event::MappingStart(..) => {
                enter(&mut stack);
                pending = None;
                stack.push(Frame::Key);
            }
            yaml_rust2::Event::SequenceStart(..) => {
                enter(&mut stack);
                pending = None;
                stack.push(Frame::Item);
            }
            yaml_rust2::Event::MappingEnd | yaml_rust2::Event::SequenceEnd => {
                stack.pop();
                settle(&mut stack);
            }
            yaml_rust2::Event::Scalar(value, ..) => {
                if enter(&mut stack) {
                    pending = LITERAL_KEYS
                        .into_iter()
                        .find(|key| *key == value)
                        .zip(Some(line));
                    continue;
                }
                if let Some((key, at)) = pending.take()
                    && differs(key, &value)
                {
                    found.push((at, key));
                }
                // The mark is the scalar's first line of text, a block scalar's
                // included (its `|` is on the line before), and past any blank
                // lines the value still opens with. A folded or multi-line plain
                // scalar joins its lines, so its copies point at its first line.
                let lead = value.len() - value.trim_start_matches('\n').len();
                for (offset, text_line) in value.lines().enumerate() {
                    for (key, literal) in line_literals(text_line) {
                        if differs(key, &literal) {
                            found.push((line + offset.saturating_sub(lead), key));
                        }
                    }
                }
                settle(&mut stack);
            }
            yaml_rust2::Event::Alias(_) => {
                pending = None;
                settle(&mut stack);
            }
            _ => {}
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// The `batten` verbs a workflow's command lines invoke (CLOUD-2063).
///
/// A command line is one whose trimmed text, less a YAML `- ` list marker and a
/// `run: `, starts `batten ` or `mise `; prose and comments that merely mention
/// a verb are not invocations. The verb is the leading lowercase words after
/// `batten`, at most two, so `batten pr ensure "$PR_NUM"` is `pr ensure`.
/// `mise run batten -- …` builds the engine from source and is not a
/// released-binary call, which the rule excludes by construction: only a bare
/// `batten` names the pinned release.
///
/// THE WRAPPED CALL TOO (CLOUD-2033): `batten ci step … -- batten release path`
/// runs the released binary twice, and reading only the line's first verb let a
/// lane call a verb its pin does not carry. Measured on #1132: three of four
/// such calls were invisible to this scan. Every `-- batten ` on a command line
/// is a released-binary call of its own.
//MUTANT-SUITE crates/batten/src/engine.rs
//MUTANT wrapped-verb-unseen|s@^        for (at, _) in command.match_indices("-- batten ") {$@        for (at, _) in command.match_indices("\\u{0}") {@|a_wrapped_released_call_invokes_its_verb
#[must_use]
pub fn invoked_verbs(text: &str) -> std::collections::BTreeSet<String> {
    fn verb(rest: &str) -> String {
        rest.split_whitespace()
            .take_while(|word| {
                word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }
    let mut verbs = std::collections::BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let command = trimmed.strip_prefix("run: ").unwrap_or(trimmed);
        if let Some(rest) = command.strip_prefix("batten ") {
            verbs.insert(verb(rest));
        } else if !command.starts_with("mise ") {
            continue;
        }
        for (at, _) in command.match_indices("-- batten ") {
            verbs.insert(verb(
                command.get(at + "-- batten ".len()..).unwrap_or_default(),
            ));
        }
    }
    verbs.retain(|verb| !verb.is_empty());
    verbs
}

/// The directory release `tag` is cached in: its binary ([`cached_release`]) and
/// its manifest ([`pinned_sums`]).
fn release_dir(state_dir: &Path, tag: &str) -> PathBuf {
    state_dir.join("engine").join(tag)
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
    release_dir(state_dir, tag).join(crate::dist::binary_file("batten", &running_target()))
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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

    /// `#MUTANT wrapped-verb-unseen` reads only each line's first verb.
    #[test]
    fn a_wrapped_released_call_invokes_its_verb() {
        let workflow = "      - run: batten ci step --arg-env X -- batten release path --strict\n\
                        \x20     - run: mise run batten -- ci step -- batten release in-flight\n\
                        \x20     - run: mise run batten -- ci step -- mise run batten -- release cut\n";
        let verbs: Vec<_> = invoked_verbs(workflow).into_iter().collect();
        assert_eq!(verbs, ["ci step", "release in-flight", "release path"]);
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

    /// A changelog that lags only its newest release still counts it
    /// (CLOUD-2279): three behind is never read as two.
    #[test]
    fn a_changelog_missing_its_newest_heading_still_counts_it() -> Result<()> {
        let headings = changelog_headings(
            "## [1.2.0](x) - 2026-02-01\n\n## [1.1.0](x) - 2026-01-01\n\n## [1.0.0](x) - 2025-12-01\n",
        );
        let newer = releases_between(&headings, "v1.0.0", "v1.3.0")?;
        let versions: Vec<String> = newer.iter().map(|h| h.version.to_string()).collect();
        assert_eq!(versions, ["1.1.0", "1.2.0", "1.3.0"]);
        Ok(())
    }

    /// A YAML comment is prose, and `KEY : value` is still the key.
    #[test]
    fn a_workflow_comment_is_not_a_copy_and_a_spaced_key_is() {
        let published = std::collections::BTreeSet::new();
        let found = workflow_literals(
            "# BATTEN_VERSION: 0.0.1\n  BATTEN_VERSION : \"0.0.210\"\n  run: make # BATTEN_VERSION: 0.0.2\n  run: echo don't # BATTEN_VERSION: 0.0.3\n  BATTEN_VERSION: 0.0.216\n",
            "v0.0.216",
            &published,
        );
        assert_eq!(found, [(2, "BATTEN_VERSION")]);
    }

    /// A quoted key is the same key, a quoted value is read unescaped, and a
    /// copy inside any string — a shell assignment in a `run:` block, or text
    /// that only looks like prose — is refused on its own line: a scalar cannot
    /// say which of its lines a shell will run.
    #[test]
    fn a_quoted_workflow_key_is_a_copy() {
        let published = std::collections::BTreeSet::new();
        let found = workflow_literals(
            "env:\n  \"BATTEN_VERSION\": \"v0.0.210\"\n  'BATTEN_SHA256': '{}'\n  NOTE: \"say \\\"BATTEN_VERSION: 0.0.1\\\" here\"\njobs:\n  x:\n    steps:\n      - run: |\n          echo ok\n          BATTEN_VERSION=v0.0.211 ./install.sh\n",
            "v0.0.216",
            &published,
        );
        assert_eq!(
            found,
            [
                (2, "BATTEN_VERSION"),
                (4, "BATTEN_VERSION"),
                (10, "BATTEN_VERSION")
            ]
        );
    }

    /// A block scalar that opens with a blank line still points at its copy's
    /// own line.
    #[test]
    fn a_block_scalar_opening_blank_points_at_its_copy() {
        let published = std::collections::BTreeSet::new();
        let found = workflow_literals(
            "steps:\n  - run: |\n\n      BATTEN_VERSION=v0.0.211 ./install.sh\n",
            "v0.0.216",
            &published,
        );
        assert_eq!(found, [(4, "BATTEN_VERSION")]);
    }

    /// A pre-release literal is read whole, so a copy equal to the pin agrees.
    #[test]
    fn a_pre_release_literal_equal_to_the_pin_agrees() {
        let published = std::collections::BTreeSet::new();
        let found = workflow_literals("  BATTEN_VERSION: 0.1.0-rc.1\n", "v0.1.0-rc.1", &published);
        assert!(found.is_empty(), "{found:?}");
    }

    /// A floor or a provision row above the pin names the moves that clear it,
    /// never the update that cannot move it back; a row below names the update.
    #[test]
    fn a_declaration_ahead_of_the_pin_names_its_own_remedy() {
        let found = disagreements(
            "min_batten_version = \"0.0.220\"\n\n[[provision]]\nname = \"batten\"\nversion = \"0.0.218\"\n\n[[provision]]\nname = \"batten\"\nversion = \"0.0.210\"\n",
            "v0.0.216",
        );
        let remedies: Vec<&str> = found.iter().map(|(_, _, remedy)| *remedy).collect();
        assert_eq!(remedies, [PIN_UP, PIN_UP, "run `batten engine update`"]);
    }

    /// Only the download segment and the asset name move; a mirror path that
    /// carries the old version is left alone, and the segment's `v` is kept.
    #[test]
    fn a_moved_url_rewrites_only_its_release() {
        assert_eq!(
            moved_url(
                "https://example.invalid/8.8.8-mirror/releases/download/v8.8.8/batten-8.8.8-x.tar.gz",
                "9.9.9"
            )
            .as_deref(),
            Some("https://example.invalid/8.8.8-mirror/releases/download/v9.9.9/batten-9.9.9-x.tar.gz")
        );
        assert_eq!(
            moved_url("https://h/download/8.8.8/a.zip", "9.9.9").as_deref(),
            Some("https://h/download/9.9.9/a.zip")
        );
        assert_eq!(moved_url("https://h/latest/a.zip", "9.9.9"), None);
    }

    /// A row naming the pin can still carry another release's url or bytes.
    #[test]
    fn an_artifact_at_the_pinned_version_is_judged_by_its_url_and_digest() -> Result<()> {
        let sums = || Ok(format!("{}  batten-9.9.9-x.tar.gz\n", "a".repeat(64)));
        let config = |url: &str, sha: &str| {
            format!(
                "[[provision]]\nname = \"batten\"\nversion = \"9.9.9\"\n\n[provision.platforms.x]\nurl = \"{url}\"\nsha256 = \"{sha}\"\n"
            )
        };
        let url = "https://h/download/v9.9.9/batten-9.9.9-x.tar.gz";
        assert!(stale_artifacts(&config(url, &"a".repeat(64)), "v9.9.9", &sums)?.is_empty());
        assert!(
            stale_artifacts(&config(url, &"A".repeat(64)), "v9.9.9", &sums)?.is_empty(),
            "a digest's case is no disagreement"
        );
        assert_eq!(
            stale_artifacts(&config(url, &"0".repeat(64)), "v9.9.9", &sums)?,
            [(
                7,
                String::from("provision batten sha256 for batten-9.9.9-x.tar.gz")
            )]
        );
        let stale = "https://h/download/v8.8.8/batten-8.8.8-x.tar.gz";
        assert_eq!(
            stale_artifacts(&config(stale, &"a".repeat(64)), "v9.9.9", &sums)?,
            [(6, format!("provision batten url {stale}"))]
        );
        let inline = format!(
            "[[provision]]\nname = \"batten\"\nversion = \"9.9.9\"\nplatforms = {{ x = {{ url = \"{stale}\", sha256 = \"{}\" }} }}\n",
            "a".repeat(64)
        );
        assert_eq!(
            stale_artifacts(&inline, "v9.9.9", &sums)?.len(),
            1,
            "an inline table is judged too"
        );
        let mirror = "https://m/batten/linux/batten.tar.gz";
        assert!(
            stale_artifacts(&config(mirror, &"0".repeat(64)), "v9.9.9", &sums)?.is_empty(),
            "a url laid out as no release download is its author's"
        );
        Ok(())
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

    #[test]
    fn the_engine_inputs_are_the_crates_and_the_cargo_manifests() {
        assert!(is_input("crates/batten/src/lib.rs"));
        assert!(is_input("Cargo.toml"));
        assert!(is_input("Cargo.lock"));
        assert!(!is_input("README.md"));
    }

    #[test]
    fn a_release_is_newer_only_when_strictly_above() -> Result<()> {
        assert!(is_newer("v1.0.1", "v1.0.0")?);
        assert!(!is_newer("v1.0.0", "v1.0.0")?);
        let one = semver::Version::new(1, 0, 0);
        assert!(!ahead_of(&one, &one));
        assert!(ahead_of(&semver::Version::new(1, 0, 1), &one));
        Ok(())
    }

    #[test]
    fn the_repair_is_admitted_whole_bare_or_rooted_and_nothing_else() {
        let root = Path::new("/work/my repo");
        assert!(is_repair(REPAIR));
        assert!(is_repair(REPAIR_PINNED));
        assert!(!is_repair("batten engine"));
        assert_eq!(
            repair_at(root, REPAIR),
            "cd '/work/my repo' && batten engine install"
        );
        assert!(is_repair_at(REPAIR, root));
        assert!(is_repair_at(&repair_at(root, REPAIR_PINNED), root));
        assert!(!is_repair_at(
            "cd /elsewhere && batten engine install",
            root
        ));
    }

    #[test]
    fn a_shell_word_is_quoted_only_when_the_shell_would_read_it() {
        assert_eq!(shell_word("/a/b-c_d.e+f@g%h:i,j"), "/a/b-c_d.e+f@g%h:i,j");
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
    }

    #[test]
    fn the_running_target_is_this_builds_own_triple() {
        let target = running_target();
        assert!(target.starts_with(std::env::consts::ARCH), "{target}");
        if cfg!(all(target_os = "linux", target_env = "gnu")) {
            assert!(target.ends_with("-unknown-linux-gnu"), "{target}");
        }
    }

    #[test]
    fn the_releases_between_exclude_the_pin_and_count_a_missing_latest_once() -> Result<()> {
        let heading = |version: &str| Heading {
            version: release_version(version).unwrap_or_else(|_| semver::Version::new(0, 0, 0)),
            date: None,
        };
        let versions = |found: Vec<Heading>| -> Vec<String> {
            found.iter().map(|h| h.version.to_string()).collect()
        };
        let headings = [heading("v1.1.0"), heading("v1.0.0")];
        assert_eq!(
            versions(releases_between(&headings, "v1.0.0", "v1.1.0")?),
            ["1.1.0"]
        );
        assert!(releases_between(&[], "v1.0.0", "v1.0.0")?.is_empty());
        Ok(())
    }

    #[test]
    fn days_are_counted_whole_from_utc_midnight() {
        assert_eq!(days_since("1970-01-01", 3 * 86_400 + 5), Some(3));
        assert_eq!(days_since("1970-01-03", 86_400), Some(0));
        assert_eq!(days_since("not a date", 0), None);
    }

    #[test]
    fn only_a_row_named_batten_is_battens() {
        let row = |name: &str| {
            let mut table = toml_edit::Table::new();
            table.insert("name", toml_edit::value(name));
            table
        };
        assert!(is_batten_row(&row("batten")));
        assert!(!is_batten_row(&row("hk")));
    }

    #[test]
    fn a_comment_starts_outside_a_string_that_opened_where_a_value_can() {
        assert_eq!(yaml_code("x: 'a # b' # c"), "x: 'a # b' ");
        assert_eq!(yaml_code("x:'a # b' # c"), "x:'a # b' ");
        assert_eq!(yaml_code("don't # c"), "don't ");
        assert_eq!(yaml_code("x # c"), "x ");
        assert_eq!(yaml_code("x#c"), "x#c");
    }

    #[test]
    fn a_copy_key_is_read_after_a_completed_value_and_never_in_a_sequence() {
        let none = std::collections::BTreeSet::new();
        assert_eq!(
            workflow_literals("a: b\nBATTEN_VERSION: v9.9.9\n", "v1.0.0", &none),
            [(2, "BATTEN_VERSION")]
        );
        assert!(
            workflow_literals(
                "list:\n  - x\n  - BATTEN_VERSION\n  - v9.9.9\n",
                "v1.0.0",
                &none
            )
            .is_empty()
        );
        assert!(workflow_literals("BATTEN_VERSION: v1.0.0\n", "v1.0.0", &none).is_empty());
    }

    #[test]
    fn a_verb_is_only_lowercase_words() {
        assert!(invoked_verbs("batten -v\n").is_empty());
        assert!(invoked_verbs("batten aB\n").is_empty());
    }

    /// Windows has no executable bit, so there the case asserts only that the
    /// call succeeds; the mode is read where the platform has one.
    #[test]
    fn a_fetched_binary_is_made_executable() -> Result<()> {
        let dir = crate::scratch::scratch("engine-make-executable");
        let path = dir.join("batten");
        std::fs::write(&path, "")?;
        make_executable(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let metadata = std::fs::metadata(&path)?;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        }
        Ok(())
    }
}
