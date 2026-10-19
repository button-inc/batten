//! The install contract: the path a user installs by resolves the assets a
//! release actually publishes, and no binary is committed.
//!
//! Ported off `mise-tasks/install-check.sh` under CLOUD-1716, for CLOUD-65.
//!
//! # Three statements of one contract, with nothing comparing them
//!
//! `install.sh` resolves an asset name, `[package.metadata.binstall]` resolves a
//! URL, and `batten dist` decides what the release is actually called. A
//! rename in `dist` is a build that still passes and an install path that 404s
//! at the only moment anyone would notice, which is on a user's machine.
//!
//! # THE CONTRACT IS PROVED BY ASKING, NOT BY SCRAPING
//!
//! `dist` owns archive naming and `install.sh` owns which targets it installs
//! and what it will ask for, so this asks each of them: `dist` in process
//! (`dist::archive_stem`, the rule `batten dist` names its archives with), and
//! `install.sh` through the query flags it publishes (`--targets`,
//! `--asset-name`). The one restatement that cannot be avoided is the
//! binstall manifest — cargo reads TOML, not a shell function — so that template
//! is resolved here and compared against what the release is named.
//!
//! **Spawning those two is a STATED INTERIM.** Both are wave 2's to retire; when
//! they are engine code this asks a function instead of a process, and nothing
//! about the contract changes.
//!
//! # WHY THE VERSION IS PROVED PARAMETRIC RATHER THAN SAMPLED
//!
//! The retired program passed a sample version of `9.9.9` so that a *hardcoded*
//! version in the template could not pass. `dist --stem` reads the crate version
//! from the workspace manifest and takes no version argument — deliberately, so
//! an archive's name cannot lie about its contents — so the sample trick is not
//! available here.
//!
//! What replaces it is stronger rather than weaker: [`parametric`] asks
//! `install.sh` for the same target under two different versions and requires
//! the answers to DIFFER and each to carry its own version. A hardcoded template
//! fails that directly, where the sample only failed it by proxy.
//!
//! # Pointer-only
//!
//! Target names, asset names and paths. Never a byte of a file it judges — which
//! for a committed binary is exactly the payload that must not reach a log.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::Result;
use crate::error::UsageError;

/// One target's expected asset name, as each authority spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    /// The target triple.
    pub target: String,
    /// What `dist` names the archive, extension included.
    pub dist: String,
    /// What `install.sh` will ask the release for.
    pub install: String,
    /// What `[package.metadata.binstall]`'s template resolves to, as a URL.
    pub binstall: String,
}

/// A disagreement between two authorities about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disagreement {
    /// The release matrix builds it and `install.sh --targets` omits it.
    Unserved(String),
    /// `install.sh --targets` lists it and no matrix leg builds it.
    Unbuilt(String),
    /// `install.sh` asks for a name `dist` does not write.
    AssetName {
        /// The target the two disagree about.
        target: String,
        /// What `dist` writes.
        dist: String,
        /// What `install.sh` asks for.
        install: String,
    },
    /// The binstall template resolves somewhere the release does not publish.
    BinstallUrl {
        /// The target the template was resolved for.
        target: String,
        /// Where the release actually puts it.
        release: String,
        /// Where `cargo binstall` would fetch from.
        binstall: String,
    },
    /// `install.sh` resolves the same name for two different versions.
    NotParametric(String),
    /// An executable binary is committed to the repository.
    CommittedBinary(String),
}

impl Disagreement {
    /// The pointer line this renders as. Rule 4: names and paths, never bytes.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Disagreement::Unserved(target) => {
                format!("{target} — built by the release matrix, absent from install.sh --targets")
            }
            Disagreement::Unbuilt(target) => {
                format!("{target} — listed by install.sh --targets, built by no matrix leg")
            }
            Disagreement::AssetName {
                target,
                dist,
                install,
            } => format!("{target} — dist writes '{dist}', install.sh asks for '{install}'"),
            Disagreement::BinstallUrl {
                target,
                release,
                binstall,
            } => format!("{target} — release has '{release}', binstall would fetch '{binstall}'"),
            Disagreement::NotParametric(target) => format!(
                "{target} — install.sh resolves one name for two versions, so its template does \
                 not carry the version"
            ),
            Disagreement::CommittedBinary(path) => {
                format!("{path} — an executable binary is committed")
            }
        }
    }
}

/// Executable-format magic, judged on bytes rather than on a path convention.
///
/// A convention is what somebody works around. `MZ` carries its third byte
/// because two printable characters alone would fire on ordinary text.
const MAGIC: &[&[u8]] = &[
    &[0x7f, 0x45, 0x4c, 0x46], // ELF
    &[0xfe, 0xed, 0xfa, 0xce], // Mach-O 32, big endian
    &[0xce, 0xfa, 0xed, 0xfe], // Mach-O 32, little endian
    &[0xfe, 0xed, 0xfa, 0xcf], // Mach-O 64, big endian
    &[0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64, little endian
    &[0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
    &[0x4d, 0x5a, 0x90],       // PE
];

/// Whether these opening bytes are an executable's.
#[must_use]
pub fn is_executable(head: &[u8]) -> bool {
    MAGIC.iter().any(|magic| head.starts_with(magic))
}

/// The release matrix, read from the workflow that decides it.
///
/// **One authority, and it is the workflow's.** `release-assets-check` holds the
/// same property: the matrix decides what a release contains, and both gates
/// read it rather than keeping a copy, so a target added there is covered here
/// with no second edit.
///
/// The form is anchored, so a `target:` in prose or under another key cannot
/// widen it.
#[must_use]
pub fn matrix_targets(workflow: &str) -> BTreeSet<String> {
    workflow
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("- target:")?;
            let target = rest.trim();
            let legal = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-');
            (!target.is_empty() && target.chars().all(legal)).then(|| target.to_owned())
        })
        .collect()
}

/// `[package.metadata.binstall]`, read the way cargo-binstall reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binstall {
    /// The `pkg-url` template.
    pub url: String,
    /// The default `pkg-fmt`, or `tgz` where none is declared.
    pub format: String,
    /// Per-target `pkg-fmt` overrides.
    pub overrides: BTreeMap<String, String>,
}

impl Binstall {
    /// The archive suffix a format implies.
    ///
    /// **An unrecognised format is could-not-look, never a guessed suffix.**
    /// Guessing would make the comparison pass over a template nobody checked,
    /// which is the vacuous green this gate exists to prevent.
    #[must_use]
    pub fn suffix(format: &str) -> Option<&'static str> {
        match format {
            "tgz" => Some(".tar.gz"),
            "zip" => Some(".zip"),
            _ => None,
        }
    }

    /// The format that applies to one target.
    #[must_use]
    pub fn format_for(&self, target: &str) -> &str {
        self.overrides
            .get(target)
            .map_or(self.format.as_str(), String::as_str)
    }

    /// Resolve the template for one target and version.
    ///
    /// # Errors
    ///
    /// A `pkg-fmt` this has no suffix rule for.
    pub fn resolve(&self, repo: &str, name: &str, version: &str, target: &str) -> Result<String> {
        let format = self.format_for(target);
        let suffix = Self::suffix(format).ok_or_else(|| {
            UsageError::raise(format!(
                "binstall pkg-fmt '{format}' (target {target}) is one this gate has no suffix rule \
                 for. Add it here in the same change that adds it to the manifest — a guessed \
                 suffix would make the comparison vacuous."
            ))
        })?;
        Ok(self
            .url
            .replace("{ repo }", repo)
            .replace("{ name }", name)
            .replace("{ version }", version)
            .replace("{ target }", target)
            .replace("{ archive-suffix }", suffix))
    }
}

/// Read the binstall table out of a manifest.
///
/// Text rather than a TOML parse, for the reason the retired program gave and
/// which survives the port: the two keys this needs are flat strings, and the
/// override table is read by its own header. A parse would be correct and would
/// also pull the whole manifest shape into a judgement that wants two values.
#[must_use]
pub fn binstall_in(manifest: &str) -> Option<Binstall> {
    let scalar = |key: &str| -> Option<String> {
        manifest.lines().find_map(|line| {
            let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
            Some(rest.trim().trim_matches('"').to_owned())
        })
    };
    let url = scalar("pkg-url")?;

    let mut overrides = BTreeMap::new();
    let mut inside: Option<String> = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(target) = trimmed
            .strip_prefix("[package.metadata.binstall.overrides.")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inside = Some(target.to_owned());
            continue;
        }
        if trimmed.starts_with('[') {
            inside = None;
            continue;
        }
        if let (Some(target), Some(rest)) = (
            inside.as_ref(),
            trimmed
                .strip_prefix("pkg-fmt")
                .and_then(|rest| rest.trim_start().strip_prefix('=')),
        ) {
            overrides.insert(target.clone(), rest.trim().trim_matches('"').to_owned());
        }
    }

    Some(Binstall {
        url,
        format: scalar("pkg-fmt").unwrap_or_else(|| String::from("tgz")),
        overrides,
    })
}

/// One scalar out of a manifest, by key.
#[must_use]
pub fn manifest_scalar(manifest: &str, key: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
        let value = rest.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

/// Whether `install.sh`'s asset template actually carries the version.
///
/// Two versions, one target, and the answers must differ and each carry its own.
/// A template with the version hardcoded — or dropped — fails this directly,
/// where the retired program's sample version only failed it by proxy.
#[must_use]
pub fn parametric(first: (&str, &str), second: (&str, &str)) -> bool {
    let (left_version, left_name) = first;
    let (right_version, right_name) = second;
    left_name != right_name
        && left_name.contains(left_version)
        && right_name.contains(right_version)
}

/// Every tracked path whose opening bytes are an executable's.
///
/// A submodule is a gitlink rather than a file and is that repository's problem,
/// so an unreadable entry is skipped rather than reported: this gate answers
/// "is a binary committed here", and a path it cannot open is not evidence that
/// one is.
#[must_use]
pub fn committed_binaries(root: &Path, tracked: &BTreeSet<String>) -> Vec<String> {
    tracked
        .iter()
        .filter(|path| {
            let Ok(bytes) = std::fs::read(root.join(path)) else {
                return false;
            };
            is_executable(&bytes)
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// The generated bootstrap (CLOUD-2203).
// ---------------------------------------------------------------------------

/// The targets the bootstrap installs: every POSIX-shell release target. The
/// one authority for that list — `install.sh` is generated from it, and
/// `release install` compares it against the release matrix.
pub const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];

/// The programs the bootstrap may run, and nothing else (CLOUD-2203). Its
/// whole job is to fetch the release binary, check it, and run it; anything a
/// script would need beyond these is work for the binary.
pub const BOOTSTRAP_PROGRAMS: &[&str] = &[
    "uname",
    "mktemp",
    "curl",
    "sha256sum",
    "shasum",
    "tar",
    "rm",
];

/// What the bootstrap asks the release for: `dist`'s own stem and extension,
/// with the version left as the shell expression that carries it.
#[must_use]
pub fn bootstrap_asset(name: &str) -> String {
    format!(
        "{}{}",
        crate::dist::archive_stem(name, "${tag#v}", "$target"),
        crate::dist::archive_ext("x86_64-unknown-linux-gnu")
    )
}

/// The file a release bakes the bootstrap's data into (CLOUD-2287).
pub const LOCK_FILE: &str = "install.lock";

/// `install.lock`: the release `install.sh` installs, and the line each target
/// archive the bootstrap fetches has in that release's `SHA256SUMS`.
///
/// **A ROOT FILE, NOT A `batten.toml` TABLE.** `Config` denies unknown fields,
/// so an older pinned engine would refuse the key; and outside `crates/` it is
/// no engine input, so baking it never moves a source pin. The renderer takes
/// it as input and `install_script.rs` is its one writer's gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// The release tag, `v`-prefixed.
    pub tag: String,
    /// `(sha256, asset)` for each target archive the bootstrap fetches, in
    /// [`TARGETS`] order.
    pub sums: Vec<(String, String)>,
}

impl Lock {
    /// The lock for release `tag` out of its `SHA256SUMS` body: the line of each
    /// [`TARGETS`] archive, and nothing else.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] naming a bootstrap target whose archive `sums` carries
    /// no line for: a bootstrap baked without it would refuse that platform.
    pub fn from_sums(name: &str, tag: &str, sums: &str) -> Result<Self> {
        let mut lines = Vec::new();
        for target in TARGETS {
            let asset = format!(
                "{}{}",
                crate::dist::archive_stem(name, tag.trim_start_matches('v'), target),
                crate::dist::archive_ext(target)
            );
            let digest = crate::engine::published_digest(sums, &asset).ok_or_else(|| {
                UsageError::raise(format!(
                    "release bake: {tag}'s SHA256SUMS carries no line for {asset}, so the \
                     bootstrap cannot be baked"
                ))
            })?;
            lines.push((digest, asset));
        }
        Ok(Self {
            tag: tag.to_owned(),
            sums: lines,
        })
    }

    /// Read a committed `install.lock`.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a file with no `tag` line or a line of neither shape.
    pub fn parse(text: &str) -> Result<Self> {
        let mut tag = None;
        let mut sums = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("tag ") {
                tag = Some(rest.trim().to_owned());
                continue;
            }
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next(), fields.next()) {
                (Some(digest), Some(asset), None) => {
                    sums.push((digest.to_ascii_lowercase(), asset.to_owned()));
                }
                _ => {
                    return Err(UsageError::raise(format!(
                        "{LOCK_FILE}: `{line}` is neither `tag <tag>` nor `<sha256>  <asset>`"
                    )));
                }
            }
        }
        let tag = tag.ok_or_else(|| UsageError::raise(format!("{LOCK_FILE}: no `tag` line")))?;
        Ok(Self { tag, sums })
    }

    /// The file's bytes.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# GENERATED by `batten release bake` (CLOUD-2287). Do not edit: each release\n\
             # bakes the tag install.sh installs, and each archive's SHA256SUMS line.\n",
        );
        let _ = writeln!(out, "tag {}", self.tag);
        for (digest, asset) in &self.sums {
            let _ = writeln!(out, "{digest}  {asset}");
        }
        out
    }

    /// Each line this lock carries that `sums` (the release's own
    /// `SHA256SUMS`) does not publish identically: empty when they agree.
    #[must_use]
    pub fn disagreements(&self, sums: &str) -> Vec<String> {
        self.sums
            .iter()
            .filter(|(digest, asset)| {
                crate::engine::published_digest(sums, asset).as_deref() != Some(digest.as_str())
            })
            .map(|(_, asset)| asset.clone())
            .collect()
    }
}

/// The committed `install.sh`, rendered from `lock` (CLOUD-2203, CLOUD-2287).
///
/// **THE BARE MINIMUM TO INSTALL AND EXECUTE RELEASED RUST, AND NO VERSION
/// CHOICE.** Detect the target, download the baked tag's archive, compare it
/// with the baked sha256, extract it, and hand over to `engine install`, which
/// follows the `batten.toml` pin from there — so a stale cached copy of this
/// script still lands on the pin. The script is cached and baked into images,
/// so any choice it made would be frozen at that copy's version; only the
/// binary can follow the pin. `BATTEN_VERSION` is the escape hatch: that tag is
/// fetched and checked against its own release's `SHA256SUMS`. Never the API,
/// whose anonymous budget a shared egress address spends. A refusal names the
/// status and the URL that answered. Exit 1 is the release's fault: a named
/// tag's missing download or digest, a digest that disagrees, or a platform no
/// release builds. Exit 2 is could-not-look: a host that does not answer, or
/// answers `404` for the baked tag, which a release published — a private
/// repository answers `404` to everything. Every request is bounded — a connect
/// timeout, a total timeout, and three retries of a transient answer — so a
/// stalled host fails the install rather than hanging it. TLS trust is curl's
/// own reading of `CURL_CA_BUNDLE`, then `SSL_CERT_FILE`. `BATTEN_RELEASES`
/// exists so a suite can serve the release from a fixture; nothing else is
/// configurable here.
//MUTANT-SUITE crates/batten/tests/it/install_web.rs
//MUTANT bootstrap-skips-its-baked-hash|s@^\[ "${{sum%% \*}}" = "$want" \] \x7c\x7c fail@true \x7c\x7c fail@|a_served_archive_disagreeing_with_the_lock_installs_nothing
#[must_use]
pub fn render_bootstrap(name: &str, repository: &str, lock: &Lock) -> String {
    let asset = bootstrap_asset(name);
    let repository = repository.trim_end_matches('/');
    let tag = &lock.tag;
    let arms = lock
        .sums
        .iter()
        .fold(String::new(), |mut arms, (digest, asset)| {
            let _ = writeln!(arms, "\t{asset}) want={digest} ;;");
            arms
        });
    format!(
        r#"#!/bin/sh
# GENERATED by `install::render_bootstrap` from install.lock (CLOUD-2203,
# CLOUD-2287). Do not edit: a test rewrites this file from the generator and
# fails when any byte differed.
#
# The whole job: fetch the baked release binary for this platform, check it
# against the baked sha256, and run it. `{name} engine install` follows the
# pin from there.
set -eu
base="${{BATTEN_RELEASES:-{repository}}}"
fail() {{
	echo "install.sh: $1" >&2
	exit "${{2:-2}}"
}}
os=$(uname -s)
arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) fail "no release for $os/$arch" 1 ;;
esac
case "$os" in
Linux)
	libc=gnu
	for loader in /lib/ld-musl-*; do
		[ -e "$loader" ] && libc=musl
	done
	target="$arch-unknown-linux-$libc"
	;;
Darwin) target="$arch-apple-darwin" ;;
*) fail "no release for $os/$arch" 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
get() {{
	got=$(curl -sSL --connect-timeout 20 --max-time 600 --retry 3 --retry-delay 1 \
		-o "$2" -w '%{{http_code}} %{{url_effective}}' "$1") || true
	case "$got" in
	200\ *) ;;
	404\ *) fail "could not download $1: $got" "${{3:-2}}" ;;
	*) fail "could not download $1: ${{got:-000}}" ;;
	esac
}}
tag="${{BATTEN_VERSION:-{tag}}}"
asset="{asset}"
want=
if [ -n "${{BATTEN_VERSION:-}}" ]; then
	get "$base/releases/download/$tag/SHA256SUMS" "$tmp/SHA256SUMS" 1
	while read -r sum file; do
		[ "${{file#\*}}" = "$asset" ] && want=$sum
	done <"$tmp/SHA256SUMS"
	missing=1
else
	case "$asset" in
{arms}	esac
	missing=2
fi
[ -n "$want" ] || fail "$tag publishes no sha256 for $asset" 1
get "$base/releases/download/$tag/$asset" "$tmp/$asset" "$missing"
if command -v sha256sum >/dev/null 2>&1; then
	sum=$(sha256sum "$tmp/$asset")
else
	sum=$(shasum -a 256 "$tmp/$asset")
fi
[ "${{sum%% *}}" = "$want" ] || fail "$asset does not match the sha256 $tag published" 1
tar -xzf "$tmp/$asset" -C "$tmp" {name}
"$tmp/{name}" engine install "$@"
"#
    )
}

/// Conventional system directories `engine install` may use when the per-user
/// one is not on `PATH`, in the order it tries them.
pub const SYSTEM_BIN_DIRS: &[&str] = &["/usr/local/bin", "/opt/homebrew/bin"];

/// Where `engine install` places the binary, and whether that is a fallback
/// off `PATH` (CLOUD-2203).
///
/// A named directory wins. Otherwise the per-user directory when it is already
/// on `PATH`; otherwise the first system directory that is both on `PATH` and
/// writable — a root Setup shell carries `/usr/local/bin` and not `~/.local/bin`;
/// otherwise the per-user directory, reported as off `PATH`.
//MUTANT-SUITE crates/batten/src/install.rs
//MUTANT self-install-ignores-path|s@^        if on_path.iter().any(\x7centry\x7c entry == dir) && writable(dir) {$@        if false {@|a_writable_system_directory_on_path_is_chosen
#[must_use]
pub fn destination(
    named: Option<std::path::PathBuf>,
    user: std::path::PathBuf,
    on_path: &[std::path::PathBuf],
    writable: impl Fn(&Path) -> bool,
) -> std::path::PathBuf {
    if let Some(named) = named {
        return named;
    }
    if on_path.contains(&user) {
        return user;
    }
    for dir in SYSTEM_BIN_DIRS.iter().map(Path::new) {
        if on_path.iter().any(|entry| entry == dir) && writable(dir) {
            return dir.to_path_buf();
        }
    }
    user
}

/// Every program the script runs, read as the first word of each command: a
/// line's first word, and the first word after `$(`, `|`, `&&` or `||`. Shell
/// keywords, builtins and assignments are not programs. The allowlist test
/// reads the RENDERED script through this, so a program added to the template
/// is refused whatever line it hides on.
#[must_use]
pub fn programs_in(script: &str) -> BTreeSet<String> {
    const SHELL: &[&str] = &[
        "set", "case", "esac", "if", "then", "else", "fi", "for", "do", "done", "in", "while",
        "read", "trap", "echo", "exit", "fail", "get", "break", "return", "command", "true", "[",
        "]", ";;", "}", "{",
    ];
    let mut programs = BTreeSet::new();
    for line in script.lines() {
        let mut line = line.trim();
        // A case pattern carries no program: `amd64)` alone, or the pattern in
        // front of the arm's command (`Darwin) target=…`), which is stripped.
        if let Some(at) = line.find(") ")
            && !line[..at].contains('(')
            && !line[..at].contains('$')
        {
            line = &line[at + 2..];
        }
        let is_bare_pattern = line.ends_with(')') && !line.contains('(') && !line.contains('$');
        // `name() {` defines a function; its name is not a program.
        let is_definition = line.ends_with("() {");
        if line.is_empty() || line.starts_with('#') || is_bare_pattern || is_definition {
            continue;
        }
        let mut heads = vec![line];
        for separator in ["$(", "| ", "&& ", "|| "] {
            heads.extend(line.split(separator).skip(1));
        }
        for head in heads {
            let Some(word) = head.split_whitespace().next() else {
                continue;
            };
            let word = word.trim_matches(|c| c == '"' || c == '\'');
            let is_assignment = word.contains('=');
            let is_case_arm = word.ends_with(')');
            let is_own_binary = word.starts_with("$tmp/");
            if !is_assignment
                && !is_case_arm
                && !is_own_binary
                && !SHELL.contains(&word)
                && word.chars().next().is_some_and(char::is_alphabetic)
            {
                programs.insert(word.to_owned());
            }
        }
    }
    programs
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    /// A `SHA256SUMS` body naming `digest` for every bootstrap target at v1.2.3.
    fn sums_of(digest: &str) -> String {
        TARGETS.iter().fold(String::new(), |mut sums, target| {
            let _ = writeln!(sums, "{digest}  batten-v1.2.3-{target}.tar.gz");
            sums
        })
    }

    /// A lock naming every bootstrap target, as a bake writes one.
    fn fixture_lock() -> Lock {
        let sums = sums_of(&"a".repeat(64));
        Lock::from_sums("batten", "v1.2.3", &sums).expect("every target has a line")
    }

    #[test]
    fn a_lock_round_trips_and_keeps_only_the_bootstrap_targets() {
        let mut sums = sums_of(&"b".repeat(64));
        let _ = writeln!(
            sums,
            "{}  batten-v1.2.3-x86_64-pc-windows-msvc.zip",
            "c".repeat(64)
        );
        let lock = Lock::from_sums("batten", "v1.2.3", &sums).expect("every target has a line");
        assert_eq!(
            lock.sums.len(),
            TARGETS.len(),
            "the zip target is not the bootstrap's"
        );
        assert_eq!(
            Lock::parse(&lock.render()).expect("a rendered lock parses"),
            lock
        );
        assert!(lock.disagreements(&sums).is_empty());
        let other = sums.replacen(&"b".repeat(64), &"d".repeat(64), 1);
        assert_eq!(lock.disagreements(&other).len(), 1);
    }

    #[test]
    fn a_release_missing_a_bootstrap_target_cannot_be_baked() {
        assert!(Lock::from_sums("batten", "v1.2.3", "").is_err());
    }

    #[test]
    fn the_bootstrap_makes_no_version_choice() {
        let script = render_bootstrap("batten", "https://example.invalid/o/r", &fixture_lock());
        for selection in [
            "pin_of",
            "batten.toml",
            "$PWD",
            "BATTEN_VERSION_FROM_REF",
            "/main/",
        ] {
            assert!(
                !script.contains(selection),
                "the script selects by {selection}"
            );
        }
        assert!(
            script.contains("tag=\"${BATTEN_VERSION:-v1.2.3}\""),
            "{script}"
        );
    }

    #[test]
    fn a_writable_system_directory_on_path_is_chosen() {
        let user = std::path::PathBuf::from("/home/u/.local/bin");
        let on_path = vec![
            std::path::PathBuf::from("/usr/local/bin"),
            std::path::PathBuf::from("/usr/bin"),
        ];
        assert_eq!(
            destination(None, user.clone(), &on_path, |_| true),
            std::path::PathBuf::from("/usr/local/bin")
        );
        // Not writable: the per-user directory, which the caller reports as off PATH.
        assert_eq!(destination(None, user.clone(), &on_path, |_| false), user);
    }

    #[test]
    fn a_named_or_on_path_user_directory_wins() {
        let user = std::path::PathBuf::from("/home/u/.local/bin");
        let named = std::path::PathBuf::from("/opt/x");
        let on_path = vec![user.clone(), std::path::PathBuf::from("/usr/local/bin")];
        assert_eq!(
            destination(Some(named.clone()), user.clone(), &on_path, |_| true),
            named
        );
        assert_eq!(destination(None, user.clone(), &on_path, |_| true), user);
    }

    #[test]
    fn the_bootstrap_runs_only_the_allowlisted_programs() {
        let script = render_bootstrap("batten", "https://example.invalid/o/r", &fixture_lock());
        let found = programs_in(&script);
        let allowed: BTreeSet<String> =
            BOOTSTRAP_PROGRAMS.iter().map(|p| (*p).to_owned()).collect();
        let extra: Vec<&String> = found.difference(&allowed).collect();
        assert!(
            extra.is_empty(),
            "programs outside the allowlist: {extra:?}"
        );
        assert!(found.contains("curl") && found.contains("tar"), "{found:?}");
    }

    /// Fails by: a system directory chosen though no `PATH` entry names it.
    #[test]
    fn a_system_directory_off_path_is_never_chosen() {
        let user = std::path::PathBuf::from("/home/u/.local/bin");
        let on_path = vec![std::path::PathBuf::from("/opt/other")];
        assert_eq!(destination(None, user.clone(), &on_path, |_| true), user);
    }

    /// Fails by: any one clause of the program reading dropped, so a pattern,
    /// a comment, a definition, an assignment or a quoted program misreads.
    #[test]
    fn programs_are_first_words_and_nothing_else() {
        let read = |line: &str| -> Vec<String> { programs_in(line).into_iter().collect() };
        assert_eq!(read("curl x"), ["curl"]);
        assert_eq!(read("\"curl\" x"), ["curl"]);
        assert_eq!(read("Darwin) curl x"), ["curl"]);
        assert_eq!(read("amd64) target=x"), Vec::<String>::new());
        assert_eq!(read("a | b)"), Vec::<String>::new(), "a bare pattern");
        assert_eq!(read("# note | jq ."), Vec::<String>::new(), "a comment");
        assert_eq!(read("curl() {"), Vec::<String>::new(), "a definition");
        assert_eq!(read("x=1"), Vec::<String>::new(), "an assignment");
        assert_eq!(read("\"$tmp/batten\" run"), Vec::<String>::new());
    }

    #[test]
    fn a_matrix_target_is_one_legal_token() {
        let workflow = "- target:\n- target: bad target!\n  - target: x86_64-unknown-linux-gnu\n";
        assert_eq!(
            matrix_targets(workflow),
            BTreeSet::from([String::from("x86_64-unknown-linux-gnu")])
        );
    }

    #[test]
    fn a_manifest_scalar_is_its_unquoted_non_empty_value() {
        let manifest = "name = \"batten\"\nempty = \"\"\n";
        assert_eq!(manifest_scalar(manifest, "name").as_deref(), Some("batten"));
        assert_eq!(manifest_scalar(manifest, "empty"), None);
        assert_eq!(manifest_scalar(manifest, "absent"), None);
    }

    /// Fails by: a template that hardcodes or drops either version read as
    /// carrying it.
    #[test]
    fn a_template_is_parametric_only_when_each_name_carries_its_version() {
        assert!(parametric(("1.0", "b-1.0.tgz"), ("2.0", "b-2.0.tgz")));
        assert!(!parametric(("1.0", "b.tgz"), ("2.0", "b-2.0.tgz")));
        assert!(!parametric(("1.0", "b-1.0.tgz"), ("2.0", "b.tgz")));
        assert!(!parametric(("1.0", "b-1.0.tgz"), ("2.0", "b-1.0.tgz")));
    }

    #[test]
    fn a_committed_binary_is_found_by_its_magic() {
        let root = crate::scratch::scratch("install-binaries");
        std::fs::write(root.join("tool"), [0x7f, 0x45, 0x4c, 0x46, 0]).unwrap();
        std::fs::write(root.join("notes.md"), "text").unwrap();
        let tracked = BTreeSet::from([
            String::from("tool"),
            String::from("notes.md"),
            String::from("gone"),
        ]);
        assert_eq!(committed_binaries(&root, &tracked), ["tool"]);
    }

    #[test]
    fn a_disagreement_line_names_the_target_and_both_spellings() {
        let line = Disagreement::AssetName {
            target: String::from("t"),
            dist: String::from("a.tgz"),
            install: String::from("b.tgz"),
        }
        .line();
        assert_eq!(line, "t — dist writes 'a.tgz', install.sh asks for 'b.tgz'");
    }

    #[test]
    fn an_added_program_is_seen_wherever_it_hides() {
        for line in ["jq . x", "x=$(jq . y)", "a | jq .", "true && jq ."] {
            assert!(
                programs_in(line).contains("jq"),
                "missed jq in {line:?}: {:?}",
                programs_in(line)
            );
        }
    }

    #[test]
    fn the_bootstrap_ends_by_running_the_binary_it_verified() {
        let script = render_bootstrap("batten", "https://example.invalid/o/r", &fixture_lock());
        assert!(
            script
                .trim_end()
                .ends_with("\"$tmp/batten\" engine install \"$@\""),
            "{script}"
        );
        assert!(!script.contains("api.github.com"), "the API is never asked");
    }

    #[test]
    fn the_bootstrap_asset_is_dists_name_with_the_tags_version() {
        let asset = bootstrap_asset("batten");
        assert_eq!(asset, "batten-v${tag#v}-$target.tar.gz");
        for target in TARGETS {
            let concrete = asset
                .replace("${tag#v}", "1.2.3")
                .replace("$target", target);
            assert_eq!(
                concrete,
                format!(
                    "{}{}",
                    crate::dist::archive_stem("batten", "1.2.3", target),
                    crate::dist::archive_ext(target)
                )
            );
        }
    }

    #[test]
    fn the_matrix_is_read_from_anchored_entries_only() {
        let workflow = "jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          \
                        - target: x86_64-unknown-linux-gnu\n          - target: aarch64-apple-darwin\n";
        let found = matrix_targets(workflow);
        assert_eq!(found.len(), 2);
        assert!(found.contains("x86_64-unknown-linux-gnu"));
    }

    /// A `target:` in prose or under another key must not widen the matrix.
    #[test]
    fn prose_naming_a_target_does_not_enter_the_matrix() {
        let workflow = "# the - target: key decides what a release contains\n    \
                        description: - target: not-a-leg here\n";
        assert!(matrix_targets(workflow).is_empty());
    }

    #[test]
    fn an_unknown_package_format_has_no_suffix() {
        assert_eq!(Binstall::suffix("tgz"), Some(".tar.gz"));
        assert_eq!(Binstall::suffix("zip"), Some(".zip"));
        assert_eq!(Binstall::suffix("7z"), None);
    }

    #[test]
    fn a_per_target_override_wins_over_the_default() {
        let manifest = "pkg-url = \"{ repo }/x\"\npkg-fmt = \"tgz\"\n\
                        [package.metadata.binstall.overrides.x86_64-pc-windows-msvc]\n\
                        pkg-fmt = \"zip\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert_eq!(table.format_for("x86_64-unknown-linux-gnu"), "tgz");
        assert_eq!(table.format_for("x86_64-pc-windows-msvc"), "zip");
    }

    #[test]
    fn an_override_table_ends_at_the_next_header() {
        let manifest = "pkg-url = \"{ repo }/x\"\n\
                        [package.metadata.binstall.overrides.a]\npkg-fmt = \"zip\"\n\
                        [other]\npkg-fmt = \"7z\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert_eq!(table.format_for("a"), "zip");
        assert_eq!(
            table.overrides.len(),
            1,
            "the `[other]` table is not an override"
        );
    }

    #[test]
    fn the_template_resolves_every_placeholder() {
        let manifest = "pkg-url = \"{ repo }/releases/download/v{ version }/{ name }-{ target }{ archive-suffix }\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        let url = table
            .resolve("https://example/r", "batten", "1.2.3", "t")
            .expect("a known format");
        assert_eq!(
            url,
            "https://example/r/releases/download/v1.2.3/batten-t.tar.gz"
        );
    }

    #[test]
    fn an_unknown_format_refuses_rather_than_guessing() {
        let manifest = "pkg-url = \"{ repo }\"\npkg-fmt = \"7z\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert!(table.resolve("r", "batten", "1.0.0", "t").is_err());
    }

    #[test]
    fn executable_magic_is_recognised_and_text_is_not() {
        assert!(is_executable(&[0x7f, b'E', b'L', b'F', 0x02]));
        assert!(is_executable(&[0x4d, 0x5a, 0x90, 0x00]));
        assert!(!is_executable(b"MZ is how a sentence might start"));
        assert!(!is_executable(b"#!/usr/bin/env bash\n"));
        assert!(!is_executable(b""));
    }

    #[test]
    fn a_version_carrying_template_is_parametric() {
        assert!(parametric(
            ("1.2.3", "batten-1.2.3-t.tar.gz"),
            ("9.9.9", "batten-9.9.9-t.tar.gz")
        ));
    }

    /// The defect the sample version existed to catch, caught directly.
    #[test]
    fn a_hardcoded_version_is_not_parametric() {
        assert!(!parametric(
            ("1.2.3", "batten-0.0.1-t.tar.gz"),
            ("9.9.9", "batten-0.0.1-t.tar.gz")
        ));
    }

    /// And a template that varies but drops the version is caught too — the
    /// names differ, so a difference test alone would pass it.
    #[test]
    fn a_template_that_varies_without_carrying_the_version_is_not_parametric() {
        assert!(!parametric(
            ("1.2.3", "batten-a-t.tar.gz"),
            ("9.9.9", "batten-b-t.tar.gz")
        ));
    }
}
