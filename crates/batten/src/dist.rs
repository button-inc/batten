//! `batten dist` (CLOUD-843): build a workspace's one release binary for a
//! target and stage its archive, retiring `mise-tasks/dist.sh`.
//!
//! # The archive NAME is a contract, not a convenience
//!
//! `cargo binstall` resolves a release asset by name (CLOUD-65), and so does an
//! installer script, so `name-vVERSION-TARGET` plus a per-target extension is what
//! makes these assets consumable at all. [`archive_stem`] and [`archive_ext`] are
//! the one place that shape is decided; `release install` asks them in process
//! rather than re-spelling them, which is what the shell's `--stem` flag existed
//! to allow a second reader to do.
//!
//! # What is the consumer's, never the engine's (non-negotiable rule 1)
//!
//! The shell carried `BIN=batten`. Here the package, its one binary target, its
//! version, the workspace root and the target directory all come from
//! `cargo metadata` over the tree the verb stands in, so the verb builds whatever
//! single-binary workspace calls it. A workspace declaring zero or several binary
//! targets is could-not-look rather than a guess: an archive named for a binary it
//! does not carry is worse than no archive.
//!
//! The version is read, never passed: a version argument could disagree with what
//! cargo actually builds, and an archive whose name lies about its contents is the
//! defect the naming contract exists to prevent.
//!
//! # The build wrappers are the shell's, measured rather than widened
//!
//! `cargo auditable` wraps the two builders it is PROVEN to compose with (`cargo`
//! and `cargo-zigbuild`), and not `cross`, where composition is unmeasured
//! (CLOUD-263). A plain build yields zero rust-crate packages to a binary SBOM
//! scan and an auditable one 85, so the wrapper is what makes the shipped binary
//! inventoriable. The `cross` legs stay unwrapped for the reason the shell gave.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! stdout is `archive=<path>` and `binary=<path>`, KEY=VALUE so a workflow can
//! append it to `$GITHUB_OUTPUT` unchanged. The build's own output is folded onto
//! stderr only when the build fails, where the compiler's errors ARE the pointer.
//!
//! # No new spawn
//!
//! Every program here — `cargo metadata`, the builder, `tar`, `zip` — runs through
//! [`exec::piped_argv`], the placed adapter's one shared spawn, so this module
//! adds no site to the spawn census.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value;

use crate::error::UsageError;
use crate::exec::{self, Diagnostics};
use crate::exit::ExitCode;

/// The cargo profile a release binary is built under.
pub const PROFILE: &str = "dist";

/// The directory, under the workspace root, the archives are staged in.
pub const OUT_DIR: &str = "dist";

// The decisions a naive port loses. Each is caught by the case it names, run
// from this file.
//MUTANT-SUITE crates/batten/src/dist.rs
//MUTANT dist-windows-by-host|s@    target.contains("-windows-")@    cfg!(windows)@|windows_targets_are_detected_by_triple_not_by_host
//MUTANT dist-stem-drops-target|s@    format!("{name}-v{version}-{target}")@    format!("{name}-v{version}")@|two_targets_never_share_an_archive_name
//MUTANT dist-auditable-on-cross|s@            Self::Cross => &\["cross", "build"],@            Self::Cross => \&["cargo", "auditable", "build"],@|cross_is_not_wrapped_in_auditable_and_the_other_two_are
//MUTANT dist-several-binaries-guessed|s@    if bins.len() != 1 {@    if bins.is_empty() {@|a_workspace_with_two_binaries_is_refused_rather_than_guessed
//MUTANT dist-versionless-name|s@!version\.is_empty()@true@|a_package_with_no_version_is_refused_rather_than_named_empty
//MUTANT dist-env-builder-ignored|s@ env\.filter(@ env.and(None::<\&str>).filter(@|the_flag_outranks_the_environment_and_an_empty_one_is_unset
//MUTANT dist-empty-env-names-a-builder|s@!value\.is_empty()@value.is_ascii()@|the_flag_outranks_the_environment_and_an_empty_one_is_unset
//MUTANT dist-env-outranks-flag|s@    flag\.or_else(@    env.or(flag).or_else(@|the_flag_outranks_the_environment_and_an_empty_one_is_unset
//MUTANT dist-stem-resolves-builder|s@^    if stem {$@    if stem \&\& false {@|a_stem_request_resolves_no_builder_and_a_build_refuses_an_unknown_one

/// Whether a target triple builds a Windows binary.
///
/// **Keyed off the TRIPLE, never the host**, so a cross-build names its archive
/// for the platform it RUNS on, not the one it was built on.
#[must_use]
pub fn is_windows_target(target: &str) -> bool {
    target.contains("-windows-")
}

/// The asset stem: `name-vVERSION-TARGET`. The contract binstall reads.
#[must_use]
pub fn archive_stem(name: &str, version: &str, target: &str) -> String {
    format!("{name}-v{version}-{target}")
}

/// The archive extension for a target: `.zip` for Windows, `.tar.gz` otherwise.
#[must_use]
pub fn archive_ext(target: &str) -> &'static str {
    if is_windows_target(target) {
        ".zip"
    } else {
        ".tar.gz"
    }
}

/// The file name the builder writes for a binary target.
#[must_use]
pub fn binary_file(bin: &str, target: &str) -> String {
    if is_windows_target(target) {
        format!("{bin}.exe")
    } else {
        bin.to_owned()
    }
}

/// How the compiler is invoked for a target.
///
/// `rustup target add` installs only the standard library; the LINKER is what
/// blocks a cross-build, so each non-native target needs one supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildTool {
    /// The host target: the system linker already works.
    Cargo,
    /// cross-rs: a per-target container carrying that target's linker and sysroot.
    Cross,
    /// cargo-zigbuild: zig as the linker, which also writes the ad-hoc signature
    /// Apple Silicon requires before it will exec an arm64 binary.
    Zigbuild,
}

/// The `--build-tool` that hands the leg to cargo-dist (CLOUD-2297):
/// `dist build --artifacts=local` compiles through `cargo auditable`, picks the
/// linker for host and target itself, and writes its own archive, its
/// `.sha256`, and the manifest fragment its global step generates the
/// installers from. Not a [`BuildTool`]: dist owns the whole build, so it has
/// no argv in that table's shape.
pub const CARGO_DIST: &str = "cargo-dist";

/// What cargo-dist names a target's archive: `name-TARGET` plus the extension
/// `dist-workspace.toml` declares, which is this module's [`archive_ext`].
/// dist's naming carries no version, so `latest/download` URLs resolve; the
/// versioned [`archive_stem`] stays published beside it for shipped engines.
#[must_use]
pub fn cargo_dist_archive(name: &str, target: &str) -> String {
    format!("{name}-{target}{}", archive_ext(target))
}

/// The checksum file cargo-dist writes beside an archive it names.
#[must_use]
pub fn cargo_dist_checksum(archive: &str) -> String {
    format!("{archive}.sha256")
}

/// The directory cargo-dist stages into, under the workspace's own `target/`.
pub const CARGO_DIST_DIR: &str = "distrib";

/// Where cargo-dist stages for the workspace at `root`: `<root>/target/distrib`,
/// never cargo's target directory, because dist ignores `CARGO_TARGET_DIR`
/// (measured: with it set, dist read and wrote the checkout's own staging).
#[must_use]
pub fn cargo_dist_staging(root: &Path) -> PathBuf {
    root.join("target").join(CARGO_DIST_DIR)
}

/// The manifest fragment one target's `dist build` leaves in [`CARGO_DIST_DIR`],
/// the name the global step reads every leg's fragment by.
#[must_use]
pub fn cargo_dist_manifest(target: &str) -> String {
    format!("{target}-dist-manifest.json")
}

/// `dist generate --mode msi`: writes the MSI template dist refuses to build
/// without. It is dist's output, never committed, so every build writes it.
pub const CARGO_DIST_MSI_TEMPLATE: [&str; 4] = ["dist", "generate", "--mode", "msi"];

/// The `dist build` argv for one target, announcing `v<version>`.
///
/// `--output-format=json` makes stdout the manifest fragment and nothing else;
/// the caller writes it where the global step reads fragments from.
#[must_use]
pub fn cargo_dist_argv(target: &str, version: &str) -> Vec<String> {
    [
        "dist",
        "build",
        "--artifacts=local",
        "--output-format=json",
        "--tag",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        format!("v{version}"),
        String::from("--target"),
        target.to_owned(),
    ])
    .collect()
}

impl BuildTool {
    /// The tool a flag names, `cargo` when it names none. `None` for anything
    /// else, which the caller refuses before anything is compiled.
    #[must_use]
    pub fn parse(name: Option<&str>) -> Option<Self> {
        match name.unwrap_or("cargo") {
            "cargo" => Some(Self::Cargo),
            "cross" => Some(Self::Cross),
            "zigbuild" => Some(Self::Zigbuild),
            _ => None,
        }
    }

    /// The build argv for one target and binary.
    ///
    /// `--locked`, so a release build resolves exactly the versions the lockfile
    /// pins; a release that silently floated a dependency is not the artifact CI
    /// tested.
    #[must_use]
    pub fn argv(self, target: &str, bin: &str) -> Vec<String> {
        let head: &[&str] = match self {
            // `auditable` wraps rustc rather than the subcommand, so it composes
            // with both of these.
            Self::Cargo => &["cargo", "auditable", "build"],
            Self::Zigbuild => &["cargo", "auditable", "zigbuild"],
            // DELIBERATELY UNWRAPPED (CLOUD-263): composition inside the
            // container is unmeasured, and an unproven wrapper does not enter a
            // matrix that once shipped six releases with zero binaries.
            Self::Cross => &["cross", "build"],
        };
        head.iter()
            .map(|word| (*word).to_owned())
            .chain(
                [
                    "--locked",
                    "--profile",
                    PROFILE,
                    "--target",
                    target,
                    "--bin",
                    bin,
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .collect()
    }
}

/// The one package a release archive is built from, as `cargo metadata` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The package name, which the asset stem carries (binstall's `{ name }`).
    pub name: String,
    /// The package version, which the asset stem carries.
    pub version: String,
    /// The binary target's name, which the builder writes.
    pub bin: String,
    /// The workspace root, where the archive directory lives.
    pub root: PathBuf,
    /// The target directory the builder writes under.
    pub target_dir: PathBuf,
}

/// Read the one releasable package out of a `cargo metadata` document.
///
/// # Errors
///
/// A pointer naming why no archive can be named: the document is not a
/// workspace's, no member declares a binary target, several do, or the package
/// declares no version.
pub fn package(metadata: &Value) -> std::result::Result<Package, String> {
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let (Some(root), Some(target_dir)) = (
        text(metadata, "workspace_root"),
        text(metadata, "target_directory"),
    ) else {
        return Err(String::from(
            "cargo metadata named no workspace root or target directory",
        ));
    };
    let members: Vec<&str> = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    // Every (package, binary) pair among the workspace's own members.
    let mut bins: Vec<(&Value, String)> = Vec::new();
    for package in packages {
        let member = package
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| members.contains(&id));
        if !member {
            continue;
        }
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for target in targets {
            let is_bin = target
                .get("kind")
                .and_then(Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")));
            if let (true, Some(name)) = (is_bin, text(target, "name")) {
                bins.push((package, name));
            }
        }
    }

    // EXACTLY ONE. Zero is nothing to ship; several is a choice this verb has no
    // argument to make, and guessing one names an archive for a binary it may
    // not carry.
    if bins.len() != 1 {
        return Err(format!(
            "the workspace declares {} binary targets, and dist builds exactly one",
            bins.len()
        ));
    }
    let Some((owner, bin)) = bins.pop() else {
        return Err(String::from("the workspace declares no binary target"));
    };
    let Some(name) = text(owner, "name") else {
        return Err(String::from("the binary's package names no package"));
    };
    let Some(version) = text(owner, "version").filter(|version| !version.is_empty()) else {
        return Err(format!(
            "package `{name}` declares no version, so the archive cannot be named"
        ));
    };
    Ok(Package {
        name,
        version,
        bin,
        root: PathBuf::from(root),
        target_dir: PathBuf::from(target_dir),
    })
}

/// A path as a pointer: relative to the workspace root when it sits under it.
fn pointer(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// One program run in a directory for its exit code and stdout, or `None` where
/// it could not start: [`exec::piped_argv`] in production, a script in a case.
///
/// **THE BUILD'S ONE EFFECT, HANDED IN** (CLOUD-2509). Every arm past the
/// builder acted only when cargo-dist was installed and a release build had
/// staged artifacts, so no case reached the refusals between the steps.
type Runner<'a> = &'a dyn Fn(&Path, &[String], Diagnostics) -> Option<(i32, String)>;

/// Run a program for its exit code, folding its output onto `err` when it fails.
///
/// `Ok(true)` ran and exited 0; `Ok(false)` did not, and `err` says why.
fn ran(dir: &Path, argv: &[String], err: &mut dyn Write, run: Runner<'_>) -> Result<bool> {
    let program = argv.first().map_or("", String::as_str);
    let Some((code, log)) = run(dir, argv, Diagnostics::Keep) else {
        writeln!(err, "dist: could not start `{program}`")?;
        return Ok(false);
    };
    if code == 0 {
        return Ok(true);
    }
    if !log.is_empty() {
        err.write_all(log.as_bytes())?;
        if !log.ends_with('\n') {
            writeln!(err)?;
        }
    }
    writeln!(err, "dist: `{program}` exited {code}")?;
    Ok(false)
}

/// The environment variable naming the builder when `--build-tool` is absent.
///
/// The retired `dist.sh` read ONLY this (`${DIST_BUILD_TOOL:-cargo}`), and a
/// maintainer's `DIST_BUILD_TOOL=zigbuild mise run dist <target>` must keep
/// meaning what it meant rather than silently building with plain cargo.
pub const BUILD_TOOL_ENV: &str = "DIST_BUILD_TOOL";

/// The builder a request names: the flag, else a non-empty
/// [`BUILD_TOOL_ENV`], else nothing (which [`BuildTool::parse`] reads as cargo).
///
/// Empty counts as unset, exactly as the shell's `:-` expansion did.
#[must_use]
pub fn named_build_tool(flag: Option<&str>, env: Option<&str>) -> Option<String> {
    flag.or_else(|| env.filter(|value| !value.is_empty()))
        .map(str::to_owned)
}

/// The builder a request builds with, or `None` for a `--stem` request.
///
/// `--stem` names the asset and never builds, so it never resolves a builder: the
/// retired `dist.sh` answered it before it ever read `DIST_BUILD_TOOL`, and an
/// unknown builder must not refuse it. Otherwise the flag, else a non-empty
/// environment value, else cargo — and `Err` carries the unknown name.
///
/// # Errors
///
/// The name, when a build is asked for and it is none of the three builders.
pub fn builder_for(
    stem: bool,
    flag: Option<&str>,
    env: Option<&str>,
) -> std::result::Result<Option<BuildTool>, String> {
    if stem {
        return Ok(None);
    }
    let named = named_build_tool(flag, env);
    BuildTool::parse(named.as_deref())
        .map(Some)
        .ok_or_else(|| named.unwrap_or_default())
}

/// `batten dist <target> [--stem] [--build-tool cargo|cross|zigbuild|cargo-dist]`, the
/// builder falling back to [`BUILD_TOOL_ENV`] when the flag is absent.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a build tool outside the three, whether the
/// flag or the environment named it, refused before anything is read or
/// compiled. A `--stem` request never builds, so it never resolves a builder
/// and an unknown one does not refuse it. Every other failure — a workspace
/// `cargo metadata` cannot read, a package no archive can be named for, a build
/// that fails or writes no binary, an archiver that fails — is `Internal`
/// (exit `3`) with its pointer on `err`, and never a partial answer on `out`.
pub fn run(
    target: &str,
    stem: bool,
    build_tool: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let from_env = std::env::var(BUILD_TOOL_ENV).ok();
    let by_dist =
        !stem && named_build_tool(build_tool, from_env.as_deref()).as_deref() == Some(CARGO_DIST);
    // `None` here IS the stem request (or cargo-dist's, which is no `BuildTool`).
    let tool = if by_dist {
        None
    } else {
        match builder_for(stem, build_tool, from_env.as_deref()) {
            Ok(tool) => tool,
            Err(named) => {
                return Err(UsageError::raise(format!(
                    "dist: --build-tool (or {BUILD_TOOL_ENV}) must be cargo, cross, or zigbuild, or {CARGO_DIST} to build through cargo-dist, got '{named}'"
                )));
            }
        }
    };
    let Some(package) = read_package(err)? else {
        return Ok(ExitCode::Internal);
    };
    let piped = |dir: &Path, argv: &[String], diagnostics: Diagnostics| {
        exec::piped_argv(dir, argv, "", diagnostics, &[])
    };
    build_and_stage(target, &package, (tool, by_dist), (out, err), &piped)
}

/// [`run`] past its reads: the stem, or the build `tool` (cargo-dist's when
/// `by_dist`) through `run`, then the archive.
fn build_and_stage(
    target: &str,
    package: &Package,
    (tool, by_dist): (Option<BuildTool>, bool),
    (out, err): (&mut dyn Write, &mut dyn Write),
    run: Runner<'_>,
) -> Result<ExitCode> {
    let stem = archive_stem(&package.name, &package.version, target);
    if by_dist {
        return run_cargo_dist(target, package, &stem, (out, err), run);
    }
    let Some(tool) = tool else {
        writeln!(out, "{stem}")?;
        return Ok(ExitCode::Success);
    };
    if !ran(&package.root, &tool.argv(target, &package.bin), err, run)? {
        return Ok(ExitCode::Internal);
    }
    let Some((archive, built)) = stage(package, target, &stem, err, run)? else {
        return Ok(ExitCode::Internal);
    };
    writeln!(out, "archive={}", pointer(&archive, &package.root))?;
    writeln!(out, "binary={}", pointer(&built, &package.root))?;
    Ok(ExitCode::Success)
}

/// The one releasable package of the workspace this verb stands in.
///
/// `Ok(None)` is could-not-look, its pointer already on `err`.
fn read_package(err: &mut dyn Write) -> Result<Option<Package>> {
    let here = std::env::current_dir()?;
    let metadata_argv: Vec<String> = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let Some((0, document)) = exec::piped_argv(&here, &metadata_argv, "", Diagnostics::Drop, &[])
    else {
        writeln!(
            err,
            "dist: cargo metadata could not read a workspace here, so no archive can be named"
        )?;
        return Ok(None);
    };
    let Ok(metadata) = serde_json::from_str::<Value>(&document) else {
        writeln!(
            err,
            "dist: cargo metadata answered something that is not JSON"
        )?;
        return Ok(None);
    };
    match package(&metadata) {
        Ok(package) => Ok(Some(package)),
        Err(reason) => {
            writeln!(err, "dist: {reason}")?;
            Ok(None)
        }
    }
}

/// Archive the binary the build wrote under the versioned `stem`, binary at
/// the archive root. `Ok(Some((archive, binary)))`, or `Ok(None)` with the
/// pointer on `err`.
fn stage(
    package: &Package,
    target: &str,
    stem: &str,
    err: &mut dyn Write,
    run: Runner<'_>,
) -> Result<Option<(PathBuf, PathBuf)>> {
    let file = binary_file(&package.bin, target);
    let built_dir = package.target_dir.join(target).join(PROFILE);
    let built = built_dir.join(&file);
    if !built.is_file() {
        writeln!(
            err,
            "dist: expected a binary at {}, found none",
            pointer(&built, &package.root)
        )?;
        return Ok(None);
    }

    let out_dir = package.root.join(OUT_DIR);
    std::fs::create_dir_all(&out_dir)?;
    let archive = out_dir.join(format!("{stem}{}", archive_ext(target)));
    // A stale archive from an earlier run must not survive a failed one.
    if archive.exists() {
        std::fs::remove_file(&archive)?;
    }
    let argv = archiver_argv(
        target,
        cfg!(windows),
        std::env::var_os("SystemRoot"),
        archive.to_string_lossy().into_owned(),
        &built_dir,
        file,
    );
    // A zip is written from inside the binary's directory; a tarball names it
    // with `-C`, so it runs from the workspace root.
    let dir = if is_windows_target(target) {
        built_dir.as_path()
    } else {
        package.root.as_path()
    };
    if !ran(dir, &argv, err, run)? || !archive.is_file() {
        writeln!(
            err,
            "dist: no archive at {}",
            pointer(&archive, &package.root)
        )?;
        return Ok(None);
    }
    Ok(Some((archive, built)))
}

/// The argv that archives `file` (in `built_dir`) as `archive` for `target`.
/// Both forms put the binary at the archive ROOT, never under
/// `target/<triple>/dist/`, so extracting yields the binary beside the user.
///
/// `system_root` is `%SystemRoot%`, used only when `windows_host`. A WINDOWS
/// HOST HAS NO `zip` (measured on windows-latest: "could not start `zip`"), and
/// every cargo-dist Windows leg builds on one. It does ship bsdtar as
/// `System32\tar.exe`, which writes the same zip, named by its full path
/// because a bash step puts Git for Windows' GNU tar, which writes no zip, first
/// on PATH. A non-Windows host cross-building the target keeps Info-ZIP
/// (CLOUD-2381).
//MUTANT archiver-ignores-host|s@^    if !windows_host {$@    if true {@|a_windows_host_never_archives_with_zip
fn archiver_argv(
    target: &str,
    windows_host: bool,
    system_root: Option<std::ffi::OsString>,
    archive: String,
    built_dir: &Path,
    file: String,
) -> Vec<String> {
    // Git's GNU tar, first on a bash step's PATH, also reads an absolute
    // `C:\…` archive as a remote host, so a Windows host tars with bsdtar too.
    let bsdtar = || {
        system_root
            .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
            .join("System32")
            .join("tar.exe")
            .to_string_lossy()
            .into_owned()
    };
    if !is_windows_target(target) {
        let tar = if windows_host {
            bsdtar()
        } else {
            "tar".to_owned()
        };
        return vec![
            tar,
            "-czf".to_owned(),
            archive,
            "-C".to_owned(),
            built_dir.to_string_lossy().into_owned(),
            file,
        ];
    }
    if !windows_host {
        return vec!["zip".to_owned(), "-q".to_owned(), archive, file];
    }
    [bsdtar()]
        .into_iter()
        .chain(["--format", "zip", "-cf"].map(str::to_owned))
        .chain([archive, file])
        .collect()
}

/// What a cargo-dist leg settles before `dist build`, in order:
///
/// * the leg's earlier outputs are removed, because `target/distrib` is never
///   cleaned and a leftover archive, checksum or MSI would pass the post-build
///   checks for bytes this build did not write;
/// * the lockfile is current (`cargo fetch --locked`), because dist's inner
///   `cargo build` takes no `--locked`, and a stale `Cargo.lock` would otherwise
///   re-resolve into dependencies CI never tested, where the cargo leg refused.
///   `fetch` rather than `metadata`: it prints nothing on stdout, so a refusal's
///   reason is not buried under the graph, and what it downloads the build
///   needs anyway;
/// * the MSI template is written ([`CARGO_DIST_MSI_TEMPLATE`]).
fn dist_preflight(
    root: &Path,
    outputs: &[&Path],
    err: &mut dyn Write,
    run: Runner<'_>,
) -> Result<bool> {
    for output in outputs {
        match std::fs::remove_file(output) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !ran(
        root,
        &["cargo", "fetch", "--locked"].map(str::to_owned),
        err,
        run,
    )? {
        return Ok(false);
    }
    ran(root, &CARGO_DIST_MSI_TEMPLATE.map(str::to_owned), err, run)
}

/// The leg, built by cargo-dist (CLOUD-2297): `dist build` for `target`, its
/// manifest fragment saved where the global step reads fragments, and the
/// binary it built archived under the versioned `stem` too, because every
/// shipped engine fetches that name (`engine::release_asset`).
fn run_cargo_dist(
    target: &str,
    package: &Package,
    stem: &str,
    (out, err): (&mut dyn Write, &mut dyn Write),
    run: Runner<'_>,
) -> Result<ExitCode> {
    let staged = cargo_dist_staging(&package.root);
    let dist_name = cargo_dist_archive(&package.name, target);
    let checksum = staged.join(cargo_dist_checksum(&dist_name));
    let dist_archive = staged.join(dist_name);
    let manifest = staged.join(cargo_dist_manifest(target));
    let msi = staged.join(format!("{}-{target}.msi", package.name));
    if !dist_preflight(
        &package.root,
        &[
            dist_archive.as_path(),
            checksum.as_path(),
            manifest.as_path(),
            msi.as_path(),
        ],
        err,
        run,
    )? {
        return Ok(ExitCode::Internal);
    }
    let argv = cargo_dist_argv(target, &package.version);
    // stdout IS the manifest fragment; the build log stays on stderr, where a
    // failure's reason is the step's only evidence.
    let Some((code, fragment)) = run(&package.root, &argv, Diagnostics::Pass) else {
        writeln!(err, "dist: could not start `dist`")?;
        return Ok(ExitCode::Internal);
    };
    if code != 0 {
        writeln!(err, "dist: `dist` exited {code}")?;
        return Ok(ExitCode::Internal);
    }
    if serde_json::from_str::<Value>(&fragment).is_err() {
        writeln!(err, "dist: `dist build` printed no manifest")?;
        return Ok(ExitCode::Internal);
    }
    std::fs::create_dir_all(&staged)?;
    crate::durable::replace(&manifest, fragment)?;

    for written in [&dist_archive, &checksum] {
        if !written.is_file() {
            writeln!(
                err,
                "dist: expected cargo-dist's {}, found none",
                pointer(written, &package.root)
            )?;
            return Ok(ExitCode::Internal);
        }
    }
    let Some((archive, built)) = stage(package, target, stem, err, run)? else {
        return Ok(ExitCode::Internal);
    };
    writeln!(out, "archive={}", pointer(&archive, &package.root))?;
    writeln!(out, "binary={}", pointer(&built, &package.root))?;
    writeln!(
        out,
        "dist_archive={}",
        pointer(&dist_archive, &package.root)
    )?;
    writeln!(out, "checksum={}", pointer(&checksum, &package.root))?;
    writeln!(out, "manifest={}", pointer(&manifest, &package.root))?;
    // The version a package channel stamps (CLOUD-2298): the crate's own, with
    // no tag prefix, which is the spelling Chocolatey and nfpm want.
    writeln!(out, "version={}", package.version)?;
    // A Windows leg's MSI (CLOUD-2298), which dist writes only for a Windows
    // target and only when `dist-workspace.toml` declares the installer.
    if msi.is_file() {
        writeln!(out, "msi={}", pointer(&msi, &package.root))?;
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-gnu";

    /// The production runner, for the cases that run real programs.
    fn piped(dir: &Path, argv: &[String], diagnostics: Diagnostics) -> Option<(i32, String)> {
        exec::piped_argv(dir, argv, "", diagnostics, &[])
    }

    /// A package rooted in a scratch directory, its binary built when `built`.
    fn scratch_package(case: &str, built: bool) -> Package {
        let root = crate::scratch::scratch(case);
        let package = Package {
            name: String::from("batten"),
            version: String::from("1.0.0"),
            bin: String::from("batten"),
            target_dir: root.join("target"),
            root,
        };
        if built {
            let dir = package.target_dir.join(TARGET).join(PROFILE);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(binary_file(&package.bin, TARGET)), "bin").unwrap();
        }
        package
    }

    /// The exit codes a scripted build answers with, and what it writes.
    #[derive(Clone, Copy)]
    struct Script {
        cargo: i32,
        dist: i32,
        dist_writes: bool,
        tar: i32,
        tar_writes: bool,
    }

    const GREEN: Script = Script {
        cargo: 0,
        dist: 0,
        dist_writes: true,
        tar: 0,
        tar_writes: true,
    };

    /// Run `body` over a runner playing `script`, answering every call it was
    /// asked, first word and second, in order.
    fn scripted<T>(script: Script, body: impl FnOnce(Runner<'_>) -> T) -> (T, Vec<String>) {
        let calls = std::cell::RefCell::new(Vec::new());
        let run = |dir: &Path, argv: &[String], _: Diagnostics| {
            calls
                .borrow_mut()
                .push(argv.iter().take(2).cloned().collect::<Vec<_>>().join(" "));
            match (argv[0].as_str(), argv.get(1).map(String::as_str)) {
                ("cargo", _) => Some((script.cargo, String::new())),
                ("dist", Some("build")) => {
                    if script.dist_writes {
                        let staged = cargo_dist_staging(dir);
                        std::fs::create_dir_all(&staged).unwrap();
                        let archive = cargo_dist_archive("batten", TARGET);
                        std::fs::write(staged.join(cargo_dist_checksum(&archive)), "sum").unwrap();
                        std::fs::write(staged.join(archive), "dist").unwrap();
                    }
                    Some((script.dist, String::from("{}")))
                }
                ("dist", _) => Some((0, String::new())),
                ("tar", _) => {
                    if script.tar_writes {
                        std::fs::write(&argv[2], "tar").unwrap();
                    }
                    Some((script.tar, String::new()))
                }
                _ => None,
            }
        };
        let answered = body(&run);
        (answered, calls.into_inner())
    }

    #[test]
    fn a_stage_archives_the_built_binary_or_says_what_is_missing() {
        let package = scratch_package("dist-stage", true);
        let stem = archive_stem("batten", "1.0.0", TARGET);
        let staged = |script: Script| {
            let mut err = Vec::new();
            let (staged, _) = scripted(script, |run| {
                stage(&package, TARGET, &stem, &mut err, run).unwrap()
            });
            (staged, String::from_utf8(err).unwrap())
        };
        let (archived, _) = staged(GREEN);
        assert_eq!(
            archived,
            Some((
                package.root.join(OUT_DIR).join(format!("{stem}.tar.gz")),
                package.target_dir.join(TARGET).join(PROFILE).join("batten"),
            ))
        );
        let (unwritten, err) = staged(Script {
            tar_writes: false,
            ..GREEN
        });
        assert_eq!(unwritten, None);
        assert!(err.contains("no archive"), "{err}");
        let (refused, _) = staged(Script {
            tar: 1,
            tar_writes: false,
            ..GREEN
        });
        assert_eq!(refused, None);
        let unbuilt = scratch_package("dist-stage-unbuilt", false);
        let mut err = Vec::new();
        let (missing, _) = scripted(GREEN, |run| {
            stage(&unbuilt, TARGET, &stem, &mut err, run).unwrap()
        });
        assert_eq!(missing, None);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("expected a binary")
        );
    }

    #[test]
    fn a_preflight_clears_the_leg_s_outputs_and_stops_at_a_refused_fetch() {
        let package = scratch_package("dist-preflight-scripted", false);
        let left = package.root.join("left.tar.xz");
        std::fs::write(&left, "stale").unwrap();
        let absent = package.root.join("absent");
        let (ready, calls) = scripted(GREEN, |run| {
            dist_preflight(&package.root, &[&left, &absent], &mut Vec::new(), run).unwrap()
        });
        assert!(ready);
        assert!(!left.exists());
        assert_eq!(calls, vec!["cargo fetch", "dist generate"]);
        let (ready, calls) = scripted(Script { cargo: 1, ..GREEN }, |run| {
            dist_preflight(&package.root, &[], &mut Vec::new(), run).unwrap()
        });
        assert!(!ready);
        assert_eq!(calls, vec!["cargo fetch"]);
        let (refused, _) = scripted(GREEN, |run| {
            dist_preflight(&package.root, &[&package.root], &mut Vec::new(), run).is_err()
        });
        assert!(refused, "a directory where an output was is not cleared");
    }

    #[test]
    fn a_cargo_dist_leg_reports_its_artifacts_only_when_each_step_held() {
        let package = scratch_package("dist-cargo-dist", true);
        let stem = archive_stem("batten", "1.0.0", TARGET);
        let leg = |script: Script| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let (code, _) = scripted(script, |run| {
                run_cargo_dist(TARGET, &package, &stem, (&mut out, &mut err), run).unwrap()
            });
            (code, String::from_utf8(out).unwrap())
        };
        let (code, out) = leg(GREEN);
        assert_eq!(code, ExitCode::Success, "{out}");
        assert!(
            out.contains("dist_archive=") && out.contains("version=1.0.0\n"),
            "{out}"
        );
        assert_eq!(leg(Script { dist: 2, ..GREEN }).0, ExitCode::Internal);
        assert_eq!(
            leg(Script {
                dist_writes: false,
                ..GREEN
            })
            .0,
            ExitCode::Internal
        );
        assert_eq!(leg(Script { cargo: 1, ..GREEN }).0, ExitCode::Internal);
    }

    #[test]
    fn a_build_that_held_is_staged_and_one_that_failed_is_not() {
        let package = scratch_package("dist-build", true);
        let build = |script: Script, tool: Option<BuildTool>| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let (code, _) = scripted(script, |run| {
                build_and_stage(TARGET, &package, (tool, false), (&mut out, &mut err), run).unwrap()
            });
            (code, String::from_utf8(out).unwrap())
        };
        let (code, out) = build(GREEN, Some(BuildTool::Cargo));
        assert_eq!(code, ExitCode::Success);
        assert!(out.starts_with("archive=dist/"), "{out}");
        let (code, out) = build(Script { cargo: 1, ..GREEN }, Some(BuildTool::Cargo));
        assert_eq!((code, out.as_str()), (ExitCode::Internal, ""));
        let (code, out) = build(GREEN, None);
        assert_eq!(
            (code, out.trim()),
            (
                ExitCode::Success,
                archive_stem("batten", "1.0.0", TARGET).as_str()
            )
        );
    }

    #[test]
    fn cargo_dist_s_own_names_are_spelled_once() {
        assert_eq!(cargo_dist_checksum("b.tar.xz"), "b.tar.xz.sha256");
        assert_eq!(
            cargo_dist_manifest("x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-gnu-dist-manifest.json"
        );
        assert_eq!(
            cargo_dist_staging(Path::new("/w")),
            Path::new("/w").join("target").join(CARGO_DIST_DIR)
        );
    }

    /// A program that ran and exited 0 is the one `true`; any other end says
    /// why on `err`.
    #[test]
    fn a_program_ran_only_when_it_exited_zero() {
        let here = std::env::current_dir().unwrap();
        let argv = |words: &[&str]| {
            words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>()
        };
        let mut err = Vec::new();
        assert!(ran(&here, &argv(&["cargo", "--version"]), &mut err, &piped).unwrap());
        assert!(err.is_empty());
        assert!(
            !ran(
                &here,
                &argv(&["cargo", "--no-such-flag-anywhere"]),
                &mut err,
                &piped
            )
            .unwrap()
        );
        let said = String::from_utf8(err).unwrap();
        // The program's own output comes first, ended by exactly one newline.
        assert!(!said.starts_with("dist:"), "{said}");
        assert!(said.contains("\ndist: `cargo` exited "), "{said}");
        assert!(!said.contains("\n\ndist:"), "{said}");
        let mut err = Vec::new();
        assert!(
            !ran(
                &here,
                &argv(&["batten-no-such-program-for-dist"]),
                &mut err,
                &piped
            )
            .unwrap()
        );
        assert!(String::from_utf8(err).unwrap().contains("could not start"));
    }

    /// A missing earlier output is nothing to remove; any other failure to
    /// remove one is an error, never a silently kept leftover.
    #[test]
    fn a_leftover_that_cannot_be_removed_stops_the_preflight() {
        let dir = crate::scratch::scratch("dist-preflight");
        std::fs::create_dir_all(dir.join("a-directory")).unwrap();
        let mut err = Vec::new();
        assert!(!dist_preflight(&dir, &[dir.join("absent").as_path()], &mut err, &piped).unwrap());
        assert!(
            dist_preflight(&dir, &[dir.join("a-directory").as_path()], &mut err, &piped).is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--stem` names the asset from the workspace and never builds, whatever
    /// builder is named; an unknown builder refuses any request that builds.
    #[test]
    fn a_stem_request_names_the_asset_and_an_unknown_builder_refuses_a_build() {
        let target = "x86_64-unknown-linux-gnu";
        // Naming cargo-dist is the discriminating case: it is the one builder
        // that would take the stem request off the stem path.
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run(target, true, Some(CARGO_DIST), &mut out, &mut err).unwrap(),
            ExitCode::Success
        );
        let said = String::from_utf8(out).unwrap();
        assert!(
            said.starts_with("batten-") && said.trim_end().ends_with(target),
            "{said}"
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(run(target, false, Some("no-such-builder"), &mut out, &mut err).is_err());
    }

    fn metadata(packages: &Value) -> Value {
        let members: Vec<Value> = packages
            .as_array()
            .unwrap()
            .iter()
            .map(|package| package["id"].clone())
            .collect();
        serde_json::json!({
            "packages": packages,
            "workspace_members": members,
            "workspace_root": "/w",
            "target_directory": "/w/target",
        })
    }

    fn crate_with(name: &str, version: &str, bins: &[&str]) -> Value {
        let mut targets: Vec<Value> = bins
            .iter()
            .map(|bin| serde_json::json!({"kind": ["bin"], "name": bin}))
            .collect();
        targets.push(serde_json::json!({"kind": ["lib"], "name": name}));
        serde_json::json!({
            "id": format!("{name} {version} (path+file:///w/{name})"),
            "name": name,
            "version": version,
            "targets": targets,
        })
    }

    #[test]
    fn windows_targets_are_detected_by_triple_not_by_host() {
        assert!(is_windows_target("x86_64-pc-windows-msvc"));
        assert!(is_windows_target("x86_64-pc-windows-gnu"));
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        ] {
            assert!(!is_windows_target(target), "{target}");
        }
    }

    #[test]
    fn the_archive_stem_is_name_v_version_target() {
        assert_eq!(
            archive_stem("widget", "1.2.3", "x86_64-unknown-linux-gnu"),
            "widget-v1.2.3-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn two_targets_never_share_an_archive_name() {
        assert_ne!(
            archive_stem("widget", "0.1.0", "aarch64-apple-darwin"),
            archive_stem("widget", "0.1.0", "x86_64-apple-darwin")
        );
    }

    #[test]
    fn the_archive_extension_is_keyed_off_the_target() {
        assert_eq!(archive_ext("x86_64-unknown-linux-musl"), ".tar.gz");
        assert_eq!(archive_ext("x86_64-pc-windows-gnu"), ".zip");
        assert_eq!(binary_file("widget", "x86_64-pc-windows-gnu"), "widget.exe");
        assert_eq!(binary_file("widget", "x86_64-unknown-linux-gnu"), "widget");
    }

    #[test]
    fn cross_is_not_wrapped_in_auditable_and_the_other_two_are() {
        let tail = [
            "--locked",
            "--profile",
            "dist",
            "--target",
            "t",
            "--bin",
            "b",
        ];
        let expect = |head: &[&str]| -> Vec<String> {
            head.iter()
                .chain(tail.iter())
                .map(|word| (*word).to_owned())
                .collect()
        };
        assert_eq!(
            BuildTool::Cargo.argv("t", "b"),
            expect(&["cargo", "auditable", "build"])
        );
        assert_eq!(
            BuildTool::Zigbuild.argv("t", "b"),
            expect(&["cargo", "auditable", "zigbuild"])
        );
        assert_eq!(BuildTool::Cross.argv("t", "b"), expect(&["cross", "build"]));
    }

    /// dist announces the package's own version as its tag, and builds only the
    /// named target: an argv that drops either builds the wrong release.
    #[test]
    fn cargo_dist_builds_one_target_under_the_packages_version() {
        // cargo-dist is requested by name and is no `BuildTool`: dist owns the build.
        assert_eq!(BuildTool::parse(Some(CARGO_DIST)), None);
        let argv = cargo_dist_argv("x86_64-unknown-linux-gnu", "1.2.3");
        assert_eq!(
            argv,
            [
                "dist",
                "build",
                "--artifacts=local",
                "--output-format=json",
                "--tag",
                "v1.2.3",
                "--target",
                "x86_64-unknown-linux-gnu"
            ]
        );
    }

    /// THE MSI'S WIX TABLE IS PINNED HERE, so editing it touches this file,
    /// which `test.yml`'s path filter watches, and the three-OS MSI and
    /// Chocolatey install proof runs. The filter does not watch
    /// `crates/batten/Cargo.toml` itself: every dependency bump edits it.
    #[test]
    fn the_msi_wix_table_is_the_one_the_install_proof_ran_on() {
        let manifest: toml::Table = include_str!("../Cargo.toml").parse().unwrap();
        let wix = &manifest["package"]["metadata"]["wix"];
        assert_eq!(
            wix["upgrade-guid"].as_str(),
            Some("4970C541-6183-44FB-BB48-BBCEDC121C9D")
        );
        assert_eq!(
            wix["path-guid"].as_str(),
            Some("55F605A4-F4D8-4892-8617-C81D1C14F137")
        );
        assert_eq!(wix["license"].as_bool(), Some(false));
        assert_eq!(wix["eula"].as_bool(), Some(false));
        assert_eq!(wix.as_table().map(toml::Table::len), Some(4));
    }

    /// A Windows host has no `zip`, so it writes the zip with its own bsdtar by
    /// full path; a non-Windows host cross-building keeps Info-ZIP, and a
    /// non-Windows target is a tarball wherever it is built (CLOUD-2381).
    #[test]
    fn a_windows_host_never_archives_with_zip() {
        let windows = "x86_64-pc-windows-gnu";
        let dir = Path::new("target/x86_64-pc-windows-gnu/dist");
        let on_windows = archiver_argv(
            windows,
            true,
            Some(std::ffi::OsString::from(r"D:\Windows")),
            "a.zip".to_owned(),
            dir,
            "batten.exe".to_owned(),
        );
        assert_ne!(on_windows[0], "zip", "{on_windows:?}");
        assert!(
            Path::new(&on_windows[0]).ends_with(Path::new("System32").join("tar.exe")),
            "{on_windows:?}"
        );
        assert!(on_windows[0].starts_with(r"D:\Windows"), "{on_windows:?}");
        assert_eq!(on_windows[1..4], ["--format", "zip", "-cf"]);
        let unset_root = archiver_argv(
            windows,
            true,
            None,
            "a.zip".to_owned(),
            dir,
            "batten.exe".to_owned(),
        );
        assert!(unset_root[0].starts_with(r"C:\Windows"), "{unset_root:?}");

        let cross = archiver_argv(
            windows,
            false,
            None,
            "a.zip".to_owned(),
            dir,
            "batten.exe".to_owned(),
        );
        assert_eq!(cross[0], "zip", "{cross:?}");

        let linux_on_windows = archiver_argv(
            "x86_64-unknown-linux-gnu",
            true,
            None,
            "a.tar.gz".to_owned(),
            dir,
            "batten".to_owned(),
        );
        assert!(
            linux_on_windows[0].starts_with(r"C:\Windows"),
            "{linux_on_windows:?}"
        );
        assert_eq!(linux_on_windows[1], "-czf");
        let linux = archiver_argv(
            "x86_64-unknown-linux-gnu",
            false,
            None,
            "a.tar.gz".to_owned(),
            dir,
            "batten".to_owned(),
        );
        assert_eq!(linux[..2], ["tar", "-czf"]);
    }

    /// dist's name carries no version and keeps the per-target extension; the
    /// versioned stem the engine fetches is a different name for the same target.
    #[test]
    fn cargo_dists_archive_name_is_versionless_and_differs_from_the_stem() {
        assert_eq!(
            cargo_dist_archive("batten", "x86_64-unknown-linux-gnu"),
            "batten-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            cargo_dist_archive("batten", "x86_64-pc-windows-gnu"),
            "batten-x86_64-pc-windows-gnu.zip"
        );
        assert_ne!(
            cargo_dist_archive("batten", "x86_64-unknown-linux-gnu"),
            format!(
                "{}{}",
                archive_stem("batten", "1.2.3", "x86_64-unknown-linux-gnu"),
                archive_ext("x86_64-unknown-linux-gnu")
            )
        );
    }

    #[test]
    fn an_absent_build_tool_is_cargo_and_an_unknown_one_is_none() {
        assert_eq!(BuildTool::parse(None), Some(BuildTool::Cargo));
        assert_eq!(BuildTool::parse(Some("cross")), Some(BuildTool::Cross));
        assert_eq!(
            BuildTool::parse(Some("zigbuild")),
            Some(BuildTool::Zigbuild)
        );
        assert_eq!(BuildTool::parse(Some("bogus")), None);
    }

    #[test]
    fn the_flag_outranks_the_environment_and_an_empty_one_is_unset() {
        assert_eq!(
            named_build_tool(Some("cross"), Some("zigbuild")).as_deref(),
            Some("cross")
        );
        assert_eq!(
            named_build_tool(None, Some("zigbuild")).as_deref(),
            Some("zigbuild")
        );
        assert_eq!(named_build_tool(None, Some("")), None);
        assert_eq!(named_build_tool(None, None), None);
    }

    #[test]
    fn a_stem_request_resolves_no_builder_and_a_build_refuses_an_unknown_one() {
        assert_eq!(builder_for(true, None, Some("bogus")), Ok(None));
        assert_eq!(builder_for(true, Some("bogus"), None), Ok(None));
        assert_eq!(
            builder_for(false, None, Some("bogus")),
            Err("bogus".to_owned())
        );
        assert_eq!(
            builder_for(false, None, Some("cross")),
            Ok(Some(BuildTool::Cross))
        );
        assert_eq!(builder_for(false, None, None), Ok(Some(BuildTool::Cargo)));
    }

    #[test]
    fn the_package_version_and_binary_come_from_the_workspace() {
        let found = package(&metadata(&serde_json::json!([crate_with(
            "widget",
            "1.2.3",
            &["widget"]
        )])))
        .unwrap();
        assert_eq!(found.name, "widget");
        assert_eq!(found.version, "1.2.3");
        assert_eq!(found.bin, "widget");
        assert_eq!(found.root, PathBuf::from("/w"));
        assert_eq!(found.target_dir, PathBuf::from("/w/target"));
    }

    #[test]
    fn a_package_with_no_version_is_refused_rather_than_named_empty() {
        let refused = package(&metadata(&serde_json::json!([crate_with(
            "widget",
            "",
            &["widget"]
        )])))
        .unwrap_err();
        assert!(refused.contains("declares no version"), "{refused}");
    }

    #[test]
    fn a_workspace_with_two_binaries_is_refused_rather_than_guessed() {
        let refused = package(&metadata(&serde_json::json!([crate_with(
            "widget",
            "1.2.3",
            &["widget", "helper"]
        )])))
        .unwrap_err();
        assert!(refused.contains("2 binary targets"), "{refused}");
    }

    #[test]
    fn a_workspace_with_no_binary_is_refused() {
        let refused = package(&metadata(&serde_json::json!([crate_with(
            "widget",
            "1.2.3",
            &[]
        )])))
        .unwrap_err();
        assert!(refused.contains("0 binary targets"), "{refused}");
    }

    #[test]
    fn a_dependency_s_binary_is_not_the_workspace_s() {
        let mut document = metadata(&serde_json::json!([crate_with(
            "widget",
            "1.2.3",
            &["widget"]
        )]));
        document["packages"]
            .as_array_mut()
            .unwrap()
            .push(crate_with("other", "9.9.9", &["other"]));
        let found = package(&document).unwrap();
        assert_eq!(found.bin, "widget");
    }

    #[test]
    fn a_pointer_is_relative_to_the_root_it_sits_under() {
        assert_eq!(
            pointer(Path::new("/w/dist/a.tar.gz"), Path::new("/w")),
            "dist/a.tar.gz"
        );
        assert_eq!(
            pointer(Path::new("/elsewhere/b"), Path::new("/w")),
            "/elsewhere/b"
        );
    }
}
