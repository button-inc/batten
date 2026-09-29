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

use crate::cli::DistRequest;
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

/// Run a program for its exit code, folding its output onto `err` when it fails.
///
/// `Ok(true)` ran and exited 0; `Ok(false)` did not, and `err` says why.
fn ran(dir: &Path, argv: &[String], err: &mut dyn Write) -> Result<bool> {
    let program = argv.first().map_or("", String::as_str);
    let Some((code, log)) = exec::piped_argv(dir, argv, "", Diagnostics::Keep, &[]) else {
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

/// `batten dist <target> [--stem] [--build-tool cargo|cross|zigbuild]`, the
/// builder falling back to [`BUILD_TOOL_ENV`] when the flag is absent.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a build tool outside the three, whether the
/// flag or the environment named it, refused before anything is read or
/// compiled. Every other failure — a workspace
/// `cargo metadata` cannot read, a package no archive can be named for, a build
/// that fails or writes no binary, an archiver that fails — is `Internal`
/// (exit `3`) with its pointer on `err`, and never a partial answer on `out`.
pub fn run(request: &DistRequest, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let target = request.target.as_str();
    let from_env = std::env::var(BUILD_TOOL_ENV).ok();
    let named = named_build_tool(request.build_tool.as_deref(), from_env.as_deref());
    let Some(tool) = BuildTool::parse(named.as_deref()) else {
        return Err(UsageError::raise(format!(
            "dist: --build-tool (or {BUILD_TOOL_ENV}) must be cargo, cross, or zigbuild, got '{}'",
            named.as_deref().unwrap_or_default()
        )));
    };

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
        return Ok(ExitCode::Internal);
    };
    let Ok(metadata) = serde_json::from_str::<Value>(&document) else {
        writeln!(
            err,
            "dist: cargo metadata answered something that is not JSON"
        )?;
        return Ok(ExitCode::Internal);
    };
    let package = match package(&metadata) {
        Ok(package) => package,
        Err(reason) => {
            writeln!(err, "dist: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };

    let stem = archive_stem(&package.name, &package.version, target);
    if request.stem {
        writeln!(out, "{stem}")?;
        return Ok(ExitCode::Success);
    }

    if !ran(&package.root, &tool.argv(target, &package.bin), err)? {
        return Ok(ExitCode::Internal);
    }

    let file = binary_file(&package.bin, target);
    let built_dir = package.target_dir.join(target).join(PROFILE);
    let built = built_dir.join(&file);
    if !built.is_file() {
        writeln!(
            err,
            "dist: expected a binary at {}, found none",
            pointer(&built, &package.root)
        )?;
        return Ok(ExitCode::Internal);
    }

    let out_dir = package.root.join(OUT_DIR);
    std::fs::create_dir_all(&out_dir)?;
    let archive = out_dir.join(format!("{stem}{}", archive_ext(target)));
    // A stale archive from an earlier run must not survive a failed one.
    if archive.exists() {
        std::fs::remove_file(&archive)?;
    }
    let absolute = archive.to_string_lossy().into_owned();
    // Both forms put the binary at the archive ROOT, never under
    // `target/<triple>/dist/`, so extracting yields the binary beside the user.
    let (dir, argv): (&Path, Vec<String>) = if is_windows_target(target) {
        (
            built_dir.as_path(),
            vec!["zip".to_owned(), "-q".to_owned(), absolute, file],
        )
    } else {
        (
            package.root.as_path(),
            vec![
                "tar".to_owned(),
                "-czf".to_owned(),
                absolute,
                "-C".to_owned(),
                built_dir.to_string_lossy().into_owned(),
                file,
            ],
        )
    };
    if !ran(dir, &argv, err)? || !archive.is_file() {
        writeln!(
            err,
            "dist: no archive at {}",
            pointer(&archive, &package.root)
        )?;
        return Ok(ExitCode::Internal);
    }

    writeln!(out, "archive={}", pointer(&archive, &package.root))?;
    writeln!(out, "binary={}", pointer(&built, &package.root))?;
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
