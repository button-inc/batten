//! What the schema sweep (`mutate::schema`) shares for running cases under
//! nextest (CLOUD-2253): the filterset naming exact cases, the target flags
//! that build only their binaries, how a wrapped case names its binary and
//! itself, the nextest config that wraps every case in the reach recorder,
//! and the snapshot of the sources a sweep reads.
//!
//! The per-case LLVM coverage map that used to live here, and the `$CARGO`
//! stand-in that narrowed cargo-mutants' test steps by it, are retired: the
//! schema records each case's reach by the switches themselves, in the same
//! build it judges (#1276).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};

/// The nextest filterset naming exactly `tests`; `none()` when there are none,
/// so a mutant nothing covers runs nothing and is re-judged by the full pass.
#[must_use]
pub fn filterset(tests: &BTreeSet<&str>) -> String {
    if tests.is_empty() {
        return String::from("none()");
    }
    tests
        .iter()
        .map(|test| format!("test(={test})"))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The cargo target flags that build exactly `binaries` (nextest binary ids:
/// `pkg` is a library's unit tests, `pkg::bin/name`, `pkg::example/name`,
/// `pkg::bench/name`, and `pkg::name` an integration test).
///
/// No covering binary still builds `--lib`, the cheapest build that decides
/// whether the mutant compiles. A mutant in a binary's own source adds
/// `--bins`, since no library target compiles that file.
#[must_use]
pub fn target_args(binaries: &BTreeSet<&str>, mutated_file: &str) -> Vec<String> {
    let mut targets: BTreeSet<Vec<String>> = BTreeSet::new();
    for binary in binaries {
        let target = match binary.split_once("::") {
            None => vec![String::from("--lib")],
            Some((_, rest)) => match rest.split_once('/') {
                Some(("bin", name)) => vec![String::from("--bin"), name.to_owned()],
                Some(("example", name)) => vec![String::from("--example"), name.to_owned()],
                Some(("bench", name)) => vec![String::from("--bench"), name.to_owned()],
                _ => vec![String::from("--test"), rest.to_owned()],
            },
        };
        targets.insert(target);
    }
    if targets.is_empty() {
        targets.insert(vec![String::from("--lib")]);
    }
    if mutated_file.ends_with("src/main.rs") || mutated_file.contains("src/bin/") {
        targets.insert(vec![String::from("--bins")]);
    }
    targets.into_iter().flatten().collect()
}

/// The checkout's Rust sources as they stand, copied under `dest`: what each
/// cargo-mutants copy is compared against to find its mutated line. Returns
/// the [`source_digest`] of the bytes it copied, so a caller compares the
/// snapshot itself, never a second read of the checkout.
///
/// NOT THE LIVE CHECKOUT, which a sweep running for hours does not freeze:
/// measured on #1276, one edit to `lib.rs` mid-sweep made its line the "first
/// difference" of every later mutant below it, so each was handed another
/// function's cases, survived them, and fell to the whole-suite pass.
///
/// # Errors
///
/// The checkout cannot be listed, or a source cannot be copied.
pub fn pristine(root: &Path, dest: &Path) -> Result<String> {
    let _ = std::fs::remove_dir_all(dest);
    let mut digest = blake3::Hasher::new();
    for path in rust_sources(root)? {
        let bytes = std::fs::read(root.join(&path)).with_context(|| format!("read {path}"))?;
        let to = dest.join(&path);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&to, &bytes).with_context(|| format!("copy {path}"))?;
        digest_one(&mut digest, &path, &bytes);
    }
    Ok(digest.finalize().to_hex().to_string())
}

/// The digest of the checkout's Rust sources, path and bytes, in the order
/// and over the set [`pristine`] copies.
///
/// # Errors
///
/// The checkout cannot be listed, or a source cannot be read.
pub fn source_digest(root: &Path) -> Result<String> {
    let mut digest = blake3::Hasher::new();
    for path in rust_sources(root)? {
        let bytes = std::fs::read(root.join(&path)).with_context(|| format!("read {path}"))?;
        digest_one(&mut digest, &path, &bytes);
    }
    Ok(digest.finalize().to_hex().to_string())
}

fn digest_one(digest: &mut blake3::Hasher, path: &str, bytes: &[u8]) {
    digest.update(path.as_bytes());
    digest.update(&[0]);
    digest.update(bytes);
    digest.update(&[0]);
}

/// Every Rust file the checkout tracks or has changed that exists, sorted.
fn rust_sources(root: &Path) -> Result<Vec<String>> {
    let mut paths: BTreeSet<String> = crate::git::tracked_paths(root)?.into_iter().collect();
    paths.extend(crate::git::changed_paths(root)?);
    Ok(paths
        .into_iter()
        .filter(|path| {
            Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                && root.join(path).is_file()
        })
        .collect())
}

/// The nextest binary id of the case a wrapper runs, from the test program's
/// path and the directory nextest starts it in, which is its package's.
///
/// NOT `NEXTEST_BINARY_ID`: nextest 0.9.104 does not hand it to a wrapper
/// script, and on #1276 every case recorded an empty binary, so every build
/// went unnarrowed and every schema judgement named the package `""`.
///
/// `deps/<target>-<hash>` is the library's unit cases where `<target>` is the
/// package's crate name, and the package's integration test otherwise.
#[must_use]
pub fn binary_id(program: &str, package_dir: &Path) -> String {
    let file = Path::new(program)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let target = file
        .rsplit_once('-')
        .map_or(file.as_str(), |(stem, _)| stem);
    let manifest = crate::fsio::read_to_string(package_dir.join("Cargo.toml")).unwrap_or_default();
    let package = manifest
        .parse::<toml::Table>()
        .ok()
        .and_then(|table| {
            table
                .get("package")?
                .get("name")?
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_default();
    if package.is_empty() || target.is_empty() {
        return String::new();
    }
    if target == package.replace('-', "_") {
        package
    } else {
        format!("{package}::{target}")
    }
}

/// The test name in the argv nextest hands a wrapper: `<binary> --exact <name>`.
#[must_use]
pub fn test_name(args: &[String]) -> Option<&str> {
    let at = args.iter().position(|arg| arg == "--exact")?;
    args.get(at + 1).map(String::as_str)
}

/// The repository's nextest config with the recording wrapper and its profile
/// added, so every case keeps the setup scripts and settings it runs under.
///
/// APPENDED AS TEXT, the experimental list alone edited in place: an edited
/// `profile.batten-cover` came out as an INLINE table, which cannot hold the
/// `[[...scripts]]` array, so the wrapper was dropped without an error and the
/// suite ran unrecorded.
///
/// # Errors
///
/// The repository's nextest config does not parse.
pub fn wrapped_config(root: &Path, recorder: &Path, arg: &str, store: &Path) -> Result<String> {
    let path = root.join(".config").join("nextest.toml");
    let text = crate::fsio::read_to_string(&path).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text.parse().context("parse nextest.toml")?;
    let mut experimental = doc
        .get("experimental")
        .and_then(toml_edit::Item::as_array)
        .cloned()
        .unwrap_or_default();
    if !experimental
        .iter()
        .any(|value| value.as_str() == Some("wrapper-scripts"))
    {
        experimental.push("wrapper-scripts");
    }
    doc["experimental"] = toml_edit::value(experimental);
    let recorder = toml_edit::Value::from(recorder.to_string_lossy().into_owned());
    // THE STORE IS NAMED, so the report is where the build reads it: left to
    // nextest, it went under the checkout's `target/`, not the build's.
    let store = toml_edit::Value::from(store.to_string_lossy().into_owned());
    let mut config = doc.to_string();
    let _ = write!(
        config,
        "\n[store]\ndir = {store}\n\n[scripts.wrapper.batten-cover]\ncommand = [{recorder}, \"{arg}\"]\n\n\
         [profile.batten-cover]\nfail-fast = false\nretries = 0\n\n\
         [profile.batten-cover.junit]\npath = \"{JUNIT}\"\n\n\
         [[profile.batten-cover.scripts]]\nfilter = \"all()\"\nrun-wrapper = \"batten-cover\"\n"
    );
    Ok(config)
}

/// The report the cover profile writes, under `<target>/nextest/batten-cover/`.
/// nextest writes it only when the run finishes.
pub(crate) const JUNIT: &str = "cover.xml";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_test_program_names_its_binary_from_its_package() {
        let dir = crate::scratch::scratch("cover-binary-id");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"batten-fsio\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        assert_eq!(
            binary_id("/t/mutants/deps/batten_fsio-0425a3337a593f5d", &dir),
            "batten-fsio",
            "the package's own crate is its library's unit cases"
        );
        assert_eq!(
            binary_id("/t/mutants/deps/it-0425a3337a593f5d", &dir),
            "batten-fsio::it",
            "any other target is the package's integration test"
        );
        let bare = crate::scratch::scratch("cover-binary-id-none");
        assert_eq!(binary_id("/t/deps/it-0425", &bare), "", "no package, no id");
    }

    #[test]
    fn the_wrapped_test_is_named_by_its_exact_argument() {
        let args: Vec<String> = ["/t/deps/it-1", "--exact", "engine_pin::init", "--nocapture"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(test_name(&args), Some("engine_pin::init"));
    }

    /// Each binary id names its own target; nothing covering still builds the
    /// library; a binary's own source adds `--bins`.
    ///
    /// Fails by: an id read as the wrong target kind, the empty case building
    /// nothing, or a binary source left unbuilt.
    #[test]
    fn each_binary_names_the_target_that_builds_it() {
        let set = |ids: &[&'static str]| ids.iter().copied().collect::<BTreeSet<&str>>();
        let lib = "crates/batten/src/lib.rs";
        assert_eq!(target_args(&set(&["batten"]), lib), ["--lib"]);
        assert_eq!(target_args(&set(&["batten::it"]), lib), ["--test", "it"]);
        assert_eq!(
            target_args(&set(&["batten::bin/batten"]), lib),
            ["--bin", "batten"]
        );
        assert_eq!(
            target_args(&set(&["batten::example/window-census"]), lib),
            ["--example", "window-census"]
        );
        assert_eq!(
            target_args(&set(&["batten::bench/b"]), lib),
            ["--bench", "b"]
        );
        assert_eq!(
            target_args(&set(&["batten", "batten::it", "batten-fsio"]), lib),
            ["--lib", "--test", "it"],
            "two libraries are one `--lib`"
        );
        assert_eq!(target_args(&set(&[]), lib), ["--lib"]);
        assert_eq!(
            target_args(&set(&["batten::it"]), "crates/batten/src/main.rs"),
            ["--bins", "--test", "it"]
        );
    }

    /// The snapshot holds the tree's Rust sources, tracked or not, and no
    /// other file; a later edit to the checkout leaves it alone, so the
    /// mutated line is found against what the sweep started from.
    ///
    /// Fails by: an untracked source left out, a non-source copied, the
    /// comparison reading the live checkout, or a source edit since the
    /// listing leaving the digest the sweep checks unmoved.
    #[test]
    fn a_snapshot_is_the_sources_as_the_sweep_found_them() {
        let dir = crate::scratch::scratch("cover-pristine");
        let repo = dir.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(repo.join("notes.txt"), "n\n").unwrap();
        crate::gitwrite::commit_paths(
            &repo,
            &[String::from("src/a.rs"), String::from("notes.txt")],
            "fixture",
        )
        .unwrap();
        std::fs::write(repo.join("src/new.rs"), "fn n() {}\n").unwrap();
        let dest = dir.join("pristine");
        let listed_over = source_digest(&repo).unwrap();
        assert_eq!(
            pristine(&repo, &dest).unwrap(),
            listed_over,
            "the snapshot's digest is the checkout's when nothing moved"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("src/a.rs")).unwrap(),
            "fn a() {}\n"
        );
        assert!(dest.join("src/new.rs").is_file(), "an untracked source");
        assert!(!dest.join("notes.txt").exists(), "a non-source");
        std::fs::write(repo.join("src/a.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("src/a.rs")).unwrap(),
            "fn a() {}\n",
            "the snapshot does not follow the checkout"
        );
        assert_ne!(
            source_digest(&repo).unwrap(),
            listed_over,
            "an edit since the listing moves the digest the sweep checks"
        );
        std::fs::write(repo.join("notes.txt"), "moved\n").unwrap();
        std::fs::write(repo.join("src/a.rs"), "fn a() {}\n").unwrap();
        assert_eq!(
            source_digest(&repo).unwrap(),
            listed_over,
            "a non-source edit does not"
        );
    }

    #[test]
    fn a_filterset_names_each_case_exactly_and_none_names_nothing() {
        assert_eq!(filterset(&BTreeSet::new()), "none()");
        assert_eq!(
            filterset(&["a::b", "c"].into_iter().collect()),
            "test(=a::b) | test(=c)"
        );
    }

    /// The wrapper config keeps the checkout's own nextest config, adds
    /// `wrapper-scripts` once, and wraps every case of its profile.
    ///
    /// Fails by: the checkout's config dropped, `wrapper-scripts` missing or
    /// doubled, or the store, wrapper or profile left out.
    #[test]
    fn the_wrapped_config_keeps_the_checkouts_and_wraps_every_case() {
        let root = crate::scratch::scratch("cover-wrapped-config");
        let recorder = Path::new("/bin/recorder");
        let store = Path::new("/state/nextest");
        let bare = wrapped_config(&root, recorder, "__rec", store).unwrap();
        assert!(
            bare.contains("experimental = [\"wrapper-scripts\"]"),
            "{bare}"
        );
        std::fs::create_dir_all(root.join(".config")).unwrap();
        std::fs::write(
            root.join(".config/nextest.toml"),
            "experimental = [\"setup-scripts\"]\n[profile.default]\nretries = 1\n",
        )
        .unwrap();
        let config = wrapped_config(&root, recorder, "__rec", store).unwrap();
        assert!(
            config.contains("experimental = [\"setup-scripts\", \"wrapper-scripts\"]"),
            "{config}"
        );
        assert!(
            config.contains("[profile.default]\nretries = 1"),
            "{config}"
        );
        assert!(
            config.contains("[store]\ndir = \"/state/nextest\""),
            "{config}"
        );
        assert!(
            config.contains("command = [\"/bin/recorder\", \"__rec\"]"),
            "{config}"
        );
        assert!(
            config.contains("run-wrapper = \"batten-cover\""),
            "{config}"
        );
        std::fs::write(
            root.join(".config/nextest.toml"),
            "experimental = [\"wrapper-scripts\"]\n",
        )
        .unwrap();
        let once = wrapped_config(&root, recorder, "__rec", store).unwrap();
        assert_eq!(once.matches("wrapper-scripts").count(), 1, "{once}");
    }
}
