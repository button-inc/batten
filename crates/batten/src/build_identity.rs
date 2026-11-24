//! The build's own identity (CLOUD-2903): what `batten --version` and
//! `engine::release` report, decided once at compile time.
//!
//! # Why a build is not its release
//!
//! Every build used to take its identity from the workspace version, which
//! release-plz moves only at a cut. So a branch hundreds of commits past
//! `v0.0.220` reported `batten 0.0.220`, byte-identical to the published
//! release, and a release pin counted as met by an engine that was not the
//! release. A build that is not the release must not carry its identity.
//!
//! # The identity (owner ruling, 2026-11-24)
//!
//! An unmarked build reports `<major>.<minor>.<patch+1>-dev.<line>.<ts>+<digest>`:
//!
//! - `<line>` is `pr<N>` for a pull request's build, `main` on `main`, the
//!   branch's [`slug`] elsewhere, `detached` with neither;
//! - `<ts>` is HEAD's committer second in UTC as `YYYYMMDDhhmmss`
//!   ([`compact_utc`]), so one commit gives one version on every machine;
//! - `<digest>` is the first [`DIGEST_HEX`] hex of the source digest `engine
//!   stamp` computes ([`source_digest`]), in semver BUILD METADATA, so it names
//!   the tree and never orders it (semver 2.0.0 §10).
//!
//! Every such identity is a semver pre-release, so it ranks below the next
//! release and above the one it follows (§11.3). Only the release build,
//! marked by [`RELEASE_MARKER`], reports the package version exactly.
//!
//! # Why this file lives outside `src/`
//!
//! `build.rs` includes it by `#[path]`, as it includes
//! `src/mutation_markers.rs`, so it is std plus `sha2` and names nothing in the
//! crate: a LEAF by construction. The library declares it too, so its cases run
//! in the library's test target and an integration case can render an identity
//! from facts it gathers itself. Nothing in the library CALLS it:
//! `engine::digest` keeps its own fold, and a parity case holds the two to one
//! answer, so it adds no edge to any module closure.
//!
//! Pure functions only: every fact arrives as an argument.

use std::collections::BTreeMap;

/// The variable the release build sets to its tag (`.github/workflows/dist.yml`).
pub const RELEASE_MARKER: &str = "BATTEN_RELEASE_TAG";

/// The variable a builder that knows its pull request sets to its number.
pub const BUILD_PR: &str = "BATTEN_BUILD_PR";

/// How many hex digits of the source digest the identity carries.
pub const DIGEST_HEX: usize = 12;

/// Which line of development a build is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A pull request's build, by number.
    Pr(u64),
    /// `main`, between a merge and the next cut.
    Main,
    /// Any other branch, by [`slug`].
    Branch(String),
    /// A checkout naming no branch and no pull request.
    Detached,
}

impl Line {
    /// The pre-release identifier this line renders as.
    #[must_use]
    pub fn identifier(&self) -> String {
        match self {
            Self::Pr(number) => format!("pr{number}"),
            Self::Main => String::from("main"),
            Self::Branch(slug) => slug.clone(),
            Self::Detached => String::from("detached"),
        }
    }
}

/// Everything an identity is rendered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The package version, `CARGO_PKG_VERSION`.
    pub package: String,
    /// The release marker, when one is set.
    pub marker: Option<String>,
    /// The line, or `None` when git answered nothing.
    pub line: Option<Line>,
    /// HEAD's committer time in seconds since the epoch, or `None` when git
    /// answered nothing.
    pub committed: Option<u64>,
    /// The source digest's first [`DIGEST_HEX`] hex digits, or `None` when a
    /// tracked input would not read.
    pub digest: Option<String>,
}

/// The identity `facts` render: exactly what `batten --version` prints after
/// `batten `.
///
/// # Errors
///
/// A marker that is not `v{package}`, naming both, or a package version that
/// is not `<major>.<minor>.<patch>`.
pub fn identity(facts: &Facts) -> Result<String, String> {
    if let Some(marker) = facts.marker.as_deref().filter(|marker| !marker.is_empty()) {
        let release = format!("v{}", facts.package);
        if marker != release {
            return Err(format!(
                "{RELEASE_MARKER}={marker} does not name this package's release {release}"
            ));
        }
        return Ok(facts.package.clone());
    }
    let next = next_patch(&facts.package)?;
    let (Some(line), Some(committed)) = (&facts.line, facts.committed) else {
        return Ok(format!("{next}-dev.unknown"));
    };
    let mut rendered = format!(
        "{next}-dev.{}.{}",
        line.identifier(),
        compact_utc(committed)
    );
    if let Some(digest) = &facts.digest {
        rendered.push('+');
        rendered.push_str(digest);
    }
    Ok(rendered)
}

/// `<major>.<minor>.<patch + 1>` of a package version, its own pre-release or
/// build metadata dropped.
fn next_patch(package: &str) -> Result<String, String> {
    let refused = || format!("the package version {package} is not <major>.<minor>.<patch>");
    let core = package.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<u64> = core
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| refused())?;
    let [major, minor, patch] = parts[..] else {
        return Err(refused());
    };
    let patch = patch.checked_add(1).ok_or_else(refused)?;
    Ok(format!("{major}.{minor}.{patch}"))
}

/// The line a build is on: the builder's pull request, then the ref's, then
/// HEAD's branch, then the ref's branch, then [`Line::Detached`].
///
/// `build_pr` is [`BUILD_PR`], `github_ref` is `GITHUB_REF` (Actions sets it on
/// every run, `refs/pull/<N>/merge` on a pull request's), and `branch` is
/// HEAD's short branch name. No build asks the network for a pull request.
///
/// # Errors
///
/// A [`BUILD_PR`] that is not a positive integer without a leading zero,
/// naming the variable.
pub fn line(
    build_pr: Option<&str>,
    github_ref: Option<&str>,
    branch: Option<&str>,
) -> Result<Line, String> {
    if let Some(named) = build_pr.filter(|named| !named.is_empty()) {
        return pr_number(named)
            .map(Line::Pr)
            .ok_or_else(|| format!("{BUILD_PR}={named} is not a pull request number"));
    }
    let github_ref = github_ref.unwrap_or_default();
    if let Some(number) = github_ref
        .strip_prefix("refs/pull/")
        .and_then(|rest| {
            rest.strip_suffix("/merge")
                .or_else(|| rest.strip_suffix("/head"))
        })
        .and_then(pr_number)
    {
        return Ok(Line::Pr(number));
    }
    let branch = branch
        .filter(|branch| !branch.is_empty())
        .or_else(|| github_ref.strip_prefix("refs/heads/"));
    Ok(match branch {
        Some("main") => Line::Main,
        Some(branch) => Line::Branch(slug(branch)),
        None => Line::Detached,
    })
}

/// A positive integer with no leading zero, or `None`.
fn pr_number(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits || text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

/// A branch name as one semver identifier: ASCII lowercase, each run of bytes
/// outside `[0-9a-z]` one `-`, leading and trailing `-` trimmed.
///
/// A slug that would read as something else gets a `b-` prefix: empty, all
/// digits (a numeric identifier, where a leading zero is invalid semver),
/// `main`, or `pr<digits>`. So a branch never reads as a pull request or as
/// `main`.
#[must_use]
pub fn slug(branch: &str) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for byte in branch.bytes().map(|byte| byte.to_ascii_lowercase()) {
        if byte.is_ascii_digit() || byte.is_ascii_lowercase() {
            if gap && !slug.is_empty() {
                slug.push('-');
            }
            gap = false;
            slug.push(char::from(byte));
        } else {
            gap = true;
        }
    }
    let numeric = slug.bytes().all(|byte| byte.is_ascii_digit());
    let pr = slug
        .strip_prefix("pr")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()));
    if numeric || pr || slug == "main" {
        slug.insert_str(0, "b-");
    }
    slug
}

/// `seconds` since the epoch as `YYYYMMDDhhmmss` in UTC.
///
/// Its own civil-date arithmetic rather than `batten_base::clock::civil`: a
/// mutation sweep of `batten-base` renders its probe into that file, which this
/// build script cannot call. A parity case holds the two to one answer.
#[must_use]
pub fn compact_utc(seconds: u64) -> String {
    let days = seconds / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let second_of_day = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    )
}

/// Whether a tracked path is an engine input: a COPY of `engine::is_input`.
#[must_use]
pub fn is_input(path: &str) -> bool {
    path.starts_with("crates/") || path == "Cargo.toml" || path == "Cargo.lock"
}

/// The source digest over `inputs` (tracked path → bytes): a COPY of
/// `engine::digest`'s fold, SHA-256 over every engine input as path, NUL,
/// bytes, NUL, in sorted order. A path that is not an engine input is ignored.
///
/// **No inputs is no digest**, never SHA-256's empty value, which names no
/// source (CLOUD-2230).
#[must_use]
pub fn source_digest(inputs: &BTreeMap<String, Vec<u8>>) -> Option<String> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut count = 0_usize;
    for (path, bytes) in inputs.iter().filter(|(path, _)| is_input(path)) {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0]);
        count += 1;
    }
    (count > 0).then(|| {
        use std::fmt::Write as _;
        hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use std::cmp::Ordering;

    const SECOND: u64 = 1_795_499_088;
    const DIGEST: &str = "3f9c2a1b7d04";

    fn facts(line: Option<Line>) -> Facts {
        Facts {
            package: String::from("0.0.220"),
            marker: None,
            line,
            committed: Some(SECOND),
            digest: Some(String::from(DIGEST)),
        }
    }

    fn rendered(line: Option<Line>) -> String {
        identity(&facts(line)).expect("renders")
    }

    fn version(text: &str) -> semver::Version {
        semver::Version::parse(text).expect("a semver version")
    }

    #[test]
    fn a_pull_request_build_renders_the_next_patch_as_a_dev_prerelease() {
        assert_eq!(
            rendered(Some(Line::Pr(1282))),
            "0.0.221-dev.pr1282.20261124054448+3f9c2a1b7d04"
        );
    }

    #[test]
    fn a_main_build_and_a_branch_build_render_their_line() {
        assert_eq!(
            rendered(Some(Line::Main)),
            "0.0.221-dev.main.20261124054448+3f9c2a1b7d04"
        );
        assert_eq!(
            rendered(Some(Line::Branch(slug("claude/1276-next")))),
            "0.0.221-dev.claude-1276-next.20261124054448+3f9c2a1b7d04"
        );
        assert_eq!(
            rendered(Some(Line::Detached)),
            "0.0.221-dev.detached.20261124054448+3f9c2a1b7d04"
        );
        assert_eq!(rendered(None), "0.0.221-dev.unknown");
        let no_time = Facts {
            committed: None,
            ..facts(Some(Line::Main))
        };
        assert_eq!(identity(&no_time).as_deref(), Ok("0.0.221-dev.unknown"));
    }

    #[test]
    fn the_release_marker_keeps_the_package_version_exactly() {
        let marked = Facts {
            marker: Some(String::from("v0.0.220")),
            ..facts(Some(Line::Pr(1282)))
        };
        assert_eq!(identity(&marked).as_deref(), Ok("0.0.220"));
        let blind = Facts {
            line: None,
            committed: None,
            digest: None,
            ..marked.clone()
        };
        assert_eq!(identity(&blind).as_deref(), Ok("0.0.220"));
        let wrong = Facts {
            marker: Some(String::from("v0.0.219")),
            ..marked
        };
        let refused = identity(&wrong).expect_err("a marker naming another release");
        assert!(
            refused.contains("v0.0.219") && refused.contains("v0.0.220"),
            "{refused}"
        );
        let empty = Facts {
            marker: Some(String::new()),
            ..facts(Some(Line::Pr(1282)))
        };
        assert_eq!(
            identity(&empty).as_deref(),
            Ok("0.0.221-dev.pr1282.20261124054448+3f9c2a1b7d04")
        );
    }

    #[test]
    fn a_package_version_that_is_not_three_numbers_is_refused() {
        for package in ["0.0", "0.0.x", "1.2.3.4"] {
            let bad = Facts {
                package: String::from(package),
                ..facts(Some(Line::Main))
            };
            assert!(identity(&bad).is_err(), "{package}");
        }
        let pre = Facts {
            package: String::from("1.2.3-rc.1"),
            ..facts(Some(Line::Main))
        };
        assert_eq!(
            identity(&pre).as_deref(),
            Ok("1.2.4-dev.main.20261124054448+3f9c2a1b7d04")
        );
    }

    #[test]
    fn the_line_reads_the_builder_then_the_ref_then_the_branch() {
        assert_eq!(
            line(Some("1282"), Some("refs/pull/9/merge"), Some("x")),
            Ok(Line::Pr(1282))
        );
        assert_eq!(
            line(None, Some("refs/pull/1282/merge"), None),
            Ok(Line::Pr(1282))
        );
        assert_eq!(
            line(Some(""), Some("refs/pull/1282/head"), Some("x")),
            Ok(Line::Pr(1282))
        );
        assert_eq!(line(None, Some("refs/heads/main"), None), Ok(Line::Main));
        assert_eq!(
            line(None, Some("refs/heads/main"), Some("feature")),
            Ok(Line::Branch(String::from("feature")))
        );
        assert_eq!(
            line(None, Some("refs/pull/0123/merge"), Some("main")),
            Ok(Line::Main)
        );
        assert_eq!(line(None, None, None), Ok(Line::Detached));
        assert_eq!(line(None, Some("refs/tags/v1"), None), Ok(Line::Detached));
        for bad in ["0123", "x", "0", "-1"] {
            let refused = line(Some(bad), None, None).expect_err(bad);
            assert!(refused.contains(BUILD_PR), "{refused}");
        }
    }

    #[test]
    fn a_branch_slug_never_reads_as_a_pull_request_or_main() {
        assert_eq!(slug("PR1282"), "b-pr1282");
        assert_eq!(slug("Main"), "b-main");
        assert_eq!(slug("1276"), "b-1276");
        assert_eq!(slug("feat//Ü_x"), "feat-x");
        assert_eq!(slug("claude/1276-next"), "claude-1276-next");
        assert_eq!(slug("--x--"), "x");
        assert_eq!(slug("pr"), "pr");
        assert_eq!(slug("ÜÜ"), "b-");
    }

    #[test]
    fn the_timestamp_is_the_committers_second_in_utc() {
        assert_eq!(compact_utc(SECOND), "20261124054448");
        for seconds in [0, 951_782_400, SECOND, 4_102_444_799] {
            let separated: String = crate::clock::rfc3339_utc(seconds)
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            assert_eq!(compact_utc(seconds), separated, "{seconds}");
        }
    }

    #[test]
    fn every_dev_identity_orders_between_its_release_and_the_next() {
        let below = version("0.0.220");
        let above = version("0.0.221");
        for line in [
            Some(Line::Pr(1282)),
            Some(Line::Main),
            Some(Line::Branch(slug("claude/1276-next"))),
            Some(Line::Branch(slug("1276"))),
            Some(Line::Detached),
            None,
        ] {
            let text = rendered(line);
            let dev = version(&text);
            assert_eq!(below.cmp_precedence(&dev), Ordering::Less, "{text}");
            assert_eq!(dev.cmp_precedence(&above), Ordering::Less, "{text}");
        }
        let marked = Facts {
            marker: Some(String::from("v0.0.220")),
            ..facts(Some(Line::Main))
        };
        assert_eq!(version(&identity(&marked).expect("renders")), below);
        // THE REJECTED FORM: build metadata alone ranks EQUAL to the release.
        assert_eq!(
            version("0.0.220+dev.3f9c2a1b7d04").cmp_precedence(&below),
            Ordering::Equal
        );
    }

    #[test]
    fn builds_on_one_pull_request_order_by_commit_time() {
        let early = version(&rendered(Some(Line::Pr(1282))));
        let late = version(
            &identity(&Facts {
                committed: Some(SECOND + 1),
                ..facts(Some(Line::Pr(1282)))
            })
            .expect("renders"),
        );
        assert_eq!(early.cmp_precedence(&late), Ordering::Less);
    }

    #[test]
    fn builds_on_two_pull_requests_never_share_precedence() {
        let ours = version(&rendered(Some(Line::Pr(1282))));
        for other in [
            Some(Line::Pr(1283)),
            Some(Line::Main),
            Some(Line::Branch(slug("claude/1276-next"))),
        ] {
            let theirs = version(&rendered(other));
            assert_ne!(ours.cmp_precedence(&theirs), Ordering::Equal, "{theirs}");
        }
    }

    #[test]
    fn the_digest_names_the_tree_and_never_orders_it() {
        let one = rendered(Some(Line::Pr(1282)));
        let two = identity(&Facts {
            digest: Some(String::from("000000000000")),
            ..facts(Some(Line::Pr(1282)))
        })
        .expect("renders");
        assert_ne!(one, two);
        assert_eq!(
            version(&one).cmp_precedence(&version(&two)),
            Ordering::Equal
        );
    }

    #[test]
    fn a_source_digest_is_engine_stamps_fold() {
        let mut inputs = BTreeMap::new();
        inputs.insert(String::from("crates/x.rs"), b"b".to_vec());
        inputs.insert(String::from("Cargo.toml"), b"a".to_vec());
        let want = "b3816bf3c55b58e188b61f27988e3dd01ed07757aa5416a407997d9fd2c1ed67";
        assert_eq!(source_digest(&inputs).as_deref(), Some(want));
        inputs.insert(String::from("README.md"), b"c".to_vec());
        assert_eq!(source_digest(&inputs).as_deref(), Some(want));
        assert_eq!(source_digest(&BTreeMap::new()), None);
        let outside: BTreeMap<String, Vec<u8>> =
            [(String::from("README.md"), b"c".to_vec())].into();
        assert_eq!(source_digest(&outside), None);
    }

    #[test]
    fn an_input_that_will_not_read_drops_only_the_metadata() {
        let unread = Facts {
            digest: None,
            ..facts(Some(Line::Pr(1282)))
        };
        assert_eq!(
            identity(&unread).as_deref(),
            Ok("0.0.221-dev.pr1282.20261124054448")
        );
    }
}
