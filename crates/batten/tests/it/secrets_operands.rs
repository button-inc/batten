//! The secrets scanner's argv is operand-terminated (CLOUD-1496).
//!
//! **The subject is the boundary between flags and operands, not detection.**
//! `secrets::run_once` hands the scanner a batch of TRACKED PATHS, and the tree
//! those paths come from is the untrusted input this gate exists to judge. A
//! repository may contain a file named `-h` or `--no-ignore`; without a `--`
//! between the scanner's own flags and the batch, the scanner reads that path as
//! an option.
//!
//! Both directions of that failure are bad, which is why this is a case and not
//! a comment. An UNKNOWN option exits non-zero, and CLOUD-59's fail-closed clause
//! turns a status that is neither clean nor found into exit 3 — the whole batch
//! refused, every other gate in the run stalled behind it. A KNOWN option
//! (`--no-ignore`, `--hidden`, a path exclusion) is worse: it silently changes
//! what is scanned while the exit stays clean, so the tree reports green over
//! files nobody looked at.
//!
//! # Why the stub is shaped the way it is
//!
//! The existing secrets suite's stub ignores its argv entirely
//! (`secrets_kind.rs`), so it cannot discriminate this fix: it emits the same
//! lines whether or not a terminator was passed. The stub here is the smallest
//! thing that CAN discriminate, and its shape is licensed by a measurement
//! against the pinned ripsecrets 0.1.11 recorded on CLOUD-1496:
//!
//! | argv                                     | result                                    |
//! | ---------------------------------------- | ----------------------------------------- |
//! | `--only-matching -- --no-ignore -h`      | a finding per operand; bare names accepted |
//! | `--only-matching --no-ignore -h` (before)| `error: unexpected argument` , exit 2      |
//!
//! So: refuse a `-`-leading argument seen BEFORE the terminator, and treat
//! everything after it as a path. The real binary would have to be provisioned
//! in CI to assert this directly, and the measurement above is what lets a stub
//! stand in for it.
//!
//! The non-UTF-8 spawn arm gets the same `--` and is covered by review rather
//! than by a case — it is unreachable in practice, as its own comment in
//! `secrets.rs` records.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, StateHome, batten, git_in, scratch};

/// The two tracked paths whose names are scanner options.
///
/// `--no-ignore` is a REAL ripsecrets flag and `-h` is a real short one, so each
/// exercises a different half of the hazard: the first would be silently honoured
/// by a scanner that accepted it, the second would be too. Sorted as `git
/// ls-files` yields them, which is the order the batch reaches the scanner in.
const HOSTILE_PATHS: [&str; 2] = ["--no-ignore", "-h"];

/// A repository, an isolated state home, and somewhere to put the stub.
///
/// Deliberately a local copy of the shape `secrets_kind.rs` uses rather than a
/// shared helper: that suite's `Env` installs a stub that ignores its argv, and
/// merging the two would mean one fixture serving two opposite requirements.
struct Env {
    repo: PathBuf,
    home: PathBuf,
    artifacts: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .git()
            .build();
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        Env {
            repo,
            home: root.join("home"),
            artifacts,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        batten()
            .state_home(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .output()
            .expect("run batten")
    }

    fn file(&self, path: &str, contents: &str) {
        let full = self.repo.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, contents).unwrap();
    }

    /// Commit everything written so far.
    ///
    /// `-A` rather than a path list on purpose: the paths here begin with `-`,
    /// and the fixture must not depend on how git's own argv parser treats them.
    /// What is under test is Batten's spawn, not this helper's.
    fn commit(&self) {
        git_in(&self.repo, &["add", "-A"]);
        git_in(&self.repo, &["commit", "-q", "-m", "base"]);
    }

    /// Write the argv-reading stub, provision it, and write the config using it.
    fn install_scanner(&self) {
        let path = self.artifacts.join("ripsecrets");
        fs::write(&path, STUB).unwrap();
        let bytes = fs::read(&path).unwrap();
        self.config(&format!("file://{}", path.display()), &digest(&bytes));
        let applied = self.run(&["provision", "apply"]);
        assert!(
            applied.status.success(),
            "the stub scanner installs: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
    }

    fn config(&self, url: &str, sha: &str) {
        // A TOML *literal* string for the url, because it carries a filesystem
        // path — `secrets_kind.rs` records the Windows reading that forced it.
        //
        // The glob is `**/-*` so the rule selects exactly the two hostile paths
        // and neither `README.md` nor `batten.toml`: a wider glob would put the
        // config itself in the batch and the assertion would stop being about
        // operand handling.
        self.file(
            "batten.toml",
            &format!(
                "version = 1\n\n\
                 [[provision]]\n\
                 name = \"ripsecrets\"\n\
                 version = \"0.0.0-stub\"\n\
                 url = '{url}'\n\
                 sha256 = \"{sha}\"\n\
                 binary = \"ripsecrets\"\n\n\
                 [[rule]]\n\
                 id = \"source carry unsafe\"\n\
                 kind = \"secrets\"\n\
                 glob = \"**/-*\"\n\
                 severity = \"deny\"\n\
                 scope = \"tree\"\n"
            ),
        );
    }
}

/// A scanner that parses its argv the way the pinned binary does.
///
/// Before the terminator: `--only-matching` is the flag this build passes, and
/// any other `-`-leading word is an unknown option — refused on stderr with the
/// pinned tool's own exit 2, which is neither its clean (0) nor its found (1)
/// status. After the terminator every word is a path, reported as a match.
///
/// The span is a placeholder rather than a credential shape: this suite asserts
/// where the scanner was pointed, and a literal credential in a committed file
/// would trip consumer #1's own `source carry unsafe` rule over this very file.
const STUB: &str = r#"#!/bin/sh
terminated=0
found=0
for arg in "$@"; do
  if [ "$terminated" -eq 0 ]; then
    case "$arg" in
      --only-matching) continue ;;
      --) terminated=1; continue ;;
      -*)
        printf 'error: unexpected argument %s found\n' "$arg" >&2
        exit 2
        ;;
    esac
  fi
  printf '%s\n' "$arg:1:redacted"
  found=1
done
[ "$found" -eq 1 ] && exit 1
exit 0
"#;

#[test]
fn a_dash_leading_tracked_path_is_scanned_as_a_path() {
    let env = Env::new("secrets-operands");
    for path in HOSTILE_PATHS {
        env.file(path, "api_key = \"placeholder\"\n");
    }
    env.install_scanner();
    env.commit();

    let out = env.run(&["enforce"]);

    // Exit 2 is the POLICY VERDICT, and that is the whole discrimination. Without
    // the `--` the stub refuses the first hostile operand with exit 2 of its own,
    // `cross_check` reads a status that is neither clean nor found, and the run is
    // exit 3 — an internal error, not a verdict. Asserting 2 here therefore fails
    // on the unfixed tree rather than passing vacuously.
    assert_eq!(
        out.status.code(),
        Some(2),
        "a tracked path named like a flag is still scanned as a path: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Appended rather than `format!`-collected: `clippy::format_collect` refuses
    // the latter, and `writeln!` into a `String` is infallible, so the result is
    // discarded as `render.rs` does for the same reason.
    let mut expected = String::new();
    for path in HOSTILE_PATHS {
        let _ = writeln!(expected, "batten deny source carry unsafe at {path}:1");
    }
    assert_eq!(
        stdout, expected,
        "one pointer line per hostile path, and nothing else"
    );

    // Pointer-only, restated as an assertion rather than as a comment: the span
    // the stub emitted is content, and no surface may carry it.
    assert!(
        !stdout.contains("redacted"),
        "the matched span reached stdout"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("redacted"),
        "the matched span reached stderr"
    );
}
