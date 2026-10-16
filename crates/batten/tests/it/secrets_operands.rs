//! The secrets scanner's argv is operand-terminated (CLOUD-1496).
//!
//! **The subject is the boundary between flags and operands, not detection.**
//! `secrets::run_once` hands the scanner a batch of TRACKED PATHS, and the tree
//! those paths come from is the untrusted input this gate exists to judge. A
//! repository may contain a file whose name begins with `-`; without a `--`
//! between the scanner's own flags and the batch, the scanner reads that path as
//! an option.
//!
//! # Both halves of the hazard, because they fail differently
//!
//! A path naming an option the scanner does NOT know is the loud half: clap
//! bails with exit 2, which is neither the scanner's clean (0) nor its found (1)
//! status, so CLOUD-59's fail-closed clause turns the whole batch into exit 3.
//! Nothing is scanned and the run says so.
//!
//! A path naming an option the scanner DOES know is the quiet half, and it is
//! the dangerous one: the flag is consumed, the file is never scanned, the exit
//! stays clean, and Batten reports a green tree over a file holding a secret.
//! Nothing in the output says a batch member went unread.
//!
//! One `--` closes both, so one fix serves two cases — but only two cases show
//! it, because a single-case suite would pin whichever half it happened to pick
//! and leave the other free to regress.
//!
//! # The stub, and the measurement that licenses its shape
//!
//! The existing secrets suite's stub ignores its argv entirely
//! (`secrets_kind.rs`), so it cannot discriminate this fix at all: it emits the
//! same lines whether or not a terminator was passed. The stub here is the
//! smallest thing that CAN, and its flag set is the pinned ripsecrets 0.1.11's
//! own, read off `--help` rather than assumed:
//!
//! | argv                                            | result                                     |
//! | ----------------------------------------------- | ------------------------------------------ |
//! | `--only-matching -- --strict-ignore plain.conf` | a finding per operand; bare names accepted |
//! | `--only-matching --strict-ignore plain.conf`    | `--strict-ignore` eaten as a flag, exit 1  |
//! | `--only-matching --no-ignore`                   | `error: unexpected argument`, exit 2       |
//!
//! `--strict-ignore` is a real 0.1.11 flag and `--no-ignore` is not one — that
//! is a `ripgrep` flag, and an earlier draft of this suite named it as the known
//! one. The distinction is the whole point: which half a given filename triggers
//! depends on the pin's actual flag table, so the stub carries that table
//! (`--only-matching`, `--strict-ignore`) and treats everything else `-`-leading
//! as unknown.
//!
//! Asserting this against the real binary would mean provisioning it in CI; the
//! measurement above is what lets a stub stand in for it.
//!
//! The non-UTF-8 spawn arm gets the same `--` and is covered by review rather
//! than by a case — it is unreachable in practice, as its own comment in
//! `secrets.rs` records.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, StateHome, batten, scratch, stderr, stdout, write};

/// A tracked path naming an option the pin does NOT know.
///
/// `--no-ignore` is a `ripgrep` flag, absent from ripsecrets 0.1.11's table, so
/// it reaches clap's unknown-argument arm — the loud, fail-closed half.
const UNKNOWN_FLAG_PATH: &str = "--no-ignore";

/// A tracked path naming an option the pin DOES know.
///
/// `--strict-ignore` is in 0.1.11's own `--help`, so an unterminated argv
/// consumes it as a flag and the file is never read — the quiet half.
const KNOWN_FLAG_PATH: &str = "--strict-ignore";

/// A repository, an isolated state home, and somewhere to put the stub.
///
/// A third near-copy of the shape `secrets_kind.rs` and `enforce_journal.rs` both
/// carry, and the duplication is real rather than justified: `install_scanner`
/// takes its script as a parameter in all three, so only the glob and this
/// suite's `STUB` actually differ. Collapsing them into one `common::` helper is
/// left undone deliberately: `tests/it/common/mod.rs` is a `MUTANT_GATES` file
/// this row does not own, and the shape it would take is recorded on CLOUD-1496
/// rather than spun onto a row of its own, which `issue file same` refuses.
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
        write(&self.repo, path, contents);
    }

    /// Write the argv-reading stub, provision it, and write the config using it.
    ///
    /// The digest is taken from `STUB` directly rather than by reading the file
    /// back: it is a compile-time constant, so the read would re-open a file to
    /// learn bytes already in hand.
    fn install_scanner(&self) {
        let path = self.artifacts.join("ripsecrets");
        fs::write(&path, STUB).unwrap();
        self.config(
            &format!("file://{}", path.display()),
            &digest(STUB.as_bytes()),
        );
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
        // The glob is `**/-*` so the rule selects exactly the hostile path and
        // neither `README.md` nor `batten.toml`: a wider glob would put the
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
/// The known-flag list is ripsecrets 0.1.11's, not an invention: `--only-matching`
/// is what this build passes and `--strict-ignore` is the one a fixture is named
/// after. Before the terminator a known flag is consumed and any other
/// `-`-leading word is an unknown option, refused on stderr with the pinned
/// tool's own exit 2 — neither its clean (0) nor its found (1) status. After the
/// terminator every word is a path, reported as a match.
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
      --) terminated=1; continue ;;
      --only-matching|--strict-ignore) continue ;;
      -*)
        printf "error: unexpected argument '%s' found\n" "$arg" >&2
        exit 2
        ;;
    esac
  fi
  printf '%s\n' "$arg:1:redacted"
  found=1
done
exit "$found"
"#;

/// The planted file's contents. Not a credential shape, deliberately — the stub
/// decides what it reports, and a literal one here would trip this repository's
/// own secrets rule over this file.
const PLANTED: &str = "api_key = \"placeholder\"\n";

/// One pointer line, in the shape `enforce` renders a deny finding.
fn deny_line(path: &str) -> String {
    format!("batten deny source carry unsafe at {path}:1\n")
}

/// Plant a secret at `path`, install the argv-reading stub, and run `enforce`.
///
/// The fixture is NOT committed, and that is not an oversight: the secrets batch
/// is the `ignore` tree walk filtered by the rule's glob (`rules::tree_files`),
/// never the git index, so staging it would fork two git processes to change
/// nothing the gate reads. `secrets_kind.rs` already relies on this — its
/// `app.conf` is written after its only commit and is still reported.
fn enforce_over(name: &str, path: &str) -> Output {
    let env = Env::new(name);
    env.file(path, PLANTED);
    env.install_scanner();
    env.run(&["enforce"])
}

/// The LOUD half: a path naming an option the pin does not know.
///
/// Before the fix the stub refuses the operand with exit 2, which `cross_check`
/// reads as neither clean nor found, and the run is exit 3 — an internal error
/// rather than a verdict, with the whole batch unscanned. So asserting the policy
/// verdict here fails on the unfixed tree rather than passing vacuously, which is
/// what the declared `drop-the-operand-terminator` mutant turns into a gate.
#[test]
fn a_dash_leading_tracked_path_is_scanned_as_a_path() {
    let out = enforce_over("secrets-operands-unknown", UNKNOWN_FLAG_PATH);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a tracked path named like an unknown flag is still scanned as a path: {}",
        stderr(&out)
    );
    assert_eq!(
        stdout(&out),
        deny_line(UNKNOWN_FLAG_PATH),
        "the pointer line, and nothing else"
    );

    // Pointer-only, and stderr is the half the equality above does not already
    // pin: the span the stub emitted is content, and no surface may carry it.
    assert!(
        !stderr(&out).contains("redacted"),
        "the matched span reached stderr"
    );
}

/// The QUIET half, and the reason this suite has two cases.
///
/// `--strict-ignore` is a flag the pin KNOWS, so before the fix the unterminated
/// argv consumes it, the scanner is left with no operands, and it exits clean
/// with nothing to say. `cross_check` is satisfied — clean status, zero parsed —
/// so Batten reports **exit 0 over a file carrying a planted secret**. No finding,
/// no error, no trace that a batch member was never read.
///
/// That is the failure the exit-code assertion in the case above would not catch
/// on its own, and it is the one that matters most: a secrets gate whose silence
/// is indistinguishable from a clean tree.
#[test]
fn a_tracked_path_named_like_a_known_flag_is_not_silently_skipped() {
    let out = enforce_over("secrets-operands-known", KNOWN_FLAG_PATH);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a tracked path named like a KNOWN flag is read as a path, not eaten as one: {}",
        stderr(&out)
    );
    assert_eq!(
        stdout(&out),
        deny_line(KNOWN_FLAG_PATH),
        "the planted secret is reported rather than silently skipped"
    );
}
