//! The secrets scanner's argv is operand-terminated (CLOUD-1496).
//!
//! **The subject is the boundary between flags and operands, not detection.**
//! `secrets::run_once` hands the scanner a batch of paths the `ignore` walk
//! found (`rules::tree_files`, so untracked files too, not only tracked ones),
//! and the tree those paths come from is the untrusted input this gate exists to
//! judge. A repository may contain a file whose name begins with `-`; without a
//! `--` between the scanner's own flags and the batch, the scanner reads that
//! path as an option.
//!
//! # Both halves of the hazard, because they fail differently
//!
//! A path naming an option the scanner does NOT know is the loud half: clap
//! bails with exit 2, which is neither the scanner's clean (0) nor its found (1)
//! status, so CLOUD-59's fail-closed clause turns the whole batch into exit 3.
//! Nothing is scanned and the run says so.
//!
//! A path naming an option the scanner DOES know is the quiet half, and it is
//! the dangerous one: the flag is consumed, that file is never scanned, the rest
//! of the batch reports normally, and the exit is the ordinary found status. The
//! cross-check is satisfied, so nothing anywhere says a batch member went unread
//! — the finding set is simply one short.
//!
//! **That is why the quiet case asserts the finding SET and not the exit code.**
//! Both runs exit 2; only the pointer lines differ. An exit-code assertion alone
//! would pass over the regression it exists to catch.
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
//! | `--only-matching --strict-ignore plain.conf`    | `--strict-ignore` eaten; only `plain.conf` |
//! | `--only-matching --no-ignore …`                 | `error: unexpected argument`, exit 2       |
//!
//! `--strict-ignore` is a real 0.1.11 flag and `--no-ignore` is not one — that
//! is a `ripgrep` flag, and an earlier draft of this suite named it as the known
//! one. The distinction is the whole point: which half a given filename triggers
//! depends on the pin's actual flag table, so the stub carries that table
//! (`--only-matching`, `--strict-ignore`) and treats everything else `-`-leading
//! as unknown.
//!
//! **Every case leaves at least one surviving operand**, which is what keeps the
//! stub faithful without modelling the pin's `[Source files]... Defaults to '.'`
//! behaviour: with every operand eaten the real binary rescans the working
//! directory and emits `./`-prefixed lines `parse_line` cannot match to the
//! batch. No case here drives that shape, so the stub does not implement it —
//! an earlier draft did drive it, and claimed a silent exit 0 the pin never
//! produces.
//!
//! Asserting this against the real binary would mean provisioning it in CI; the
//! measurement above is what lets a stub stand in for it.
//!
//! **And here is what the stub CANNOT see, said plainly because a stub's blind
//! spots are the reason to distrust one.** It reports every post-terminator word
//! as a match, so it would pass a case for a file named exactly `-` — where the
//! pin instead applies the stdin convention, reads nothing, and leaves the file
//! unscanned even after `--`. No case here uses that name, because asserting it
//! against this stub would pin the stub's behaviour rather than the pin's. The
//! measurement and the remedy are on CLOUD-1492; `secrets.rs` carries the same
//! note beside the terminator.
//!
//! The non-UTF-8 spawn arm needs no case of its own: the terminator is the last
//! element of `secrets.rs`'s `SCANNER_FLAGS`, so both arms carry it by
//! construction and the declared mutant deletes it from both at once. That arm
//! is unreachable in practice anyway, as its own comment there records.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, StateHome, batten, scratch, stderr, stdout, write};

/// A path naming an option the pin does NOT know.
///
/// `--no-ignore` is a `ripgrep` flag, absent from ripsecrets 0.1.11's table, so
/// it reaches clap's unknown-argument arm — the loud, fail-closed half.
const UNKNOWN_FLAG_PATH: &str = "--no-ignore";

/// A path naming an option the pin DOES know.
///
/// `--strict-ignore` is in 0.1.11's own `--help`, so an unterminated argv
/// consumes it as a flag and that file is never read — the quiet half.
const KNOWN_FLAG_PATH: &str = "--strict-ignore";

/// The ordinary companion, and it is load-bearing rather than scenery.
///
/// It is the operand that SURVIVES an eaten flag, which is what makes the quiet
/// half observable: the run still reports it, still exits found, and the only
/// trace of the dropped path is a finding set one line short. Sorts after both
/// hostile names, so the expected output is hostile-then-plain.
const PLAIN_PATH: &str = "plain.conf";

/// A repository, an isolated state home, and somewhere to put the stub.
///
/// A FOURTH near-copy of the shape `secrets_kind.rs`, `enforce_journal.rs` and
/// `provision.rs` each carry, and the duplication is real rather than justified:
/// `install_scanner` takes its script as a parameter in the others, so only the
/// glob and this suite's `STUB` actually differ.
///
/// It is left undone for scope, and the honest reason is narrower than a `common::`
/// helper. These are `mod`s of one integration binary, so the cheap route is not
/// `tests/it/common/mod.rs` — a `MUTANT_GATES` file with `spawn-factory` allowlist
/// entries, which this row certainly does not own — but `crate::secrets_kind::Env`
/// made `pub(crate)` with its hardcoded `glob = "**/*.conf"` taken as a parameter.
/// That is a smaller edit than this copy, and it is still a file CLOUD-1496 does
/// not own, so collapsing it here would widen the PR into a sibling's test module.
/// Filed as its own row.
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
            stderr(&applied)
        );
    }

    fn config(&self, url: &str, sha: &str) {
        // A TOML *literal* string for the url, because it carries a filesystem
        // path — `secrets_kind.rs` records the Windows reading that forced it.
        //
        // The glob alternates so the rule selects exactly the hostile path and
        // its plain companion, and neither `README.md` nor `batten.toml`: a
        // wider glob would put the config itself in the batch and the assertion
        // would stop being about operand handling, while a bare `**/-*` would
        // exclude the companion the quiet half needs.
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
                 glob = \"**/{{-*,{PLAIN_PATH}}}\"\n\
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
/// The trailing status is the literal found (1) rather than a count of what was
/// reported, because the module doc's "every case leaves at least one surviving
/// operand" makes a count a variable with one reachable value. A counted exit
/// would also read as if the pin's clean (0) path were modelled here, which is
/// exactly what that paragraph says this stub declines to model.
///
/// The span is a placeholder rather than a credential shape: this suite asserts
/// where the scanner was pointed, and a literal credential in a committed file
/// would trip consumer #1's own `source carry unsafe` rule over this very file.
const STUB: &str = r#"#!/bin/sh
terminated=0
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
done
exit 1
"#;

/// The planted file's contents. Not a credential shape, deliberately — the stub
/// decides what it reports, and a literal one here would trip this repository's
/// own secrets rule over this file.
const PLANTED: &str = "api_key = \"placeholder\"\n";

/// One pointer line, in the shape `enforce` renders a deny finding.
fn deny_line(path: &str) -> String {
    format!("batten deny source carry unsafe at {path}:1\n")
}

/// Plant a secret at `hostile` and at the plain companion, install the
/// argv-reading stub, and run `enforce`.
///
/// The fixture is NOT committed, and that is not an oversight: the secrets batch
/// is the `ignore` walk filtered by the rule's glob (`rules::tree_files`), never
/// the git index, so staging it would fork two git processes to change nothing
/// the gate reads. `secrets_kind.rs` already relies on this — its `app.conf` is
/// written after its only commit and is still reported.
fn enforce_over(name: &str, hostile: &str) -> Output {
    let env = Env::new(name);
    env.file(hostile, PLANTED);
    env.file(PLAIN_PATH, PLANTED);
    env.install_scanner();
    env.run(&["enforce"])
}

/// The LOUD half: a path naming an option the pin does not know.
///
/// The name says "tracked" because CLOUD-1496's §7 fixed it and the `//MUTANT`
/// row in `secrets.rs` cites it; the batch is in fact the `ignore` walk, so
/// untracked files are in scope too, and the module doc says so. Its sibling
/// below was free to be named accurately.
///
/// Before the fix the stub refuses that operand with exit 2, which `cross_check`
/// reads as neither clean nor found, so the run is exit 3 — an internal error
/// rather than a verdict, with the whole batch unscanned, the companion
/// included. Asserting the policy verdict here therefore fails on the unfixed
/// tree rather than passing vacuously, which is what the declared
/// `drop-the-operand-terminator` mutant turns into a gate.
#[test]
fn a_dash_leading_tracked_path_is_scanned_as_a_path() {
    let out = enforce_over("secrets-operands-unknown", UNKNOWN_FLAG_PATH);

    assert_eq!(
        out.status.code(),
        Some(2),
        "a path named like an unknown flag is still scanned as a path: {}",
        stderr(&out)
    );
    assert_eq!(
        stdout(&out),
        deny_line(UNKNOWN_FLAG_PATH) + &deny_line(PLAIN_PATH),
        "one pointer line per planted file, and nothing else"
    );
}

/// The QUIET half, and the reason this suite has two cases.
///
/// `--strict-ignore` is a flag the pin KNOWS, so before the fix the unterminated
/// argv consumes it while `plain.conf` survives as an operand. The scanner
/// reports the companion, exits found, and `cross_check` is satisfied — so the
/// run is **exit 2 either way** and the only difference is that one planted
/// secret is missing from the finding set. Nothing is logged, nothing errors,
/// and a batch member was never read.
///
/// That is why this case asserts the finding set rather than the status: the
/// exit-code assertion above would not catch this regression, and this is the
/// failure that matters most — a secrets gate whose silence is indistinguishable
/// from a clean file.
#[test]
fn a_path_named_like_a_known_flag_is_not_silently_skipped() {
    let out = enforce_over("secrets-operands-known", KNOWN_FLAG_PATH);

    assert_eq!(
        stdout(&out),
        deny_line(KNOWN_FLAG_PATH) + &deny_line(PLAIN_PATH),
        "the path named like a KNOWN flag is read rather than eaten as one, so \
         its planted secret is reported beside the companion's"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "and the verdict is unchanged, which is exactly why the set is what \
         discriminates: {}",
        stderr(&out)
    );
}
