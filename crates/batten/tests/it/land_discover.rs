//! `land lap --discover`: every tier, every red, nothing proved (CLOUD-2862).
//!
//! A lap gated on its cheap tiers stops at the first red one, so on a red head
//! the expensive tiers never run and no complete red list exists. Discovery runs
//! the consumer's `$LAND_DISCOVER` once, on HEAD as it stands, and nothing it
//! answers can stand in for a lap: no `verify` receipt, no lap record line, no
//! replay, no push.
//!
//! The gates here are `sh <script>`, so the argv `$LAND_DISCOVER` is split into
//! needs no permission bit, and every script and marker lives OUTSIDE the
//! fixture repository: a gate that wrote into the tree it judges would be
//! refused for moving it, which would turn a passing case into a refusal for a
//! reason the case is not about. Each case's subject is a POSIX `sh` program, so
//! off unix it returns before it asserts, through the `cfg!` arm.

use crate::common;

use std::path::PathBuf;

use common::{Fixture, batten, scratch, stderr, stdout};

/// A fixture repository, its bare remote holding the fixture's HEAD as `main`,
/// and the directory beside it that holds the gates and their markers.
struct Landing {
    repo: PathBuf,
    remote: PathBuf,
    beside: PathBuf,
}

impl Landing {
    fn new(name: &str) -> Self {
        let beside = scratch(name);
        let repo = Fixture::at(beside.join("repo"))
            .config("version = 1\n")
            .file("lib.rs", "fine\n")
            .git()
            .base_commit()
            .build();
        // THE REMOTE IS A BARE CLONE OF THE FIXTURE, never a forked `init`:
        // the template already carries the history the remote must hold.
        let remote = beside.join("remote.git");
        let source = repo.display().to_string();
        common::git_in(&beside, &["clone", "-q", "--bare", &source, "remote.git"]);
        let url = remote.display().to_string();
        common::git_in(&repo, &["remote", "add", "origin", &url]);
        common::git_in(&repo, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        Self {
            repo,
            remote,
            beside,
        }
    }

    /// A gate `sh` runs: `body`, written beside the repository. The argv
    /// `$LAND_DISCOVER` and `$LAND_VERIFY` carry is `sh <path>`.
    fn gate(&self, name: &str, body: &str) -> String {
        let path = self.beside.join(name);
        std::fs::write(&path, body).expect("write the gate");
        format!("sh {}", path.display())
    }

    /// A marker path beside the repository.
    fn marker(&self, name: &str) -> PathBuf {
        self.beside.join(name)
    }

    /// The remote's `main`, as the bare repository holds it.
    fn remote_main(&self) -> String {
        common::git_in(&self.remote, &["rev-parse", "refs/heads/main"])
            .trim()
            .to_owned()
    }

    fn head(&self) -> String {
        common::git_in(&self.repo, &["rev-parse", "HEAD"])
            .trim()
            .to_owned()
    }

    /// The lap record this branch has accumulated, or empty where nothing wrote one.
    fn lap_record(&self) -> String {
        let dir = common::git_in(&self.repo, &["rev-parse", "--git-dir"]);
        let branch = common::git_in(&self.repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
        let path = self
            .repo
            .join(dir.trim())
            .join("batten-receipts")
            .join(format!("lap.{}", branch.trim().replace('/', "-")));
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// `batten land lap` with `args`, both commands declared, and no stall arm:
    /// the suite's own task pid must not become the gate's.
    fn lap(&self, args: &[&str], verify: &str, discover: &str) -> (i32, String) {
        let output = batten()
            .args(["land", "lap"])
            .args(args)
            .env("LAND_VERIFY", verify)
            .env("LAND_DISCOVER", discover)
            .env("LAND_WORKFLOW", "fast-forward.yml")
            .env("LAND_SELF_STALL_BEATS", "0")
            .env_remove("BATTEN_TASK_PID")
            .env_remove("MISE_TASK_PGID_MANAGED")
            .current_dir(&self.repo)
            .streamed_output()
            .expect("run batten land lap");
        (
            output.status.code().expect("exit code"),
            format!("{}{}", stdout(&output), stderr(&output)),
        )
    }

    /// `batten receipt status verify`'s exit code: `2` is no receipt.
    fn verify_receipt(&self) -> i32 {
        let output = batten()
            .args(["receipt", "status", "verify"])
            .current_dir(&self.repo)
            .streamed_output()
            .expect("run batten receipt status");
        output.status.code().expect("exit code")
    }
}

/// **A discovery lap runs `$LAND_DISCOVER`, never `$LAND_VERIFY`, and proves
/// nothing either way.**
///
/// Marker B is the discovery command's and A the verify command's, so a lap that
/// swapped the two is told apart by A's absence. The red half exits 2 and the
/// green half exits 0, and neither writes a `verify` receipt, a lap record line
/// (a held lap's included) or a push: the remote's `main` is where it started.
#[test]
fn a_discovery_lap_runs_its_command_and_writes_no_verify_receipt() {
    if !cfg!(unix) {
        return;
    }
    let landing = Landing::new("land-discover-runs");
    let verified = landing.marker("A");
    let discovered = landing.marker("B");
    let verify = landing.gate("verify.sh", &format!("touch {}\n", verified.display()));
    let red = landing.gate(
        "red.sh",
        &format!("touch {}\nexit 1\n", discovered.display()),
    );
    let remote_before = landing.remote_main();

    let (code, said) = landing.lap(&["--discover"], &verify, &red);
    assert_eq!(code, 2, "a red discovery is the policy verdict: {said}");
    assert!(discovered.exists(), "the discovery command ran: {said}");
    assert!(
        !verified.exists(),
        "the verify command did not run in its place: {said}"
    );
    assert_eq!(
        landing.verify_receipt(),
        2,
        "no verify receipt was written: {said}"
    );
    let record = landing.lap_record();
    assert!(
        record.is_empty(),
        "a discovery run keeps no lap record, held or not: {record:?}"
    );
    assert_eq!(
        landing.remote_main(),
        remote_before,
        "the remote did not move"
    );

    // THE GREEN HALF: an exit 0 is still no proof.
    std::fs::remove_file(&discovered).expect("clear marker B");
    let green = landing.gate("green.sh", &format!("touch {}\n", discovered.display()));
    let (code, said) = landing.lap(&["--discover"], &verify, &green);
    assert_eq!(code, 0, "a green discovery exits 0: {said}");
    assert!(discovered.exists(), "the discovery command ran: {said}");
    assert!(!verified.exists(), "and the verify command did not: {said}");
    assert_eq!(
        landing.verify_receipt(),
        2,
        "a green discovery still writes no verify receipt: {said}"
    );
    assert!(landing.lap_record().is_empty(), "nor any record line");
    assert_eq!(landing.remote_main(), remote_before, "nor any push");
}

/// **`--discover` beside `--hold` is a usage error that runs neither command**:
/// a discovery run holds no lap, so asking it to is a request with no meaning.
#[test]
fn discover_with_hold_is_refused_as_usage() {
    if !cfg!(unix) {
        return;
    }
    let landing = Landing::new("land-discover-hold");
    let verified = landing.marker("A");
    let discovered = landing.marker("B");
    let verify = landing.gate("verify.sh", &format!("touch {}\n", verified.display()));
    let discover = landing.gate("discover.sh", &format!("touch {}\n", discovered.display()));

    let (code, said) = landing.lap(&["--discover", "--hold"], &verify, &discover);
    assert_eq!(code, 1, "the pair is a usage error: {said}");
    assert!(!discovered.exists(), "the discovery command did not run");
    assert!(!verified.exists(), "nor the verify command");
}

/// **A base that moves under a discovery run neither rebases it nor buys a
/// second lap.** The discovery command itself advances the remote's `main`
/// through a second clone, and counts its own runs: HEAD after equals HEAD
/// before, the command ran once, and the remote DID move, so the case is not
/// passing over a race that never happened.
#[test]
fn a_discovery_lap_on_a_moved_base_does_not_rebase() {
    if !cfg!(unix) {
        return;
    }
    let landing = Landing::new("land-discover-moved-base");
    let helper = landing.beside.join("helper");
    let remote = landing.remote.display().to_string();
    let helper_at = helper.display().to_string();
    common::git_in(&landing.beside, &["clone", "-q", &remote, &helper_at]);
    let runs = landing.marker("runs");
    let discover = landing.gate(
        "advance.sh",
        &format!(
            "echo ran >> {runs}\n\
             git -C {helper} -c user.name=moved -c user.email=moved@example.invalid \
             commit -q --allow-empty -m moved\n\
             git -C {helper} push -q origin HEAD:refs/heads/main\n\
             exit 1\n",
            runs = runs.display(),
            helper = helper.display(),
        ),
    );
    let verify = landing.gate("verify.sh", "exit 0\n");
    let head_before = landing.head();
    let remote_before = landing.remote_main();

    let (code, said) = landing.lap(&["--discover"], &verify, &discover);
    assert_eq!(code, 2, "the run's own red is its verdict: {said}");
    assert_ne!(
        landing.remote_main(),
        remote_before,
        "the base did move during the run: {said}"
    );
    assert_eq!(
        landing.head(),
        head_before,
        "HEAD is where the run found it: {said}"
    );
    let ran = std::fs::read_to_string(&runs).expect("the discovery command ran");
    assert_eq!(ran.lines().count(), 1, "one run, no second lap: {said}");
}
