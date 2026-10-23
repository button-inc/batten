//! What the lease asks of the world beyond its own ref, over the compiled
//! binary: the forge's commit and compare reads behind `lease carries`, the
//! cancellation behind `lease guard`, and the signal `stop` sends.
//!
//! Every forge read goes through `crate::rest`, which answers from the
//! `BATTEN_REST_FIXTURE` directory when one is named, so each case is a canned
//! forge whose `args` record is the request the binary actually sent. The
//! answers are routed by endpoint (`routes`), because one verb asks several.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common;

/// The repository every case names.
const REPO: &str = "acme/widgets";

/// The head every case judges.
const HEAD: &str = "hhhhhhh";

/// A repository declaring two landing paths, with a canned forge beside it.
fn fixture(name: &str) -> PathBuf {
    let dir = common::Fixture::new(name)
        .config("version = 1\n\n[lease]\nlanding_paths = [\"a.sh\", \"b.sh\"]\n")
        .build();
    std::fs::create_dir_all(dir.join("forge")).expect("the fixture directory");
    dir
}

/// Answer requests whose `<METHOD> <url>` contains `needle` with `body`
/// under `status`.
fn route(dir: &Path, needle: &str, status: u16, body: &str) {
    let forge = dir.join("forge");
    let routes = forge.join("routes");
    let table = std::fs::read_to_string(&routes).unwrap_or_default();
    let file = format!("answer.{}", table.lines().count());
    std::fs::write(&routes, format!("{table}{needle}\t{file}\n")).expect("the route table");
    std::fs::write(
        forge.join(file),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("the canned answer");
}

/// The newest commit on `main` touching `path` is `sha`.
fn newest(dir: &Path, path: &str, sha: &str) {
    route(
        dir,
        &format!("commits?sha=main&path={path}&"),
        200,
        &format!("[{{\"sha\": \"{sha}\"}}]"),
    );
}

/// No commit on `main` has touched `path`.
fn untouched(dir: &Path, path: &str) {
    route(dir, &format!("commits?sha=main&path={path}&"), 200, "[]");
}

/// The forge compares `base...head` as `status`.
fn compares(dir: &Path, base: &str, head: &str, status: &str) {
    route(
        dir,
        &format!("compare/{base}...{head}"),
        200,
        &format!("{{\"status\": \"{status}\"}}"),
    );
}

/// Every request the fixture answered.
fn asked(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("forge").join("args")).unwrap_or_default()
}

fn said(output: &Output) -> String {
    format!("{}{}", common::stdout(output), common::stderr(output))
}

/// `batten lease <args>` against the fixture's forge, with no lease remote
/// and nothing from a runner's own environment.
fn lease(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .arg("lease")
        .args(args)
        .env("GH_REPO", REPO)
        .env("LEASE_TRUNK", "main")
        .env("BATTEN_REST_FIXTURE", dir.join("forge"))
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_SERVER_URL")
        .env_remove("LAND_LOCK_REMOTE")
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// The forge's four compare answers, each read as the verdict it is: a head
/// that is `identical` to or `ahead` of trunk's landing commit is current, and
/// one `behind` or `diverged` from it is stale, named by the commit it lacks.
///
/// Fails by: the forge read, the newest-commit read or the compare read
/// answering a constant; or either pair of answers read as the other's.
#[test]
fn each_compare_answer_reads_as_its_verdict() {
    for (status, code) in [
        ("identical", 0),
        ("ahead", 0),
        ("behind", 2),
        ("diverged", 2),
    ] {
        let dir = fixture(&format!("lease-world-{status}"));
        newest(&dir, "a.sh", "aaaa");
        untouched(&dir, "b.sh");
        compares(&dir, "aaaa", HEAD, status);
        let read = lease(&dir, &["carries", HEAD]);
        assert_eq!(read.status.code(), Some(code), "{status}: {}", said(&read));
        assert!(
            asked(&dir).contains(&format!("repos/{REPO}/compare/aaaa...{HEAD}")),
            "{}",
            asked(&dir)
        );
        if code == 2 {
            assert!(
                said(&read).contains("does not carry aaaa"),
                "{}",
                said(&read)
            );
        }
    }
}

/// Of two landing commits, the one that carries the other is the newer, and
/// it is what a head must carry.
///
/// Fails by: two different commits read as one, so the older decides.
#[test]
fn the_newer_of_two_landing_commits_decides() {
    let dir = fixture("lease-world-newer");
    newest(&dir, "a.sh", "aaaa");
    newest(&dir, "b.sh", "bbbb");
    compares(&dir, "aaaa", "bbbb", "ahead");
    compares(&dir, "bbbb", HEAD, "behind");
    let stale = lease(&dir, &["carries", HEAD]);
    assert_eq!(stale.status.code(), Some(2), "{}", said(&stale));
    assert!(
        said(&stale).contains("does not carry bbbb"),
        "{}",
        said(&stale)
    );
}

/// A forge that will not answer is could-not-look, never a verdict.
///
/// Fails by: a refused read's body handed on as a reading.
#[test]
fn a_refused_forge_read_is_could_not_look() {
    let dir = fixture("lease-world-refused");
    route(&dir, "commits?", 403, "[{\"sha\": \"aaaa\"}]");
    let unknown = lease(&dir, &["carries", HEAD]);
    assert_eq!(unknown.status.code(), Some(3), "{}", said(&unknown));
}

/// A head nobody named is not judged, and the forge is not asked about it.
///
/// Fails by: the reads taken anyway for a head that is blank.
#[test]
fn a_blank_head_asks_the_forge_nothing() {
    let dir = fixture("lease-world-blank");
    newest(&dir, "a.sh", "aaaa");
    let unknown = lease(&dir, &["carries", " "]);
    assert_eq!(unknown.status.code(), Some(3), "{}", said(&unknown));
    assert_eq!(asked(&dir), "", "nothing was asked");
}

/// A stale head's guard asks the forge to cancel its run, and a refused
/// cancellation runs anyway.
///
/// Fails by: the cancellation never asked for, or a refusal read as granted
/// (which then waits to be killed).
#[test]
fn a_stale_guard_asks_to_cancel_and_runs_when_refused() {
    let dir = fixture("lease-world-cancel");
    newest(&dir, "a.sh", "aaaa");
    untouched(&dir, "b.sh");
    compares(&dir, "aaaa", HEAD, "behind");
    route(&dir, "actions/runs/77/cancel", 409, "{}");
    let guarded = lease(&dir, &["guard", HEAD, "topic", "77"]);
    assert_eq!(guarded.status.code(), Some(0), "{}", said(&guarded));
    assert!(
        said(&guarded).contains("the cancellation was refused; running anyway"),
        "{}",
        said(&guarded)
    );
    assert!(
        asked(&dir).contains(&format!(
            "POST https://api.github.com/repos/{REPO}/actions/runs/77/cancel"
        )),
        "{}",
        asked(&dir)
    );
}

/// `stop` signals the holder it names, so its own trap runs.
///
/// Fails by: no signal sent at all, which leaves the holder sleeping out its
/// whole interval. Off unix there is no signal to send (`stop` is inert by
/// construction there), so there is no subject to drive.
#[test]
fn stop_terminates_the_holder_it_names() {
    if cfg!(not(unix)) {
        return;
    }
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject is a signal to ANOTHER process, so a real child is the only holder that can receive one"
    )]
    let mut holder = std::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("a holder to stop");
    let pid = holder.id();
    // Reaped on its own thread, so a `stop` that sends nothing FAILS here within
    // the bound rather than hanging out the holder's whole interval.
    let (reaped, exited) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = reaped.send(holder.wait());
    });
    batten::lease::stop(pid);
    let Ok(reaped) = exited.recv_timeout(std::time::Duration::from_secs(30)) else {
        // Nothing stopped it: kill it so the reaping thread ends, then fail.
        #[expect(
            clippy::disallowed_types,
            reason = "stays, and test-only: the cleanup of the real child this case spawned, when the subject failed to signal it"
        )]
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        let _ = exited.recv();
        panic!("stop sent no signal: the holder was still running after 30s");
    };
    let status = reaped.expect("the holder is reaped");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(15), "stopped by SIGTERM: {status:?}");
    }
    #[cfg(not(unix))]
    let _ = status;
}

/// A discovery ceiling between a directory and its repository fences the walk,
/// as git's own does, so the repository's remote cannot name the slug a forge
/// read asks about.
///
/// Fails by: the `GIT_CEILING_DIRECTORIES` reading dropped, which walks
/// straight past the fence to the remote above.
#[test]
fn a_ceiling_between_a_directory_and_its_repository_fences_the_walk() {
    let config = "version = 1\n\n[lease]\nlanding_paths = [\"a.sh\"]\n";
    let dir = common::Fixture::new("lease-world-ceiling")
        .config(config)
        .file("below/deeper/batten.toml", config)
        .build();
    common::git_in(
        &dir,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ],
    );
    let below = dir.join("below").join("deeper");
    let asking = |ceiling: Option<&Path>| {
        let forge = dir.join(if ceiling.is_some() { "fenced" } else { "open" });
        std::fs::create_dir_all(&forge).expect("the fixture directory");
        let mut command = common::batten();
        command
            .args(["lease", "carries", HEAD])
            .env("LEASE_TRUNK", "main")
            .env("BATTEN_REST_FIXTURE", &forge)
            .env_remove("GH_REPO")
            .env_remove("LAND_LOCK_REMOTE")
            .env_remove("GIT_CEILING_DIRECTORIES")
            .current_dir(&below);
        if let Some(ceiling) = ceiling {
            command.env("GIT_CEILING_DIRECTORIES", ceiling);
        }
        let _ = command.output().expect("the compiled binary runs");
        std::fs::read_to_string(forge.join("args")).unwrap_or_default()
    };
    let open = asking(None);
    assert!(open.contains("repos/acme/widgets/"), "unfenced: {open}");
    let fenced = asking(Some(&dir.join("below")));
    assert!(!fenced.is_empty(), "the fenced read still asks: {fenced}");
    assert!(!fenced.contains("repos/acme/widgets/"), "fenced: {fenced}");
}
