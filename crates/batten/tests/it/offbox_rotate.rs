//! `batten offbox rotate` (CLOUD-2724), over the compiled binary.
//!
//! A rotation pass is exercised beside the code, over the transport stand-in.
//! Here: the workflow file the verb prints, and the answers it gives before any
//! transport.

use crate::common::{StateHome as _, batten, scratch, scratch_repo, stdout};

const INSTALL_URL: &str = "https://example.test/install.sh";

fn rotate(case: &str, args: &[&str]) -> std::process::Output {
    let home = scratch(&format!("{case}-home"));
    batten()
        .args(["offbox", "rotate"])
        .args(args)
        .current_dir(scratch_repo(case))
        .state_home(&home)
        .output()
        .expect("run batten offbox rotate")
}

/// The top-level keys of a workflow file: every line that starts in column
/// zero and is not a comment.
fn top_level(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .filter(|line| !line.starts_with([' ', '#']) && !line.is_empty())
        .collect()
}

/// The lines indented under the top-level key `key`, up to the next one.
fn under<'a>(workflow: &'a str, key: &str) -> Vec<&'a str> {
    workflow
        .lines()
        .skip_while(|line| *line != key)
        .skip(1)
        .take_while(|line| line.starts_with(' '))
        .map(str::trim)
        .collect()
}

/// Fails by: a workflow that starts on every session push, that grants more
/// than it needs, or that installs whatever version is newest that day.
#[test]
fn the_printed_workflow_runs_on_a_schedule_alone_and_pins_this_version() {
    let output = rotate(
        "offbox-rotate-workflow",
        &["--print-workflow", "--install-url", INSTALL_URL],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let workflow = stdout(&output);

    assert_eq!(
        top_level(&workflow),
        [
            "name: offbox-rotate",
            "on:",
            "permissions:",
            "concurrency:",
            "jobs:"
        ]
    );
    // Its only trigger: one key under `on`, and it is the schedule.
    let triggers: Vec<&str> = workflow
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.starts_with(' '))
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .collect();
    assert_eq!(triggers, ["  schedule:"]);
    assert_eq!(under(&workflow, "on:")[1], "- cron: \"17 * * * *\"");
    // What it may do: write contents, and nothing else.
    assert_eq!(under(&workflow, "permissions:"), ["contents: write"]);

    // How `batten` gets there: the URL it was given, for this binary's version.
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        workflow.contains(&format!("          BATTEN_VERSION: v{version}\n")),
        "{workflow}"
    );
    assert!(
        workflow.contains(&format!("          INSTALL_URL: \"{INSTALL_URL}\"\n")),
        "{workflow}"
    );
    assert!(workflow.contains("curl -sSfL --retry 3 \"$INSTALL_URL\" | sh\n"));
    // What it runs, against the repository it is installed in.
    assert!(
        workflow.contains(
            "run: batten offbox rotate --remote \"${{ github.server_url }}/${{ github.repository }}\" --quiet-runs 6\n"
        ),
        "{workflow}"
    );
    assert!(workflow.contains("          GH_TOKEN: ${{ github.token }}\n"));
    // It checks out nothing and uses no action: there is no `uses:` to pin.
    assert!(!workflow.contains("uses:"), "{workflow}");
    assert!(!workflow.contains("__"), "a placeholder was left in");
}

/// Fails by: a workflow printed with nothing to install `batten` from.
#[test]
fn printing_the_workflow_needs_the_install_url() {
    let output = rotate("offbox-rotate-no-url", &["--print-workflow"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--install-url"),
        "{output:?}"
    );
}

/// Fails by: a pass run against no repository, or with a count that is not
/// one, reaching the transport.
#[test]
fn a_pass_needs_a_remote_and_a_whole_number_of_runs() {
    let bare = rotate("offbox-rotate-no-remote", &[]);
    assert_eq!(bare.status.code(), Some(1), "{bare:?}");
    assert_eq!(stdout(&bare), "");

    let counted = rotate(
        "offbox-rotate-bad-count",
        &[
            "--remote",
            "https://forge.invalid/a/state",
            "--quiet-runs",
            "soon",
        ],
    );
    assert_eq!(counted.status.code(), Some(1), "{counted:?}");
    assert_eq!(stdout(&counted), "");
    assert!(
        String::from_utf8_lossy(&counted.stderr).contains("--quiet-runs"),
        "{counted:?}"
    );
}
