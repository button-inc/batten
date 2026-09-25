//! The retired `BATTEN_HOOK_BYPASS` opens no class, over the registry this
//! repository ships.
//!
//! CLOUD-1357 narrowed the hatch to classes declaring no override route; it is
//! now removed for all of them. `bypass_scrub.rs` proves that over a fixture's
//! one row. This tier proves it over the LIVE root, where the question means
//! something: a class with an override precondition, a class with none, and the
//! protected-path class each still refuse with the variable set.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

/// A class that declares an `override` route with a precondition, and is raised
/// on the mediated boundary. `batten.toml`'s `branch write unsafe` row.
const PRECONDITIONED: &str = "branch write unsafe";
/// The same, spelled as a command this repository refuses.
const PRECONDITIONED_CALL: &str = "git push --force-with-lease origin main";

/// A class with NO override route, raised on the same boundary by the vendored
/// `trunk-based` preset — the kind CLOUD-1357 left the hatch open for.
const BARE: &str = "trunk push forced";
/// The same, spelled as a command.
const BARE_CALL: &str = "git push --force origin main";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// Adjudicate over the compiled binary at the real root, with the hatch set or
/// not, and hand back the exit code and what was written to stderr.
///
/// `common::batten()` scrubs every row-declared hatch, so `hatch` is the only
/// way the retired name is present.
fn adjudicate(command: &str, hatch: bool) -> (Option<i32>, String) {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut builder = common::batten();
    builder
        .args(["adjudicate", "--harness", "exit-code"])
        .current_dir(root());
    if hatch {
        builder.env("BATTEN_HOOK_BYPASS", "1");
    }
    let mut child = builder
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(payload(command).as_bytes());
    }
    let out = child.wait_with_output().expect("await batten");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// SHOWN ABLE TO FAIL: against the build before the removal, the bare class
/// exited `0` with the variable set, which is the case CLOUD-1357 left open.
#[test]
fn the_retired_hatch_opens_no_class() {
    // The protected-path arm holds only while the committed set is declared.
    let mut cases = vec![(BARE_CALL, BARE), (PRECONDITIONED_CALL, PRECONDITIONED)];
    if crate::common::committed_protected_declared() {
        cases.push(("rm batten.toml", "path write refused"));
    }
    for (call, class) in cases {
        let (code, cause) = adjudicate(call, true);
        assert_eq!(
            code,
            Some(2),
            "{class} must refuse with the name set\n{cause}"
        );
        assert!(cause.contains(class), "and under its own class\n{cause}");
        let (plain, _) = adjudicate(call, false);
        assert_eq!(plain, Some(2), "and without it: {class}");
    }
}
