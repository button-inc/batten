//! Every `pkl` spawn in the suite carries the CA selection `mise.toml`'s
//! `vars.pkl_ca` makes (CLOUD-2841).
//!
//! A bare `pkl eval` in a TLS-intercepting sandbox fails the handshake on a cold
//! package cache, and a case reading that could-not-fetch as its verdict passes or
//! fails for the wrong reason. CI's runner has no intercepting proxy, so only these
//! two cases discriminate there: one holds the selection to the authority's rule,
//! the other holds every spawn to the one helper that applies it.

use std::ffi::OsString;
use std::path::Path;

use batten::capture::Streamed as _;

use crate::common;

/// The five selections the row names, then the authority's order.
#[test]
fn the_ca_selection_matches_vars_pkl_ca() {
    let dir = common::scratch("pkl-ca-selection");
    common::write(&dir, "batten.pem", "batten\n");
    common::write(&dir, "ssl.pem", "ssl\n");
    let (batten, ssl, missing) = (
        dir.join("batten.pem"),
        dir.join("ssl.pem"),
        dir.join("missing.pem"),
    );
    let set = |path: &Path| Some(path.as_os_str().to_owned());
    let flag = |path: &Path| {
        vec![
            OsString::from("--ca-certificates"),
            path.as_os_str().to_owned(),
        ]
    };

    assert_eq!(
        common::pkl_ca_selection(set(&batten), set(&ssl)),
        flag(&batten),
        "BATTEN_CA_BUNDLE naming a file wins over SSL_CERT_FILE"
    );
    assert_eq!(
        common::pkl_ca_selection(None, set(&ssl)),
        flag(&ssl),
        "SSL_CERT_FILE is the fallback when BATTEN_CA_BUNDLE is unset"
    );
    assert_eq!(
        common::pkl_ca_selection(set(&missing), set(&ssl)),
        flag(&ssl),
        "a BATTEN_CA_BUNDLE naming no file is skipped, never passed"
    );
    assert!(
        common::pkl_ca_selection(set(&missing), set(&missing)).is_empty(),
        "two candidates naming no file select nothing"
    );
    assert!(
        common::pkl_ca_selection(None, None).is_empty(),
        "two unset candidates select nothing"
    );
    assert!(
        common::pkl_ca_selection(Some(OsString::new()), None).is_empty(),
        "a set but empty BATTEN_CA_BUNDLE names no file"
    );

    // THE AUTHORITY'S ORDER, so the helper and `vars.pkl_ca` cannot drift.
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(common::at_root("mise.toml")).expect("mise.toml is readable"),
    )
    .expect("mise.toml is TOML");
    let template = manifest
        .get("vars")
        .and_then(|vars| vars.get("pkl_ca"))
        .and_then(toml::Value::as_str)
        .expect("mise.toml declares vars.pkl_ca");
    let position = |name: &str| {
        template
            .find(name)
            .unwrap_or_else(|| panic!("vars.pkl_ca names {name}: {template}"))
    };
    assert!(
        position("BATTEN_CA_BUNDLE") < position("SSL_CERT_FILE"),
        "vars.pkl_ca tries BATTEN_CA_BUNDLE before SSL_CERT_FILE, as pkl_ca_selection does: {template}"
    );
}

/// The one spawn carries the selection: `pkl_command`'s argv is `eval` and then
/// the flag, so a helper that dropped it would spawn bare `pkl eval` for every
/// case `every_pkl_spawn_carries_the_ca_selection` routes through it.
///
/// The argv is driven with explicit candidates, never the environment: CI sets
/// neither variable, so an argv read off `pkl_command()` there is `eval` either
/// way (CLOUD-2917). `pkl_command()` itself is held over an environment that
/// names files by [`pkl_command_reads_the_environment_in_order`].
#[test]
fn the_pkl_spawn_carries_the_selection_after_eval() {
    let dir = common::scratch("pkl-ca-spawn");
    common::write(&dir, "ssl.pem", "ssl\n");
    let ssl = dir.join("ssl.pem");
    assert_eq!(
        common::pkl_argv(None, Some(ssl.as_os_str().to_owned())),
        vec![
            OsString::from("eval"),
            OsString::from("--ca-certificates"),
            ssl.as_os_str().to_owned(),
        ],
        "the pkl argv is `eval` with the CA selection appended"
    );
    assert_eq!(
        common::pkl_argv(None, None),
        vec![OsString::from("eval")],
        "with nothing selected the argv is plain `eval`"
    );
    assert_eq!(
        common::pkl_command()
            .get_args()
            .map(ToOwned::to_owned)
            .collect::<Vec<OsString>>(),
        common::pkl_argv(
            std::env::var_os("BATTEN_CA_BUNDLE"),
            std::env::var_os("SSL_CERT_FILE"),
        ),
        "the one pkl spawn runs that argv over the environment"
    );
}

/// The CA variables the re-spawned child reads, set by
/// [`pkl_command_reads_the_environment_in_order`] alone.
const CA_VARIABLES: [&str; 2] = ["BATTEN_CA_BUNDLE", "SSL_CERT_FILE"];

/// The file the parent expects the child's `pkl_command()` to select.
const CHILD_EXPECTS: &str = "BATTEN_PKL_CA_CHILD_EXPECTS";

/// `pkl_command()` ITSELF carries the selection, on any runner (CLOUD-2917).
///
/// CI sets neither CA variable, so an argv read off `pkl_command()` in this
/// process is `eval` whatever the helper does with them. This test binary is
/// spawned again, exact filter, with an environment of its own, twice:
///
/// * BOTH variables naming real, distinct files, which holds the ORDER:
///   `BATTEN_CA_BUNDLE`'s file outranks `SSL_CERT_FILE`'s, so a helper that
///   swaps the two fails;
/// * `SSL_CERT_FILE` ALONE, `BATTEN_CA_BUNDLE` removed, which holds that the
///   helper READS it: `pkl_argv(var_os("BATTEN_CA_BUNDLE"), None)` passes the
///   first run and fails this one.
///
/// A helper that spawns bare `pkl eval`, or passes neither variable, fails both.
/// The environment is the child's own, so no parallel case reads a mutated one.
#[test]
fn pkl_command_reads_the_environment_in_order() {
    let dir = common::scratch("pkl-ca-child");
    common::write(&dir, "batten.pem", "batten\n");
    common::write(&dir, "ssl.pem", "ssl\n");
    let batten = dir.join("batten.pem");
    let ssl = dir.join("ssl.pem");
    child_selects(
        &[(CA_VARIABLES[0], &batten), (CA_VARIABLES[1], &ssl)],
        &batten,
    );
    child_selects(&[(CA_VARIABLES[1], &ssl)], &ssl);
}

/// Run [`pkl_command_child`] with exactly `set` of [`CA_VARIABLES`] (the rest
/// removed) and assert it held `pkl_command()` to `expected`'s file.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only (CLOUD-2917): the subject is `pkl_command()` over an environment this process does not have, so this test binary runs again as a child that has it"
)]
fn child_selects(set: &[(&str, &Path)], expected: &Path) {
    let mut child = std::process::Command::new(std::env::current_exe().expect("this test binary"));
    child.args([
        "pkl_ca::pkl_command_child",
        "--exact",
        "--ignored",
        "--test-threads=1",
    ]);
    for name in CA_VARIABLES {
        child.env_remove(name);
    }
    for (name, path) in set {
        child.env(name, path);
    }
    let output = child
        .env(CHILD_EXPECTS, expected)
        .streamed_output()
        .expect("spawn this test binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "pkl_command() selects {} under {set:?}: {stdout}{}",
        expected.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    // A filter that matched nothing exits 0 too.
    assert!(stdout.contains("1 passed"), "the child case ran: {stdout}");
}

/// The child half: `pkl_command()`'s argv over the environment the case above
/// hands it, held to the file that case names in [`CHILD_EXPECTS`].
///
/// Ignored, because it is not a case: run without that parent it has no
/// expectation to hold, and fails rather than passing over nothing.
#[test]
#[ignore = "the child pkl_command_reads_the_environment_in_order spawns; it reads the file that case names"]
fn pkl_command_child() {
    let expected =
        std::env::var_os(CHILD_EXPECTS).expect("spawned by the parent, which names the file");
    assert!(
        Path::new(&expected).is_file(),
        "the expected selection is a real file, so a selection is observable"
    );
    assert_eq!(
        common::pkl_command()
            .get_args()
            .map(ToOwned::to_owned)
            .collect::<Vec<OsString>>(),
        vec![
            OsString::from("eval"),
            OsString::from("--ca-certificates"),
            expected,
        ],
        "pkl_command() is `eval` with the file its environment selects"
    );
}

/// No test file but the helper's own spawns `pkl` by any other route.
#[test]
fn every_pkl_spawn_carries_the_ca_selection() {
    // ASSEMBLED FROM PARTS, so this file does not match itself.
    let tool = "pkl";
    let spellings = [
        format!("require_tool(\"{tool}\")"),
        format!("Command::new(\"{tool}\")"),
        format!("require_bin(\"{tool}\""),
        format!("mise exec {tool}"),
    ];
    let helper = common::at_root("crates/batten/tests/it/common/mod.rs");
    let offenders: Vec<String> = common::test_sources()
        .into_iter()
        .filter(|path| *path != helper)
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            let hit = spellings
                .iter()
                .find(|spelling| text.contains(spelling.as_str()))?;
            Some(format!("{} ({hit})", path.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "spawn pkl through common::pkl_command(), which applies the CA selection: {offenders:?}"
    );
}
