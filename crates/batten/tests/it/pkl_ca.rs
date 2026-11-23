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
    let flag = |path: &Path| vec![OsString::from("--ca-certificates"), path.as_os_str().to_owned()];

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
            let hit = spellings.iter().find(|spelling| text.contains(spelling.as_str()))?;
            Some(format!("{} ({hit})", path.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "spawn pkl through common::pkl_command(), which applies the CA selection: {offenders:?}"
    );
}
