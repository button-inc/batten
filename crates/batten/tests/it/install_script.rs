//! The committed `install.sh` is `install::render_bootstrap`'s output and
//! nothing else (CLOUD-2203).
//!
//! The script runs on a host with nothing installed yet, so it stays POSIX
//! shell — but it is generated, never hand-written. Its behaviour is pinned end
//! to end in `install_web.rs`; this file pins its BYTES. Following rust-analyzer's
//! `ensure_file_contents`, the case rewrites the file from the generator and
//! fails when any byte differed: a stale or hand-edited `install.sh` is both
//! repaired and refused in one run, and the diff to commit is the generator's.
//!
//! The suite's cases until CLOUD-2203 drove the 748-line hand-written script.
//! Every behaviour the generated bootstrap keeps is pinned where it now lives —
//! the download, digest, retry, exit-class and CA cases in `install_web.rs`, the
//! placement and version-from-ref cases in `engine_install.rs` and `engine.rs` —
//! and the ledger below names each case's file. The API route, its query flags
//! and its proxy-credential fallback have no surface left, which this file's one
//! case pins.

// CLOUD-1268's fifth arm: `install.sh` is one of the four files that stay bash,
// so every arm names it as the survivor it still accounts for.
//
// Each arm names the file that carries the case NOW (CLOUD-2203). An arm naming
// this file is a case whose surface the generated bootstrap does not have — the
// GitHub API payload, the query flags, `--help`, and the proxy and token fallback,
// which existed only because the API route sent a credential — and the one case
// here pins that: `install.sh` is the generator's bytes and nothing else.
//
// ported: tests/install.bats subject:install.sh crates/batten/tests/it/install_script.rs
// ported: "install.bats::--targets lists the targets a POSIX installer can serve" crates/batten/tests/it/release_install.rs subject:install.sh
// ported: "install.bats::--asset-name is name-vversion-target with a per-target extension" crates/batten/src/install.rs subject:install.sh
// ported: "install.bats::the query flags install nothing" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a release whose digest matches installs the binary" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::BATTEN_VERSION selects a tag rather than the latest release" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::THE DEFECT: a digest that does not match the bytes installs nothing" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::THE DEFECT: an asset the API reports no digest for is refused, not installed unverified" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a release carrying no asset for this target is exit 1, naming the asset" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a target no release leg builds is refused before any request" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::an unreadable release is exit 2 — could not look, not a broken release" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a payload with no tag_name is exit 2, never a guessed version" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::the compact payload shape parses too — neither wire form is assumed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::--help explains the surface and exits 0" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::THE DEFECT: installing off PATH is a refusal, not a warning over exit 0" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::the off-PATH refusal has an opt-out, for a deliberate destination" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::a declared CA bundle reaches curl, for a proxy that re-terminates TLS" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::CURL_CA_BUNDLE outranks SSL_CERT_FILE when both are declared" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::no CA declaration means no cacert line — an unproxied host is untouched" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::the retry is bounded and reports rather than looping forever" crates/batten/tests/it/install_web.rs subject:install.sh
// ported: "install.bats::a proxy refusal is retried around the proxy with the operator's own credential" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::an ordinary failure never leaves the proxy" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a refusal from an authority the operator chose is honoured, not bypassed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the fallback can be switched off entirely" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the ordinary token order still wins on the first attempt" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the version comes from the ref's manifest when one is named" crates/batten/tests/it/engine_install.rs subject:install.sh
// ported: "install.bats::a ref naming an unreleased version falls back to the latest release" crates/batten/src/engine.rs subject:install.sh
// ported: "install.bats::an explicitly named version never falls back" crates/batten/tests/it/engine_install.rs subject:install.sh

use crate::common;

#[test]
fn install_sh_is_the_generated_bootstrap() {
    let path = common::at_root("install.sh");
    let generated = batten::install::render_bootstrap("batten", env!("CARGO_PKG_REPOSITORY"));
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    if committed != generated {
        std::fs::write(&path, &generated).expect("rewrite install.sh");
        panic!(
            "install.sh differed from install::render_bootstrap's output and has been \
             regenerated; commit the rewritten file — it is never edited by hand"
        );
    }
}
