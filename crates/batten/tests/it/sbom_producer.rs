//! `batten sbom` over stubbed tools, and `pin parse other` over the compiled
//! engine (CLOUD-262, CLOUD-628, CLOUD-629, CLOUD-630, CLOUD-664, CLOUD-667,
//! CLOUD-1717, CLOUD-843).
//!
//! The COMPILED BINARY is run with a stubbed `syft` and `cargo` first on `PATH`,
//! which is the only way to produce the inflated shapes and the synthetic
//! metadata rows on demand: the real cataloger's output depends on how many
//! times a workflow happens to reference an action. Assertions are over the
//! producer's OWN documents, because the inventory reduction shares the
//! normaliser's identity rule and can only ever observe agreement.
//!
//! The derivation was `[tasks.sbom]`'s inline body until CLOUD-843 retired it
//! onto the verb; `[tasks.record-sbom]`'s reduction is `--record` now, and its
//! cases are at the foot of this file. Every could-not-look is exit 3, the
//! engine's code for it, where the body exited 2.
//!
//! The licence table's two refusals moved to `policy/sbom-actions.rego`; those
//! cases drive the committed module through `rules::run_static` with the real
//! `[[pattern]]` row, and assert the row EVALUATED — a skipped row reports no
//! findings and reads clean. The producer, for its part, reads only rows of the
//! right shape.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/sbom.sh policy/sbom-actions.rego kind:mechanism crates/batten/tests/it/sbom_producer.rs
// carried: tests/sbom.bats policy/sbom-actions.rego kind:mechanism crates/batten/tests/it/sbom_producer.rs
// carried: "one action referenced twice yields ONE component" crates/batten/src/sbom.rs kind:verb
// carried: "the relative-path component is gone — it was never a dependency" crates/batten/src/sbom.rs kind:verb
// carried: "THE GUARD: the document still DESCRIBES its subject, which shares a triple with the workspace member" crates/batten/src/sbom.rs kind:verb
// carried: "no relationship is left dangling, and none is duplicated" crates/batten/src/sbom.rs kind:verb
// carried: "the CycloneDX graph is rewritten too, not just its component list" crates/batten/src/sbom.rs kind:verb
// carried: "every remaining component is a distinct thing" crates/batten/src/sbom.rs kind:verb
// carried: "normalization is deterministic — two runs produce identical documents" crates/batten/src/sbom.rs kind:verb
// changed: "--names answers without scanning, and reports the normalized asset paths" crates/batten/src/sbom.rs `batten sbom --names`, and the subject and directory are `[sbom]`'s `subject` and `out_dir` rather than a literal and `SBOM_OUT_DIR`
// carried: "the document's own subject carries the workspace supplier, not NOASSERTION" crates/batten/src/sbom.rs kind:verb
// carried: "THE FIELD SPLIT: an empty authors array still gets a supplier, and NOASSERTION for originator" crates/batten/src/sbom.rs kind:verb
// carried: "a crate with authors gets both, and the originator is the author rather than the registry" crates/batten/src/sbom.rs kind:verb
// carried: "a package whose source is NOT crates.io is never labelled crates.io" crates/batten/src/sbom.rs kind:verb
// carried: "a semver build-metadata version still resolves, despite the purl encoding it" crates/batten/src/sbom.rs kind:verb
// carried: "an action's own supplier is never overwritten by the cargo pass" crates/batten/src/sbom.rs kind:verb
// carried: "THE BOILERPLATE TRAP: an Apache-2.0 LICENSE yields NONE, never the license prose" crates/batten/src/sbom.rs kind:verb
// carried: "an MIT-style LICENSE yields exactly its holder line" crates/batten/src/sbom.rs kind:verb
// carried: "a holder outside the license files is still found, and a comment marker is stripped" crates/batten/src/sbom.rs kind:verb
// changed: "a lockfile package absent from the cache is a HARD FAILURE, not a NOASSERTION" crates/batten/src/sbom.rs still a hard failure naming a count and never the crate, at exit 3 rather than 2: could-not-look is 3 under the engine's one exit table, and the half-written documents are removed
// carried: "the copyright pass is deterministic across two runs" crates/batten/src/sbom.rs kind:verb
// carried: "a manifest license reaches BOTH SPDX license fields" crates/batten/src/sbom.rs kind:verb
// carried: "the deprecated slash spelling is rewritten to OR, because it is not valid SPDX" crates/batten/src/sbom.rs kind:verb
// carried: "HONEST ABSENCE: an empty manifest license leaves NOASSERTION rather than guessing" crates/batten/src/sbom.rs kind:verb
// carried: "an action keeps whatever license syft gave it — the cargo pass does not reach it" crates/batten/src/sbom.rs kind:verb
// changed: "a mapped action carries its license and copyright rather than NOASSERTION" crates/batten/src/sbom.rs the table is the one `[sbom] actions` names rather than `SBOM_ACTIONS_TABLE` or a literal path
// carried: "NONE is written for an action whose license file states no holder" crates/batten/src/sbom.rs kind:verb
// carried: "an action absent from the table keeps NOASSERTION rather than borrowing a row" crates/batten/src/sbom.rs kind:verb
// changed: "a table row with fewer than three fields is refused, not silently partial" policy/sbom-actions.rego refused by the module as `pin parse broken` pointing at the row's line, rather than by the producer at exit 1; the producer reads only whole rows, so a short one never reaches a document either
// changed: "a key carrying no 40-hex pin is refused — the pin is the drift authority" policy/sbom-actions.rego refused by the module as `pin parse loose` pointing at the row's line; the key must be exactly `owner/repo@<40-hex>` now, where the program counted characters
// changed: "a key whose pin is SHORT of 40 hex is refused too, not just an absent one" policy/sbom-actions.rego the same move: `pin parse loose`, the length arm being the pattern's `{40}`
// carried: "comments and blank lines in the table are skipped by shape" policy/sbom-actions.rego kind:mechanism
// changed: "a cargo metadata that cannot run fails rather than shipping NOASSERTION" crates/batten/src/sbom.rs still refused with the same sentence and no document, at exit 3: could-not-look
// changed: "a syft that cannot run produces no document and fails" crates/batten/src/sbom.rs still refused with `could not scan`, at exit 3: could-not-look
// changed: "a declared licence table that cannot be read is could-not-look" crates/batten/src/sbom.rs the body refused at exit 2 on an unreadable `SBOM_ACTIONS_TABLE`; the verb refuses at exit 3 on an unreadable `[sbom] actions`, and a table nobody declares is no pass rather than a refusal

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use batten::rules::{self, Rule};
use serde_json::Value;

const PIN: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CACHE: &str = "cargo-home/registry/src/index.crates.io-fixture";

/// The identity fixture: two references to ONE action, one real crate, a
/// relative-path component, the workspace member, and the document subject that
/// shares its triple.
const IDENTITY_SPDX: &str = r#"{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/syft/1",
 "creationInfo":{"created":"2026-08-10T00:00:00Z"},
 "packages":[
   {"SPDXID":"SPDXRef-DocumentRoot-Directory-batten","name":"batten","versionInfo":"9.9.9"},
   {"SPDXID":"SPDXRef-Package-rust-crate-batten-aaa","name":"batten","versionInfo":"9.9.9"},
   {"SPDXID":"SPDXRef-Package-crate0","name":"crate0","versionInfo":"1.0.0",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/crate0@1.0.0"}]},
   {"SPDXID":"SPDXRef-Package-action-bbb","name":"actions/checkout","versionInfo":"v7",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]},
   {"SPDXID":"SPDXRef-Package-action-aaa","name":"actions/checkout","versionInfo":"v7",
    "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]},
   {"SPDXID":"SPDXRef-Package-local","name":"./action","versionInfo":"UNKNOWN",
    "supplier":"Organization: ."}
 ],
 "relationships":[
   {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-batten","relationshipType":"DESCRIBES"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-crate0","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-action-aaa","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-action-bbb","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-DocumentRoot-Directory-batten","relatedSpdxElement":"SPDXRef-Package-local","relationshipType":"CONTAINS"},
   {"spdxElementId":"SPDXRef-Package-crate0","relatedSpdxElement":"SPDXRef-Package-rust-crate-batten-aaa","relationshipType":"DEPENDENCY_OF"}
 ]}"#;

const IDENTITY_CDX: &str = r#"{"serialNumber":"urn:uuid:0000-1",
 "metadata":{"timestamp":"2026-08-10T00:00:00Z",
             "component":{"bom-ref":"ref-root","name":"batten","version":"9.9.9"}},
 "components":[
   {"bom-ref":"ref-crate0","name":"crate0","version":"1.0.0","purl":"pkg:cargo/crate0@1.0.0"},
   {"bom-ref":"ref-action-bbb","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"},
   {"bom-ref":"ref-action-aaa","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"},
   {"bom-ref":"ref-local","name":"./action","version":"UNKNOWN"}
 ],
 "dependencies":[
   {"ref":"ref-root","dependsOn":["ref-crate0","ref-action-aaa","ref-action-bbb","ref-local"]},
   {"ref":"ref-action-bbb","dependsOn":[]}
 ]}"#;

/// A `syft` writing the two fixture documents where `--output` says. Sentinels:
/// `syft.fails`; `syft.volatile` stamps a fresh namespace per run, which the
/// stability reading must see past.
const SYFT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[ ! -f "$FIXTURE/syft.fails" ] || exit 1
spdx=""
cdx=""
want=0
for arg in "$@"; do
	if [ "$want" = 1 ]; then
		case "$arg" in
		spdx-json=*) spdx="${arg#spdx-json=}" ;;
		cyclonedx-json=*) cdx="${arg#cyclonedx-json=}" ;;
		esac
		want=0
		continue
	fi
	[ "$arg" = "--output" ] && want=1
done
printf '%s\n' "$*" >>"$FIXTURE/syft.args"
mkdir -p "$(dirname "$spdx")" "$(dirname "$cdx")"
cat "$FIXTURE/spdx.fixture" >"$spdx"
cat "$FIXTURE/cdx.fixture" >"$cdx"
if [ -f "$FIXTURE/syft.drifts" ]; then
	# Portable on purpose: BSD sed reads `-i`'s next word as a backup suffix,
	# and BSD wc pads the count, so the macOS leg never drifted.
	n=$(wc -l <"$FIXTURE/syft.args" | tr -d ' ')
	sed "s/\"crate0\"/\"crate$n\"/" "$spdx" >"$spdx.drift"
	mv "$spdx.drift" "$spdx"
fi
"#;

const CARGO: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" != "fetch" ] || exit 0
[ ! -f "$FIXTURE/metadata.fails" ] || exit 1
if [ "${1:-}" = "metadata" ]; then
	printf '{"packages": %s}\n' "$(cat "$FIXTURE/metadata.json")"
	exit 0
fi
exit 1
"#;

fn executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path).expect("stat").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }
}

/// The `[sbom]` table a fixture declares, with `extra` appended inside it.
fn config(extra: &str) -> String {
    format!(
        "version = 1\nscope = [\"**\"]\n\n\
         [[rule]]\nid = \"manifest list wrong\"\nkind = \"policy\"\nscope = \"tree\"\n\
         module = \"inventory.rego\"\nseverity = \"deny\"\n\n\
         [[rule.tools]]\nid = \"inventory\"\ntool = \"syft\"\nversion = \"1.51.1\"\ninput = \"Cargo.lock\"\n\n\
         [sbom]\nsubject = \"batten\"\nout_dir = \"out\"\nbinary_out_dir = \"dist\"\n\
         exclude = [\"./tests/bats\", \"./target\"]\ninventory = \"inventory\"\n{extra}"
    )
}

/// One fixture: a repository with a manifest and an `[sbom]` table, stubbed
/// tools, a registry cache, and the two documents syft will "emit".
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("sbom-producer-{name}"));
        let repo = dir.join("repo");
        common::write(
            &repo,
            "Cargo.toml",
            "version = \"9.9.9\"\nauthors = [\"Button Inc.\"]\n",
        );
        common::write(&repo, "Cargo.lock", "# a lockfile\n");
        common::write(&repo, "batten.toml", &config(""));
        // A module the row can name; the reduction is read out of the tool store
        // directly, so what it decides is not this tier's subject.
        common::write(
            &repo,
            "inventory.rego",
            "package fixture.inventory\n\nimport rego.v1\n\nrules contains \"manifest list wrong\"\n",
        );
        common::init_repo(&repo);
        common::git_in(&repo, &["add", "-A"]);
        common::git_in(&repo, &["commit", "-qm", "fixture"]);
        fs::create_dir_all(dir.join(CACHE)).expect("cache");
        fs::create_dir_all(dir.join("bin")).expect("bin");
        executable(&dir.join("bin/syft"), SYFT);
        executable(&dir.join("bin/cargo"), CARGO);
        let fixture = Self { dir };
        fixture.documents(IDENTITY_SPDX, IDENTITY_CDX);
        fixture.metadata(&format!(
            r#"[{{"name":"batten","version":"9.9.9","source":null,"authors":["Button Inc."]}},{{"name":"crate0","version":"1.0.0","source":"{CRATES_IO}","authors":["Someone"]}}]"#
        ));
        fixture
    }

    fn repo(&self) -> PathBuf {
        self.dir.join("repo")
    }

    fn documents(&self, spdx: &str, cdx: &str) {
        common::write(&self.dir, "spdx.fixture", spdx);
        common::write(&self.dir, "cdx.fixture", cdx);
    }

    /// One SPDX package and one `CycloneDX` component, plus the subject.
    fn component(&self, spdx_package: &str, cdx_component: &str) {
        self.documents(
            &format!(
                r#"{{"SPDXID":"SPDXRef-DOCUMENT","name":"batten",
 "documentNamespace":"https://example.invalid/1",
 "creationInfo":{{"created":"2026-08-10T00:00:00Z"}},
 "packages":[{{"SPDXID":"SPDXRef-DocumentRoot-Directory-batten","name":"batten","versionInfo":"9.9.9"}},{spdx_package}],
 "relationships":[{{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-DocumentRoot-Directory-batten","relationshipType":"DESCRIBES"}}]}}"#
            ),
            &format!(
                r#"{{"serialNumber":"urn:uuid:1","metadata":{{"timestamp":"2026-08-10T00:00:00Z",
 "component":{{"bom-ref":"ref-root","name":"batten","version":"9.9.9"}}}},
 "components":[{cdx_component}]}}"#
            ),
        );
    }

    /// A cargo component named `name@version`, in both formats.
    fn crate_component(&self, name: &str, version: &str) {
        let purl = format!("pkg:cargo/{name}@{}", version.replace('+', "%2B"));
        self.component(
            &format!(
                r#"{{"SPDXID":"SPDXRef-P-a","name":"{name}","versionInfo":"{version}","externalRefs":[{{"referenceType":"purl","referenceLocator":"{purl}"}}]}}"#
            ),
            &format!(r#"{{"bom-ref":"r-a","name":"{name}","version":"{version}","purl":"{purl}"}}"#),
        );
    }

    /// `cargo metadata`'s packages, and an unpacked cache dir for each sourced one.
    fn metadata(&self, packages: &str) {
        self.metadata_uncached(packages);
        let parsed: Value = serde_json::from_str(packages).expect("packages parse");
        for package in parsed.as_array().expect("an array") {
            if package["source"].is_null() {
                continue;
            }
            let nv = format!(
                "{}-{}",
                package["name"].as_str().unwrap(),
                package["version"].as_str().unwrap()
            );
            fs::create_dir_all(self.dir.join(CACHE).join(nv)).expect("cache dir");
        }
    }

    fn metadata_uncached(&self, packages: &str) {
        common::write(&self.dir, "metadata.json", packages);
    }

    /// One registry crate with `package` as its metadata row.
    fn registry_crate(&self, name: &str, version: &str, extra: &str) {
        self.crate_component(name, version);
        self.metadata(&format!(
            r#"[{{"name":"{name}","version":"{version}","source":"{CRATES_IO}"{extra}}}]"#
        ));
    }

    /// A file inside an unpacked crate's source.
    fn crate_file(&self, name_version: &str, file: &str, body: &str) {
        common::write(&self.dir.join(CACHE).join(name_version), file, body);
    }

    /// Declare a licence table carrying `rows`.
    fn table(&self, rows: &[&str]) {
        common::write(
            &self.repo(),
            "actions.tsv",
            &format!("{}\n", rows.join("\n")),
        );
        common::write(
            &self.repo(),
            "batten.toml",
            &config("actions = \"actions.tsv\"\n"),
        );
    }

    fn sentinel(&self, name: &str) {
        common::write(&self.dir, name, "");
    }

    /// The compiled binary, in the fixture repository, with the stubs first.
    fn batten(&self, args: &[&str]) -> Output {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.dir.join("bin")).chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        common::batten()
            .args(args)
            .current_dir(self.repo())
            .env("PATH", path)
            .env("FIXTURE", &self.dir)
            .env("CARGO_HOME", self.dir.join("cargo-home"))
            .stdin(Stdio::null())
            .output()
            .expect("run the producer")
    }

    fn produce(&self, names: bool) -> Output {
        if names {
            self.batten(&["sbom", "--names"])
        } else {
            self.batten(&["sbom"])
        }
    }

    /// Produce, asserting success, and return both documents.
    fn documents_produced(&self) -> (Value, Value) {
        let out = self.produce(false);
        assert!(out.status.success(), "the producer derives: {}", said(&out));
        (self.read("batten.spdx.json"), self.read("batten.cdx.json"))
    }

    fn read(&self, name: &str) -> Value {
        let text = fs::read_to_string(self.repo().join("out").join(name)).expect("a document");
        serde_json::from_str(&text).expect("the document parses")
    }
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn packages(spdx: &Value) -> Vec<Value> {
    spdx["packages"].as_array().cloned().unwrap_or_default()
}

fn components(cdx: &Value) -> Vec<Value> {
    cdx["components"].as_array().cloned().unwrap_or_default()
}

fn named<'a>(entries: &'a [Value], name: &str) -> Vec<&'a Value> {
    entries.iter().filter(|e| e["name"] == name).collect()
}

/// The first package named `name`'s `field`, or `ABSENT`.
fn field(spdx: &Value, name: &str, key: &str) -> String {
    packages(spdx)
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p[key].as_str())
        .unwrap_or("ABSENT")
        .to_owned()
}

fn subject(spdx: &Value) -> String {
    spdx["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["relationshipType"] == "DESCRIBES")
        .and_then(|r| r["relatedSpdxElement"].as_str())
        .unwrap()
        .to_owned()
}

fn purl(package: &Value) -> String {
    package["externalRefs"]
        .as_array()
        .and_then(|refs| refs.iter().find(|r| r["referenceType"] == "purl"))
        .and_then(|r| r["referenceLocator"].as_str())
        .unwrap_or("")
        .to_owned()
}

// --- component identity (CLOUD-664) ---------------------------------------------

#[test]
fn one_action_referenced_twice_yields_one_component() {
    let (spdx, cdx) = Fixture::new("one-action").documents_produced();
    assert_eq!(named(&packages(&spdx), "actions/checkout").len(), 1);
    assert_eq!(named(&components(&cdx), "actions/checkout").len(), 1);
}

#[test]
fn the_relative_path_component_is_gone() {
    let (spdx, cdx) = Fixture::new("relative").documents_produced();
    let pathlike = |e: &&Value| e["name"].as_str().unwrap_or("").starts_with("./");
    assert_eq!(packages(&spdx).iter().filter(pathlike).count(), 0);
    assert_eq!(components(&cdx).iter().filter(pathlike).count(), 0);
}

#[test]
fn the_guard_the_document_still_describes_its_subject() {
    let (spdx, _) = Fixture::new("guard").documents_produced();
    let described = subject(&spdx);
    assert_eq!(described, "SPDXRef-DocumentRoot-Directory-batten");
    let all = packages(&spdx);
    assert_eq!(
        all.iter()
            .filter(|p| p["SPDXID"] == described.as_str())
            .count(),
        1
    );
    assert_eq!(
        all.iter()
            .filter(|p| p["SPDXID"] == "SPDXRef-Package-rust-crate-batten-aaa")
            .count(),
        1,
        "the graph node survives beside the subject"
    );
    assert_eq!(named(&all, "batten").len(), 2);
}

#[test]
fn no_relationship_is_left_dangling_and_none_is_duplicated() {
    let (spdx, _) = Fixture::new("dangling").documents_produced();
    let mut ids: Vec<String> = packages(&spdx)
        .iter()
        .map(|p| p["SPDXID"].as_str().unwrap().to_owned())
        .collect();
    ids.push("SPDXRef-DOCUMENT".to_owned());
    let edges = spdx["relationships"].as_array().unwrap();
    for edge in edges {
        for end in ["spdxElementId", "relatedSpdxElement"] {
            assert!(ids.iter().any(|id| edge[end] == id.as_str()), "{edge}");
        }
    }
    let mut unique = edges.clone();
    unique.sort_by_key(ToString::to_string);
    unique.dedup();
    assert_eq!(unique.len(), edges.len(), "no repeated edge");
    let contains = edges
        .iter()
        .filter(|e| e["relationshipType"] == "CONTAINS")
        .count();
    assert_eq!(contains, 2, "crate0 and the one merged action");
}

#[test]
fn the_cyclonedx_graph_is_rewritten_too() {
    let (_, cdx) = Fixture::new("cdx-graph").documents_produced();
    let mut refs: Vec<String> = components(&cdx)
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap().to_owned())
        .collect();
    refs.push(
        cdx["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let dependencies = cdx["dependencies"].as_array().unwrap();
    for dependency in dependencies {
        assert!(refs.iter().any(|r| dependency["ref"] == r.as_str()));
        for on in dependency["dependsOn"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            assert!(refs.iter().any(|r| on == r.as_str()), "{on}");
        }
    }
    let root = dependencies
        .iter()
        .find(|d| d["ref"] == "ref-root")
        .unwrap();
    assert_eq!(root["dependsOn"].as_array().unwrap().len(), 2);
}

#[test]
fn every_remaining_component_is_a_distinct_thing() {
    let (spdx, _) = Fixture::new("distinct").documents_produced();
    let described = subject(&spdx);
    let rest: Vec<Value> = packages(&spdx)
        .into_iter()
        .filter(|p| p["SPDXID"] != described.as_str())
        .collect();
    let mut triples: Vec<String> = rest
        .iter()
        .map(|p| format!("{}|{}|{}", p["name"], p["versionInfo"], purl(p)))
        .collect();
    triples.sort();
    triples.dedup();
    assert_eq!(rest.len(), triples.len());
}

#[test]
fn normalization_is_deterministic_across_two_runs() {
    let fixture = Fixture::new("deterministic");
    let (first, _) = fixture.documents_produced();
    let (second, _) = fixture.documents_produced();
    assert_eq!(first, second);
}

#[test]
fn names_answer_without_scanning() {
    let fixture = Fixture::new("names");
    let out = fixture.produce(true);
    assert!(out.status.success(), "{}", said(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text, "spdx=out/batten.spdx.json\ncdx=out/batten.cdx.json\n");
    assert!(!fixture.repo().join("out/batten.spdx.json").exists());
    assert!(
        !fixture.dir.join("syft.args").exists(),
        "nothing was scanned"
    );
}

#[test]
fn the_scan_passes_the_declared_exclusions_subject_and_version() {
    let fixture = Fixture::new("argv");
    fixture.documents_produced();
    let args = fs::read_to_string(fixture.dir.join("syft.args")).expect("syft ran");
    assert!(
        args.starts_with(
            "scan dir:. --exclude ./tests/bats --exclude ./target --source-name batten --source-version 9.9.9 --output spdx-json="
        ),
        "{args}"
    );
}

// --- supplier and originator (CLOUD-630) ------------------------------------------

#[test]
fn the_documents_own_subject_carries_the_workspace_supplier() {
    let fixture = Fixture::new("subject-supplier");
    fixture.crate_component("crate0", "1.0.0");
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "batten", "supplier"),
        "Organization: Button Inc."
    );
}

#[test]
fn the_field_split_an_empty_authors_array_still_gets_a_supplier() {
    let fixture = Fixture::new("field-split");
    fixture.registry_crate("anon", "1.0.0", r#","authors":[]"#);
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(field(&spdx, "anon", "supplier"), "Organization: crates.io");
    assert_eq!(field(&spdx, "anon", "originator"), "NOASSERTION");
}

#[test]
fn a_crate_with_authors_gets_both_and_the_originator_is_the_author() {
    let fixture = Fixture::new("authored");
    fixture.registry_crate("written", "2.0.0", r#","authors":["A Real Author"]"#);
    let (spdx, cdx) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "written", "supplier"),
        "Organization: crates.io"
    );
    assert_eq!(
        field(&spdx, "written", "originator"),
        "Organization: A Real Author"
    );
    let all = components(&cdx);
    let component = named(&all, "written")[0];
    assert_eq!(component["publisher"], "Organization: crates.io");
    assert_eq!(component["author"], "A Real Author");
}

#[test]
fn a_package_whose_source_is_not_crates_io_is_never_labelled_crates_io() {
    let fixture = Fixture::new("forked");
    fixture.crate_component("forked", "3.0.0");
    fixture.metadata(
        r#"[{"name":"forked","version":"3.0.0","source":"git+https://example.invalid/forked?rev=deadbeef","authors":["Forker"]}]"#,
    );
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(field(&spdx, "forked", "supplier"), "NOASSERTION");
    assert_eq!(field(&spdx, "forked", "originator"), "Organization: Forker");
}

#[test]
fn a_semver_build_metadata_version_still_resolves() {
    let fixture = Fixture::new("build-metadata");
    fixture.registry_crate("toml", "1.1.4+spec-1.1.0", r#","authors":["Toml Author"]"#);
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(field(&spdx, "toml", "supplier"), "Organization: crates.io");
}

#[test]
fn an_actions_own_supplier_is_never_overwritten_by_the_cargo_pass() {
    let fixture = Fixture::new("action-supplier");
    fixture.component(
        r#"{"SPDXID":"SPDXRef-P-a","name":"actions/checkout","versionInfo":"v7","supplier":"Organization: GitHub","originator":"Organization: GitHub","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]}"#,
        r#"{"bom-ref":"r-a","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"}"#,
    );
    fixture.metadata(&format!(
        r#"[{{"name":"actions/checkout","version":"v7","source":"{CRATES_IO}","authors":["Wrong"]}}]"#
    ));
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "actions/checkout", "supplier"),
        "Organization: GitHub"
    );
    assert_eq!(
        field(&spdx, "actions/checkout", "originator"),
        "Organization: GitHub"
    );
}

// --- copyright (CLOUD-629) --------------------------------------------------------

#[test]
fn the_boilerplate_trap_an_apache_license_yields_none() {
    let fixture = Fixture::new("boilerplate");
    fixture.registry_crate("boiler", "1.0.0", r#","authors":["Someone"]"#);
    fixture.crate_file(
        "boiler-1.0.0",
        "LICENSE",
        "   Apache License\n   Version 2.0, January 2004\n\n   4. Redistribution. You may reproduce and distribute copies of the Work\n      notices from the Source form of the Work, and You must include a\n      copyright notice that is included in or attached to the work.\n",
    );
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(field(&spdx, "boiler", "copyrightText"), "NONE");
}

#[test]
fn an_mit_style_license_yields_exactly_its_holder_line() {
    let fixture = Fixture::new("mit");
    fixture.registry_crate("aho", "1.1.5", r#","authors":["Andrew Gallant"]"#);
    fixture.crate_file(
        "aho-1.1.5",
        "LICENSE",
        "Copyright (c) 2015 Andrew Gallant\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n",
    );
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "aho", "copyrightText"),
        "Copyright (c) 2015 Andrew Gallant"
    );
}

#[test]
fn a_holder_outside_the_license_files_is_still_found() {
    let fixture = Fixture::new("headered");
    fixture.registry_crate("headered", "1.0.0", r#","authors":["Chen"]"#);
    fixture.crate_file(
        "headered-1.0.0",
        "src/lib.rs",
        "// Copyright 2015, Yuheng Chen.\n// Licensed under whatever.\nfn main() {}\n",
    );
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "headered", "copyrightText"),
        "Copyright 2015, Yuheng Chen."
    );
}

#[test]
fn the_most_frequent_holder_in_the_tree_wins() {
    let fixture = Fixture::new("frequent");
    fixture.registry_crate("frequent", "1.0.0", r#","authors":["Someone"]"#);
    fixture.crate_file("frequent-1.0.0", "src/a.rs", "// Copyright 2019 Zed\n");
    fixture.crate_file("frequent-1.0.0", "src/b.rs", "// Copyright 2020 Amy\n");
    fixture.crate_file("frequent-1.0.0", "src/c.rs", "// Copyright 2019 Zed\n");
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "frequent", "copyrightText"),
        "Copyright 2019 Zed"
    );
}

#[test]
fn a_lockfile_package_absent_from_the_cache_is_a_hard_failure() {
    let fixture = Fixture::new("absent");
    fixture.crate_component("absent", "2.0.0");
    fixture.metadata_uncached(&format!(
        r#"[{{"name":"absent","version":"2.0.0","source":"{CRATES_IO}","authors":["Nobody"]}}]"#
    ));
    let out = fixture.produce(false);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    let text = said(&out);
    assert!(text.contains("no unpacked source"), "{text}");
    assert!(!text.contains("absent-2.0.0"), "pointer-only: {text}");
    assert!(
        !fixture.repo().join("out/batten.spdx.json").exists(),
        "no half-enriched document is left behind"
    );
}

#[test]
fn the_copyright_pass_is_deterministic_across_two_runs() {
    let fixture = Fixture::new("multi");
    fixture.registry_crate("multi", "1.0.0", r#","authors":["Someone"]"#);
    fixture.crate_file(
        "multi-1.0.0",
        "LICENSE",
        "Copyright (c) 2020 First Holder\nCopyright (c) 2021 Second Holder\nCopyright (c) 2021 Second Holder\n",
    );
    let (first, _) = fixture.documents_produced();
    let (second, _) = fixture.documents_produced();
    assert_eq!(
        field(&first, "multi", "copyrightText"),
        field(&second, "multi", "copyrightText")
    );
    assert_eq!(
        field(&first, "multi", "copyrightText"),
        "Copyright (c) 2020 First Holder",
        "the license file is authoritative, so its first anchored line wins"
    );
}

// --- license (CLOUD-628) ----------------------------------------------------------

#[test]
fn a_manifest_license_reaches_both_spdx_license_fields() {
    let fixture = Fixture::new("licensed");
    fixture.registry_crate(
        "licensed",
        "1.0.0",
        r#","authors":["Someone"],"license":"Apache-2.0 OR MIT""#,
    );
    let (spdx, cdx) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "licensed", "licenseConcluded"),
        "Apache-2.0 OR MIT"
    );
    assert_eq!(
        field(&spdx, "licensed", "licenseDeclared"),
        "Apache-2.0 OR MIT"
    );
    assert_eq!(
        named(&components(&cdx), "licensed")[0]["licenses"][0]["expression"],
        "Apache-2.0 OR MIT"
    );
}

#[test]
fn the_deprecated_slash_spelling_is_rewritten_to_or() {
    let fixture = Fixture::new("slashy");
    fixture.registry_crate(
        "slashy",
        "1.0.0",
        r#","authors":["Someone"],"license":"Apache-2.0 / MIT""#,
    );
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "slashy", "licenseConcluded"),
        "Apache-2.0 OR MIT"
    );
}

#[test]
fn honest_absence_an_empty_manifest_license_leaves_noassertion() {
    let fixture = Fixture::new("unlicensed");
    fixture.registry_crate("unlicensed", "1.0.0", r#","authors":["Someone"]"#);
    let (spdx, cdx) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "unlicensed", "licenseConcluded"),
        "NOASSERTION"
    );
    assert!(
        named(&components(&cdx), "unlicensed")[0]
            .get("licenses")
            .is_none()
    );
}

// --- the pinned actions (CLOUD-667) -----------------------------------------------

fn action_fixture(name: &str) -> Fixture {
    let fixture = Fixture::new(name);
    fixture.component(
        r#"{"SPDXID":"SPDXRef-P-a","name":"actions/checkout","versionInfo":"v7","licenseConcluded":"NOASSERTION","copyrightText":"NOASSERTION","supplier":"Organization: GitHub","originator":"Organization: GitHub","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:github/actions/checkout@v7"}]}"#,
        r#"{"bom-ref":"r-a","name":"actions/checkout","version":"v7","purl":"pkg:github/actions/checkout@v7"}"#,
    );
    fixture.metadata("[]");
    fixture
}

#[test]
fn an_action_keeps_whatever_license_syft_gave_it() {
    let fixture = action_fixture("action-license");
    fixture.table(&["# no rows"]);
    fixture.metadata(&format!(
        r#"[{{"name":"actions/checkout","version":"v7","source":"{CRATES_IO}","authors":["Wrong"],"license":"WRONG-LICENSE"}}]"#
    ));
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "actions/checkout", "licenseConcluded"),
        "NOASSERTION"
    );
}

#[test]
fn a_mapped_action_carries_its_license_and_copyright() {
    let fixture = action_fixture("mapped");
    fixture.table(&[&format!(
        "actions/checkout@{PIN}\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors"
    )]);
    let (spdx, cdx) = fixture.documents_produced();
    assert_eq!(field(&spdx, "actions/checkout", "licenseConcluded"), "MIT");
    assert_eq!(
        field(&spdx, "actions/checkout", "copyrightText"),
        "Copyright (c) 2018 GitHub, Inc. and contributors"
    );
    assert_eq!(
        field(&spdx, "actions/checkout", "supplier"),
        "Organization: GitHub"
    );
    assert_eq!(
        named(&components(&cdx), "actions/checkout")[0]["licenses"][0]["expression"],
        "MIT"
    );
}

#[test]
fn none_is_written_for_an_action_whose_license_file_states_no_holder() {
    let fixture = action_fixture("none-holder");
    fixture.table(&[&format!("actions/checkout@{PIN}\tLGPL-3.0-only\tNONE")]);
    let (spdx, cdx) = fixture.documents_produced();
    assert_eq!(field(&spdx, "actions/checkout", "copyrightText"), "NONE");
    assert!(
        named(&components(&cdx), "actions/checkout")[0]
            .get("copyright")
            .is_none()
    );
}

#[test]
fn an_action_absent_from_the_table_keeps_noassertion() {
    let fixture = action_fixture("unmapped");
    fixture.table(&[&format!(
        "some/other-action@{PIN}\tMIT\tCopyright (c) 2020 Someone"
    )]);
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(
        field(&spdx, "actions/checkout", "licenseConcluded"),
        "NOASSERTION"
    );
}

#[test]
fn the_producer_reads_only_whole_pinned_rows() {
    // The refusal is the module's now; what the producer owes is never to write a
    // short or unpinned row into a document.
    for (name, row) in [
        ("short", format!("actions/checkout@{PIN}\tMIT")),
        ("keyless", "actions/checkout\tMIT\tCopyright".to_owned()),
        // The module refuses a short pin; the producer must not write one either,
        // or the document carries a license the gate calls unpinned.
        (
            "short-pin",
            "actions/checkout@deadbeef\tMIT\tCopyright".to_owned(),
        ),
    ] {
        let fixture = action_fixture(&format!("shape-{name}"));
        fixture.table(&[&row]);
        let (spdx, _) = fixture.documents_produced();
        assert_eq!(
            field(&spdx, "actions/checkout", "licenseConcluded"),
            "NOASSERTION",
            "{name}"
        );
    }
}

#[test]
fn comments_and_blank_lines_are_skipped_by_the_producer() {
    let fixture = action_fixture("comments");
    fixture.table(&[
        "# a comment",
        "",
        &format!("actions/checkout@{PIN}\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors"),
    ]);
    let (spdx, _) = fixture.documents_produced();
    assert_eq!(field(&spdx, "actions/checkout", "licenseConcluded"), "MIT");
}

#[test]
fn a_declared_table_that_cannot_be_read_is_could_not_look() {
    let fixture = action_fixture("unreadable-table");
    fixture.table(&["# rows"]);
    fs::remove_file(fixture.repo().join("actions.tsv")).expect("remove the table");
    let out = fixture.produce(false);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(
        said(&out).contains("cannot read actions.tsv"),
        "{}",
        said(&out)
    );
    assert!(
        !fixture.dir.join("syft.args").exists(),
        "refused before scanning"
    );
}

// --- could-not-look ---------------------------------------------------------------

#[test]
fn a_cargo_metadata_that_cannot_run_is_could_not_look() {
    let fixture = Fixture::new("no-metadata");
    fixture.sentinel("metadata.fails");
    let out = fixture.produce(false);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("could not read cargo metadata"));
    assert!(!fixture.repo().join("out/batten.spdx.json").exists());
}

#[test]
fn a_syft_that_cannot_run_produces_no_document() {
    let fixture = Fixture::new("no-syft");
    fixture.sentinel("syft.fails");
    let out = fixture.produce(false);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("could not scan"));
    assert!(!fixture.repo().join("out/batten.spdx.json").exists());
}

#[test]
fn a_manifest_with_no_version_is_refused_before_the_scan() {
    let fixture = Fixture::new("no-version");
    common::write(&fixture.repo(), "Cargo.toml", "[package]\nname = \"x\"\n");
    let out = fixture.produce(false);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(
        said(&out).contains("could not read a version"),
        "{}",
        said(&out)
    );
    assert!(!fixture.dir.join("syft.args").exists());
}

#[test]
fn no_sbom_table_is_a_usage_error_never_a_guess() {
    let fixture = Fixture::new("undeclared");
    common::write(
        &fixture.repo(),
        "batten.toml",
        "version = 1\nscope = [\"**\"]\n",
    );
    let out = fixture.produce(true);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("[sbom]"), "{}", said(&out));
}

// --- `--record`: the inventory reduction (retiring `[tasks.record-sbom]`) ----------

/// The recorded counts, read back through the tool store's projection.
fn recorded(fixture: &Fixture) -> Option<Vec<String>> {
    let store = fixture.repo().join(".git/batten-tools");
    let entry = fs::read_dir(&store).ok()?.next()?.ok()?;
    let text = fs::read_to_string(entry.path()).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

#[test]
fn the_reduction_records_counts_and_never_the_document() {
    let fixture = Fixture::new("record");
    let out = fixture.batten(&["sbom", "--record"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(out.stdout.is_empty(), "silent on success: {}", said(&out));
    let lines = recorded(&fixture).expect("a record under the declared tool row");
    assert_eq!(
        lines,
        vec![
            "spdx-cargo 1",
            "cdx-cargo 1",
            "spdx-stable yes",
            "cdx-stable yes",
            "subject 1",
            "entries 3",
            "distinct 3",
            "pathlike 0",
            "unversioned 0",
            "nosupplier 0",
            "subject-unset 0",
            "originator-disagrees 0",
            "copyright-unset 0",
            "license-unset 2",
            "license-slashed 0",
            "action-unset 1",
        ]
    );
    assert!(
        !fixture.repo().join("out").exists(),
        "both derivations went to scratch, never the declared directory"
    );
}

#[test]
fn two_scans_that_differ_record_an_unstable_inventory() {
    let fixture = Fixture::new("record-drift");
    fixture.sentinel("syft.drifts");
    let out = fixture.batten(&["sbom", "--record"]);
    assert!(out.status.success(), "{}", said(&out));
    let lines = recorded(&fixture).expect("a record");
    assert!(lines.contains(&"spdx-stable no".to_owned()), "{lines:?}");
    assert!(lines.contains(&"cdx-stable yes".to_owned()), "{lines:?}");
}

#[test]
fn a_derivation_that_cannot_run_records_nothing() {
    let fixture = Fixture::new("record-refused");
    fixture.sentinel("syft.fails");
    let out = fixture.batten(&["sbom", "--record"]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(recorded(&fixture).is_none(), "nothing recorded");
}

#[test]
fn record_takes_no_other_flag() {
    let fixture = Fixture::new("record-usage");
    let out = fixture.batten(&["sbom", "--record", "--names"]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
}

// --- `pin parse other` over the engine ------------------------------------------

const TABLE: &str = "mise-tasks/sbom-actions.tsv";

fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "pin parse other",
        "kind": "policy",
        "scope": "tree",
        "line_sources": [TABLE],
        "module": "policy/sbom-actions.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn patterns() -> Vec<batten::pattern::NamedPattern> {
    let config = fs::read_to_string(common::at_root("batten.toml")).expect("the committed config");
    let parsed: toml::Value = toml::from_str(&config).expect("batten.toml parses");
    let found: Vec<_> = parsed["pattern"]
        .as_array()
        .expect("`[[pattern]]` rows")
        .iter()
        .filter(|row| row["id"].as_str() == Some("sbom-action-key"))
        .map(|row| batten::pattern::NamedPattern {
            id: row["id"].as_str().unwrap().to_owned(),
            regex: row["regex"].as_str().unwrap().to_owned(),
        })
        .collect();
    assert_eq!(found.len(), 1, "the pattern the module reads is declared");
    found
}

/// `(verdict, line)` for every finding over a table carrying `rows`.
fn judged(name: &str, rows: &[&str]) -> Vec<(String, Option<usize>)> {
    let root = common::scratch(&format!("sbom-actions-{name}"));
    common::write(&root, TABLE, &format!("{}\n", rows.join("\n")));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(
        common::at_root("policy/sbom-actions.rego"),
        root.join("policy/sbom-actions.rego"),
    )
    .expect("install committed module");
    let verdicts = common::verdicts_in(&root);
    let patterns = patterns();
    let scan = rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            records: &[],
        },
        &root,
    )
    .expect("the read surface runs a policy row");
    // A SKIPPED row reports no findings too.
    assert!(scan.not_evaluated.is_empty(), "{:?}", scan.not_evaluated);
    scan.findings
        .iter()
        .map(|finding| {
            let class = scan
                .classes
                .get(&finding.identity.fingerprint.to_hex())
                .cloned()
                .unwrap_or_default();
            (class, finding.line)
        })
        .collect()
}

#[test]
fn the_committed_table_is_whole_and_pinned() {
    let committed = fs::read_to_string(common::at_root(TABLE)).expect("the committed table");
    let rows: Vec<&str> = committed.lines().collect();
    assert_eq!(judged("committed", &rows), vec![]);
}

#[test]
fn a_table_row_with_fewer_than_three_fields_is_refused() {
    let found = judged(
        "short",
        &["# header", &format!("actions/checkout@{PIN}\tMIT")],
    );
    assert_eq!(found, vec![("pin parse broken".to_owned(), Some(2))]);
}

#[test]
fn a_key_carrying_no_pin_is_refused() {
    let found = judged(
        "keyless",
        &["actions/checkout\tMIT\tCopyright (c) 2018 GitHub"],
    );
    assert_eq!(found, vec![("pin parse loose".to_owned(), Some(1))]);
}

#[test]
fn a_key_whose_pin_is_short_of_40_hex_is_refused_too() {
    let found = judged(
        "short-pin",
        &["actions/checkout@deadbeef\tMIT\tCopyright (c) 2018 GitHub"],
    );
    assert_eq!(found, vec![("pin parse loose".to_owned(), Some(1))]);
}

#[test]
fn comments_and_blank_lines_in_the_table_are_skipped_by_shape() {
    let found = judged(
        "comments",
        &[
            "# a comment",
            "",
            &format!("actions/checkout@{PIN}\tMIT\tNONE"),
        ],
    );
    assert_eq!(found, vec![]);
}
