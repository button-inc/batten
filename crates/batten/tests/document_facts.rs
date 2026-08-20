//! CLOUD-772's §7 obligations: a document fact, three-valued, per format.
//!
//! The measured defect these are written against is not a wrong answer, it is a
//! **silent** one. Seventy-three hand-rolled readers of TOML, YAML, JSON and
//! JSON5 live in this repository's task layer, and every one of them defaults an
//! extraction that returned nothing to agreement — so a file the reader cannot
//! understand passes the gate over it, and the gate is quietest exactly when it
//! has seen the least. Each case below therefore asserts the *distinction*
//! between "looked and it is not there" and "could not look", never merely that
//! the happy path works.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::PathBuf;

use batten::facts::{Format, Look, Node};
use common::{Fixture, stderr, stdout};

/// One well-formed document per format, each carrying the same shape: a table
/// `pin` with a `rust` key. Written per format rather than generated, so the
/// syntax a consumer actually types is what is parsed.
const WELL_FORMED: &[(Format, &str)] = &[
    (Format::Toml, "[pin]\nrust = \"1.97.1\"\n"),
    (Format::Yaml, "pin:\n  rust: \"1.97.1\"\n"),
    (Format::Json, "{\"pin\": {\"rust\": \"1.97.1\"}}"),
    // The three things a JSON parser refuses and every brace-depth state machine
    // gets wrong: a comment, an unquoted key, a trailing comma.
    (
        Format::Json5,
        "{\n  // the pin\n  pin: { rust: \"1.97.1\", },\n}",
    ),
];

/// Text that is not a document in the paired format. Each is malformed in that
/// format's own way rather than being one blob reused four times, because a blob
/// every parser rejects proves nothing about any of them.
const MALFORMED: &[(Format, &str)] = &[
    (Format::Toml, "[pin\nrust = "),
    (Format::Yaml, "pin:\n\t- bad tab indent\n  - and: [unclosed"),
    (Format::Json, "{\"pin\": {\"rust\": }"),
    (Format::Json5, "{ pin: { rust: \"1.97.1\" "),
];

#[test]
fn every_parseable_format_reads_the_same_node_path() {
    // The point of a document fact: `pin.rust` means the same thing in four
    // syntaxes, so a rule is written once rather than per format.
    for (format, text) in WELL_FORMED {
        let Look::Is(document) = format.read(text) else {
            panic!("{} did not parse a well-formed document", format.as_str());
        };
        assert_eq!(
            document.at("pin.rust"),
            Look::Is(&Node::Text("1.97.1".to_owned())),
            "{} addressed pin.rust differently",
            format.as_str()
        );
    }
}

#[test]
fn a_document_that_does_not_parse_is_could_not_look_and_never_no_rows() {
    // THE case. `Look::IsNot` here would say "looked, and pin.rust is not in
    // this file", which is the vacuous pass: a syntax error says nothing at all
    // about what the file contains.
    //
    // Fails by: collapsing `CouldNotLook` into `IsNot` in `Format::read`, or
    // returning an empty document instead of refusing.
    for (format, text) in MALFORMED {
        assert_eq!(
            format.read(text),
            Look::CouldNotLook,
            "{} read a malformed document as an answer",
            format.as_str()
        );
    }
}

#[test]
fn a_missing_node_is_is_not_and_a_broken_file_is_could_not_look() {
    // The two absences, side by side, over the same format — which is the whole
    // content of the three-valued contract. A test asserting only one of them
    // passes just as happily when they are the same value.
    let Look::Is(document) = Format::Toml.read("[pin]\nrust = \"1.97.1\"\n") else {
        panic!("the well-formed document did not parse");
    };
    assert_eq!(document.at("pin.python"), Look::IsNot);
    assert_eq!(Format::Toml.read("[pin\n"), Look::CouldNotLook);
    assert_ne!(
        Look::<&Node>::IsNot,
        Look::<&Node>::CouldNotLook,
        "the two absences must not be the same value"
    );
}

#[test]
fn a_declared_pkl_path_answers_could_not_look_rather_than_nothing() {
    // PKL is deliberately excluded and deliberately DECLARABLE. An absent
    // variant would answer a consumer's declaration with "no rows", and the only
    // way to find that out is that the rule never fires — the exact vacuous pass
    // the whole issue is filed against, reintroduced by the omission.
    assert!(!Format::Pkl.parseable());
    assert_eq!(
        Format::Pkl.read("amends \"package://example.com/Thing.pkl\"\n"),
        Look::CouldNotLook
    );
    // And it is a real member of the vocabulary, not a token the config rejects.
    assert!(Format::ALL.contains(&Format::Pkl));
    assert_eq!(Format::Pkl.as_str(), "pkl");
}

#[test]
fn all_covers_every_format() {
    // The totality anchor, in `RuleKind::ALL`'s shape: the match below is
    // exhaustive by the compiler, and this asserts `ALL` agrees with it.
    let mut seen = Vec::new();
    for format in Format::ALL {
        match format {
            Format::Toml | Format::Yaml | Format::Json | Format::Json5 | Format::Pkl => {
                seen.push(format.as_str());
            }
        }
    }
    assert_eq!(seen, ["toml", "yaml", "json", "json5", "pkl"]);
}

#[test]
fn key_order_is_the_keys_order_and_never_the_files() {
    // §6 byte-stability, made structural rather than careful: the document tree
    // is a `BTreeMap`, so two files carrying the same keys in different order
    // parse to the same value and any pass over either is identical.
    //
    // Fails by: carrying the map in insertion order.
    let one = Format::Json.read("{\"b\": 2, \"a\": 1}");
    let other = Format::Json.read("{\"a\": 1, \"b\": 2}");
    assert_eq!(one, other);
    let Look::Is(document) = one else {
        panic!("the document did not parse");
    };
    let Node::Map(map) = document else {
        panic!("the document is not a mapping");
    };
    assert_eq!(map.keys().collect::<Vec<_>>(), ["a", "b"]);
}

#[test]
fn a_number_survives_as_the_source_wrote_it() {
    // A version pin is the number this fact exists to compare, and re-formatting
    // a parsed float is the classic place one stops round-tripping. Carrying the
    // source text is what keeps `1.90` from coming back as `1.9`.
    let Look::Is(document) = Format::Yaml.read("pin: 1.90\n") else {
        panic!("the document did not parse");
    };
    assert_eq!(
        document.at("pin"),
        Look::Is(&Node::Number("1.90".to_owned()))
    );
}

#[test]
fn a_document_rule_fails_the_run_and_reports_only_a_pointer() {
    // End to end over the compiled binary, which is where a consumer meets this.
    // Rule 4 is the assertion that matters: the VALUE read must not reach either
    // channel. These documents carry tokens and internal hostnames, so a check
    // that echoed what it found would be the leak the pointer-only rule exists
    // to prevent.
    let dir = Fixture::new("document-pointer-only")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"pin-agreement\"\n\
             kind = \"document\"\n\
             glob = \"pins.toml\"\n\
             format = \"toml\"\n\
             node = \"pin.rust\"\n\
             pattern = \"1.97.1\"\n\
             severity = \"deny\"\n",
        )
        .file("pins.toml", "[pin]\nrust = \"s3cr3t-internal-host\"\n")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2), "a divergent node must fail");
    let both = format!("{}{}", stdout(&output), stderr(&output));
    assert!(both.contains("pins.toml"), "the pointer names the file");
    assert!(both.contains("pin-agreement"), "and names the rule");
    assert!(
        !both.contains("s3cr3t-internal-host"),
        "the value read must never be reported"
    );
}

#[test]
fn a_document_that_cannot_be_parsed_fails_the_run_rather_than_passing_it() {
    // The end-to-end half of the three-valued case. A gate over a file it could
    // not read must not report agreement — which is what all 73 readers this
    // replaces do today.
    //
    // Fails by: returning `Ok` with no finding on the `CouldNotLook` arm of
    // `document_in_file`.
    let dir = Fixture::new("document-unreadable")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"pin-agreement\"\n\
             kind = \"document\"\n\
             glob = \"pins.toml\"\n\
             format = \"toml\"\n\
             node = \"pin.rust\"\n\
             pattern = \"1.97.1\"\n\
             severity = \"deny\"\n",
        )
        .file("pins.toml", "[pin\nrust = ")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a document that could not be looked at must not read as agreement"
    );
}

#[test]
fn a_matching_node_is_clean() {
    let dir = Fixture::new("document-agrees")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"pin-agreement\"\n\
             kind = \"document\"\n\
             glob = \"pins.yml\"\n\
             format = \"yaml\"\n\
             node = \"pin.rust\"\n\
             pattern = \"1.97.1\"\n\
             severity = \"deny\"\n",
        )
        .file("pins.yml", "pin:\n  rust: \"1.97.1\"\n")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0));
}

/// The artifacts this repository's task layer parses by hand, and which
/// `crates/batten` must therefore never name.
///
/// Rule 1 as a **gate** rather than a convention (CLOUD-772): the core knows
/// formats, and which path carries which format is the consumer's `batten.toml`.
/// A core that named one of these would have made the document fact a per-artifact
/// feature, which is the accretion this milestone exists to stop.
const CONSUMER_ARTIFACTS: &[&str] = &[
    ".github/workflows",
    ".claude/settings.json",
    "renovate.json5",
    "hk.pkl",
    "mise.toml",
    "mise.lock",
];

/// Where an artifact name is still permitted, each with the reason.
///
/// A **declared** list, not a suppression: every row is a name the core carries
/// for a reason that predates this issue and that the document fact does not
/// discharge. It is a ratchet — the list may shrink and a new hit fails — which
/// is the difference between a gate with a stated residue and a gate switched
/// off. `batten.toml`, `Cargo.toml` and `Cargo.lock` are deliberately absent
/// from `CONSUMER_ARTIFACTS` above for a different reason again: the first is
/// Batten's own config authority (`config::CONFIG_FILE`) and the other two are
/// this crate's own manifest, so none of the three is a *consumer's* identifier
/// at all.
const STATED_RESIDUE: &[(&str, &str)] = &[
    // A hook envelope names the host's own settings file, because that is the
    // path the host writes and the engine reads back. It is the harness's
    // vocabulary, not an artifact this fact parses.
    ("src/hook.rs", ".claude/settings.json"),
    // Prose in module docs, recording where a mechanism used to live.
    ("src/hook.rs", "mise.toml"),
    ("src/commit.rs", "mise.toml"),
    ("src/receipt.rs", "mise.toml"),
    ("src/provision.rs", "mise.lock"),
];

#[test]
fn no_artifact_name_reaches_the_core() {
    // Non-negotiable rule 1, computed. Scans `crates/batten/src` — the core —
    // and not `tests/`, where a fixture legitimately writes a workflow file to
    // prove the walker sees it.
    //
    // Pointer-only (rule 4): a hit reports `path:line` and the artifact, never
    // the line.
    //
    // Fails by: naming any of the artifacts above in a new core module — which
    // is exactly what a per-artifact document fact would have had to do.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&src).expect("read src") {
        let path = entry.expect("read entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let relative = format!(
            "src/{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
        );
        let source = fs::read_to_string(&path).expect("read source");
        for (index, line) in source.lines().enumerate() {
            for artifact in CONSUMER_ARTIFACTS {
                if line.contains(artifact)
                    && !STATED_RESIDUE.contains(&(relative.as_str(), artifact))
                {
                    offenders.push(format!("{relative}:{} {artifact}", index + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a consumer's artifact name reached `crates/batten` (non-negotiable rule 1). The core \
         knows formats; which path carries which format is the consumer's `batten.toml` \
         (CLOUD-772):\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_stated_residue_is_a_ratchet_and_not_a_suppression() {
    // A declared exemption that no longer names a real hit is an exemption
    // nobody will notice has gone stale, and the list would only ever grow. So
    // each row must still be live: remove the last mention of an artifact from a
    // module and this fails until the row goes too.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for (module, artifact) in STATED_RESIDUE {
        let source = fs::read_to_string(src.join(module.trim_start_matches("src/")))
            .unwrap_or_else(|_| panic!("{module} is named by the residue but does not exist"));
        assert!(
            source.contains(artifact),
            "{module} no longer names {artifact}; drop its row from STATED_RESIDUE"
        );
    }
}
