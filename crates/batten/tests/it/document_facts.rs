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

use crate::common;

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
    // The body is deliberately the thing that breaks a whole-stream YAML read:
    // a table, a task list and a block quote are the three shapes CLOUD-1787
    // measured failing. If this fixture parses, the body is not being read.
    (
        Format::Markdown,
        "---\npin:\n  rust: \"1.97.1\"\n---\n# heading\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n- [ ] a task\n\n> **NOTE** text\n",
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
    // A fence that IS there and whose contents are not YAML. The other markdown
    // non-answer — no fence at all — is `Look::IsNot` and belongs to
    // `a_markdown_file_without_a_fence_is_is_not_and_never_could_not_look`,
    // which is the distinction this format exists to make.
    (
        Format::Markdown,
        "---\npin:\n\t- bad tab indent\n  - and: [unclosed\n---\n# heading\n",
    ),
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
fn a_markdown_file_without_a_fence_is_is_not_and_never_could_not_look() {
    // CLOUD-1787's distinction, and the reason `Format::Markdown` is the one
    // format whose `read` may answer `IsNot`. A well-formed markdown file with
    // no frontmatter is not one the reader failed on — it read the whole thing
    // and there is no document in it. Reporting that as `CouldNotLook` says the
    // reader broke, and sends an author looking for a malformed fence that is
    // simply absent.
    //
    // Fails by: collapsing the no-fence case into `CouldNotLook` (or into
    // `Look::Is` of an empty map, which would be the vacuous pass).
    for text in [
        "# heading\n\nprose only.\n",
        // A `---` that is not on the first line is a horizontal rule. A reader
        // that went looking for one anywhere would turn prose into a document.
        "# heading\n---\npin:\n  rust: \"1.97.1\"\n---\n",
        // A leading blank line is not a fence either.
        "\n---\npin:\n  rust: \"1.97.1\"\n---\n",
        // Opened and never closed: guessing where it ends is the same error as
        // finding one mid-file.
        "---\npin:\n  rust: \"1.97.1\"\n\n# heading\n",
    ] {
        assert_eq!(
            Format::Markdown.read(text),
            Look::IsNot,
            "markdown read a file with no frontmatter as something other than IsNot"
        );
    }
    assert_ne!(
        Look::<Node>::IsNot,
        Look::<Node>::CouldNotLook,
        "the two markdown non-answers must not be the same value"
    );
}

#[test]
fn a_markdown_body_never_reaches_a_parser() {
    // THE defect (CLOUD-1787). Identical correct frontmatter; only the body
    // varies, over the exact shapes measured failing when the file was read as
    // one YAML stream. Every one of them must read `pin.rust` identically,
    // because the body is not read at all.
    //
    // Fails by: handing the whole file to the YAML reader, which is what
    // `format = "yaml"` over a `*.md` glob does — four of these six then answer
    // `CouldNotLook` and report as a node mismatch.
    const FRONTMATTER: &str = "---\npin:\n  rust: \"1.97.1\"\n---\n";
    for body in [
        "prose only.\n",
        "*emphasis*, **bold**, Rate: 3:1\n",
        "a [[wikilink]] mid-sentence.\n",
        "[[wikilink]] opening the body.\n",
        "- [ ] a task\n",
        "| a | b |\n| - | - |\n| 1 | 2 |\n",
        "> **HEADING** text\n",
    ] {
        let text = format!("{FRONTMATTER}{body}");
        let Look::Is(document) = Format::Markdown.read(&text) else {
            panic!("a markdown body changed whether the frontmatter parsed");
        };
        assert_eq!(
            document.at("pin.rust"),
            Look::Is(&Node::Text("1.97.1".to_owned())),
            "a markdown body changed what the frontmatter said"
        );
    }
}

#[test]
fn an_empty_fence_is_an_empty_document_and_not_an_absent_one() {
    // Present-and-empty is an ANSWER. A file whose fence is `---\n---` has
    // frontmatter and it has no keys, which is a different authoring fault from
    // having no fence at all — and a gate over `name:` must be able to deny the
    // first rather than skip it.
    //
    // Fails by: routing the empty block through the YAML reader, where an empty
    // stream is `CouldNotLook`, or by collapsing it into the no-fence `IsNot`.
    let Look::Is(document) = Format::Markdown.read("---\n---\n# heading\n") else {
        panic!("an empty fence did not read as a document");
    };
    assert_eq!(document, Node::Map(std::collections::BTreeMap::new()));
    // Looked, and the key is not there — which is exactly what it should say,
    // and is NOT the same answer as the file having no fence at all.
    assert_eq!(document.at("name"), Look::IsNot);
    assert_eq!(Format::Markdown.read("# heading\n"), Look::IsNot);
}

#[test]
fn the_fence_is_recognised_across_the_spellings_a_consumer_actually_writes() {
    // A BOM is invisible to the author, `\r\n` is what a Windows editor writes,
    // and `...` is YAML's other document terminator. Refusing any of them would
    // blame a file for its encoding or for reading the YAML spec.
    //
    // Fails by: anchoring the fence rule to `---\n` and a `\n---\n` terminator
    // alone, which is what the byte scan it shares with `budget` used to do.
    for text in [
        "\u{feff}---\npin:\n  rust: \"1.97.1\"\n---\n# heading\n",
        "---\r\npin:\r\n  rust: \"1.97.1\"\r\n---\r\n# heading\r\n",
        "---\npin:\n  rust: \"1.97.1\"\n...\n# heading\n",
    ] {
        let Look::Is(document) = Format::Markdown.read(text) else {
            panic!("a legitimate fence spelling did not read as a document");
        };
        assert_eq!(
            document.at("pin.rust"),
            Look::Is(&Node::Text("1.97.1".to_owned()))
        );
    }
}

/// One well-formed fence per admitted dialect (CLOUD-1886), every one carrying
/// the shape `WELL_FORMED` carries: a table `pin` with a `rust` key.
///
/// Written out per dialect rather than generated from the delimiter table,
/// because the point is that the bytes a consumer actually types are what gets
/// parsed — a generator would only restate `FENCES` and would agree with it
/// however wrong `FENCES` was.
const DIALECTS: &[(&str, &str)] = &[
    ("yaml", "---\npin:\n  rust: \"1.97.1\"\n---\n"),
    ("toml", "+++\n[pin]\nrust = \"1.97.1\"\n+++\n"),
    (
        "json-fenced",
        ";;;\n{\"pin\": {\"rust\": \"1.97.1\"}}\n;;;\n",
    ),
    ("tagged-yaml", "---yaml\npin:\n  rust: \"1.97.1\"\n---\n"),
    ("tagged-toml", "---toml\n[pin]\nrust = \"1.97.1\"\n---\n"),
    (
        "tagged-json",
        "---json\n{\"pin\": {\"rust\": \"1.97.1\"}}\n---\n",
    ),
    ("json-object", "{\n  \"pin\": {\"rust\": \"1.97.1\"}\n}\n"),
];

#[test]
fn every_frontmatter_dialect_reads_the_same_node_path() {
    // The point of CLOUD-1886, in the shape CLOUD-1787 established one dialect
    // over: `pin.rust` means the same thing whichever delimiter the author
    // reached for, so a tree mixing a Hugo `+++` post and a Jekyll `---` post is
    // one rule rather than two.
    //
    // Fails by: dropping a row from `FENCES` — a `+++` file then answers `IsNot`,
    // which is the defect this row is filed against — or by handing every block
    // to the YAML reader regardless of which delimiter opened it, where a TOML
    // table reads as `CouldNotLook` and reports here as a node mismatch.
    let mut seen = 0usize;
    for (dialect, fence) in DIALECTS {
        let text = format!("{fence}# heading\n\n| a | b |\n| - | - |\n| 1 | 2 |\n");
        let Look::Is(document) = Format::Markdown.read(&text) else {
            panic!("{dialect} did not read as a document");
        };
        assert_eq!(
            document.at("pin.rust"),
            Look::Is(&Node::Text("1.97.1".to_owned())),
            "{dialect} addressed pin.rust differently"
        );
        seen += 1;
    }
    // ANTI-VACUITY: an empty table passes the loop above in silence, and the
    // whole row is the claim that SEVERAL dialects agree.
    assert_eq!(seen, DIALECTS.len());
    assert!(seen > 1, "one dialect cannot demonstrate agreement");
}

#[test]
fn a_toml_fence_is_not_closed_by_a_yaml_document_terminator() {
    // `...` is YAML's second document terminator and TOML has no such concept,
    // so accepting it there would invent a grammar rather than admit one. The
    // fence is therefore unterminated, and an unterminated fence is no fence.
    //
    // Fails by: giving every dialect one shared closer set — the tidying this
    // table most invites, and the one that would make `+++ … ...` a document
    // nothing writes.
    assert_eq!(
        Format::Markdown.read("+++\n[pin]\nrust = \"1.97.1\"\n...\n# heading\n"),
        Look::IsNot
    );
    // The control, without which the case above passes for a TOML fence that
    // never parses at all: the same block closed by its own delimiter reads.
    let Look::Is(document) = Format::Markdown.read("+++\n[pin]\nrust = \"1.97.1\"\n+++\n") else {
        panic!("a well-formed TOML fence did not read as a document");
    };
    assert_eq!(
        document.at("pin.rust"),
        Look::Is(&Node::Text("1.97.1".to_owned()))
    );
}

#[test]
fn a_tagged_fence_closes_on_the_bare_delimiter() {
    // gray-matter's asymmetry, which is the half of its syntax a reader invents
    // symmetrically and then reads nothing: `---toml` opens and the plain `---`
    // closes, because the language is the remainder of the OPENING line only.
    //
    // Fails by: closing a tagged fence on its own tag, which reads the file the
    // way the syntax looks rather than the way it is specified.
    let Look::Is(document) =
        Format::Markdown.read("---toml\n[pin]\nrust = \"1.97.1\"\n---\nbody\n")
    else {
        panic!("a tagged fence did not close on the bare delimiter");
    };
    assert_eq!(
        document.at("pin.rust"),
        Look::Is(&Node::Text("1.97.1".to_owned()))
    );
    // And the mirror, without which the case above is satisfied by a reader that
    // accepts both spellings: repeating the tag does not close anything.
    assert_eq!(
        Format::Markdown.read("---toml\n[pin]\nrust = \"1.97.1\"\n---toml\nbody\n"),
        Look::IsNot
    );
}

#[test]
fn an_unfenced_json_object_ends_where_its_parser_says_and_not_at_a_brace() {
    // Hugo counts braces with its own quote and escape state. This does not:
    // the object ends where `serde_json` says the value ended. The fixture is
    // the case that separates the two — a `}` inside a string — and a brace
    // counter stops early on it, taking half an object as the whole document
    // and leaving the rest of the object in the body.
    //
    // Fails by: replacing the parse with a scan for a closing brace, in any
    // form, including one that tracks quotes but not escapes.
    let Look::Is(document) =
        Format::Markdown.read("{\"pin\": {\"rust\": \"1.97.1\"}, \"brace\": \"}\"}\n# heading\n")
    else {
        panic!("a leading JSON object did not read as a document");
    };
    assert_eq!(
        document.at("pin.rust"),
        Look::Is(&Node::Text("1.97.1".to_owned()))
    );
    assert_eq!(
        document.at("brace"),
        Look::Is(&Node::Text("}".to_owned())),
        "the object was cut short at a brace inside a string"
    );
}

#[test]
fn a_leading_brace_that_is_not_an_object_is_prose() {
    // The unfenced form is the only admitted one with no delimiter, so it is the
    // only one that can claim bytes an author never offered as frontmatter —
    // and `budget` shares this split, so a false positive stops a file being
    // charged for its own content. Requiring a parsed OBJECT is the bound.
    //
    // Fails by: accepting any leading JSON value, or by treating a leading `{`
    // as a fence opener before the parse has agreed that it is one.
    for text in [
        // A JSON array is a value and is not frontmatter.
        "[1, 2]\n# heading\n",
        // A bare scalar likewise.
        "\"just a string\"\n# heading\n",
        // An object that does not parse is not a document this reader failed on
        // — nothing says the author meant frontmatter rather than prose opening
        // with a brace, and guessing is how prose becomes a document.
        "{\"pin\": {\"rust\": }\n# heading\n",
        // A brace mid-sentence, which is the ordinary markdown case.
        "the shape is {\"a\": 1}\n",
    ] {
        assert_eq!(
            Format::Markdown.read(text),
            Look::IsNot,
            "a leading brace that is not an object was read as frontmatter"
        );
    }
}

#[test]
fn a_fence_that_is_not_the_first_line_is_prose_in_every_dialect() {
    // CLOUD-1787's strictness, carried to the delimiters CLOUD-1886 adds rather
    // than relaxed by them. Hugo skips leading blank lines and whitespace before
    // the delimiter; following it would turn a `+++` opening a section into a
    // document.
    //
    // Fails by: searching for an opener anywhere in the file, or by trimming
    // leading blank lines before looking.
    let mut seen = 0usize;
    for opener in ["+++", ";;;", "---toml"] {
        for text in [
            format!("# heading\n{opener}\n[pin]\nrust = \"1.97.1\"\n{opener}\n"),
            format!("\n{opener}\n[pin]\nrust = \"1.97.1\"\n{opener}\n"),
            // Opened and never closed: guessing where it ends is the same error
            // as finding one mid-file.
            format!("{opener}\n[pin]\nrust = \"1.97.1\"\n\n# heading\n"),
        ] {
            assert_eq!(
                Format::Markdown.read(&text),
                Look::IsNot,
                "{opener} was read as a fence where it does not lead the file"
            );
            seen += 1;
        }
    }
    // ANTI-VACUITY: the nested loops are two tables, and either being empty
    // would pass.
    assert_eq!(seen, 9);
}

#[test]
fn an_unknown_tag_is_not_a_fence_and_never_a_guess() {
    // Guessing which parser `---xml` meant is the same error as guessing where
    // an unterminated fence ends, and it is the worse one: it would hand an
    // author's bytes to a parser they did not name.
    //
    // Fails by: treating any `---<word>` opener as a fence and falling back to
    // one dialect for the tags it does not know.
    assert_eq!(
        Format::Markdown.read("---xml\n<pin rust=\"1.97.1\"/>\n---\n# heading\n"),
        Look::IsNot
    );
    // The control: the same shape under a tag that IS declared reads, so the
    // case above is about the tag and not about the fixture.
    assert!(matches!(
        Format::Markdown.read("---yaml\npin:\n  rust: \"1.97.1\"\n---\n# heading\n"),
        Look::Is(_)
    ));
}

#[test]
fn an_empty_fence_is_an_empty_document_in_every_dialect() {
    // The empty-block answer is decided BEFORE the dialect is dispatched, and
    // must be, because the three parsers disagree about empty input in three
    // directions: an empty YAML stream is `CouldNotLook`, an empty TOML document
    // is a valid empty table, and empty JSON is an EOF error. Dispatching first
    // makes one fence concept answer three ways depending on which delimiter the
    // author reached for.
    //
    // Fails by: moving the `block.trim().is_empty()` check behind the dispatch,
    // which reddens the YAML and JSON rows and leaves TOML passing — the shape
    // that makes this look like a YAML bug rather than an ordering one.
    let empty = Node::Map(std::collections::BTreeMap::new());
    let mut seen = 0usize;
    for text in [
        "---\n---\n# heading\n",
        "+++\n+++\n# heading\n",
        ";;;\n;;;\n# heading\n",
        "---toml\n---\n# heading\n",
        // The unfenced form reaches the same value by a different route: `{}`
        // is not an empty BLOCK, it is an object that parses to no keys. Both
        // must answer present-and-empty or the two routes disagree.
        "{}\n# heading\n",
    ] {
        let Look::Is(document) = Format::Markdown.read(text) else {
            panic!("an empty fence did not read as a document");
        };
        assert_eq!(document, empty);
        // Looked, and the key is not there — which is NOT the same answer as the
        // file having no fence at all.
        assert_eq!(document.at("name"), Look::IsNot);
        seen += 1;
    }
    assert_eq!(seen, 5);
}

#[test]
fn a_malformed_block_is_could_not_look_in_every_fenced_dialect() {
    // The fence IS there and its contents are not that dialect's syntax, which
    // is a different non-answer from having no fence: `CouldNotLook` says the
    // reader could not read it, and sends an author to the block. Each fixture
    // is malformed in its own dialect's way, because a blob every parser rejects
    // proves nothing about any of them.
    //
    // Fails by: collapsing a parse failure inside a recognised fence into
    // `IsNot`, which reports a fence that is sitting on line 1 as absent — the
    // exact harm CLOUD-1886 is filed against, reintroduced one layer in.
    let mut seen = 0usize;
    for (dialect, text) in [
        ("toml", "+++\n[pin\nrust = \n+++\n# heading\n"),
        (
            "json-fenced",
            ";;;\n{\"pin\": {\"rust\": }\n;;;\n# heading\n",
        ),
        ("tagged-toml", "---toml\n[pin\nrust = \n---\n# heading\n"),
        (
            "tagged-json",
            "---json\n{\"pin\": {\"rust\": }\n---\n# heading\n",
        ),
        (
            "tagged-yaml",
            "---yaml\npin:\n\t- bad tab indent\n  - and: [unclosed\n---\n# heading\n",
        ),
    ] {
        assert_eq!(
            Format::Markdown.read(text),
            Look::CouldNotLook,
            "{dialect} read a malformed block as an answer"
        );
        seen += 1;
    }
    assert_eq!(seen, 5);
}

#[test]
fn a_markdown_body_never_reaches_a_parser_in_any_dialect() {
    // CLOUD-1787's defect, asked of the dialects CLOUD-1886 adds. Identical
    // correct frontmatter; only the body varies, over the shapes measured
    // failing when the file was read as one stream. A `+++` fence is the sharper
    // case than the `---` one above it, because a markdown body is not
    // accidentally valid TOML in the way it is accidentally valid YAML — so a
    // reader that leaked the body here would fail loudly rather than subtly.
    //
    // Fails by: reading past the closing delimiter, or by taking the LAST
    // delimiter in the file rather than the first one that closes the fence.
    const FRONTMATTER: &str = "+++\n[pin]\nrust = \"1.97.1\"\n+++\n";
    let mut seen = 0usize;
    for body in [
        "prose only.\n",
        "*emphasis*, **bold**, Rate: 3:1\n",
        "- [ ] a task\n",
        "| a | b |\n| - | - |\n| 1 | 2 |\n",
        "> **HEADING** text\n",
        // A body carrying the opening delimiter again, which is what a reader
        // scanning for the last one gets wrong.
        "a thematic break follows\n\n+++\n\nmore prose\n",
    ] {
        let text = format!("{FRONTMATTER}{body}");
        let Look::Is(document) = Format::Markdown.read(&text) else {
            panic!("a markdown body changed whether the frontmatter parsed");
        };
        assert_eq!(
            document.at("pin.rust"),
            Look::Is(&Node::Text("1.97.1".to_owned())),
            "a markdown body changed what the frontmatter said"
        );
        seen += 1;
    }
    assert_eq!(seen, 6);
}

#[test]
fn markdown_is_declarable_by_extension_and_names_no_second_parser() {
    // `.md` was a load-time refusal before CLOUD-1787 ("this build has no parser
    // for that extension"), so widening it breaks no config that could exist.
    assert_eq!(Format::for_path("notes/entity.md"), Some(Format::Markdown));
    assert!(Format::Markdown.parseable());
    assert_eq!(Format::Markdown.as_str(), "markdown");
    // CLOUD-846's refusal stands: the frontmatter is YAML read by the one YAML
    // reader, and no markdown grammar was added. A file whose fence holds YAML
    // and a YAML file holding the same bytes are the same document.
    let Look::Is(fenced) = Format::Markdown.read("---\npin:\n  rust: \"1.97.1\"\n---\nbody\n")
    else {
        panic!("the fence did not parse");
    };
    let Look::Is(plain) = Format::Yaml.read("pin:\n  rust: \"1.97.1\"\n") else {
        panic!("the YAML did not parse");
    };
    assert_eq!(fenced, plain);
}

#[test]
fn all_covers_every_format() {
    // The totality anchor, in `RuleKind::ALL`'s shape: the match below is
    // exhaustive by the compiler, and this asserts `ALL` agrees with it.
    let mut seen = Vec::new();
    for format in Format::ALL {
        match format {
            Format::Toml
            | Format::Yaml
            | Format::Json
            | Format::Json5
            | Format::Pkl
            | Format::Markdown => {
                seen.push(format.as_str());
            }
        }
    }
    assert_eq!(seen, ["toml", "yaml", "json", "json5", "pkl", "markdown"]);
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
