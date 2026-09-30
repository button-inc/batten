//! Every rule declares its remedy: `fix` or `no_fix_reason`, exactly one, and a
//! reason names its class and the missing substrate (CLOUD-1576).
//!
//! The mutations this suite reddens, declared in `crates/batten/src/remedy.rs`:
//!
//! MUTANT fix-and-reason-both-admitted|
//! MUTANT empty-fix-reason-admitted|

use batten::waiver::Date;

const COMMAND: &str = "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"command\"\nglob = \"**/*.rs\"\n\
                       check = \"true\"\nseverity = \"deny\"\nscope = \"tree\"\n";
const FORBID: &str = "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
                      pattern = \"TODO\"\nseverity = \"deny\"\nscope = \"tree\"\n";

fn with(base: &str, extra: &str) -> String {
    format!("{base}{extra}")
}

fn smells(text: &str) -> Vec<&'static str> {
    let today = Date::parse("2026-09-30").unwrap();
    batten::lint::smells(text, "test", None, today, &[])
        .unwrap()
        .into_iter()
        .map(|smell| smell.id)
        .collect()
}

#[test]
fn a_row_with_both_keys_is_malformed() {
    let text = with(
        COMMAND,
        "fix = \"true\"\nno_fix_reason = \"class 3 (review): a judgement\"\n",
    );
    let err = batten::config::parse(&text, "test").unwrap_err();
    assert!(format!("{err:#}").contains("never both"), "{err:#}");
    assert!(batten::remedy::malformed(Some("true"), Some("class 3 (x): y")).is_some());
}

#[test]
fn a_blank_reason_is_malformed() {
    for blank in ["", "   ", "\t\n"] {
        let text = with(FORBID, &format!("no_fix_reason = {blank:?}\n"));
        let err = batten::config::parse(&text, "test").unwrap_err();
        assert!(
            format!("{err:#}").contains("is blank"),
            "{blank:?}: {err:#}"
        );
    }
}

#[test]
fn one_key_alone_is_well_formed() {
    // The anti-vacuity mirror: the refusals above would pass on a loader that
    // refused every row, so a single key of either kind must load.
    batten::config::parse(&with(COMMAND, "fix = \"true\"\n"), "test").unwrap();
    batten::config::parse(
        &with(
            FORBID,
            "no_fix_reason = \"class 3 (review): a judgement\"\n",
        ),
        "test",
    )
    .unwrap();
}

#[test]
fn a_row_declaring_neither_is_a_smell() {
    assert!(smells(FORBID).contains(&"remedy-undeclared"));
}

#[test]
fn an_unclassed_reason_is_a_smell_and_a_classed_one_is_clean() {
    let unclassed = with(FORBID, "no_fix_reason = \"delete the literal\"\n");
    assert!(smells(&unclassed).contains(&"fix-reason-unclassed"));
    let classed = with(
        FORBID,
        "no_fix_reason = \"class 2 (a codemod verb): delete the literal\"\n",
    );
    let found = smells(&classed);
    assert!(!found.contains(&"fix-reason-unclassed"), "{found:?}");
    assert!(!found.contains(&"remedy-undeclared"), "{found:?}");
    let fixed = smells(&with(COMMAND, "fix = \"true\"\n"));
    assert!(!fixed.contains(&"remedy-undeclared"), "{fixed:?}");
}

#[test]
fn the_class_grammar_is_exact() {
    use batten::remedy::classified;
    assert!(classified("class 1 (a YAML backend): pin the SHA"));
    assert!(classified("class 3 (review disposition): walk callers"));
    for bad in [
        "class 4 (x): y",
        "class 1: y",
        "class 1 (): y",
        "class 1 (x):",
        "class 1 (x) y",
        "Class 1 (x): y",
        "delete it",
    ] {
        assert!(!classified(bad), "{bad}");
    }
}

#[test]
fn every_rule_in_this_repository_declares_its_remedy() {
    // The whole-tree instance of the predicate, over this repository's own
    // authority — the consumer this gate exists for is first of all this one.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join("batten.toml")).unwrap();
    let found: Vec<_> = smells(&text)
        .into_iter()
        .filter(|id| *id == "remedy-undeclared" || *id == "fix-reason-unclassed")
        .collect();
    assert!(found.is_empty(), "{} rows", found.len());
}
