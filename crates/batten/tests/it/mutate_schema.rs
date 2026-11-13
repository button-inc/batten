//! The schema sweep end to end, over a crate small enough to build in seconds:
//! one build with every mutant switched in, the unviable loop, the reach run,
//! each verdict judged by switch, and a second sweep reusing the first's.

use crate::common;

/// The fixture crate's library. Each function is the site of one verdict.
const LIB: &str = "pub fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\n\
pub fn same(a: u8, b: u8) -> bool {\n    a == b\n}\n\
pub fn untested() -> bool {\n    true\n}\n\
pub const fn two() -> u8 {\n    2\n}\n\
pub const TWO: u8 = two();\n\
pub const fn three() -> u8 {\n    3\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {\n        assert_eq!(super::add(2, 3), 5);\n    }\n\
    #[test]\n    fn compares() {\n        assert!(super::same(1, 1));\n    }\n\
    #[test]\n    fn triples() {\n        assert_eq!(super::three(), 3);\n    }\n}\n";

/// One mutant as `cargo mutants --list --json` prints it.
fn mutant(
    name: &str,
    genre: &str,
    replacement: &str,
    span: [usize; 4],
    function: (&str, &str, [usize; 4]),
) -> serde_json::Value {
    let at = |s: [usize; 4]| {
        serde_json::json!({
            "start": {"line": s[0], "column": s[1]},
            "end": {"line": s[2], "column": s[3]},
        })
    };
    serde_json::json!({
        "name": name,
        "file": "src/lib.rs",
        "package": "fix",
        "genre": genre,
        "replacement": replacement,
        "span": at(span),
        "function": {
            "function_name": function.0,
            "return_type": function.1,
            "span": at(function.2),
        },
    })
}

/// Every verdict a sweep can reach, each from its own mutant: a kill, a
/// survivor a case reaches, a site no case reaches, a hang, and a mutant that
/// does not compile; then a second sweep over the same tree keeps every one,
/// knows the unviable mutant without building it, and reuses the reach record.
///
/// Fails by: an unviable mutant judged (it would survive), a hang read as a
/// kill, a site no case reaches judged by a run, a failed case read as a
/// survivor, the exit not saying a mutant survived, or a second sweep that
/// rebuilds what the first proved unviable.
#[test]
fn a_sweep_judges_every_verdict_and_a_second_reuses_the_first() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = common::scratch_repo("mutate-schema-sweep");
    common::write(
        &repo,
        "Cargo.toml",
        "[package]\nname = \"fix\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [workspace]\n\n[profile.mutants]\ninherits = \"test\"\n",
    );
    common::write(
        &repo,
        ".config/nextest.toml",
        "[profile.mutants]\nfail-fast = true\n\
         slow-timeout = { period = \"2s\", terminate-after = 2 }\n",
    );
    common::write(&repo, "src/lib.rs", LIB);
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "seed"]);
    let add = ("add", "-> u8", [1, 1, 3, 2]);
    let listing = serde_json::json!([
        mutant("kill", "BinaryOperator", "*", [2, 7, 2, 8], add),
        mutant(
            "survive",
            "BinaryOperator",
            "<=",
            [5, 7, 5, 9],
            ("same", "-> bool", [4, 1, 6, 2]),
        ),
        mutant(
            "unreached",
            "FnValue",
            "false",
            [8, 5, 8, 9],
            ("untested", "-> bool", [7, 1, 9, 2]),
        ),
        mutant("ill-typed", "FnValue", "\"x\"", [2, 5, 2, 10], add),
        mutant("hang", "FnValue", "loop {}", [2, 5, 2, 10], add),
        mutant(
            "const-caller",
            "FnValue",
            "0",
            [11, 5, 11, 6],
            ("two", "-> u8", [10, 1, 12, 2]),
        ),
        mutant(
            "const-kill",
            "FnValue",
            "0",
            [15, 5, 15, 6],
            ("three", "-> u8", [14, 1, 16, 2]),
        ),
        mutant(
            "field",
            "StructField",
            "",
            [8, 5, 8, 9],
            ("untested", "-> bool", [7, 1, 9, 2]),
        ),
    ]);
    let file = common::scratch("mutate-schema-listing").join("listing.json");
    std::fs::write(&file, listing.to_string()).unwrap();
    let file = file.to_string_lossy().into_owned();
    let sweep = || {
        let output = common::run(&repo, &["__mutate-schema", &file, "2"]);
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, said, err) = sweep();
    assert_eq!(code, Some(2), "a survivor exits 2\n{said}\n{err}");
    assert!(
        said.contains(
            "{\"caught\": 2, \"missed\": 1, \"timeout\": 1, \"uncovered\": 1}, 1 unviable, 2 classic"
        ),
        "{said}\n{err}"
    );
    assert!(said.contains("missed\tsurvive\n"), "{said}");
    assert!(said.contains("uncovered\tunreached\n"), "{said}");
    assert!(said.contains("timeout\thang\n"), "{said}");
    assert!(
        said.contains("build 1 refused 1 mutant(s), handed back 1 for a const caller"),
        "{said}"
    );
    assert!(said.contains("classic\tconst-caller\n"), "{said}");
    assert!(
        said.contains("classic\tfield\n"),
        "a handed-back mutant is named: {said}"
    );
    let (code, again, err) = sweep();
    assert_eq!(code, Some(2), "{again}\n{err}");
    assert!(
        again.contains("1 unviable known from earlier runs"),
        "{again}"
    );
    assert!(again.contains("build 2 clean, 1 unviable"), "{again}");
    assert!(
        again.contains(
            "{\"caught\": 2, \"missed\": 1, \"timeout\": 1, \"uncovered\": 1}, 1 unviable, 2 classic"
        ),
        "{again}\n{err}"
    );
}
