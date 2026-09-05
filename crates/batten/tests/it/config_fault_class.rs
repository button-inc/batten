//! End-to-end tests over the compiled binary: a config fault names a declared
//! class, and that class stays reachable while the config is broken (CLOUD-1313).
//!
//! # Why this tier, and why a unit test cannot stand in for it
//!
//! `config.rs`'s own census proves the wrapping is written. It reads source
//! text, so it cannot tell a class that is attached from one that is attached
//! and then discarded somewhere between `parse_ungated` and the process's exit
//! code — which is exactly the shape of the defect CLOUD-1049 recorded one
//! surface over, where a correct projection was thrown away by a guard one line
//! later and every predicate in the module went quiet at exit 0.
//!
//! So the assertion here is over stderr and the exit code, which is what a
//! consumer actually gets.
//!
//! # The second arm is the load-bearing one
//!
//! `batten policy explain` loads the config to answer. A config-fault class is
//! therefore the one class whose remedy channel is dark at precisely the moment
//! it fires, unless the class resolves from the vendored table with no config
//! load. `explain_over` asserts that with the broken config still in place.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::Fixture;

/// A config whose ONLY fault is in the named table.
///
/// Every row deserializes cleanly and fails its table's validator, which is the
/// distinction that makes these cases reach the class at all: a row that fails
/// `toml::from_str` is refused before any validator runs and carries no class by
/// design.
const FAULTS: &[(&str, &str, &str)] = &[
    (
        "verb declare refused",
        "verb",
        "version = 1\n\
         [[verb]]\nverb = \"frobnicate\"\neffect = \"write\"\n\
         [[verb]]\nverb = \"frobnicate\"\neffect = \"write\"\n",
    ),
    (
        "pattern declare refused",
        "pattern",
        "version = 1\n[[pattern]]\nid = \"unclosed\"\nregex = \"[\"\n",
    ),
    (
        "verdict declare refused",
        "verdict",
        "version = 1\n\
         [[verdict]]\nid = \"notthreewords\"\ngloss = \"a gloss\"\nclass = \"a class\"\n",
    ),
    (
        "redirect declare refused",
        "redirect",
        "version = 1\n\
         [[redirect]]\nglob = \"*.frob\"\nmutation = \"mise run fmt\"\n\
         [[redirect]]\nglob = \"*.frob\"\nmutation = \"mise run fmt\"\n",
    ),
    (
        "marker declare refused",
        "marker",
        "version = 1\n[[marker]]\nid = \"blank\"\ntoken = \"\"\n",
    ),
    (
        "rule declare refused",
        "rule",
        "version = 1\n[[rule]]\nid = \"unsevered\"\nkind = \"policy\"\n",
    ),
    (
        "output declare refused",
        "exec_pattern",
        "version = 1\n\
         [[exec_pattern]]\nid = \"twice\"\npattern = \"x\"\nreason = \"r\"\n\
         [[exec_pattern]]\nid = \"twice\"\npattern = \"y\"\nreason = \"r\"\n",
    ),
    // The SECOND `OutputPattern` table, and it earns its own row here for the
    // reason it earns its own class: the fault is byte-identical to the one above
    // — a duplicate id — and only the table it sits in decides which file an
    // author has to open. A case reaching one class over both tables would report
    // the wrong one and pass.
    (
        "environment declare refused",
        "verify_environment_pattern",
        "version = 1\n\
         [[verify_environment_pattern]]\nid = \"twice\"\npattern = \"x\"\nreason = \"r\"\n\
         [[verify_environment_pattern]]\nid = \"twice\"\npattern = \"y\"\nreason = \"r\"\n",
    ),
    (
        "waiver declare refused",
        "waiver",
        "version = 1\n\
         [[waiver]]\nrule = \"absent\"\nreason = \"r\"\nexpires = \"2999-01-01\"\n\
         [[waiver]]\nrule = \"absent\"\nreason = \"r\"\nexpires = \"2999-01-02\"\n",
    ),
    (
        "fact declare refused",
        "fact",
        "version = 1\n\
         [[fact]]\nname = \"twice\"\nreturns = \"opaque\"\n\
         [[fact]]\nname = \"twice\"\nreturns = \"opaque\"\n",
    ),
    (
        "mint declare refused",
        "mint",
        "version = 1\n\
         [[mint]]\nname = \"twice\"\ntool = \"Bash\"\nkey = \"branch\"\n\
         mode = \"replace\"\nbody = \"b\"\n\
         [[mint]]\nname = \"twice\"\ntool = \"Bash\"\nkey = \"branch\"\n\
         mode = \"replace\"\nbody = \"b\"\n",
    ),
    (
        "recorder declare refused",
        "recorder",
        "version = 1\n\
         [[recorder]]\nname = \"twice\"\nrecord = \"notes.md\"\ntool = \"Bash\"\n\
         key = \"branch\"\ncolumns = []\n\
         [[recorder]]\nname = \"twice\"\nrecord = \"notes.md\"\ntool = \"Bash\"\n\
         key = \"branch\"\ncolumns = []\n",
    ),
    (
        "provision declare refused",
        "provision",
        "version = 1\n\
         [[provision]]\nname = \"twice\"\nversion = \"1.0.0\"\nbinary = \"b\"\n\
         [[provision]]\nname = \"twice\"\nversion = \"1.0.0\"\nbinary = \"b\"\n",
    ),
    (
        "startup declare refused",
        "startup",
        "version = 1\n\
         [[startup]]\nid = \"twice\"\ngloss = \"g\"\ncheck = [\"true\"]\n\
         [[startup]]\nid = \"twice\"\ngloss = \"g\"\ncheck = [\"true\"]\n",
    ),
    // NOT a `Config` table: a remedy is resolved across the redirect, verb and
    // rule tables at once, which is why it is a call at the load rather than a
    // validator over one field — and why CLOUD-1189 could not declare a class
    // for it, which is the case that produced CLOUD-1313.
    //
    // The glob is unique, so `redirect::validate` passes and the refusal comes
    // from the resolver rather than from the table it is written in.
    //
    // Two things about this remedy are load-bearing and both were got wrong
    // before they were read (`redirect::invocation`):
    //
    // It names a `batten` verb, because the resolver decides invocations of the
    // crate's OWN surface and deliberately leaves `mise run …` or `git …` to the
    // operator's PATH — a second authority. A fixture naming a mise task exits 0.
    //
    // And it is written as a CODE SPAN, because the resolver reads backtick
    // spans and deliberately under-denies a command named in bare prose. A
    // fixture without the backticks also exits 0. Either mistake ships a case
    // that asserts a refusal it never reaches.
    (
        "remedy resolve missing",
        "redirect.mutation",
        "version = 1\n\
         [[redirect]]\nglob = \"*.frob\"\nmutation = \"run `batten frobnicate the thing`\"\n",
    ),
];

fn repo_with(name: &str, config: &str) -> std::path::PathBuf {
    Fixture::new(name).config(config).build()
}

/// The `batten: ` prefix `output::error` writes, then the class, then the prose.
fn refusal_names(stderr: &str, class: &str) -> bool {
    stderr.contains(&format!("batten: {class}: "))
}

#[test]
fn every_config_fault_names_its_table_s_declared_class() {
    for (class, table, config) in FAULTS {
        let dir = repo_with(&format!("fault-{table}"), config);
        let output = common::run(&dir, &["check"]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Exit 1 and not 2: a config fault is a statement about the invocation,
        // never a policy verdict about the repository (house style §7).
        assert_eq!(
            output.status.code(),
            Some(1),
            "`[[{table}]]` fault should be a usage error, got: {stderr}"
        );
        assert!(
            refusal_names(&stderr, class),
            "a `[[{table}]]` fault must name `{class}`, got: {stderr}"
        );
    }
}

/// The remedy channel stays open over the config that broke.
///
/// This is the constraint the row was filed without: `explain` resolves through
/// the config loader, so before CLOUD-1313's first half a class raised BY a
/// malformed config could not be looked up WHILE that config was malformed.
#[test]
fn a_config_fault_s_class_explains_while_the_config_is_still_broken() {
    for (class, table, config) in FAULTS {
        let dir = repo_with(&format!("explain-over-fault-{table}"), config);
        let output = common::run(&dir, &["policy", "explain", class]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "`{class}` must explain over the config that raises it, got: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(class),
            "the explanation must name the class it answers for, got: {stdout}"
        );
    }
}

/// Every class the loader can raise has a fixture that actually reaches it.
///
/// The reachability clause, and it is the one a reader would otherwise take on
/// trust: a class declared, wrapped and never raised is the dead gate this
/// repository exists to refuse, and it looks identical to a live one from every
/// angle except a case that fires it. `Native::CONFIG_FAULTS` is the authority
/// both this suite and `config.rs`'s census are held to, so a fourteenth table
/// cannot arrive wrapped-but-untested.
#[test]
fn every_class_the_loader_raises_has_a_case_above() {
    let mut covered: Vec<&str> = FAULTS.iter().map(|(class, _, _)| *class).collect();
    let mut declared: Vec<&str> = batten::verdict::Native::CONFIG_FAULTS
        .iter()
        .map(|native| native.id())
        .collect();
    covered.sort_unstable();
    declared.sort_unstable();
    assert_eq!(
        covered, declared,
        "a config-fault class with no case above is reachable only in principle"
    );
}

/// The anti-vacuity mirror: a well-formed config still loads and says nothing.
///
/// Without this the suite above is satisfied by a loader that refuses every
/// config, which would name the right class every time and be useless.
#[test]
fn a_config_with_no_fault_raises_no_class() {
    let dir = repo_with("fault-none", "version = 1\n");
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("declare refused"),
        "a clean config raises no table class, got: {stderr}"
    );
}

/// A fault the loader cannot attribute to a table still refuses, classless.
///
/// `None` on `UsageError::verdict` is a decision rather than a gap: a file that
/// will not parse as TOML failed before any validator ran, so naming a table
/// would be inventing an attribution the loader does not have.
#[test]
fn an_unparseable_config_refuses_without_inventing_a_table() {
    let dir = repo_with("fault-unparseable", "version = 1\n[[verb]]\nverb = \n");
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid config") && !stderr.contains("declare refused"),
        "a parse failure predates every validator, so it names no table: {stderr}"
    );
}

/// This repository's own committed authority still loads.
///
/// The other half of the mirror, over the real tree rather than a fixture —
/// thirteen new classes are thirteen new ways to refuse a config that was fine.
#[test]
fn the_committed_authority_still_loads() {
    let output = common::run(&common::at_root("."), &["config", "show"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's own config must still load: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
