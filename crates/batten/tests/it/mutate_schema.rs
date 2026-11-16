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
pub fn five() -> u8 {\n    5\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {\n        assert_eq!(super::add(2, 3), super::five());\n    }\n\
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

/// A committed fixture crate whose library is [`LIB`], with a nextest profile
/// that ends a hang in seconds.
fn seeded(name: &str) -> std::path::PathBuf {
    seeded_with(name, LIB)
}

/// [`seeded`] over the library `lib`.
fn seeded_with(name: &str, lib: &str) -> std::path::PathBuf {
    let repo = common::scratch_repo(name);
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
    common::write(&repo, "src/lib.rs", lib);
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "seed"]);
    repo
}

/// The listing every verdict comes from, written under the case's own scratch
/// `name` where the sweep reads it.
fn listing(name: &str) -> String {
    let add = ("add", "-> u8", [1, 1, 3, 2]);
    let untested = ("untested", "-> bool", [7, 1, 9, 2]);
    let listing = serde_json::json!([
        mutant("kill", "BinaryOperator", "*", [2, 7, 2, 8], add),
        mutant(
            "survive",
            "BinaryOperator",
            "<=",
            [5, 7, 5, 9],
            ("same", "-> bool", [4, 1, 6, 2]),
        ),
        mutant("unreached", "FnValue", "false", [8, 5, 8, 9], untested),
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
        mutant("field", "StructField", "", [8, 5, 8, 9], untested),
    ]);
    let file = common::scratch(name).join("listing.json");
    std::fs::write(&file, listing.to_string()).unwrap();
    file.to_string_lossy().into_owned()
}

/// Whether reach runs cases under a tracer on this host, as the schema asks:
/// never from a process already traced, as this case is inside a sweep's reach.
fn traced() -> bool {
    cfg!(target_os = "linux")
        && !std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("TracerPid:"))
                .is_some_and(|pid| pid.trim() != "0")
        })
        && std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|dir| dir.join("strace").is_file())
}

/// The verdict counts every sweep of the fixture reaches.
const COUNTS: &str =
    "{\"caught\": 2, \"missed\": 1, \"timeout\": 1, \"uncovered\": 1}, 1 unviable, 2 classic";

/// Every verdict a sweep can reach, each from its own mutant: a kill, a
/// survivor a case reaches, a site no case reaches, a hang, and a mutant that
/// does not compile; then a second sweep over the same tree keeps every one,
/// knows the unviable mutant without building it, and reuses the reach record.
///
/// Fails by: an unviable mutant judged (it would survive), a hang read as a
/// kill, a site no case reaches judged by a run, a failed case read as a
/// survivor, the exit not saying a mutant survived, a second sweep that
/// rebuilds what the first proved unviable, a new helper or const moving every
/// key, a traced case keyed on a non-Rust file it never read, or
/// an executed function's non-body change moving none.
#[test]
fn a_sweep_judges_every_verdict_and_a_second_reuses_the_first() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = seeded("mutate-schema-sweep");
    let file = listing("mutate-schema-listing");
    let sweep = || {
        let output = common::run(&repo, &["__mutate-schema", &file, "2"]);
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, said, err) = sweep();
    assert_eq!(code, Some(2), "a survivor exits 2\n{said}\n{err}");
    assert!(said.contains(COUNTS), "{said}\n{err}");
    for line in [
        "missed\tsurvive\n",
        "uncovered\tunreached\n",
        "timeout\thang\n",
        "build 1 refused 1 mutant(s), handed back 1 for a const caller",
        "classic\tconst-caller\n",
        "classic\tfield\n",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    let (code, again, err) = sweep();
    assert_eq!(code, Some(2), "{again}\n{err}");
    // NO BUILD ROUND REDISCOVERS WHAT THE FIRST SWEEP FOUND: the unviable
    // mutant and the const-caller hand-back are both journaled, so the second
    // sweep's first build is clean — once, the hand-back cost a refused build
    // on every sweep.
    for line in [
        "1 unviable, 1 handed back and 0 unprobed file(s) known from earlier runs",
        "build 1 clean, 1 unviable",
        "reused 5 of 5 verdict(s)",
        COUNTS,
    ] {
        assert!(again.contains(line), "{line:?} in {again}\n{err}");
    }
    // THE SOUNDNESS CASE (Ekstazi; RTS++): an edit to a function a case
    // executes, though it is neither the mutated function nor the test, moves
    // that case's key. `adds` calls `five`, so the two mutants it reaches are
    // judged again; the three no case running `five` reaches are reused.
    let edited = LIB.replace("    5\n}", "    4 + 1\n}");
    common::write(&repo, "src/lib.rs", &edited);
    let (code, third, err) = sweep();
    assert_eq!(code, Some(2), "{third}\n{err}");
    assert!(third.contains("reused 3 of 5 verdict(s)"), "{third}\n{err}");
    assert!(
        third.contains("reach carried 2 case(s) across the change"),
        "only adds, which runs five, is recorded again: {third}"
    );
    assert!(third.contains(COUNTS), "{third}");
    // THE REUSE CASE: a new function no case runs, with a doc comment, and a
    // new const no case names move no key: a function is its own probe's, and
    // a const keys only the cases whose functions name it.
    let grown = format!(
        "{edited}/// A helper no case runs.\npub fn helper(x: u8) -> u8 {{\n    x\n}}\n\
         pub const UNNAMED: u8 = 7;\n"
    );
    common::write(&repo, "src/lib.rs", &grown);
    let (code, fourth, err) = sweep();
    assert_eq!(code, Some(2), "{fourth}\n{err}");
    assert!(
        fourth.contains("reach carried 3 case(s) across the change"),
        "an added item re-records no case: {fourth}"
    );
    assert!(
        fourth.contains("reused 5 of 5 verdict(s)"),
        "{fourth}\n{err}"
    );
    // AND ITS SOUNDNESS HALF: what leaves the skeleton is in the item's probe,
    // so a change to `five` outside its body still moves the cases running it.
    let inlined = grown.replace("pub fn five()", "#[inline(never)]\npub fn five()");
    common::write(&repo, "src/lib.rs", &inlined);
    let (code, fifth, err) = sweep();
    assert_eq!(code, Some(2), "{fifth}\n{err}");
    assert!(fifth.contains("reused 3 of 5 verdict(s)"), "{fifth}\n{err}");
    assert!(
        fifth.contains("reach carried 2 case(s) across the change"),
        "{fifth}"
    );
    // THE CASE #1276 PAID SIX HOURS FOR: a non-Rust file no case reads. A
    // traced case keys on the files it touched, so every verdict is reused;
    // untraced, every case keys on every non-Rust file and is judged again.
    common::write(&repo, "notes.txt", "a note no case reads\n");
    let (code, sixth, err) = sweep();
    assert_eq!(code, Some(2), "{sixth}\n{err}");
    assert_eq!(
        sixth.contains("reused 5 of 5 verdict(s)"),
        traced(),
        "traced: {}\n{sixth}\n{err}",
        traced()
    );
    let carried = if traced() {
        "reach carried 3 case(s)"
    } else {
        "reach carried 0 case(s)"
    };
    assert!(sixth.contains(carried), "{carried:?} in {sixth}");
}

/// A fixture case that, when `BATTEN_FIXTURE_STOP` is set, SIGKILLs the sweep
/// above it — and every process between — before it reaches its end-of-run
/// seal: a kill partway through reach, at a point name order makes exact.
/// It runs `five` first, so the edit that moves `adds` moves it too and it is
/// recorded again rather than carried; `five` holds no mutant, so no verdict
/// changes. Unset, it passes having done only that.
const STOPPER: &str = "    #[test]\n    fn zz_stop() {\n\
        assert_eq!(super::five(), 5);\n\
        if std::env::var_os(\"BATTEN_FIXTURE_STOP\").is_none() {\n            return;\n        }\n\
        let (mut pid, mut chain) = (std::process::id(), Vec::new());\n\
        loop {\n\
            let status = std::fs::read_to_string(format!(\"/proc/{pid}/status\")).unwrap();\n\
            let parent: u32 = status.lines().find_map(|l| l.strip_prefix(\"PPid:\")).unwrap().trim().parse().unwrap();\n\
            assert!(parent > 1, \"no sweep above this case\");\n\
            chain.push(parent);\n\
            let cmdline = std::fs::read(format!(\"/proc/{parent}/cmdline\")).unwrap();\n\
            if String::from_utf8_lossy(&cmdline).contains(\"__mutate-schema\") {\n                break;\n            }\n\
            pid = parent;\n\
        }\n\
        for pid in chain.iter().rev() {\n\
            let _ = std::process::Command::new(\"kill\").args([\"-9\", &pid.to_string()]).status();\n\
        }\n    }\n";

/// A sweep killed partway through reach keeps every case it finished: the next
/// sweep seals what the stopped one left, against the snapshot it ran over, and
/// carries it across a head that moved meanwhile.
///
/// Fails by: a finished case's record lost to the kill (it records again, so
/// fewer are carried), a leftover sealed over the wrong snapshot (its digest
/// moves, so it is not carried), or verdicts that differ from an unkilled run.
#[test]
fn a_sweep_killed_in_reach_keeps_every_case_it_finished() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let _ = common::require_bin("nextest", "cargo-nextest");
    let lib = {
        let end = LIB
            .rfind("\n}\n")
            .expect("the tests module closes the library");
        format!("{}\n{STOPPER}}}\n", &LIB[..end])
    };
    let repo = seeded_with("mutate-schema-killed", &lib);
    let file = listing("mutate-schema-killed-listing");
    // ONE CASE AT A TIME, IN NAME ORDER: `adds`, `compares`, `triples`, then
    // the stopper — so the kill lands at the same case on every run.
    let sweep = |stop: bool| {
        let mut command = common::batten();
        command
            .args(["__mutate-schema", &file, "2"])
            .current_dir(&repo)
            .env("NEXTEST_TEST_THREADS", "1");
        if stop {
            command.env("BATTEN_FIXTURE_STOP", "1");
        }
        let output = command.streamed_output().expect("run batten");
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, first, err) = sweep(false);
    assert_eq!(code, Some(2), "{first}\n{err}");
    assert!(first.contains(COUNTS), "{first}\n{err}");
    // The head moves under `adds` (it runs `five`), and the stopper fires once
    // `adds` has re-recorded and the two carried cases have been skipped.
    let edited = lib.replace("    5\n}", "    4 + 1\n}");
    common::write(&repo, "src/lib.rs", &edited);
    let (code, killed, err) = sweep(true);
    assert_ne!(code, Some(0), "{killed}\n{err}");
    assert_ne!(code, Some(2), "the sweep never reported: {killed}\n{err}");
    assert!(
        !killed.contains(COUNTS),
        "killed before any verdict: {killed}"
    );
    // And moves again, by nothing any case runs.
    let grown = format!("{edited}pub fn helper(x: u8) -> u8 {{\n    x\n}}\n");
    common::write(&repo, "src/lib.rs", &grown);
    let (code, third, err) = sweep(false);
    assert_eq!(code, Some(2), "{third}\n{err}");
    for line in [
        "sealed 1 case(s) a stopped run finished",
        "reach carried 3 case(s)",
        COUNTS,
    ] {
        assert!(third.contains(line), "{line:?} in {third}\n{err}");
    }
}
