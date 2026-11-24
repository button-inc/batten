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
         [workspace]\n",
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

/// Whether reach runs cases under a tracer on this host ([`common::traced`]).
fn traced() -> bool {
    common::traced()
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
    // OFF CI (CLOUD-2850): under `CI` no stored verdict answers, and this case
    // is about the ones that do.
    let sweep = || {
        let output = common::batten()
            .args(["__mutate-schema", &file, "2"])
            .current_dir(&repo)
            .env_remove("CI")
            .streamed_output()
            .expect("run batten");
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, said, err) = sweep();
    assert_eq!(
        code,
        Some(3),
        "the fixture's hang is a timeout, and a timeout decides nothing, so the sweep exits 3 (W1, could-not-look outranks a survivor's 2)\n{said}\n{err}"
    );
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
    assert_eq!(code, Some(3), "{again}\n{err}");
    // NO BUILD ROUND REDISCOVERS WHAT THE FIRST SWEEP FOUND: the unviable
    // mutant and the const-caller hand-back are both journaled, so the second
    // sweep's first build is clean — once, the hand-back cost a refused build
    // on every sweep.
    for line in [
        "1 unviable, 1 handed back and 0 unprobed file(s) known from earlier runs",
        "build 1 clean, 1 unviable",
        // FOUR, NOT FIVE (W1): the hang's stored timeout decided nothing, so
        // it is judged again on every sweep and never reused.
        "reused 4 of 5 verdict(s)",
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
    assert_eq!(code, Some(3), "{third}\n{err}");
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
    assert_eq!(code, Some(3), "{fourth}\n{err}");
    assert!(
        fourth.contains("reach carried 3 case(s) across the change"),
        "an added item re-records no case: {fourth}"
    );
    assert!(
        fourth.contains("reused 4 of 5 verdict(s)"),
        "{fourth}\n{err}"
    );
    // AND ITS SOUNDNESS HALF: what leaves the skeleton is in the item's probe,
    // so a change to `five` outside its body still moves the cases running it.
    let inlined = grown.replace("pub fn five()", "#[inline(never)]\npub fn five()");
    common::write(&repo, "src/lib.rs", &inlined);
    let (code, fifth, err) = sweep();
    assert_eq!(code, Some(3), "{fifth}\n{err}");
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
    assert_eq!(code, Some(3), "{sixth}\n{err}");
    assert_eq!(
        sixth.contains("reused 4 of 5 verdict(s)"),
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
///
/// IT KILLS ONLY BEHIND FINISHED SIBLINGS: a sibling case's record without its
/// `done` means a case still runs beside the stopper, so the kill would land
/// at no exact point. The stopper then panics, saying so, instead of killing.
const STOPPER: &str = "    #[test]\n    fn zz_stop() {\n\
        assert_eq!(super::five(), 5);\n\
        if std::env::var_os(\"BATTEN_FIXTURE_STOP\").is_none() {\n            return;\n        }\n\
        let mine = std::path::PathBuf::from(std::env::var_os(\"BATTEN_MUTANT_RECORD\").unwrap());\n\
        for entry in std::fs::read_dir(mine.parent().unwrap()).unwrap() {\n\
            let dir = entry.unwrap().path();\n\
            if dir != mine && dir.join(\"case\").is_file() {\n\
                assert!(dir.join(\"done\").is_file(), \"a case still running beside the stopper: {}\", dir.display());\n\
            }\n\
        }\n\
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
/// A SWEEP UNDER A LAP SAYS IT MOVED (CLOUD-2369): one `mutant:changed` step
/// outlasted the 240-beat stall bound on #1276 while judging, and the lap was
/// cancelled as stalled. Each progress line is the supervising task's `Sig`.
#[test]
fn a_sweep_under_a_supervising_task_moves_its_signal() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = seeded("mutate-schema-signal");
    let file = listing("mutate-schema-signal-listing");
    let registered = common::batten()
        .args(["task", "register", "land", "515151", "verify"])
        .current_dir(&repo)
        .streamed_output()
        .expect("register the supervising task");
    assert!(
        registered.status.success(),
        "{}",
        common::stderr(&registered)
    );
    let output = common::batten()
        .args(["__mutate-schema", &file, "2"])
        .env("BATTEN_TASK_PID", "515151")
        .current_dir(&repo)
        .streamed_output()
        .expect("run the sweep");
    let said = common::stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(3),
        "{said}\n{}",
        common::stderr(&output)
    );
    assert_eq!(
        batten::task::read_field(&repo.join(".git"), "515151", "sig").as_deref(),
        Some("mutate schema: judged 5/5"),
        "the last progress line is the task's signal: {said}"
    );
}

/// A library one of whose cases fails before any mutant is switched in, and
/// reaches some sites but not others.
const RED_LIB: &str = "pub fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\n\
pub fn same(a: u8, b: u8) -> bool {\n    a == b\n}\n\
pub fn broken() -> u8 {\n    1\n}\n\
pub fn id(x: u8) -> u8 {\n    x\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {\n        assert_eq!(super::add(2, 3), 5);\n    }\n\
    #[test]\n    fn compares() {\n        assert!(super::same(1, 1));\n    }\n\
    #[test]\n    fn ids() {\n        let _ = super::id(1);\n    }\n\
    #[test]\n    fn red() {\n        let _ = super::add(1, 1) + super::broken() + super::id(0);\n\
        panic!(\"red before any mutant\");\n    }\n}\n";

/// The listing over [`RED_LIB`], one mutant per rule.
fn red_listing(name: &str) -> String {
    let listing = serde_json::json!([
        mutant(
            "kill",
            "BinaryOperator",
            "*",
            [2, 7, 2, 8],
            ("add", "-> u8", [1, 1, 3, 2])
        ),
        mutant(
            "survive",
            "BinaryOperator",
            "<=",
            [5, 7, 5, 9],
            ("same", "-> bool", [4, 1, 6, 2]),
        ),
        mutant(
            "poisoned",
            "FnValue",
            "0",
            [8, 5, 8, 6],
            ("broken", "-> u8", [7, 1, 9, 2]),
        ),
        mutant(
            "shielded",
            "FnValue",
            "0",
            [11, 5, 11, 6],
            ("id", "-> u8", [10, 1, 12, 2]),
        ),
    ]);
    let file = common::scratch(name).join("listing.json");
    std::fs::write(&file, listing.to_string()).unwrap();
    file.to_string_lossy().into_owned()
}

/// A CASE RED BEFORE ANY MUTANT POISONS ONLY WHAT IT REACHES (#1276: four red
/// cases out of ~10,500 left 12,452 mutants with no verdict). The red case is
/// a finding and never a kill; a mutant it does not reach is judged from its
/// green cases; a green kill stands whatever red case also reaches the site;
/// and a mutant a red case reaches that no green case kills is listed as
/// unjudged beside the survivors. The exit stays non-zero while one is red,
/// and a second sweep over the same tree keeps all of it: the red case is
/// never sealed as passing and carried past its failure.
///
/// Fails by: one red case refusing the whole sweep, the red case counted as
/// the kill of a mutant it reaches, a red-reached mutant read as caught,
/// missed or uncovered, a red case missing from the report, a zero exit, or a
/// second sweep carrying the red case as passed.
#[test]
fn a_red_baseline_case_poisons_only_the_mutants_it_reaches() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = seeded_with("mutate-schema-red", RED_LIB);
    let file = red_listing("mutate-schema-red-listing");
    let sweep = || {
        let output = common::run(&repo, &["__mutate-schema", &file, "2"]);
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, said, err) = sweep();
    assert_eq!(code, Some(2), "a red baseline case exits 2\n{said}\n{err}");
    for line in [
        "baseline-red\tfix tests::red\t",
        "red before any mutant",
        "missed\tsurvive\n",
        "unjudged (baseline-red: fix tests::red)\tpoisoned\n",
        "unjudged (baseline-red: fix tests::red)\tshielded\n",
        "{\"caught\": 1, \"missed\": 1, \"unjudged\": 2}, 0 unviable, 0 classic",
        "mutate schema: 1 baseline-red case(s), 2 unjudged mutant(s)",
    ] {
        assert!(said.contains(line), "{line:?} in {said}\n{err}");
    }
    assert!(!said.contains("\tkill\n"), "the green kill stands: {said}");
    let (code, again, err) = sweep();
    assert_eq!(code, Some(2), "{again}\n{err}");
    for line in [
        "reach carried 3 case(s)",
        "baseline-red\tfix tests::red\t",
        "unjudged (baseline-red: fix tests::red)\tpoisoned\n",
        "{\"caught\": 1, \"missed\": 1, \"unjudged\": 2}",
    ] {
        assert!(again.contains(line), "{line:?} in {again}\n{err}");
    }
    // FIXED, THE POISONED MUTANTS ARE JUDGED: nothing it said stands.
    let fixed = RED_LIB.replace("panic!(\"red before any mutant\");\n", "");
    assert_ne!(fixed, RED_LIB, "the fix removes the panic");
    common::write(&repo, "src/lib.rs", &fixed);
    let (code, third, err) = sweep();
    assert_eq!(code, Some(2), "{third}\n{err}");
    assert!(!third.contains("baseline-red"), "{third}\n{err}");
    assert!(!third.contains("unjudged"), "{third}\n{err}");
    assert!(
        third.contains("{\"caught\": 1, \"missed\": 3}"),
        "{third}\n{err}"
    );
}

/// A library with one case red only under the judge's own environment, and
/// one that needs its fixture directory inside the tree it was built from and
/// its temp directory outside it, as a plain run has them (CLOUD-2789).
const JUDGE_LIB: &str = "pub fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\n\
pub fn sneak() -> u8 {\n    1\n}\n\
pub fn three() -> u8 {\n    3\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {\n        assert_eq!(super::add(2, 3), 5);\n    }\n\
    #[test]\n    fn envy() {\n        let _ = super::add(1, 1) + super::sneak();\n\
        assert!(std::env::var_os(\"BATTEN_MUTANT\").is_none(), \"red under the judge\");\n    }\n\
    #[test]\n    fn intree() {\n        assert_eq!(super::three(), 3);\n\
        if std::env::var_os(\"BATTEN_MUTANT\").is_some() {\n\
            let tree = std::fs::canonicalize(env!(\"CARGO_MANIFEST_DIR\")).unwrap();\n\
            let fixtures = std::env::var_os(\"BATTEN_TEST_TMPDIR\").expect(\"a fixture root\");\n\
            let fixtures = std::fs::canonicalize(fixtures).unwrap();\n\
            assert!(fixtures.starts_with(&tree), \"{} outside {}\", fixtures.display(), tree.display());\n\
            let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();\n\
            assert!(!tmp.starts_with(&tree), \"{} inside {}\", tmp.display(), tree.display());\n\
        }\n    }\n}\n";

/// A JUDGING RUN'S OWN ENVIRONMENT GETS A CONTROL (W2): a case green under
/// reach but red under the judge's argv and env with no mutant active would
/// read as the kill of every mutant it reaches. One null-mutant run per sweep
/// finds it, and it is excluded exactly as a baseline-red case is; and the
/// judge's fixtures sit inside the mirror, so a case that needs its tree
/// around them kills its mutant there, while its temp directory stays outside
/// it, where a case that needs no checkout around its scratch finds none.
///
/// Fails by: the judge-only red case read as a kill (no control), it missing
/// from the report, or the in-tree case red under the judge (its fixtures
/// outside the mirror, or its temp directory inside it, CLOUD-2789), which
/// would leave `inner` unjudged.
#[test]
fn a_null_mutant_control_excludes_a_case_red_only_under_the_judge() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = seeded_with("mutate-schema-control", JUDGE_LIB);
    let listing = serde_json::json!([
        mutant(
            "kill",
            "BinaryOperator",
            "*",
            [2, 7, 2, 8],
            ("add", "-> u8", [1, 1, 3, 2])
        ),
        mutant(
            "sneaky",
            "FnValue",
            "0",
            [5, 5, 5, 6],
            ("sneak", "-> u8", [4, 1, 6, 2])
        ),
        mutant(
            "inner",
            "FnValue",
            "0",
            [8, 5, 8, 6],
            ("three", "-> u8", [7, 1, 9, 2])
        ),
    ]);
    let file = common::scratch("mutate-schema-control-listing").join("listing.json");
    std::fs::write(&file, listing.to_string()).unwrap();
    let output = common::run(&repo, &["__mutate-schema", &file.to_string_lossy(), "2"]);
    let (said, err) = (common::stdout(&output), common::stderr(&output));
    assert_eq!(output.status.code(), Some(2), "{said}\n{err}");
    for line in [
        "baseline-red\tfix tests::envy\tred under the judge\n",
        "unjudged (baseline-red: fix tests::envy)\tsneaky\n",
        "{\"caught\": 2, \"unjudged\": 1}",
        "mutate schema: control run found 1 case(s) red under the judge",
    ] {
        assert!(said.contains(line), "{line:?} in {said}\n{err}");
    }
}

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
    // ONE CASE AT A TIME, IN NAME ORDER: `adds`, `compares`, `triples`, then
    // the stopper — so the kill lands at the same case on every run. PINNED IN
    // THE FIXTURE'S COMMITTED NEXTEST CONFIG, which the reach run's own config
    // is built on (`cover::wrapped_config`), and never by `NEXTEST_TEST_THREADS`:
    // a suite run inherits no `NEXTEST_*` (`mutate::SUITE_SCRUBBED`), so that pin
    // never reached the cases, they ran side by side, and under load the stopper
    // killed `adds` while it still sealed its record (CLOUD-2789).
    let config = std::fs::read_to_string(repo.join(".config/nextest.toml")).expect("the config");
    common::write(
        &repo,
        ".config/nextest.toml",
        &format!("[profile.default]\ntest-threads = 1\n\n{config}"),
    );
    common::git_in(&repo, &["commit", "-qam", "one case at a time"]);
    let file = listing("mutate-schema-killed-listing");
    let sweep = |stop: bool| {
        let mut command = common::batten();
        command
            .args(["__mutate-schema", &file, "2"])
            .current_dir(&repo);
        if stop {
            command.env("BATTEN_FIXTURE_STOP", "1");
        }
        let output = command.streamed_output().expect("run batten");
        let said = common::stdout(&output);
        (output.status.code(), said, common::stderr(&output))
    };
    let (code, first, err) = sweep(false);
    assert_eq!(code, Some(3), "{first}\n{err}");
    assert!(first.contains(COUNTS), "{first}\n{err}");
    // The head moves under `adds` (it runs `five`), and the stopper fires once
    // `adds` has re-recorded and the two carried cases have been skipped.
    let edited = lib.replace("    5\n}", "    4 + 1\n}");
    common::write(&repo, "src/lib.rs", &edited);
    let (code, killed, err) = sweep(true);
    assert!(
        !format!("{killed}{err}").contains("a case still running beside the stopper"),
        "the cases ran side by side: {killed}\n{err}"
    );
    assert_ne!(code, Some(0), "{killed}\n{err}");
    assert_ne!(code, Some(3), "the sweep never reported: {killed}\n{err}");
    assert!(
        !killed.contains(COUNTS),
        "killed before any verdict: {killed}"
    );
    // And moves again, by nothing any case runs.
    let grown = format!("{edited}pub fn helper(x: u8) -> u8 {{\n    x\n}}\n");
    common::write(&repo, "src/lib.rs", &grown);
    let (code, third, err) = sweep(false);
    assert_eq!(code, Some(3), "{third}\n{err}");
    for line in [
        "sealed 1 case(s) a stopped run finished",
        "reach carried 3 case(s)",
        COUNTS,
    ] {
        assert!(third.contains(line), "{line:?} in {third}\n{err}");
    }
}

/// `mise run mutant:rust` ON ITS OWN JUDGES A DECLARED BASE (CLOUD-2855): the
/// task, not its caller, owns `origin/main`, so a standalone run no longer hands
/// `batten mutate cargo` an empty base (the verb's usage refusal). A caller's
/// own base wins, and under `mutant`'s `MUTANT_WHOLE_TREE` the default yields,
/// so the whole-tree schedule is not turned into a base-and-tree usage error
/// (CLOUD-2849). Fails by: the default deleted (`rust-base-undeclared`), a
/// caller's base overridden, or the default leaking into the whole-tree run.
///
/// THE STUB IS A `#!/bin/sh` SCRIPT, which only a unix host executes, so the
/// case returns early elsewhere and still compiles on every target (CLOUD-1148).
/// THE ROUND BOUND'S GUARANTEE (CLOUD-2882): crates that share no dependency
/// are refused in ONE round, however many there are and whichever cargo
/// starts first. Built one job at a time, `cargo test --no-run` stopped at the
/// first failed crate, so each independent crate cost its own round: #1276's
/// cold build took 11 and 12 rounds against a cap of 12.
///
/// Fails by: a second refusing round for the second crate, which is the
/// keep-going build gone; or a clean round that is not the second.
#[test]
fn independent_crates_are_refused_in_one_round() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let repo = common::scratch_repo("mutate-schema-one-round");
    common::write(
        &repo,
        "Cargo.toml",
        "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"3\"\n",
    );
    common::write(
        &repo,
        ".config/nextest.toml",
        "[profile.mutants]\nfail-fast = true\n\
         slow-timeout = { period = \"2s\", terminate-after = 2 }\n",
    );
    let lib = "pub fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn adds() {\n        assert_eq!(super::add(2, 3), 5);\n    }\n}\n";
    let mut listed = Vec::new();
    for package in ["a", "b"] {
        common::write(
            &repo,
            &format!("{package}/Cargo.toml"),
            &format!("[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
        );
        common::write(&repo, &format!("{package}/src/lib.rs"), lib);
        let mut ill = mutant(
            &format!("ill-typed-{package}"),
            "FnValue",
            "\"x\"",
            [2, 5, 2, 10],
            ("add", "-> u8", [1, 1, 3, 2]),
        );
        ill["file"] = serde_json::json!(format!("{package}/src/lib.rs"));
        ill["package"] = serde_json::json!(package);
        listed.push(ill);
    }
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "seed"]);
    let file = common::scratch("mutate-schema-one-round-listing").join("listing.json");
    std::fs::write(&file, serde_json::Value::Array(listed).to_string()).unwrap();
    let output = common::batten()
        .args(["__mutate-schema", &file.to_string_lossy(), "2"])
        .current_dir(&repo)
        .env_remove("CI")
        // ONE JOB, SO WHICH CRATE CARGO STARTS FIRST CANNOT MATTER: with
        // several, both refusals could land in one round by racing.
        .env("CARGO_BUILD_JOBS", "1")
        .streamed_output()
        .expect("run batten");
    let said = common::stdout(&output);
    let err = common::stderr(&output);
    for line in ["build 1 refused 2 mutant(s)", "build 2 clean, 2 unviable"] {
        assert!(said.contains(line), "{line:?} in {said}\n{err}");
    }
}

#[test]
fn mutant_rust_runs_on_its_own_against_a_declared_base() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::scratch_repo("mutant-rust-base");
    let stub = dir.join("batten-stub");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf 'base=[%s] whole=[%s] argv=[%s]\\n' \"$MUTANT_CHANGED_SINCE\" \"$MUTANT_WHOLE_TREE\" \"$*\"\n",
    )
    .expect("plant the stub engine");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
    }
    let bin = stub.to_string_lossy().into_owned();
    let run = |env: &[(&str, &str)]| {
        let mut all = vec![("BATTEN_BIN", bin.as_str())];
        all.extend_from_slice(env);
        let output = common::mise_task(&dir, "--skip-deps mutant:rust", &all, "");
        let said = common::stdout(&output);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{said}{}",
            common::stderr(&output)
        );
        said
    };
    let alone = run(&[]);
    assert!(
        alone.contains("base=[origin/main] whole=[] argv=[mutate cargo]"),
        "{alone}"
    );
    let chosen = run(&[("MUTANT_CHANGED_SINCE", "HEAD~1")]);
    assert!(chosen.contains("base=[HEAD~1]"), "{chosen}");
    let whole = run(&[("MUTANT_WHOLE_TREE", "1")]);
    assert!(whole.contains("base=[] whole=[1]"), "{whole}");
}
