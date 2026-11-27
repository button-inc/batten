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

/// The verdict counts every sweep of the fixture reaches. The hang is CAUGHT,
/// not a timeout (CLOUD-2904's hang-as-caught): its case is cut at its own
/// limit while its control passes inside a fifth of it, so the mutant's run is
/// what ran long, and a run that cannot end is a kill.
const COUNTS: &str = "{\"caught\": 3, \"missed\": 1, \"uncovered\": 1}, 1 unviable, 2 classic";

/// Every verdict a sweep can reach, each from its own mutant: a kill, a
/// survivor a case reaches, a site no case reaches, a hang, and a mutant that
/// does not compile; then a second sweep over the same tree keeps every one,
/// knows the unviable mutant without building it, and reuses the reach record.
///
/// Fails by: an unviable mutant judged (it would survive), a hang read as a
/// kill, a site no case reaches judged by a run, a failed case read as a
/// survivor, the exit not saying a mutant survived, a second sweep that
/// rebuilds what the first proved unviable, a control run over cases no
/// judging run executes (C3), a new helper or const moving every key, a traced case keyed on a non-Rust file it never read, or
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
        Some(2),
        "the fixture's hang is caught (its control passes inside a fifth of the cut), so \
         nothing is left undecided and the survivor's 2 is the exit\n{said}\n{err}"
    );
    assert!(said.contains(COUNTS), "{said}\n{err}");
    for line in [
        "missed\tsurvive\n",
        "uncovered\tunreached\n",
        "1 mutant(s) caught by a hang",
        "build 1 refused 1 mutant(s), handed back 1 for a const caller",
        "classic\tconst-caller\n",
        "classic\tfield\n",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    // OFF CI NO CASE IS RECORDED TWICE, so no stability is claimed: a line
    // reporting "stable for 0 case(s)" says a comparison ran that did not
    // (CLOUD-2789).
    assert!(!said.contains("reach stable"), "{said}\n{err}");
    let (code, again, err) = sweep();
    assert_eq!(code, Some(2), "{again}\n{err}");
    // NO BUILD ROUND REDISCOVERS WHAT THE FIRST SWEEP FOUND: the unviable
    // mutant and the const-caller hand-back are both journaled, so the second
    // sweep's first build is clean — once, the hand-back cost a refused build
    // on every sweep.
    for line in [
        "1 unviable, 1 handed back and 0 unprobed file(s) known from earlier runs",
        "build 1 clean, 1 unviable",
        // ALL FIVE: the hang is caught (CLOUD-2904), a decision, so it is
        // stored and reused like any kill. A timeout would decide nothing and
        // be judged again on every sweep (W1).
        "reused 5 of 5 verdict(s)",
        COUNTS,
        // NO CONTROL FOR WHAT NO RUN EXECUTES (CLOUD-2253, C3): every
        // mutant is decided by its journal, so no case is controlled.
        "control ran 0 of the 0 case(s) still to judge",
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
    // ONLY `adds`, whose digest moved, is controlled again: the cases of the
    // three reused verdicts are run by nothing.
    assert!(
        third.contains("control ran 1 of the 1 case(s) still to judge"),
        "{third}\n{err}"
    );
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
    // Every verdict, the caught hang's included (CLOUD-2904): nothing moved.
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
        Some(2),
        "{said}\n{}",
        common::stderr(&output)
    );
    // EVERY SWEEP LINE ADVANCES THE STEP (9f8b61051), the closing summary
    // included, so the signal is whichever progress line came last, never a
    // fixed one. Judging still has to have been said along the way.
    assert!(
        said.lines()
            .any(|line| line.starts_with("mutate schema: judged 5/5")),
        "the sweep says its judging: {said}"
    );
    let last = said
        .lines()
        .rfind(|line| line.starts_with("mutate schema: ") || line.starts_with("mutate sweep: "));
    assert!(last.is_some(), "the sweep printed progress: {said}");
    assert_eq!(
        batten::task::read_field(&repo.join(".git"), "515151", "sig").as_deref(),
        last,
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
    assert_eq!(code, Some(2), "{first}\n{err}");
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

/// The crates in the longest chain from `name` down through `deps`, `name`
/// counted, memoised in `seen`.
fn depth(
    name: &str,
    deps: &std::collections::BTreeMap<String, Vec<String>>,
    seen: &mut std::collections::BTreeMap<String, usize>,
) -> usize {
    if let Some(known) = seen.get(name) {
        return *known;
    }
    let below = deps
        .get(name)
        .into_iter()
        .flatten()
        .map(|dep| depth(dep, deps, seen))
        .max()
        .unwrap_or(0);
    seen.insert(name.to_owned(), below + 1);
    below + 1
}

/// The longest chain of workspace crates, each depending on the next, in this
/// repository's own workspace: the crates under `crates/` and their `path`
/// dependencies on one another.
fn workspace_chain() -> usize {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf();
    let mut deps: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(&crates).unwrap().flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("Cargo.toml")) else {
            continue;
        };
        let manifest: toml::Table = text.parse().expect("a manifest");
        let name = manifest["package"]["name"].as_str().unwrap().to_owned();
        let on: Vec<String> = ["dependencies", "dev-dependencies", "build-dependencies"]
            .iter()
            .filter_map(|table| manifest.get(*table).and_then(toml::Value::as_table))
            .flat_map(|table| table.iter())
            .filter(|(_, spec)| spec.get("path").is_some())
            .map(|(dep, _)| dep.clone())
            .collect();
        deps.insert(name, on);
    }
    let mut seen = std::collections::BTreeMap::new();
    deps.keys()
        .map(|name| depth(name, &deps, &mut seen))
        .max()
        .unwrap_or(0)
}

/// THE ROUND BOUND COVERS THIS WORKSPACE (CLOUD-2882): a round sees a crate's
/// refusals only once every crate it depends on builds clean, so the rounds a
/// listing needs grow with the longest chain of workspace crates. #1276's
/// cold build was clean in round 11 over a six-crate chain, two rounds a
/// crate at most, and [`batten::mutate::schema::ROUNDS`] is that allowance.
///
/// Fails by: a crate split or a new dependency deepening the chain past what
/// the bound was measured to cover. That fails here, before every `mutants`
/// job fails at the cap; the remedy is a measured bound or a shallower
/// chain, never a raised cap alone. Also fails if the chain is read as empty.
#[test]
fn the_round_bound_covers_the_workspace_chain() {
    let chain = workspace_chain();
    assert!(
        chain >= 6,
        "fsio, facts, base, core, batten, codemods: {chain}"
    );
    assert!(
        2 * chain <= batten::mutate::schema::ROUNDS,
        "a {chain}-crate chain needs up to {} rounds; the bound is {}",
        2 * chain,
        batten::mutate::schema::ROUNDS
    );
}

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

/// `mise run mutant:changed` HANDS A CALLER'S BASE TO BOTH RUNNERS (CLOUD-2918):
/// `origin/main` is its default, so an operator who narrowed the base gets that
/// base judged by `mutant:declared` and `mutant:rust` alike, never the whole
/// branch. Fails by: the task setting `origin/main` unconditionally
/// (`changed-base-overrides-caller`), which overwrote the caller's value before
/// either subtask read it.
///
/// THE STUB IS A `#!/bin/sh` SCRIPT, which only a unix host executes, so the
/// case returns early elsewhere and still compiles on every target (CLOUD-1148).
/// `MISE_TASK_SKIP_DEPENDS` reaches the nested `mise run` too, so neither
/// subtask provisions the pkl package this case never reads.
#[test]
fn mutant_changed_hands_a_callers_base_to_both_runners() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::scratch_repo("mutant-changed-base");
    let stub = dir.join("batten-stub");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf 'base=[%s] argv=[%s]\\n' \"$MUTANT_CHANGED_SINCE\" \"$*\"\n",
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
        let mut all = vec![
            ("BATTEN_BIN", bin.as_str()),
            ("MISE_TASK_SKIP_DEPENDS", "1"),
        ];
        all.extend_from_slice(env);
        let output = common::mise_task(&dir, "--skip-deps mutant:changed", &all, "");
        let said = common::stdout(&output);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{said}{}",
            common::stderr(&output)
        );
        said
    };
    for (env, base) in [
        (&[][..], "origin/main"),
        (&[("MUTANT_CHANGED_SINCE", "HEAD~1")][..], "HEAD~1"),
    ] {
        let said = run(env);
        for runner in ["mutate sweep", "mutate cargo"] {
            let line = format!("base=[{base}] argv=[{runner}]");
            assert!(said.contains(&line), "{line:?} in {said}");
        }
    }
}

/// The reach recorder refuses to run a case with nowhere to record it: a
/// wrapper run outside a reach run exits 101 and says why, never 0.
///
/// Fails by: `record` answering `Ok(0)` without running anything, which reads
/// as a passing case and seals a reach that recorded nothing (CLOUD-2789).
#[test]
fn a_record_run_with_no_reach_directory_fails() {
    let dir = common::Fixture::new("schema-record-no-reach").build();
    let ran = common::run(&dir, &[batten::mutate::schema::RECORD_ARG, "false"]);
    assert_eq!(ran.status.code(), Some(101), "{ran:?}");
    assert!(
        String::from_utf8_lossy(&ran.stderr).contains("no reach directory"),
        "{ran:?}"
    );
}

/// The library a whole-pass case judges: while the file `pin` stands beside
/// it, `two`'s only case pins its value, so each mutant cargo-mutants makes of
/// it is caught, and without it the case still runs `two`, so each survives
/// rather than goes unreached. The pin is not Rust, so moving it moves the tree and never
/// the patch.
const PASSING_LIB: &str = "pub fn two() -> u8 {\n    2\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn twos() {\n        \
let got = super::two();\n        \
if std::path::Path::new(\"pin\").exists() {\n            assert_eq!(got, 2);\n        }\n    }\n}\n";

/// `batten mutate cargo` over `repo`'s change since `base`, off CI.
fn cargo_sweep(repo: &std::path::Path, base: &str) -> (Option<i32>, String) {
    let output = common::batten()
        .args(["mutate", "cargo"])
        .current_dir(repo)
        .env("MUTANT_RUNNERS", "cargo-mutants=**/*.rs")
        .env("MUTANT_CHANGED_SINCE", base)
        // `mutant:rust`'s per-job cost, which a hand-back is sized by.
        .env("MUTANT_JOB_DISK_MB", "6200")
        .env("MUTANT_JOB_MEMORY_MB", "4000")
        .env("MUTANT_JUDGE_MEMORY_MB", "1")
        .env_remove("CI")
        .env_remove(batten::mutate::WHOLE_TREE)
        .streamed_output()
        .expect("run batten mutate cargo");
    let mut said = common::stdout(&output);
    said.push_str(&common::stderr(&output));
    (output.status.code(), said)
}

/// [`cargo_sweep`] as shard `shard` (`k/n`) of the judging.
fn cargo_sweep_on(repo: &std::path::Path, base: &str, shard: &str) -> (Option<i32>, String) {
    let output = common::batten()
        .args(["mutate", "cargo"])
        .current_dir(repo)
        .env("MUTANT_RUNNERS", "cargo-mutants=**/*.rs")
        .env("MUTANT_CHANGED_SINCE", base)
        .env("MUTANT_SHARD", shard)
        .env("MUTANT_JOB_DISK_MB", "6200")
        .env("MUTANT_JOB_MEMORY_MB", "4000")
        .env("MUTANT_JUDGE_MEMORY_MB", "1")
        .env_remove("CI")
        .env_remove(batten::mutate::WHOLE_TREE)
        .streamed_output()
        .expect("run batten mutate cargo");
    let mut said = common::stdout(&output);
    said.push_str(&common::stderr(&output));
    (output.status.code(), said)
}

/// A `mutate cargo` RUN OVER A TREE SEEN PASSING WHOLE IS ANSWERED (CLOUD-2253,
/// C7): a land lap's rerun over the same tree lists nothing, builds nothing
/// and reaches nothing. A file outside the patch that a case reads is a tree
/// that moved, judged again, and here the survivor it now lets through is
/// found.
///
/// Fails by: no pass record, so the second run lists and builds again; or a
/// record keyed on the patch alone, so the third run answers 0 over a tree
/// whose only case no longer pins the value.
#[test]
fn a_cargo_run_over_a_tree_seen_passing_whole_is_not_run_again() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let _ = common::scratch_state_root();
    let repo = seeded_with("mutate-cargo-pass", "pub fn one() -> u8 {\n    1\n}\n");
    common::write(
        &repo,
        "batten.toml",
        &format!("version = 1\n{}", crate::step_journal::MUTANTS_PROVISION),
    );
    common::write(&repo, "pin", "two\n");
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "provision and pin"]);
    let base = common::git_in(&repo, &["rev-parse", "HEAD"]);
    let base = base.trim();
    common::write(&repo, "src/lib.rs", PASSING_LIB);
    common::git_in(&repo, &["commit", "-qam", "two"]);
    let answered = "mutate cargo: this tree passed whole";
    let (code, said) = cargo_sweep(&repo, base);
    assert_eq!(code, Some(0), "every mutant of `two` is caught\n{said}");
    assert!(!said.contains(answered), "{said}");
    let (code, said) = cargo_sweep(&repo, base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains(answered),
        "the second run is answered\n{said}"
    );
    assert!(!said.contains("mutant(s) of"), "nothing is listed\n{said}");
    std::fs::remove_file(repo.join("pin")).expect("unpin");
    let (code, said) = cargo_sweep(&repo, base);
    assert!(
        !said.contains(answered),
        "a moved tree is judged again\n{said}"
    );
    assert_eq!(code, Some(2), "and its survivor found\n{said}");
}

/// A library whose `two` only a const calls, so every mutant of it is handed
/// back ([`seeded_with`]): `pins` kills each, `runs` reaches each and pins
/// nothing. `RUNS` is `runs`' body, which a case edits to move its digest.
fn handed_back_lib(runs: &str) -> String {
    format!(
        "pub const fn two() -> u8 {{\n    2\n}}\npub const TWO: u8 = two();\n\
         #[cfg(test)]\nmod tests {{\n    #[test]\n    fn pins() {{\n        \
         assert_eq!(super::TWO + super::two(), 4);\n    }}\n    #[test]\n    fn runs() {{\n        \
         {runs}\n    }}\n}}\n"
    )
}

/// A HAND-BACK IS JOURNALED BY ITS PAIRS (CLOUD-2253, C8), as a switched
/// mutant is: once `pins` killed it, an edit to `runs`, another case
/// observing it, decides it from that journaled kill with no mirror build,
/// where its key over every observing case moved and it built again.
///
/// Fails by: hand-backs keyed only on the whole observing set, so the second
/// run judges each again ("0 reused"); or a pair kill journaled for a case
/// that did not fail, which the first run's verdicts would contradict.
#[test]
fn a_hand_back_is_decided_by_its_journaled_pairs() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let _ = common::scratch_state_root();
    let repo = seeded_with("mutate-handback-pairs", "pub fn one() -> u8 {\n    1\n}\n");
    common::write(
        &repo,
        "batten.toml",
        &format!("version = 1\n{}", crate::step_journal::MUTANTS_PROVISION),
    );
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "provision"]);
    let base = common::git_in(&repo, &["rev-parse", "HEAD"]);
    let base = base.trim();
    common::write(
        &repo,
        "src/lib.rs",
        &handed_back_lib("let _ = super::two();"),
    );
    common::git_in(&repo, &["commit", "-qam", "two"]);
    let (code, said) = cargo_sweep(&repo, base);
    assert_eq!(code, Some(0), "`pins` kills every hand-back\n{said}");
    let judged = said
        .lines()
        .find(|line| line.contains("handed-back mutant(s) judged in place"))
        .unwrap_or_else(|| panic!("hand-backs judged\n{said}"))
        .to_owned();
    assert!(judged.ends_with(", 0 reused"), "{judged}\n{said}");
    let count = judged
        .split_whitespace()
        .nth(2)
        .expect("a count")
        .to_owned();
    common::write(
        &repo,
        "src/lib.rs",
        &handed_back_lib("let two = super::two();\n        let _ = two;"),
    );
    let (code, said) = cargo_sweep(&repo, base);
    assert_eq!(code, Some(0), "{said}");
    let reused = format!("{count} handed-back mutant(s) judged in place, {count} reused");
    assert!(said.contains(&reused), "{reused:?} in\n{said}");
}

/// A library whose `make` builds `P` through a struct expression with a base,
/// so cargo-mutants deletes each field of it: two hand-backs on adjacent
/// lines, and the one case runs `make` and pins nothing, so each survives.
const SIBLING_FIELDS_LIB: &str = "#[derive(Default)]\npub struct P {\n    pub a: u8,\n    pub b: u8,\n}\n\
pub fn make() -> P {\n    P {\n        a: 1,\n        b: 2,\n        ..Default::default()\n    }\n}\n\
#[cfg(test)]\nmod tests {\n    #[test]\n    fn makes() {\n        let _ = super::make();\n    }\n}\n";

/// EVERY HAND-BACK VERDICT REACHES THE TALLY, ONCE (CLOUD-2253): two field
/// deletions on adjacent lines of one struct expression are each handed
/// back, and a hand-back's run judges its sibling beside it, since
/// cargo-mutants applies no `--re` to a field deletion. Unsharded, the final
/// list names every survivor and the count holds every one; across shards,
/// each survivor is listed by exactly one shard and the shards' counts sum,
/// whichever shard's run happened to print its sibling's MISSED.
///
/// Fails by: a handed-back survivor dropped from the final list or count, as
/// bootstrap shard 3/8 read `schema.rs:8992`, so a lap's exit could read green
/// over it; or one counted by two shards.
#[test]
fn every_handed_back_survivor_is_listed_and_counted_once() {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let _ = common::scratch_state_root();
    let repo = seeded_with("mutate-handback-tally", "pub fn one() -> u8 {\n    1\n}\n");
    common::write(
        &repo,
        "batten.toml",
        &format!("version = 1\n{}", crate::step_journal::MUTANTS_PROVISION),
    );
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-qm", "provision"]);
    let base = common::git_in(&repo, &["rev-parse", "HEAD"]);
    let base = base.trim();
    common::write(&repo, "src/lib.rs", SIBLING_FIELDS_LIB);
    common::git_in(&repo, &["commit", "-qam", "make"]);
    let survivors = |said: &str| -> Vec<String> {
        said.lines()
            .filter(|line| line.starts_with("missed\tsrc/lib.rs:"))
            .map(str::to_owned)
            .collect()
    };
    let missed = |said: &str| -> usize {
        let tally = said
            .lines()
            .find(|line| line.starts_with("mutate schema: {"))
            .unwrap_or_default();
        tally
            .split("\"missed\": ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|count| count.parse().ok())
            .unwrap_or(0)
    };
    let (code, said) = cargo_sweep(&repo, base);
    assert_eq!(code, Some(2), "every mutant of `make` survives\n{said}");
    let whole = survivors(&said);
    for field in ["a", "b"] {
        let deletion = format!("delete field {field} from struct P");
        assert!(
            whole.iter().any(|line| line.contains(&deletion)),
            "the survivor deleting `{field}` is listed\n{said}"
        );
    }
    assert_eq!(
        missed(&said),
        whole.len(),
        "the count holds every listed survivor\n{said}"
    );
    // THE SIBLING A RUN JUDGED IS SAID AS NO VERDICT, never left as a bare
    // MISSED for a reader to count.
    assert!(
        said.contains("'s run also judged src/lib.rs:8:9: delete field a"),
        "the sibling is named as no verdict\n{said}"
    );
    let mut listed = Vec::new();
    let mut counted = 0;
    for shard in 0..4 {
        let (_, said) = cargo_sweep_on(&repo, base, &format!("{shard}/4"));
        counted += missed(&said);
        listed.extend(survivors(&said));
    }
    listed.sort();
    let mut once = whole.clone();
    once.sort();
    assert_eq!(listed, once, "each survivor is listed by exactly one shard");
    assert_eq!(
        counted,
        whole.len(),
        "and the shards' counts sum to the whole's"
    );
}

/// What a killed sweep had made durable at the kill: the reach records done
/// passing, the passing controls and the verdicts its journal held.
#[derive(Debug, Default)]
struct AtKill {
    finished: usize,
    controls: usize,
    verdicts: usize,
}

/// [`AtKill`] read from the mirror state of `repo`'s sweeps.
fn at_kill(repo: &std::path::Path) -> AtKill {
    let target = batten::mutate::schema::mirror_target(repo).expect("the mirror's target");
    let state = target
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the mirror state");
    let finished = std::fs::read_dir(state.join("reach"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            std::fs::read_to_string(entry.path().join("done")).is_ok_and(|code| code == "0")
        })
        .count();
    let journal = std::fs::read_to_string(state.join("verdicts")).unwrap_or_default();
    let field = |line: &str| line.split('\t').nth(1).unwrap_or_default().to_owned();
    let controls = journal
        .lines()
        .filter(|line| field(line).starts_with("control:"))
        .count();
    // BY MUTANT, NEVER BY LINE: a kill pair is journaled beside its verdict.
    let verdicts = journal
        .lines()
        .filter(|line| {
            matches!(
                field(line).as_str(),
                "caught" | "missed" | "uncovered" | "timeout"
            )
        })
        .filter_map(|line| line.split('\t').nth(2))
        .collect::<std::collections::BTreeSet<&str>>()
        .len();
    AtKill {
        finished,
        controls,
        verdicts,
    }
}

/// `line` with every ANSI escape sequence removed.
fn uncoloured(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for end in chars.by_ref() {
                if end.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Every process below `pid`, read from `/proc`, deepest last.
fn descendants(pid: i32) -> Vec<i32> {
    let parent_of = |of: i32| -> Option<i32> {
        let stat = std::fs::read_to_string(format!("/proc/{of}/stat")).ok()?;
        let after = stat.rsplit_once(')')?.1;
        after.split_whitespace().nth(1)?.parse().ok()
    };
    let all: Vec<i32> = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    let mut found = vec![pid];
    let mut at = 0;
    while at < found.len() {
        let here = found[at];
        found.extend(all.iter().filter(|child| parent_of(**child) == Some(here)));
        at += 1;
    }
    found.remove(0);
    found
}

/// The schema sweep over `file` in `repo`, `SIGKILL`ed with every process
/// below it, as a worker restart kills them, on the first line holding `at`
/// once a line holding `after` has been said (at once where `after` is
/// empty): whether the kill landed, and everything said until then.
///
/// NO CLOCK: the kill is the event a stage says, never a delay.
fn sweep_killed_on(
    repo: &std::path::Path,
    file: &str,
    (after, at): (&str, &str),
) -> (bool, String) {
    let mut armed = after.is_empty();
    sweep_killed_when(repo, file, |line| {
        let now = armed && line.contains(at);
        armed |= !after.is_empty() && line.contains(after);
        now
    })
}

/// [`sweep_killed_on`], killed on the first line `kill` answers true for,
/// each line handed to it in the order said.
fn sweep_killed_when(
    repo: &std::path::Path,
    file: &str,
    mut kill: impl FnMut(&str) -> bool,
) -> (bool, String) {
    use std::io::BufRead as _;
    let mut command = common::batten();
    command
        .args(["__mutate-schema", file, "2"])
        .current_dir(repo)
        .env_remove("CI")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn the sweep");
    let pid = i32::try_from(child.id()).expect("a pid");
    let (send, lines) = std::sync::mpsc::channel::<String>();
    let streams: Vec<Box<dyn std::io::Read + Send>> = vec![
        Box::new(child.stdout.take().expect("its stdout")),
        Box::new(child.stderr.take().expect("its stderr")),
    ];
    let pumps: Vec<std::thread::JoinHandle<()>> = streams
        .into_iter()
        .map(|stream| {
            let send = send.clone();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stream)
                    .lines()
                    .map_while(Result::ok)
                {
                    if send.send(line).is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    drop(send);
    let (mut said, mut killed) = (String::new(), false);
    for line in lines {
        // NEXTEST COLOURS ITS CASE LINES: matched on the text, escapes off.
        let line = uncoloured(&line);
        said.push_str(&line);
        said.push('\n');
        if !killed && kill(&line) {
            // EVERY PROCESS BELOW IT, STOPPED FIRST: a run that sets its own
            // group is no less killed by a restart.
            let mut tree = descendants(pid);
            tree.insert(0, pid);
            for each in &tree {
                if let Some(target) = rustix::process::Pid::from_raw(*each) {
                    let _ = rustix::process::kill_process(target, rustix::process::Signal::STOP);
                }
            }
            for each in &tree {
                if let Some(target) = rustix::process::Pid::from_raw(*each) {
                    let _ = rustix::process::kill_process(target, rustix::process::Signal::KILL);
                }
            }
            killed = true;
        }
    }
    let _ = child.wait();
    for pump in pumps {
        let _ = pump.join();
    }
    (killed, said)
}

/// The fixture sweep of [`seeded`], one case at a time so a kill lands at one
/// case, killed at `point` and relaunched: what it had made durable at the
/// kill, and what the relaunch said.
fn killed_and_relaunched(name: &str, point: (&str, &str)) -> (AtKill, String) {
    let (repo, file) = one_case_at_a_time(name);
    let (killed, before) = sweep_killed_on(&repo, &file, point);
    assert!(killed, "the sweep never said {point:?}:\n{before}");
    let durable = at_kill(&repo);
    (durable, relaunched(&repo, &file))
}

/// [`seeded`] under `name`, its cases run one at a time so a kill lands at
/// one case, and its listing.
fn one_case_at_a_time(name: &str) -> (std::path::PathBuf, String) {
    let _ = common::require_bin("nextest", "cargo-nextest");
    let _ = common::scratch_state_root();
    let repo = seeded(name);
    let config = std::fs::read_to_string(repo.join(".config/nextest.toml")).expect("the config");
    common::write(
        &repo,
        ".config/nextest.toml",
        &format!("[profile.default]\ntest-threads = 1\n\n{config}"),
    );
    common::git_in(&repo, &["commit", "-qam", "one case at a time"]);
    let file = listing(&format!("{name}-listing"));
    (repo, file)
}

/// The fixture sweep over `file` in `repo`, run to its end: what it said,
/// once its exit and verdicts are checked.
fn relaunched(repo: &std::path::Path, file: &str) -> String {
    let output = common::batten()
        .args(["__mutate-schema", file, "2"])
        .current_dir(repo)
        .env_remove("CI")
        .streamed_output()
        .expect("relaunch the sweep");
    let said = common::stdout(&output);
    let err = common::stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{said}\n{err}");
    assert!(
        said.contains(COUNTS),
        "the relaunch's verdicts: {said}\n{err}"
    );
    said
}

/// The number before `after` in the line of `said` that holds `holding`.
fn count_in(said: &str, holding: &str, after: &str) -> Option<usize> {
    let line = said.lines().find(|line| line.contains(holding))?;
    line.split(after)
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// What a relaunch redid, read from its own lines: no finished reach record
/// recorded again, no passing control run again, and no verdict judged again.
fn assert_nothing_finished_redone(durable: &AtKill, said: &str) {
    if let Some(before) = count_in(said, "reach runs", "case(s), ") {
        assert!(
            before >= durable.finished,
            "{durable:?}: the relaunch held fewer finished cases than the kill left\n{said}"
        );
    }
    // A CONTROL JOURNALED BEFORE THE KILL IS NEVER RUN AGAIN: where the killed
    // run had controlled every case it recorded, the relaunch controls none.
    let ran = count_in(said, "control ran", "control ran ").unwrap_or(0);
    if durable.finished > 0 && durable.controls >= durable.finished {
        assert_eq!(
            ran, 0,
            "{durable:?}: a control journaled before the kill ran again\n{said}"
        );
    }
    let reused = count_in(said, "mutate schema: reused", "reused ").unwrap_or(0);
    assert!(
        reused >= durable.verdicts,
        "{durable:?}: a verdict journaled before the kill was judged again\n{said}"
    );
}

/// CRASH-ONLY (CLOUD-2904): a sweep killed once its build is done, every
/// process at once as a worker restart kills them, relaunches to a build that
/// knows what the killed one found and the same verdicts.
///
/// Fails by: the build's discoveries lost with the kill, so the relaunch's
/// first build refuses the unviable mutant again.
#[test]
fn a_sweep_killed_after_its_build_rebuilds_nothing_it_found() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (durable, said) =
        killed_and_relaunched("mutate-crash-build", ("", "stage build outputs took"));
    assert!(
        said.contains("1 unviable, 1 handed back and 0 unprobed file(s) known from earlier runs"),
        "{said}"
    );
    assert_nothing_finished_redone(&durable, &said);
}

/// CRASH-ONLY (CLOUD-2904): a sweep killed mid-reach, behind its first
/// finished case, relaunches keeping that case: sealed or counted finished,
/// never recorded again.
///
/// Fails by: a finished record lost to the kill, or left unsealed and
/// recorded again by the relaunch.
#[test]
fn a_sweep_killed_mid_reach_records_no_finished_case_again() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (durable, said) = killed_and_relaunched("mutate-crash-reach", ("reach runs", "PASS ["));
    assert!(
        durable.finished >= 1,
        "a case finished before the kill: {durable:?}"
    );
    assert_nothing_finished_redone(&durable, &said);
}

/// CRASH-ONLY (CLOUD-2904): a sweep killed once reach is sealed relaunches
/// to a reach that starts no case.
///
/// Fails by: a sealed reach run again on the relaunch.
#[test]
fn a_sweep_killed_after_reach_starts_no_case_again() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (durable, said) =
        killed_and_relaunched("mutate-crash-sealed", ("", "stage reach seal took"));
    assert!(
        !said.contains("reach runs") || said.contains("reach runs 0 of"),
        "{said}"
    );
    assert_nothing_finished_redone(&durable, &said);
}

/// CRASH-ONLY (CLOUD-2904): a sweep killed once its control has run, and so
/// while it judges, relaunches to a control of no case and judges no
/// mutant again whose verdict it had journaled.
///
/// Fails by: the control's passes journaled only at the end of the sweep, or
/// a journaled verdict judged again.
#[test]
fn a_sweep_killed_while_judging_controls_nothing_and_rejudges_nothing() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (durable, said) = killed_and_relaunched("mutate-crash-judge", ("", "stage control took"));
    assert!(
        durable.controls >= 1,
        "the control was journaled: {durable:?}"
    );
    assert!(
        said.contains("control ran 0 of the"),
        "every case's passing control was journaled: {said}"
    );
    assert_nothing_finished_redone(&durable, &said);
}

/// CRASH-ONLY (CLOUD-2904): a sweep killed once every mutant is judged, and
/// a null lap over a finished sweep, relaunch to reuse every verdict, control
/// no case, start no reach case, and take the packed build as built.
///
/// Fails by: any finished unit redone on a relaunch that changed nothing.
#[test]
fn a_sweep_killed_after_judging_or_run_again_redoes_nothing() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (durable, said) = killed_and_relaunched("mutate-crash-judged", ("", "stage judging took"));
    assert!(
        durable.verdicts == 5,
        "every verdict was journaled: {durable:?}"
    );
    for line in [
        "reused 5 of 5 verdict(s)",
        "control ran 0 of the 0 case(s) still to judge",
        // NOTHING DERIVED AGAIN BEFORE IT JUDGES (CLOUD-2904): a finished
        // run's unsealable records and untakeable selection digests were
        // derived again on every relaunch, 837 s and 790 s on #1276.
        ", 0 tried",
    ] {
        assert!(said.contains(line), "{line:?} in {said}");
    }
    assert!(
        !said.contains("leftovers derived"),
        "no leftovers derived again: {said}"
    );
    assert!(
        !said.contains("reach runs") || said.contains("reach runs 0 of"),
        "{said}"
    );
    assert_nothing_finished_redone(&durable, &said);
}

/// CRASH-ONLY, CONVERGING (CLOUD-2904): a reach killed again and again, each
/// time just after a case it had not finished before finishes, keeps every
/// finished case: each relaunch holds more finished than the one before, and
/// the last starts only what no kill left finished.
///
/// Fails by: a finished case lost to a kill, or recorded again by the next
/// run, so the finished count stalls and repeated preemptions never converge
/// (a looping lap preempting a seed that never finished).
#[test]
fn a_reach_killed_again_and_again_converges() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (repo, file) = one_case_at_a_time("mutate-crash-converge");
    let mut finished_before = Vec::new();
    for _ in 0..2 {
        let mut held: Option<usize> = None;
        let mut passed = 0;
        let (killed, said) = sweep_killed_when(&repo, &file, |line| {
            if held.is_none() {
                held = count_in(line, "reach runs", "case(s), ");
                return false;
            }
            if line.contains("PASS [") {
                passed += 1;
            }
            // THE FIRST CASE NO EARLIER RUN FINISHED: the finished ones run
            // first, in name order, and pass at once.
            held.is_some_and(|held| passed > held)
        });
        assert!(
            killed,
            "the reach passed a case it had not finished: {said}"
        );
        finished_before.push(held.expect("the reach line"));
    }
    assert!(
        finished_before.windows(2).all(|pair| pair[1] > pair[0]),
        "each relaunch holds more finished cases: {finished_before:?}"
    );
    let said = relaunched(&repo, &file);
    let (Some(starts), Some(listed), Some(held)) = (
        count_in(&said, "reach runs", "reach runs "),
        count_in(&said, "reach runs", " of "),
        count_in(&said, "reach runs", "case(s), "),
    ) else {
        panic!("the last relaunch's reach line: {said}");
    };
    assert!(held > *finished_before.last().unwrap(), "{said}");
    assert_eq!(
        starts,
        listed - held,
        "only what no kill left finished: {said}"
    );
}
