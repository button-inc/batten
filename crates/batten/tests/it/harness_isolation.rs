//! A case's spawn of the binary judges its own fixture, never the checkout
//! holding this build (CLOUD-2059).
//!
//! `common::batten`'s door refuses a spawn whose working directory sits under the
//! build's scratch root with no repository of its own, because `git::repo_root`
//! ignores discovery ceilings by design and such a fixture resolves to the real
//! checkout. The decision is `batten::testing::falls_through`; these cases show
//! the door applies it, in both directions.

use std::path::Path;

use crate::common;

/// Whether a bare scratch directory falls through on THIS build's layout. It
/// does wherever the target directory sits inside a checkout — this repository's
/// own, and CI's — and does not where `CARGO_TARGET_DIR` is outside every
/// worktree, which the guard rightly leaves alone (review of #1089). Each door
/// case asserts the refusal EXACTLY when this holds, so neither layout reads red
/// for the wrong reason.
///
/// AN ORACLE OF ITS OWN, read straight off the resolver the binary uses, and
/// never `batten::testing::falls_through`: that function is what the mutants
/// change, and an expectation computed by it would move with the mutation and
/// pass every one of them.
fn falls_through(dir: &Path) -> bool {
    // The resolver's own spelling, never a bare `canonicalize`: on Windows that
    // answers verbatim and no plain root starts with it (CLOUD-2059).
    let scratch = batten::git::canonical(&common::target_tmp());
    // THE FENCE ANSWERS FIRST (CLOUD-2904): this suite fences discovery at its
    // scratch root, so resolving a directory that falls through panics, and
    // that panic is the same answer as an owner outside the scratch root.
    std::panic::catch_unwind(|| batten::git::worktree_root(dir)).map_or(true, |owner| {
        owner.is_ok_and(|owner| !owner.starts_with(&scratch))
    })
}

/// The binary's door refuses a spawn in a bare scratch directory exactly when it
/// falls through.
#[test]
fn a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused() {
    let bare = common::scratch("harness-isolation-bare");
    let refused = std::panic::catch_unwind(|| {
        let _ = common::batten()
            .arg("--version")
            .current_dir(&bare)
            .streamed_output();
    })
    .is_err();
    assert_eq!(
        refused,
        falls_through(&bare),
        "the binary's door refuses exactly a directory that falls through"
    );
}

/// The task door refuses the same directory, and reads it WHEN THE BODY SPAWNS,
/// not when the command was built (review of #1089). A caller that builds in its
/// own repository and then moves the command somewhere that falls through is
/// refused before the body runs.
#[test]
fn a_task_body_redirected_to_a_fall_through_is_refused_before_it_runs() {
    let owned = common::scratch("harness-isolation-task-owned");
    common::init_repo(&owned);
    let bare = common::scratch("harness-isolation-task-bare");
    let refused = std::panic::catch_unwind(|| {
        let mut task = common::task_bash(&owned, "touch ran");
        task.current_dir(&bare);
        let _ = task.streamed_output();
    })
    .is_err();
    let falls = falls_through(&bare);
    assert_eq!(
        refused, falls,
        "the task door refuses exactly a directory that falls through"
    );
    assert!(
        !falls || !bare.join("ran").exists(),
        "and refuses it before the body runs"
    );
}

/// The piped door refuses before the child runs too (review of #1089).
/// `run_with_stdin` hands its command to a helper that spawns it as a plain
/// `Command`, below the wrapper's own checks, so without its own check the child
/// ran and only the drop check objected afterwards. `init` writes `batten.toml`,
/// so a child that ran leaves one.
#[test]
fn a_piped_spawn_into_a_fall_through_is_refused_before_it_runs() {
    let bare = common::scratch("harness-isolation-piped");
    let falls = falls_through(&bare);
    let refused = std::panic::catch_unwind(|| {
        let _ = common::run_with_stdin(&bare, &["init"], "");
    })
    .is_err();
    assert_eq!(
        refused, falls,
        "the piped door refuses exactly a directory that falls through"
    );
    assert!(
        !falls || !bare.join("batten.toml").exists(),
        "and refuses it before the child runs"
    );
}

/// The case's OWN library calls resolve the root its children are pinned to, so
/// an admission issued in-process, a lap verified in-process, or a decision
/// appended in-process lands in the case's store and not the developer's — the
/// 22 segments one full run still wrote after every spawn door was pinned.
#[test]
fn in_process_state_resolves_to_the_cases_own_root() {
    let _ = common::scratch("harness-isolation-in-process");
    assert_eq!(
        batten::state::data_dir().expect("a data directory"),
        common::scratch_state_root(),
        "a fixture contains the process, so the library resolves the case's root"
    );
}

/// The child's home is the case's own on every platform, so nothing in the
/// developer's `~/.claude`, `~/.gitconfig` or global mise config reaches a verdict
/// a CI runner, which has none of them, would not reproduce.
#[test]
fn every_spawn_of_the_binary_pins_the_home() {
    let homes = common::homes(&common::batten());
    assert_eq!(
        homes.len(),
        2,
        "the home must be pinned on every platform: {homes:?}"
    );
    for (name, value) in &homes {
        assert_eq!(
            value.as_path(),
            common::scratch_home(),
            "{name} must point at the case's own home, never the developer's"
        );
    }
}

/// mise's config search stops at the fixture root on every spawn (CLOUD-2176), so
/// a fixture under `target/tmp` cannot resolve this checkout's `mise.toml` and run
/// its tasks against the host — which a `SessionStart` in a fixture did, for every
/// `session:*` task, until CLOUD-2173.
#[test]
fn every_spawn_stops_mises_walk_at_the_fixture_root() {
    let root = &common::target_tmp();
    let command = common::batten();
    let ceiling = command
        .get_envs()
        .find(|(name, _)| *name == "MISE_CEILING_PATHS")
        .and_then(|(_, value)| value);
    assert_eq!(
        ceiling,
        Some(root.as_os_str()),
        "every spawn must stop mise's config search at the fixture root"
    );
}

/// EVERY HOST-SESSION VARIABLE THE ENGINE READS IS SCRUBBED FROM EVERY SPAWN
/// (CLOUD-2789).
///
/// A case whose verdict reads the host's live session is a gate that answers
/// one way in the session that ran it and another on the land or CI. Measured
/// on #1276: `CLAUDE_PID` handed `doctor` the host session's root, so
/// `doctor::this_repository_is_healthy` and `init`'s read-verb case were red
/// wherever that root's wiring differed. So every `"CLAUDE_*"` name the engine
/// spells is one `common::batten` removes, and a new one fails here until it is
/// scrubbed or argued below.
///
/// `CLAUDE_PROJECT_DIR` is the one argued exception: the engine spells it as
/// the token a committed wiring row substitutes, and never reads it from its
/// environment.
///
/// Fails by: a host-session name the engine spells reaching a spawn.
#[test]
fn every_spawn_scrubs_the_host_session_the_engine_reads() {
    const NEVER_READ: &[&str] = &["CLAUDE_PROJECT_DIR"];
    let named: std::collections::BTreeSet<String> = common::rust_sources()
        .into_iter()
        .filter(|path| path.components().any(|part| part.as_os_str() == "src"))
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|text| host_session_names(&text))
        .filter(|name| !NEVER_READ.contains(&name.as_str()))
        .collect();
    assert!(
        named.contains("CLAUDE_CODE_REMOTE"),
        "the census read no engine source naming the session: {named:?}"
    );
    let command = common::batten();
    let scrubbed: Vec<String> = command
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .filter_map(|(name, _)| name.to_str().map(str::to_owned))
        .collect();
    let reaching: Vec<&String> = named
        .iter()
        .filter(|name| !scrubbed.contains(name))
        .collect();
    assert!(
        reaching.is_empty(),
        "these host-session variables reach every spawn: {reaching:?}"
    );
}

/// THE MUTANT SWITCH REACHES EVERY ENGINE SPAWN (#1276): a schema judge
/// exports [`batten::mutate::schema::ACTIVE`] to the cases it runs, and a site
/// that only a spawned `batten` reaches is judged through that child. Scrubbed
/// there, every such mutant would run unswitched and read as a survivor the
/// suite could never kill. `task_bash` removes it on purpose (CLOUD-2789), for
/// a sweep a case starts runs its own baseline; the engine spawn never does.
///
/// Fails by: the switch added to `common::batten`'s scrub, or replaced there.
#[test]
fn the_mutant_switch_reaches_every_engine_spawn() {
    let switch = std::ffi::OsStr::new(batten::mutate::schema::ACTIVE);
    for command in [
        common::batten(),
        common::batten_as(std::path::Path::new(env!("CARGO_BIN_EXE_batten"))),
    ] {
        assert!(
            !command.get_envs().any(|(name, _)| name == switch),
            "an engine spawn touches {switch:?}, so a judged mutant never reaches the child"
        );
    }
}

/// Every `"CLAUDE_<NAME>"` string literal in `source`.
fn host_session_names(source: &str) -> Vec<String> {
    let prefix = concat!("\"CLAUDE", "_");
    source
        .match_indices(prefix)
        .filter_map(|(at, _)| {
            let rest = &source[at + 1..];
            let end = rest.find('"')?;
            let name = &rest[..end];
            name.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                .then(|| name.to_owned())
        })
        .collect()
}

/// The reader the census above stands on: a quoted name is found, prose and a
/// lower-case word are not.
///
/// Fails by: the reader matching nothing, which passes the census vacuously.
#[test]
fn the_host_session_reader_finds_a_quoted_name_only() {
    let quoted = concat!("std::env::var(\"CLAUDE", "_PID\")");
    assert_eq!(host_session_names(quoted), vec!["CLAUDE_PID".to_owned()]);
    assert!(host_session_names("reads `CLAUDE_PID` from the host").is_empty());
    assert!(host_session_names(concat!("\"CLAUDE", "_pid\"")).is_empty());
}

/// REFUSED BEFORE THE CHILD EXISTS, not reported after it ran: the point is that
/// a falling-through fixture never touches the checkout. `init` writes
/// `batten.toml` into its working directory, so a child that ran leaves one.
#[test]
fn a_fall_through_is_refused_before_the_child_runs() {
    let bare = common::scratch("harness-isolation-before");
    let falls = falls_through(&bare);
    let attempt = std::panic::catch_unwind(|| {
        let _ = common::batten()
            .arg("init")
            .current_dir(&bare)
            .streamed_output();
    });
    assert_eq!(attempt.is_err(), falls, "the door refused the spawn");
    assert!(
        !falls || !bare.join("batten.toml").exists(),
        "and refused it before the child ran"
    );
}

/// THE ANTI-VACUITY ARM: a door that refused every spawn would satisfy the case
/// above. A fixture that IS a repository runs, and so does a spawn at the real
/// root, which the committed-configuration suites make on purpose.
#[test]
fn a_spawn_in_its_own_repository_or_at_the_real_root_runs() {
    let owned = common::scratch("harness-isolation-owned");
    common::init_repo(&owned);
    for dir in [owned, common::committed_repo().to_path_buf()] {
        let output = common::batten()
            .arg("--version")
            .current_dir(&dir)
            .streamed_output()
            .expect("run batten");
        assert!(output.status.success(), "{}", common::stderr(&output));
    }
}

/// D3 (CLOUD-2904): a spawn of the binary inside the checkout holding this
/// build is refused before it runs, a spawn naming no directory runs in the
/// case's own fixture repository rather than inheriting the crate directory,
/// and a fixture repository under the scratch root runs.
///
/// Fails by: the door judging only a directory under the scratch root, which
/// let a spawn with no `current_dir` run in the crate directory and read the
/// real checkout's HEAD, refs and receipts.
#[test]
fn a_spawn_inside_the_checkout_is_refused() {
    let unnamed = common::batten();
    let cwd = unnamed
        .get_current_dir()
        .expect("a spawn always has a directory");
    assert_eq!(
        cwd,
        common::case_fixture(),
        "a spawn naming no directory runs in the case's own fixture, never the crate directory"
    );
    assert!(
        cwd.join(".git").exists(),
        "and that fixture is a repository"
    );
    let named = std::panic::catch_unwind(|| {
        let _ = common::batten()
            .arg("--version")
            .current_dir(common::at_root("."))
            .streamed_output();
    })
    .is_err();
    assert!(named, "a spawn at the checkout's root");
    let owned = common::scratch_repo("harness-isolation-owned-cwd");
    let ran = common::batten()
        .arg("--version")
        .current_dir(&owned)
        .streamed_output()
        .expect("a fixture repository runs");
    assert!(ran.status.success());
}

/// The at-root ratchet ([`common::AT_ROOT_CASES`]) names only live cases,
/// sorted and once each, so it can only shrink.
///
/// Fails by: a name left behind after its case moved to a fixture or was
/// renamed, a duplicate, or an unsorted insertion that hides one.
#[test]
fn the_at_root_list_only_names_live_cases_in_order() {
    let listed: Vec<&str> = common::AT_ROOT_CASES.lines().collect();
    let mut sorted = listed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(listed, sorted, "sorted, and each case once");
    let sources: String = std::fs::read_dir(common::at_root("crates/batten/tests/it"))
        .expect("the suite's sources")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| std::fs::read_to_string(path).expect("a source"))
        .collect();
    for case in listed {
        let name = case.rsplit("::").next().expect("a case name");
        assert!(
            sources.contains(&format!("fn {name}(")),
            "{case} is listed and no case of that name is left"
        );
    }
}
