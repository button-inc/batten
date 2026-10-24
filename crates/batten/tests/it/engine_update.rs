//! The hook's two engine handoffs, and where the release build lives
//! (CLOUD-2376).
//!
//! `engine_install.rs` pins that a pin IS followed. This file pins what happens
//! when the thing it is followed to does not answer: a checkout build that
//! crashes must not become the hook's own exit, because every code outside
//! `crate::exit`'s table — a panic's `101`, a missing interpreter's `127`, and
//! `1` with them — is read by a harness as "the hook itself failed, run the
//! call". That is the fail-open the whole boundary exists to close, so it is
//! asserted over the compiled binary through both handoffs rather than at a
//! function.
//!
//! The second case is the other half of the same defect: the build was looked
//! up where `engine install` does not necessarily write it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// THE ATTRIBUTE IS REQUIRED HERE RATHER THAN CHOSEN, which is the one bar
// `rules/rust.md` holds this route to. Every case stands a `#!/bin/sh` build
// where a source pin points and marks it executable through
// `std::os::unix::fs::PermissionsExt` — a symbol the Windows target does not
// have, so the `cfg!` arm that rule prefers would not type-check. The subject
// is the same: a program with no extension, which Windows can neither execute
// nor make executable. `engine_install.rs`'s `repair` module is gated for this
// reason and these cases are its siblings.
#![cfg(unix)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

/// A repository with one tracked file, so a source digest has something to
/// hash and `git` answers about a worktree.
fn repo(name: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", "version = 1\n");
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "batten.toml", "crates/x/src/lib.rs"]);
    dir
}

/// A case's repository, its outside-the-tree install directory, and the
/// private binary in it — the three names derived from one stem, so they agree
/// by construction rather than by five string literals staying in step.
fn case_tree(case: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = repo(&format!("engine-2376-{case}"));
    let installed = common::scratch_outside_tree("engine-2376", &format!("{case}-installed"));
    let binary = private_binary(&installed);
    (dir, installed, binary)
}

/// A private name for the compiled binary, so this case's installed engine is
/// its own and a stamp written beside it is nobody else's.
fn private_binary(dir: &Path) -> PathBuf {
    private_build(&dir.join("engine").join("batten"))
}

/// Place the compiled binary at `at`, by LINK where the filesystem allows one.
///
/// The test binary is ~137 MiB and this file wants it in five places, so
/// copying would write most of a gigabyte per run — and these cases carry
/// `//MUTANT-SUITE` rows, so a sweep replays them. A link is enough because
/// nothing here writes THROUGH the file: a stamp is a sibling
/// (`engine::stamp_path`) and `durable::replace` renames over the directory
/// entry, leaving the shared inode untouched. `scratch_outside_tree` can land
/// on another filesystem, so a cross-device link falls back to the copy.
fn private_build(at: &Path) -> PathBuf {
    std::fs::create_dir_all(at.parent().unwrap()).unwrap();
    let built = Path::new(env!("CARGO_BIN_EXE_batten"));
    std::fs::hard_link(built, at)
        .or_else(|_| std::fs::copy(built, at).map(|_| ()))
        .expect("place the compiled binary");
    at.to_path_buf()
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("stat the stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod the stub");
}

fn pin_source(dir: &Path, digest: &str) {
    common::write(
        dir,
        "batten.toml",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
}

/// The marker a stub build prints before it dies. Asserted ABSENT: a crashing
/// child decided nothing, so nothing it said may reach the harness's stdout.
const MARKER: &str = "the-crashing-build-spoke";

/// What a build that DOES decide says on each stream. Asserted PRESENT, which
/// is the half `MARKER` cannot pin: see
/// [`a_followed_builds_decision_reaches_the_harness_whole`].
const DECIDED: &str = "the-followed-build-decided";
const EXPLAINED: &str = "the-followed-build-explained";

/// What `batten.toml` asks for. Deliberately NOT [`built`] — the pin is stale
/// by construction, and that is the whole reason a follow happens at all. Make
/// the two equal and every case here passes over a tree nothing was followed
/// in. Functions rather than consts because `str::repeat` is not `const`.
fn pinned() -> String {
    "1".repeat(64)
}

/// What a stub build stamps itself with.
fn built() -> String {
    "2".repeat(64)
}

/// A checkout build that records every run, says one line, and dies of a code
/// the §7 table does not name.
///
/// `101` rather than an invented number because it is what a Rust panic
/// actually exits with, which is the shape this defect was found in.
fn crashing_build(dir: &Path, stamp: &str) {
    stub_build(
        &dir.join("target").join("release"),
        stamp,
        &format!(
            // DRAINS STDIN, because a real engine does. The hand-off inherits
            // this process's stdin and that is where the envelope arrives, so a
            // stub that never reads leaves the payload sitting there for the
            // parent's fall-through to find — which is not the state a crashed
            // engine leaves behind. Reading it first is what makes these cases
            // exercise the fall-through the issue actually ships.
            "#!/bin/sh\ncat >/dev/null 2>&1\necho ran >> \"{}\"\necho \"{MARKER}\"\nexit 101\n",
            dir.join("runs").display()
        ),
    );
}

/// A checkout build that ANSWERS, used where the case is about the path to it
/// rather than about its exit.
fn speaking_build(at: &Path, stamp: &str) {
    stub_build(at, stamp, "#!/bin/sh\necho \"checkout build ran $*\"\n");
}

/// A stamped, executable stand-in for the checkout's release build.
fn stub_build(at: &Path, digest: &str, script: &str) {
    let build = at.join("batten");
    common::write(at, "batten", script);
    make_executable(&build);
    stamp(&build, digest);
}

/// Stamp `build` with `digest`, through the engine's own writer.
///
/// [`batten::engine::stamp`] rather than a hand-rolled `write`, so the
/// fixtures produce whatever the engine produces — the path AND the contents.
/// Spelling either here would let the two drift, which is the defect the
/// production half of this change exists to close.
fn stamp(build: &Path, digest: &str) {
    batten::engine::stamp(build, digest).expect("stamp the stub build");
}

/// How many times a stub build was spawned, read from the file it appends to.
fn runs(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("runs"))
        .unwrap_or_default()
        .lines()
        .count()
}

/// Run `binary` from `cwd`, judging `dir`, with `env` layered on top.
///
/// A COPY of `engine_install.rs`'s `run_from`, and the only difference is the
/// `env` tail the redirection case needs — that one pins `CARGO_TARGET_DIR` to
/// `dir/target` and so does this, which is why the override has to layer over
/// it rather than replace it. The honest fix is the tail on the original and
/// one shared fixture module for both files; it would also end the second copy
/// of the environment-scrub list, which is the half that silently rots when a
/// new variable is added to one and not the other. Not done here because it
/// edits a suite this change does not otherwise touch — CLOUD-2431.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: these cases run a private COPY of the compiled binary, which `common::batten` cannot target"
)]
fn run_from(
    binary: &Path,
    dir: &Path,
    cwd: &Path,
    args: &[&str],
    stdin: &str,
    env: &[(&str, &Path)],
) -> Output {
    use std::io::Write as _;
    // The case's own `bin` and the system's, never the caller's `PATH`: a
    // resolved `batten` from the session's own install would be replaced.
    let path = std::env::join_paths([
        dir.join("bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .unwrap();
    let mut command = std::process::Command::new(binary);
    common::state_dir(&mut command, &dir.join("state"));
    command
        .args(args)
        .current_dir(cwd)
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env("HOME", dir)
        .env("BATTEN_INSTALL_DIR", dir.join("install-dir"))
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_VERSION")
        .env_remove("BATTEN_RELEASES")
        .env_remove("BATTEN_ENGINE_UPDATED")
        .env_remove(batten::engine::LOCAL_ENV)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = common::spawn_copy(&mut command);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for batten")
}

fn run(binary: &Path, dir: &Path, args: &[&str], stdin: &str) -> Output {
    run_from(binary, dir, dir, args, stdin, &[])
}

fn text(output: &Output) -> String {
    format!("{}{}", common::stdout(output), common::stderr(output))
}

/// The adjudication verb, as a harness spells it.
const ADJUDICATE: [&str; 3] = ["adjudicate", "--harness", "claude-code"];

/// What must hold of a hand-off to a build that crashed: the FLOOR decided the
/// call, the build's line is not on stdout, and it was spawned exactly once.
///
/// **THE FLOOR'S OWN ANSWER, NOT MERELY "NOT THE CHILD'S CODE".** This read
/// `!matches!(code, Some(1 | 101))` and was satisfied by exit `0` — which is
/// exactly what the follow arm returned once the stub drained stdin, because
/// the fall-through then re-read a spent stream, found nothing to adjudicate,
/// and ALLOWED. A negative assertion over two codes cannot tell "the floor
/// refused" from "nobody judged anything", and those are the two outcomes this
/// whole issue is about.
///
/// So both halves are named. `3` is the code: the engine could not load the
/// rules it is registered to enforce, which is a could-not-look about Batten
/// rather than a verdict about the tree. The VERDICT rides the document, which
/// is where this harness reads one — so the deny is asserted there, and the two
/// hand-offs now answer identically because they spawn identically.
fn a_crash_decided_nothing(output: &Output, dir: &Path, arm: &str) {
    assert_eq!(
        output.status.code(),
        Some(3),
        "{arm}: a crashed child decided nothing, so the floor answers: {}",
        text(output)
    );
    assert!(
        common::stdout(output).contains(r#""permissionDecision":"deny""#),
        "{arm}: and the floor's answer is a deny the harness reads: {}",
        text(output)
    );
    assert!(
        !common::stdout(output).contains(MARKER),
        "{arm}: a crashed child said nothing the harness reads: {}",
        text(output)
    );
    assert_eq!(
        runs(dir),
        1,
        "{arm}: the crashing build ran once: {}",
        text(output)
    );
}

/// A `PreToolUse` envelope, as a harness writes one. The session id is what the
/// hook resolves the authority by, so every case's envelopes must agree on it.
fn envelope(session: &str, tool: &str, input: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PreToolUse","session_id":"{session}","permission_mode":"default","tool_name":"{tool}","tool_input":{input}}}"#
    )
}

fn bash_envelope(session: &str, command: &str) -> String {
    envelope(session, "Bash", &format!(r#"{{"command":"{command}"}}"#))
}

/// A CRASHING BUILD NEVER BECOMES THE HOOK'S OWN ANSWER (CLOUD-2376).
///
/// Both handoffs are exercised, because they are two different spawns with two
/// different fall-throughs and only one of them was reachable at a time:
/// `follow_pin` teed its child and let its raw code become the process exit,
/// and `hand_to_checkout_build` wrote the child's stdout and then folded every
/// unrecognised code onto `Usage`. Either way a panicking build put a line on
/// the harness's stdout and a non-blocking code on the hook's exit, which is
/// an unjudged tool call.
///
/// What must hold afterwards: the exit is neither `1` nor `101`, the build's
/// line is not on stdout, and the build ran ONCE per call — the two handoffs
/// find the same file, so a fall-through that forgot the first would spawn the
/// crash twice to learn the same thing.
///
/// The two arms are separate cases, and the split is about the mutation sweep
/// rather than taste: `mutate` replays a Rust suite as `cargo test -- <case>`,
/// so three `//MUTANT` rows naming ONE function each paid for the other arm's
/// spawns and both floor invocations, none of which can redden the mutant
/// under test.
#[test]
fn a_crashing_followed_build_never_fails_the_hook_open() {
    // Through `follow_pin`: the installed engine stands IN the checkout.
    let (dir, _installed, binary) = case_tree("crash-follow");
    pin_source(&dir, &pinned());
    crashing_build(&dir, &built());

    let output = run(
        &binary,
        &dir,
        &ADJUDICATE,
        &bash_envelope("crash-follow", "ls"),
    );
    a_crash_decided_nothing(&output, &dir, "follow");
}

/// The load-fault hand-off's half of
/// [`a_crashing_followed_build_never_fails_the_hook_open`], where the shell
/// stands OUTSIDE the checkout: `follow_pin` finds no repository, and the hook
/// reaches the authority the envelope named (CLOUD-2204).
#[test]
fn a_crashing_handed_off_build_never_fails_the_hook_open() {
    let (dir, installed, binary) = case_tree("crash-handoff");
    // The session records its authority from inside the repository first,
    // unpinned, exactly as `a_hook_outside_the_checkout_hands_off_to_the_authoritys_build`
    // does. Nothing is asserted of it: no crashing build exists yet, so an
    // assertion that its marker is absent would be asserting its own premise.
    run(
        &binary,
        &dir,
        &ADJUDICATE,
        &bash_envelope("crash-handoff", "ls"),
    );
    pin_source(&dir, &pinned());
    crashing_build(&dir, &built());

    let output = run_from(
        &binary,
        &dir,
        &installed,
        &ADJUDICATE,
        &bash_envelope("crash-handoff", "ls"),
        &[],
    );
    a_crash_decided_nothing(&output, &dir, "handoff");
}

/// THE FLOOR STILL DECIDES, which is what makes dropping a crashed child's
/// answer safe rather than merely quiet: over rules that will not load, a
/// write to a path that is not the config is refused and a read proceeds.
#[test]
fn the_floor_still_decides_over_rules_that_will_not_load() {
    let (dir, installed, binary) = case_tree("crash-floor");
    run(
        &binary,
        &dir,
        &ADJUDICATE,
        &bash_envelope("crash-floor", "ls"),
    );
    pin_source(&dir, &pinned());
    crashing_build(&dir, &built());

    let write = envelope(
        "crash-floor",
        "Write",
        &format!(
            r#"{{"file_path":"{}","content":"x"}}"#,
            dir.join("src.txt").display()
        ),
    );
    let refused = run_from(&binary, &dir, &installed, &ADJUDICATE, &write, &[]);
    assert!(
        text(&refused).contains("engine-cannot-adjudicate"),
        "the floor refuses a write it has no rules for: {}",
        text(&refused)
    );
    let read = envelope(
        "crash-floor",
        "Read",
        &format!(r#"{{"file_path":"{}"}}"#, dir.join("src.txt").display()),
    );
    let admitted = run_from(&binary, &dir, &installed, &ADJUDICATE, &read, &[]);
    assert!(
        !text(&admitted).contains("engine-cannot-adjudicate"),
        "a read still answers over rules that will not load: {}",
        text(&admitted)
    );
}

/// THE MIRROR: every other verb is a transparent passthrough still
/// (CLOUD-2376).
///
/// The case above drops a child's code and its bytes, and that narrowing has
/// to stop at the hook verb. `exec` carries the child's own code, `101`
/// included, and its bytes as they arrive — the code is not Batten's to
/// re-table there. The checkout build is a working engine rather than a stub,
/// because the claim is about what a FOLLOWED batten does with a wrapped
/// command.
#[test]
fn a_followed_exec_still_passes_its_childs_code_and_bytes_through() {
    let (dir, _installed, binary) = case_tree("exec-passthrough");
    pin_source(&dir, &pinned());
    let build = private_build(&dir.join("target").join("release").join("batten"));
    stamp(&build, &built());

    // `--tee` because capturing is `exec`'s default since CLOUD-429; the claim
    // here is that a FOLLOWED engine's passthrough is byte-for-byte what an
    // unfollowed one's is, not that the default changed.
    let output = run(
        &binary,
        &dir,
        &["exec", "--tee", "--", "sh", "-c", "echo x; exit 101"],
        "",
    );
    assert_eq!(
        output.status.code(),
        Some(101),
        "a wrapped command's own code passes through: {}",
        text(&output)
    );
    assert!(
        common::stdout(&output).contains('x'),
        "and its bytes do too: {}",
        text(&output)
    );
}

/// A FOLLOWED BUILD'S DECISION REACHES THE HARNESS WHOLE (CLOUD-2376).
///
/// The crash cases above pin the REFUSING half — a code outside the §7 table
/// decides nothing and none of its bytes escape. They cannot pin the admitting
/// half, because a child that answered `Success` and a child that crashed both
/// leave the hook allowing with nothing on stdout a harness reads. Measured:
/// nineteen mutations replacing `exec::captured_in_env` wholesale with a
/// constant `(code, stdout, stderr)` survived the entire suite, including the
/// ones that drop the child's bytes on the floor.
///
/// So this case asserts the code AND both streams, and the code is `2`: the one
/// §7 value a fall-through cannot reach here, since the fixture's config loads
/// and a hook that judged for itself would allow. A constant in that function's
/// place now disagrees with this case whatever constant it is.
#[test]
fn a_followed_builds_decision_reaches_the_harness_whole() {
    let (dir, _installed, binary) = case_tree("hook-answer");
    pin_source(&dir, &pinned());
    stub_build(
        &dir.join("target").join("release"),
        &built(),
        &format!("#!/bin/sh\necho \"{DECIDED}\"\necho \"{EXPLAINED}\" >&2\nexit 2\n"),
    );

    let output = run(
        &binary,
        &dir,
        &ADJUDICATE,
        &bash_envelope("hook-answer", "echo hi"),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "the followed build's own code is the hook's: {}",
        text(&output)
    );
    assert!(
        common::stdout(&output).contains(DECIDED),
        "and its stdout reaches the harness: {}",
        text(&output)
    );
    assert!(
        common::stderr(&output).contains(EXPLAINED),
        "and so does its stderr: {}",
        text(&output)
    );
}

/// A RELEASE PIN THIS BINARY CANNOT FETCH IS A REFUSAL, NOT A SHRUG
/// (CLOUD-2376).
///
/// Only the hook path falls through to the refusal floor on a failed fetch
/// (CLOUD-2116), because the floor still decides the call and admits the one
/// repair verb. Every other verb must report: running anyway decides under the
/// very engine the pin refuses, which is what `follow_pin`'s own doc says the
/// fetch is not best-effort for.
///
/// Nothing tested that guard, and the reason was in the production code rather
/// than in the suite: `follow_pin` spelled the release repository as a baked
/// literal, so no fixture could point the fetch anywhere and no case could make
/// one fail. Mutating `!may_build` to `true` therefore survived. It reads
/// `releases_repository()` now, like every other fetch in the binary, and
/// `localhost:1` is this suite's established unreachable host — no network is
/// touched either way.
#[test]
fn a_release_pin_this_binary_cannot_fetch_refuses_off_the_hook_path() {
    let (dir, _installed, binary) = case_tree("unreachable-release");
    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );

    let output = run_from(
        &binary,
        &dir,
        &dir,
        &["config", "show"],
        "",
        &[(
            "BATTEN_RELEASES",
            Path::new("https://localhost:1/example/pkg"),
        )],
    );
    // A NON-ZERO CODE PROVES NOTHING ON ITS OWN, and asserting it alone is how
    // the first version of this case passed over the very mutation it was
    // written for: falling through leaves the PRE-PARSE staleness refusal to
    // speak instead, and that refuses too. Measured, both readings of a failed
    // fetch stop the verb; they differ only in which subject is reported.
    assert_ne!(
        output.status.code(),
        Some(0),
        "a pin that cannot be fetched is never run past: {}",
        text(&output)
    );
    // WHICH SUBJECT SPOKE is therefore the whole assertion, and it is written
    // as the staleness refusal's ABSENCE rather than the fetch failure's
    // presence. The fetch's own words are not stable enough to pin: with an
    // egress proxy in front of it the unreachable host answers `404` and the
    // subject is a usage refusal at exit 1, and without one the connect fails
    // and the subject is a transport error at exit 3. Both are the follow
    // reporting. Only the fall-through reaches this line, in either
    // environment, because only then has nothing been fetched to report about.
    assert!(
        !common::stderr(&output).contains("install the pin with"),
        "the follow reported the fetch, not the staleness refusal it would \
         have fallen through to: {}",
        text(&output)
    );
}

/// A SOURCE PIN WITH NO BUILD IS BUILT, OFF THE HOOK PATH (CLOUD-2062).
///
/// The `None if may_build` arm, which `the_hook_path_never_builds_a_source_pin`
/// pins only from the other side: that case proves the HOOK does not build, and
/// is satisfied whether or not any other verb does. Mutating the guard to
/// `false` therefore survived the whole suite — nothing asserted that a verb
/// which MAY build reaches `install_source` at all.
///
/// Asserted without a successful cargo build, because none is needed to
/// discriminate. The fixture carries no manifest, so the install attempt fails
/// at once and the refusal names `cargo build --release -p batten`. Measured by
/// hand against the arm's other reading, which is what a verb that never
/// attempts the build does: it runs, prints the effective config and exits `0`
/// — no refusal of any kind, because a stale SOURCE pin stops nothing by
/// itself. So both halves are named, the attempt and the silence.
#[test]
fn a_source_pin_with_no_build_is_built_off_the_hook_path() {
    let (dir, _installed, binary) = case_tree("source-pin-builds");
    pin_source(&dir, &pinned());
    assert!(
        !dir.join("target").join("release").join("batten").exists(),
        "the arm under test is the one with no build to follow"
    );

    let output = run(&binary, &dir, &["config", "show"], "");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a pin that could not be built is reported, never run past: {}",
        text(&output)
    );
    assert!(
        common::stderr(&output).contains("cargo build --release -p batten"),
        "and the build is what was attempted: {}",
        text(&output)
    );
    assert!(
        common::stdout(&output).is_empty(),
        "the verb the follow preceded never ran: {}",
        text(&output)
    );
}

/// ONE PLACE NAMES THE RELEASE BUILD (CLOUD-2376).
///
/// `engine install` wrote into `$CARGO_TARGET_DIR/release`, and the follow read
/// `target/release`. With that variable set the two named different files, so a
/// source pin was followed to a stale build or to nothing at all while the
/// engine the install had just produced sat elsewhere. Here there IS no
/// `target/release`, so the case can only pass by reading the variable.
///
/// The redirect points OUTSIDE the repository, which is the shape a shared
/// target directory takes and the one a containment rule got wrong: `root` here
/// is the tree this process would run cargo in, so wherever its own cargo was
/// told to write IS its own build, inside the checkout or not.
#[test]
fn a_source_pin_is_followed_into_a_redirected_target_dir() {
    let (dir, _installed, binary) = case_tree("redirected-target");
    pin_source(&dir, &pinned());
    let elsewhere = common::scratch_outside_tree("engine-2376", "redirected-target-dir");
    speaking_build(&elsewhere.join("release"), &built());
    assert!(
        !dir.join("target").join("release").join("batten").exists(),
        "the only build is the redirected one"
    );

    let output = run_from(
        &binary,
        &dir,
        &dir,
        &["config", "show"],
        "",
        &[("CARGO_TARGET_DIR", elsewhere.as_path())],
    );
    assert!(
        text(&output).contains("checkout build ran config show"),
        "the pin is followed to the build cargo was told to write: {}",
        text(&output)
    );
}

/// THE HAND-OFF READS NO `CARGO_TARGET_DIR` OF THIS PROCESS (CLOUD-2376).
///
/// The mirror of the case above, and the reason the distinction is drawn by
/// CALLER rather than by where the path lands. `CARGO_TARGET_DIR` says where
/// THIS process's cargo writes, so it speaks for the tree this process would
/// build and for no other. The load-fault hand-off asks about the envelope's
/// AUTHORITY — a different checkout, in exactly the case it exists for — so
/// applying the variable there would follow a source pin into the build of a
/// tree nobody asked about.
///
/// The redirect here is RELATIVE, which is the shape a containment rule let
/// through: it resolves under the authority's own root, so "is the path inside
/// `root`" answers yes about a build this process never made. The hand-off
/// must look under the authority's plain `target/release` and find nothing.
#[test]
fn the_handoff_reads_no_target_dir_of_this_process() {
    let (dir, installed, binary) = case_tree("foreign-target");
    // The session records its authority from inside the repository first,
    // unpinned, as the other hand-off case does.
    run(
        &binary,
        &dir,
        &ADJUDICATE,
        &bash_envelope("foreign-target", "ls"),
    );
    pin_source(&dir, &pinned());
    // Under the authority's root, so a containment test would admit it, and
    // reachable only by reading this process's variable.
    speaking_build(&dir.join("elsewhere").join("release"), &built());
    assert!(
        !dir.join("target").join("release").join("batten").exists(),
        "the only build is the redirected one"
    );

    let output = run_from(
        &binary,
        &dir,
        &installed,
        &ADJUDICATE,
        &bash_envelope("foreign-target", "ls"),
        &[("CARGO_TARGET_DIR", Path::new("elsewhere"))],
    );
    assert!(
        !text(&output).contains("checkout build ran"),
        "another tree's build is never handed to: {}",
        text(&output)
    );
}
