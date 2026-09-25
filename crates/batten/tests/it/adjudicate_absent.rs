//! A call this build cannot adjudicate is DENIED, never allowed by a failure.
//!
//! The tier that proves the engine does not fail open when it has read its own
//! authority and been told it cannot enforce it. Unit cases over `adjudicate`
//! cannot host this: the defect is not in the decision, it is in what the
//! BOUNDARY does with a load that failed, and only the compiled binary answers
//! that — `mediated_admission.rs`'s header records the same lesson, where unit
//! cases passed while the binary allowed the write.
//!
//! # The mirror is not decoration
//!
//! `a_loadable_config_still_allows_an_ordinary_call` is what stops this being
//! satisfied by an adjudicator that denies everything. A fail-closed hook that
//! refuses each call is not a fix, it is an outage — CLOUD-1688's falsifier says
//! so in as many words, and that is why the pair lands together.
//!
//! # Scope
//!
//! The CONFIG half of CLOUD-1688: a `batten.toml` this build cannot load. The
//! VERB half — a registration spelling a subcommand the installed binary does
//! not have — needs `doctor` to interrogate the installed artifact rather than
//! itself, because a self-check runs in the build that mise resolves and never
//! in the one the hook does. It lands with that part and belongs in this file.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin};

/// A `batten.toml` mid-edit, which is the largest measured bucket: seven windows
/// across one 5-day session, 1,149 calls, every one of them unjudged.
const WILL_NOT_PARSE: &str = "version = 1\nthis is not toml\n";

/// A config that loads and declares nothing this call matches.
const LOADS: &str = "version = 1\n";

/// A config that LOADS and refuses the read.
///
/// The discriminator for `the_floor_does_not_reach_a_config_that_loads`: a
/// tool-keyed `shape` row is exactly what `is_adjudicable`'s `PreTool` clause
/// exists to serve, so this is the case a floor applied unconditionally would
/// wrongly allow. Asserting `0` over `LOADS` would prove nothing — that config
/// denies nothing, so allow is the answer either way.
const DENIES_THE_READ: &str = "version = 1\n\
     \n\
     [[rule]]\n\
     id = \"fixture read refused\"\n\
     kind = \"shape\"\n\
     scope = \"mediated_call\"\n\
     severity = \"deny\"\n\
     tool = \"Read\"\n\
     reason = \"the fixture refuses this read\"\n";

/// A fixture carrying `body` as its committed authority.
fn fixture(name: &str, body: &str) -> PathBuf {
    Fixture::new(name)
        .config(body)
        .file("notes.md", "ordinary\n")
        .git()
        .base_commit()
        .build()
}

/// A Claude Code `PreToolUse` envelope carrying a command, so the boundary
/// treats it as adjudicable and reaches the config load at all.
fn payload() -> String {
    "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
     \"tool_input\":{\"command\":\"echo hello\"}}"
        .to_owned()
}

/// Adjudicate on the neutral adapter, where the VERDICT IS THE NUMBER.
///
/// `exit-code` rather than `claude-code` for the two cases that ask what the
/// code is: on Claude Code the deny is the JSON document at exit `0`, so a case
/// asserting a number there would assert the wrong channel. The document is
/// checked separately below.
fn code(dir: &Path) -> Option<i32> {
    run_with_stdin(dir, &["adjudicate", "--harness", "exit-code"], &payload())
        .status
        .code()
}

/// A `PreToolUse` envelope naming `tool`, carrying `input` verbatim.
fn envelope(tool: &str, input: &str) -> String {
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"{tool}\",\"tool_input\":{input}}}"
    )
}

/// A write envelope naming `path`.
///
/// `Write` is in `Harness::write_tools` for the neutral adapter too, so the
/// boundary derives `Envelope::writes` from it exactly as on a real host. The
/// path is spelled ABSOLUTELY, which is what Claude Code sends and what
/// `relativise_writes` is there to normalize — a relative path would skip the
/// normalization the exemption depends on.
fn write_envelope(path: &Path) -> String {
    envelope(
        "Write",
        &format!(
            "{{\"file_path\":{}}}",
            serde_json::to_string(&path.to_string_lossy()).expect("a path serializes")
        ),
    )
}

/// Adjudicate `body` on the neutral adapter and hand back the code.
fn code_for(dir: &Path, body: &str) -> Option<i32> {
    run_with_stdin(dir, &["adjudicate", "--harness", "exit-code"], body)
        .status
        .code()
}

#[test]
fn a_config_this_build_cannot_load_denies_rather_than_failing_open() {
    // WAS `1`, WHICH A HARNESS READS AS A NON-BLOCKING HOOK ERROR, so the
    // mediated tool ran with nothing judging it (CLOUD-1677).
    //
    // `2` HERE AND `3` ON A DOCUMENT HARNESS, and the split is the protocol
    // rather than a preference: this adapter's ONLY deny channel is the number,
    // so the number has to carry the refusal. Where the decision object carries
    // it instead, the number is free to say could-not-look — the case below
    // asserts that side.
    let dir = fixture("adjudicate-unloadable", WILL_NOT_PARSE);
    assert_eq!(
        code(&dir),
        Some(2),
        "a call nothing could judge must be refused, not allowed by the failure"
    );
}

#[test]
fn a_loadable_config_still_allows_an_ordinary_call() {
    // THE MIRROR. Without it the case above is satisfied by an adjudicator that
    // denies every call in the fleet, which is an outage wearing a fix's clothes.
    let dir = fixture("adjudicate-loadable", LOADS);
    assert_eq!(
        code(&dir),
        Some(0),
        "a config that loads and refuses nothing must still allow"
    );
}

#[test]
fn the_declared_hatch_still_reaches_a_clone_whose_config_will_not_load() {
    // What keeps a container recoverable rather than bricked. A stale binary
    // meeting a newer config refuses every call until one of them moves, so the
    // operator's declared escape has to survive exactly the state that needs it.
    //
    // `common::batten()` scrubs every bypass variable by construction, so setting
    // one here is the only way it is present — a case that inherited it from the
    // developer's shell would pass without testing anything.
    use std::io::Write as _;
    use std::process::Stdio;

    let dir = fixture("adjudicate-hatch", WILL_NOT_PARSE);
    let mut child = common::batten()
        .args(["adjudicate", "--harness", "exit-code"])
        .current_dir(&dir)
        .env("BATTEN_HOOK_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload().as_bytes())
        .expect("the payload is writable");
    let output = child.wait_with_output().expect("the binary answers");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the declared hatch must still pass a call the engine cannot judge"
    );
}

#[test]
fn on_claude_code_the_refusal_is_the_document_rather_than_the_number() {
    // THE CHANNEL IS PER-HARNESS AND THE NUMBER IS NOT (`run_hook`'s own
    // contract). This host reads the JSON decision object and ignores the code,
    // so a deny raised as `2` here would be a refusal nobody receives — which is
    // the reason this arm renders rather than raising a `Denial`.
    let dir = fixture("adjudicate-document", WILL_NOT_PARSE);
    let output = run_with_stdin(
        dir.as_path(),
        &["adjudicate", "--harness", "claude-code"],
        &payload(),
    );
    let rendered = String::from_utf8_lossy(&output.stdout);
    // The row's falsifier names the field rather than the word: a `contains("deny")`
    // would pass on a document that merely mentioned it, including one that said
    // the opposite.
    assert!(
        rendered.contains(r#""permissionDecision":"deny""#),
        "the decision object must carry the deny: {rendered}"
    );
    // AND THE NUMBER IS FREE TO BE HONEST, which is the half that needs the
    // document to exist. §6-§7 reserve `3` for could-not-look, and `exit.rs`
    // keeps `Usage` and `Internal` the only codes a failure of Batten's own may
    // produce *so that fail-open is structural*. Answering `2` here would buy the
    // refusal a second time and spend that guarantee for the copy.
    assert_eq!(
        output.status.code(),
        Some(3),
        "where the document refuses, the number says nothing was judged"
    );
}

#[test]
fn the_declaration_that_would_not_parse_is_named_without_quoting_it() {
    // Non-negotiable rule 4, and the row asks for this clause by name: the reason
    // carries the parse position, never the config's contents. The fixture's body
    // is `this is not toml`, so its presence in the output would be the leak.
    let dir = fixture("adjudicate-pointer-only", WILL_NOT_PARSE);
    let output = run_with_stdin(
        dir.as_path(),
        &["adjudicate", "--harness", "claude-code"],
        &payload(),
    );
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(
        !rendered.contains("this is not toml"),
        "a refusal about an unreadable config must not quote it: {rendered}"
    );
}

// ─── THE FLOOR UNDER THE REFUSAL (CLOUD-1842) ───
//
// The cases above prove the engine does not fail OPEN on a config it cannot
// load. These prove it does not brick the container either — and each carries a
// mirror, because a floor that swallowed every call would satisfy "the Read
// answers" while reverting CLOUD-1677 entirely.

#[test]
fn a_read_still_answers_over_a_config_that_will_not_load() {
    // THE MEASURED BRICK. Before this floor the call below denied at `2`, and
    // its reason carried the parse error the agent was thereby denied the means
    // to read. Every declared escape is unreachable from inside that state:
    // CLOUD-1605 (the env hatch cannot be spelled on the Bash surface) and
    // CLOUD-1579 (an override over an unloadable config cannot be minted).
    let dir = fixture("adjudicate-floor-read", WILL_NOT_PARSE);
    assert_eq!(
        code_for(&dir, &envelope("Read", r#"{"file_path":"notes.md"}"#)),
        Some(0),
        "a classified read mutates nothing, so no rule could have refused it"
    );
}

#[test]
fn a_command_is_still_refused_over_a_config_that_will_not_load() {
    // THE MIRROR, and the row's own falsifier. CLOUD-1677 measured 1,149 calls
    // proceeding unjudged through seven windows of a mid-edit config. If this
    // reddens, the floor has swallowed the refusal and the change is that defect
    // restored.
    let dir = fixture("adjudicate-floor-command", WILL_NOT_PARSE);
    assert_eq!(
        code_for(&dir, &payload()),
        Some(2),
        "a command is a mutation this build cannot judge, so it still refuses"
    );
}

#[test]
fn a_mutating_mcp_call_is_still_refused_over_a_config_that_will_not_load() {
    // THE DEFECT THE FIRST DRAFT SHIPPED, pinned so it cannot return.
    //
    // `command.is_empty() && writes.is_none()` is NOT "cannot mutate":
    // `operation_of` maps an MCP call to `Operation::Mcp`, a `Task` to
    // `Subagent` and an unrecognised tool to `Other`, and all three carry an
    // empty command and no write. Measured against the built binary before the
    // correction — `mcp__serena__write_memory`, whose target `.serena/memories/**`
    // is a PROTECTED path, was allowed at exit `0`.
    let dir = fixture("adjudicate-floor-mcp", WILL_NOT_PARSE);
    assert_eq!(
        code_for(
            &dir,
            &envelope(
                "mcp__serena__write_memory",
                r#"{"memory_name":"x","content":"y"}"#
            )
        ),
        Some(2),
        "an MCP call carries no command and no write and still mutates"
    );
}

#[test]
fn a_subagent_spawn_is_still_refused_over_a_config_that_will_not_load() {
    // The same shape one operation over. `Task` is `Operation::Subagent`, also
    // commandless and writeless, and it spawns work this build cannot judge.
    let dir = fixture("adjudicate-floor-task", WILL_NOT_PARSE);
    assert_eq!(
        code_for(&dir, &envelope("Task", r#"{"prompt":"do a thing"}"#)),
        Some(2),
        "a subagent spawn is not a read"
    );
}

#[test]
fn the_repair_write_reaches_the_config_that_will_not_load() {
    // THE LOCKOUT'S EXIT. `batten.toml` is a protected path and the protected
    // gate is deliberately outside the general hatch's reach — sound while a
    // policy is LOADED, vacuous here, where `Policy::declaring_nothing` carries
    // an empty protected set because no table could be read at all. Without this
    // the one write that ENDS the degraded state is the one it refuses.
    let dir = fixture("adjudicate-floor-repair", WILL_NOT_PARSE);
    let target = dir.join("batten.toml");
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(0),
        "the write that would repair the faulting config must not be refused by it"
    );
}

#[test]
fn a_write_to_another_path_is_still_refused_over_a_config_that_will_not_load() {
    // THE MIRROR FOR THE REPAIR ARM, and what keeps the exemption from being a
    // general write permit. `notes.md` sits beside the config in the same
    // fixture, so the only difference from the case above is the name.
    let dir = fixture("adjudicate-floor-other-write", WILL_NOT_PARSE);
    let target = dir.join("notes.md");
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(2),
        "only the config authority is exempt; every other write is still a mutation"
    );
}

#[test]
fn a_neighbour_named_like_the_config_is_not_the_config() {
    // WHOLE-NAME EQUALITY, NEVER A SUFFIX. `crates/batten.toml` ends with the
    // authority's name and is a different file; an `ends_with` test — the
    // obvious spelling — would hand the exemption to every one of them.
    let dir = fixture("adjudicate-floor-lookalike", WILL_NOT_PARSE);
    let target = dir.join("crates").join("batten.toml");
    std::fs::create_dir_all(target.parent().expect("the parent is named"))
        .expect("the fixture is writable");
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(2),
        "a path that merely ends with the authority's name is a different file"
    );
}

#[test]
fn a_whitespace_bearing_name_is_not_the_config() {
    // NO `trim()`, and this is why. `" batten.toml"` is a different file on a
    // POSIX filesystem, and trimming would let a write to it through the one
    // exemption that exists to end a lockout. The first draft borrowed the trim
    // from `bypass::operation_of`, where it compares two CALLS to each other and
    // whitespace is transcription noise — here it is an identity check against a
    // constant, where whitespace is part of the name.
    let dir = fixture("adjudicate-floor-whitespace", WILL_NOT_PARSE);
    let target = dir.join(" batten.toml");
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(2),
        "a leading space makes it a different file, not the authority"
    );
}

#[test]
fn the_floor_does_not_reach_a_config_that_loads() {
    // THE SCOPE MIRROR, AND IT HAS TO BE ABLE TO FAIL. This config DENIES the
    // read, so the assertion is that it still does. A floor applied
    // unconditionally rather than on the `ConfigUnreadable` arm would allow
    // here, switching off every loaded tool-keyed row for every read in the
    // fleet — the `is_adjudicable` clause CLOUD-924 added, turned back off.
    let dir = fixture("adjudicate-floor-scoped", DENIES_THE_READ);
    assert_eq!(
        code_for(&dir, &envelope("Read", r#"{"file_path":"notes.md"}"#)),
        Some(2),
        "a rule this build COULD read still decides; the floor is not a bypass"
    );
}

// THE BREAK-GLASS OVER A CONFIG THAT LOADS (CLOUD-1847).
//
// Everything above this line is CLOUD-1842's floor, which answers only on the
// `ConfigUnreadable` arm — and `the_floor_does_not_reach_a_config_that_loads`
// pins that scope deliberately. The cases below are the OTHER state: a config
// that parses, loads and lints clean, whose rows refuse the calls that would
// remove them. The floor never sees it, and a container in it has no exit.
//
// Measured in a live session: a `mediated_call` `policy` row whose body was bare
// truthiness on `input.call` passed `batten config lint` at rc=0, "0 smell(s)",
// then refused `Bash`, `Read`, and the `Edit` of `batten.toml` that would undo
// it. The session ended by abandonment.

/// A config that LOADS and refuses both halves of the repair floor.
///
/// Two `shape` rows rather than a rego module, on `DENIES_THE_READ`'s reason: a
/// tool-keyed row is the cheapest thing that denies for real, and the mechanism
/// under test is the ripcord rather than any particular way of writing a deny.
/// Both halves are here because the floor admits exactly two shapes, and a
/// fixture that refused only one would let a half-working ripcord pass.
const DENIES_THE_REPAIR: &str = "version = 1\n\
     \n\
     [[rule]]\n\
     id = \"fixture read refused\"\n\
     kind = \"shape\"\n\
     scope = \"mediated_call\"\n\
     severity = \"deny\"\n\
     tool = \"Read\"\n\
     reason = \"the fixture refuses this read\"\n\
     \n\
     [[rule]]\n\
     id = \"fixture write refused\"\n\
     kind = \"shape\"\n\
     scope = \"mediated_call\"\n\
     severity = \"deny\"\n\
     tool = \"Write\"\n\
     reason = \"the fixture refuses this write\"\n";

/// A config that LOADS and refuses ONLY `Bash`.
///
/// The falsifier's fixture: with the sentinel armed, `Bash` must still deny. A
/// ripcord that admitted it would be a global allow wearing a record.
const DENIES_ONLY_BASH: &str = "version = 1\n\
     \n\
     [[rule]]\n\
     id = \"fixture command refused\"\n\
     kind = \"shape\"\n\
     scope = \"mediated_call\"\n\
     severity = \"deny\"\n\
     tool = \"Bash\"\n\
     reason = \"the fixture refuses this command\"\n";

/// Arm the sentinel in `dir`, untracked.
///
/// Written after the fixture's `base_commit` on purpose: a COMMITTED sentinel is
/// the thing `no-armed-ripcord` refuses, so a fixture that committed one would be
/// asserting the state the repository forbids.
fn arm(dir: &Path) {
    std::fs::write(dir.join(batten::ripcord::SENTINEL), "").expect("arm the ripcord");
}

#[test]
fn a_loaded_rule_refuses_the_repair_when_the_ripcord_is_not_armed() {
    // THE ANTI-VACUITY HALF, and without it every case below is satisfied by a
    // build that allows these calls unconditionally. The config here denies the
    // read, nothing is armed, and the answer must still be the refusal.
    let dir = fixture("ripcord-unarmed", DENIES_THE_REPAIR);
    assert_eq!(
        code_for(&dir, &envelope("Read", r#"{"file_path":"notes.md"}"#)),
        Some(2),
        "with no sentinel the loaded rule decides, exactly as it did before"
    );
}

#[test]
fn the_ripcord_admits_a_read_a_loaded_rule_refused() {
    // The case the row exists for: the config loads, the rule denies, and the
    // container can look again.
    let dir = fixture("ripcord-armed-read", DENIES_THE_REPAIR);
    arm(&dir);
    assert_eq!(
        code_for(&dir, &envelope("Read", r#"{"file_path":"notes.md"}"#)),
        Some(0),
        "an armed ripcord admits the read that would diagnose the fault"
    );
}

#[test]
fn the_ripcord_admits_the_repair_write() {
    // The other half of the floor, and the one that actually ends the lockout:
    // the authority is what carries the offending row, so a ripcord that opened
    // reads and not this write would leave the container able to see the fault
    // and unable to fix it.
    let dir = fixture("ripcord-armed-write", DENIES_THE_REPAIR);
    arm(&dir);
    let target = dir.join("batten.toml");
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(0),
        "an armed ripcord admits the write onto the config authority"
    );
}

#[test]
fn the_ripcord_is_not_a_global_allow() {
    // THE FALSIFIER THE ROW NAMES. `Bash` is outside the repair floor —
    // `Operation::Execute`, whose argv this boundary cannot decide — so it stays
    // refused with the sentinel armed. If this ever answers `0`, the ripcord has
    // become the password CLOUD-1357 retired and must not land.
    let dir = fixture("ripcord-not-global", DENIES_ONLY_BASH);
    arm(&dir);
    assert_eq!(
        code(&dir),
        Some(2),
        "the ripcord opens the repair floor, never the whole surface"
    );
}

#[test]
fn the_sentinel_can_be_armed_under_a_config_that_denies_every_write() {
    // THE BOOTSTRAP, AND WITHOUT IT THE MECHANISM IS CIRCULAR. Nothing is armed
    // here, and the config refuses `Write` — so the call that would arm the
    // ripcord is exactly the call the fault denies. Arming grants nothing by
    // itself; the next call still has to be inside the floor.
    let dir = fixture("ripcord-bootstrap", DENIES_THE_REPAIR);
    let target = dir.join(batten::ripcord::SENTINEL);
    assert_eq!(
        code_for(&dir, &write_envelope(&target)),
        Some(0),
        "creating the sentinel is admitted whether or not the sentinel exists"
    );
}

#[test]
fn arming_grants_nothing_on_its_own() {
    // The bootstrap's own mirror: the door above is open unconditionally, so it
    // must open onto nothing. A `Bash` call over the same fixture, with the
    // sentinel NOT armed, is still refused — the write that arms it is admitted,
    // and no other call is.
    let dir = fixture("ripcord-bootstrap-mirror", DENIES_ONLY_BASH);
    assert_eq!(
        code(&dir),
        Some(2),
        "an unarmed tree decides by its rules, and the bootstrap opens no other call"
    );
}

#[test]
fn a_directory_named_like_the_sentinel_is_not_one() {
    // `is_file`, never `exists`. A directory at that path is not a sentinel, and
    // reading one as armed would make an accidental `mkdir` a bypass.
    let dir = fixture("ripcord-directory", DENIES_THE_REPAIR);
    std::fs::create_dir(dir.join(batten::ripcord::SENTINEL)).expect("create the directory");
    assert_eq!(
        code_for(&dir, &envelope("Read", r#"{"file_path":"notes.md"}"#)),
        Some(2),
        "a directory is not the sentinel and grants nothing"
    );
}

#[test]
fn a_pull_says_which_refusal_it_stood_down() {
    // POINTER, NEVER THE PAYLOAD (rule 4). The line names the class and the
    // sentinel, so a reader can find the record; the tool's own input never
    // appears. Saying WHICH refusal was admitted is what keeps this from being
    // the silent bypass again, wearing a record's clothes.
    let dir = fixture("ripcord-pointer", DENIES_THE_REPAIR);
    arm(&dir);
    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &envelope("Read", r#"{"file_path":"notes.md"}"#),
    );
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("admitted by the ripcord"),
        "the pull is announced rather than silent: {said}"
    );
    assert!(
        said.contains(batten::ripcord::SENTINEL),
        "the line names the sentinel a reader has to disarm: {said}"
    );
}
