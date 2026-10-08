//! The emitted mediated line, measured against the declared ceiling
//! (CLOUD-1286).
//!
//! **Over the compiled binary, against the committed `batten.toml`.** A
//! `with input as` case or a fixture registry would fabricate the very thing
//! under test: the question is what an agent in THIS repository actually sees
//! when a real row refuses a real command, and a fixture answers about a tree
//! nobody works in.
//!
//! **WHAT THE CEILING IS A CEILING ON** (CLOUD-1386). It bounds the line an agent
//! reads on EVERY firing, which is the ~300-a-session cost CLOUD-1286 measured.
//! It is not a bound on the once-per-session sighting, where the class's own
//! route travels so a reader meeting it for the first time can act. Those are
//! different quantities and one budget cannot govern both — a ceiling that
//! covered the first sighting would forbid a remedy from ever reaching a reader,
//! which is the defect that cost a session and the reason the route came back.
//!
//! So every measurement here is of a REPEAT firing. `refusal` fires twice and
//! returns the second.
//!
//! The discriminating pair is the whole file. The deny half is that a line over
//! the ceiling is reported; the allow half — anti-vacuity, and the load-bearing
//! one (CLOUD-418) — is that every refusal this repository can actually emit
//! passes. A ceiling that refuses correct output is a gate somebody switches
//! off, and the converted `tool select other` refusal is the specific line
//! the row names.
//!
//! **BOTH ARMS ARE MEASURED HERE NOW, EACH AGAINST ITS OWN CEILING**
//! (CLOUD-1637). The paragraph above is right that the two are different
//! quantities, and it drew the wrong conclusion from that: it left the first
//! sighting measured by nothing. `[refusal] first_sighting_max_tokens` is the
//! second key and the fixture cases below are where it is exercised.
//!
//! The real-root cases stay real-root and stay repeats. The first-sighting cases
//! CANNOT be: the sightings store lives under `$GIT_DIR` and this repository's is
//! full of whatever the working session already saw, so a fixture with its own
//! `$GIT_DIR` is the only way to observe a genuine first firing without reaching
//! into the tree under test. The fixture carries the COMMITTED config, so what it
//! measures is still this repository's rows.
//!
//! **EVERY PAYLOAD NAMES A SESSION (CLOUD-2075).** The store is per context —
//! the session, plus the agent id where a subagent reads — and a payload naming
//! no session is full on every firing and marks nothing. So the real-root
//! repeats fire under one session this suite owns, and the fixture cases name
//! theirs explicitly through [`fires_in`].

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The session the real-root repeats fire under: this suite's own context, so
/// it never consumes a sighting of the working session's.
const SUITE_SESSION: &str = "refusal-ceiling-suite";

fn payload(command: &str) -> String {
    payload_in(Some(SUITE_SESSION), None, command)
}

/// A Bash `PreToolUse` payload in `session` (and `agent`), or naming none.
fn payload_in(session: Option<&str>, agent: Option<&str>, command: &str) -> String {
    let mut value = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    if let Some(session) = session {
        value["session_id"] = serde_json::Value::from(session);
    }
    if let Some(agent) = agent {
        value["agent_id"] = serde_json::Value::from(agent);
    }
    value.to_string()
}

/// The refusal text a mediated call produces on a REPEAT firing, which is what
/// the ceiling governs (CLOUD-1386).
///
/// **The ceiling is a per-firing cost, so it is measured on the firing that
/// repeats.** A class explains itself once per session — the route travels with
/// the first sighting and never again — so measuring whichever firing happened to
/// come first would measure the once-per-session line against a per-firing budget
/// and report a ceiling breach for output that is paid once.
///
/// Fired twice rather than by clearing the store, and deliberately: this suite
/// runs against the REAL repository, so forgetting its sightings would reach into
/// the tree it is measuring. Two firings need no such reach — whatever the store
/// held on entry, the second is a repeat by construction.
fn refusal(command: &str) -> Option<String> {
    repeat_refusal(&payload(command))
}

/// [`refusal`] over any hook payload, not only a Bash command line.
fn repeat_refusal(payload: &str) -> Option<String> {
    let _first_sighting = refusal_once(payload);
    refusal_once(payload)
}

/// One firing, whatever the store says.
fn refusal_once(payload: &str) -> Option<String> {
    let run = run_with_stdin(&root(), &["adjudicate", "--harness", "exit-code"], payload);
    if run.status.code() == Some(2) {
        Some(stderr(&run).trim().to_owned())
    } else {
        None
    }
}

/// The declared ceiling, read from the committed config rather than re-typed.
///
/// Re-typing it here would make this suite pass over a `batten.toml` whose
/// ceiling had been raised or deleted, which is the whole failure the
/// `refusal-ceiling-raised` weakening exists to report.
fn declared_ceiling() -> usize {
    declared("max_tokens")
}

/// The full arm's ceiling, read the same way (CLOUD-2075).
fn declared_first_sighting_ceiling() -> usize {
    declared("first_sighting_max_tokens")
}

fn declared(key: &str) -> usize {
    let text = std::fs::read_to_string(root().join("batten.toml"))
        .expect("the committed config is readable");
    let config: toml::Value = toml::from_str(&text).expect("the committed config parses");
    usize::try_from(
        config
            .get("refusal")
            .and_then(|table| table.get(key))
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| panic!("`[refusal] {key}` is declared")),
    )
    .expect("a ceiling is not negative")
}

/// The committed `reason` of one `[[rule]]` row.
fn rule_reason(id: &str) -> String {
    let text = std::fs::read_to_string(root().join("batten.toml"))
        .expect("the committed config is readable");
    let config: toml::Value = toml::from_str(&text).expect("the committed config parses");
    config
        .get("rule")
        .and_then(toml::Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
        })
        .and_then(|row| row.get("reason"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("`{id}` declares a reason"))
        .trim()
        .to_owned()
}

/// `budget.rs`'s estimator, which is what the engine's own `Ceiling::over` uses.
fn estimated_tokens(line: &str) -> usize {
    line.len() / 4
}

/// The mediated commands this repository's rows actually refuse, one per
/// composer that can fire from a Bash call.
///
/// Not every declared class — the ones reachable from a mediated command line,
/// because those are what the ~300 firings a session are made of.
const CORPUS: &[&str] = &[
    // The row CLOUD-1286's acceptance names by name.
    "sed -n '1,40p' AGENTS.md",
    "head -40 batten.toml",
    "cat .serena/project.yml",
    // The three discard shapes.
    "mise run verify | tail -1",
    "mise run verify >log 2>&1; ls",
    "nohup mise run verify &",
];

#[test]
fn every_mediated_refusal_this_tree_emits_is_within_the_declared_ceiling() {
    // ANTI-VACUITY, and it is the case that decides whether the ceiling is a
    // gate or a switch waiting to be flipped. If this fails, the answer is
    // almost never to raise the number.
    let ceiling = declared_ceiling();
    let mut over: Vec<(usize, String)> = Vec::new();
    for command in CORPUS {
        let Some(line) = refusal(command) else {
            panic!("the corpus must refuse, or it measures nothing: {command}");
        };
        let cost = estimated_tokens(&line);
        if cost > ceiling {
            over.push((cost, line));
        }
    }
    assert!(
        over.is_empty(),
        "every emitted line must be within the declared ceiling of {ceiling}: {over:?}"
    );
}

#[test]
fn a_routed_read_of_every_committed_memory_is_within_the_declared_ceiling() {
    // THE CORPUS ABOVE IS BASH ONLY, and `path read routed` fires on a `Read`
    // (CLOUD-1929): its line carries the path AND the row's `read` remedy, so its
    // cost grows with the name. Every memory is enumerated rather than one named,
    // because the longest name is the one that breaches — measured at 101 bytes
    // against a 96-byte ceiling while the tool rode as a third subject.
    let ceiling = declared_ceiling();
    let memories = root().join(".serena/memories");
    let mut measured = 0_usize;
    let mut over: Vec<(usize, String)> = Vec::new();
    for entry in std::fs::read_dir(&memories).expect("the committed memories are listable") {
        let name = entry.expect("a memory entry").file_name();
        let path = format!(".serena/memories/{}", name.to_string_lossy());
        let encoded = serde_json::to_string(&path).expect("a path is encodable");
        let read = format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\
             \"tool_input\":{{\"file_path\":{encoded}}}}}"
        );
        let Some(line) = repeat_refusal(&read) else {
            panic!("a generic read of a memory must refuse, or this measures nothing: {path}");
        };
        measured += 1;
        let cost = estimated_tokens(&line);
        if cost > ceiling {
            over.push((cost, line));
        }
    }
    assert!(measured > 0, "the memory store is not empty");
    assert!(
        over.is_empty(),
        "every routed-read line must be within the declared ceiling of {ceiling}: {over:?}"
    );
}

#[test]
fn a_declared_refusal_emits_its_class_and_its_pointers_and_stops() {
    // The acceptance, asserted on the shape rather than on the count: no
    // `Refused by` prefix, no parenthetical gloss, no `Fix:` clause, and no
    // hatch sentence. Each of the four was a copy of something declared once.
    let line = refusal("sed -n '1,40p' AGENTS.md").expect("the row refuses");
    assert!(
        line.starts_with("verdict 'tool run loose' rule 'tool select other'"),
        "the labelled class leads the line: {line}"
    );
    for wrapper in ["Refused by", "Fix:", "Bypass with", " ("] {
        assert!(
            !line.contains(wrapper),
            "the emitted line must not carry `{wrapper}`: {line}"
        );
    }
}

#[test]
fn no_refusal_lost_its_pointer() {
    // The acceptance clause that keeps this from being achieved by saying less
    // about WHICH file. The prose is what shortened; the pointer is what the
    // reader acts on, and it stayed inline for exactly that reason.
    let line = refusal("head -40 batten.toml").expect("the row refuses");
    assert!(
        line.contains("batten.toml"),
        "the operand a caller can act on stays inline: {line}"
    );
}

/// A fixture repository carrying the COMMITTED config and modules.
///
/// Its own `$GIT_DIR`, which is the whole reason it exists: the sightings store
/// lives there, so a fixture is a session that has seen nothing. The real root
/// cannot answer a first-sighting question — its store holds whatever the running
/// session already met — and clearing it would reach into the tree under test.
///
/// Modules copied by ENUMERATION rather than by name, for `board_receipts`'
/// stated reason: naming a consumer's policy filenames inside `crates/**` is
/// non-negotiable rule 1, and `source name other` computes that.
fn fixture(name: &str) -> PathBuf {
    stage(name, COMMITTED)
}

/// The committed config, as every fixture here stages it.
const COMMITTED: &str = include_str!("../../../../batten.toml");

/// [`fixture`] for a case that sends a `SessionStart`, with the committed
/// config's session provisioning removed: every `[[startup]]` row and every
/// `session-start` handler.
///
/// The engine's own session-start work — forgetting a context's sightings,
/// re-delivering them on a compaction — runs before any declared row and is what
/// those cases assert. The declared rows are this repository's provisioning, and
/// in a fixture they are worse than irrelevant: the fixture lives under
/// `target/tmp`, mise walks up to this checkout's `mise.toml`, and each `mise run
/// session:*` then provisions the HOST — `mise install`, the git hooks, `wiring
/// reclaim -y`, a forge probe over the network. Measured 2026-10-08
/// (CLOUD-2173): 200 spawned processes and 78s for one `SessionStart` alone, and
/// 260s under the suite, which made each such case the suite's critical path.
//MUTANT-SUITE crates/batten/tests/it/refusal_ceiling.rs
//MUTANT session-startup-rows-kept|s@^    config\.remove("startup");$@@|the_session_fixture_carries_no_session_provisioning
//MUTANT session-start-handlers-kept|s@^            \.retain(\x7crow\x7c row\.get("on")\.and_then(toml_edit::Item::as_str) != Some("session-start"));$@            .retain(\x7c_\x7c true);@|the_session_fixture_carries_no_session_provisioning
fn session_fixture(name: &str) -> PathBuf {
    let mut config: toml_edit::DocumentMut =
        COMMITTED.parse().expect("the committed config is TOML");
    config.remove("startup");
    if let Some(handlers) = config
        .get_mut("hook")
        .and_then(|hook| hook.get_mut("handler"))
        .and_then(toml_edit::Item::as_array_of_tables_mut)
    {
        handlers
            .retain(|row| row.get("on").and_then(toml_edit::Item::as_str) != Some("session-start"));
    }
    stage(name, &config.to_string())
}

/// How many `[[startup]]` rows and `session-start` handlers `config` declares.
fn session_provisioning(config: &str) -> (usize, usize) {
    let config: toml_edit::DocumentMut = config.parse().expect("a TOML config");
    let startup = config
        .get("startup")
        .and_then(toml_edit::Item::as_array_of_tables)
        .map_or(0, toml_edit::ArrayOfTables::len);
    let handlers = config
        .get("hook")
        .and_then(|hook| hook.get("handler"))
        .and_then(toml_edit::Item::as_array_of_tables)
        .map_or(0, |rows| {
            rows.iter()
                .filter(|row| {
                    row.get("on").and_then(toml_edit::Item::as_str) == Some("session-start")
                })
                .count()
        });
    (startup, handlers)
}

/// Stage `config` and the committed policy modules in a fixture named `name`.
fn stage(name: &str, config: &str) -> PathBuf {
    let staged = Fixture::new(name).config(config);
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let entry = entry.expect("a policy directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(entry.file_name())).expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

/// One firing in a fixture under session `s1`, returning the emitted line.
fn fires(repo: &Path, command: &str) -> String {
    fires_in(repo, Some("s1"), None, command)
}

/// One firing in a fixture in `session` (plus `agent`), returning the line.
fn fires_in(repo: &Path, session: Option<&str>, agent: Option<&str>, command: &str) -> String {
    let run = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload_in(session, agent, command),
    );
    assert_eq!(
        run.status.code(),
        Some(2),
        "the corpus must refuse, or it measures nothing: {command}"
    );
    stderr(&run).trim().to_owned()
}

/// A hook event other than a Bash call, through the Claude Code adapter.
fn hook(repo: &Path, value: &serde_json::Value) -> std::process::Output {
    run_with_stdin(
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &value.to_string(),
    )
}

const FULL: &str = " — ";

/// The first sighting of a document-only class carries its definition.
///
/// **THE CASE THE ROW WAS FILED ON.** `tool run loose` declares exactly one
/// route and its kind is `document`, so under the old renderer — which filled
/// `routes` from `command_routes` — the list was empty, the empty-routes early
/// return fired, and the FIRST sighting emitted the same bare token as a repeat.
/// The gloss rendered on no arm at all. 144 of 201 classes were in that state.
///
/// The route target is `rules/scanning.md` and NOT `.claude/rules/scanning.md`:
/// the latter is a pointer stub since CLOUD-1152, because five of the six
/// harnesses in `Harness` cannot read `.claude/`. Rendering the stub would send a
/// refused reader one hop further for nothing.
#[test]
fn a_first_sighting_carries_the_gloss_and_its_route_by_kind() {
    let repo = fixture("first-sighting-document-route");
    let line = fires(&repo, "head -40 batten.toml");
    assert!(
        line.starts_with("verdict 'tool run loose'"),
        "the class still leads the line: {line}"
    );
    assert!(
        line.contains("batten.toml"),
        "the pointer stays inline: {line}"
    );
    assert!(
        line.contains("tool select other"),
        "the rule id is the hop to the row's own remedy: {line}"
    );
    assert!(
        line.contains(" — "),
        "the gloss clause is present on a first sighting: {line}"
    );
    assert!(
        line.contains("a shell text utility stood in for the structured file surface"),
        "and it is the class's declared gloss: {line}"
    );
    assert!(
        line.contains("read rules/scanning.md"),
        "a `document` route renders as a read of the authority: {line}"
    );
    assert!(
        !line.contains(".claude/rules/scanning.md"),
        "and names the authority rather than the stub (CLOUD-1152): {line}"
    );
}

/// A shape deny's first sighting names the verb that prints the ROW's remedy,
/// never the file that refused it (CLOUD-1806).
///
/// The class's only route used to be `read batten.toml` — back to the config the
/// refusing row lives in. The `read batten.toml` negation and the `policy
/// explain` assertion stay here even once the line carries the row's real id,
/// because those are what discriminate a regression to the circular route.
#[test]
fn a_shape_first_sighting_names_the_rows_remedy_verb() {
    let repo = fixture("shape-first-sighting-remedy");
    let line = fires(&repo, "gh pr merge 5");
    for needle in [
        "call name refused",
        "commit ship other",
        "batten policy explain '",
    ] {
        assert!(line.contains(needle), "{needle} missing: {line}");
    }
    assert!(
        !line.contains("read batten.toml"),
        "the route must not send the reader back to the refusing file: {line}"
    );
    let explained = common::run(&repo, &["policy", "explain", "call name refused"]);
    let said = String::from_utf8_lossy(&explained.stdout);
    assert!(
        said.contains("articulate the call"),
        "the class declares its override route: {said}"
    );
    assert!(
        !said.contains("batten.toml"),
        "and no route names the config file: {said}"
    );
}

/// The pointer arm is a byte PREFIX of the full arm, and sheds no pointer
/// (CLOUD-2075 §7 case 2).
///
/// This reverses the repeat that dropped its routes: everything the pointer arm
/// says, the full arm said first and in the same order, and the subjects and
/// routes — every way out — are the same set on both.
#[test]
fn the_pointer_arm_carries_every_route_and_subject_the_full_arm_does() {
    let repo = fixture("pointer-carries-routes");
    let first = fires(&repo, "head -40 batten.toml");
    let repeat = fires(&repo, "head -40 batten.toml");
    assert_ne!(first, repeat, "the two arms differ, or nothing was saved");
    assert!(
        first.starts_with(&repeat),
        "the pointer is a byte prefix of the full arm: {repeat:?} vs {first:?}"
    );
    assert!(!repeat.contains(FULL), "the pointer has no tail: {repeat}");
    let head = first.split(FULL).next().expect("a head");
    assert_eq!(head, repeat, "the full arm's pointers ARE the pointer arm");
    for kept in [
        "rule 'tool select other'",
        "batten.toml",
        "read rules/scanning.md",
        "run batten policy explain 'tool select other' 'tool run loose'",
    ] {
        assert!(
            repeat.contains(kept),
            "the pointer keeps `{kept}`: {repeat}"
        );
    }
}

/// The full arm carries the row's own reason and both labels (CLOUD-2075 §7
/// case 1), reversing the first sighting that left the reason out.
#[test]
fn a_first_sighting_carries_the_rows_reason_and_both_labels() {
    let repo = fixture("first-sighting-reason");
    let line = fires(&repo, "head -40 batten.toml");
    let reason = rule_reason("tool select other");
    let opening: String = reason.chars().take(40).collect();
    for needle in [
        "verdict 'tool run loose'",
        "rule 'tool select other'",
        "a shell text utility stood in for the structured file surface",
        opening.as_str(),
        "read rules/scanning.md",
        "run batten policy explain 'tool select other' 'tool run loose'",
    ] {
        assert!(line.contains(needle), "`{needle}` missing: {line}");
    }
    // ONE HOP (CLOUD-2142): the line names its lookup once, for both names.
    assert_eq!(
        line.matches("batten policy").count(),
        1,
        "exactly one lookup per line: {line}"
    );
}

/// A live class carrying `doc`, over the real load-time validator (CLOUD-2143).
fn documented(why: Option<&str>, act: &[&str]) -> batten::verdict::DeclaredVerdict {
    let mut class = batten::verdict::vendored()
        .into_iter()
        .find(|class| class.id == "tool run loose")
        .expect("a vendored class to dress");
    class.doc = batten::doc::Doc {
        why: why.map(str::to_owned),
        act: act.iter().map(|item| (*item).to_owned()).collect(),
        dont: Vec::new(),
    };
    class
}

fn loads(class: batten::verdict::DeclaredVerdict) -> Result<(), String> {
    batten::verdict::validate(&[class], &batten::verdict::Vocabulary::default())
        .map_err(|error| error.to_string())
}

/// The load tier of the first sighting's budget (CLOUD-2143): over 640 bytes
/// does not load, and the same class under it does — the anti-vacuity half.
#[test]
fn a_class_doc_over_640_bytes_does_not_load() {
    let small = documented(Some("A short reason"), &["do the one thing"]);
    assert_eq!(loads(small), Ok(()), "a doc within budget loads");
    let item = "x".repeat(200);
    let big = documented(Some("A short reason"), &[&item, &item, &item]);
    let refused = loads(big).expect_err("a 640-byte-plus doc is refused at load");
    assert!(refused.contains("640"), "{refused}");
}

#[test]
fn a_class_doc_citing_an_issue_key_does_not_load() {
    let cited = documented(Some("Measured on ABC-123"), &["do the one thing"]);
    let refused = loads(cited).expect_err("an issue key in a doc is refused");
    assert!(refused.contains("issue key"), "{refused}");
}

#[test]
fn a_class_doc_with_two_sentence_why_does_not_load() {
    let two = documented(Some("One thing. Another thing"), &["do the one thing"]);
    assert!(loads(two).is_err(), "`why` is one sentence");
}

/// Every id the engine raises with no `[[rule]]` row resolves to a definition
/// compiled into the binary (CLOUD-2142), and an unknown name to none.
///
/// The suite [`batten::verdict`]'s `native-table-empty` mutant is killed in.
#[test]
fn a_native_rule_id_has_a_definition() {
    for name in [
        "engine-cannot-adjudicate",
        "program-unknown",
        "stop.unfinished",
        "hook.handler.some-id",
    ] {
        let definition = batten::verdict::native_definition(name)
            .unwrap_or_else(|| panic!("{name} resolves to nothing"));
        assert!(!definition.trim().is_empty(), "{name}: empty definition");
    }
    for unknown in ["hook.handler.", "no-such-engine-id", ""] {
        assert_eq!(
            batten::verdict::native_definition(unknown),
            None,
            "{unknown}"
        );
    }
}

/// A collapsed row — id equal to its class — still labels both (CLOUD-2075 §7
/// case 3), on both arms.
#[test]
fn a_collapsed_row_still_labels_rule_and_verdict() {
    let repo = fixture("collapsed-row-labels");
    let command = "git push --force-with-lease origin main";
    let both = "verdict 'branch write unsafe' rule 'branch write unsafe'";
    let first = fires(&repo, command);
    let repeat = fires(&repo, command);
    assert!(first.starts_with(both), "{first}");
    assert!(repeat.starts_with(both), "{repeat}");
}

/// Two contexts in one clone never consume each other's sighting (CLOUD-2075
/// §7 case 4): session A, session B, and A's subagent each get the full arm.
#[test]
fn two_contexts_in_one_clone_each_get_the_full_text() {
    let repo = fixture("two-contexts");
    let command = "head -40 batten.toml";
    let a = fires_in(&repo, Some("A"), None, command);
    let b = fires_in(&repo, Some("B"), None, command);
    let sub = fires_in(&repo, Some("A"), Some("x"), command);
    let again = fires_in(&repo, Some("A"), None, command);
    assert!(a.contains(FULL), "{a}");
    assert!(b.contains(FULL), "another session is its own reader: {b}");
    assert!(sub.contains(FULL), "a subagent is its own reader: {sub}");
    assert!(
        !again.contains(FULL),
        "A's second firing is the pointer: {again}"
    );
}

/// The session fixture stages no session provisioning, and the committed config
/// has some to strip (CLOUD-2173).
///
/// The second half is the anti-vacuity: were the committed config ever to
/// declare none, the first half would pass over a strip that removes nothing, and
/// the two `SessionStart` cases below would still be fast for a reason this case
/// no longer proves.
#[test]
fn the_session_fixture_carries_no_session_provisioning() {
    let (startup, handlers) = session_provisioning(COMMITTED);
    assert!(
        startup > 0,
        "the committed config declares `[[startup]]` rows"
    );
    assert!(
        handlers > 0,
        "the committed config declares session-start handlers"
    );
    let repo = session_fixture("session-provisioning-stripped");
    let staged = std::fs::read_to_string(repo.join("batten.toml")).expect("the staged config");
    assert_eq!(
        session_provisioning(&staged),
        (0, 0),
        "a SessionStart in this fixture must not provision the host"
    );
}

/// A `SessionStart` forgets one context and leaves the rest (CLOUD-2075 §7
/// case 5).
#[test]
fn a_session_start_forgets_only_that_contexts_sightings() {
    let repo = session_fixture("session-start-scoped");
    let command = "head -40 batten.toml";
    let _ = fires_in(&repo, Some("A"), None, command);
    let _ = fires_in(&repo, Some("B"), None, command);
    let started = hook(
        &repo,
        &serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "A",
            "source": "startup",
        }),
    );
    assert_eq!(started.status.code(), Some(0), "{}", stderr(&started));
    let a = fires_in(&repo, Some("A"), None, command);
    let b = fires_in(&repo, Some("B"), None, command);
    assert!(a.contains(FULL), "A was forgotten, so A is told again: {a}");
    assert!(!b.contains(FULL), "B was not touched: {b}");
}

/// A compaction re-delivers every item the cycle saw, at once (CLOUD-2075 §7
/// case 6), and keeps it marked.
#[test]
fn a_compaction_redelivers_every_seen_item_once_at_session_start() {
    let repo = session_fixture("compaction-redelivers");
    let command = "head -40 batten.toml";
    let full = fires_in(&repo, Some("A"), None, command);
    assert!(full.contains(FULL), "{full}");
    let compacted = hook(
        &repo,
        &serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "A",
            "source": "compact",
        }),
    );
    assert_eq!(compacted.status.code(), Some(0), "{}", stderr(&compacted));
    let document: serde_json::Value = String::from_utf8_lossy(&compacted.stdout)
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .expect("the session start emits its advisory document");
    let context = document["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("an additionalContext string");
    assert!(
        context.contains(&full),
        "the full arm is re-delivered byte for byte: {context}"
    );
    let next = fires_in(&repo, Some("A"), None, command);
    assert!(!next.contains(FULL), "and stays marked: {next}");
}

/// An edit to a definition mid-cycle is a new item (CLOUD-2075 §7 case 7,
/// CLOUD-1582's pair absorbed).
#[test]
fn an_edited_definition_is_a_new_item_mid_cycle() {
    let repo = fixture("definition-edited");
    let command = "head -40 batten.toml";
    let first = fires_in(&repo, Some("A"), None, command);
    assert!(first.contains(FULL), "{first}");
    let config = repo.join("batten.toml");
    let text = std::fs::read_to_string(&config).expect("the fixture config");
    let reason = rule_reason("tool select other");
    let opening: String = reason.chars().take(40).collect();
    assert!(
        text.contains(&opening),
        "the fixture carries the committed reason"
    );
    let edited = text.replacen(&opening, "An edited sentence names the same remedy", 1);
    std::fs::write(&config, edited).expect("rewrite the fixture config");
    let second = fires_in(&repo, Some("A"), None, command);
    assert!(
        second.contains(FULL) && second.contains("An edited sentence"),
        "an edited definition renders in full again: {second}"
    );
    let third = fires_in(&repo, Some("A"), None, command);
    assert!(!third.contains(FULL), "an unchanged one does not: {third}");
}

/// A payload naming no session is full on every firing and marks nothing
/// (CLOUD-2075 §7 case 8).
#[test]
fn a_session_less_payload_is_full_on_every_firing() {
    let repo = fixture("session-less");
    let command = "head -40 batten.toml";
    let first = fires_in(&repo, None, None, command);
    let second = fires_in(&repo, None, None, command);
    assert!(first.contains(FULL) && second.contains(FULL), "{second}");
    assert!(
        !repo.join(".git/batten-sightings").exists(),
        "a reader that cannot be named shares no key"
    );
}

/// The `PostToolUse` boundary marks a full arm read from tool output
/// (CLOUD-2075 §7 case 9); a later hook firing in that context is the pointer.
#[test]
fn the_boundary_marks_and_collapses_a_full_arm_in_tool_output() {
    let repo = fixture("boundary-marks");
    let command = "head -40 batten.toml";
    let full = fires_in(&repo, Some("B"), None, command);
    assert!(full.contains(FULL), "{full}");
    let output = format!("{full}\ncanary\n{full}\n");
    let posted = hook(
        &repo,
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": "A",
            "tool_name": "Bash",
            "tool_input": {"command": "batten check"},
            "tool_response": {"stdout": output, "stderr": "", "interrupted": false},
        }),
    );
    assert_eq!(posted.status.code(), Some(0), "{}", stderr(&posted));
    let rewrites = batten::hook::Harness::ClaudeCode
        .capabilities()
        .rewrites_tool_output
        .is_capturable();
    let said = String::from_utf8_lossy(&posted.stdout);
    if rewrites {
        assert!(said.contains("updatedToolOutput"), "{said}");
    } else {
        assert!(
            !said.contains("updatedToolOutput"),
            "no rewrite where none is measured: {said}"
        );
    }
    let next = fires_in(&repo, Some("A"), None, command);
    assert!(!next.contains(FULL), "the boundary marked it: {next}");
}

/// Every arm the corpus emits is within its declared ceiling (CLOUD-2075 §7
/// case 1b): the full arm against `first_sighting_max_tokens`, the pointer arm
/// against `max_tokens`. A measurement, so it prints what it measured.
#[test]
fn every_arm_the_corpus_emits_is_within_its_declared_ceiling() {
    let full_ceiling = declared_first_sighting_ceiling();
    let pointer_ceiling = declared_ceiling();
    let repo = fixture("corpus-arms");
    let mut widest = (0_usize, String::new(), 0_usize, String::new());
    let mut over: Vec<(usize, String)> = Vec::new();
    for (index, command) in CORPUS.iter().enumerate() {
        let session = format!("corpus-{index}");
        let full = fires_in(&repo, Some(&session), None, command);
        let pointer = fires_in(&repo, Some(&session), None, command);
        let (full_cost, pointer_cost) = (estimated_tokens(&full), estimated_tokens(&pointer));
        if full_cost > widest.0 {
            widest.0 = full_cost;
            widest.1.clone_from(&full);
        }
        if pointer_cost > widest.2 {
            widest.2 = pointer_cost;
            widest.3.clone_from(&pointer);
        }
        if full_cost > full_ceiling {
            over.push((full_cost, full));
        }
        if pointer_cost > pointer_ceiling {
            over.push((pointer_cost, pointer));
        }
    }
    // THE MEASUREMENT IS THE OUTPUT: the `[refusal]` comment's table is read
    // off these two lines (CLOUD-2075 §E), so they print pass or fail.
    #[expect(
        clippy::print_stderr,
        reason = "the case reports the measured widest arm the ceilings are declared from"
    )]
    {
        eprintln!("measured full {} {}", widest.0, widest.1);
        eprintln!("measured pointer {} {}", widest.2, widest.3);
    }
    assert!(over.is_empty(), "over a declared ceiling: {over:?}");
}

/// The store is WRITTEN between the two firings, which is what makes the arms
/// switch.
///
/// The filing session found `.git/batten-sightings` absent after hundreds of
/// refusals and could not explain it. This is that measurement: absent before,
/// present after, so a session that sees no compact arm has a store that did not
/// write rather than a renderer that did not switch.
#[test]
fn the_sightings_store_is_written_by_a_first_firing() {
    let repo = fixture("sightings-store-written");
    let store = repo.join(".git/batten-sightings");
    assert!(
        !store.exists(),
        "a fixture is a session that has seen nothing"
    );
    let _first = fires(&repo, "head -40 batten.toml");
    assert!(
        store.exists(),
        "the first firing marks the rule, or every firing is a first sighting"
    );
}

/// Two rows raising ONE class each get their own first sighting.
///
/// **The second amendment's correction, as a case.** The store digested the CLASS
/// token for its whole life, so under a shared class the first row to fire
/// consumed the sighting for all of them and the next row's first firing rendered
/// as a repeat — its rule-specific remedy never pointed at. Every plain `shape`
/// row (eleven in this config when CLOUD-1806 counted) raises `call name
/// refused`; two of them are enough to decide it.
#[test]
fn a_second_row_of_a_shared_class_still_gets_its_definition() {
    let repo = fixture("shared-class-two-rows");
    let first = fires(&repo, "cargo build");
    assert!(
        first.contains(" — "),
        "row one's first firing carries its definition: {first}"
    );
    let other = fires(&repo, "sed -n '1,40p' AGENTS.md");
    assert!(
        other.contains(" — "),
        "and row two's first firing is not consumed by row one's: {other}"
    );
    assert_ne!(
        first, other,
        "two rows, two rule ids, two definitions — not one class's line twice"
    );
}

/// Every vendored class whose only ways out end in a protected path stays
/// admissible, through its own override or through the blocker's (CLOUD-1893).
///
/// A starter consumer protects `batten.toml`, and dozens of vendored classes
/// route only into it; one admission on `path write refused` is what keeps them
/// from being a deadlock. The population is DERIVED, never counted, so a row
/// moving a class in or out of the family touches neither side.
#[test]
fn every_class_routed_only_into_a_protected_path_is_admissible() {
    use batten::verdict::{RouteKind, routed_only_into_protection, vendored};
    let starter = batten::config::parse(batten::init::STARTER, batten::config::CONFIG_FILE)
        .expect("the starter parses");
    let sets = batten::rules::Sets::from_config(&starter).expect("the starter's sets compile");
    let protects = |path: &str| sets.protected.contains(path);
    assert!(
        protects(batten::config::CONFIG_FILE),
        "the starter no longer protects batten.toml, so this gate covers nothing — re-scope it"
    );

    let registry = vendored();
    let stuck = routed_only_into_protection(&registry, protects);
    assert!(
        stuck.is_empty(),
        "classes routed only into a protected path with no admission: {stuck:?}"
    );

    let blocker = batten::verdict::Native::ProtectedMutation.id();
    let mut without = registry.clone();
    let entry = without
        .iter_mut()
        .find(|entry| entry.id == blocker)
        .expect("the blocker is vendored");
    let before = entry.routes.len();
    entry
        .routes
        .retain(|route| route.kind != RouteKind::Override);
    assert!(
        entry.routes.len() < before,
        "the blocker declares an admission to remove"
    );

    let historical: Vec<String> = registry
        .iter()
        .filter(|entry| entry.successor.is_none() && entry.withdrawn.is_none())
        .filter(|entry| {
            entry.routes.len() == 1
                && entry.routes[0].kind == RouteKind::Document
                && entry.routes[0].target == batten::config::CONFIG_FILE
        })
        .map(|entry| entry.id.clone())
        .collect();
    let got = routed_only_into_protection(&without, protects);
    assert!(!historical.is_empty(), "the CLOUD-1357 family is not empty");
    for id in &historical {
        assert!(
            got.contains(id),
            "{id} routes only into batten.toml: {got:?}"
        );
    }
    for id in &got {
        let entry = without
            .iter()
            .find(|entry| &entry.id == id)
            .expect("a returned id names a class");
        assert!(
            entry.routes.iter().all(|route| !matches!(
                route.kind,
                RouteKind::Override | RouteKind::Command | RouteKind::Issue
            )),
            "{id} has a way out of its own and was returned anyway"
        );
    }
}

/// Every class this config declares can render a route on a first sighting.
///
/// The completeness arm the row asks for, and the one that would have caught the
/// defect at load rather than in production. Read off the committed config
/// directly — no spawn per class — because the question is a property of the
/// declared table: a class whose only routes are `override` renders no way out,
/// and `override` is excluded from the clause by construction.
#[test]
fn no_declared_class_would_render_a_first_sighting_with_no_route() {
    let text = std::fs::read_to_string(root().join("batten.toml"))
        .expect("the committed config is readable");
    let config: toml::Value = toml::from_str(&text).expect("the committed config parses");
    let verdicts = config
        .get("verdict")
        .and_then(toml::Value::as_array)
        .expect("`[[verdict]]` rows are declared");
    let mut bare: Vec<String> = Vec::new();
    for entry in verdicts {
        let id = entry
            .get("id")
            .and_then(toml::Value::as_str)
            .expect("a class has an id");
        // A tombstone is exempt: nothing raises it, so it renders nowhere.
        if entry.get("successor").is_some() || entry.get("withdrawn").is_some() {
            continue;
        }
        let renders = entry
            .get("route")
            .and_then(toml::Value::as_array)
            .is_some_and(|routes| {
                routes.iter().any(|route| {
                    route.get("kind").and_then(toml::Value::as_str) != Some("override")
                })
            });
        if !renders {
            bare.push(id.to_owned());
        }
    }
    assert!(
        bare.is_empty(),
        "every declared class must render at least one `run`/`read`/`see` route on \
         its first sighting; these would render none: {bare:?}"
    );
}

#[test]
fn the_ceiling_can_fail() {
    // CLOUD-418: a gate nobody has seen fail is a gate nobody knows works. The
    // engine's own comparison is exercised here rather than the corpus above,
    // because the tree passing is the point of the corpus and a tree that could
    // fail it would be a defect rather than a fixture.
    let ceiling = declared_ceiling();
    let long = "path write refused ".to_owned() + &"a/very/deep/".repeat(60) + "file.rs";
    assert!(
        estimated_tokens(&long) > ceiling,
        "a line this long must be over the ceiling, or the comparison decides nothing"
    );
    let full_ceiling = declared_first_sighting_ceiling();
    let long_full = long.clone() + " — " + &"a sentence that runs on ".repeat(80);
    assert!(
        estimated_tokens(&long_full) > full_ceiling,
        "a full arm this long must be over its ceiling, or that comparison decides nothing"
    );
    let short = refusal("nohup mise run verify &").expect("the row refuses");
    assert!(
        estimated_tokens(&short) <= ceiling,
        "and a real one must be under it: {short}"
    );
}
