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

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, run_with_stdin_at_real_root, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
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
    let _first_sighting = refusal_once(command);
    refusal_once(command)
}

/// One firing, whatever the store says.
fn refusal_once(command: &str) -> Option<String> {
    let run = run_with_stdin_at_real_root(
        &root(),
        &["adjudicate", "--harness", "exit-code"],
        &payload(command),
    );
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
    let text = std::fs::read_to_string(root().join("batten.toml"))
        .expect("the committed config is readable");
    let config: toml::Value = toml::from_str(&text).expect("the committed config parses");
    usize::try_from(
        config
            .get("refusal")
            .and_then(|table| table.get("max_tokens"))
            .and_then(toml::Value::as_integer)
            .expect("`[refusal] max_tokens` is declared"),
    )
    .expect("a ceiling is not negative")
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
fn a_declared_refusal_emits_its_class_and_its_pointers_and_stops() {
    // The acceptance, asserted on the shape rather than on the count: no
    // `Refused by` prefix, no parenthetical gloss, no `Fix:` clause, and no
    // hatch sentence. Each of the four was a copy of something declared once.
    let line = refusal("sed -n '1,40p' AGENTS.md").expect("the row refuses");
    assert!(
        line.starts_with("tool run loose"),
        "the class leads the line: {line}"
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
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
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

/// One firing in a fixture, returning the emitted line.
fn fires(repo: &Path, command: &str) -> String {
    let run = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(command),
    );
    assert_eq!(
        run.status.code(),
        Some(2),
        "the corpus must refuse, or it measures nothing: {command}"
    );
    stderr(&run).trim().to_owned()
}

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
        line.starts_with("tool run loose"),
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

/// The repeat is compact, and a byte PREFIX of the first sighting.
///
/// The prefix property is what makes the two arms one line rather than two
/// renderings: everything the repeat says, the first sighting said first and in
/// the same order. A reader who has met the class recognises the compact form as
/// the head of what they already read.
#[test]
fn a_repeat_drops_the_definition_and_keeps_the_pointers() {
    let repo = fixture("repeat-is-compact");
    let first = fires(&repo, "head -40 batten.toml");
    let repeat = fires(&repo, "head -40 batten.toml");
    assert_ne!(first, repeat, "the two arms differ, or nothing was saved");
    assert!(
        first.starts_with(&repeat),
        "the repeat is a byte prefix of the first sighting: {repeat:?} vs {first:?}"
    );
    assert!(
        repeat.contains("tool select other"),
        "the rule id stays on the repeat arm — for 66 rows it is the only \
         discriminator (CLOUD-1637's second amendment): {repeat}"
    );
    for dropped in [" — ", "read rules/scanning.md"] {
        assert!(
            !repeat.contains(dropped),
            "the repeat drops `{dropped}`: {repeat}"
        );
    }
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
/// as a repeat — its rule-specific remedy never pointed at. Fourteen `shape` rows
/// in this config raise `call name refused`; two of them are enough to decide it.
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
    let long = "path write refused ".to_owned() + &"a/very/deep/".repeat(20) + "file.rs";
    assert!(
        estimated_tokens(&long) > ceiling,
        "a line this long must be over the ceiling, or the comparison decides nothing"
    );
    let short = refusal("nohup mise run verify &").expect("the row refuses");
    assert!(
        estimated_tokens(&short) <= ceiling,
        "and a real one must be under it: {short}"
    );
}
