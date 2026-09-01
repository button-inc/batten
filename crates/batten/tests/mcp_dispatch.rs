//! `batten mcp call`, over the compiled binary (CLOUD-1260).
//!
//! # Why this tier exists beside the module's own cases
//!
//! `mcp.rs`'s unit cases pin the PREDICATE — which fields a reduction keeps, what
//! a token refuses, how the three could-not-look answers differ. They cannot pin
//! that the ENGINE builds the input the predicate reads: a case constructing an
//! `McpConfig` by hand fabricates the very shape the config loader may be unable
//! to produce, which is `.claude/rules/policy-modules.md`'s two-tier rule one
//! layer out of Rego. Both live instances of that class in this repository were
//! found by adding the second tier, not by reading.
//!
//! # The bound this suite states rather than pretending past
//!
//! **A completed dispatch is not hermetically testable here, and that is a
//! property of the transport rather than of the effort spent.** `fetch` is built
//! `https_only`, so a loopback listener cannot be reached at all — a *trusted*
//! local certificate is unreachable by construction, because the roots are
//! vendored and nothing signs a loopback CA. `fetch.rs`'s own header records the
//! same limit for the same reason.
//!
//! So the compiled-binary tier covers everything up to the socket: config
//! loading, wiring resolution and each of its refusals, the exit class each
//! refusal lands in, and the pointer discipline over every message. What a
//! successful exchange returns is the module tier's, over a response value.
//! Claiming a live dispatch case here would be coverage rather than a test.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, at_root, run, stderr, stdout};

/// A repository declaring one repo-relative wiring source and one reduction.
fn repo_declaring(name: &str, wiring: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            r#"
version = 1

[[mcp.source]]
id = "project"
path = "wiring.json"
node = "mcpServers"

[[mcp.result]]
method = "get_thing"
reduce = "project"
fields = ["id", "status"]
"#,
        )
        .file("wiring.json", wiring)
        .git()
        .build()
}

#[test]
fn the_verb_is_declared_and_is_not_on_the_read_only_allowlist() {
    // §5's agent allowlist is DERIVED from the effect field, so an optimistic
    // `read` here would widen it silently. The spec is the authority a consumer
    // reads, which is why this asserts over the emitted spec rather than over
    // `SURFACE` — a consumer never sees the constant.
    let spec = run(Path::new("."), &["spec", "--format", "json"]);
    assert!(spec.status.success(), "the spec renders");
    let rendered = stdout(&spec);
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("the spec is JSON");
    let call = find_command(&parsed, "mcp call").expect("`mcp call` is declared");
    assert_ne!(
        call.get("effect").and_then(serde_json::Value::as_str),
        Some("read"),
        "`mcp call` makes an outbound call and writes the capture store, so a `read` \
         classification would put it on the derived read-only allowlist"
    );
}

/// The declared command whose path is `path`, wherever the spec nests it.
fn find_command<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("path").and_then(serde_json::Value::as_str) == Some(path) {
                return Some(value);
            }
            map.values().find_map(|inner| find_command(inner, path))
        }
        serde_json::Value::Array(items) => items.iter().find_map(|item| find_command(item, path)),
        _ => None,
    }
}

#[test]
fn the_verb_names_no_harness_which_is_the_whole_portability_claim() {
    // CLOUD-1260's design (b) claims to need NOTHING from any harness: the
    // connector is not registered, Batten holds the endpoint, and there is
    // nothing left to intercept. A `--harness` flag on this verb would falsify
    // that claim in the one place a reader would check it, so its ABSENCE is the
    // assertion — and it is asserted rather than reviewed, because a flag added
    // later would arrive quietly.
    let help = run(Path::new("."), &["mcp", "call", "--help"]);
    let rendered = format!("{}{}", stdout(&help), stderr(&help));
    assert!(
        !rendered.contains("--harness"),
        "`mcp call` must not take a harness: it is dispatch, not mediation"
    );

    // And the roster it must NOT be narrower than: every harness the generator
    // knows still reaches one unconditional dispatch path. Asserted by showing
    // the generator has a roster at all and that this verb is blind to it.
    let harnesses = run(Path::new("."), &["generate", "hooks", "--help"]);
    let roster = format!("{}{}", stdout(&harnesses), stderr(&harnesses));
    assert!(
        roster.contains("claude-code"),
        "the harness roster is `generate hooks --harness`'s own value list"
    );
}

#[test]
fn an_undeclared_source_set_and_an_unmatched_server_are_different_answers() {
    // THE ANTI-VACUITY PAIR. "there is nowhere to look" and "we looked and did
    // not find it" are different facts about the world, and a verb that reported
    // them identically would tell an operator to fix a config that is correct.
    let bare = Fixture::new("mcp-no-sources")
        .config("version = 1\n")
        .git()
        .build();
    let nowhere = run(&bare, &["mcp", "call", "anything", "get_thing"]);
    assert_eq!(
        nowhere.status.code(),
        Some(1),
        "a repository that declares no source has nowhere to dispatch and attempted nothing — \
         that is a statement about the INVOCATION, which is exit 1. A 2 anywhere here would tell \
         every pre-tool hook that POLICY refused"
    );
    let nowhere = stderr(&nowhere);
    assert!(
        nowhere.contains("[[mcp.source]]"),
        "the refusal must name what is missing, not merely that something is: {nowhere}"
    );

    let declared = repo_declaring(
        "mcp-unmatched",
        r#"{"mcpServers": {"other": {"url": "https://example.invalid/x"}}}"#,
    );
    let missing = run(&declared, &["mcp", "call", "absent-server", "get_thing"]);
    assert_eq!(missing.status.code(), Some(3));
    let missing = stderr(&missing);
    assert!(
        missing.contains("tried: project"),
        "a source that was consulted and did not answer names itself: {missing}"
    );
    assert_ne!(
        nowhere, missing,
        "the two could-not-look answers must not be byte-identical"
    );
}

#[test]
fn a_wiring_file_that_will_not_parse_is_could_not_look_and_not_an_absent_server() {
    // The arm a caller must never read as "the connector is not configured": a
    // file somebody is halfway through editing. Collapsing this into the absent
    // case is CLOUD-251's vacuous pass on a new surface.
    let broken = repo_declaring("mcp-unreadable", "{ this is not json");
    let answer = run(&broken, &["mcp", "call", "anything", "get_thing"]);
    assert_eq!(answer.status.code(), Some(3));
    let message = stderr(&answer);
    assert!(
        message.contains("will not parse"),
        "the cause must be distinguishable from an absent server: {message}"
    );
}

#[test]
fn no_refusal_carries_a_resolved_path() {
    // Non-negotiable rule 4 where it matters most. A resolved path here is a
    // machine's home directory, which is exactly what keying a source by id
    // exists to keep out of every message.
    let declared = repo_declaring("mcp-pointer-only", r#"{"mcpServers": {}}"#);
    let answer = run(&declared, &["mcp", "call", "anything", "get_thing"]);
    let message = stderr(&answer);
    assert!(
        !message.contains("wiring.json"),
        "the resolved path must not travel; the source ID is the pointer: {message}"
    );
    assert!(
        !message.contains(declared.to_string_lossy().as_ref()),
        "and neither must the directory it resolved beneath: {message}"
    );
}

#[test]
fn malformed_params_are_the_callers_mistake_and_never_a_could_not_look() {
    // The exit split, asserted rather than described: a params document that
    // will not read is a statement about the INVOCATION (exit 1), where an
    // unreachable server is a statement about the world (exit 3). Collapsing
    // them would tell an operator to fix their config about their own typo.
    let declared = repo_declaring("mcp-bad-params", r#"{"mcpServers": {}}"#);
    let answer = run(
        &declared,
        &["mcp", "call", "anything", "get_thing", "{not json"],
    );
    assert_eq!(
        answer.status.code(),
        Some(1),
        "a malformed params document is a usage error"
    );
}

#[test]
fn a_malformed_mcp_table_is_refused_at_load_rather_than_at_dispatch() {
    // House style §8: a config fault is reported by the config verbs, not
    // discovered by the one call that needed it. This is also the engine tier of
    // `mcp::validate` — the unit cases build the struct by hand, and this proves
    // the LOADER reaches the same refusal from committed bytes.
    let escaping = Fixture::new("mcp-escaping-path")
        .config(
            r#"
version = 1

[[mcp.source]]
id = "outside"
root = "HOME"
path = "../elsewhere.json"
node = "mcpServers"
"#,
        )
        .git()
        .build();
    let answer = run(&escaping, &["config", "lint"]);
    assert_eq!(
        answer.status.code(),
        Some(1),
        "a path that leaves its root is a config fault: {}",
        stderr(&answer)
    );

    let empty_fields = Fixture::new("mcp-empty-fields")
        .config(
            r#"
version = 1

[[mcp.result]]
method = "get_thing"
reduce = "project"
fields = []
"#,
        )
        .git()
        .build();
    let answer = run(&empty_fields, &["config", "lint"]);
    assert_eq!(
        answer.status.code(),
        Some(1),
        "a reduction over no fields is a dropped payload wearing a projection's costume: {}",
        stderr(&answer)
    );
}

#[test]
fn a_well_formed_table_loads_which_is_what_makes_the_refusals_above_discriminate() {
    // The allow half (CLOUD-418). Without it every case above is satisfied by a
    // loader that refuses every `[mcp]` table, which would gate nothing.
    let declared = repo_declaring("mcp-loads", r#"{"mcpServers": {}}"#);
    let answer = run(&declared, &["config", "lint"]);
    assert!(
        answer.status.success(),
        "a well-formed table must load: {}",
        stderr(&answer)
    );

    // And this repository's own committed table, which is the one a consumer
    // actually runs against. `at_root` rather than `.`: a test's cwd is the CRATE
    // directory, which carries no `batten.toml`, so the relative form asserted
    // "no config found" and would have passed over any table at all.
    let here = run(&at_root("."), &["config", "lint"]);
    assert!(
        here.status.success(),
        "the committed `[mcp]` table must load: {}",
        stderr(&here)
    );
}

#[test]
fn a_write_side_reduction_starves_neither_consumer_that_needs_the_stored_body() {
    // CLOUD-1122's load-bearing acceptance, and the half a naive "make it
    // quieter" breaks. CLOUD-815 compares the stored body against the sent one —
    // that comparison IS the detection — and CLOUD-1118 wants the post-write body
    // so a lint straight after a write decides over what was actually stored.
    //
    // Both read the CAPTURE STORE rather than the caller's copy, and `mcp call`
    // stores the response WHOLE before reducing anything. So the proof is that a
    // response filed the way this verb files one is still resolvable by the
    // reader those consumers use, with its body intact — asserted over the
    // compiled binary rather than assumed from the code.
    let repo = repo_declaring("mcp-write-fidelity", r#"{"mcpServers": {}}"#);
    let home = repo.join(".home");
    std::fs::create_dir_all(&home).expect("a state home");

    let body = "a description long enough that no reduction would carry it. ".repeat(40);
    let stored = serde_json::json!({
        "id": "KEY-1",
        "status": "In Progress",
        "description": body,
    });
    seed_write_response(&repo, &home, &stored);

    // The reader BOTH consumers use, run over the store the engine wrote. A
    // reduction that starved them would show up here as a resolve that finds
    // nothing, or as a body that came back short.
    let found = find_in(
        &repo,
        &home,
        &["capture", "find", "KEY-1", "--tool", "save_issue"],
    );
    assert!(
        found.status.success(),
        "the stored write response must still resolve by key: {}",
        stderr(&found)
    );
    assert!(
        stdout(&found).contains("save_issue"),
        "and it must resolve under the method that wrote it: {}",
        stdout(&found)
    );

    // `--raw` is the route `board-write-record` and a post-write lint take to the
    // bytes. The whole body has to come back, or CLOUD-815's comparison is over a
    // truncated artifact and CLOUD-1118's lint decides over half a document.
    let raw = find_in(
        &repo,
        &home,
        &["capture", "find", "KEY-1", "--tool", "save_issue", "--raw"],
    );
    assert!(
        raw.status.success(),
        "the raw route stays open: {}",
        stderr(&raw)
    );
    let bytes = stdout(&raw);
    assert!(
        bytes.contains(body.trim_end()),
        "the stored body must survive WHOLE — a fix that starved these two would trade one \
         defect for two"
    );
}

/// Seed a `save_issue` response into the store by driving the engine's own
/// `PostToolUse` event.
///
/// **Written by the ENGINE rather than placed in the store by this test**, which
/// is the whole reason this tier exists: a fixture assembling the store by hand
/// would prove the reader can read what the test writes and say nothing about
/// whether the writer produces it.
fn seed_write_response(dir: &Path, home: &Path, document: &serde_json::Value) {
    use std::io::Write as _;
    use std::process::Stdio;

    let envelope = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "mcp-suite",
        "tool_name": "mcp__tracker__save_issue",
        "tool_input": {},
        "tool_response": [{ "type": "text", "text": document.to_string() }],
    })
    .to_string();
    let mut command = common::batten();
    command
        .args(["hook", "--harness", "claude-code"])
        .current_dir(dir)
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    common::state_home(&mut command, home);
    let mut child = command.spawn().expect("spawn the post-tool hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(envelope.as_bytes())
        .expect("write the response");
    let recorded = child.wait_with_output().expect("record the response");
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "the post-tool hook must accept the response: {}",
        String::from_utf8_lossy(&recorded.stderr)
    );
}

/// Run a `capture` verb against the same state home the seed wrote into.
fn find_in(dir: &Path, home: &Path, args: &[&str]) -> Output {
    let mut command = common::batten();
    command.args(args).current_dir(dir);
    common::state_home(&mut command, home);
    command.output().expect("run the capture verb")
}

#[test]
fn this_change_introduces_no_consumer_identifier_into_the_crate() {
    // NON-NEGOTIABLE RULE 1, AS AN ACCEPTANCE TEST rather than a style note. The
    // whole design rests on the crate knowing only "dispatch a declared method;
    // reduce by a declared projection" — a launcher's config path or a harness's
    // dot-directory inside `crates/batten` is the violation, and every one of
    // them belongs in the consumer's `batten.toml`.
    //
    // # Two bounds, both deliberate, because an unbounded version of this asserts
    // something the repository has never held
    //
    // **COMMENTS ARE STRIPPED FIRST.** Rule 1 governs what the crate KNOWS, and a
    // doc comment explaining why a name lives in config is prose about the rule
    // rather than an instance of breaking it. `.claude/rules/scanning.md`'s row
    // two is exactly this distinction — whether a token is in code, in a comment
    // or in a string is a syntax question, and a text scan answers the wrong one.
    // Measured: an unstripped scan reported nine files, of which every hit in
    // this module was a sentence citing the row it implements.
    //
    // **THE SCOPE IS WHAT THIS CHANGE INTRODUCED**, not the whole crate. Run
    // crate-wide over code, the tracker-method half of this predicate is ALREADY
    // RED on `main`: `lib.rs` declares `READ_TOOL` and `WRITE_TOOL` as crate
    // constants naming two tracker methods. That is a real finding and it is
    // reported on CLOUD-1260 rather than fixed here — repairing landed code the
    // brief did not scope would widen the PR, and weakening the assertion to hide
    // it would be worse than either. What this case owns is that the MCP change
    // adds none of its own.
    let mut hits: Vec<String> = Vec::new();
    for path in sources(&at_root("crates/batten/src")) {
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let code: String = source
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(before, _)| before))
            .collect::<Vec<_>>()
            .join("\n");
        // The launcher and harness config locations CLOUD-1260 resolves. Every
        // one is a `[[mcp.source]]` row's business: the engine expands a variable
        // a row names and has no opinion about which variables exist.
        //
        // Assembled rather than written whole, because this file sits under
        // `crates/batten` and a literal here would be a hit for the gate it
        // states — `git.rs`'s own idiom, and the reason
        // `.claude/rules/policy-modules.md` records why a substring gate must
        // hide its own literals when its corpus includes itself.
        for needle in [
            ["/tmp/mcp", "-config"].concat(),
            [".claude", ".json"].concat(),
        ] {
            if code.contains(needle.as_str()) {
                hits.push(format!("{} carries {needle}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a launcher's config layout must live in `batten.toml` and nowhere in the crate:\n{}",
        hits.join("\n")
    );

    // And the new module specifically, over the tracker vocabulary: the crate
    // knows two verbs and neither is a method name.
    let module = std::fs::read_to_string(at_root("crates/batten/src/mcp.rs")).expect("the module");
    let code: String = module
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(before, _)| before))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [["get", "_issue"].concat(), ["save", "_issue"].concat()] {
        assert!(
            !code.contains(needle.as_str()),
            "mcp.rs must not name a tracker method in code: {needle}"
        );
    }
}

/// Every `.rs` file under `root`, recursively.
fn sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            found.push(path);
        }
    }
    found
}
