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
//! **This suite stops at the socket, and the reason it gives used to be wrong.**
//! It read: *"a loopback listener cannot be reached at all — a trusted local
//! certificate is unreachable by construction, because the roots are vendored and
//! nothing signs a loopback CA."* That is false, and the correction matters
//! because it was an argument for never trying. `fetch.rs`'s `CA_BUNDLE` reads
//! `SSL_CERT_FILE` and **adds** to the vendored roots precisely so a
//! re-terminating proxy can be trusted, and a locally minted CA is the same shape.
//! Measured 2026-09-01: a loopback TLS server serving the streamable-HTTP
//! handshake was driven end to end by the compiled binary — `initialize`, the
//! `Mcp-Session-Id` round trip, `tools/call`, SSE framing and the reduction — over
//! a genuine 23,371-byte tracker payload, reduced to 593 bytes.
//!
//! So what bounds this suite is COST rather than impossibility: standing that
//! server up needs a POST-speaking listener, which `openssl s_server` is not, and
//! `provision.rs`'s `mint_ca_and_server_certificate` is only half the harness. The
//! remaining half is worth its own row rather than a hand-rolled listener here.
//!
//! Until then the compiled-binary tier covers everything up to the socket: config
//! loading, wiring resolution and each of its refusals, credential resolution and
//! each of ITS refusals, the exit class each lands in, and the pointer discipline
//! over every message — including the one that matters most, that a resolved
//! credential reaches no output on any path.
//!
//! # AND THE RESPONSE SIDE IS REACHED WITHOUT A SOCKET AT ALL (CLOUD-1403)
//!
//! "Stops at the socket" was read once as "stops at the response", and that is
//! the sentence worth correcting rather than deleting. What needs a listener is
//! the TRANSPORT — handshake, session header, SSE framing. What a server SAYS is
//! a `fetch::Response`, which is `pub` with `pub` fields, so a case can build one
//! and drive the real parsing and rendering path with no listener, no certificate
//! and nothing fabricated except the bytes.
//!
//! The refusal cases below do exactly that. Reading this header as a bar on them
//! is what sent one session looking for a loopback TLS responder for a test that
//! never needed one — so the bound is now stated as the transport's rather than
//! as the whole response half's.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

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

/// A repository whose one source declares a credential, spelled by the caller.
///
/// The wiring names a server that resolves, so every case below reaches the
/// CREDENTIAL step rather than stopping at an earlier refusal — which is the
/// difference between testing this feature and testing the one before it.
fn repo_with_credential(name: &str, credential: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            r#"
version = 1

[[mcp.source]]
id = "project"
path = "wiring.json"
node = "mcpServers"
{credential}

[[mcp.result]]
method = "get_thing"
reduce = "project"
fields = ["id"]
"#
        ))
        .file(
            "wiring.json",
            r#"{"mcpServers": {"srv": {"url": "https://example.invalid/mcp"}}}"#,
        )
        .git()
        .build()
}

#[test]
fn a_declared_credential_that_will_not_resolve_refuses_rather_than_dispatching_bare() {
    // THE CASE THIS ROW EXISTS FOR, and the one a naive implementation gets
    // wrong by omission: falling through to an unauthenticated call produces a
    // 401 from the server, which reads as the SERVER's fault and sends whoever
    // debugs it to the wrong system. Measured on 2026-09-01, that is exactly the
    // confusion a bare 401 caused here — twice, across two issues.
    let repo = repo_with_credential(
        "mcp-credential-unset",
        "\n[mcp.source.credential]\nenv = \"BATTEN_TEST_TOKEN_NOT_SET\"\n",
    );
    let answer = run(&repo, &["mcp", "call", "srv", "get_thing"]);
    assert_eq!(
        answer.status.code(),
        Some(3),
        "a credential the row demands and the host does not supply is could-not-look"
    );
    let message = stderr(&answer);
    assert!(
        message.contains("BATTEN_TEST_TOKEN_NOT_SET"),
        "the refusal names the VARIABLE to fix, which is the only actionable thing it knows: \
         {message}"
    );
}

#[test]
fn a_credential_file_that_will_not_read_names_the_variable_and_never_the_path() {
    // Rule 4 on the credential's own failure path. The io error carries the
    // expanded path — somebody's home directory — so it is dropped rather than
    // formatted, and what survives is the name a reader can act on.
    let repo = repo_with_credential(
        "mcp-credential-file",
        "\n[mcp.source.credential]\nfile_from = \"BATTEN_TEST_TOKEN_FILE\"\n",
    );
    let secret_dir = repo.join("nowhere");
    let answer = common::batten()
        .args(["mcp", "call", "srv", "get_thing"])
        .current_dir(&repo)
        .env("BATTEN_TEST_TOKEN_FILE", secret_dir.join("absent.txt"))
        .output()
        .expect("run batten");
    assert_eq!(answer.status.code(), Some(3));
    let message = stderr(&answer);
    assert!(
        message.contains("BATTEN_TEST_TOKEN_FILE"),
        "the refusal names the variable: {message}"
    );
    assert!(
        !message.contains("absent.txt"),
        "the refusal must not carry the path the variable expanded to: {message}"
    );
}

#[test]
fn a_resolved_credential_reaches_no_output_on_any_path() {
    // THE NEGATIVE HALF, and it is asserted where a secret actually escapes: the
    // FAILURE path. The endpoint here is unresolvable, so the dispatch fails
    // AFTER the credential has been read and folded into a header — which is the
    // exact window a happy-path-only assertion never opens.
    let token = "sk-batten-test-do-not-emit-2f8a1c";
    let repo = repo_with_credential(
        "mcp-credential-quiet",
        "\n[mcp.source.credential]\nenv = \"BATTEN_TEST_TOKEN\"\nscheme = \"Bearer\"\n",
    );
    let answer = common::batten()
        .args(["mcp", "call", "srv", "get_thing"])
        .current_dir(&repo)
        .env("BATTEN_TEST_TOKEN", token)
        .output()
        .expect("run batten");
    assert!(
        !answer.status.success(),
        "example.invalid does not resolve, so this run must fail — which is the point: the \
         assertion below is about a FAILURE path"
    );
    let seen = format!("{}{}", stdout(&answer), stderr(&answer));
    assert!(
        !seen.contains(token),
        "a resolved credential must reach no output on any path, and this one is the path a \
         redaction gets forgotten on"
    );
    assert!(
        !seen.contains("Bearer"),
        "nor may the scheme leak the shape of the header that was sent: {seen}"
    );
}

#[test]
fn a_credential_row_that_cannot_mean_one_thing_is_refused_at_load() {
    // At LOAD, not at dispatch: a row naming neither variable resolves to
    // nothing, and a row naming both has no single answer. Either would send an
    // unauthenticated call that looks like the server refusing.
    for (name, row) in [
        (
            "mcp-credential-neither",
            "\n[mcp.source.credential]\nheader = \"Authorization\"\n",
        ),
        (
            "mcp-credential-both",
            "\n[mcp.source.credential]\nenv = \"A\"\nfile_from = \"B\"\n",
        ),
    ] {
        let repo = repo_with_credential(name, row);
        let answer = run(&repo, &["config", "lint"]);
        assert_eq!(
            answer.status.code(),
            Some(1),
            "{name}: a credential row that cannot mean one thing is the caller's mistake"
        );
    }
}

#[test]
fn a_source_declaring_no_credential_behaves_exactly_as_before() {
    // The byte-identical arm (CLOUD-418's mirror, and CLOUD-1261's acceptance by
    // name). Adding this key must not change what a source that does not use it
    // does — otherwise every existing consumer's dispatch quietly changed.
    let repo = repo_with_credential("mcp-credential-absent", "");
    let answer = run(&repo, &["mcp", "call", "srv", "get_thing"]);
    let message = stderr(&answer);
    assert!(
        !message.contains("credential"),
        "a source declaring none must not mention one: {message}"
    );
    assert_eq!(
        answer.status.code(),
        Some(3),
        "it fails at the SOCKET, which is where it failed before this key existed"
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
        .args(["adjudicate", "--harness", "claude-code"])
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

// --- the refusal line the server's own message reaches (CLOUD-1403) ---------
//
// THE INTEGRATION TIER, AND IT NEEDS NO SERVER — which is the correction worth
// recording, because the first attempt at this row concluded the opposite and
// went looking for a loopback TLS listener.
//
// `envelope` is a pure function of a `fetch::Response`, and that type is `pub`
// with `pub` fields. This target links the library, so a case can BUILD a refusal
// envelope and drive the real rendering path: no listener, no certificate, no
// network, and nothing fabricated except the bytes a server would have sent.
//
// That is a different question from the module's own cases, which pin the
// message-shaping function alone. These pin that the shaped message reaches the
// line a caller actually reads, through the same branch `mcp call` takes.

/// A response carrying `body` with a 200 status, as the transport hands one over.
fn answered(body: &str) -> batten::fetch::Response {
    batten::fetch::Response {
        status: 200,
        body: body.as_bytes().to_vec(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
    }
}

/// The rendered refusal for a JSON-RPC error envelope.
fn refusal(body: &str) -> String {
    batten::mcp::envelope(&answered(body), "save_issue")
        .expect_err("a JSON-RPC error envelope is a refusal")
        .to_string()
}

#[test]
fn a_refusal_carries_the_servers_own_message_and_not_only_its_code() {
    // THE DEFECT THIS ROW IS FOR, at the seam that had it. Measured 2026-09-03:
    // `save_issue` answered `-32003` with nothing else, and the identical call
    // through the connector's own tool succeeded — so the one fact that could
    // have said which path was wrong had been dropped at this branch.
    let line = refusal(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"Issue state 'Todo' is not valid for this team"}}"#,
    );
    assert!(line.contains("-32003"), "the code still travels: {line}");
    assert!(
        line.contains("Issue state 'Todo' is not valid for this team"),
        "and the server's own message travels with it: {line}"
    );
}

#[test]
fn a_refusal_never_carries_the_arbitrary_data_member() {
    // THE BOUND, and the half that keeps this inside rule 4. §5.1 defines `data`
    // as "a Primitive or Structured value" — arbitrary, unlike the one-sentence
    // `message` — so it is the payload and stays out. Without this case the
    // relay could widen to the whole error object and nothing would notice.
    let line = refusal(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"not permitted","data":{"token":"SECRETLEAK","rows":[1,2,3]}}}"#,
    );
    assert!(
        line.contains("not permitted"),
        "the message travels: {line}"
    );
    assert!(
        !line.contains("SECRETLEAK"),
        "the arbitrary `data` member must never reach a finding: {line}"
    );
}

#[test]
fn a_refusal_message_a_server_wrote_as_a_trace_is_cut_to_one_line() {
    // A server that ignores the SHOULD sends frames. Relaying the whole of one
    // buries the line a reader needs, which is the second half of the same
    // defect: the old output printed a backtrace for somebody else's verdict.
    let line = refusal(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"bad request\\n  at Foo.bar (/srv/app.js:12)\\n  at Baz\"}}",
    );
    assert!(
        line.contains("bad request"),
        "the first line travels: {line}"
    );
    assert!(
        !line.contains("Foo.bar"),
        "and the frames after it do not: {line}"
    );
}

#[test]
fn an_error_carrying_no_message_says_so_rather_than_rendering_a_bare_code() {
    // COULD-NOT-LOOK, KEPT DISTINCT. `message` is REQUIRED by §5.1, so a server
    // omitting it is malformed — and the honest line says the message was absent
    // rather than trailing off, which is what the pre-change output looked like
    // for every refusal.
    let line = refusal(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003}}"#);
    assert!(line.contains("-32003"), "the code still travels: {line}");
    assert!(
        line.contains("no message"),
        "an absent message is stated, not elided: {line}"
    );
}

#[test]
fn a_successful_envelope_is_still_a_result_and_not_a_refusal() {
    // THE PREMISE CASE. Every assertion above is about the error branch; without
    // one proving the success branch still returns, a `envelope` that refused
    // everything would satisfy all four.
    let value = batten::mcp::envelope(
        &answered(r#"{"jsonrpc":"2.0","id":1,"result":{"id":"KEY-1"}}"#),
        "get_issue",
    )
    .expect("a result envelope is not a refusal");
    assert_eq!(
        value.get("id").and_then(serde_json::Value::as_str),
        Some("KEY-1")
    );
}

/*
#MUTANT error-message-dropped|s@            .and_then(serde_json::Value::as_str)@            .and_then(|_unread| None::<\&str>)@|a_refusal_carries_the_servers_own_message_and_not_only_its_code
*/

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
