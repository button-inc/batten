//! The `secrets` rule kind, end to end over the compiled binary (CLOUD-59).
//!
//! **The claim under test is a negative**: that no surface Batten writes can
//! carry a matched byte. A negative needs a witness that would be found if the
//! claim were false, so every case here plants a token and then searches for it
//! everywhere the run could have put it — stdout, stderr, the `-J` document, and
//! every file under the state root, which is where the key and any cache live.
//!
//! # The planted token is assembled at runtime, and that is load-bearing
//!
//! Consumer #1's own `no-secrets` rule globs the whole tree, so a literal
//! credential written into this file would be a standing violation of the rule
//! this suite exists to prove — the repository would fail its own gate, forever,
//! on its own test fixture. The token is therefore built from fragments at
//! runtime and exists in no committed byte sequence.
//!
//! The same reasoning rules out a real secret of any kind: these are synthetic
//! shapes that exist nowhere but the scratch tree each test builds.
//!
//! # The scanner is a stub, provisioned through `file://`
//!
//! The suite pins the *adapter*, not ripsecrets' detection. A stub emits the
//! exact output shape measured against ripsecrets 0.1.11 — `path:line:span`
//! under `--only-matching`, exit 0 clean / 1 found — which is what lets a case
//! drive the disagreement branches a real scanner will not produce on demand.
//! Detection itself is adopted prior art and is exercised by consumer #1's own
//! gate once the pin lands.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use batten::provision::digest;
use common::{Fixture, StateHome, batten, git_in, scratch};

/// A repository, an isolated `HOME`/`XDG_DATA_HOME`, and a place to write stub
/// artifacts — the shape `tests/provision.rs` already uses, for the same reason:
/// the cache and the minted key must land somewhere this test owns rather than
/// in the developer's real state directory.
struct Env {
    repo: PathBuf,
    home: PathBuf,
    artifacts: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .build();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        Env {
            repo,
            home: root.join("home"),
            artifacts,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        batten()
            .state_home(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .output()
            .expect("run batten")
    }

    fn cache(&self) -> PathBuf {
        self.home.join("data").join("batten")
    }

    fn file(&self, path: &str, contents: &str) {
        let full = self.repo.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, contents).unwrap();
    }

    /// Write a stub scanner, provision it, and write the config that uses it.
    ///
    /// Returns after `provision apply` has installed it, so a case that wants a
    /// COLD cache simply does not call this.
    fn install_scanner(&self, script: &str) {
        let path = self.artifacts.join("ripsecrets");
        fs::write(&path, script).unwrap();
        let bytes = fs::read(&path).unwrap();
        self.config(&format!("file://{}", path.display()), &digest(&bytes));
        let applied = self.run(&["provision", "apply"]);
        assert!(
            applied.status.success(),
            "the stub scanner installs: {}",
            String::from_utf8_lossy(&applied.stderr)
        );
    }

    fn config(&self, url: &str, sha: &str) {
        // A TOML *literal* string for the url, because it carries a filesystem
        // path: `file://D:\a\batten\...` in a basic string reads `\a` as a
        // control character and rejects `\U`, so the config fails to parse and
        // every case here dies on its own fixture rather than on its subject
        // (CLOUD-113's Windows job). Literal strings process no escapes.
        self.file(
            "batten.toml",
            &format!(
                "version = 1\n\n\
                 [[provision]]\n\
                 name = \"ripsecrets\"\n\
                 version = \"0.0.0-stub\"\n\
                 url = '{url}'\n\
                 sha256 = \"{sha}\"\n\
                 binary = \"ripsecrets\"\n\n\
                 [[rule]]\n\
                 id = \"no-secrets\"\n\
                 kind = \"secrets\"\n\
                 glob = \"**/*.conf\"\n\
                 severity = \"deny\"\n\
                 scope = \"tree\"\n"
            ),
        );
    }

    /// Append another `[[rule]]` to the config `install_scanner` already wrote.
    ///
    /// For the isolation cases below, which need a SECOND gate in the same run —
    /// the whole claim is about what happens to the other gates when one of them
    /// cannot complete, and a single-rule fixture cannot show it.
    fn add_rule(&self, toml: &str) {
        let path = self.repo.join("batten.toml");
        let existing = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{existing}\n{toml}")).unwrap();
    }

    /// Every byte this run could have written, out of tree: the provision cache
    /// and the minted key both live here.
    fn state_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        collect(&self.cache(), &mut out);
        out
    }
}

fn collect(dir: &Path, out: &mut Vec<u8>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if let Ok(bytes) = fs::read(&path) {
            out.extend_from_slice(&bytes);
            out.push(b'\n');
        }
    }
}

/// The fragments the synthetic credentials are assembled from.
///
/// Split so the contiguous token exists in no committed byte sequence — see the
/// module docs: a literal here would violate consumer #1's own `no-secrets` rule
/// over this very file.
const TOKEN_PARTS: [&str; 5] = ["AKIA", "7QF2", "NX8M", "3JD5", "W0PC"];
const OTHER_PARTS: [&str; 5] = ["AKIA", "B4T6", "LZ9R", "K1YV", "H2SD"];

fn token() -> String {
    TOKEN_PARTS.concat()
}

fn other_token() -> String {
    OTHER_PARTS.concat()
}

/// The shell that reconstructs a token inside the stub, without the contiguous
/// string ever appearing in the script.
///
/// **This is not decoration, and the first version of this suite failed without
/// it.** `provision` caches the exact artifact bytes by contract, so a stub
/// carrying the token as a literal puts it under the state root — and the
/// assertions below search the state root precisely because that is where a leak
/// would land. A test whose own fixture trips its assertion teaches nothing, and
/// weakening the assertion to exclude the cache would have hidden a real leak in
/// the one place Batten writes files nobody reads.
fn shell_token(parts: [&str; 5]) -> String {
    let mut out = String::new();
    for part in parts {
        out.push('"');
        out.push_str(part);
        out.push('"');
    }
    out
}

/// A stub emitting ripsecrets' measured output shape for the given matches.
///
/// A match is `(path, line, which token)`; `None` means a span the parser should
/// refuse. The stub ignores its arguments beyond echoing what it was told to,
/// which is what makes the disagreement cases below expressible at all — a real
/// scanner cannot be asked to contradict itself.
fn stub(matches: &[(&str, usize, Option<[&str; 5]>)], exit: i32) -> String {
    let mut script = String::from("#!/bin/sh\n");
    // `writeln!` into a String is infallible; the results are discarded rather
    // than propagated, as `render.rs` does for the same reason.
    for (index, (path, line, parts)) in matches.iter().enumerate() {
        if let Some(parts) = parts {
            let _ = writeln!(script, "T{index}={}", shell_token(*parts));
            let _ = writeln!(script, "printf '%s\\n' \"{path}:{line}:$T{index}\"");
        } else {
            // A shape this build cannot parse, still carrying a token: the
            // hazard is that an unparseable line is one the scanner emitted
            // BECAUSE it found a secret in it.
            let _ = writeln!(script, "T{index}={}", shell_token(TOKEN_PARTS));
            let _ = writeln!(script, "printf '%s\\n' \"!! unexpected $T{index}\"");
        }
    }
    let _ = writeln!(script, "exit {exit}");
    script
}

/// The stub that reports nothing and exits clean.
fn clean_stub() -> String {
    stub(&[], 0)
}

/// Assert `needle` appears in none of the places a run can write.
fn nowhere(env: &Env, output: &Output, needle: &str, case: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!stdout.contains(needle), "{case}: the token reached stdout");
    assert!(!stderr.contains(needle), "{case}: the token reached stderr");
    let state = env.state_bytes();
    assert!(
        !String::from_utf8_lossy(&state).contains(needle),
        "{case}: the token reached a file under the state root"
    );
}

// --- (a) the deny verdict is pointer-only -------------------------------------

#[test]
fn a_planted_secret_is_a_pointer_and_never_its_bytes() {
    let env = Env::new("secrets-pointer");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 1));

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a deny finding is the policy verdict"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "app.conf:1 no-secrets\n",
        "stdout is the pointer line and nothing else"
    );
    nowhere(&env, &out, &secret, "text output");
}

#[test]
fn the_json_document_carries_no_span_either() {
    let env = Env::new("secrets-json");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 1));

    let out = env.run(&["enforce", "-J"]);
    assert_eq!(out.status.code(), Some(2));
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("the -J document parses");
    let finding = &document["findings"][0];
    assert_eq!(finding["path"], "app.conf");
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["rule"], "no-secrets");
    nowhere(&env, &out, &secret, "-J output");
}

// --- (b) the identity is secret-class and keyed -------------------------------

#[test]
fn the_emitted_identity_is_secret_class_and_differs_from_the_unkeyed_digest() {
    let env = Env::new("secrets-identity");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 1));

    let out = env.run(&["enforce", "-J"]);
    let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let identity = &document["findings"][0]["identity"];

    // The version tag is what asserts the adapter selected the KEYED path: an
    // unkeyed span would have been minted under the code kind's version.
    let version = identity["version"].as_str().expect("a version");
    assert!(
        version.starts_with("secret:"),
        "the identity is secret-class, not code-class: {version}"
    );

    // And the fingerprint is not the unkeyed digest of the same span.
    let unkeyed = batten::identity::code_fingerprint(
        "no-secrets",
        "app.conf",
        &secret,
        batten::identity::SpanNormalization::Verbatim,
    )
    .unwrap();
    assert_ne!(
        identity["fingerprint"].as_str().unwrap(),
        unkeyed.to_hex(),
        "a keyed identity must never equal the unkeyed digest it exists to replace"
    );
}

#[test]
fn two_repositories_mint_two_keys_and_two_identities_for_one_secret() {
    // The machine-scoped key, observed rather than asserted: the same secret at
    // the same path under two state roots is two identities, which is the
    // documented trade the module doc states.
    let secret = token();
    let fingerprint = |name: &str| -> String {
        let env = Env::new(name);
        env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
        env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 1));
        let out = env.run(&["enforce", "-J"]);
        let document: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        document["findings"][0]["identity"]["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_ne!(fingerprint("secrets-key-a"), fingerprint("secrets-key-b"));
}

// --- (c) byte-stability, including across matched files -----------------------

#[test]
fn the_same_input_twice_is_byte_identical_and_ordered() {
    let env = Env::new("secrets-stable");
    let (one, two) = (token(), other_token());
    env.file("b.conf", &format!("k = \"{one}\"\n"));
    env.file("a.conf", &format!("k = \"{two}\"\n"));
    // Emitted in the reverse of the order the output must appear in: the
    // scanner's walker is parallel, so the adapter sorts rather than trusting
    // the stream's order.
    env.install_scanner(&stub(
        &[
            ("b.conf", 1, Some(TOKEN_PARTS)),
            ("a.conf", 1, Some(OTHER_PARTS)),
        ],
        1,
    ));

    let first = env.run(&["enforce"]);
    let second = env.run(&["enforce"]);
    assert_eq!(first.stdout, second.stdout, "text output is byte-stable");
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        "a.conf:1 no-secrets\nb.conf:1 no-secrets\n",
        "ordered by path, not by the order the scanner happened to emit"
    );

    let first_json = env.run(&["enforce", "-J"]);
    let second_json = env.run(&["enforce", "-J"]);
    assert_eq!(first_json.stdout, second_json.stdout, "-J is byte-stable");

    // A second run reuses the key rather than re-minting: identical output IS
    // that assertion, since the key id is inside every fingerprint.
    nowhere(&env, &first, &one, "run one");
    nowhere(&env, &second_json, &two, "run two");
}

// --- (d) the read-only surface refuses the kind -------------------------------

#[test]
fn check_refuses_a_config_carrying_a_secrets_rule() {
    let env = Env::new("secrets-check-refusal");
    env.install_scanner(&clean_stub());

    let out = env.run(&["check"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a refusal is usage, not a verdict"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("batten enforce"),
        "the refusal names the verb that runs it: {stderr}"
    );
}

// --- (e) a cold cache is never a clean tree -----------------------------------

#[test]
fn an_uninstalled_scanner_is_exit_one_naming_the_install_verb() {
    let env = Env::new("secrets-cold-cache");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    // Config written, `provision apply` deliberately NOT run.
    env.config("file:///dev/null/never-fetched", &"0".repeat(64));

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a scanner that did not run is not evidence of a clean tree"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("batten provision apply"), "{stderr}");
    nowhere(&env, &out, &secret, "cold cache");
}

// --- (f) the fail-closed cross-check, both directions -------------------------

#[test]
fn a_clean_exit_that_emitted_a_match_is_internal_error() {
    let env = Env::new("secrets-clean-with-match");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 0));

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "the exit status and the output disagree, so neither is a verdict"
    );
    nowhere(&env, &out, &secret, "clean-with-match");
}

#[test]
fn a_found_exit_that_emitted_nothing_is_internal_error() {
    // The silent false green the clause exists to prevent: the tool says it
    // found secrets, the parser produced none, and reporting clean would infer a
    // clean tree from a stream that failed to parse.
    let env = Env::new("secrets-found-with-none");
    env.file("app.conf", "k = 1\n");
    env.install_scanner(&stub(&[], 1));

    let out = env.run(&["enforce"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("never inferred"), "{stderr}");
}

#[test]
fn an_unparseable_line_is_internal_error_naming_no_bytes() {
    let env = Env::new("secrets-unparseable");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    // A shape this build cannot parse, still carrying the token.
    env.install_scanner(&stub(&[("app.conf", 1, None)], 1));

    let out = env.run(&["enforce"]);
    assert_eq!(out.status.code(), Some(3));
    nowhere(&env, &out, &secret, "unparseable line");
}

#[test]
fn a_tool_failure_is_internal_error_rather_than_a_clean_tree() {
    let env = Env::new("secrets-tool-error");
    env.file("app.conf", "k = 1\n");
    env.install_scanner(&stub(&[], 2));

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "the scanner's own failure is neither verdict"
    );
}

// --- (g) a clean tree is still clean ------------------------------------------

#[test]
fn a_clean_scan_exits_zero_with_no_output() {
    // The negative control: without it every case above would pass on an engine
    // that always errored.
    let env = Env::new("secrets-clean");
    env.file("app.conf", "k = 1\n");
    env.install_scanner(&clean_stub());

    let out = env.run(&["enforce"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn a_glob_matching_nothing_never_spawns_the_scanner() {
    // The glob is a gate before it is an argv source: a stub that would fail the
    // run if executed proves the spawn never happened.
    let env = Env::new("secrets-no-match");
    env.file("app.txt", "not matched by the rule's glob\n");
    env.install_scanner("#!/bin/sh\nexit 3\n");

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "no match means no spawn, so the failing stub never ran"
    );
}

// --- (h) the key file's custody, observed through the binary ------------------

#[test]
fn the_key_is_minted_owner_only_under_the_state_root() {
    let env = Env::new("secrets-key-file");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 1));
    env.run(&["enforce"]);

    // Resolved against the XDG_DATA_HOME the CHILD ran with, not this process's:
    // `batten::secrets::key_path` reads the ambient environment, which in the
    // test runner is the developer's own, so calling it here would assert about
    // the wrong directory entirely.
    //
    // The SEGMENT, though, comes from the library — `derive_repo_name` is a pure
    // function of the root and reads nothing ambient, so it is safe to call here
    // and it is the one authority for the rule. Spelling it `file_name()` was a
    // second copy of that rule, and CLOUD-296 (which gave the segment a
    // per-checkout digest) is what a second copy costs.
    let canonical = env.repo.canonicalize().unwrap_or_else(|_| env.repo.clone());
    let segment = batten::state::derive_repo_name(&canonical).expect("derive the state segment");
    let key = env
        .cache()
        .join(segment)
        .join("identity")
        .join("secret-key");
    assert!(key.is_file(), "the run minted a key at {}", key.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the key file is owner-only");
    }

    // And it is never in the tree.
    assert!(
        !env.repo.join("identity").exists(),
        "nothing about the key is written into the repository"
    );
}

// --- (g) fail-closed isolation, end to end (CLOUD-126) -----------------------
//
// This kind is the one that reaches a CONTAINED failure from a config a
// consumer can write. `cross_check` raises a plain internal error — deliberately
// not a `UsageError` — for every disagreement between the scanner's exit status
// and its own output, which is exactly the "gate could not complete" shape the
// isolation is about. Every other route the engine has was closed deliberately:
// the document family reports could-not-look as a FINDING (CLOUD-849), and the
// tree walk keeps only regular files, so `forbid_in_file`'s non-`NotFound` arm
// has no config-reachable input.

/// A second gate that fires, so the isolation claim has something to be about.
const SIBLING_RULE: &str = "[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\nscope = \"tree\"\n";

#[test]
fn an_erroring_gate_exits_three_while_the_other_gates_still_evaluate() {
    // §7's first clause. The secrets row cannot complete; the sibling row runs,
    // finds nothing, and the run reports the error rather than the sibling's
    // silence.
    let env = Env::new("secrets-isolation-exit-three");
    env.file("app.conf", "k = 1\n");
    env.install_scanner(&stub(&[], 1));
    env.add_rule(SIBLING_RULE);
    // Clean under the sibling, so `3` is the only non-zero on offer — otherwise
    // this would pass on a `2` that says nothing about isolation.
    env.file("lib.rs", "nothing here\n");

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "an unevaluable gate never resolves to pass"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("errored no-secrets"),
        "the erroring gate appears in output, by id: {stderr}"
    );
    assert!(
        !stderr.contains("errored no-todo"),
        "a gate that completed is not reported as having failed to: {stderr}"
    );
}

#[test]
fn an_erroring_gate_does_not_suppress_another_gates_findings() {
    // THE ANTI-COLLATERAL CLAUSE, and the one that fails loudest without the
    // isolation: before it, the `?` in the rule loop propagated out of the whole
    // scan, so this run emitted NO findings at all and the sibling never ran.
    //
    // It also pins CLOUD-126's precedence row end to end: a violation beside an
    // error reports `2`, because `3` in a hook reads as "retry" and that is the
    // wrong response to a decided refusal. Both are non-zero either way, so what
    // is under test is which non-zero the caller sees — never whether it passes.
    let env = Env::new("secrets-isolation-no-collateral");
    env.file("app.conf", "k = 1\n");
    env.install_scanner(&stub(&[], 1));
    env.add_rule(SIBLING_RULE);
    env.file("lib.rs", "TODO fix\n");

    let out = env.run(&["enforce"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a decided refusal outranks an infrastructure complaint"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "lib.rs:1 no-todo\n",
        "the surviving gate's finding still reaches stdout"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("errored no-secrets"),
        "precedence governs the exit code, never what appears in output: {stderr}"
    );
}

#[test]
fn a_contained_failure_still_names_what_went_wrong() {
    // The reason travels with the class. Withholding it — CLOUD-126 §5 read
    // literally — leaves an operator told that a gate "errored" when the engine
    // knew, and used to say, that a scanner and its own output disagreed.
    //
    // Pointer-only is preserved by construction rather than by suppression: the
    // message `cross_check` builds carries a rule id and a count and no byte of
    // any match, which is what `nowhere` asserts across this whole suite.
    let env = Env::new("secrets-isolation-reason");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    // A clean exit that nonetheless emitted a match: the other direction of the
    // cross-check, and the one that carries a token through the failing path.
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 0));

    let out = env.run(&["enforce"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disagree"),
        "the reason reaches the operator: {stderr}"
    );
    assert!(
        stderr.contains("errored no-secrets"),
        "beside the id and the class: {stderr}"
    );
    nowhere(&env, &out, &secret, "contained failure");
}

#[test]
fn the_data_channel_reports_the_contained_failure_as_a_class_token_alone() {
    // The `-J` half of the split, and the half the human-channel case above
    // cannot show. A machine consumer reads neither stderr nor a prose line, so
    // without this field a run that could not evaluate a gate is
    // indistinguishable on the data channel from one that evaluated it clean.
    //
    // The class token and the rule id, and NOTHING else: the reason travels on
    // the message channel because rule 4 binds every error this crate builds to
    // be a pointer, and that argument is about a human reading a diagnostic. The
    // data channel gets the stable token a consumer can branch on (§6), so
    // `ErrorView` has no field a message could arrive in.
    let env = Env::new("secrets-isolation-json");
    let secret = token();
    env.file("app.conf", &format!("api_key = \"{secret}\"\n"));
    env.install_scanner(&stub(&[("app.conf", 1, Some(TOKEN_PARTS))], 0));

    let out = env.run(&["enforce", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let document: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("-J stdout is JSON");

    assert_eq!(document["errored"][0]["rule"], "no-secrets");
    assert_eq!(document["errored"][0]["class"], "internal");
    assert_eq!(
        document["errored"][0].as_object().map(serde_json::Map::len),
        Some(2),
        "the class token and the id, and no third key a reason could ride in on"
    );
    // A run with nothing contained emits no key at all — what keeps the field
    // additive, so every document a consumer parses today is unchanged.
    assert!(
        document["findings"].as_array().is_some_and(Vec::is_empty),
        "the gate could not complete, so it produced no finding either"
    );
    nowhere(&env, &out, &secret, "contained failure under -J");
}
