//! End-to-end tests for the one promotion setting (CLOUD-49).
//!
//! `fail_on_warning` is a single global setting resolved once through the §8
//! precedence chain and exposed three ways — the `--fail-on-warning` flag,
//! `BATTEN_FAIL_ON_WARNING`, and a `batten.toml` key. Everything below is
//! asserted over the **compiled binary**, because the claim being made is about
//! what a caller observes: an exit code and some bytes on stdout.
//!
//! These live in their own file rather than `tests/cli.rs` so the setting's
//! contract reads as one document — the promotion, the raise-only clamp, the
//! three surfaces agreeing, and the boundary the setting does *not* cross.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, stderr, stdout};

/// A config whose only rule carries `severity`, with `top_level` spliced in
/// **before** the rule table — a bare key written after one would be parsed as
/// part of it, so the ordering is load-bearing rather than cosmetic.
fn config(top_level: &str, severity: &str) -> String {
    format!(
        "version = 1\n{top_level}\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\n\
         glob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"{severity}\"\n"
    )
}

/// The default fixture: one `warn`-severity rule and nothing else, so every
/// promotion case below has *no* `deny` finding to lean on — the acceptance
/// requires that a warn hit alone flips the verdict.
fn warn_only() -> String {
    config("", "warn")
}

/// The pointer line the fixture below produces, byte for byte.
const WARN_POINTER: &str = "lib.rs:2 no-todo\n";

/// Create a fresh temp repo containing `config`, a `lib.rs` that trips the rule,
/// and optionally a `batten.local.toml`.
fn repo(name: &str, config: &str, local: Option<&str>) -> PathBuf {
    // Starting from an empty directory is `Fixture`'s unconditional behaviour
    // (CLOUD-63), and it is load-bearing here: the rule globs `**/*.rs`, so ANY
    // stray source file an earlier run left behind becomes an extra finding,
    // and every assertion below that indexes `findings[0]` reads the wrong one.
    let mut fixture = Fixture::new(name)
        .config(config)
        .file("lib.rs", "fine\nTODO fix this\n");
    if let Some(contents) = local {
        fixture = fixture.file("batten.local.toml", contents);
    }
    fixture.build()
}

/// Run `batten` in `dir` with `args`, with the setting's env var cleared unless
/// `env` supplies one — a developer's exported knob must never decide a case.
fn run(dir: &Path, args: &[&str], env: Option<&str>) -> Output {
    let mut command = common::batten();
    command.args(args).current_dir(dir);
    match env {
        Some(value) => command.env("BATTEN_FAIL_ON_WARNING", value),
        None => command.env_remove("BATTEN_FAIL_ON_WARNING"),
    };
    command.output().expect("run batten")
}

#[test]
fn a_warn_finding_is_clean_by_default_and_a_violation_when_promoted() {
    // The issue's headline acceptance, in its testable form: one warn-severity
    // finding and no other hits. Exit 0 unset; exit 2 — the policy verdict of
    // §7, the same code a `deny` finding returns — when the setting is on.
    let dir = repo("fow-headline", &warn_only(), None);

    let default = run(&dir, &["check"], None);
    assert_eq!(default.status.code(), Some(0), "a warn finding is clean");

    let promoted = run(&dir, &["check", "--fail-on-warning"], None);
    assert_eq!(
        promoted.status.code(),
        Some(2),
        "…and promotable to a violation"
    );

    // Reporting is untouched by the promotion: the finding prints identically
    // either way, so turning the setting on cannot change *what* was found.
    assert_eq!(stdout(&default), WARN_POINTER);
    assert_eq!(stdout(&promoted), WARN_POINTER);
}

#[test]
fn the_flag_the_env_var_and_the_config_key_are_one_setting() {
    // Three surfaces, one resolved value: identical exit code and identical
    // bytes. If any surface ever grew its own semantics this is where it shows.
    let plain = repo("fow-three-flag", &warn_only(), None);
    let committed = repo(
        "fow-three-config",
        &config("fail_on_warning = true\n", "warn"),
        None,
    );

    let by_flag = run(&plain, &["check", "--fail-on-warning"], None);
    let by_env = run(&plain, &["check"], Some("true"));
    let by_key = run(&committed, &["check"], None);

    for (name, output) in [("flag", &by_flag), ("env", &by_env), ("config", &by_key)] {
        assert_eq!(output.status.code(), Some(2), "{name} must promote");
        assert_eq!(stdout(output), WARN_POINTER, "{name} output must match");
    }

    // The same three surfaces on `enforce`, which shares the pipeline: the
    // setting is read from the resolved config, not re-declared per verb.
    assert_eq!(
        run(&plain, &["enforce", "--fail-on-warning"], None)
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn a_committed_on_cannot_be_turned_off_by_a_lower_precedence_source() {
    // Raise-only (§8). The refusal is a usage error (exit 1), not a quiet
    // downgrade — an override that reads as applied while doing nothing is the
    // failure this clamp exists to prevent.
    let committed = config("fail_on_warning = true\n", "warn");

    let with_local = repo(
        "fow-raise-only-local",
        &committed,
        Some("version = 1\nfail_on_warning = false\n"),
    );
    let refused = run(&with_local, &["check"], None);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a weakening is a usage error"
    );
    let message = stderr(&refused);
    assert!(
        message.contains("fail_on_warning") && message.contains("may only tighten"),
        "the refusal must name the key and say why, got: {message}"
    );

    let by_env = repo("fow-raise-only-env", &committed, None);
    assert_eq!(
        run(&by_env, &["check"], Some("false")).status.code(),
        Some(1),
        "env may not turn a committed on off either"
    );

    // Restating the committed value is not a weakening — it resolves, promotes,
    // and the run reaches the verdict rather than the refusal.
    assert_eq!(
        run(&by_env, &["check"], Some("true")).status.code(),
        Some(2)
    );

    // The flag has no negative form at all, so the highest-precedence layer is
    // structurally incapable of expressing the weakening.
    let no_off_switch = run(&by_env, &["check", "--fail-on-warning=false"], None);
    assert_eq!(
        no_off_switch.status.code(),
        Some(1),
        "--fail-on-warning takes no value"
    );
}

#[test]
fn only_the_middle_rank_is_promoted() {
    // Two halves of one clause. An `allow` rule is switched off, so the setting
    // has no finding to promote and the run stays clean — the setting can never
    // turn a disabled rule into a gate. A `deny` rule blocks either way, so no
    // error-severity finding is *required* for a promotion to happen.
    let allowed = repo("fow-allow-rank", &config("", "allow"), None);
    let output = run(&allowed, &["check", "--fail-on-warning"], None);
    assert_eq!(output.status.code(), Some(0), "an allow rule stays off");
    assert_eq!(stdout(&output), "", "…and reports nothing");

    let denied = repo("fow-deny-rank", &config("", "deny"), None);
    for args in [&["check"][..], &["check", "--fail-on-warning"][..]] {
        assert_eq!(
            run(&denied, args, None).status.code(),
            Some(2),
            "a deny finding blocks regardless of the setting"
        );
    }

    // A clean tree is clean under the setting: promotion acts on findings that
    // exist, never on their absence.
    let clean = repo("fow-clean", &warn_only(), None);
    fs::write(clean.join("lib.rs"), "all clear\n").expect("rewrite source");
    assert_eq!(
        run(&clean, &["check", "--fail-on-warning"], None)
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn an_empty_env_var_is_unset_and_an_unparseable_one_is_refused() {
    // §10's empty→default position: a CI that exports every knob unconditionally
    // produces an empty value, and that must fall through rather than fail the
    // run. A *present but unparseable* value is the opposite — refused loudly.
    let dir = repo("fow-env-shapes", &warn_only(), None);
    for empty in ["", "   "] {
        assert_eq!(
            run(&dir, &["check"], Some(empty)).status.code(),
            Some(0),
            "an empty env var must not claim the key"
        );
    }

    for bad in ["1", "0", "yes", "TRUE"] {
        let output = run(&dir, &["check"], Some(bad));
        assert_eq!(output.status.code(), Some(1), "{bad:?} must be refused");
        assert!(
            stderr(&output).contains("false, true"),
            "the refusal must name the accepted tokens, got: {}",
            stderr(&output)
        );
    }
}

#[test]
fn json_records_the_promoted_disposition_and_is_byte_stable() {
    // §6: the data channel is byte-identical for identical input and carries the
    // disposition. `severity` is the rule's own rating and `report` is that
    // rating after promotion, so a promoted warning is legible as warn → fail.
    let dir = repo("fow-json", &warn_only(), None);

    let unset = run(&dir, &["check", "-J"], None);
    assert_eq!(unset.status.code(), Some(0));
    let unset_json: serde_json::Value = serde_json::from_str(&stdout(&unset)).expect("valid JSON");
    assert_eq!(unset_json["fail_on_warning"], false);
    assert_eq!(unset_json["findings"][0]["severity"], "warn");
    assert_eq!(unset_json["findings"][0]["report"], "warn");
    assert_eq!(unset_json["findings"][0]["rule"], "no-todo");
    assert_eq!(unset_json["findings"][0]["path"], "lib.rs");
    assert_eq!(unset_json["findings"][0]["line"], 2);

    let promoted = run(&dir, &["check", "--fail-on-warning", "-J"], None);
    assert_eq!(promoted.status.code(), Some(2));
    let promoted_json: serde_json::Value =
        serde_json::from_str(&stdout(&promoted)).expect("valid JSON");
    assert_eq!(promoted_json["fail_on_warning"], true);
    assert_eq!(
        promoted_json["findings"][0]["severity"], "warn",
        "the rule's own rating is unchanged by the promotion"
    );
    assert_eq!(
        promoted_json["findings"][0]["report"], "fail",
        "…and the reported disposition records that it was promoted"
    );

    // Pointer-only holds on this channel too (non-negotiable rule 4).
    assert!(!stdout(&promoted).contains("fix this"));

    // Same input, identical bytes — asserted on both settings, and against the
    // long flag as well as `-J`, which must be the same switch.
    assert_eq!(stdout(&unset), stdout(&run(&dir, &["check", "-J"], None)));
    assert_eq!(
        stdout(&promoted),
        stdout(&run(&dir, &["check", "-J"], Some("true")))
    );
    assert_eq!(
        stdout(&unset),
        stdout(&run(&dir, &["check", "--json"], None))
    );

    // A clean run still emits its document: JSON that is sometimes absent is
    // unparseable, so the empty answer is `findings: []`, not no output.
    let clean = repo("fow-json-clean", &warn_only(), None);
    fs::write(clean.join("lib.rs"), "all clear\n").expect("rewrite source");
    let empty = run(&clean, &["check", "-J"], None);
    assert_eq!(empty.status.code(), Some(0));
    let empty_json: serde_json::Value = serde_json::from_str(&stdout(&empty)).expect("valid JSON");
    assert_eq!(empty_json["findings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn config_show_reports_the_setting_and_the_layer_that_won_it() {
    // §8: the tool answers "which layer set this", so nobody has to reconstruct
    // the chain by hand. This is also the byte-stable JSON record of the
    // resolved setting, alongside the per-run record `-J` emits.
    let dir = repo(
        "fow-config-show",
        &config("fail_on_warning = true\n", "warn"),
        None,
    );

    let committed = run(&dir, &["config", "show", "--json"], None);
    assert_eq!(committed.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_str(&stdout(&committed)).expect("valid JSON");
    // Each key is `{value, source}` — total attribution over the document
    // rather than a parallel map keyed by the overridable subset (CLOUD-30).
    assert_eq!(json["fail_on_warning"]["value"], true);
    assert_eq!(json["fail_on_warning"]["source"], "repo-config");

    // A higher layer restating it wins the attribution without changing the value.
    let by_flag = run(
        &dir,
        &["config", "show", "--json", "--fail-on-warning"],
        None,
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&by_flag)).expect("valid JSON");
    assert_eq!(json["fail_on_warning"]["source"], "flag");

    let unset = repo("fow-config-show-unset", &warn_only(), None);
    let json: serde_json::Value =
        serde_json::from_str(&stdout(&run(&unset, &["config", "show", "--json"], None)))
            .expect("valid JSON");
    assert_eq!(json["fail_on_warning"]["value"], false);
    assert_eq!(json["fail_on_warning"]["source"], "default");
}

/// Walk an emitted `batten spec` tree, collecting every command path that
/// declares a `fail_on_warning` flag and every command path in the surface.
fn walk_spec(node: &serde_json::Value, promotion_flags: &mut Vec<String>, verbs: &mut Vec<String>) {
    let path = node["path"].as_str().unwrap_or_default().to_owned();
    for flag in node["flags"].as_array().into_iter().flatten() {
        if flag["name"] == "fail_on_warning" {
            promotion_flags.push(path.clone());
        }
    }
    verbs.push(path);
    for sub in node["subcommands"].as_array().into_iter().flatten() {
        walk_spec(sub, promotion_flags, verbs);
    }
}

#[test]
fn there_is_exactly_one_promotion_knob_and_exec_is_not_a_consumer() {
    // The scope boundary, asserted on the emitted surface itself (§11).
    //
    // This replaces the tripwire that stood here until `batten exec` landed
    // (CLOUD-285). The clause it was deferring — "the setting does not alter exec
    // behavior" — is now exercised for real against a running exec below, rather
    // than only asserted structurally.
    //
    // What is still deferred, and re-pointed rather than dropped: an exec OUTPUT
    // PREDICATE match must fail whether or not `fail_on_warning` is set, because a
    // warn-but-pass match would be invisible to an agent reading only the exit
    // code. Predicates are CLOUD-117 and do not exist yet, so the tripwire at the
    // end of this test now watches for their config key instead of for the verb.
    let dir = repo("fow-surface", &warn_only(), None);
    let spec: serde_json::Value =
        serde_json::from_str(&stdout(&run(&dir, &["spec"], None))).expect("valid spec JSON");

    let (mut promotion_flags, mut verbs) = (Vec::new(), Vec::new());
    walk_spec(&spec, &mut promotion_flags, &mut verbs);

    // A global clap arg is attached to every command it is visible on, so the
    // check is on the *name*: there is one promotion setting, and no verb
    // declares a differently-named local one to sit beside it.
    assert!(
        !promotion_flags.is_empty(),
        "the promotion setting must reach the emitted spec"
    );
    let strays: Vec<&String> = verbs
        .iter()
        .filter(|path| path.contains("fail-on-warning") || path.contains("promote"))
        .collect();
    assert!(
        strays.is_empty(),
        "no verb may own a promotion knob: {strays:?}"
    );

    // The verb exists now, so its absence of a promotion knob is a real
    // assertion rather than a statement about an empty set.
    assert!(
        verbs.iter().any(|path| path == "exec"),
        "`batten exec` must be in the emitted surface"
    );

    // And the acceptance clause, exercised rather than asserted: a promoted repo
    // full of warn findings changes nothing about what a wrapped command returns.
    // `exec` renders no verdict, so there is nothing for a promotion to promote.
    let promoted = repo("fow-exec-promoted", &config("", "warn"), None);
    for env in [None, Some("true")] {
        let clean = run(
            &promoted,
            &["--fail-on-warning", "exec", "--", "sh", "-c", "exit 0"],
            env,
        );
        assert_eq!(
            clean.status.code(),
            Some(0),
            "a promoted warn finding must not touch a clean wrapped command"
        );
        let failing = run(
            &promoted,
            &["--fail-on-warning", "exec", "--", "sh", "-c", "exit 7"],
            env,
        );
        assert_eq!(
            failing.status.code(),
            Some(7),
            "the child's code is the child's, whatever the promotion setting says"
        );
    }

    // And the assertion the tripwire that used to stand here was holding a place
    // for. It fired twice as designed — once when `batten exec` landed (CLOUD-285)
    // and once when the output-predicate config key did (CLOUD-117) — and this is
    // the real thing it was deferring to.
    //
    // An exec output match fails UNCONDITIONALLY. There is no severity field on a
    // pattern and no dependence on `fail_on_warning`, because the only surface an
    // agent acts on is the exit code: a warn-but-pass match would be invisible to
    // it and would reproduce the exact false green the predicate exists to kill.
    let with_pattern = repo(
        "fow-exec-pattern",
        &config(
            "\n[[exec_pattern]]\nid = \"lying-zero\"\npattern = \"warning[duplicate]\"\n\
             stream = \"both\"\nreason = \"configure the tool to fail instead\"\n",
            "warn",
        ),
        None,
    );
    for env in [None, Some("true"), Some("false")] {
        let matched = run(
            &with_pattern,
            &["exec", "--", "sh", "-c", "echo 'warning[duplicate] x'"],
            env,
        );
        assert_eq!(
            matched.status.code(),
            Some(1),
            "an output match must fail whatever the promotion setting says (env {env:?})"
        );
        // Pointer-only: the pattern id and a location, never the matched line.
        let report = stderr(&matched);
        assert!(
            report.contains("lying-zero"),
            "the refusal names the pattern"
        );
        assert!(
            !report.contains("warning[duplicate] x"),
            "the refusal must never echo the matched line: {report}"
        );
    }

    // And the negative, so the assertion above is about the match rather than
    // about `exec` failing generally: the same command with nothing to match
    // exits 0 under every promotion setting.
    for env in [None, Some("true")] {
        let clean = run(
            &with_pattern,
            &["exec", "--", "sh", "-c", "echo 'all good'"],
            env,
        );
        assert_eq!(
            clean.status.code(),
            Some(0),
            "no match, no promotion (env {env:?})"
        );
    }
}
