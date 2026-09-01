//! A remedy resolves to a declared command or rule, over the compiled binary
//! (CLOUD-1189).
//!
//! # Why this tier and not the unit tests beside the predicate
//!
//! `redirect::validate_remedies` takes its two authorities as arguments, so a
//! unit test hands it whatever rule ids and remedy strings it likes and never
//! proves the CONFIG LOADER assembles them. The defect that shape cannot see is
//! the one `verbs::validate` actually had for its whole life (CLOUD-242): a
//! refusal with no call site, asserted present by a doc comment and a passing
//! test that reached past `parse` to call the validator by hand. Every case here
//! goes through the binary's own `config` load.
//!
//! # The population is currently zero, and that is the row's own premise
//!
//! Measured on the committed table: **22 remedy strings, 0 naming a `batten`
//! invocation**, and 44 `command` routes, 0 of them `batten`-invoking. So this
//! gate reports nothing today and is not expected to. CLOUD-1189 says so in as
//! many words — *"the hole is real today — a remedy could already name a command
//! that never existed, and nothing would say so"* — and its acceptance is that
//! the gate **survives the surface rename by construction**: it resolves against
//! `SURFACE`, so a renamed verb makes a stale remedy fail immediately rather than
//! silently.
//!
//! That makes the anti-vacuity arm here load-bearing in the harder direction
//! (CLOUD-418). A gate over an empty population passes trivially, so the cases
//! that matter are the constructed ones showing it CAN fail, and
//! `the_committed_table_loads` is the mirror that keeps the predicate from being
//! tightened into something the real config trips over.

use crate::common::{Fixture, run, stderr};

/// A config declaring one redirect row whose remedy is `mutation`.
fn config_with(mutation: &str) -> String {
    format!(
        r#"version = 1

[[rule]]
id = "a-declared-rule"
kind = "forbid"
scope = "tree"
glob = "**/*.md"
pattern = "nothing-matches-this"
severity = "deny"

[[redirect]]
glob = "guarded/**"
mutation = "{mutation}"
"#
    )
}

/// (a) A remedy naming a verb the surface does not declare is reported.
///
/// The row's own worked case: a verb that moves turns every remedy naming it
/// into a lie, silently. `show config` is the spelling CLOUD-1184's rename
/// retired, so this is the shape rather than an invented one.
#[test]
fn a_remedy_naming_an_undeclared_command_is_refused() {
    let dir = Fixture::new("redirect-resolves-undeclared")
        .config(&config_with("run `batten show config` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        !output.status.success(),
        "a remedy naming a command the surface does not declare must not load"
    );
    let text = stderr(&output);
    assert!(
        text.contains("redirect[guarded/**].mutation"),
        "the refusal names the remedy's own key: {text}"
    );
    assert!(
        text.contains("show config"),
        "the refusal names the unresolvable command: {text}"
    );
    // AND IT IS THIS REFUSAL, not any refusal. A fixture config that merely
    // failed to parse would satisfy a bare `!success` assertion, and the first
    // draft of this file did exactly that — `glob` typed as an array turned three
    // cases red and would have left these two green for the wrong reason.
    assert!(
        text.contains("not a declared command"),
        "the refusal is the remedy resolver's, not a parse error: {text}"
    );
    // POINTER-ONLY (rule 4): the key and the command, never the remedy prose
    // that carried them.
    assert!(
        !text.contains("instead"),
        "the refusal must not echo the remedy's prose: {text}"
    );
}

/// (b) The anti-vacuity mirror — a declared command resolves and is silent.
///
/// Without this a predicate that refused every `batten` invocation would pass
/// the case above, which is the arm CLOUD-418 exists for.
#[test]
fn a_remedy_naming_a_declared_command_is_clean() {
    let dir = Fixture::new("redirect-resolves-declared")
        .config(&config_with("run `batten config show` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        output.status.success(),
        "a remedy naming a declared command must load: {}",
        stderr(&output)
    );
}

/// (b') The second object shape: a declared rule id after a declared verb.
///
/// A gate that only knew `SURFACE` would report this as broken, which is the
/// false positive that gets a gate switched off — so the arm is asserted rather
/// than assumed from the code reading.
#[test]
fn a_remedy_naming_a_declared_rule_id_is_clean() {
    let dir = Fixture::new("redirect-resolves-rule-id")
        .config(&config_with("run `batten check a-declared-rule` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        output.status.success(),
        "a remedy naming a declared rule id must load: {}",
        stderr(&output)
    );
}

/// And the discriminator for that arm: a word the rule table does NOT declare,
/// after a declared verb, is still reported.
///
/// Without this, "accept anything after a resolved prefix" would pass the case
/// above — the rule-id arm would be decorative rather than deciding.
#[test]
fn a_remedy_naming_an_undeclared_rule_id_is_refused() {
    let dir = Fixture::new("redirect-resolves-unknown-rule")
        .config(&config_with("run `batten check no-such-rule` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        !output.status.success(),
        "a remedy naming a rule the table does not declare must not load"
    );
    let text = stderr(&output);
    assert!(
        text.contains("no-such-rule"),
        "the refusal names the unresolvable word: {text}"
    );
    assert!(
        text.contains("neither a declared rule id"),
        "the refusal is the rule-id arm's, not a parse error: {text}"
    );
}

/// A `<placeholder>` operand is judged by neither authority.
///
/// What a verb's operands may be is a per-verb arity question, and this row
/// reads the command surface and the rule table rather than a third one.
#[test]
fn a_placeholder_operand_is_not_judged() {
    let dir = Fixture::new("redirect-resolves-placeholder")
        .config(&config_with("run `batten capture show <handle>` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        output.status.success(),
        "a placeholder operand must not be resolved against anything: {}",
        stderr(&output)
    );
}

/// (c) A remedy naming a non-batten command is left alone.
///
/// That is the operator's PATH, and resolving it needs a second authority over
/// what is installed — which is `policy/verdict-routes-resolve.rego`'s `mise
/// run` arm and not this one.
#[test]
fn a_remedy_naming_a_non_batten_command_is_not_judged() {
    for remedy in [
        "run `mise run land` instead",
        "use `git restore` to put it back",
    ] {
        let dir = Fixture::new("redirect-resolves-foreign")
            .config(&config_with(remedy))
            .build();
        let output = run(&dir, &["config", "show"]);
        assert!(
            output.status.success(),
            "a non-batten remedy must not be judged here: {}",
            stderr(&output)
        );
    }
}

/// A flag is judged by neither authority.
///
/// Which flags a verb takes is `SURFACE`'s own declaration and `clap`'s to
/// enforce at the call; resolving one here would be a third reading of it.
#[test]
fn a_flag_is_not_judged() {
    let dir = Fixture::new("redirect-resolves-flag")
        .config(&config_with("run `batten config show --json` instead"))
        .build();
    let output = run(&dir, &["config", "show"]);
    assert!(
        output.status.success(),
        "a flag must not be resolved against the rule table: {}",
        stderr(&output)
    );
}

/// THE BOUND, ASSERTED RATHER THAN LEFT TO THE CODE READING: an invocation is a
/// code span, so bare prose naming the binary is not one.
///
/// This is the arm that under-denies, and it is the sanctioned direction. The
/// first version of this gate had no such bound: it collected every following
/// token that looked like a subcommand word, so `run `batten capture show
/// <handle>` instead` was read as a four-word invocation ending in `instead`,
/// and `instead` was reported as an undeclared rule id. A finding invented out
/// of English is the false positive that gets a gate switched off, and it turned
/// three cases in this file red before it was bounded.
///
/// Both halves are asserted here, because the sentence in `invocation`'s doc
/// comment is a claim about behaviour and a claim about behaviour needs a case.
#[test]
fn an_invocation_is_a_code_span_and_bare_prose_is_not_one() {
    // No code span at all: nothing is claimed, however the sentence reads.
    let prose = Fixture::new("redirect-resolves-prose")
        .config(&config_with(
            "this is refused before batten writes anything",
        ))
        .build();
    assert!(
        run(&prose, &["config", "show"]).status.success(),
        "prose after the word `batten` is not a subcommand path"
    );
    // And the under-deny stated outright: the same undeclared verb that IS
    // refused inside a span is not refused outside one. Recorded so a later
    // reader tightening this knows exactly which case they are changing.
    let bare = Fixture::new("redirect-resolves-bare")
        .config(&config_with("run batten show config instead"))
        .build();
    assert!(
        run(&bare, &["config", "show"]).status.success(),
        "a command named in bare prose is deliberately not judged"
    );
}

/// (d) THE ANTI-VACUITY MIRROR THAT MATTERS: this repository's own committed
/// table loads.
///
/// A gate whose first firing is a false positive gets an exception written for
/// it, and the exception is what rots. `config show` over the real root is the
/// cheapest whole-table assertion available, and it is the one that would go red
/// if the predicate were tightened past what an author actually writes.
#[test]
fn the_committed_table_loads() {
    let root = crate::common::at_root(".");
    let output = run(&root, &["config", "show"]);
    assert!(
        output.status.success(),
        "the committed remedy table must resolve: {}",
        stderr(&output)
    );
}
