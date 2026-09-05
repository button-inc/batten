//! The two-shapes retirement rule is present in the tree, at the trigger, not
//! only in a rego header and a refusal (CLOUD-1132).
//!
//! `policy/shell-retirement.rego` admits exactly one disposition for a governed
//! shell gate — retire it whole, or leave it — and `shell edit refused` declares
//! one route with no override and no `bypass_env`. That rule was written down in
//! two places and a reader reached neither before they had already edited the
//! file: the module's own header, and the refusal itself. Two documents
//! `AGENTS.md` routes to implied the opposite — `rules/toolchain.md`
//! introduced `mise-tasks/` as real programs run in the gate, and
//! `mem:toolchain-and-hooks` framed the port as future work the layer was being
//! maintained through meanwhile.
//!
//! Measured cost: in one planning session that gap produced two wrong conclusions
//! in a row, each needing a verification pass to undo — first that six issues were
//! blocked and the ratchet needed changing, then that the ratchet and
//! `rules/policy-modules.md` were in direct conflict over whether a
//! `tests/<gate>.bats` may exist. Both were the same move: looking for a third
//! shape so the bash could keep being edited.
//!
//! WHAT THIS FILE ASSERTS, AND WHAT IT CANNOT. It asserts **presence**: the rules
//! file still states both shapes and that there is no third, still names the
//! module and the verdict token, still carries the edit-versus-deletion asymmetry
//! by naming the module's two classifying rules, still says what a retirement
//! owes and which single edit is admitted, still carries the sentence about a plan
//! whose §1 is in the wrong shape — and is still routed to from `AGENTS.md`'s
//! index **with** the warning in the cell. That catches deletion and drift in the
//! prose, which is the same shape `scanner_taxonomy.rs` uses over
//! `rules/scanning.md` and `spawn_census.rs` over `clippy.toml`.
//!
//! It does **not** catch an agent who does not read the file, and it holds nothing
//! about whether a given change should have been reshaped as a retirement. That
//! axis is `shell-retirement`'s, it is decided over a real diff with a real exit
//! code, and a §7 here claiming otherwise would be this row's own defect one level
//! up.
//!
//! **And it deliberately pins no glob.** The governed sets are the module's, and a
//! copy of them in prose is the drift the row refuses — so what is asserted is
//! that the prose names the module's classifying RULES, and that the module still
//! declares them. A renamed predicate fails here; a widened one does not, and
//! should not.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The rules file the doctrine binds in.
const RULES: &str = "rules/toolchain.md";

/// The always-loaded file whose index has to route a reader to [`RULES`].
///
/// `CLAUDE.md` is a symlink to this; the tracked path is the one asserted.
const INDEX: &str = "AGENTS.md";

/// The module that decides, which the prose must cite rather than restate.
const MODULE: &str = "policy/shell-retirement.rego";

/// The rules file the `$MUTANT_GATES` clause lives in.
const MODULE_RULES: &str = "rules/policy-modules.md";

/// The two classifying rules whose asymmetry is the trap.
///
/// Named rather than described, in both directions: the prose has to point at
/// them and the module has to still declare them, which is what makes this an
/// anti-drift assertion rather than a second copy of the predicate.
const CLASSIFIERS: &[&str] = &["governed_at_head", "governed_when_deleted"];

fn rules_text() -> String {
    fs::read_to_string(at_root(RULES)).expect("`rules/toolchain.md` is committed")
}

#[test]
fn the_rules_state_both_shapes_and_that_there_is_no_third() {
    let text = rules_text();
    for clause in [
        "two landable shapes",
        "there is no third",
        "Retire it whole",
        "Leave the file alone",
    ] {
        assert!(
            text.contains(clause),
            "{RULES} must still say `{clause}` — the rule is that the set of shapes \
             is closed, and prose that lists two without closing the set reads as \
             two examples"
        );
    }
}

#[test]
fn the_rules_name_the_module_and_the_verdict_that_decide() {
    let text = rules_text();
    for token in [MODULE, "shell edit refused", "rule read first"] {
        assert!(
            text.contains(token),
            "{RULES} must name `{token}` — a reader who meets the refusal has to be \
             able to get from its words back to this page, and a page that names \
             neither the module nor the class is not that destination"
        );
    }
}

/// The asymmetry, in both directions: the prose points at the classifiers, and
/// the module still declares them.
#[test]
fn the_rules_carry_the_edit_versus_deletion_asymmetry() {
    let text = rules_text();
    let module = fs::read_to_string(at_root(MODULE)).expect("the module is committed");
    for classifier in CLASSIFIERS {
        assert!(
            text.contains(classifier),
            "{RULES} must name `{classifier}` — the edit set and the deletion set \
             are different sets, and a page that states one governed set leaves a \
             reader confident about the case it does not cover"
        );
        assert!(
            module.contains(classifier),
            "{MODULE} must still declare `{classifier}` — {RULES} sends a reader to \
             it by name, and a renamed predicate turns that pointer into a dead end"
        );
    }
    assert!(
        text.contains("ungoverned\nfor edits and governed for deletion")
            || text.contains("ungoverned for edits and governed for deletion"),
        "{RULES} must state the consequence and not only the two sets: a nested or \
         extensionless program under `mise-tasks/` is ungoverned for edits and \
         governed for deletion, which is the case a reader gets wrong"
    );
}

/// A page can state the shapes and still leave a reader unable to write one.
#[test]
fn the_rules_say_what_a_retirement_owes_and_which_edit_is_admitted() {
    let text = rules_text();
    for clause in [
        "one arm per deleted path",
        "$MUTANT_GATES",
        "only_drops_a_retired_reference",
    ] {
        assert!(
            text.contains(clause),
            "{RULES} must still carry `{clause}` — a rule stating only what is \
             refused leaves the admitted shape to be rediscovered, and the one \
             admitted edit is what a retirement's own cleanup needs"
        );
    }
}

/// "A policy surface" is three shapes, and the prose has to say which is which.
///
/// `has_policy_surface` admits a consumer module, a preset, or engine source, and
/// the arm is byte-checkable where the CHOICE between them is not — so the only
/// thing standing between CLOUD-843's ~130 remaining programs and CLOUD-1176's
/// scope creep is a reader knowing the order. A page that says "a policy surface"
/// and stops reads as "a Rego module", which makes every retirement onto an
/// existing verb look unspellable; that misreading cost this session two wrong
/// turns in one turn.
///
/// Both directions, for `the_rules_carry_the_edit_versus_deletion_asymmetry`'s
/// reason: the prose names the three homes, and the module still declares three
/// arms. Dropping the preset arm — the one no landed row has used — is the failure
/// this pins, because it is the arm whose absence pushes an author toward the core.
#[test]
fn the_rules_name_the_three_homes_and_the_module_admits_them() {
    let text = squashed(&rules_text());
    for clause in [
        "Consumer module",
        "**Preset**",
        "Engine source",
        "mechanism only",
    ] {
        assert!(
            text.contains(&squashed(clause)),
            "{RULES} must name `{clause}` — `has_policy_surface` admits three \
             successor shapes and cannot decide which one a retirement SHOULD have \
             taken, so a page naming fewer than three leaves that choice to be \
             guessed at exactly the moment it is being made"
        );
    }

    let module = squashed(&fs::read_to_string(at_root(MODULE)).expect("the module is committed"));
    assert_eq!(
        module.matches("has_policy_surface(path) if {").count(),
        3,
        "{MODULE} must declare all three `has_policy_surface` arms — a preset lives \
         at `crates/batten/src/policy/presets/**` and is a `.rego`, so it fails the \
         module arm on the prefix and the engine-source arm on the suffix. Without \
         its own arm the one generic-by-construction home cannot be spelled, while \
         the core can, and the gate's incentive runs toward the thing {RULES} tells \
         an author to avoid"
    );
    assert!(
        module.contains("crates/batten/src/policy/presets/"),
        "{MODULE}'s preset arm must match the path presets actually live at"
    );
}

/// The successor KIND field is stated where the author meets it (CLOUD-1182).
///
/// The field is the only thing standing between the campaign's remaining ~130
/// programs and CLOUD-1176's scope creep, and unlike the three homes above it is a
/// REFUSAL — so a page that does not name it produces a load failure whose remedy
/// the reader cannot look up. Both directions, as everything else in this file
/// does: the prose names the two values and the module still admits exactly those.
///
/// It deliberately does NOT pin the 77-of-113 count. That number moves with every
/// retirement, and a test asserting it would fail on correct work — the same
/// reason this file pins no glob.
#[test]
fn the_rules_name_the_successor_kind_field_and_the_module_admits_it() {
    let text = squashed(&rules_text());
    for clause in ["kind:verb", "kind:mechanism", "shell port unnamed"] {
        assert!(
            text.contains(&squashed(clause)),
            "{RULES} must name `{clause}` — an engine-source arm now OWES its kind, \
             and a page that does not say so leaves the author meeting the refusal \
             with nowhere to look up what it wants"
        );
    }

    let module = squashed(&fs::read_to_string(at_root(MODULE)).expect("the module is committed"));
    assert!(
        module.contains("shell port unnamed"),
        "{MODULE} must still raise the token {RULES} tells the author about"
    );
    assert!(
        module.contains(squashed("data.batten.patterns[\"retirement-kind-field\"]").as_str()),
        "{MODULE} must read the kind field through its `[[pattern]]` row rather \
         than an inline regex — `rules/policy-modules.md` refuses the \
         latter at load, and the registry is what keeps one concept one spelling"
    );
}

/// Whitespace-insensitive, because these clauses are prose: `mise run fmt` runs
/// prettier over Markdown and a reflow that moved a line break would otherwise
/// turn a live assertion into a false failure.
fn squashed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The sentence the measured session cost, which is the one a reader acts on at
/// the moment the mistake is available to them.
#[test]
fn the_rules_name_the_wrong_conclusion_the_gap_produced() {
    let text = rules_text();
    assert!(
        text.contains("has not found a blocked row"),
        "{RULES} must still say that a plan naming an edit to a governed program \
         has not found a blocked row but a row whose §1 is in the wrong shape — \
         that is the move this rule exists to catch, and it was made twice"
    );
    assert!(
        text.contains("Do not conclude the ratchet needs changing"),
        "{RULES} must still refuse the second half of that move explicitly: the \
         cheapest reading of a refusal that arrives late is that the gate is wrong"
    );
}

/// The `$MUTANT_GATES` clause cannot be read as demanding a suite for a gate that
/// was just retired.
#[test]
fn the_module_rules_scope_the_mutant_gates_clause_to_a_gate_that_stays() {
    let text =
        fs::read_to_string(at_root(MODULE_RULES)).expect("`rules/policy-modules.md` is committed");
    assert!(
        text.contains("remains registered"),
        "{MODULE_RULES} must scope the `$MUTANT_GATES` / `tests/<gate>.bats` \
         requirement to a gate that REMAINS registered; unscoped it reads as \
         unconditional, and was read that way as a direct conflict with the rule \
         that refuses adding a bats suite"
    );
}

#[test]
fn the_index_routes_a_reader_to_the_rules_with_the_warning_in_the_cell() {
    let index = fs::read_to_string(at_root(INDEX)).expect("`AGENTS.md` is committed");
    let row = index
        .lines()
        .find(|line| line.starts_with('|') && line.contains("toolchain.md"))
        .expect("the `.claude/rules/` index still carries a row for `toolchain.md`");
    assert!(
        row.contains("two landable shapes"),
        "{INDEX}'s index cell must carry the warning itself, not only the route: a \
         reader who is about to edit a governed program decides whether to open \
         `toolchain.md` from this cell, and a cell that reads as setup notes is \
         one they skip. In place rather than as a new line — the file is at its \
         budgeted line ceiling, which `mise run policy budget` gates"
    );
}
