# CLOUD-1210's ratchet: the cargo test-target count does not grow.
#
# WHY A MODULE AND NOT `kind = "ratchet"`. That kind's own doc defines it as "the
# total occurrences of `pattern` across files matching `glob`" — a TOKEN COUNT
# INSIDE FILES. `tests-not-deleted` counts `#[test]`; `bash-surface-not-growing`
# counts `#MISE description=`. A cargo test-target count is a property of the
# DIRECTORY STRUCTURE plus Cargo's autodiscovery, and no `glob`+`pattern` pair
# computes it. So the ratchet is spelled as a predicate over paths.
#
# WHY THE PATH SPELLING IS SOUND HERE WHEN A FILE COUNT WAS NOT. Cargo
# autodiscovers one test target per TOP-LEVEL `crates/batten/tests/*.rs`, and a
# file one segment deeper — inside a group directory carrying `main.rs` — is not a
# target at all. So "no new top-level `crates/batten/tests/*.rs`" IS "the target
# count does not grow", exactly, rather than approximately.
#
# THAT DISTINCTION IS WHAT KEEPS CLOUD-843'S CAMPAIGN RUNNING, and it is the whole
# reason this is not a `[[ratchet]]` over files. `.claude/rules/toolchain.md`
# requires every retirement to land its predicate as a `policy/*.rego` module PLUS
# a `crates/batten/tests/*.rs` tier, so a retirement adds a test file BY MANDATE —
# which is why `prune.rs` recorded the count moving 110 -> 114 -> 118 across three
# readings in ten days, and why 142 -> 144 happened in eight commits. A gate
# refusing every added test FILE would fire on the next correctly-executed
# retirement and the campaign would have to switch it off: the shape a gate does
# not survive. A retirement landing its tier as a `mod` inside the group is
# invisible to this rule, which is the property that makes it survivable.
#
# NO SPAWN, AND NO BASE-REV POSITION TO TAKE. `input.tree["base-delta"]` is the
# comparison already — the engine resolved it — so the hard half of a ratchet
# spelling disappears rather than being solved.
# THE MUTATIONS, chosen to DISCRIMINATE rather than to be plausible. A mutation
# over a conjunct some other conjunct already excludes survives, and surviving is
# the only way you find out — so each names the case that must turn red.
#
# The first is not hypothetical: the depth test shipped as `== 5` in this file's
# first revision, which is exactly inverted, and the compiled tier caught it.
#MUTANT depth-may-invert|s@count(segments) == 4@count(segments) == 5@|a module inside the group is not a target, and a new top-level file is
#MUTANT extension-may-widen|s@endswith(path, ".rs")@true@|a fixture file under tests/ is not a target
#
#MUTANT-EXEMPT CLOUD-1210|no `tests/test-targets.bats` exists and none may: `.claude/rules/toolchain.md`'s two-shapes rule and `shell add refused` refuse adding an authored bats suite, and `mutant` resolves a gate's suite as `tests/$gate.bats`, so there is no named case a mutation could turn red. The second tier is `crates/batten/tests/it/test_targets.rs`, which drives the compiled engine over a real fixture repository with a real base ref — and is what caught the inverted depth test the first `#MUTANT` row above records
package batten

import rego.v1

rules contains "test-target-added"

# The branch's own diff. `base-delta` is NULL when the base rev does not resolve,
# so `added` does not hold and this rule goes silent — could-not-look, never a
# fabricated empty delta that would pass the gate on ignorance. That is
# `filed-here.rego`'s reading of the same fact and it is deliberate here too.
delta := input.tree["base-delta"]

# A path is a NEW TEST TARGET when it is added, sits directly under
# `crates/batten/tests/`, and ends in `.rs`.
#
# `count(segments) == 4` is what makes it TOP-LEVEL: `crates/batten/tests/x.rs`
# splits to FOUR segments, while `crates/batten/tests/it/x.rs` splits to five and
# is a module rather than a target. Spelled as a segment count rather than a glob
# because the engine's globs use `literal_separator(true)`, so `*` already stops
# at a `/` — and stating the depth explicitly is what a reader can check against
# Cargo's autodiscovery rule without knowing that.
#
# THE COUNT WAS WRITTEN AS 5 AND THAT WAS EXACTLY INVERTED: it refused the grouped
# module and allowed the new target, which is the one direction that fails
# silently. The load-time cases below agreed with the mistake, because a
# `with input as` case can only be as right as its author. The compiled tier in
# `crates/batten/tests/it/test_targets.rs` is what caught it — which is the whole
# reason `.claude/rules/policy-modules.md` calls that second tier not optional.
added_target contains path if {
	some path in delta.added
	segments := split(path, "/")
	count(segments) == 4
	segments[0] == "crates"
	segments[1] == "batten"
	segments[2] == "tests"
	endswith(path, ".rs")
}

violation contains {
	"rule": "test-target-added",
	"verdict": "test add refused",
	"subjects": [{"path": path}],
} if {
	some path in added_target
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. What they cannot pin is that the engine builds the
# input the predicate reads — `with input as` fabricates the very shape the engine
# may be unable to produce — so `crates/batten/tests/it/test_targets.rs` runs the
# same questions over the compiled binary. Both tiers, per
# `.claude/rules/policy-modules.md`, and the second is not optional.

test_a_new_top_level_test_file_is_refused if {
	count(violation) == 1 with input as {"tree": {"base-delta": {
		"added": ["crates/batten/tests/new_gate.rs"],
		"edited": [],
		"deleted": [],
	}}}
}

# THE CASE THAT MAKES THE RULE SURVIVABLE. A retirement's tier lands inside the
# group and must not be refused; without this the campaign switches the gate off.
test_a_module_inside_the_group_is_not_a_target if {
	count(violation) == 0 with input as {"tree": {"base-delta": {
		"added": ["crates/batten/tests/it/new_gate.rs"],
		"edited": [],
		"deleted": [],
	}}}
}

# An EDITED top-level file is not a new target. Only `added` mints one, and
# reading `edited` would refuse every change to a file that already exists.
test_an_edited_file_is_not_a_new_target if {
	count(violation) == 0 with input as {"tree": {"base-delta": {
		"added": [],
		"edited": ["crates/batten/tests/it/walker.rs"],
		"deleted": [],
	}}}
}

# A non-Rust file under `tests/` is fixture data, not a target.
test_a_fixture_file_is_not_a_target if {
	count(violation) == 0 with input as {"tree": {"base-delta": {
		"added": ["crates/batten/tests/fixtures/hooks/new.json"],
		"edited": [],
		"deleted": [],
	}}}
}

# ANTI-VACUITY on the depth check. A path under ANOTHER crate's `tests/` has the
# same shape and the same segment count, so without the `crates/batten` anchor
# this rule would refuse a sibling crate's targets — and with a wrong anchor it
# would refuse nothing at all and still pass every case above.
test_another_crates_test_file_is_not_this_rules_business if {
	count(violation) == 0 with input as {"tree": {"base-delta": {
		"added": ["crates/other/tests/new_gate.rs"],
		"edited": [],
		"deleted": [],
	}}}
}

# COULD NOT LOOK. A null `base-delta` must go silent rather than read as an empty
# diff — the distinction `filed-here.rego` records and the one a migration gate
# has to keep.
test_an_unresolvable_base_refuses_nothing if {
	count(violation) == 0 with input as {"tree": {"base-delta": null}}
}
