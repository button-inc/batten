# The claim order survives in the instruction surface (CLOUD-1343).
#
# The claim receipt is minted on `claim check`'s PULLABLE path and keyed by the
# branch checked out at that moment. That one fact makes two orderings fail in
# opposite directions, and BOTH are reachable by following the instructions:
# claim-then-branch strands the receipt on a branch the work will not land on,
# and claiming a SECOND time runs after the row has left Todo, reads it as held,
# and refuses `not-todo` — where the holder is the caller, ninety seconds
# earlier. The only route past that is `--takeover` against oneself, which writes
# a takeover record for a row nobody else touched, and CLOUD-1139 needs that
# signal to stay rare.
#
# Measured twice in two sessions, both times by an agent following the documented
# order correctly. The instructions were not WRONG so much as silent about the
# ordering, and silence is what a reader fills in with the natural reading.
#
# WHAT THIS DECIDES, AND WHY IT IS A GATE RATHER THAN PROSE. The object is a
# tracked file's own text — does the always-loaded file state the order, and does
# the triggered rules file carry the reason. That is a real object with a real
# exit code, so non-negotiable rule 3 is satisfied. It catches DELETION and DRIFT,
# which is the whole failure mode here: the remedy is words, and words evaporate.
#
# WHAT IT CANNOT DECIDE, stated so no §7 overclaims it. Whether a given session
# actually claimed before branching is not a property of the tree, and a gate
# resolving to that would be the model verdict rule 3 forbids. This is the same
# division `rules/scanning.md` records for its own case: the prose carries
# the position, and the gate keeps the prose from evaporating.
#
# TWO FILES BECAUSE A BUDGET FORCED IT, and the split is load-bearing rather than
# incidental. `policy-budget` caps AGENTS.md at 3500 tokens and 199 lines; the
# first draft of CLOUD-1343 put the whole explanation there and blew both. So the
# always-loaded file carries only the ORDER an agent needs in hand every turn, and
# the reason lives in the rules file that loads at the trigger — which means BOTH
# arms are needed, since either half alone is a reader who learns only half the
# trap.
#MUTANT-SUITE crates/batten/tests/it/claim_order.rs
#MUTANT order-may-go-unstated|s@^	not index_states_the_order$@	false@|an_index_that_does_not_state_the_order_is_refused
#MUTANT reason-may-go-unwritten|s@^	not rules_carry_both_directions$@	false@|a_rules_file_missing_a_failure_direction_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.claim_order_is_stated

import rego.v1

rules contains "claim-order-is-stated"

# The always-loaded file. `CLAUDE.md` is a symlink to this; the TRACKED path is
# the one judged, because the symlink is not what the budget counts.
index_path := "AGENTS.md"

rules_path := "rules/toolchain.md"

# A file this reader could not open is could-not-look, and is reported as such by
# the arm at the bottom rather than passing silently — the `missing` clause
# `rules/policy-modules.md` requires, without which a module reports green
# over a file it never read.
line(path) := input.tree.lines[path]

# NOT APPLICABLE IS NOT A FINDING, and the guard is the triggered file rather than
# the index. This row is about a SPLIT — the order in the always-loaded file, the
# reason in the file that loads at the trigger — so a tree carrying an
# instructions file and no `.claude/rules/` surface has not made that split and is
# answering for nothing here. Measured: the committed configuration is run over a
# fixture repository whose `AGENTS.md` is the single word `instructions`, and
# without this conjunct every arm below fires on it.
#
# Keyed on the RULES file for that reason and not the index: guarding on the index
# would be circular, since an absent index is exactly what one arm exists to
# refuse. `hk-fix-selection`'s `governed` is the same shape over its own config.
governed if count(line(rules_path)) > 0

# THE ORDER, in the always-loaded file. The phrase is the one the file states;
# matching a looser paraphrase would pass a rewrite that dropped the ordering,
# which is the drift this exists to catch.
index_states_the_order if {
	some text in line(index_path)
	contains(text, "branch first, then claim")
}

# EXACTLY ONE CLAIM. Branching first is necessary and NOT sufficient: the refusal
# that actually bit, twice, arrives on the re-run after the row has left Todo. An
# index that stated only "branch first" would leave a reader walking into it.
index_asks_for_one_claim if {
	some text in line(index_path)
	contains(text, "ONCE")
}

# BOTH FAILURE DIRECTIONS, in the triggered file. One alone is half a warning.
rules_carry_both_directions if {
	some claim_then_branch in line(rules_path)
	contains(claim_then_branch, "Claim, then branch")
	some claim_twice in line(rules_path)
	contains(claim_twice, "Claim twice")
}

violation contains {
	"rule": "claim-order-is-stated",
	"verdict": "claim declare dropped",
	"subjects": [{"path": index_path}],
} if {
	governed
	line(index_path)
	not index_states_the_order
}

violation contains {
	"rule": "claim-order-is-stated",
	"verdict": "claim declare dropped",
	"subjects": [{"path": index_path}],
} if {
	governed
	line(index_path)
	not index_asks_for_one_claim
}

violation contains {
	"rule": "claim-order-is-stated",
	"verdict": "claim declare dropped",
	"subjects": [{"path": rules_path}],
} if {
	governed
	not rules_carry_both_directions
}

# COULD NOT LOOK IS NOT A CLEAN TREE. A declared source that would not parse is
# reported rather than left absent, or this gate comes back green over a file it
# never opened.
violation contains {
	"rule": "claim-order-is-stated",
	"verdict": "claim declare dropped",
	"subjects": [{"path": path}],
} if {
	governed
	some path, _ in input.tree.missing
}

# The predicate's own tests. The SILENT case is load-bearing: every arm here is a
# refusal, so a module that fired on everything would satisfy each deny case
# while deciding nothing.

sound := {"tree": {
	"lines": {
		"AGENTS.md": ["pulled — branch first, then claim ONCE (`mise run claim-check`)"],
		"rules/toolchain.md": ["- Claim, then branch.", "- Claim twice."],
	},
	"missing": {},
}}

swap(path, lines) := {"tree": object.union(
	object.remove(sound.tree, ["lines"]),
	{"lines": object.union(
		object.remove(sound.tree.lines, [path]),
		{path: lines},
	)},
)}

test_a_sound_tree_is_clean if {
	count(violation) == 0 with input as sound
}

test_an_index_that_does_not_state_the_order_is_refused if {
	some v in violation with input as swap("AGENTS.md", ["pulled — claim ONCE, then assign"])
	v.verdict == "claim declare dropped"
}

# BRANCHING FIRST IS NOT SUFFICIENT, so an index that says only that is still
# refused: the second claim is the half that actually bit.
test_an_index_that_does_not_ask_for_one_claim_is_refused if {
	some v in violation with input as swap("AGENTS.md", ["pulled — branch first, then claim it"])
	v.verdict == "claim declare dropped"
}

test_a_rules_file_missing_a_failure_direction_is_refused if {
	found := violation with input as swap("rules/toolchain.md", ["- Claim, then branch."])
	some v in found
	v.verdict == "claim declare dropped"
}

# THE FINDING POINTS AT THE FILE THAT LOST THE TEXT, not at whichever sorts
# first: a reader told "the claim order is gone" needs to know which of the two
# to open.
test_the_finding_names_the_file_that_drifted if {
	found := violation with input as swap("rules/toolchain.md", ["- Claim, then branch."])
	paths := {sub.path | some v in found; some sub in v.subjects}
	paths == {"rules/toolchain.md"}
}

test_a_source_that_would_not_parse_is_reported if {
	some v in violation with input as {"tree": object.union(
		sound.tree,
		{"missing": {"AGENTS.md": "unparsed"}},
	)}
	v.verdict == "claim declare dropped"
}

# AN INDEX WITH NO TRIGGERED RULES FILE IS THE FIXTURE SHAPE, and it is silent.
# This is the arm the committed configuration is actually run over: a repository
# carrying an instructions file that never made this split.
test_an_index_without_the_rules_file_is_not_judged if {
	count(violation) == 0 with input as {"tree": {
		"lines": {"AGENTS.md": ["instructions"]},
		"missing": {},
	}}
}

# A TREE WITHOUT THESE FILES IS NOT THIS ROW'S BUSINESS, which is what keeps the
# committed config usable over a fixture repository that carries neither.
test_a_tree_carrying_neither_file_is_never_refused if {
	count(violation) == 0 with input as {"tree": {"lines": {}, "missing": {}}}
}
