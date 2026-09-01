#MUTANT-SUITE crates/batten/tests/it/preset_segments.rs
#MUTANT force-flag-unread|s@^\tword in {"--force", "-f"}$@\tfalse@|a_force_push_alone_still_denies
# Trunk-based development: a shared branch is not rewritten under its readers.
#
# `--force-with-lease` is deliberately NOT matched. It is the sanctioned form —
# it refuses when the remote moved, which is the whole difference between
# "I know what I am replacing" and "replace whatever is there". A preset that
# banned both would push its consumers toward the bypass rather than toward the
# safer flag.
#
# Names no repository, no ref and no task: this is true of the practice, which is
# what a vendored preset may contain (non-negotiable rule 1).
package batten.trunk_based

import rego.v1

rules contains "no-force-push"

violation contains {
	"rule": "no-force-push",
	"verdict": "trunk push forced",
} if {
	# PER SEGMENT, NOT PER LINE (CLOUD-857). This read
	# `split(input.call.command, " ")` and anchored `words[0] == "git"` over the
	# whole command, so it asked about the first word of the LINE. Measured: the
	# bare `git push --force origin main` denied and
	# `cd /tmp && git push --force origin main` was allowed — and a real agent
	# command is compound most of the time, so the silence was the common case.
	#
	# `input.call.segments` is `hook::segments`, the engine's own quote-aware
	# tokenizer, projected rather than re-derived. There is no `split` here now
	# and there must not be one: a second tokenizer in Rego is what this row
	# exists to prevent, ~80 times over.
	some segment in input.call.segments
	segment.words[0] == "git"
	"push" in segment.words
	some word in segment.words
	word in {"--force", "-f"}
}

# The predicate's own tests (CLOUD-835), and the second one is the point: the
# distinction this preset exists to draw is `--force` against
# `--force-with-lease`, so a suite that only proved the deny fires would not
# have tested the practice at all.
#
# `with input as` rather than a declared fixture: the input is local to the test
# that depends on it, which is OPA and Conftest's own shape, and a preset ships
# with no consumer tree to declare documents from.
#
# THESE LIVE IN THE REGISTERED MODULE, AND THAT COST WAS MEASURED. `policy::load`
# compiles and smoke-queries every registered module on every mediated call, so a
# `test_` rule here is evaluated on the hook path — the one place this repository
# budgets in milliseconds. Measured 2026-08-21, `perf-pair` against the merge
# base on one machine: `hook` 3.2 ms -> 3.3 ms and `wired` 7.2 ms -> 7.4 ms, both
# ratio 1.03, inside the 0.966-1.102 spread a null comparison of one identical
# binary produces. `noop`, `passthrough` and `check` did not move.
#
# So a sibling-file convention that kept tests out of the loaded set buys
# nothing, and is not worth the second load path it would cost. Re-measure before
# concluding otherwise: to move this row, bring a number.
# EVERY CASE PASSES SEGMENTS, AND AT LEAST ONE IS COMPOUND (CLOUD-857). The old
# suite handed each case a bare command and was green over the hole above — the
# predicate WAS exercised and the module WAS tested, which is why neither safety
# net fired. A bare-only suite is now reported by `batten policy test` itself, so
# this shape is the enforced one rather than a convention.
test_no_force_push if {
	some v in violation with input as {"call": {"segments": [{"words": ["git", "push", "--force", "origin", "main"], "raw": "git push --force origin main", "terminator": null}]}}
	v.rule == "no-force-push"
}

test_short_force_flag_is_caught_too if {
	some v in violation with input as {"call": {"segments": [{"words": ["git", "push", "-f", "origin", "main"], "raw": "git push -f origin main", "terminator": null}]}}
	v.rule == "no-force-push"
}

# THE CASE THE OLD SUITE COULD NOT HAVE: the force push is the SECOND element of
# a list, so `words[0]` over the whole line is `cd`. This is the measurement the
# row was filed on.
test_a_force_push_later_in_a_list_is_caught if {
	some v in violation with input as {"call": {"segments": [
		{"words": ["cd", "/tmp"], "raw": "cd /tmp", "terminator": "&&"},
		{"words": ["git", "push", "--force", "origin", "main"], "raw": "git push --force origin main", "terminator": null},
	]}}
	v.rule == "no-force-push"
}

test_force_with_lease_is_left_alone if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["git", "push", "--force-with-lease", "origin", "main"], "raw": "git push --force-with-lease origin main", "terminator": null}]}}
}

# The distinction survives segmentation, which is the half a deny-only suite
# would not have tested: the same compound shape, the sanctioned flag.
test_force_with_lease_survives_a_list_too if {
	count(violation) == 0 with input as {"call": {"segments": [
		{"words": ["cd", "/tmp"], "raw": "cd /tmp", "terminator": "&&"},
		{"words": ["git", "push", "--force-with-lease", "origin", "main"], "raw": "git push --force-with-lease origin main", "terminator": null},
	]}}
}

# A MENTION IS NOT AN INVOCATION, and segmentation must not regress it: the
# quoted span survives as ONE word (CLOUD-269), so `words[0]` is `echo`.
test_a_quoted_mention_does_not_fire if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["echo", "git push --force origin main"], "raw": "echo \"git push --force origin main\"", "terminator": null}]}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"segments": [{"words": ["hg", "push", "--force"], "raw": "hg push --force", "terminator": null}]}}
}
