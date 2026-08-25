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
	"verdict": "V-FORCE-PUSH-AT-TRUNK",
} if {
	words := split(input.call.command, " ")
	words[0] == "git"
	"push" in words
	some word in words
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
test_no_force_push if {
	some v in violation with input as {"call": {"command": "git push --force origin main"}}
	v.rule == "no-force-push"
}

test_short_force_flag_is_caught_too if {
	some v in violation with input as {"call": {"command": "git push -f origin main"}}
	v.rule == "no-force-push"
}

test_force_with_lease_is_left_alone if {
	count(violation) == 0 with input as {"call": {"command": "git push --force-with-lease origin main"}}
}

test_another_tool_is_not_judged if {
	count(violation) == 0 with input as {"call": {"command": "hg push --force"}}
}
