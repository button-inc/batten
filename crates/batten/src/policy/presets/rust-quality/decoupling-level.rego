# The module graph is no worse than the row's base (plan step 3, CLOUD-2821).
#
# Two refusals, each from the engine's `coupling` fact (head and base), each
# with its outcome evidence:
#
# - `module score dropped`: M-score (Pisch, Cai, Kazman, Lefever, Fang, ESEM
#   2024) fell. Over 1,220 releases it "correlated well with maintenance
#   effort" and stayed stable where Decoupling Level and propagation cost are
#   "distorted by sizes or isolated files".
# - `module cycle grown`: the largest cycle of files grew. Anti-patterns
#   "caused by cycles among files" had the most impact on maintenance burden in
#   a 1,252-project study (ICSE 2025), and acyclicity is Lakos's design
#   imperative (Large-Scale C++ Vol. I, section 2.2.24).
#
# Decoupling Level is not gated: the same study found "no significant
# correlation between DL and any maintenance activity metrics". Propagation
# cost is not gated: it falls whenever an unconnected file is added (Mo et al.,
# ICSE 2016). Both stay in the fact for a reader.
#
# The engine measures and decides nothing (CLOUD-1009 D4); the row chooses the
# base, a commit's parent for "no commit makes it worse".
package batten

import rego.v1

rules contains "module score dropped"

rules contains "module cycle grown"

violation contains {
	"rule": "module score dropped",
	"verdict": "module score dropped",
	"subjects": [{"artifact": "mscore"}],
} if {
	input.tree.coupling.head.mscore < input.tree.coupling.base.mscore
}

violation contains {
	"rule": "module cycle grown",
	"verdict": "module cycle grown",
	"subjects": [{"artifact": "largest_component"}],
} if {
	input.tree.coupling.head.largest_component > input.tree.coupling.base.largest_component
}

test_a_lowered_score_is_refused if {
	count(violation) == 1 with input as {"tree": {"coupling": {
		"head": {"mscore": 0.31, "largest_component": 3},
		"base": {"mscore": 0.32, "largest_component": 3},
	}}}
}

test_a_grown_cycle_is_refused if {
	count(violation) == 1 with input as {"tree": {"coupling": {
		"head": {"mscore": 0.32, "largest_component": 4},
		"base": {"mscore": 0.32, "largest_component": 3},
	}}}
}

test_an_equal_or_better_graph_passes if {
	count(violation) == 0 with input as {"tree": {"coupling": {
		"head": {"mscore": 0.32, "largest_component": 3},
		"base": {"mscore": 0.32, "largest_component": 3},
	}}}
	count(violation) == 0 with input as {"tree": {"coupling": {
		"head": {"mscore": 0.40, "largest_component": 2},
		"base": {"mscore": 0.32, "largest_component": 3},
	}}}
}

# No base side (a row without `base`): nothing to compare, nothing refused.
test_no_base_side_refuses_nothing if {
	count(violation) == 0 with input as {"tree": {"coupling": {"head": {"mscore": 0.1, "largest_component": 9}}}}
}
