# Decoupling Level never falls against the row's base (plan step 3, CLOUD-2821).
#
# The measure is the engine's `coupling` fact: Mo, Cai, Kazman, Xiao and Feng,
# "Decoupling Level: A New Metric for Architectural Maintenance Complexity",
# ICSE 2016, computed over the declared `use` graph at file level, head and
# base. The same paper measures propagation cost falling as unconnected files
# are added, so this module gates DL and never PC; the fact reports PC for a
# reader only.
#
# The judgement is the one comparison below. The engine measures and decides
# nothing (CLOUD-1009 D4), and the row chooses the base: a commit's parent for
# "no commit makes it worse".
package batten

import rego.v1

rules contains "module decoupling dropped"

violation contains {
	"rule": "module decoupling dropped",
	"verdict": "module decoupling dropped",
	"subjects": [{"artifact": "decoupling_level"}],
} if {
	input.tree.coupling.head.decoupling_level < input.tree.coupling.base.decoupling_level
}

test_a_lowered_level_is_refused if {
	count(violation) == 1 with input as {"tree": {"coupling": {
		"head": {"decoupling_level": 0.31},
		"base": {"decoupling_level": 0.32},
	}}}
}

test_an_equal_or_raised_level_passes if {
	count(violation) == 0 with input as {"tree": {"coupling": {
		"head": {"decoupling_level": 0.32},
		"base": {"decoupling_level": 0.32},
	}}}
	count(violation) == 0 with input as {"tree": {"coupling": {
		"head": {"decoupling_level": 0.40},
		"base": {"decoupling_level": 0.32},
	}}}
}

# No base side (a row without `base`): nothing to compare, nothing refused.
test_no_base_side_refuses_nothing if {
	count(violation) == 0 with input as {"tree": {"coupling": {"head": {"decoupling_level": 0.1}}}}
}
