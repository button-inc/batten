#MUTANT-SUITE crates/batten/tests/it/measure_and_edit_routes.rs
#MUTANT profiler-unread|s@^\tprogram.name in profilers$@\tfalse@|a_profiler_is_sent_to_the_skill
# `program measure first`: a profiler run by hand is handed `skills/profile`.
#
# MEASURED, and why this exists beside `program measure unread`. One session
# profiled `stop` four times and rebuilt the recipe each time: callgrind on the
# stripped release binary (no function named), a bare `< payload` that fed only
# the first of ten samply iterations, a sysctl lowered and nearly left lowered,
# folded stacks read as 700 lines. The skill and `mise run profile` carry every
# one of those; nothing put them in front of the call that needed them.
#
# A WARN ROW, NEVER A DENY, `forge read first`'s shape: the call is allowed and
# the pointer rides it. `mise run profile` and the `batten-profile` binary are
# the route itself and are not selected.
#
# SELECTED ON THE PROGRAM, so `cd x && mise exec -- samply …` resolves to
# `samply`. `pre-tool` only, so one call gets one pointer.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.profile_read_first

import rego.v1

rules contains "program measure first"

profilers := {"valgrind", "samply", "hyperfine", "perf", "strace", "callgrind_annotate", "cg_annotate", "cg_diff"}

violation contains {
	"rule": "program measure first",
	"verdict": "program measure first",
	"subjects": [{"count": 1}],
} if {
	object.get(input.call, "event", "pre-tool") == "pre-tool"
	some program in input.call.programs
	program.name in profilers
}

call(programs) := {"call": {
	"command": concat(" && ", [p.name | some p in programs]),
	"segments": [],
	"programs": programs,
	"roots": ["/r"],
}}

prog(name, argv) := {"program": name, "name": name, "arguments": argv, "subcommand": null, "global-options": [], "mediated": false}

test_every_profiler_is_handed_the_skill if {
	every name in profilers {
		some _ in violation with input as call([prog(name, ["x"])])
	}
}

# The run is usually `cd <fixture> && <profiler> …`: a later segment is judged.
test_a_later_segment_is_judged_too if {
	some _ in violation with input as {"call": {
		"command": "cd target/perf/check-repo && samply record -- x",
		"segments": [{"words": ["cd", "target/perf/check-repo"]}, {"words": ["samply", "record", "--", "x"]}],
		"programs": [prog("cd", ["target/perf/check-repo"]), prog("samply", ["record", "--", "x"])],
		"roots": ["/r"],
	}}
}

test_the_route_itself_is_not_selected if {
	count(violation) == 0 with input as call([prog("mise", ["run", "profile", "--", "stop"])])
	count(violation) == 0 with input as call([prog("batten-profile", ["hot", "x.json"])])
}

test_a_post_tool_echo_is_not_repeated if {
	count(violation) == 0 with input as {"call": object.union(call([prog("samply", ["record"])]).call, {"event": "post-tool"})}
}
