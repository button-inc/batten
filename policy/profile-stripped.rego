#MUTANT-SUITE crates/batten/tests/it/measure_and_edit_routes.rs
#MUTANT stripped-unread|s@^\tstripped(word)$@\tfalse@|callgrind_on_a_release_binary_is_refused
# `program measure unread`: a CPU profiler pointed at a stripped release binary.
#
# `[profile.release]` has `strip = true`, so callgrind on `target/release/<bin>`
# attributes every instruction to a bare address. Measured on `stop`: 1.8 G
# instructions, 85% under one chain of `???:0x…` frames, and a rebuild before
# anything could be named. The profile is a minute of valgrind spent to learn
# nothing, and the agent rediscovers the remedy every time. The remedy is the
# `profiling` Cargo profile and `skills/profile`, which this refusal names at
# the moment it is needed.
#
# Only valgrind is judged; `hyperfine` on `release` is right, since the absolute
# gate measures `release`.

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: this row is `scope = "mediated_call"`, so
#   it reads the `{call, facts}` document and never the tree.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.profile_stripped

import rego.v1

rules contains "program measure unread"

violation contains {
	"rule": "program measure unread",
	"verdict": "program measure unread",
	"subjects": [{"count": 1}],
} if {
	some program in input.call.programs
	program.name == "valgrind"
	some word in program.arguments
	stripped(word)
}

# `target/release/batten`, `./target/release/x`, `/abs/target/release/x`. A
# triple's release dir (`target/<triple>/release/x`) strips the same way.
stripped(word) if {
	regex.match(data.batten.patterns["release-binary-path"], word)
}

call(argv) := {"call": {
	"command": concat(" ", array.concat(["valgrind"], argv)),
	"segments": [],
	"programs": [{"program": "valgrind", "name": "valgrind", "arguments": argv, "subcommand": null, "global-options": [], "mediated": false}],
	"roots": ["/home/user/repo"],
}}

test_callgrind_on_the_release_binary_is_refused if {
	some _ in violation with input as call(["--tool=callgrind", "/home/user/repo/target/release/batten", "adjudicate"])
}

test_every_release_spelling_is_refused if {
	every argv in [
		["--tool=callgrind", "target/release/batten"],
		["--tool=callgrind", "./target/release/batten", "check"],
		["--tool=cachegrind", "/r/target/x86_64-unknown-linux-gnu/release/batten"],
	] {
		some _ in violation with input as call(argv)
	}
}

# The run is usually `cd <fixture> && valgrind …`, so the profiler sits in a
# later segment; every program on the line is judged, not the first word.
test_a_later_segment_is_judged_too if {
	some _ in violation with input as {"call": {
		"command": "cd target/perf/check-repo && valgrind --tool=callgrind /r/target/release/batten adjudicate",
		"segments": [
			{"words": ["cd", "target/perf/check-repo"]},
			{"words": ["valgrind", "--tool=callgrind", "/r/target/release/batten", "adjudicate"]},
		],
		"programs": [
			{"program": "cd", "name": "cd", "arguments": ["target/perf/check-repo"], "subcommand": null, "global-options": [], "mediated": false},
			{"program": "valgrind", "name": "valgrind", "arguments": ["--tool=callgrind", "/r/target/release/batten", "adjudicate"], "subcommand": null, "global-options": [], "mediated": false},
		],
		"roots": ["/r"],
	}}
}

test_the_profiling_binary_is_allowed if {
	count(violation) == 0 with input as call(["--tool=callgrind", "/home/user/repo/target/profiling/batten", "adjudicate"])
}

test_an_output_file_under_release_is_not_a_binary if {
	count(violation) == 0 with input as call(["--callgrind-out-file=target/release/x.out", "target/profiling/batten"])
}
