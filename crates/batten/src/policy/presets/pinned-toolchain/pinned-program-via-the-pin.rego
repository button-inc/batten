#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT mediation-unread|s@^\tnot entry.mediated$@\tfalse@|every_shipped_preset_passes_its_own_suite
# A pinned toolchain: a program the pin provides is reached through the pin.
#
# The practice is that a project which pins its tools gets the pinned ones. A
# program reached around the pin is a different build, on a different version,
# with a different environment — and the failure that produces is the dangerous
# kind, because it looks like the failure the caller was investigating.
#
# Measured on this repository's own consumer, 2026-08-23: a session reproducing an
# in-gate test failure ran the suite's runner directly rather than through the
# task that wraps it. Same binary, same arguments; what was missing was the
# environment the pin composes, so every run died on an unset variable instead of
# on the assertion under test. An unset-variable death under `set -u` is
# indistinguishable from an assertion failure at the resolution a caller reads.
# Sixty runs measured nothing, three false claims were published, and an Urgent
# row was filed on them.
#
# NAMES NO TOOL, NO TASK AND NO PIN, which is what a vendored preset may contain
# (non-negotiable rule 1). Which programs the pin provides is a FACT the boundary
# resolves for the project being judged, and whether the pin selected this one is
# a reading of the argv that the boundary also owns. A preset that named a
# mediator would be one project's argv wearing a practice's clothes.
package batten.pinned_toolchain

import rego.v1

rules contains "pinned-program-via-the-pin"

# The programs this project's pin provides.
#
# `null` — could-not-look — leaves this set empty, so the predicate below cannot
# hold and the preset is silent. That is the only safe direction for a fact that
# names every program in a project: a refusal on a failure to look would refuse
# the project.
provided contains name if {
	names := input.facts["pinned-programs"]
	is_array(names)
	some name in names
}

# One entry per segment of the command, so a program reached around the pin in the
# second half of a pipeline is as visible as one in the first.
#
# `mediated` is the BOUNDARY's reading, not this module's. Deciding it here would
# mean re-implementing the wrapper look-through, the environment assignments and
# every spelling of the mediator's own invocation — a second authority over an
# argv the engine already parses, and the class of defect that authority split
# exists to prevent.
violation contains {
	"rule": "pinned-program-via-the-pin",
	"verdict": "pin reach loose",
	"subjects": [{"artifact": entry.name}],
} if {
	some entry in input.call.programs
	not entry.mediated
	provided[entry.name]
}

# --- cases ---------------------------------------------------------------
#
# The load-time tier, evaluated on the hook path like every registered module's
# (`no-force-push`'s header measures what that costs and finds it inside the
# null-comparison spread).

test_a_pinned_program_reached_around_the_pin_is_refused if {
	some v in violation with input as {
		"call": {"programs": [{"program": "./tests/bats/bin/bats", "name": "bats", "mediated": false}]},
		"facts": {"pinned-programs": ["bats", "jq"]},
	}
	v.rule == "pinned-program-via-the-pin"
}

test_the_same_program_through_the_pin_is_left_alone if {
	count(violation) == 0 with input as {
		"call": {"programs": [{"program": "bats", "name": "bats", "mediated": true}]},
		"facts": {"pinned-programs": ["bats", "jq"]},
	}
}

# The half that pays for the practice: a program the pin does not provide is a
# genuine one-off, and refusing it would make the preset a ban on the shell.
test_a_program_the_pin_does_not_provide_is_not_judged if {
	count(violation) == 0 with input as {
		"call": {"programs": [{"program": "ls", "name": "ls", "mediated": false}]},
		"facts": {"pinned-programs": ["bats", "jq"]},
	}
}

# COULD-NOT-LOOK IS SILENT, never a refusal. This is the case that keeps the
# preset from denying every program in a project whose pin the boundary could not
# reach — a fresh clone, a machine with no toolchain manager installed, a record
# written under a different manifest.
test_an_unresolved_fact_refuses_nothing if {
	count(violation) == 0 with input as {
		"call": {"programs": [{"program": "./tests/bats/bin/bats", "name": "bats", "mediated": false}]},
		"facts": {"pinned-programs": null},
	}
}

# Every segment is judged, which is what makes a pipeline as visible as a bare
# call. Without this the practice would hold for `bats …` and not for
# `something | bats …`.
#
# THE COMMAND IS SPELLED OUT BESIDE THE PROJECTION, and it is not decoration:
# `programs` is DERIVED from that line by the boundary, so a case carrying the
# array without the command it came from documents a shape rather than a call.
# CLOUD-857 measured what that costs one layer over — the vendored `no-force-push`
# preset anchored on the first word of the whole line, so `git push --force` denied
# and `cd /tmp && git push --force` was allowed, and its own cases never passed a
# compound command to notice. `module-tested-bare-only` is the gate that came out
# of it, and this is the case it asks every mediated module for.
test_a_later_segment_is_judged_too if {
	some v in violation with input as {
		"call": {
			"command": "cat notes.txt | ./tests/bats/bin/bats tests/land.bats",
			"programs": [
				{"program": "cat", "name": "cat", "mediated": false},
				{"program": "./tests/bats/bin/bats", "name": "bats", "mediated": false},
			],
		},
		"facts": {"pinned-programs": ["bats"]},
	}
	v.subjects[0].artifact == "bats"
}
