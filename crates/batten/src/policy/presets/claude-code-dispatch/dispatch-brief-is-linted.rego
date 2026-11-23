#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT brief-lint-unread|s@^\tinput.facts\["dispatch-brief"\].clean == false$@\tfalse@|an_unlinted_dispatch_is_refused_with_its_findings
# A dispatch whose message fails the brief lint is refused (CLOUD-2858).
#
# THE GATE DECIDES, NEVER A HUMAN (owner ruling, 2026-11-23). A dispatch was
# granted only when its message carried two receipts, a passing `batten lint
# brief` and the owner's answer to a question naming the message's digest, so
# every follow-up cost the owner a question. The ruling that every call the
# engine allows is granted made that approval a contradiction. The brief
# schema is now a deny gate on the call itself: a message the lint refuses is
# refused here with its findings, and a message it passes has no finding and is
# granted by `auto-mode-is-preapproved` like any allowed call.
#
# THE FACT IS THE ENGINE'S. `dispatch-brief` is the lint's report over the
# call's own message, computed in process at pre-tool for `create_session` and
# `send_message` alone: `clean`, and the `missing` and `unrunnable` section ids.
# Ids only, never a byte of the message (rule 4), and `null` for every other
# call, which raises nothing.
#
# The deny outranks every grant, so a failing brief is refused in every mode.
#
# ITS OWN PRESET, NOT A `claude-code-cloud` MODULE, for the reason
# `claude-code-plan` is one (2ef6df8b): a module added there rides the
# consumer's existing row, named `plan write refused` after the one class that
# preset raises, and a second deny class makes that name wrong for this engine
# while a pinned release still demands it. A preset of its own is enabled by a
# row of its own, named for its one class, under every engine.
package batten.claude_code_dispatch

import rego.v1

rules contains "dispatch brief refused"

violation contains {
	"rule": "dispatch brief refused",
	"verdict": "dispatch brief refused",
	# THE SECTION IDS, never the message: `missing:<id>` for a section with no
	# label, `unrunnable:<id>` for one with no fenced command.
	"subjects": findings(input.facts["dispatch-brief"]),
} if {
	input.call.event == "pre-tool"
	input.facts["dispatch-brief"].clean == false
}

findings(report) := array.concat(
	[{"artifact": concat(":", ["missing", id])} | some id in report.missing],
	[{"artifact": concat(":", ["unrunnable", id])} | some id in report.unrunnable],
)

brief(clean, missing, unrunnable) := {"clean": clean, "missing": missing, "unrunnable": unrunnable}

test_a_failing_brief_is_refused_with_its_ids if {
	some found in violation with input as {
		"call": {"event": "pre-tool", "tool": "mcp__x__send_message"},
		"facts": {"dispatch-brief": brief(false, ["check"], [])},
	}
	found.subjects == [{"artifact": "missing:check"}]
}

test_a_passing_brief_raises_nothing if {
	count(violation) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "mcp__x__send_message"},
		"facts": {"dispatch-brief": brief(true, [], [])},
	}
}

test_a_call_that_is_not_a_dispatch_raises_nothing if {
	count(violation) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "Bash"},
		"facts": {"dispatch-brief": null},
	}
}
