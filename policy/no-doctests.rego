# METADATA
# description: |
#   No runnable doctest exists, because this workspace's test runner does not run
#   them — CLOUD-813, ported from `mise-tasks/no-doctests.sh` under CLOUD-843.
#
#   `test:cargo` runs `cargo nextest run`, and nextest does not execute
#   doctests. That is the scheduler's scope rather than a defect, but it means
#   the runner swap moved a class of test from "run on every PR" to "run
#   nowhere". What made the swap safe was a measurement: the class was EMPTY. An
#   empty class is not a stable property, so the emptiness is asserted rather
#   than assumed — the moment someone writes a doc example it is dead code that
#   reads like a tested one, which is the worst shape a test can take because a
#   reader trusts it precisely for being executable.
#
#   A doctest is not forbidden. This forces a decision: run doctests as their own
#   step, or mark the fence `text`/`ignore`. Either is fine; neither is silence.
#
#   TEXT, NOT A COMPILE. The obvious predicate is `cargo test --doc` reporting
#   zero, and it costs a full workspace build to answer a question the source
#   already answers. This reads the fences — which is also what lets it be a
#   `read`-effect rule at all rather than a spawn.
#
#   THE PARITY IS THE PORT'S ONE PIECE OF REAL WORK. The shell toggled an `open`
#   flag as it walked each file, because a CLOSING fence carries no info string
#   and would otherwise read as an unattributed — therefore runnable — opening
#   one. Rego has no walk state, so the same decision is expressed as parity: a
#   fence is an opener exactly when an even number of fences precede it in that
#   file. Same rule, no mutable flag.
#
#   `no_run` COUNTS AS NON-RUNNING and that is deliberate: it still compiles
#   under `cargo test --doc`, and it is still not run by nextest, so the gate
#   stays about EXECUTION rather than about compilation.
#
#   Output is a pointer, never the payload (non-negotiable rule 4): `path:line`
#   and the fence's info string, never the example.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.no_doctests

import rego.v1

rules contains "no-doctests"

# A doc-comment line's text, with the marker stripped. Undefined for any line
# that is not a doc comment, which is what keeps the fence scan inside them.
doc_body(line) := body if {
	trimmed := trim_left(line, " \t")
	startswith(trimmed, "///")
	body := trim_left(trim_left(trimmed, "/"), " \t")
}

doc_body(line) := body if {
	trimmed := trim_left(line, " \t")
	startswith(trimmed, "//!")
	body := trim_left(trim_space(substring(trimmed, 3, -1)), " \t")
}

# Is this doc-comment body a fence, and what does it declare?
fence_info(body) := info if {
	startswith(body, "```")
	info := trim_space(substring(body, 3, -1))
}

fence_info(body) := info if {
	startswith(body, "~~~")
	info := trim_space(substring(body, 3, -1))
}

# Every fence line in every scanned file, as [path, index, info].
fences contains [path, index, info] if {
	some path, file_lines in input.tree.lines
	some index, line in file_lines
	info := fence_info(doc_body(line))
}

# How many fences precede this one in the same file.
preceding(path, index) := count([other |
	some [p, other, _] in fences
	p == path
	other < index
])

# An OPENER is a fence with an even number of fences before it in its file. The
# shell's toggle, written as the parity it always was.
openers contains [path, index, info] if {
	some [path, index, info] in fences
	preceding(path, index) % 2 == 0
}

# The info strings rustdoc will not RUN. `no_run` is here for the reason the
# header gives: it compiles and is still not executed.
non_running := {"text", "ignore", "compile_fail", "no_run"}

runnable contains [path, index] if {
	some [path, index, info] in openers
	not declares_non_running(info)
}

# An info string is a comma- or space-separated attribute list, so membership is
# over its fields rather than over the whole string: ` rust,ignore ` names
# `ignore`, and a substring test would also match `ignored_thing`.
declares_non_running(info) if {
	some field in split(replace(info, ",", " "), " ")
	trim_space(field) in non_running
}

violation contains {
	"rule": "no-doctests",
	"verdict": "test state early",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some [path, index] in runnable
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE — the parity rule and the attribute list. They cannot
# pin that the ENGINE hands this module the crate sources at all, which is the
# anti-vacuity half the shell spent an explicit arm on and which a fabricated
# input would assert into existence. `crates/batten/tests/it/no_doctests.rs` is
# that tier.

scan(ls) := {"tree": {"lines": {"crates/demo/src/lib.rs": ls}}}

test_an_unattributed_fence_is_runnable if {
	some v in violation with input as scan(["/// ```", "/// let x = 1;", "/// ```"])
	v.verdict == "test state early"
}

test_a_text_fence_is_not_a_doctest if {
	count(violation) == 0 with input as scan(["/// ```text", "/// not rust", "/// ```"])
}

test_every_non_running_attribute_is_honoured if {
	count(violation) == 0 with input as scan([
		"/// ```ignore",
		"/// ```",
		"/// ```compile_fail",
		"/// ```",
		"/// ```no_run",
		"/// ```",
	])
}

# THE PARITY CASE. Three fences: opener, closer, opener. The middle one carries
# no info string, and a reader without the parity rule counts it as a second
# unattributed opener — reporting two findings where there is one.
test_a_closing_fence_is_not_an_unattributed_opener if {
	found := violation with input as scan([
		"/// ```text",
		"/// safe",
		"/// ```",
	])
	count(found) == 0
}

test_a_fence_outside_a_doc_comment_is_not_a_doctest if {
	count(violation) == 0 with input as scan(["// ```", "let x = 1;", "// ```"])
}

test_an_attribute_list_names_its_fields if {
	count(violation) == 0 with input as scan(["/// ```rust,ignore", "/// x", "/// ```"])
}

#MUTANT-SUITE crates/batten/tests/it/no_doctests.rs
#MUTANT doctest-parity-unread|s@preceding(path, index) % 2 == 0@true@|a_closing_fence_is_not_read_as_an_unattributed_opener
#MUTANT doctest-attribute-unread|s@not declares_non_running(info)@true@|a_text_fence_is_not_a_doctest_over_the_binary
