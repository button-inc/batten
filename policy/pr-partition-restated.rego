# METADATA
# description: |
#   ONE PR PER BRANCH IS AGENTS.md's RULE, AND NOTHING ELSE MAY SAY OTHERWISE.
#
#   AGENTS.md carries the workflow contract's branch clause -- one commit one issue,
#   one branch many rows, and a single pull request over all of them. This module
#   refuses a SECOND statement of that decision anywhere else in the tree, in the
#   direction that contradicts it: prose claiming a unit lands through a pull
#   request of its own.
#
#   WHY A GATE AND NOT A CONVENTION. Measured 2026-09-02, on this branch, by the
#   agent that wrote this file. A row's comment in `policy/harness-wiring.rego`
#   quoted ONE tracker issue's own §1 -- that issue's units each land separately --
#   as a sentence of ordinary normative prose, with no marker separating a quoted
#   local decision from the file's own binding claims. A planning turn read that
#   line, adopted it as repository convention, and produced a plan partitioned into
#   eight pull requests. The contradicted rule had been loaded in the same turn.
#
#   THE PROSE WAS THE WHOLE SURFACE, which is what makes a text predicate the right
#   instrument here rather than an approximation of one: a scan of the tree found
#   the phrase family exactly once outside AGENTS.md. Removing that line and
#   refusing its return is the complete fix for the measured instance.
#
#   THIS FILE MAY NOT SPELL THE PHRASE IT MATCHES. The pattern lives in the
#   `[[pattern]]` registry and is read from `data.batten.patterns`, so a comment
#   quoting it here would trip the module over its own explanation and the only
#   repairs are an exemption or a deleted rule -- both worse than the duplication
#   the registry exists to stop. `mise.toml`'s inline-body ratchet records the same
#   constraint for its own case, in those words. Name the shape, never the string.
#
#   THE PATTERN DISCRIMINATES AND THAT WAS MEASURED TOO. Four tracked files say a
#   change landed in a pull request of its own, meaning the ordinary thing --
#   release-plz bumping a version, a guard refusing the branch that added it -- and
#   every one of them is legitimate. A predicate keyed on the possessive alone
#   refuses all four. So the registry row names the PARTITION claim: a unit landing
#   that way, or a per-unit rate. The four survive; the one that produced this
#   module does not.
#
#   WHAT THIS DOES NOT REACH, stated rather than left to be found. It catches a
#   restatement of THIS decision in THIS phrase family, and nothing else. It is not
#   a general "prose that contradicts a binding rule" detector, and no text
#   predicate is: `.claude/rules/scanning.md` records what claiming the ambitious
#   guarantee costs when only the modest one is held. The general half is
#   `a-spawn-carries-the-workflow-contract`, which binds the prompt of a planning
#   spawn rather than the prose it may read.
#
#   AGENTS.md IS NOT GLOBBED, so this module carries no exemption at all. The rule's
#   `line_sources` name where binding prose is written in this repository; the file
#   that OWNS the decision is not among them, and a file no glob names is unread
#   rather than clean. That is a bound rather than a hole, and it is the reason the
#   `[[rule]]` row's globs are the declaration a reviewer checks.
#
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.pr_partition_restated

import rego.v1

rules contains "pr-partition-restated"

# A line of declared prose asserting the partition AGENTS.md refuses.
#
# POINTER-ONLY (non-negotiable rule 4): the path and the line, never the line's
# text. A finding that echoed the sentence would restate the claim it refuses,
# and would itself be a tracked copy of the phrase the moment anyone pasted the
# report into the tree.
violation contains {
	"rule": "pr-partition-restated",
	"verdict": "prose state other",
	"subjects": [{"path": path, "line": number}],
} if {
	some path, lines in input.tree.lines
	some index, line in lines
	regex.match(data.batten.patterns["pr-partition-prose"], line)
	number := index + 1
}

# COULD NOT LOOK IS NOT CLEAN, and `unreadable` is the only cause reachable here.
#
# The asymmetry is `harness-wiring`'s and it is load-bearing for the same reason:
# a glob matching no file on some checkout is the ordinary case, and firing on
# absence would redden a consumer for a state nobody caused. A declared source
# that EXISTS and could not be read is a file this module reported green over
# without opening.
#
# WHY NOT `unparsed`, WHICH IS WHAT THIS CLAUSE FIRST ASKED FOR. `NotAcquired`
# splits the two on whether a parser ever saw the bytes: `unparsed` is "read as
# text and the parser refused it", while non-UTF-8 and every other I/O failure are
# `unreadable` because "nothing was ever handed to a parser". A `line_sources`
# glob reads raw lines and has no parser at all, so `unparsed` cannot occur on this
# module's own declared sources and the clause asking for it was DEAD. Naming a
# cause this rule cannot reach is also the coverage-without-walking shape the
# registry rules refuse one file over.
#
# FOUND BY THE COMPILED TIER, NOT BY READING. The load-time tier passed over the
# dead version, because a `with input as` case supplies whatever cause its author
# believed in -- which is exactly the failure `.claude/rules/policy-modules.md`
# records two live instances of, arriving on the module written to close that
# class.
violation contains {
	"rule": "pr-partition-restated",
	"verdict": "source parse refused",
	"subjects": [{"count": count(unreadable)}],
} if {
	count(unreadable) > 0
}

unreadable contains name if {
	some name, cause in input.tree.missing
	cause == "unreadable"
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.lines` for the declared globs, nor that it populates
# `input.tree.missing` with a cause -- a `with input as` case fabricates the very
# shape the engine may be unable to produce. That is
# `crates/batten/tests/it/pr_partition_restated.rs`, over the compiled binary, and
# `.claude/rules/policy-modules.md` records both live instances of the dead-gate
# class as having been found by adding exactly that tier.
#
# The fixture vocabulary is supplied the way `lock-complete` supplies its own:
# `data.batten.patterns` is CONSUMER config, so a load-time case that assumed the
# real row would pass over a registry that no longer carries it.

# THE FIXTURE VOCABULARY IS DELIBERATELY NOT THE REAL ROW'S, and the substitution
# is the only thing that keeps this tier writable at all. `line_sources` globs
# this directory, so an in-module case containing text the registry row matches
# would refuse THIS FILE, and both repairs -- an exemption for the module over its
# own subject, or a weaker row -- are the failure modes the header already names.
#
# So the split is by SUBJECT rather than by convenience. These cases pin the
# PREDICATE: that a matching line is refused, that the finding points at a
# path and a line and carries no text, that `unreadable` speaks and `absent` does
# not. What they cannot pin is the row's WORDING -- whether it discriminates the
# partition claim from the four ordinary possessive uses this tree already
# carries. That is a claim about consumer config, so it belongs in the tier that
# runs the real config through the real binary, and
# `crates/batten/tests/it/pr_partition_restated.rs` is where it lives.
#
# Two distinct tokens rather than one, so the anti-vacuity direction is walked at
# this level too: a predicate hard-coding either would pass one case and fail the
# other.
fixture_patterns := {"pr-partition-prose": `(ALPHA-PARTITION|BETA-PARTITION)`}

tree(lines) := {"tree": {"lines": lines, "missing": {}}}

test_a_line_the_row_does_not_match_is_clean if {
	count(violation) == 0 with input as tree({"policy/a.rego": ["# the branch lands by fast-forward"]})
		with data.batten.patterns as fixture_patterns
}

test_a_matching_line_is_refused if {
	some v in violation with input as tree({"policy/a.rego": ["# ALPHA-PARTITION"]})
		with data.batten.patterns as fixture_patterns
	v.verdict == "prose state other"
}

# THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by a predicate
# matching one hard-coded string, and every other spelling the row carries ships
# as coverage having never been walked.
test_the_rows_other_spelling_is_refused_too if {
	some v in violation with input as tree({".claude/rules/toolchain.md": ["BETA-PARTITION"]})
		with data.batten.patterns as fixture_patterns
	v.verdict == "prose state other"
}

test_the_finding_points_at_a_line_and_never_at_the_text if {
	some v in violation with input as tree({"policy/x.rego": ["# ordinary", "# ALPHA-PARTITION"]})
		with data.batten.patterns as fixture_patterns
	some s in v.subjects
	s.line == 2
	s.path == "policy/x.rego"
	not "text" in object.keys(s)
}

test_an_unreadable_source_is_reported_rather_than_passed if {
	some v in violation with input as {"tree": {"lines": {}, "missing": {"policy/x.rego": "unreadable"}}}
		with data.batten.patterns as fixture_patterns
	v.verdict == "source parse refused"
}

# ABSENT IS THE ORDINARY CASE and must not redden a consumer whose tree carries
# fewer of these globs.
test_an_absent_source_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"lines": {}, "missing": {"policy/x.rego": "absent"}}}
		with data.batten.patterns as fixture_patterns
}

#MUTANT-SUITE crates/batten/tests/it/pr_partition_restated.rs
#MUTANT partition-unread|s@\tregex.match\(data.batten.patterns\["pr-partition-prose"\], line\)@\tfalse@|a_matching_line_is_refused
#MUTANT missing-channel-silent|s@\tcause == "unreadable"@\tfalse@|an_unreadable_source_is_reported_rather_than_passed
