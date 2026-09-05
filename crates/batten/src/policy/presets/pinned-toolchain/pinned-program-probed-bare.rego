#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT probe-mediation-unread|s@^\tentry.name in probe_verbs$@\tfalse@|every_shipped_preset_passes_its_own_suite
# A pinned toolchain: asking the bare PATH about a pinned program answers about
# the wrong toolchain, and the empty answer reads as "not installed here".
#
# THE FAILURE DIRECTION IS THE OPPOSITE OF THE SIBLING RULE'S, which is why that
# rule does not cover this and why folding them together would make one rule's
# anti-vacuity case the other's positive case. `pinned-program-via-the-pin` is
# about EXECUTION: you ran the pinned name and got a different build, so
# something wrong happened. This is about a PRESENCE ANSWER: nothing ran, nothing
# broke, and the caller concluded a capability does not exist.
#
# A gate watching only which PROGRAM ran cannot see it: the pinned name is an
# ARGUMENT of the probe, never the thing invoked. `programs[_].arguments` is what
# makes it visible (CLOUD-1382) — the same entry, read one field further.
#
# **SCOPED BY MEASUREMENT, NOT BY THE VERB LIST THE ROW PROPOSED.** CLOUD-1256
# named `command -v` as the motivating case on the premise that the program run
# there is `command`. Measured against this engine, that premise is overtaken: the
# boundary LOOKS THROUGH `command`, so `command -v gh` resolves an effective
# program of `gh` and the sibling rule already speaks. Re-measured over the
# shipped binary, one pinned program, four spellings:
#
#     command -v gh          -> pin reach loose   (the sibling already fires)
#     command gh --version   -> pin reach loose   (an invocation, correctly)
#     which gh               -> SILENT
#     type gh                -> SILENT
#
# So this rule covers `which` and `type` and deliberately NOT `command`. Adding
# `command` would double-report one call under two classes, which is the thing the
# disjointness case below exists to police — and would have been invisible had the
# positive case asserted only that the program was named.
#
# Measured 2026-08-31 in this repository's own session: `command -v gh` answered
# empty, that was read as the pinned route having failed, and PR create, PR close
# and a branch deletion all went to the documented last-resort path — where the
# deletion hit `HTTP 403`, because that credential can push a branch and not
# delete a ref. `gh api -X DELETE …` through the pin then succeeded first try. One
# false-negative probe, three operations misrouted, one hard failure.
#
# WARN RATHER THAN DENY, and the choice is load-bearing. The probe is not wrong,
# it is under-scoped: `command -v` correctly reports what the current PATH
# resolves. It is a correct answer to a question the caller did not mean to ask,
# which is the shape a warning fixes and a refusal does not — a deny here would
# refuse a correct shell habit.
#
# NAMES NO TOOL, NO TASK AND NO PIN (non-negotiable rule 1). The probe verbs are
# POSIX shell; which programs the pin provides is a fact the boundary resolves for
# whatever project is being judged.
package batten.pinned_toolchain_probe

import rego.v1

rules contains "pinned-program-probed-bare"

# The programs this project's pin provides.
#
# `null` — could-not-look — leaves this set empty, so the predicate below cannot
# hold and the preset is silent. The only safe direction for a fact that names
# every program in a project.
provided contains name if {
	names := input.facts["pinned-programs"]
	is_array(names)
	some name in names
}

# The probe verbs this rule owns, MEASURED rather than recalled from POSIX.
#
# `command` is absent BY MEASUREMENT — see the header: the boundary looks through
# it, so the sibling rule already speaks for every `command` spelling and adding
# it here would double-report. `hash`, `whereis` and `whence` are absent for a
# different reason: a command-position count over this repository's own gate
# programs and harness config finds `hash` **0**, `type -p`/`type -t` **0**,
# `whereis`/`whence` **0**. A first draft carried all three from recall, where
# each would have been a conjunct nothing exercises. Add a verb when a call site
# demands it.
#
# `which` and `type` answer about presence and nothing else, so neither needs a
# flag to tell a probe from an invocation the way `command` would.
#
# WRITTEN INLINE RATHER THAN AS A `[[pattern]]` ROW, which is the preset rule and
# not a shortcut: a preset reaches a consumer who wrote no rows, so
# `data.batten.patterns["x"]` resolves to undefined there, Rego reads undefined as
# *does not hold*, and the rule would load clean while deciding nothing.
# CLOUD-1161's `ci-hygiene` preset shipped two dead predicates exactly that way.
probe_verbs := {"which", "type"}

# The pinned program a probe names, if any.
#
# ON THE PROGRAM, NOT ON THE FIRST WORD (CLOUD-1382). This read
# `segment.words[0] in probe_verbs`, which is one construct short of the program:
# `(which gh)`, `time which gh` and `{ which gh; }` each put something else at
# index 0, and each still runs the probe. Measured on `trunk-based`'s sibling
# preset, six such tokens at exit 0.
#
# READ OFF `programs`, the argv the engine already parsed — never a `split` of
# `input.call.command`. A second parser is a second authority over one call,
# measured at CLOUD-857 where a module anchored on the first word of the whole
# line denied `git push --force` and allowed `cd /tmp && git push --force`.
#
# `arguments` rather than the segment's words, so the pinned name has to be
# something THIS probe was handed: a probe of one program and an invocation of
# another on the same line are two facts, and reading the whole segment would
# merge them.
probed contains name if {
	some entry in input.call.programs
	entry.name in probe_verbs
	some name in entry.arguments
	provided[name]
}

# An unmediated presence probe for a program the pin provides.
#
# `not mediated` IS THE LOAD-BEARING CONJUNCT and its absence made the first draft
# of this rule net-negative. Measured 2026-08-31: bare `command -v gh` → not
# found; the same probe inside the pin's composed environment → the pinned path.
# INSIDE THE PIN THE PROBE IS CORRECT AND IDIOMATIC, and this repository has four
# live in-task sites that are every one of them right. Without this conjunct the
# rule scores four false positives and zero true positives in its own consumer.
#
# The mediation reading is the BOUNDARY's, taken off `programs` rather than
# re-derived here, for the same reason the sibling rule takes it there.
violation contains {
	"rule": "pinned-program-probed-bare",
	"verdict": "pin probe bare",
	"subjects": [{"artifact": name}],
} if {
	some name in probed
	not mediated_call
}

# Whether the boundary read this call as running through the pin.
#
# One entry is enough: a mediated call composes the pin's environment for
# everything in it, which is exactly why an in-pin probe is correct.
mediated_call if {
	some entry in input.call.programs
	entry.mediated
}

# --- cases ---------------------------------------------------------------

# THE GRAMMAR CASE (CLOUD-1382), as the boundary now resolves it: the caller
# wrote `time which gh`, `time` is grammar the walk steps past, and the entry
# names the probe with its own argument.
test_a_grammar_token_does_not_hide_the_probe if {
	some v in violation with input as {
		"call": {
			"command": "time which gh",
			"segments": [{"words": ["time", "which", "gh"]}],
			"programs": [{"program": "which", "name": "which", "arguments": ["gh"], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
	v.subjects[0].artifact == "gh"
}

# AND THE PINNED NAME MUST BE THIS PROBE'S ARGUMENT. A probe of one program
# beside an invocation of the pinned one is two facts, and reading the whole
# segment would have merged them into a finding nobody can act on.
test_a_pinned_name_belonging_to_another_program_is_not_probed if {
	count(violation) == 0 with input as {
		"call": {
			"command": "which curl && gh pr list",
			"segments": [
				{"words": ["which", "curl"]},
				{"words": ["gh", "pr", "list"]},
			],
			"programs": [
				{"program": "which", "name": "which", "arguments": ["curl"], "mediated": false},
				{"program": "gh", "name": "gh", "arguments": ["pr", "list"], "mediated": false},
			],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}

test_an_unmediated_probe_for_a_pinned_program_is_reported if {
	some v in violation with input as {
		"call": {
			"command": "which gh",
			"segments": [{"words": ["which", "gh"]}],
			"programs": [{"program": "which", "name": "which", "arguments": ["gh"], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh", "jq"]},
	}
	v.subjects[0].artifact == "gh"
}

test_type_is_a_probe_too if {
	some v in violation with input as {
		"call": {
			"command": "type gh",
			"segments": [{"words": ["type", "gh"]}],
			"programs": [{"program": "type", "name": "type", "arguments": ["gh"], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
	v.subjects[0].artifact == "gh"
}

# `command` IS NOT THIS RULE'S VERB, and the case says so rather than leaving it
# to the verb set. The boundary looks through `command`, so the sibling rule
# already reports every spelling of it — firing here too would put one call under
# two classes with two different remedies.
test_command_is_left_to_the_sibling_rule if {
	count(violation) == 0 with input as {
		"call": {
			"command": "command -v gh",
			"segments": [{"words": ["command", "-v", "gh"]}],
			"programs": [{"program": "gh", "name": "gh", "arguments": [], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}

# THE ANTI-VACUITY MIRROR. Without it the cases above are satisfied by a rule that
# flags every probe there is, and probing an unpinned program is ordinary.
test_a_probe_for_an_unpinned_program_is_not_reported if {
	count(violation) == 0 with input as {
		"call": {
			"command": "which curl",
			"segments": [{"words": ["which", "curl"]}],
			"programs": [{"program": "which", "name": "which", "arguments": ["curl"], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}

# THE CASE WHOSE ABSENCE MADE THE FIRST DRAFT NET-NEGATIVE. Inside the pin the
# probe is correct, and this stands for the four live in-repo sites.
test_a_mediated_probe_is_not_reported if {
	count(violation) == 0 with input as {
		"call": {
			"command": "mise exec -- bash -c \"which gh\"",
			"segments": [{"words": ["mise", "exec", "--", "bash", "-c", "which gh"]}],
			"programs": [{"program": "bash", "name": "bash", "arguments": ["-c", "which gh"], "mediated": true}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}

# The two rules stay DISJOINT: a bare invocation is the sibling's finding and must
# not be double-reported here.
test_a_bare_invocation_is_not_this_rules_finding if {
	count(violation) == 0 with input as {
		"call": {
			"command": "gh pr list",
			"segments": [{"words": ["gh", "pr", "list"]}],
			"programs": [{"program": "gh", "name": "gh", "arguments": ["pr", "list"], "mediated": false}],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}

# COULD-NOT-LOOK IS SILENT, never a refusal.
test_an_unresolved_fact_refuses_nothing if {
	count(violation) == 0 with input as {
		"call": {
			"command": "which gh",
			"segments": [{"words": ["which", "gh"]}],
			"programs": [{"program": "which", "name": "which", "arguments": ["gh"], "mediated": false}],
		},
		"facts": {"pinned-programs": null},
	}
}

# A later segment is judged too, so a probe in the second half of a pipeline is as
# visible as one in the first — the shape `module-tested-bare-only` asks every
# mediated module for.
test_a_later_segment_is_judged_too if {
	some v in violation with input as {
		"call": {
			"command": "echo hi && which gh",
			"segments": [
				{"words": ["echo", "hi"]},
				{"words": ["which", "gh"]},
			],
			"programs": [
				{"program": "echo", "name": "echo", "arguments": ["hi"], "mediated": false},
				{"program": "which", "name": "which", "arguments": ["gh"], "mediated": false},
			],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
	v.subjects[0].artifact == "gh"
}

# THE STATED BOUND, PINNED AS A CASE (CLOUD-1256's §2). `hook::segments` has no
# case for `$(` or a backtick, so a probe nested in a command substitution arrives
# as one quoted word and is INVISIBLE here. Measured over this repository's own
# call sites, the nested form outnumbers the direct one — so this rule catches the
# form that bit the session and not the form the tree mostly writes.
#
# Asserted rather than left implicit: it documents the hole at the tier that would
# notice if a later tokenizer change silently closed it. Widening `segments` to
# recurse into `$(…)` would change every landed `shape` and `pipeline` verdict and
# is a different row.
test_a_probe_nested_in_a_substitution_is_not_seen if {
	count(violation) == 0 with input as {
		"call": {
			"command": "binary=\"$(which gh)\"",
			"segments": [{"words": ["binary=$(which gh)"]}],
			# NO ENTRY AT ALL, which is the engine's own answer rather than a
			# convenience: the one word is an environment assignment, so
			# `effective_program` walks past it and finds nothing to run.
			"programs": [],
		},
		"facts": {"pinned-programs": ["gh"]},
	}
}
