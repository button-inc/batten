# METADATA
# description: |
#   The successor for `hook-profile-check` (CLOUD-509, retired under CLOUD-1199).
#
#   Six steps dominate the hk gate, so they declare `profiles = List("slow")`,
#   `hk.pkl` enables `slow` at the config layer, and `.claude/hooks/git-hook.sh`
#   disables it with `--profile '!slow'` for the one path paid per commit. That
#   split can fail two ways and THEY ARE NOT SYMMETRIC:
#
#     * the slow tier stops being skipped at pre-commit — commits get slow again.
#       Annoying, loud, self-correcting. Not a correctness problem.
#     * the slow tier stops running under `check` — clippy, the test suite and
#       `batten-check` silently vanish from `mise run ci`, `verify` and CI. Green
#       everywhere, nothing tested.
#
#   The second is the one that must be impossible, so `profiled-step-not-in-check`
#   is the load-bearing predicate and the mutation below sits on it.
#
#   WHY A RECORD RATHER THAN A DERIVATION FROM `hk.pkl`. The tier is derived from
#   hk's OWN plan — a step hk excludes for a missing profile when the profile is
#   off is, by construction, a step that declared it. Re-deriving that from
#   `hk.pkl`'s text would be a second authority over hk's profile resolution, and
#   it would go stale in the silent direction the moment hk changed its ordering.
#   The plan is a third-party tool's answer over a pinned input, which is exactly
#   the `tool-verdict` triple, so the producer records it and this adjudicates.
#
#   THREE ANSWERS, AND THE EMPTY ONE IS A FINDING HERE. This module reads the
#   record's three states differently from `validator-verdict-clean`, deliberately:
#   ABSENT is could-not-look (nothing has planned this tree). PRESENT AND EMPTY is
#   the tier having EVAPORATED — no step declares the profile any more — which the
#   shell gate refused as its anti-vacuity arm and which must stay a refusal, since
#   every per-step assertion below would otherwise pass over an empty set.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.hook_profile

import rego.v1

rules contains "hook-profile"

# The status a step selected by the `check` hook carries in hk's plan.
included := "included"

# The hook file whose invocation line decides what a commit pays.
hook := ".claude/hooks/git-hook.sh"

# The recorded plan, guarded. `null` is a hard evaluation FAULT under `some .. in`
# rather than a silent miss, and an id nothing recorded is absent from the map.
plan := verdict if {
	is_object(input.tree["tool-verdict"])
	verdict := input.tree["tool-verdict"]["hk-plan"]
}

# A slow-tier step that `check` does not select.
#
# THE FALSE GREEN THIS EXISTS FOR. The step still declares the profile, so the
# pre-commit path still skips it — and nothing else notices that `check` stopped
# selecting it, because a skipped step and a passing one look identical in a
# summary.
stray contains name if {
	some name, status in plan
	status != included
}

violation contains {
	"rule": "hook-profile",
	"verdict": "step declare missing",
	"subjects": [{"count": count(stray)}],
} if {
	count(stray) > 0
}

# THE TIER EVAPORATED. Present and empty: something planned this tree and no step
# declared the profile, so there is nothing left for the rule above to judge and
# every one of its assertions would pass over an empty set.
#
# Told apart from ABSENT by `is_object` plus the count: an id nothing recorded
# never binds `plan` at all, and that is could-not-look rather than a finding.
violation contains {
	"rule": "hook-profile",
	"verdict": "tier list empty",
	"subjects": [{"artifact": "hk-plan"}],
} if {
	is_object(plan)
	count(plan) == 0
}

# THE ECONOMY HALF, and it is a property of a FILE rather than of a plan.
#
# NON-COMMENT LINES THAT ACTUALLY RUN THE HOOK, which is the whole subtlety and
# was measured: deleting the flag from the command left the shell gate green,
# because the explanatory comment above it still spelled it.
invocations contains line if {
	some line in input.tree.lines[hook]
	contains(line, "hk run")
	not startswith(trim_space(line), "#")
}

flagged contains line if {
	some line in invocations
	contains(line, "--profile")
	contains(line, "!slow")
}

violation contains {
	"rule": "hook-profile",
	"verdict": "hook declare missing",
	"subjects": [{"path": hook}],
} if {
	count(invocations) > 0
	count(flagged) == 0
}

#MUTANT-EXEMPT CLOUD-931|no `tests/hook-profile.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `shell add refused` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/hook_profile.rs`, neither of which is what the mutation runner drives. The mutation this row WOULD declare is on `status != included` — the load-bearing conjunct, since a slow step the `check` hook does not select is the false green the whole rule exists for — and `a_slow_step_missing_from_check_is_refused` plus its anti-vacuity mirror `a_wired_split_is_clean` are what stand in for it. CLOUD-1267 owns closing this for the Rego layer as a whole

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree["tool-verdict"]["hk-plan"]` at all — a `with input as` case
# fabricates the very shape the engine may be unable to produce (CLOUD-845), and
# here it would fabricate the keying the record turns on.
# `crates/batten/tests/hook_profile.rs` is that tier.

planned(steps) := {"tree": {
	"tool-verdict": {"hk-plan": steps},
	"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
}}

test_every_slow_step_selected_by_check_is_clean if {
	count(violation) == 0 with input as planned({"test": "included", "batten-check": "included"})
}

test_a_slow_step_missing_from_check_is_refused if {
	some v in violation with input as planned({"test": "included", "batten-check": "skipped"})
	v.verdict == "step declare missing"
}

# An evaporated tier is a FINDING, not a clean read — the anti-vacuity arm.
test_an_empty_plan_is_refused if {
	some v in violation with input as planned({})
	v.verdict == "tier list empty"
}

# COULD-NOT-LOOK. Nothing has planned this tree, which is not the same as a tier
# that evaporated, and collapsing them would refuse on every fresh checkout.
test_no_record_is_not_refused if {
	count(violation) == 0 with input as {"tree": {
		"tool-verdict": {},
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
	}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": null, "lines": {".claude/hooks/git-hook.sh": []}}}
}

test_a_hook_that_stopped_passing_the_flag_is_refused if {
	some v in violation with input as {"tree": {
		"tool-verdict": {"hk-plan": {"test": "included"}},
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit"]},
	}}
	v.verdict == "hook declare missing"
}

# The measured case: the flag is gone from the COMMAND and still present in the
# comment above it, which is what left the shell gate green.
test_the_flag_in_a_comment_alone_does_not_satisfy_it if {
	some v in violation with input as {"tree": {
		"tool-verdict": {"hk-plan": {"test": "included"}},
		"lines": {".claude/hooks/git-hook.sh": ["# we pass --profile '!slow' here", "hk run pre-commit"]},
	}}
	v.verdict == "hook declare missing"
}
