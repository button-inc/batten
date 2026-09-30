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
#   WHY hk'S OWN PLANS RATHER THAN A DERIVATION FROM `hk.pkl`. The tier is
#   derived from hk's OWN plan — a step hk excludes for a missing profile when the
#   profile is off is, by construction, a step that declared it. Re-deriving that
#   from `hk.pkl`'s text would be a second authority over hk's profile resolution,
#   and it would go stale in the silent direction the moment hk changed its
#   ordering. Two `[[rule.plan]]` rows acquire both plans at the boundary
#   (`Fact::Plan`): `gate` is `check` as committed, `gate-fast` is `check` with
#   `--profile '!slow'`. The join a producer's `jq` used to make is here, where it
#   is a decision (CLOUD-843, retiring the `hk-plan` record).
#
#   THREE ANSWERS, AND THE EMPTY ONE IS A FINDING HERE. ABSENT is could-not-look
#   (either plan could not be acquired). A tier that is EMPTY while both plans were
#   acquired has EVAPORATED — no step declares the profile any more — which the
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

rules contains "hook declare other"

# The status a step selected by the `check` hook carries in hk's plan.
included := "included"

# The hook file whose invocation line decides what a commit pays.
hook := ".claude/hooks/git-hook.sh"

# The status a step the fast plan skips for its missing profile carries, and the
# runner's KIND token for that reason — never its prose.
skipped := "skipped"

profile_exclude := "profile_exclude"

# The two acquired plans, guarded. `null` is a hard evaluation FAULT under
# `some .. in` rather than a silent miss, and a plan that could not be acquired is
# `null` or absent.
#
# The local is NOT named `acquired`: that is the package rule below, and regorus
# resolves the local against the rule, which left every plan undefined and the
# whole module silent.
plan(id) := found if {
	is_object(input.tree.plan)
	found := input.tree.plan[id]
	is_object(found)
}

acquired if {
	plan("gate")
	plan("gate-fast")
}

# The slow tier: every step the fast plan skips because its profile is off.
#
# ANY REASON, NOT THE FIRST. `reasonKind` is the reason the runner acted on;
# whether a step DECLARED the tier is a membership question every reason answers,
# which is how the retired `jq` join asked it
# (`any(.reasons[]?; .kind == "profile_exclude")`). Reading the first alone would
# drop a step whose runner listed another reason ahead of the profile out of the
# tier, and nothing would say so.
tier contains plan_step.name if {
	acquired
	some plan_step in plan("gate-fast").steps
	plan_step.status == skipped
	profile_exclude in plan_step.reasonKinds
}

selected contains plan_step.name if {
	some plan_step in plan("gate").steps
	plan_step.status == included
}

# A slow-tier step that `check` does not select.
#
# THE FALSE GREEN THIS EXISTS FOR. The step still declares the profile, so the
# pre-commit path still skips it — and nothing else notices that `check` stopped
# selecting it, because a skipped step and a passing one look identical in a
# summary.
stray contains name if {
	some name in tier
	not name in selected
}

violation contains {
	"rule": "hook declare other",
	"verdict": "step declare missing",
	"subjects": [{"count": count(stray)}],
} if {
	count(stray) > 0
}

# THE TIER EVAPORATED. Both plans acquired and no step declared the profile, so
# there is nothing left for the rule above to judge and every one of its
# assertions would pass over an empty set.
#
# Told apart from ABSENT by `acquired`: a plan that could not be taken never binds
# it, and that is could-not-look rather than a finding.
#
# NEGATED, NEVER COUNTED: a partial set with no members is UNDEFINED under
# regorus rather than `{}`, so `count(tier) == 0` was undefined in exactly the
# case this arm exists for and the evaporated tier read as clean.
tier_declared if {
	some _ in tier
}

violation contains {
	"rule": "hook declare other",
	"verdict": "tier list empty",
	"subjects": [{"artifact": "gate-fast"}],
} if {
	acquired
	not tier_declared
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
	"rule": "hook declare other",
	"verdict": "hook declare missing",
	"subjects": [{"path": hook}],
} if {
	count(invocations) > 0
	count(flagged) == 0
}

#MUTANT-SUITE crates/batten/tests/it/hook_profile.rs
#MUTANT tier-unread|s@^\tnot name in selected$@\tfalse@|a_slow_step_the_check_plan_does_not_select_is_refused

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.plan` at all — a `with input as` case fabricates the very shape the
# engine may be unable to produce (CLOUD-845), and here it would fabricate the
# acquisition the tier turns on. `crates/batten/tests/it/hook_profile.rs` is that
# tier.

kinds_of(kind) := [] if kind == null

kinds_of(kind) := [kind] if kind != null

step(name, status, kind) := {"name": name, "status": status, "reasonKind": kind, "reasonKinds": kinds_of(kind), "orderIndex": 0, "parallelGroupId": "0", "fileCount": 0}

# `slow` maps each slow-tier step to its status under `check`; `fast` is one
# ordinary step both plans include.
planned(slow) := {"tree": {
	"plan": {
		"gate": {"steps": array.concat(
			[step(name, status, null) | some name, status in slow],
			[step("fmt", "included", null)],
		)},
		"gate-fast": {"steps": array.concat(
			[step(name, "skipped", "profile_exclude") | some name, _ in slow],
			[step("fmt", "included", null)],
		)},
	},
	"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
}}

test_every_slow_step_selected_by_check_is_clean if {
	count(violation) == 0 with input as planned({"test": "included", "batten-check": "included"})
}

test_a_slow_step_missing_from_check_is_refused if {
	some v in violation with input as planned({"test": "included", "batten-check": "skipped"})
	v.verdict == "step declare missing"
}

# A STEP SKIPPED IN THE FAST PLAN FOR ANOTHER REASON is not in the tier: a glob
# miss is not a profile.
test_a_step_skipped_for_a_glob_miss_is_not_in_the_tier if {
	glob := {"tree": {
		"plan": {
			"gate": {"steps": [step("docs", "skipped", "no_files")]},
			"gate-fast": {"steps": [step("docs", "skipped", "no_files"), step("test", "skipped", "profile_exclude")]},
		},
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
	}}
	violation == {{"rule": "hook declare other", "verdict": "step declare missing", "subjects": [{"count": 1}]}} with input as glob
}

# A STEP WHOSE PROFILE IS NOT ITS FIRST REASON is still in the tier, and still a
# stray when `check` does not select it.
test_a_step_whose_profile_is_not_its_first_reason_is_in_the_tier if {
	late := object.union(step("late", "skipped", "no_files"), {"reasonKinds": ["no_files", "profile_exclude"]})
	listed := {"tree": {
		"plan": {
			"gate": {"steps": [step("late", "skipped", "no_files")]},
			"gate-fast": {"steps": [late]},
		},
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
	}}
	violation == {{"rule": "hook declare other", "verdict": "step declare missing", "subjects": [{"count": 1}]}} with input as listed
}

# An evaporated tier is a FINDING, not a clean read — the anti-vacuity arm.
test_an_empty_plan_is_refused if {
	some v in violation with input as planned({})
	v.verdict == "tier list empty"
}

# COULD-NOT-LOOK. A plan that could not be acquired is not a tier that
# evaporated, and collapsing them would refuse on every checkout without hk.
test_no_plan_is_not_refused if {
	count(violation) == 0 with input as {"tree": {
		"plan": {"gate": null},
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit --profile '!slow'"]},
	}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"plan": null, "lines": {".claude/hooks/git-hook.sh": []}}}
}

test_a_hook_that_stopped_passing_the_flag_is_refused if {
	some v in violation with input as {"tree": {
		"plan": null,
		"lines": {".claude/hooks/git-hook.sh": ["hk run pre-commit"]},
	}}
	v.verdict == "hook declare missing"
}

# The measured case: the flag is gone from the COMMAND and still present in the
# comment above it, which is what left the shell gate green.
test_the_flag_in_a_comment_alone_does_not_satisfy_it if {
	some v in violation with input as {"tree": {
		"plan": null,
		"lines": {".claude/hooks/git-hook.sh": ["# we pass --profile '!slow' here", "hk run pre-commit"]},
	}}
	v.verdict == "hook declare missing"
}
