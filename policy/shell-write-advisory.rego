# The retirement gate, said at the edit instead of at `verify` (CLOUD-1131).
#
# `shell-retirement` admits one disposition for a governed shell gate — port and
# retire — and it is `scope = "tree"`, so its refusal first arrives at `mise run
# verify`, after the work is finished. Measured twice in one planning session,
# that ordering produces the wrong conclusion rather than the right one: the
# reader has a finished edit and a gate saying no, so the cheapest reading is
# "the gate is wrong" instead of "this should have been a retirement".
#
# This module changes nothing about what lands. It is `severity = "warn"`, so it
# is demoted to advice and the tree gate keeps the verdict. What it buys is the
# ORDER the refusal arrives in.
#
# WHY A `warn` AND NOT A DENY, which is the shape the row was regroomed to
# recommend. A deny at write time would have to be narrowed to a shape that is
# never part of a retirement, and the narrowing this surface can express is not
# tight enough to carry a refusal — see the governed-set bound below. An advisory
# over-approximates harmlessly; a deny over-approximating is a false positive in
# a gate every retirement in CLOUD-843's campaign passes through.
#
# THE CHANNEL IS MEASURED, NOT ASSUMED, and that is this module's precondition
# rather than a remark. `AdvisoryReach.delivered_on` omitted `PreToolUse` for its
# whole life on the claim that the event's only model-facing channel is exit 2, so
# an advisory there would be discarded or become a deny. Probed 2026-08-29 as a
# discriminating pair over one command: with the event delivered, the agent
# received the demoted text as `additionalContext` and the call was ALLOWED; with
# it absent, silence. A module emitting into a channel nobody reads is the
# sensor-with-no-reader defect CLOUD-1131 exists inside, which is why the probe
# came before this file.
#
# ONE AUTHORITY ON WHAT IS GOVERNED, BY CALL RATHER THAN BY COPY. `load` compiles
# every registered module into one bundle, so `shell_retirement`'s own predicates
# are callable here. Restating its path test would be a second authority that can
# drift from the first, which §1 forbids — and the drift would be invisible,
# because both would still pass their own suites.
#
# THE BOUND, STATED BECAUSE IT IS NOT OBVIOUS AND CANNOT BE CLOSED HERE. The
# tree gate classifies an EDIT with `governed_at_head`, which reads the file:
# `authored_shell` requires a shebang or a `#MISE description=` line, via
# `input.tree.lines[path]`. **`input.tree.*` does not exist on the mediated-call
# surface** — a key from the wrong surface reads as undefined, the body never
# holds, and the module would be a dead gate byte-identical to a clean tree
# (`rules/policy-modules.md`'s recorded class). So this module can only
# use the PATH-ONLY predicates, which are `governed_when_deleted`'s, and that set
# is WIDER than the edit-time one: it includes a `mise-tasks/` file carrying
# neither marker, which `shell-retirement` would not refuse an edit to.
#
# Over-approximating is the sanctioned direction for an advisory — it says
# "consider whether this is a retirement" about a file the tree gate would let
# pass, and the tree gate is still what decides. It would NOT be sanctioned for a
# deny, which is the other half of why this is a `warn`.

#MUTANT-SUITE crates/batten/tests/it/shell_write_advisory.rs
#MUTANT write-operation-unread|s@^\tinput.call.operation == "write"$@\tfalse@|a_write_to_a_governed_shell_path_signals_without_refusing

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: this row is `scope = "mediated_call"`, so
#   it reads `{call, facts}` and never the tree document — which is the whole of
#   why this module cannot compute `governed_at_head` and must use the path-only
#   predicates instead. The bind is what turns that from a comment into a build
#   error: a module reading `input.tree.*` here fails to type check rather than
#   evaluating to undefined and reporting green (CLOUD-845).
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.shell_write_advisory

rules contains "shell-write-at-the-edit"

# The governed set — RESTATED, and that is a defect carrying a mechanism rather
# than a preference.
#
# Calling the owning module's predicate is what §1 asks for, and it does not
# compile: `data.batten.shell_retirement.under_mise_tasks(path)` is refused with
# `could not find function`. One bundle does share one engine, so a shared VALUE
# resolves across modules — but a FUNCTION rule in another package does not, so
# `policy.rs`'s "a helper defined in one module is callable from another" holds
# for data and not for this.
#
# The two authorities can therefore drift, and the drift would be INVISIBLE: each
# module keeps passing its own suite while they disagree about what is governed.
# `crates/batten/tests/shell_write_advisory.rs` is the gate against that — it
# classifies one corpus through both surfaces and fails on any disagreement — so
# this is a mechanism rather than a comment asking the next author to remember.
#
# Kept as two arms under the same names as the module it mirrors, so a reader
# diffing them sees one shape rather than two spellings of one idea.
governed(path) if under_mise_tasks(path)

governed(path) if is_bats(path)

under_mise_tasks(path) if {
	startswith(path, "mise-tasks/")
	not endswith(path, ".py")
	not endswith(path, ".tsv")
}

is_bats(path) if {
	startswith(path, "tests/")
	endswith(path, ".bats")
}

# A write whose target the retirement gate governs.
#
# `is_string` IS LOAD-BEARING AND NOT DEFENSIVE. `input.call.writes` is `null` on
# every call that is not a write tool — a Bash command, a read, a write whose
# payload named no path — and `startswith(null, _)` is not a false answer but an
# evaluation error. The guard is what makes "no target" resolve to silence rather
# than to a fault, which is the vacuity case this surface makes easy to get wrong.
#
# THE DELETION A RETIREMENT PERFORMS CANNOT REACH THIS BODY, and that is
# structural rather than a heuristic worth trusting. A retirement deletes the
# path, and a deletion arrives as a Bash `git rm` or `rm` — a command, carrying no
# `writes` key at all — so `input.call.operation` is not `"write"` and the first
# conjunct already fails. That is why this advisory cannot impede the one
# disposition the tree gate admits.
violation contains {
	"rule": "shell-write-at-the-edit",
	"verdict": "shell edit early",
	"subjects": [{"path": path}],
} if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
	governed(path)
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------
#
# The load-time tier. It pins the predicate; `crates/batten/tests/` is the tier
# that proves the ENGINE builds the input this reads, which a `with input as`
# case structurally cannot.

test_a_write_to_an_authored_shell_gate_is_flagged if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "mise-tasks/ready-lint.sh",
	}}
	v.verdict == "shell edit early"
}

test_a_write_to_a_bats_suite_is_flagged if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "tests/land.bats",
	}}
	v.verdict == "shell edit early"
}

# The wider set the bound above names, asserted so the over-approximation is a
# decision on the record rather than a surprise to the next reader.
test_a_nested_mise_tasks_path_is_flagged_though_the_edit_gate_would_not if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "mise-tasks/lib/helper",
	}}
	v.verdict == "shell edit early"
}

test_an_ungoverned_write_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "crates/batten/src/hook.rs",
	}}
}

# The two exclusions `under_mise_tasks` carries, so a change dropping them is
# visible here too.
test_a_python_helper_under_mise_tasks_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "mise-tasks/bench.py",
	}}
}

# THE DISCRIMINATING CASE. A predicate keyed on the path alone passes every case
# above and refuses every retirement, so this is the one that tells a correct
# module from a plausible one.
test_a_deletion_of_the_same_path_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "git rm mise-tasks/ready-lint.sh",
		"writes": null,
	}}
}

# THE COMPOUND DELETION, which is what a retirement actually looks like: a
# program and its suite are two paths, so the real shape is one list rather than
# one command. `policy test` requires a mediated module's suite to carry a
# compound case (CLOUD-857) because a predicate reading `input.call.command`
# answers about the first word of the whole LINE — measured on a vendored preset
# where `git push --force` denied and `cd /tmp && git push --force` did not.
#
# This module reads no command at all, so it is structurally immune to that
# defect — and the case is worth its lines anyway, because "immune" is a claim
# about the current predicate rather than about the next edit to it.
test_a_compound_retirement_deletion_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "git rm mise-tasks/ready-lint.sh && git rm tests/ready-lint.bats",
		"writes": null,
	}}
}

# The vacuity case: absent rather than null, which is the other spelling a host
# can produce.
test_a_call_carrying_no_write_target_is_silent if {
	count(violation) == 0 with input as {"call": {"operation": "command"}}
}
