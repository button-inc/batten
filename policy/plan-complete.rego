# The plan a branch declared, held to its own end (CLOUD-472).
#
# WHY THIS IS A SEPARATE MODULE FROM `filed-here`. That one's subject is the
# BOARD — rows this branch put on the tracker — and its header rests on three
# refusals none of which subsumes another. A plan entry is not a board row: it is
# the agent's own declared work, in the agent's own words, and folding it in
# would make that invariant unreadable. Same shape, different subject, different
# store.
#
# THE SENSOR EXISTED AND HAD NO RATCHET, which is this repository's recurring
# defect rather than a new one. An agent's task list is displayed every turn and
# is the most legible statement of what it believes is outstanding — and nothing
# in the tree could see it, so a branch could land with half its list `pending`
# and every gate stayed green. Measured 2026-09-01: three items sat `pending`
# while the session reported the work as planned, and the only detector was a
# human asking.
#
# A VERB WRITES THIS STORE, NOT A HOOK, and the direction is the whole design.
# Recording from the harness's own todo tool needs a spelling per host —
# `TaskCreate`/`TaskUpdate`, `write_todos`, `todowrite`, `update_plan` — and
# fails the same way in three different ways: an unsurveyed harness, a tool a
# setting switched off, and a compliant agent all record nothing, so the gate
# reads clean. `OpenCode` makes it concrete by denying `todowrite` to subagents at
# session creation whatever the config says. `batten record plan` inverts it: the
# agent tells the engine, and a missing record REFUSES, identically everywhere.
#
# WHAT IT DOES NOT DO (rule 3): it reads a status token and nothing else. It does
# not judge whether an entry was worth doing, whether its text is honest, or
# whether the work behind `completed` happened. Those are model verdicts and no
# gate here makes one. The author closes the entry, drops it, or spends an
# admission whose articulation says why it is not this branch's to finish — and
# that articulation is hash-bound into the commit message, where a reviewer reads
# it.
#
# POINTER, NEVER PAYLOAD (rule 4): a refusal names the entry's id and its status
# token. The id is the agent's own text, so the finding carries it as an
# `artifact` subject rather than as prose, and the entry's description never
# enters the store at all.
#MUTANT-SUITE crates/batten/tests/it/plan_complete.rs
#MUTANT unfinished-entry-unread|s@^\tnot done(entry_row.status)$@\tfalse@|an_unfinished_entry_stops_the_lap
#MUTANT no-plan-at-all-unpriced|s@^\tcount(changed) > 0$@\tfalse@|a_branch_that_recorded_no_plan_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.plan_complete

import rego.v1

rules contains "plan-unfinished"

rules contains "plan-unrecorded"

# The store, or nothing. ABSENT IS NOT EMPTY, and the two reach different arms
# below on purpose: an empty file is "I recorded a plan and it holds no entries",
# while no file at all is "this branch never told the engine anything" — which is
# the vacuity `plan-unrecorded` exists to price rather than to pass.
recorded := input.tree.records.plan

# One entry per line, `<id> <status>`. A line this reader cannot parse is skipped
# rather than judged, matching every other record reader here: the writer already
# refused a malformed line, so anything unparseable at read time is a torn store
# and not an author's claim.
entry contains row if {
	some raw in recorded
	columns := split(raw, " ")
	count(columns) >= 2
	columns[0] != ""
	row := {"id": columns[0], "status": columns[1]}
}

# The two terminal statuses. `deleted` is terminal because withdrawing an entry
# is a decision the author is entitled to make and the store records that they
# made it; what the gate refuses is an entry left in flight, not one closed.
done(status) if {
	status in {"completed", "deleted"}
}

# The branch's own diff, as the engine resolved it — the same reading
# `filed-here` takes, and `null` when the base does not resolve, so `changed`
# stays empty and every arm below goes quiet rather than fabricating a verdict.
delta := input.tree["base-delta"]

changed contains path if {
	some path in delta.added
}

changed contains path if {
	some path in delta.edited
}

changed contains path if {
	some path in delta.deleted
}

# `plan-unfinished`: an entry the branch declared and left in flight.
violation contains {
	"rule": "plan-unfinished",
	"verdict": "plan declare held",
	"subjects": [{"artifact": entry_row.id}],
} if {
	some entry_row in entry
	not done(entry_row.status)
}

# A BRANCH THAT CLAIMED WORK. `claim check` writes this store on its pullable
# path, so its presence is the branch saying "I pulled a row and I am working
# it" — precisely the population that owes a plan.
claimed if {
	some _ in input.tree.records.claim
}

# `plan-unrecorded`: A CLAIMED BRANCH THAT DECLARED NO PLAN AT ALL.
#
# WITHOUT THIS ARM THE GATE IS WORTHLESS, and that is not hypothetical — a
# refusal over "entries left in flight" is satisfied completely by never
# recording an entry, so the cheapest route past it is silence. Same vacuity
# `mutate` already refuses by REPORTING a declared mutation whose named case does
# not exist rather than counting it.
#
# THE CLAIM IS THE PRECONDITION, AND THE FIRST DRAFT GOT THIS WRONG. It asked
# only for a non-empty diff, which is true of every scratch fixture and every
# consumer checkout — measured, that version reddened four `cli.rs` cases whose
# only business was exercising unrelated rules over a fixture repository. A rule
# that fires on any dirty tree makes the committed config unusable over a test
# repo, and a rule like that gets switched off. Keying on the claim asks the
# question where the answer is owed: a branch that pulled a row is doing tracked
# work; one that did not is not this arm's business.
#
# A NON-EMPTY DIFF IS STILL REQUIRED, so the arm prices work rather than
# existence: a claimed branch that has not started has nothing to have planned.
# An empty RECORD satisfies it — the store exists, so the branch spoke — which
# keeps the remedy honest for a genuinely trivial change: one call saying so,
# rather than a fabricated entry.
violation contains {
	"rule": "plan-unrecorded",
	"verdict": "plan declare absent",
	"subjects": [{"count": count(changed)}],
} if {
	claimed
	not recorded
	count(changed) > 0
}

# The predicate's own tests. The SILENT cases are the load-bearing half here for
# the usual reason: both arms are refusals, so a module that fired on everything
# would satisfy every deny case while deciding nothing.

# Both builders carry a claim, because both arms are about a branch doing tracked
# work and a fixture without one would exercise the wrong population.
plan(lines, changed_paths) := {"tree": {
	"records": {"plan": lines, "claim": ["CLOUD-1"]},
	"base-delta": {"added": changed_paths, "edited": [], "deleted": [], "code-changed": []},
}}

no_plan(changed_paths) := {"tree": {
	"records": {"claim": ["CLOUD-1"]},
	"base-delta": {"added": changed_paths, "edited": [], "deleted": [], "code-changed": []},
}}

test_an_unfinished_entry_is_refused if {
	some v in violation with input as plan(["1 pending"], ["src/a.rs"])
	v.verdict == "plan declare held"
}

test_an_in_progress_entry_is_refused if {
	some v in violation with input as plan(["1 in_progress"], ["src/a.rs"])
	v.verdict == "plan declare held"
}

test_a_completed_entry_is_clean if {
	count(violation) == 0 with input as plan(["1 completed"], ["src/a.rs"])
}

# WITHDRAWING AN ENTRY IS A DECISION, AND THE STORE RECORDS THAT IT WAS MADE.
# The gate refuses work left in flight, never work the author decided against.
test_a_deleted_entry_is_clean if {
	count(violation) == 0 with input as plan(["1 deleted"], ["src/a.rs"])
}

# ONE FINDING PER ENTRY, so a reviewer sees which item rather than a count they
# have to reconstruct — and finishing one does not clear another.
test_every_unfinished_entry_is_named if {
	ids := {v.subjects[0].artifact | some v in violation} with input as plan(
		["1 completed", "2 pending", "3 in_progress"],
		["src/a.rs"],
	)
	ids == {"2", "3"}
}

# THE ANTI-VACUITY ARM. Never recording is the cheapest way past a refusal over
# unfinished entries, so silence is priced.
test_a_branch_that_recorded_no_plan_is_refused if {
	some v in violation with input as no_plan(["src/a.rs"])
	v.verdict == "plan declare absent"
}

# AN EMPTY RECORD IS AN ANSWER. The branch spoke and said there is nothing to
# track, which is the honest remedy for a trivial change — as against a
# fabricated entry, which is what a gate demanding a non-empty list would buy.
test_an_empty_record_satisfies_the_vacuity_arm if {
	count(violation) == 0 with input as plan([], ["src/a.rs"])
}

# A BRANCH HOLDING NOTHING OPEN HAS NOTHING TO HAVE PLANNED, so a fresh checkout
# is never refused for a plan it had no occasion to write.
test_a_branch_with_no_diff_is_never_refused if {
	count(violation) == 0 with input as no_plan([])
}

# COULD NOT READ THE BASE leaves the vacuity arm silent rather than firing on
# every branch whose base does not resolve — a verdict about the environment is
# not a verdict about the branch.
test_an_unresolvable_delta_leaves_the_vacuity_arm_silent if {
	count(violation) == 0 with input as {"tree": {
		"records": {"claim": ["CLOUD-1"]},
		"base-delta": null,
	}}
}

# AN UNCLAIMED BRANCH IS NOT THIS ARM'S BUSINESS, and this is the case that keeps
# the committed config usable over a scratch tree. Without it the arm fires on
# every fixture repository that runs the whole config to exercise some unrelated
# rule — measured at four such cases before the claim became the precondition.
test_an_unclaimed_branch_owes_no_plan if {
	count(violation) == 0 with input as {"tree": {
		"records": {},
		"base-delta": {"added": ["src/a.rs"], "edited": [], "deleted": [], "code-changed": []},
	}}
}

test_a_line_this_reader_cannot_parse_is_skipped if {
	count(violation) == 0 with input as plan(["", "nonsense"], ["src/a.rs"])
}
