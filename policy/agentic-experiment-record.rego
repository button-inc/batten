# A declared agentic trial names everything an outcome can be read against, and a
# disposition asserting a finding owes a result (CLOUD-1116).
#
# THE SUBJECT IS THE RECORD, NEVER THE TREATMENT. This decides completeness over
# `bench/agentic/trials.toml` and `bench/agentic/method.toml` and nothing else. It
# does not know whether prose in a verdict's `class` helped an agent, and it must
# not: that is a judgement, and non-negotiable rule 3 keeps a judgement out of a
# verdict. What it can decide, byte-for-byte, is whether a row that CLAIMS an
# outcome carries the arms, the fixture, the run count and the falsifier that
# would let anyone else check the claim.
#
# WHY A GATE AT ALL, since nobody is forced to write a trial. Because the failure
# mode here is not an absent record, it is a HALF one. CLOUD-1089 paid for that
# twice in one survey: two instruments returned exit 0 while measuring nothing —
# jscpd reporting "0 files analyzed", sonarjs with an undefined parser — and both
# would have been written up as clean results had a human not looked. A trial
# missing its baseline arm reads exactly like a trial that ran, and the write-up
# is the same length. `method.toml`'s canary rule is that lesson stated for an
# arm; this is it stated for the row.
#
# THE DISPOSITION CLAUSE IS THE ONE THAT WILL FIRE IN ANGER. Every row ships
# `pending`, which is the honest state for a declared-but-unrun trial. The moment
# somebody writes `gate-candidate` they are asserting a finding, and this refuses
# it without a `[trial.result]` beside it — the shape CLOUD-680 calls laundering,
# arriving through the record channel instead of through an override.
#
# TWO RECORDS, ONE PREDICATE, and the split is `trials.toml`'s own header: the
# method record owns what "improved" means and the workload record owns each
# experiment's arms. A row is complete only JOINTLY — its `disposition` is checked
# against the method's declared list, so a new disposition cannot be invented at
# the row.
#
# NOT `bench/tokens/`, and `method.toml` states why at length: that record set's
# invariant is byte-for-byte comparison across runs, which no model arm can
# satisfy. Nothing here edits it.
#MUTANT-SUITE crates/batten/tests/it/agentic_record.rs
#
# BOTH SCRIPTS ARE ANCHORED ON THE LEADING TAB, so they reach the rule BODY and
# not their own declaration lines below. An unanchored `s@count(incomplete) >
# 0@false@` also rewrites this comment — harmless, but it makes the staged diff
# unreadable, and a script that matches its own row is one edit away from
# CLOUD-1445's inert mutation.
#MUTANT incomplete-trial-passes|s@^\tcount(incomplete) > 0$@\tfalse@|a_trial_missing_a_required_key_is_reported
#MUTANT unsupported-finding-passes|s@^\tcount(unsupported) > 0$@\tfalse@|a_disposition_asserting_a_finding_without_a_result_is_reported

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.agentic_experiment_record

import rego.v1

rules contains "agentic-record-incomplete"

rules contains "agentic-finding-unsupported"

rules contains "agentic-record-unreadable"

trials_path := "bench/agentic/trials.toml"

method_path := "bench/agentic/method.toml"

# The keys a trial row must name at its top level, and the reason each is here
# rather than optional:
#
# `question` and `intended_outcome` are what makes the row falsifiable in advance
# rather than after the fact. `intervention` is the class being tested, so a
# result can be pooled with its siblings. `model` and `fixture` are the two things
# that make a rerun a rerun; `runs` is what makes a difference a difference.
# `governed_action` names the mediated call the trial is ABOUT, which is what
# bounds the attribution window `method.toml` declares. `evidence` is what the
# treatment arm actually shows the agent. `canary` is CLOUD-1089's lesson.
required_trial_keys := {
	"id",
	"question",
	"intended_outcome",
	"intervention",
	"model",
	"fixture",
	"runs",
	"governed_action",
	"evidence",
	"canary",
}

# Both arms, because a single-arm trial is an anecdote with a run count.
required_arms := {"baseline", "treatment"}

# The falsifier's three fields. `statement` is what would refute the hypothesis,
# `downside` is what a null result costs anyway, and `disposition` is what the row
# currently asserts.
required_falsifier_keys := {"statement", "downside", "disposition"}

# What the method record must name for any of the above to be readable as an
# outcome: the window and what is held constant.
required_method_keys := {"attribution_window", "held_constant"}

trials := input.tree.documents[trials_path].trial

method := input.tree.documents[method_path].method

# --- completeness ------------------------------------------------------------

violation contains {
	"rule": "agentic-record-incomplete",
	"verdict": "test declare partial",
	"subjects": [{"path": trials_path}, {"count": count(incomplete)}],
} if {
	count(incomplete) > 0
}

# A row is incomplete if it misses a top-level key, an arm, or a falsifier field.
#
# KEYED ON THE ROW'S INDEX, never on its `id` — a row whose missing key IS `id`
# has no id to be counted under, and counting it under the empty string would
# collapse every such row into one finding.
incomplete contains index if {
	some index, trial in trials
	some key in required_trial_keys
	not key in object.keys(trial)
}

incomplete contains index if {
	some index, trial in trials
	some arm in required_arms
	not arm in object.keys(object.get(trial, "arms", {}))
}

incomplete contains index if {
	some index, trial in trials
	some key in required_falsifier_keys
	not key in object.keys(object.get(trial, "falsifier", {}))
}

# The method record is held to the same standard, and raises the same class: a
# window nobody declared makes every row's outcome unattributable, so the record
# SET is what is partial rather than any one row.
violation contains {
	"rule": "agentic-record-incomplete",
	"verdict": "test declare partial",
	"subjects": [{"path": method_path}, {"count": count(method_gaps)}],
} if {
	count(method_gaps) > 0
}

method_gaps contains key if {
	trials
	some key in required_method_keys
	not key in object.keys(method)
}

method_gaps contains key if {
	trials
	some key in {"measured", "unmeasured"}
	not key in object.keys(object.get(method, "outcomes", {}))
}

method_gaps contains key if {
	trials
	some key in {"method", "dispositions"}
	not key in object.keys(object.get(method, "adjudication", {}))
}

# --- a finding without a result ----------------------------------------------

violation contains {
	"rule": "agentic-finding-unsupported",
	"verdict": "test state early",
	"subjects": [{"path": trials_path}, {"count": count(unsupported)}],
} if {
	count(unsupported) > 0
}

# A COMPREHENSION DOES NOT PROPAGATE UNDEFINED, which is why both clauses below
# guard on the count rather than relying on this rule to be absent. A method
# record declaring no `dispositions` yields the EMPTY set here, not undefined — so
# an unguarded membership test would report every row's disposition as undeclared,
# on top of the `method_gaps` finding that already says the vocabulary is missing.
# One cause, one finding: that gap is the method record's.
declared_dispositions := {name | some name in method.adjudication.dispositions}

# A disposition the method record does not declare. Invented at the row is how a
# vocabulary stops meaning anything.
unsupported contains index if {
	count(declared_dispositions) > 0
	some index, trial in trials
	disposition := trial.falsifier.disposition
	not disposition in declared_dispositions
}

# A disposition asserting a finding, with no result beside it. `pending` is the
# one value that asserts nothing and is therefore the one that needs no result.
unsupported contains index if {
	count(declared_dispositions) > 0
	some index, trial in trials
	disposition := trial.falsifier.disposition
	disposition in declared_dispositions
	disposition != "pending"
	not "result" in object.keys(trial)
}

# --- could not look ----------------------------------------------------------

# THE `missing` CLAUSE. A module that iterates only what acquired reports green
# over a file it never read, and a dead gate and a clean tree are byte-identical
# on the decision surface. Both records are named, because either one absent
# leaves the joint predicate unable to decide.
violation contains {
	"rule": "agentic-record-unreadable",
	"verdict": "input read absent",
	"subjects": [{"path": path}],
} if {
	some path in {trials_path, method_path}
	input.tree.missing[path]
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE parses either TOML
# record into `input.tree.documents`, or that an absent one reaches
# `input.tree.missing`. `crates/batten/tests/it/agentic_record.rs` is the tier
# that drives the compiled binary, and it is where the `missing` clause is
# asserted for that reason.
#
# `object.union` MERGES RECURSIVELY, so a case meaning to REPLACE a sub-table
# cannot be written with it — `object.union(row, {"arms": {"treatment": …}})`
# keeps the `baseline` it was trying to remove, and the case then passes over an
# input it never constructed. `replacing` composes remove-then-union for that
# reason, and it is a measured correction rather than a precaution: two cases here
# were written the naive way and both were green for the wrong reason.
replacing(object, key, value) := object.union(object.remove(object, {key}), {key: value})

complete_method := {
	"attribution_window": "the governed action under test",
	"held_constant": ["repository revision"],
	"outcomes": {"measured": ["denials before success"], "unmeasured": ["whether the rationale is sound"]},
	"adjudication": {
		"method": "paired difference",
		"dispositions": ["pending", "gate-candidate"],
	},
	"canary": {"required": true},
}

complete_trial := {
	"id": "a-trial",
	"question": "does it help",
	"intended_outcome": "the floor",
	"intervention": "gate-feedback",
	"model": "claude-opus-5",
	"fixture": "03720c38",
	"runs": 10,
	"governed_action": "a commit touching a protected path",
	"evidence": "the verdict token alone",
	"canary": "a commit touching no protected path must not be refused",
	"arms": {"baseline": "no token", "treatment": "the token"},
	"falsifier": {
		"statement": "denials do not fall",
		"downside": "a standing token cost",
		"disposition": "pending",
	},
}

tree(trial, method_doc) := {"tree": {"documents": {
	"bench/agentic/trials.toml": {"trial": [trial]},
	"bench/agentic/method.toml": {"method": method_doc},
}}}

test_a_complete_pending_trial_is_silent if {
	count(violation) == 0 with input as tree(complete_trial, complete_method)
}

test_a_trial_missing_a_required_key_is_reported if {
	count(violation) == 1 with input as tree(object.remove(complete_trial, {"fixture"}), complete_method)
}

# THE RUN COUNT IS A REQUIRED KEY AND ZERO IS NOT ITS ABSENCE. A row declaring
# `runs = 0` is a different defect from a row declaring no runs at all, and only
# the second is this predicate's.
test_a_trial_declaring_no_runs_is_reported if {
	count(violation) == 1 with input as tree(object.remove(complete_trial, {"runs"}), complete_method)
}

test_a_single_armed_trial_is_reported if {
	count(violation) == 1 with input as tree(
		replacing(complete_trial, "arms", {"treatment": "the token"}),
		complete_method,
	)
}

test_a_trial_with_no_arms_table_is_reported if {
	count(violation) == 1 with input as tree(object.remove(complete_trial, {"arms"}), complete_method)
}

test_a_trial_with_no_falsifier_is_reported if {
	count(violation) == 1 with input as tree(object.remove(complete_trial, {"falsifier"}), complete_method)
}

test_a_trial_naming_no_canary_is_reported if {
	count(violation) == 1 with input as tree(object.remove(complete_trial, {"canary"}), complete_method)
}

# ONE FINDING, NOT SIX. The count is over rows rather than over missing keys, so a
# row that is entirely absent is one thing to fix rather than a wall.
test_a_row_missing_everything_is_one_finding if {
	count(violation) == 1 with input as tree({"falsifier": {"disposition": "pending"}}, complete_method)
}

test_a_disposition_asserting_a_finding_without_a_result_is_reported if {
	count(violation) == 1 with input as tree(
		replacing(
			complete_trial, "falsifier",
			replacing(complete_trial.falsifier, "disposition", "gate-candidate"),
		),
		complete_method,
	)
}

test_a_disposition_asserting_a_finding_with_a_result_is_silent if {
	count(violation) == 0 with input as tree(
		object.union(
			replacing(
				complete_trial, "falsifier",
				replacing(complete_trial.falsifier, "disposition", "gate-candidate"),
			),
			{"result": {"denials_before_success": "3.1 against 6.4"}},
		),
		complete_method,
	)
}

# A DISPOSITION THE METHOD RECORD DOES NOT DECLARE. Invented at the row is how a
# vocabulary stops meaning anything, and it is the arm a `result` cannot excuse.
test_an_undeclared_disposition_is_reported if {
	count(violation) == 1 with input as tree(
		object.union(
			replacing(
				complete_trial, "falsifier",
				replacing(complete_trial.falsifier, "disposition", "obviously-true"),
			),
			{"result": {"denials_before_success": "3.1 against 6.4"}},
		),
		complete_method,
	)
}

test_a_method_record_declaring_no_window_is_reported if {
	count(violation) == 1 with input as tree(
		complete_trial,
		object.remove(complete_method, {"attribution_window"}),
	)
}

test_a_method_record_naming_no_unmeasured_dimension_is_reported if {
	count(violation) == 1 with input as tree(
		complete_trial,
		replacing(complete_method, "outcomes", {"measured": ["denials before success"]}),
	)
}

# THE VOCABULARY'S ABSENCE IS ONE FINDING, NOT SEVEN. Removing `adjudication`
# takes the `dispositions` list with it, and the guard on `declared_dispositions`
# is what keeps every row from being reported as carrying an undeclared value on
# top of the method gap that is the actual cause.
test_a_method_record_declaring_no_adjudication_is_reported if {
	count(violation) == 1 with input as tree(
		complete_trial,
		object.remove(complete_method, {"adjudication"}),
	)
}

# NO TRIALS IS NOT AN INCOMPLETE METHOD. A repository that declares no agentic
# work at all is silent here — every `method_gaps` clause is guarded on `trials`
# resolving, so this gate costs a consumer nothing until it writes a row.
test_a_tree_with_no_records_is_silent if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

test_an_unreadable_trials_record_is_reported if {
	count(violation) == 1 with input as {"tree": {"missing": {"bench/agentic/trials.toml": "absent"}}}
}

test_an_unreadable_method_record_is_reported if {
	count(violation) == 1 with input as {"tree": {"missing": {"bench/agentic/method.toml": "absent"}}}
}
