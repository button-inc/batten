# The external analyzer's verdict on one SHA (CLOUD-441), retired off
# `[tasks."sonar-gate"]`'s bash body under CLOUD-843.
#
# THE SPLIT IS §5's. The reading is `batten record query check-runs --input
# sha=<sha>`, a declared `[[forge.query]]` row: the vendored client walks the
# commit's check-runs and records the declared fields per run into the
# `check-runs` family. This decides over that family and nothing else. The task
# is now two argv steps, the query then `check --rule 'check grade other'`.
#
# ONE NAME, AND ABSENT IS NOT A VETO. The analyzer declines to grade some heads
# and then posts no run at all; failing on that would wedge every change it has no
# opinion about. So a family with no run under `check` is silent, exactly as the
# retired body's early exit 0 was. Another check's failure gets neither a vote nor
# a veto.
#
# THE LATEST RUN DECIDES (CLOUD-436), ordered as `checks green` orders one name
# (`crates/batten/src/checks_green.rs::key`): a run still open with no conclusion
# stamp above everything, then `completed_at` (CLOUD-1662), then `started_at`, then
# the run id; among equal keys the LEAST conclusive wins, so an unorderable pair
# fails closed. A completed run that answered nothing (`skipped`, `cancelled`, or a
# conclusion nobody has seen) never displaces an older verdict when it carries no
# conclusion stamp to be ordered by — the backstop `checks green`'s `winner` keeps.
#
# THE ANSWERED SET is `[env] CI_ANSWERED_CONCLUSIONS` in `mise.toml`, restated
# here because a module reads no environment; `crates/batten/tests/it/sonar_gate.rs`
# drives every member of that declaration through the binary, so the two cannot
# drift apart in the direction that would call an answer "not yet".
#
# THE THREE VERDICTS. `check grade red` is the analyzer's objection, pointing at
# the conclusion. `check grade early` is no answer yet — running, skipped,
# cancelled — pointing at the status or conclusion. `check read partial` is a
# window the query could not finish, which is never judged as the whole.
#
#MUTANT-SUITE crates/batten/tests/it/sonar_gate.rs
#MUTANT red-analysis-passes|s@^\trank(run) == 2$@\tfalse@|a_failed_or_timed_out_analysis_is_red_and_names_only_a_pointer
#MUTANT unanswered-is-an-answer|s@^\trank(run) >= 3$@\tfalse@|pending_skipped_and_cancelled_are_not_an_answer
#MUTANT other-checks-judged|s@^\trow.name == check$@\ttrue@|another_checks_failure_is_none_of_this_gates_business
#MUTANT conclusion-stamp-ignored|s@^\tb := .*$@\tb := a@|a_concurrent_skip_does_not_bury_the_failure_it_raced
#MUTANT unanswered-displaces-a-verdict|s@^\tkey(older) != key(newest)$@\tfalse@|a_later_unstamped_skip_does_not_erase_a_verdict
#MUTANT truncated-window-judged|s@^\ttruncated$@\tfalse@|a_truncated_window_is_partial_never_a_pass

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.sonar_gate

import rego.v1

rules contains "check grade other"

# The one name this repository's analyzer posts under.
check := "SonarCloud Code Analysis"

answered := {"success", "neutral", "failure", "timed_out", "action_required"}

passing := {"success", "neutral"}

lines := input.tree.records["check-runs"]

rows contains row if {
	some line in lines
	startswith(line, "row\t")
	row := json.unmarshal(trim_prefix(line, "row\t"))
}

runs := {row |
	some row in rows
	row.name == check
}

# A field the forge left out is `null` in the record; ordering reads it as the
# lowest value, which is what an absent stamp means.
text(value) := value if is_string(value)

text(value) := "" if not is_string(value)

id_of(run) := run.id if is_number(run.id)

id_of(run) := 0 if not is_number(run.id)

# A pointer never carries an empty or null word: the retired body printed `-`.
label(value) := value if label_readable(value)

label(value) := "-" if not label_readable(value)

label_readable(value) if {
	is_string(value)
	value != ""
}

unfinished(run) if {
	text(run.completed_at) == ""
	run.status != "completed"
}

open_rank(run) := 1 if unfinished(run)

open_rank(run) := 0 if not unfinished(run)

key(run) := [open_rank(run), text(run.completed_at), text(run.started_at), id_of(run)]

# How conclusive a run is, `checks green`'s `rank`: 4 still running, 3 completed
# without an answer, 2 an objection, 1 a pass.
rank(run) := 4 if run.status != "completed"

rank(run) := 3 if {
	run.status == "completed"
	not run.conclusion in answered
}

rank(run) := 2 if {
	run.status == "completed"
	run.conclusion in answered
	not run.conclusion in passing
}

rank(run) := 1 if {
	run.status == "completed"
	run.conclusion in passing
}

# The runs holding the greatest key, and among those the least conclusive — one
# component at a time, so no comparison is ever made between composite values.
# Called only over a non-empty pool.
latest(pool) := top if {
	a := {r | some r in pool; open_rank(r) == max({open_rank(s) | some s in pool})}
	b := {r | some r in a; text(r.completed_at) == max({text(s.completed_at) | some s in a})}
	c := {r | some r in b; text(r.started_at) == max({text(s.started_at) | some s in b})}
	d := {r | some r in c; id_of(r) == max({id_of(s) | some s in c})}
	top := {r | some r in d; rank(r) == max({rank(s) | some s in d})}
}

newest_set := latest(runs) if count(runs) > 0

answering := {run | some run in runs; rank(run) != 3}

older_set := latest(answering) if count(answering) > 0

# The backstop: the newest run answered nothing and carries no conclusion stamp,
# and a STRICTLY older run answered or is still answering. An equal key is the
# unorderable pair, which stays with the least conclusive reading.
yields if {
	some newest in newest_set
	rank(newest) == 3
	text(newest.completed_at) == ""
	some older in older_set
	key(older) != key(newest)
}

winners := older_set if yields

winners := newest_set if not yields

violation contains {
	"rule": "check grade other",
	"verdict": "check grade red",
	"subjects": [{"artifact": label(run.conclusion)}],
} if {
	some run in winners
	rank(run) == 2
}

violation contains {
	"rule": "check grade other",
	"verdict": "check grade early",
	"subjects": [{"artifact": pointer(run)}],
} if {
	some run in winners
	rank(run) >= 3
}

pointer(run) := label(run.status) if run.status != "completed"

pointer(run) := label(run.conclusion) if run.status == "completed"

# A window the query could not finish, or a record with no closing line at all:
# a prefix is never judged as the population.
violation contains {
	"rule": "check grade other",
	"verdict": "check read partial",
	"subjects": [{"artifact": "window"}],
} if {
	truncated
}

truncated if {
	some line in lines
	startswith(line, "window\tstate=truncated")
}

violation contains {
	"rule": "check grade other",
	"verdict": "check read partial",
	"subjects": [{"artifact": "window"}],
} if {
	count(lines) > 0
	not closed
}

closed if {
	some line in lines
	startswith(line, "window\t")
}

# --- cases -------------------------------------------------------------------

run_row(status, conclusion, name, started, completed, id) := sprintf("row\t%s", [json.marshal({
	"completed_at": completed,
	"conclusion": conclusion,
	"id": id,
	"name": name,
	"started_at": started,
	"status": status,
})])

whole := "window\tstate=whole\tread=1\tkept=1"

tree(rows_in) := {"tree": {"records": {"check-runs": array.concat(rows_in, [whole])}}}

one(status, conclusion) := tree([run_row(status, conclusion, check, "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1)])

verdicts(found) := {entry.verdict | some entry in found}

test_green_and_neutral_pass if {
	count(violation) == 0 with input as one("completed", "success")
	count(violation) == 0 with input as one("completed", "neutral")
}

test_failure_and_timed_out_are_red if {
	verdicts(violation) == {"check grade red"} with input as one("completed", "failure")
	verdicts(violation) == {"check grade red"} with input as one("completed", "timed_out")
}

test_the_red_pointer_is_the_conclusion if {
	found := violation with input as one("completed", "failure")
	{entry.subjects[0].artifact | some entry in found} == {"failure"}
}

test_running_skipped_and_cancelled_are_early if {
	verdicts(violation) == {"check grade early"} with input as tree([run_row("in_progress", null, check, "2026-08-12T03:00:00Z", null, 1)])
	verdicts(violation) == {"check grade early"} with input as one("completed", "skipped")
	verdicts(violation) == {"check grade early"} with input as one("completed", "cancelled")
	verdicts(violation) == {"check grade early"} with input as one("completed", "stale")
}

test_absent_is_not_a_veto if {
	count(violation) == 0 with input as tree([run_row("completed", "failure", "ci", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1)])
	count(violation) == 0 with input as tree([])
}

test_no_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_later_failure_supersedes_a_success if {
	verdicts(violation) == {"check grade red"} with input as tree([
		run_row("completed", "success", check, "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		run_row("completed", "failure", check, "2026-08-12T03:05:00Z", "2026-08-12T03:06:00Z", 2),
	])
}

test_a_rerun_in_flight_is_early if {
	verdicts(violation) == {"check grade early"} with input as tree([
		run_row("completed", "success", check, "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		run_row("in_progress", null, check, "2026-08-12T03:05:00Z", null, 2),
	])
}

test_the_conclusion_stamp_leads_the_start if {
	# The failure started first and concluded last: it is the event's latest.
	verdicts(violation) == {"check grade red"} with input as tree([
		run_row("completed", "failure", check, "2026-08-12T04:05:37Z", "2026-08-12T04:20:00Z", 7),
		run_row("completed", "skipped", check, "2026-08-12T04:05:39Z", "2026-08-12T04:05:40Z", 8),
	])
}

test_an_unstamped_later_skip_yields_to_an_older_verdict if {
	count(violation) == 0 with input as tree([
		run_row("completed", "success", check, "2026-08-12T02:34:02Z", null, 1),
		run_row("completed", "skipped", check, "2026-08-12T02:34:03Z", null, 2),
	])
}

test_an_unorderable_pair_fails_closed if {
	verdicts(violation) == {"check grade red"} with input as tree([
		run_row("completed", "failure", check, null, null, null),
		run_row("completed", "success", check, null, null, null),
	])
	verdicts(violation) == {"check grade early"} with input as tree([
		run_row("completed", "cancelled", check, null, null, null),
		run_row("completed", "success", check, null, null, null),
	])
}

test_a_truncated_window_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [
		run_row("completed", "success", check, "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		"window\tstate=truncated\tread=1\tkept=1\ttotal=400\tpages=3",
	]}}}
	verdicts(found) == {"check read partial"}
}

test_a_record_with_no_closing_line_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [run_row("completed", "success", check, "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1)]}}}
	verdicts(found) == {"check read partial"}
}
