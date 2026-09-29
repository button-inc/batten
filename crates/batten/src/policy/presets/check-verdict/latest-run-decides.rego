# A check's verdict on one commit is its LATEST run, and "not yet" is never a
# pass (CLOUD-441's decision, moved out of a consumer module into a preset under
# CLOUD-843).
#
# WHAT IS READ, AND WHO DID WHICH HALF. One record family, `check-runs`, written
# by `batten record query` from the consumer's own `[[forge.query]]` row: the
# commit's check-runs, one `row<TAB><json>` line per run carrying `status`,
# `conclusion`, `name`, `started_at`, `completed_at` and `id`, then one closing
# `window` line. The family name and those six keys are this preset's contract.
# WHICH commit, WHICH repository and WHICH check names are the consumer's row —
# a name filter belongs on the query, where the forge applies it — so nothing
# here names a repository, an analyzer or a check.
#
# EACH NAME ON ITS OWN LATEST RUN (CLOUD-436), ordered as a check-run is ordered
# everywhere in this engine: a run still open with no conclusion stamp above
# everything, then `completed_at` (CLOUD-1662), then `started_at`, then the run id;
# among equal keys the LEAST conclusive wins, so an unorderable pair fails closed.
# A completed run that answered nothing never displaces an older verdict when it
# carries no conclusion stamp to be ordered by — the backstop for a reading that
# cannot be ordered by conclusion. That order is `checks green`'s, and the
# consumer tier replays both over the same readings, so the two cannot drift.
#
# ABSENT IS NOT A VETO. A check that declined to run posts no run at all, and
# failing on that would wedge every commit it has no opinion about. A family with
# no rows is silent; so is a tree whose producer never ran.
#
# THE ANSWERED SET IS THE PRACTICE'S, not a consumer knob. A check-run concludes
# in the forge's closed vocabulary, and `skipped`, `cancelled` and a conclusion
# nobody has seen judged nothing (CLOUD-363, CLOUD-376). Moving a word into the
# answered set would let a run that judged nothing read as a verdict, which is
# why it costs a diff here rather than a config line.
#
# THE THREE VERDICTS. `check grade red` is an objection, pointing at the name
# and the conclusion. `check grade early` is no answer yet — running, skipped,
# cancelled — pointing at the name and the status or conclusion. `check read
# partial` is a window the query could not finish, a record torn without its
# one closing line, or a row line torn mid-JSON, none ever judged as the whole.
#
# EVERY NAME IS PREFIXED `verdict_`: a preset's modules share one `package`, and
# a sibling added later must not collide with these.
#
# EVERY HELPER IS DEFINED ABOVE ITS READER. Rego is order-independent and regorus
# is not: a rule defined below the rule reading it resolves to undefined, and the
# reader then decides nothing while loading clean.
#
#MUTANT-SUITE crates/batten/tests/it/sonar_gate.rs
#MUTANT red-analysis-passes|s@^\tverdict_rank(run) == 2$@\tfalse@|a_failed_or_timed_out_analysis_is_red_and_names_only_a_pointer
#MUTANT unanswered-is-an-answer|s@^\tverdict_rank(run) >= 3$@\tfalse@|pending_skipped_and_cancelled_are_not_an_answer
#MUTANT names-pooled|s@^\trow.name == name$@\ttrue@|each_name_is_judged_on_its_own_latest_run
#MUTANT conclusion-stamp-ignored|s@^\tb := .*$@\tb := a@|a_concurrent_skip_does_not_bury_the_failure_it_raced
#MUTANT unanswered-displaces-a-verdict|s@^\tverdict_key(older) != verdict_key(newest)$@\tfalse@|a_later_unstamped_skip_does_not_erase_a_verdict
#MUTANT truncated-window-judged|s@^\tverdict_truncated$@\tfalse@|a_truncated_window_is_partial_never_a_pass
#MUTANT torn-record-judged|s@^\tverdict_closes != 1$@\tfalse@|a_record_torn_without_its_closing_line_is_partial
#MUTANT torn-row-faults|s@^\tjson.is_valid(text)$@\ttrue@|a_row_torn_mid_json_is_partial
#MUTANT torn-row-dropped|s@^\tverdict_torn_row$@\tfalse@|a_row_torn_mid_json_is_partial

# METADATA
# description: |
#   Bound to the TREE surface: the enabling row is `scope = "tree"`, so this
#   reads `input.tree` and never the mediated call.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.check_verdict

import rego.v1

rules contains "check grade red"

rules contains "check grade early"

rules contains "check read partial"

# The family this preset reads: its contract with the consumer's query row.
verdict_family := "check-runs"

# The conclusions that are an answer, and the two of them that pass.
verdict_answered := {"success", "neutral", "failure", "timed_out", "action_required"}

verdict_passing := {"success", "neutral"}

# The record's lines, or undefined where there is none. The `is_object` guard is
# first because `some .. in null` is an evaluation FAULT, and a fault takes the
# whole bundle down rather than missing quietly.
verdict_lines := lines if {
	is_object(input.tree.records)
	lines := input.tree.records[verdict_family]
	is_array(lines)
}

# A `row` line's JSON text, or undefined for any other line.
verdict_row_text(line) := trim_prefix(line, "row\t") if {
	is_string(line)
	startswith(line, "row\t")
}

# A row text that reads as one JSON object. `json.is_valid` is FIRST because
# `json.unmarshal` of a torn text is an evaluation fault under regorus's strict
# builtin errors, and a fault takes the whole bundle down — the same reason
# `verdict_lines` guards with `is_object`.
verdict_row_object(text) if {
	json.is_valid(text)
	is_object(json.unmarshal(text))
}

verdict_rows contains row if {
	some line in verdict_lines
	text := verdict_row_text(line)
	verdict_row_object(text)
	row := json.unmarshal(text)
}

# A `row` line that does not read as one object was torn mid-write by something
# other than the producer: never dropped quietly, never judged as the whole.
verdict_torn_row if {
	some line in verdict_lines
	text := verdict_row_text(line)
	not verdict_row_object(text)
}

# A name a run can be judged under: a non-empty string. The engine's reading of
# the same rows drops a run with no name, and so does this.
verdict_named(row) if {
	is_string(row.name)
	row.name != ""
}

verdict_names contains row.name if {
	some row in verdict_rows
	verdict_named(row)
}

verdict_runs(name) := {row |
	some row in verdict_rows
	verdict_named(row)
	row.name == name
}

# A field the forge left out is `null` in the record; ordering reads it as the
# lowest value, which is what an absent stamp means.
verdict_text(value) := value if is_string(value)

verdict_text(value) := "" if not is_string(value)

verdict_id(run) := run.id if is_number(run.id)

verdict_id(run) := 0 if not is_number(run.id)

# A pointer never carries an empty or null word.
verdict_readable(value) if {
	is_string(value)
	value != ""
}

verdict_label(value) := value if verdict_readable(value)

verdict_label(value) := "-" if not verdict_readable(value)

verdict_unfinished(run) if {
	verdict_text(run.completed_at) == ""
	run.status != "completed"
}

verdict_open(run) := 1 if verdict_unfinished(run)

verdict_open(run) := 0 if not verdict_unfinished(run)

verdict_key(run) := [verdict_open(run), verdict_text(run.completed_at), verdict_text(run.started_at), verdict_id(run)]

# How conclusive a run is: 4 still running, 3 completed without an answer, 2 an
# objection, 1 a pass.
verdict_rank(run) := 4 if run.status != "completed"

verdict_rank(run) := 3 if {
	run.status == "completed"
	not run.conclusion in verdict_answered
}

verdict_rank(run) := 2 if {
	run.status == "completed"
	run.conclusion in verdict_answered
	not run.conclusion in verdict_passing
}

verdict_rank(run) := 1 if {
	run.status == "completed"
	run.conclusion in verdict_passing
}

# The runs holding the greatest key, and among those the least conclusive — one
# component at a time, so no comparison is ever made between composite values.
# Called only over a non-empty pool.
verdict_latest(pool) := top if {
	a := {r | some r in pool; verdict_open(r) == max({verdict_open(s) | some s in pool})}
	b := {r | some r in a; verdict_text(r.completed_at) == max({verdict_text(s.completed_at) | some s in a})}
	c := {r | some r in b; verdict_text(r.started_at) == max({verdict_text(s.started_at) | some s in b})}
	d := {r | some r in c; verdict_id(r) == max({verdict_id(s) | some s in c})}
	top := {r | some r in d; verdict_rank(r) == max({verdict_rank(s) | some s in d})}
}

verdict_newest(name) := verdict_latest(verdict_runs(name))

verdict_answering(name) := {run |
	some run in verdict_runs(name)
	verdict_rank(run) != 3
}

verdict_older(name) := verdict_latest(verdict_answering(name)) if count(verdict_answering(name)) > 0

# The backstop: the newest run answered nothing and carries no conclusion stamp,
# and a STRICTLY older run answered or is still answering. An equal key is the
# unorderable pair, which stays with the least conclusive reading.
verdict_yields(name) if {
	some newest in verdict_newest(name)
	verdict_rank(newest) == 3
	verdict_text(newest.completed_at) == ""
	some older in verdict_older(name)
	verdict_key(older) != verdict_key(newest)
}

verdict_winners(name) := verdict_older(name) if verdict_yields(name)

verdict_winners(name) := verdict_newest(name) if not verdict_yields(name)

# What a run with no answer yet points at: its status while it runs, its
# conclusion once it has completed without one.
verdict_pointer(run) := verdict_label(run.status) if run.status != "completed"

verdict_pointer(run) := verdict_label(run.conclusion) if run.status == "completed"

verdict_truncated if {
	some line in verdict_lines
	startswith(line, "window\tstate=truncated")
}

# Bound through `lines` rather than counted over `verdict_lines` directly: a
# comprehension over an undefined record is the EMPTY array, and a count of zero
# there would call every tree without the family torn.
verdict_closes := count([line | some line in lines; startswith(line, "window\t")]) if {
	lines := verdict_lines
}

violation contains {
	"rule": "check grade red",
	"verdict": "check grade red",
	"subjects": [{"artifact": name}, {"artifact": verdict_label(run.conclusion)}],
} if {
	some name in verdict_names
	some run in verdict_winners(name)
	verdict_rank(run) == 2
}

violation contains {
	"rule": "check grade early",
	"verdict": "check grade early",
	"subjects": [{"artifact": name}, {"artifact": verdict_pointer(run)}],
} if {
	some name in verdict_names
	some run in verdict_winners(name)
	verdict_rank(run) >= 3
}

# A window the query could not finish: a prefix is never judged as the
# population.
violation contains {
	"rule": "check read partial",
	"verdict": "check read partial",
	"subjects": [{"artifact": verdict_family}],
} if {
	verdict_truncated
}

# A record present without exactly one closing line was torn by something other
# than its producer, which writes whole or removes.
violation contains {
	"rule": "check read partial",
	"verdict": "check read partial",
	"subjects": [{"artifact": verdict_family}],
} if {
	verdict_closes != 1
}

# A row line torn mid-JSON: the rest of the record is not the whole reading.
violation contains {
	"rule": "check read partial",
	"verdict": "check read partial",
	"subjects": [{"artifact": verdict_family}],
} if {
	verdict_torn_row
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/sonar_gate.rs` drives the
# query and this preset through the compiled binary, and
# `crates/batten/tests/it/policy_presets.rs` loads it for a consumer with no
# vocabulary of its own.

verdict_case_row(status, conclusion, name, started, completed, id) := sprintf("row\t%s", [json.marshal({
	"completed_at": completed,
	"conclusion": conclusion,
	"id": id,
	"name": name,
	"started_at": started,
	"status": status,
})])

verdict_case_whole := "window\tstate=whole\tread=1\tkept=1"

verdict_case_tree(rows_in) := {"tree": {"records": {"check-runs": array.concat(rows_in, [verdict_case_whole])}}}

verdict_case_one(status, conclusion) := verdict_case_tree([verdict_case_row(status, conclusion, "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1)])

verdict_case_tokens(found) := {entry.verdict | some entry in found}

test_green_and_neutral_pass if {
	count(violation) == 0 with input as verdict_case_one("completed", "success")
	count(violation) == 0 with input as verdict_case_one("completed", "neutral")
}

test_failure_and_timed_out_are_red if {
	verdict_case_tokens(violation) == {"check grade red"} with input as verdict_case_one("completed", "failure")
	verdict_case_tokens(violation) == {"check grade red"} with input as verdict_case_one("completed", "timed_out")
}

test_the_red_pointer_is_the_name_and_the_conclusion if {
	found := violation with input as verdict_case_one("completed", "failure")
	{[entry.subjects[0].artifact, entry.subjects[1].artifact] | some entry in found} == {["lint", "failure"]}
}

test_running_skipped_cancelled_and_unseen_are_early if {
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_tree([verdict_case_row("in_progress", null, "lint", "2026-08-12T03:00:00Z", null, 1)])
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_one("completed", "skipped")
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_one("completed", "cancelled")
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_one("completed", "stale")
}

test_an_empty_family_and_no_record_are_silent if {
	count(violation) == 0 with input as verdict_case_tree([])
	count(violation) == 0 with input as {"tree": {"records": {}}}
	count(violation) == 0 with input as {"tree": {"records": null}}
}

test_each_name_is_judged_on_its_own_latest if {
	found := violation with input as verdict_case_tree([
		verdict_case_row("completed", "failure", "build", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:05:00Z", "2026-08-12T03:06:00Z", 2),
	])
	{entry.subjects[0].artifact | some entry in found} == {"build"}
}

test_a_later_failure_supersedes_a_success if {
	verdict_case_tokens(violation) == {"check grade red"} with input as verdict_case_tree([
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		verdict_case_row("completed", "failure", "lint", "2026-08-12T03:05:00Z", "2026-08-12T03:06:00Z", 2),
	])
}

test_a_rerun_in_flight_is_early if {
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_tree([
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		verdict_case_row("in_progress", null, "lint", "2026-08-12T03:05:00Z", null, 2),
	])
}

test_the_conclusion_stamp_leads_the_start if {
	# The failure started first and concluded last: it is the event's latest.
	verdict_case_tokens(violation) == {"check grade red"} with input as verdict_case_tree([
		verdict_case_row("completed", "failure", "lint", "2026-08-12T04:05:37Z", "2026-08-12T04:20:00Z", 7),
		verdict_case_row("completed", "skipped", "lint", "2026-08-12T04:05:39Z", "2026-08-12T04:05:40Z", 8),
	])
}

test_an_unstamped_later_skip_yields_to_an_older_verdict if {
	count(violation) == 0 with input as verdict_case_tree([
		verdict_case_row("completed", "success", "lint", "2026-08-12T02:34:02Z", null, 1),
		verdict_case_row("completed", "skipped", "lint", "2026-08-12T02:34:03Z", null, 2),
	])
}

test_an_unorderable_pair_fails_closed if {
	verdict_case_tokens(violation) == {"check grade red"} with input as verdict_case_tree([
		verdict_case_row("completed", "failure", "lint", null, null, null),
		verdict_case_row("completed", "success", "lint", null, null, null),
	])
	verdict_case_tokens(violation) == {"check grade early"} with input as verdict_case_tree([
		verdict_case_row("completed", "cancelled", "lint", null, null, null),
		verdict_case_row("completed", "success", "lint", null, null, null),
	])
}

test_a_truncated_window_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		"window\tstate=truncated\tread=1\tkept=1\ttotal=400\tpages=3",
	]}}}
	verdict_case_tokens(found) == {"check read partial"}
}

test_a_record_with_no_closing_line_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1)]}}}
	verdict_case_tokens(found) == {"check read partial"}
}

test_a_row_torn_mid_json_is_partial_not_a_fault if {
	found := violation with input as {"tree": {"records": {"check-runs": [
		"row\t{\"status\": \"compl",
		verdict_case_whole,
	]}}}
	verdict_case_tokens(found) == {"check read partial"}
}

test_a_row_that_is_json_but_no_object_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [
		"row\t[1, 2]",
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		verdict_case_whole,
	]}}}
	verdict_case_tokens(found) == {"check read partial"}
}

test_a_record_with_two_closing_lines_is_partial if {
	found := violation with input as {"tree": {"records": {"check-runs": [
		verdict_case_row("completed", "success", "lint", "2026-08-12T03:00:00Z", "2026-08-12T03:01:00Z", 1),
		verdict_case_whole,
		verdict_case_whole,
	]}}}
	verdict_case_tokens(found) == {"check read partial"}
}
