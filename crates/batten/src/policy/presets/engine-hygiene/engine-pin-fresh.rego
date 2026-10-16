# METADATA
# description: |
#   A consumer's engine pin is no further behind the latest published release
#   than the consumer allows (CLOUD-2279).
#
#   A pin left behind still runs, so nothing else says it is stale: CLOUD-2279
#   measured a consumer three releases back for days with no signal anywhere.
#   `batten engine outdated --notice` tells a session once a day; this module is
#   the gate half, for a consumer that wants staleness to refuse.
#
#   THE THRESHOLDS ARE THE PRODUCER'S, NEVER THIS MODULE'S. A preset cannot read
#   a consumer's own numbers (`data.batten.*` is undefined for one), so the
#   consumer passes them to `batten engine outdated --record <family>
#   --max-releases N --max-days D`, which writes the verdict as one line:
#   `engine-fresh\t<fresh|stale>\t<pin>\t<latest>\t<releases-behind>\t<days-behind>`.
#   `release-due` puts its consumer number on its producer for the same reason.
#
#   THE RECORD IS READ BY KIND, never by family name: the family is the
#   consumer's to declare, and a preset naming it would ship non-negotiable rule
#   1's violation into every binary.
#
#   NO RECORD IS SILENCE. A run that could not look clears the record rather than
#   leaving an old reading to stand in for a fresh one, and CI keeps no record at
#   all, so this gate holds in sessions and is silent in CI by design.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.engine_hygiene

import rego.v1

rules contains "release pin stale"

# EVERY NAME IS PREFIXED `eh_`: a preset's modules share one `package`, so a bare
# helper name would collide with the next module this bundle ships.
#
# EVERY HELPER IS DEFINED ABOVE ITS READER: regorus resolves a rule defined below
# the rule that reads it as undefined.
#
#MUTANT-SUITE crates/batten/tests/it/engine_install.rs
#MUTANT fresh-ignores-stale-record|s@^\tcolumns\[1\] == "stale"$@\tfalse@|a_stale_engine_fresh_record_fails_check

# Every `engine-fresh` line in the store, split into its six columns.
#
# The `is_object` guard is first because `some .. in null` is a hard evaluation
# FAULT, and a fault takes the whole bundle down rather than missing quietly.
eh_lines contains columns if {
	is_object(input.tree.records)
	some lines in input.tree.records
	is_array(lines)
	some line in lines
	is_string(line)
	startswith(line, "engine-fresh\t")
	columns := split(line, "\t")
	count(columns) == 6
}

violation contains {
	"rule": "release pin stale",
	"verdict": "release pin stale",
	"subjects": [{"artifact": sprintf("%s:behind-%s", [columns[2], columns[3]])}],
} if {
	some columns in eh_lines
	columns[1] == "stale"
}

# --- the load-time tier ------------------------------------------------------

eh_record(line) := {"tree": {"records": {"x": [line]}}}

test_a_stale_record_is_refused if {
	found := violation with input as eh_record("engine-fresh\tstale\tv1.0.0\tv1.4.0\t4\t20")
	{entry.subjects[0].artifact | some entry in found} == {"v1.0.0:behind-v1.4.0"}
}

test_a_fresh_record_is_clean if {
	count(violation) == 0 with input as eh_record("engine-fresh\tfresh\tv1.0.0\tv1.1.0\t1\t2")
}

test_no_record_is_silence if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}

test_a_torn_line_is_not_read if {
	count(violation) == 0 with input as eh_record("engine-fresh\tstale\tv1.0.0")
}

test_an_absent_record_store_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"records": null}}
}
