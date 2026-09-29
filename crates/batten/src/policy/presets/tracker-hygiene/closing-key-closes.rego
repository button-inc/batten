# METADATA
# description: |
#   A pull-request body that names its issue but never in closing form, so the
#   merge will not move the board (CLOUD-192, the subtraction CLOUD-674's; moved
#   into this preset from a consumer module under CLOUD-843).
#
#   A tracker's merged-event automation fires only for a CLOSING pull request.
#   Measured on consumer #1 as a controlled pair on one issue: a trailer-only
#   reference merged and never moved; a closing keyword merged and reached review
#   two seconds later.
#
#   TWO REFUSALS:
#
#     1. the body closes something — then every key the branch SERVED (the first
#        key of each `Refs:` trailer) must be closed too, or it is stranded on
#        the trunk below review;
#     2. the body closes nothing — then every key it NAMES is reported, unless a
#        declared hold marker says the pull request declines to complete it.
#
#   A marker NAMING keys exempts exactly those from the subtraction; a bare
#   marker declines the whole body. A branch serving no key is not judged by the
#   subtraction.
#
#   `record derive closing-key` records only KEY SETS — what the body names, what
#   it closes (the engine grammar's closing reading), what the branch served,
#   and what a marker holds. This decides.
#
#   COMPLETE OR TORN: each of the four readings appears exactly once.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
#MUTANT named-but-unclosed-passes|s@^\tcount(closing_closing) == 0$@\tfalse@|a_body_naming_its_issue_but_never_closing_it_is_refused
#MUTANT strand-never-fires|s@^\tsome key in closing_stranded$@\tsome key in set()@|a_body_closing_a_strict_subset_of_the_served_keys_is_refused
#MUTANT held-goes-global|s@^closing_hold_global if closing_field("hold") == "global"$@closing_hold_global if closing_hold_any@|a_keyed_marker_does_not_excuse_a_key_it_never_named
#MUTANT torn-record-passes|s@^\tcount(closing_present) != count(closing_readings)$@\tfalse@|a_closing_key_record_missing_a_reading_is_torn

rules contains "diff key other"

# EVERY NAME HERE IS PREFIXED `closing_`, for the shared package's reason.
closing_lines := input.tree.records["closing-key"]

closing_readings := {"named", "closing", "served", "hold"}

# `<reading>\t<key key …|->`, plus `hold\t<none|global|key key …>`.
#
# A SET, NOT A FUNCTION BINDING ONE VALUE: a reading written twice with two
# values would make a function raise `eval_conflict_error` — a fault that
# silences every rule in the package — where a set reads it as the torn record
# it is.
closing_values(name) := {columns[1] |
	some line in closing_lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == name
}

closing_field(name) := value if {
	candidates := closing_values(name)
	count(candidates) == 1
	some value in candidates
}

closing_present contains name if {
	some name in closing_readings
	count([line | some line in closing_lines; startswith(line, sprintf("%s\t", [name]))]) == 1
	closing_field(name)
}

closing_torn if {
	closing_lines
	count(closing_present) != count(closing_readings)
}

closing_keys(name) := set() if closing_field(name) in {"-", "none", "global"}

closing_keys(name) := result if {
	value := closing_field(name)
	not value in {"-", "none", "global"}
	result := {key | some key in split(value, " "); key != ""}
}

closing_named := closing_keys("named")

closing_closing := closing_keys("closing")

closing_served := closing_keys("served")

closing_held := closing_keys("hold")

closing_hold_any if closing_field("hold") != "none"

closing_hold_global if closing_field("hold") == "global"

# The subtraction (CLOUD-674), less any key a keyed marker names.
closing_stranded contains key if {
	some key in closing_served
	not key in closing_closing
	not key in closing_held
}

# 1. Closes something, strands the rest — unless a bare marker declines it all.
violation contains {
	"rule": "diff key other",
	"verdict": "diff key dropped",
	"subjects": [{"artifact": key}],
} if {
	not closing_torn
	count(closing_closing) > 0
	not closing_hold_global
	some key in closing_stranded
}

# 2. Closes nothing, and no marker declines — every named key is reported.
violation contains {
	"rule": "diff key other",
	"verdict": "diff key missing",
	"subjects": [{"artifact": key}],
} if {
	not closing_torn
	count(closing_closing) == 0
	not closing_hold_any
	some key in closing_named
}

violation contains {
	"rule": "diff key other",
	"verdict": "diff read partial",
	"subjects": [{"count": count(closing_present)}],
} if {
	closing_torn
}

# --- cases -------------------------------------------------------------------

closing_tree(named_, closing_, served_, hold_) := {"tree": {"records": {"closing-key": [
	sprintf("named\t%s", [named_]),
	sprintf("closing\t%s", [closing_]),
	sprintf("served\t%s", [served_]),
	sprintf("hold\t%s", [hold_]),
]}}}

test_closing_named_never_closed_is_refused if {
	found := violation with input as closing_tree("ACME-192", "-", "-", "none")
	{entry.verdict | some entry in found} == {"diff key missing"}
}

test_closing_a_close_passes if {
	count(violation) == 0 with input as closing_tree("ACME-192", "ACME-192", "ACME-192", "none")
}

test_closing_a_bare_marker_declines if {
	count(violation) == 0 with input as closing_tree("ACME-192", "-", "-", "global")
	count(violation) == 0 with input as closing_tree("ACME-1 ACME-2", "ACME-1", "ACME-1 ACME-2", "global")
}

test_closing_a_stranded_key_is_refused if {
	found := violation with input as closing_tree("ACME-1 ACME-2", "ACME-1", "ACME-1 ACME-2", "none")
	{entry.verdict | some entry in found} == {"diff key dropped"}
}

# The keyed marker must not take the global exit: `held` non-empty is per-key.
test_closing_a_keyed_marker_is_not_global if {
	found := violation with input as closing_tree("ACME-1 ACME-2", "ACME-1", "ACME-1 ACME-2 ACME-3", "ACME-2")
	{entry.subjects[0].artifact | some entry in found} == {"ACME-3"}
}

test_closing_no_refs_is_not_judged if {
	count(violation) == 0 with input as closing_tree("ACME-1 ACME-2", "ACME-1", "-", "none")
}

test_closing_a_missing_reading_is_torn if {
	found := violation with input as {"tree": {"records": {"closing-key": ["named\tACME-1", "closing\t-"]}}}
	{entry.verdict | some entry in found} == {"diff read partial"}
}
