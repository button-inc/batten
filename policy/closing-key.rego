# A PR body that names its issue but never in closing form, so the merge will not
# move the board (ported off `mise-tasks/closing-key-check.sh` under CLOUD-1717;
# the predicate is CLOUD-192's, the subtraction CLOUD-674's).
#
# The tracker's merged-event automation fires only for a CLOSING pull request.
# Measured as a controlled pair on one issue: `Refs: CLOUD-192` merged and never
# moved; `Closes CLOUD-192` merged and reached In Review two seconds later.
#
# TWO REFUSALS, IN THE RETIRED ORDER:
#
#   1. the body closes something — then every key the branch SERVED (the first
#      key of each `Refs:` trailer) must be closed too, or it is stranded on
#      `main` below In Review (CLOUD-674, measured at `b2f8992`);
#   2. the body closes nothing — then every key it NAMES is reported, unless a
#      line-anchored `DO-NOT-CLOSE` says the PR declines to complete its issue.
#
# A marker NAMING keys exempts exactly those from the subtraction; a bare marker
# declines the whole body. A branch serving no `Refs:` key is not judged by the
# subtraction, and a body naming no key at all is `pr-names-an-issue`'s case.
#
# THE SPLIT IS §5's AND RULE 4's. `[tasks.closing-key-record]` reads the body and
# the branch's log and records only KEY SETS: what the body names, what it closes
# (the engine grammar's own `keys_closed_in`, which also knows a disclaimer is not
# a close), what the branch served, and what a marker holds. This decides.
#
# COMPLETE OR TORN: each of the four readings appears exactly once, and a record
# missing one is refused rather than decided over part of the answer.
#
#MUTANT-SUITE crates/batten/tests/it/closing_key.rs
#MUTANT named-but-unclosed-passes|s@^\tcount(closing) == 0$@\tfalse@|a_body_naming_its_issue_but_never_closing_it_is_refused
#MUTANT strand-never-fires|s@^\tsome key in stranded$@\tsome key in set()@|a_body_closing_a_strict_subset_of_the_served_keys_is_refused
#MUTANT held-goes-global|s@^hold_global if field("hold") == "global"$@hold_global if hold_any@|a_keyed_marker_does_not_excuse_a_key_it_never_named
#MUTANT torn-record-passes|s@^\tcount(present) != count(readings)$@\tfalse@|a_record_missing_a_reading_is_torn_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.closing_key

import rego.v1

rules contains "diff key other"

# The producer's lines, or nothing — absent is could-not-look and silent.
lines := input.tree.records["closing-key"]

readings := {"named", "closing", "served", "hold"}

# `<reading>\t<key key …|->`, plus `hold\t<none|global|key key …>`.
#
# A SET, NOT A FUNCTION BINDING ONE VALUE: a reading written twice with two
# values would make a function raise `eval_conflict_error` — a fault that
# silences every rule here — where a set reads it as the torn record it is.
values(name) := {columns[1] |
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == name
}

field(name) := value if {
	candidates := values(name)
	count(candidates) == 1
	some value in candidates
}

present contains name if {
	some name in readings
	count([line | some line in lines; startswith(line, sprintf("%s\t", [name]))]) == 1
	field(name)
}

torn if {
	lines
	count(present) != count(readings)
}

keys(name) := set() if field(name) in {"-", "none", "global"}

keys(name) := result if {
	value := field(name)
	not value in {"-", "none", "global"}
	result := {key | some key in split(value, " "); key != ""}
}

named := keys("named")

closing := keys("closing")

served := keys("served")

held := keys("hold")

hold_any if field("hold") != "none"

hold_global if field("hold") == "global"

# The subtraction (CLOUD-674), less any key a keyed marker names.
stranded contains key if {
	some key in served
	not key in closing
	not key in held
}

# 1. Closes something, strands the rest — unless a bare marker declines it all.
violation contains {
	"rule": "diff key other",
	"verdict": "diff key dropped",
	"subjects": [{"artifact": key}],
} if {
	not torn
	count(closing) > 0
	not hold_global
	some key in stranded
}

# 2. Closes nothing, and no marker declines — every named key is reported.
violation contains {
	"rule": "diff key other",
	"verdict": "diff key missing",
	"subjects": [{"artifact": key}],
} if {
	not torn
	count(closing) == 0
	not hold_any
	some key in named
}

violation contains {
	"rule": "diff key other",
	"verdict": "diff read partial",
	"subjects": [{"count": count(present)}],
} if {
	torn
}

# The keyed marker must not take the global exit: `held` non-empty is per-key.
test_a_keyed_marker_is_not_global if {
	found := violation with input as tree("CLOUD-1 CLOUD-2", "CLOUD-1", "CLOUD-1 CLOUD-2 CLOUD-3", "CLOUD-2")
	{entry.subjects[0].artifact | some entry in found} == {"CLOUD-3"}
}

# --- cases -------------------------------------------------------------------

tree(named_, closing_, served_, hold_) := {"tree": {"records": {"closing-key": [
	sprintf("named\t%s", [named_]),
	sprintf("closing\t%s", [closing_]),
	sprintf("served\t%s", [served_]),
	sprintf("hold\t%s", [hold_]),
]}}}

test_named_never_closed_is_refused if {
	found := violation with input as tree("CLOUD-192", "-", "-", "none")
	{entry.verdict | some entry in found} == {"diff key missing"}
}

test_a_close_passes if {
	count(violation) == 0 with input as tree("CLOUD-192", "CLOUD-192", "CLOUD-192", "none")
}

test_a_bare_marker_declines if {
	count(violation) == 0 with input as tree("CLOUD-192", "-", "-", "global")
	count(violation) == 0 with input as tree("CLOUD-1 CLOUD-2", "CLOUD-1", "CLOUD-1 CLOUD-2", "global")
}

test_a_stranded_key_is_refused if {
	found := violation with input as tree("CLOUD-1 CLOUD-2", "CLOUD-1", "CLOUD-1 CLOUD-2", "none")
	{entry.verdict | some entry in found} == {"diff key dropped"}
}

test_no_refs_is_not_judged if {
	count(violation) == 0 with input as tree("CLOUD-1 CLOUD-2", "CLOUD-1", "-", "none")
}

test_a_missing_reading_is_torn if {
	found := violation with input as {"tree": {"records": {"closing-key": ["named\tCLOUD-1", "closing\t-"]}}}
	{entry.verdict | some entry in found} == {"diff read partial"}
}
