# METADATA
# description: |
#   A pull-request body that defers a decision without naming the issue that
#   owns it (CLOUD-323, narrowed by CLOUD-338; moved into this preset from a
#   consumer module under CLOUD-843).
#
#   "What you decline to fix, you file", and a pull-request body is not a
#   durable home: nothing sweeps merged bodies. Measured on consumer #1, two
#   decisions landed on the trunk recorded only in a paragraph.
#
#   PARAGRAPH-SCOPED, AND THE CLAIMED KEYS DO NOT COUNT. Body-level key presence
#   carries no information — every pull request names a key — and a key the pull
#   request already CLAIMS names the work in hand, not a home for what it
#   defers. So a deferral is owned only by a key its own paragraph names that is
#   not in the claimed set.
#
#   `record derive deferral` finds the consumer's declared deferral shapes
#   outside code spans and records each hit as a paragraph NUMBER and the keys
#   that paragraph names — never its prose. An unresolvable claim is an empty
#   claimed set, which leaves every owner standing: the fail-open direction.
#
#   THE CENSUS CLOSES THE RECORD.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
#MUTANT ownerless-deferral-passes|s@^\tcount(deferral_owners(entry)) == 0$@\tfalse@|a_deferral_with_no_owner_in_its_paragraph_is_refused
#MUTANT claimed-key-owns|s@^\tnot key in deferral_claimed$@\ttrue@|a_deferral_owned_only_by_the_claimed_issue_is_refused
#MUTANT torn-record-passes|s@^\tcount(deferral_census) != 1$@\tfalse@|a_deferral_record_without_its_census_is_torn

rules contains "prose own other"

# EVERY NAME HERE IS PREFIXED `deferral_`, for the shared package's reason.
deferral_lines := input.tree.records.deferral

# `deferral\t<paragraph>\t<key key …|->`.
deferral_entries contains {"paragraph": columns[1], "keys": deferral_keys_of(columns[2])} if {
	some line in deferral_lines
	columns := split(line, "\t")
	count(columns) == 3
	columns[0] == "deferral"
}

# `claimed\t<key key …|->`, at most one line.
deferral_claimed contains key if {
	some line in deferral_lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == "claimed"
	some key in deferral_keys_of(columns[1])
}

deferral_keys_of(field) := set() if field == "-"

deferral_keys_of(field) := result if {
	field != "-"
	result := {key | some key in split(field, " "); key != ""}
}

deferral_deferral_lines contains line if {
	some line in deferral_lines
	startswith(line, "deferral\t")
}

deferral_census contains to_number(raw) if {
	some line in deferral_lines
	startswith(line, "census\tdeferrals=")
	raw := substring(line, count("census\tdeferrals="), -1)
	regex.match(`^[0-9]+$`, raw)
}

deferral_torn if {
	deferral_lines
	count(deferral_census) != 1
}

deferral_torn if {
	some n in deferral_census
	n != count(deferral_deferral_lines)
}

deferral_owners(entry) := {key |
	some key in entry.keys
	not key in deferral_claimed
}

violation contains {
	"rule": "prose own other",
	"verdict": "prose own unnamed",
	"subjects": [{"artifact": sprintf("paragraph:%s", [entry.paragraph])}],
} if {
	not deferral_torn
	some entry in deferral_entries
	count(deferral_owners(entry)) == 0
}

violation contains {
	"rule": "prose own other",
	"verdict": "prose read partial",
	"subjects": [{"count": count(deferral_census)}],
} if {
	deferral_torn
}

# --- cases -------------------------------------------------------------------

deferral_tree(lines) := {"tree": {"records": {"deferral": lines}}}

test_deferral_an_ownerless_deferral_is_refused if {
	found := violation with input as deferral_tree(["claimed\t-", "deferral\t2\t-", "census\tdeferrals=1"])
	{entry.verdict | some entry in found} == {"prose own unnamed"}
}

test_deferral_naming_an_unclaimed_owner_passes if {
	found := violation with input as deferral_tree([
		"claimed\tACME-1",
		"deferral\t1\tACME-1 ACME-2",
		"census\tdeferrals=1",
	])
	count(found) == 0
}

test_deferral_the_claimed_key_alone_does_not_own_it if {
	found := violation with input as deferral_tree(["claimed\tACME-1", "deferral\t1\tACME-1", "census\tdeferrals=1"])
	count(found) == 1
}

test_deferral_none_is_clean if {
	found := violation with input as deferral_tree(["claimed\t-", "census\tdeferrals=0"])
	count(found) == 0
}

test_deferral_a_missing_census_is_torn if {
	found := violation with input as deferral_tree(["claimed\t-", "deferral\t1\tACME-2"])
	{entry.verdict | some entry in found} == {"prose read partial"}
}
