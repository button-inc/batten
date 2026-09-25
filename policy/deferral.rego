# A PR body that defers a decision without naming the issue that owns it (ported
# off `mise-tasks/deferral-check.sh` under CLOUD-1717; the predicate is
# CLOUD-323's, narrowed by CLOUD-338).
#
# "What you decline to fix, you file", and a PR body is not a durable home:
# nothing sweeps merged bodies. Two decisions landed on `main` during CLOUD-164
# recorded only in a paragraph (CLOUD-321, CLOUD-322).
#
# PARAGRAPH-SCOPED, AND THE CLAIMED KEYS DO NOT COUNT. Body-level key presence
# carries no information — every PR names a key — and a key the PR already
# CLAIMS names the work in hand, not a home for what it defers (CLOUD-338,
# measured on #275). So a deferral is owned only by a key its own paragraph
# names that is not in the claimed set.
#
# THE SPLIT IS §5's AND RULE 4's. The producer, `[tasks.deferral-record]`,
# reads the body, finds the two measured shapes (`judgement call`, `not
# verified`) outside code spans, and records each hit as a paragraph NUMBER and
# the keys that paragraph names — never its prose. This module subtracts and
# decides. An unresolvable claim is an empty claimed set, which leaves every
# owner standing: the fail-open direction the retired program chose.
#
# THE CENSUS CLOSES THE RECORD: `census\tdeferrals=<n>` counts the `deferral`
# lines above it, and a record missing it or disagreeing with it is torn.
#
#MUTANT-SUITE crates/batten/tests/it/deferral.rs
#MUTANT ownerless-deferral-passes|s@^\tcount(owners(entry)) == 0$@\tfalse@|a_deferral_with_no_owner_in_its_paragraph_is_refused
#MUTANT claimed-key-owns|s@^\tnot key in claimed$@\ttrue@|a_deferral_owned_only_by_the_claimed_issue_is_refused
#MUTANT torn-record-passes|s@^\tcount(census) != 1$@\tfalse@|a_record_without_its_census_is_torn_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.deferral

import rego.v1

rules contains "prose own other"

# The producer's lines, or nothing — absent is could-not-look and silent.
lines := input.tree.records.deferral

# `deferral\t<paragraph>\t<key key …|->`.
entries contains {"paragraph": columns[1], "keys": keys_of(columns[2])} if {
	some line in lines
	columns := split(line, "\t")
	count(columns) == 3
	columns[0] == "deferral"
}

# `claimed\t<key key …|->`, at most one line.
claimed contains key if {
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == "claimed"
	some key in keys_of(columns[1])
}

keys_of(field) := set() if field == "-"

keys_of(field) := result if {
	field != "-"
	result := {key | some key in split(field, " "); key != ""}
}

deferral_lines contains line if {
	some line in lines
	startswith(line, "deferral\t")
}

census contains to_number(raw) if {
	some line in lines
	startswith(line, "census\tdeferrals=")
	raw := substring(line, count("census\tdeferrals="), -1)
	regex.match(data.batten.patterns["whole-number"], raw)
}

torn if {
	lines
	count(census) != 1
}

torn if {
	some n in census
	n != count(deferral_lines)
}

owners(entry) := {key |
	some key in entry.keys
	not key in claimed
}

violation contains {
	"rule": "prose own other",
	"verdict": "prose own unnamed",
	"subjects": [{"artifact": sprintf("paragraph:%s", [entry.paragraph])}],
} if {
	not torn
	some entry in entries
	count(owners(entry)) == 0
}

violation contains {
	"rule": "prose own other",
	"verdict": "prose read partial",
	"subjects": [{"count": count(census)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

tree(lines) := {"tree": {"records": {"deferral": lines}}}

test_an_ownerless_deferral_is_refused if {
	found := violation with input as tree(["claimed\t-", "deferral\t2\t-", "census\tdeferrals=1"])
	{entry.verdict | some entry in found} == {"prose own unnamed"}
}

test_a_deferral_naming_an_unclaimed_owner_passes if {
	found := violation with input as tree(["claimed\tCLOUD-1", "deferral\t1\tCLOUD-1 CLOUD-2", "census\tdeferrals=1"])
	count(found) == 0
}

test_the_claimed_key_alone_does_not_own_it if {
	found := violation with input as tree(["claimed\tCLOUD-1", "deferral\t1\tCLOUD-1", "census\tdeferrals=1"])
	count(found) == 1
}

test_no_deferral_is_clean if {
	found := violation with input as tree(["claimed\t-", "census\tdeferrals=0"])
	count(found) == 0
}

test_a_missing_census_is_torn if {
	found := violation with input as tree(["claimed\t-", "deferral\t1\tCLOUD-2"])
	{entry.verdict | some entry in found} == {"prose read partial"}
}
