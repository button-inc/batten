# METADATA
# description: |
#   A published release's checksum manifest covers exactly the release's own
#   assets, never itself, and every entry's bytes agree (CLOUD-278, lifted out of
#   `policy/release-assets.rego` under CLOUD-843).
#
#   A manifest a packager cannot trust pins nothing, and every way it goes wrong
#   stays silent without a gate: absent, listing itself, covering nothing,
#   omitting an asset the release carries, naming one it does not, or
#   disagreeing on bytes because an asset was re-uploaded after the manifest was
#   cut. None of those is a fact about any one consumer, so the decision ships
#   here and each consumer supplies only the record.
#
#   THE RECORD IS `batten record release`'s, and this module reads EVERY record
#   rather than one by name: the family is the consumer's to declare, and a
#   preset naming it would ship non-negotiable rule 1's violation into every
#   binary. It narrows on the KIND column instead — `release-tag`,
#   `release-manifest`, `release-asset`, `release-covered`, `release-mismatch`
#   and the closing `release-census` — which is why the producer prefixes them.
#
#   MISMATCH ONLY ONCE THE NAMES AGREE: with a name missing, the byte check
#   reports that as a failure too, and one defect would be counted twice under
#   two pointers.
#
#   THE CENSUS CLOSES THE RECORD and counts every kind above it, so a record torn
#   mid-write is its own finding rather than a partial release judged whole.
#
#   WHAT THIS DOES NOT DECIDE: which archives and documents a release MUST
#   carry. That list is read off the consumer's own build workflow, so it is the
#   consumer's module; this one decides only whether the manifest tells the truth
#   about what the release does carry.
#
#   Patterns are INLINE, as a preset's must be: a preset reaches a consumer who
#   wrote no `[[pattern]]` row, and a registry read would decide nothing there.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_hygiene

import rego.v1

rules contains "release pin broken"

rules contains "release record torn"

# EVERY NAME IS PREFIXED `rh_`: a preset's modules share one `package`, so a bare
# helper name would collide with the next module this bundle ships, and regorus
# reports that as an engine fault rather than an authoring mistake.
#
# EVERY HELPER IS DEFINED ABOVE ITS READER: regorus resolves a rule defined below
# the rule that reads it as undefined, and the load-time tier at the bottom
# cannot see it because its references all point backwards.
#
#MUTANT-SUITE crates/batten/tests/it/release_hygiene.rs
#MUTANT manifest-absence-passes|s@^\tnot rh_manifest(lines) in rh_of(lines, "release-asset")$@\tfalse@|the_release_hygiene_preset_refuses_a_release_with_no_manifest
#MUTANT omission-passes|s@^\tsome omitted in rh_omitted(lines)$@\tsome omitted in set()@|the_release_hygiene_preset_refuses_an_omission_and_an_orphan
#MUTANT mismatch-passes|s@^\tsome mismatched in rh_mismatched(lines)$@\tsome mismatched in set()@|the_release_hygiene_preset_refuses_a_byte_mismatch_once_the_names_agree
#MUTANT torn-record-passes|s@^\tnot rh_whole(lines)$@\tfalse@|the_release_hygiene_preset_refuses_a_torn_record

# The census's counted kinds, each spelled `release-<key>` in the record.
rh_counted := ["tag", "manifest", "asset", "covered", "mismatch"]

# Whether a line is one of this practice's kinds.
rh_is_kind(line) if {
	some key in rh_counted
	startswith(line, sprintf("release-%s\t", [key]))
}

rh_is_kind(line) if startswith(line, "release-census\t")

# Every record carrying at least one of this practice's lines, by family name.
#
# The `is_object` guard is first because `some .. in null` is a hard evaluation
# FAULT, and a fault takes the whole bundle down rather than missing quietly.
rh_records[name] := lines if {
	is_object(input.tree.records)
	some name, lines in input.tree.records
	is_array(lines)
	some line in lines
	rh_is_kind(line)
}

# The values of one two-column kind in one record.
rh_of(lines, kind) := {columns[1] |
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == kind
}

# The census's `key=count` pairs, whole numbers only.
rh_census(lines) := {pair[0]: pair[1] |
	some line in lines
	startswith(line, "release-census\t")
	some field in array.slice(split(line, "\t"), 1, 100)
	pair := split(field, "=")
	count(pair) == 2
	regex.match(`^[0-9]+$`, pair[1])
}

# One closing census, agreeing with every kind it counts, and exactly one
# manifest named.
rh_whole(lines) if {
	count([line | some line in lines; startswith(line, "release-census\t")]) == 1
	census := rh_census(lines)
	every key in rh_counted {
		to_number(census[key]) == count([line | some line in lines; startswith(line, sprintf("release-%s\t", [key]))])
	}
	count(rh_of(lines, "release-manifest")) == 1
}

rh_manifest(lines) := name if {
	names := rh_of(lines, "release-manifest")
	count(names) == 1
	some name in names
}

# What the manifest covers, itself excluded.
rh_covered(lines) := rh_of(lines, "release-covered") - {rh_manifest(lines)}

# What the manifest should cover: every asset but itself.
rh_expected(lines) := rh_of(lines, "release-asset") - {rh_manifest(lines)}

rh_omitted(lines) := {name |
	some name in rh_expected(lines)
	not name in rh_covered(lines)
}

rh_orphaned(lines) := {name |
	some name in rh_covered(lines)
	not name in rh_of(lines, "release-asset")
}

# The byte failures, held back while any name disagrees.
rh_mismatched(lines) := rh_of(lines, "release-mismatch") if {
	count(rh_omitted(lines)) == 0
	count(rh_orphaned(lines)) == 0
} else := set()

# Whether this record's manifest is on the release at all.
rh_carried(lines) if rh_manifest(lines) in rh_of(lines, "release-asset")

violation contains {
	"rule": "release record torn",
	"verdict": "release record torn",
	"subjects": [{"count": count(lines)}],
} if {
	some lines in rh_records
	not rh_whole(lines)
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-missing", [rh_manifest(lines)])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	not rh_manifest(lines) in rh_of(lines, "release-asset")
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-self", [rh_manifest(lines)])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	rh_carried(lines)
	rh_manifest(lines) in rh_of(lines, "release-covered")
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-empty", [rh_manifest(lines)])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	rh_carried(lines)
	count(rh_covered(lines)) == 0
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-omits", [omitted])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	rh_carried(lines)
	count(rh_covered(lines)) > 0
	some omitted in rh_omitted(lines)
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-orphan", [orphan])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	rh_carried(lines)
	count(rh_covered(lines)) > 0
	some orphan in rh_orphaned(lines)
}

violation contains {
	"rule": "release pin broken",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-mismatch", [mismatched])}],
} if {
	some lines in rh_records
	rh_whole(lines)
	rh_carried(lines)
	count(rh_covered(lines)) > 0
	some mismatched in rh_mismatched(lines)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/release_hygiene.rs` is the
# tier that proves the ENGINE builds what it reads, with the empty vocabulary.

rh_record(body) := {"tree": {"records": {"x": array.concat(body, [sprintf(
	"release-census\ttag=%d\tmanifest=%d\tasset=%d\tcovered=%d\tmismatch=%d",
	[
		count([l | some l in body; startswith(l, "release-tag\t")]),
		count([l | some l in body; startswith(l, "release-manifest\t")]),
		count([l | some l in body; startswith(l, "release-asset\t")]),
		count([l | some l in body; startswith(l, "release-covered\t")]),
		count([l | some l in body; startswith(l, "release-mismatch\t")]),
	],
)])}}}

rh_healthy := [
	"release-tag\tv1",
	"release-manifest\tSUMS",
	"release-asset\ta.tar.gz",
	"release-asset\tb.json",
	"release-asset\tSUMS",
	"release-covered\ta.tar.gz",
	"release-covered\tb.json",
]

rh_pointers(found) := {entry.subjects[0].artifact | some entry in found}

test_a_healthy_release_is_clean if {
	count(violation) == 0 with input as rh_record(rh_healthy)
}

test_no_manifest_on_the_release_is_refused if {
	found := violation with input as rh_record([
		"release-tag\tv1",
		"release-manifest\tSUMS",
		"release-asset\ta.tar.gz",
	])
	rh_pointers(found) == {"SUMS:checksums-missing"}
}

test_a_manifest_listing_only_itself_is_self_and_empty if {
	found := violation with input as rh_record([
		"release-tag\tv1",
		"release-manifest\tSUMS",
		"release-asset\ta.tar.gz",
		"release-asset\tSUMS",
		"release-covered\tSUMS",
		"release-mismatch\tSUMS",
	])
	rh_pointers(found) == {"SUMS:checksums-self", "SUMS:checksums-empty"}
}

test_an_omission_is_named_and_nothing_else if {
	found := violation with input as rh_record([
		"release-tag\tv1",
		"release-manifest\tSUMS",
		"release-asset\ta.tar.gz",
		"release-asset\tb.json",
		"release-asset\tSUMS",
		"release-covered\ta.tar.gz",
	])
	rh_pointers(found) == {"b.json:checksums-omits"}
}

test_a_mismatch_is_held_back_while_a_name_disagrees if {
	found := violation with input as rh_record(array.concat(rh_healthy, [
		"release-covered\tghost.zip",
		"release-mismatch\tghost.zip",
	]))
	rh_pointers(found) == {"ghost.zip:checksums-orphan"}
}

test_a_mismatch_once_the_names_agree_is_refused if {
	found := violation with input as rh_record(array.concat(rh_healthy, ["release-mismatch\ta.tar.gz"]))
	rh_pointers(found) == {"a.tar.gz:checksums-mismatch"}
}

test_a_record_with_no_census_is_torn if {
	found := violation with input as {"tree": {"records": {"x": rh_healthy}}}
	{entry.verdict | some entry in found} == {"release record torn"}
}

# ANOTHER RECORDER'S LINES are not this practice's: the store holds every
# recorder's records, and a bare `asset` is a word anyone might write.
test_another_recorders_record_is_not_read if {
	count(violation) == 0 with input as {"tree": {"records": {"y": ["asset\ta", "row\t{}"]}}}
}

test_an_absent_record_store_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"records": null}}
}
