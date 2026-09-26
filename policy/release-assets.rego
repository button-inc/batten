# A release carries one archive per target the dist matrix builds, every
# platform-independent asset the release job uploads, and a checksum manifest that
# covers exactly those assets with matching bytes (ported off
# `mise-tasks/release-assets-check.sh` under CLOUD-1717; the predicates are
# CLOUD-258's, CLOUD-262's and CLOUD-278's).
#
# `release-artifacts.yml` failed on every release from v0.0.31 to v0.0.36 and no
# binary shipped, unnoticed, because a `release`-triggered run reaches no PR and no
# gate. This is that missing signal, run on a clock (`release-assets.yml`) because
# it is a property of the world rather than of a commit.
#
# THE SPLIT IS §5's. `[tasks.release-assets-record]` reads the workflow's own
# matrix and upload lines, the release's asset list, and — when a manifest is
# on it — the manifest's entries and `sha256sum -c`'s failures, and records only
# NAMES. Every set comparison is here: which target has no archive, which asset
# is absent, whether the manifest is missing, lists itself, covers nothing, omits
# an asset, names an orphan, or disagrees on bytes. The producer refuses where
# the retired program exited 2 — an unreadable workflow, no targets, no upload
# line, no tag, an unreadable release, a failed download — and writes nothing.
#
# ARCHIVE, NOT TRIPLE: a composed leg also uploads `<stem>.spdx.json`, whose name
# carries the same triple, so a target is present only when an asset naming it
# ends in `.tar.gz` or `.zip` — the document must not stand in for the binary.
#
# MISMATCH ONLY ONCE THE NAMES AGREE, as the retired program ordered it: with a
# name missing, `sha256sum -c` reports that as a failure too, and one defect
# would be counted twice under two rule ids.
#
# THE CENSUS CLOSES THE RECORD and counts every kind of line above it.
#
#MUTANT-SUITE crates/batten/tests/it/release_assets.rs
#MUTANT missing-archive-passes|s@^\tnot archived(target)$@\tfalse@|a_release_with_only_the_schema_is_refused
#MUTANT mismatch-passes|s@^\tsome name in mismatched$@\tsome name in set()@|a_byte_mismatch_is_refused_once_the_names_agree
#MUTANT torn-record-passes|s@^\tnot census_agrees$@\tfalse@|a_release_assets_record_without_its_census_is_torn_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.release_assets

import rego.v1

rules contains "release grade other"

lines := input.tree.records["release-assets"]

kinds := ["target", "extra", "asset", "manifest", "covered", "mismatch"]

of(kind) := {columns[1] |
	some line in lines
	columns := split(line, "\t")
	count(columns) == 2
	columns[0] == kind
}

targets := of("target")

extras := of("extra")

assets := of("asset")

covered_raw := of("covered")

mismatched_raw := of("mismatch")

manifest := name if {
	names := of("manifest")
	count(names) == 1
	some name in names
}

# `census\ttarget=<n>\textra=<n>\tasset=<n>\tmanifest=<n>\tcovered=<n>\tmismatch=<n>`.
census_counts[pair[0]] := pair[1] if {
	some line in lines
	startswith(line, "census\t")
	some field in array.slice(split(line, "\t"), 1, 100)
	pair := split(field, "=")
	count(pair) == 2
	regex.match(data.batten.patterns["whole-number"], pair[1])
}

census_agrees if {
	count([line | some line in lines; startswith(line, "census\t")]) == 1
	every kind in kinds {
		to_number(census_counts[kind]) == count([line | some line in lines; startswith(line, sprintf("%s\t", [kind]))])
	}
	manifest
}

torn if {
	lines
	not census_agrees
}

archived(target) if {
	some name in assets
	contains(name, target)
	regex.match(data.batten.patterns["release-archive"], name)
}

violation contains {
	"rule": "release grade other",
	"verdict": "release ship missing",
	"subjects": [{"artifact": target}],
} if {
	not torn
	some target in targets
	not archived(target)
}

violation contains {
	"rule": "release grade other",
	"verdict": "release ship missing",
	"subjects": [{"artifact": name}],
} if {
	not torn
	some name in extras
	not name in assets
}

manifest_on_release if manifest in assets

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-missing", [manifest])}],
} if {
	not torn
	not manifest_on_release
}

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-self", [manifest])}],
} if {
	not torn
	manifest_on_release
	manifest in covered_raw
}

covered := covered_raw - {manifest}

expected := assets - {manifest}

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-empty", [manifest])}],
} if {
	not torn
	manifest_on_release
	count(covered) == 0
}

omitted := {name | some name in expected; not name in covered}

orphaned := {name | some name in covered; not name in assets}

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-omits", [name])}],
} if {
	not torn
	manifest_on_release
	count(covered) > 0
	some name in omitted
}

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-orphan", [name])}],
} if {
	not torn
	manifest_on_release
	count(covered) > 0
	some name in orphaned
}

mismatched := mismatched_raw if {
	count(omitted) == 0
	count(orphaned) == 0
} else := set()

violation contains {
	"rule": "release grade other",
	"verdict": "release pin broken",
	"subjects": [{"artifact": sprintf("%s:checksums-mismatch", [name])}],
} if {
	not torn
	manifest_on_release
	count(covered) > 0
	some name in mismatched
}

violation contains {
	"rule": "release grade other",
	"verdict": "release read partial",
	"subjects": [{"count": count(lines)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

record(body) := {"tree": {"records": {"release-assets": array.concat(body, [sprintf(
	"census\ttarget=%d\textra=%d\tasset=%d\tmanifest=%d\tcovered=%d\tmismatch=%d",
	[
		count([l | some l in body; startswith(l, "target\t")]),
		count([l | some l in body; startswith(l, "extra\t")]),
		count([l | some l in body; startswith(l, "asset\t")]),
		count([l | some l in body; startswith(l, "manifest\t")]),
		count([l | some l in body; startswith(l, "covered\t")]),
		count([l | some l in body; startswith(l, "mismatch\t")]),
	],
)])}}}

healthy := [
	"target\tx86_64-unknown-linux-gnu",
	"extra\tbatten.schema.json",
	"manifest\tSHA256SUMS",
	"asset\tbatten-x86_64-unknown-linux-gnu.tar.gz",
	"asset\tbatten.schema.json",
	"asset\tSHA256SUMS",
	"covered\tbatten-x86_64-unknown-linux-gnu.tar.gz",
	"covered\tbatten.schema.json",
]

test_a_healthy_release_is_clean if {
	count(violation) == 0 with input as record(healthy)
}

test_an_sbom_does_not_stand_in_for_an_archive if {
	found := violation with input as record([
		"target\tx86_64-unknown-linux-gnu",
		"manifest\tSHA256SUMS",
		"asset\tbatten-x86_64-unknown-linux-gnu.spdx.json",
		"asset\tSHA256SUMS",
		"covered\tbatten-x86_64-unknown-linux-gnu.spdx.json",
	])
	{entry.verdict | some entry in found} == {"release ship missing"}
}

test_a_mismatch_is_held_back_while_a_name_disagrees if {
	found := violation with input as record(array.concat(healthy, [
		"covered\tghost.tar.gz",
		"mismatch\tghost.tar.gz",
	]))
	{entry.subjects[0].artifact | some entry in found} == {"ghost.tar.gz:checksums-orphan"}
}

test_a_missing_census_is_torn if {
	found := violation with input as {"tree": {"records": {"release-assets": healthy}}}
	{entry.verdict | some entry in found} == {"release read partial"}
}
