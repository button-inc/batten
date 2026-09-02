# METADATA
# description: |
#   The successor for `sbom-check` (CLOUD-262, retired under CLOUD-1318).
#
#   The published SBOM is read by whoever is doing vendor review rather than by
#   anyone here who could notice it is wrong, and nothing in the Rust build reads
#   it — so a wrong inventory is not merely unused, it is a false claim about what
#   shipped. That is what makes it worth gating.
#
#   THE SCAN STAYS OUTSIDE, and that is house style §5 rather than a workaround:
#   `check` is `read` and structurally cannot spawn, so `syft` remains a command on
#   PATH (§9's prior art) and `mise-tasks/sbom.sh` remains the producer that
#   derives the documents. What moved here is the ADJUDICATION — the half that had
#   no successor, because a module asking what a scan found read undefined and
#   decided nothing.
#
#   TWO OF THE PREDICATES NEED NO RECORD AT ALL, which is what keeps the producer's
#   trusted surface narrow. `sbom-package-drift`'s expected count is
#   `Cargo.lock`'s own `source = ` lines, and `sbom-action-unmapped` is every
#   SHA-pinned `uses:` in a workflow against `mise-tasks/sbom-actions.tsv`'s key
#   column. Both are properties of committed text, so they are decided here from
#   `input.tree.lines` and the producer cannot get them wrong on this module's
#   behalf. Only the counts that require reading a derived document — which this
#   surface cannot open — travel through `input.tree["tool-verdict"]`.
#
#   THE EXPECTED COUNT IS THE LOCKFILE'S *SOURCED* PACKAGES, NOT ALL OF THEM
#   (CLOUD-664). syft 1.50.0 deliberately gives the local workspace member no
#   registry purl (anchore/syft#5105): `batten` is `publish = false` and is in no
#   registry, so a `pkg:cargo/batten@...` coordinate would assert a registry
#   presence that does not exist. An entry carrying a `source` key is a registry or
#   git dependency and gets a purl; one without is local to this workspace and does
#   not. Stating the invariant over the thing that actually predicts a purl also
#   keeps holding if the workspace grows a second member, where subtracting a
#   hardcoded 1 would not.
#
#   THREE ANSWERS, AND EMPTY IS A FINDING HERE. ABSENT is could-not-look — nothing
#   has scanned this tree, which is the ordinary state on a checkout whose globs
#   never fired, and refusing there would deny every clone until a producer runs.
#   PRESENT AND EMPTY is the producer having recorded nothing, which would make
#   every count below pass over an absent key, so it refuses — `hook-profile`'s
#   reading, for `hook-profile`'s reason.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.sbom_inventory

import rego.v1

rules contains "sbom-empty"

rules contains "sbom-unrecorded"

rules contains "sbom-package-drift"

rules contains "sbom-unstable"

rules contains "sbom-components-inflated"

rules contains "sbom-supplier-unset"

rules contains "sbom-copyright-unenriched"

rules contains "sbom-license-unenriched"

rules contains "sbom-action-unenriched"

rules contains "sbom-action-unmapped"

# The lockfile the cargo count is stated against, and the table every SHA-pinned
# action must appear in. Both are committed text this row declares as
# `line_sources`, so they are read here rather than trusted from a record.
lockfile := "Cargo.lock"

actions_table := "mise-tasks/sbom-actions.tsv"

# The recorded scan, guarded. `null` is a hard evaluation FAULT under `some .. in`
# rather than a silent miss, and an id nothing recorded is absent from the map.
scan := verdict if {
	is_object(input.tree["tool-verdict"])
	verdict := input.tree["tool-verdict"].sbom
}

# A recorded count, as a number. A key the producer did not write leaves this
# undefined, so every rule reading it abstains rather than comparing against zero
# — the difference between "the scan says none" and "nobody recorded it".
count_of(key) := value if {
	raw := scan[key]
	value := to_number(raw)
}

# --- the scan is unusable ----------------------------------------------------

# AN SBOM THAT CATALOGS NOTHING MUST NOT REPORT GREEN. A scan whose catalogers all
# missed would otherwise pass every equality below trivially: two empty documents
# agree, and an empty count matches an empty count.
violation contains {
	"rule": "sbom-empty",
	"verdict": "tool read broken",
	"subjects": [{"count": count_of(format)}],
} if {
	some format in ["spdx-cargo", "cdx-cargo"]
	count_of(format) == 0
}

# PRESENT AND EMPTY: the producer ran and wrote no counts, so nothing below has an
# input. Told apart from ABSENT by `is_object` plus the count — an id nothing
# recorded never binds `scan` at all.
violation contains {
	"rule": "sbom-unrecorded",
	"verdict": "tool read broken",
	"subjects": [{"artifact": "sbom"}],
} if {
	is_object(scan)
	count(scan) == 0
}

# TWO SCANS OF ONE TREE MUST PRODUCE IDENTICAL BYTES once the fields that
# legitimately vary are removed — a fresh document namespace and creation time in
# SPDX, a fresh serial number and timestamp in CycloneDX. This is what makes the
# published document a function of the source rather than of when it was cut.
violation contains {
	"rule": "sbom-unstable",
	"verdict": "tool read broken",
	"subjects": [{"artifact": format}],
} if {
	some format in ["spdx-stable", "cdx-stable"]
	scan[format] != "yes"
}

# A DOCUMENT THAT DESCRIBES NOTHING is could-not-look rather than a clean
# inventory: the subject is what the component counts are measured against, so
# without it every one of them is taken over the wrong set.
violation contains {
	"rule": "sbom-unrecorded",
	"verdict": "tool read broken",
	"subjects": [{"artifact": "describes"}],
} if {
	count_of("subject") == 0
}

# --- the document disagrees with the tree ------------------------------------

# The lockfile's own lines, or NOTHING. Binding this separately is what keeps an
# unreadable lockfile out of the comparison below: a comprehension over an absent
# key yields an empty array, so a `declared` derived straight from
# `input.tree.lines` would read 0 and report every real count as drift. Undefined
# here leaves every rule that needs it abstaining, and the `missing` clause is
# what says so out loud.
lock_lines := input.tree.lines[lockfile]

# The lockfile entries that predict a purl: a `source` key means a registry or git
# dependency. Counted from the committed text, so the producer is not trusted for
# the number this whole clause is stated against.
declared := count([line |
	some line in lock_lines
	startswith(line, "source = ")
])

# COMPUTED, NEVER HARDCODED. The issue that specified this recorded 156 cargo and
# 175 total, and the total had already moved by 2 a day later as the workflow
# actions changed. A pinned number would fail on a true tree; the relation is the
# invariant.
#
# Each format is counted separately because they render purls differently, so a
# regression in one renderer is invisible to a gate that only ever reads the other.
violation contains {
	"rule": "sbom-package-drift",
	"verdict": "manifest count wrong",
	"subjects": [{"path": lockfile}, {"count": count_of(format)}],
} if {
	# THE LOCKFILE WAS READ, and this guard is NOT redundant with `lock_lines`
	# being undefined — measured by `test_an_unreadable_lockfile_reports_no_drift`,
	# which was red without it. A Rego comprehension whose body references an
	# undefined variable yields an EMPTY array rather than undefined, so `declared`
	# still resolves to 0 and every honest count reads as drift against a file
	# nobody opened. Binding the lines separately was not enough; the rule has to
	# demand them.
	is_array(lock_lines)
	some format in ["spdx-cargo", "cdx-cargo"]
	count_of(format) != 0
	count_of(format) != declared
}

# ONE ENTRY PER THING DEPENDED ON (CLOUD-664). syft emits a component per
# REFERENCE SITE, so the document once claimed 340 entries for 290 distinct
# things: 57 `pkg:github` entries for 9 unique actions, plus a `./action`
# component that is a relative path in this repository rather than a dependency of
# it. `sbom.sh` normalises that; this keeps it normalised, and it is deliberately a
# property of the DOCUMENT rather than of the normaliser — a cataloger that starts
# emitting a new inflated shape is caught without anyone having predicted which.
violation contains {
	"rule": "sbom-components-inflated",
	"verdict": "manifest count wrong",
	"subjects": [{"count": count_of("entries")}],
} if {
	count_of("entries") != count_of("distinct")
}

violation contains {
	"rule": "sbom-components-inflated",
	"verdict": "manifest count wrong",
	"subjects": [{"count": count_of(shape)}],
} if {
	some shape in ["pathlike", "unversioned"]
	count_of(shape) != 0
}

# --- fields the tree states and the document does not ------------------------

# `supplier` is who DISTRIBUTED the package, which the lockfile's resolution
# states, and `originator` is who WROTE it, which `cargo metadata`'s `authors`
# answers or honestly does not. Both halves are counted, because a supplier count
# alone cannot tell an originator that agrees with the manifest from one copied
# out of the supplier field — the agreement is what makes the two fields mean
# different things.
#
# Pointer-only matters more here than anywhere else in this module: an `authors`
# entry is a personal name and often an email address, so the finding carries
# counts and never a value.
violation contains {
	"rule": "sbom-supplier-unset",
	"verdict": "manifest state missing",
	"subjects": [{"count": count_of(field)}],
} if {
	some field in ["nosupplier", "originator-disagrees", "subject-unset"]
	count_of(field) != 0
}

# `copyrightText` has no source in `cargo metadata` at all — it is read from the
# bytes `Cargo.lock` pins by checksum. The producer writes one of exactly two
# values and never NOASSERTION: an anchored holder line where the pinned sources
# carry one, and `NONE` where every pinned byte was searched and none does.
# Measured against `sbomcheck` 5.0.3, `NONE` is conformant and `NOASSERTION` is
# not, so only the third state is refused here.
#
# This field needs pointer-only more than any other: a copyright statement is a
# personal name, so echoing the value would publish names into every CI log.
violation contains {
	"rule": "sbom-copyright-unenriched",
	"verdict": "manifest state missing",
	"subjects": [{"count": count_of("copyright-unset")}],
} if {
	count_of("copyright-unset") != 0
}

# `cargo metadata` reports a license for every package in this tree and
# `cargo-deny` already gates those same expressions, so this is the one field
# whose data was authoritative all along and simply unused by the document. The
# slash count is the second half: the deprecated cargo spelling is not a valid
# SPDX expression, so one reaching the document unrewritten is an unparseable
# field rather than a missing one — worse than an honest NOASSERTION, in a field
# whose whole purpose is to be parsed.
violation contains {
	"rule": "sbom-license-unenriched",
	"verdict": "manifest state missing",
	"subjects": [{"count": count_of(field)}],
} if {
	some field in ["license-unset", "license-slashed"]
	count_of(field) != 0
}

# Every `pkg:github` component carries both a license and a copyright.
violation contains {
	"rule": "sbom-action-unenriched",
	"verdict": "manifest state missing",
	"subjects": [{"count": count_of("action-unset")}],
} if {
	count_of("action-unset") != 0
}

# --- the pinned actions, decided from committed text -------------------------

# Every workflow line carrying a SHA-pinned `uses:`.
#
# A MATCH TEST RATHER THAN A CAPTURE, which is forced rather than chosen: this
# build carries `regex.match` and nothing that returns submatches — every other
# module here reaches for the same one, and `shell-retirement.rego` says so at its
# own site ("`indexof` plus a NAME TEST rather than a capture"). So the reference
# is never extracted; the question is asked the other way round below.
#
# The pattern is a `[[pattern]]` row rather than an inline regex, which the loader
# refuses outright: one concept, one spelling.
pinned contains line if {
	some file, lines in input.tree.lines
	startswith(file, ".github/workflows/")
	some line in lines
	regex.match(data.batten.patterns["sbom-action-pin"], line)
}

# The table's own lines, or NOTHING — `lock_lines`' reason exactly. An absent
# table would leave `mapped` empty and report every pin as unmapped, which is the
# could-not-look answer dressed as a finding.
table_lines := input.tree.lines[actions_table]

# The key column, one per row. The table is TSV and its key is spelled exactly as
# a `uses:` line spells the reference, which is what lets the containment test
# below stand in for the extraction this build cannot do.
keys contains key if {
	some row in table_lines
	key := trim_space(split(row, "\t")[0])
	key != ""
}

# A pinned line whose reference some row declares. Matched on repo AND sha
# together, because the key carries both — a table row whose sha is stale does not
# match the line that moved, which is exactly the drift this detects.
mapped contains line if {
	some line in pinned
	some key in keys
	contains(line, key)
}

# THE DRIFT DETECTOR, and the reason a committed table is defensible at all. A
# pinned action's license is immutable, so recording it is a property of this
# commit — but only while the table still describes the pins the workflows carry.
# This fires on the one event that breaks that: a pin moving. A renovate bump that
# does not record the new commit's license fails rather than silently degrading
# the document.
#
# Matched on repo AND sha together, because a table row whose sha is stale is
# exactly the drift.
violation contains {
	"rule": "sbom-action-unmapped",
	"verdict": "pin table missing",
	"subjects": [{"path": actions_table}, {"count": count(unmapped)}],
} if {
	count(unmapped) > 0
}

# POINTER-ONLY: a count and the table's path. The `uses:` line itself carries a
# repository name and a sha, and the finding names neither.
unmapped contains line if {
	# The table was READ, or this is could-not-look rather than a tree where
	# nothing is mapped.
	is_array(table_lines)
	some line in pinned
	not line in mapped
}

# COULD NOT LOOK IS A FINDING, NOT SILENCE. A declared source that would not parse
# belongs in `input.tree.missing`, and a module that iterates only what it could
# read reports green over a file it never opened.
violation contains {
	"rule": "sbom-unrecorded",
	"verdict": "tool read broken",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE composes the
# `tool-verdict` key from the tool, its pin and the input's digest, nor that it
# fills `input.tree.lines` for the two declared sources — a `with input as` case
# fabricates the very shape the engine may be unable to produce (CLOUD-845,
# CLOUD-857). `crates/batten/tests/it/sbom_inventory.rs` is that tier.

recorded(verdict) := {"tree": {
	"tool-verdict": {"sbom": verdict},
	"lines": {"Cargo.lock": [], "mise-tasks/sbom-actions.tsv": []},
	"missing": {},
}}

# A scan agreeing with a two-entry lockfile, every field enriched.
clean := {
	"spdx-cargo": "2",
	"cdx-cargo": "2",
	"spdx-stable": "yes",
	"cdx-stable": "yes",
	"subject": "1",
	"entries": "2",
	"distinct": "2",
	"pathlike": "0",
	"unversioned": "0",
	"nosupplier": "0",
	"originator-disagrees": "0",
	"subject-unset": "0",
	"copyright-unset": "0",
	"license-unset": "0",
	"license-slashed": "0",
	"action-unset": "0",
}

# The same, over a lockfile whose sourced entries the counts agree with.
tree(verdict) := {"tree": {
	"tool-verdict": {"sbom": verdict},
	"lines": {
		"Cargo.lock": ["source = \"registry+one\"", "source = \"registry+two\""],
		"mise-tasks/sbom-actions.tsv": [],
	},
	"missing": {},
}}

test_a_clean_scan_agreeing_with_the_lockfile_is_clean if {
	count(violation) == 0 with input as tree(clean)
}

test_a_cargo_count_that_disagrees_with_the_lockfile_is_refused if {
	some v in violation with input as tree(object.union(clean, {"spdx-cargo": "3"}))
	v.verdict == "manifest count wrong"
}

# THE OTHER RENDERER. A gate reading only SPDX is blind to a CycloneDX regression.
test_the_cyclonedx_count_is_judged_too if {
	some v in violation with input as tree(object.union(clean, {"cdx-cargo": "5"}))
	v.verdict == "manifest count wrong"
}

test_an_empty_catalog_is_never_read_as_agreement if {
	some v in violation with input as tree(object.union(clean, {"spdx-cargo": "0", "cdx-cargo": "0"}))
	v.verdict == "tool read broken"
}

# AN EMPTY CATALOG MUST NOT ALSO READ AS DRIFT: the count is zero against a
# two-entry lockfile, and reporting both would send the author after a cataloger
# and a normaliser at once. `sbom-empty` owns it.
test_an_empty_catalog_is_not_also_reported_as_drift if {
	ids := {v.rule | some v in violation} with input as tree(object.union(clean, {"spdx-cargo": "0", "cdx-cargo": "0"}))
	not "sbom-package-drift" in ids
}

test_two_scans_that_disagree_are_refused if {
	some v in violation with input as tree(object.union(clean, {"spdx-stable": "no"}))
	v.rule == "sbom-unstable"
}

test_an_inflated_component_set_is_refused if {
	some v in violation with input as tree(object.union(clean, {"distinct": "1"}))
	v.rule == "sbom-components-inflated"
}

test_a_pathlike_component_is_refused if {
	some v in violation with input as tree(object.union(clean, {"pathlike": "1"}))
	v.rule == "sbom-components-inflated"
}

test_a_document_describing_nothing_is_could_not_look if {
	some v in violation with input as tree(object.union(clean, {"subject": "0"}))
	v.verdict == "tool read broken"
}

test_an_unset_supplier_is_refused if {
	some v in violation with input as tree(object.union(clean, {"nosupplier": "4"}))
	v.rule == "sbom-supplier-unset"
}

# THE AGREEMENT HALF, which a supplier count alone cannot see.
test_an_originator_disagreeing_with_the_manifest_is_refused if {
	some v in violation with input as tree(object.union(clean, {"originator-disagrees": "1"}))
	v.rule == "sbom-supplier-unset"
}

test_an_unset_copyright_is_refused if {
	some v in violation with input as tree(object.union(clean, {"copyright-unset": "7"}))
	v.rule == "sbom-copyright-unenriched"
}

test_a_slash_form_license_is_refused if {
	some v in violation with input as tree(object.union(clean, {"license-slashed": "1"}))
	v.rule == "sbom-license-unenriched"
}

test_an_unenriched_action_is_refused if {
	some v in violation with input as tree(object.union(clean, {"action-unset": "2"}))
	v.rule == "sbom-action-unenriched"
}

# --- the pinned actions, over committed text rather than a record --------------

# A workflow and a table, so the pin clauses have something to decide over.
workflows(uses, rows) := {"tree": {
	"tool-verdict": {"sbom": clean},
	"lines": {
		"Cargo.lock": ["source = \"registry+one\"", "source = \"registry+two\""],
		"mise-tasks/sbom-actions.tsv": rows,
		".github/workflows/ci.yml": uses,
	},
	"missing": {},
}}

pin := "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7"

table_row := "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\tMIT\tGitHub"

test_a_pin_the_table_declares_is_clean if {
	count(violation) == 0 with input as workflows([pin], [table_row])
}

# THE DRIFT DETECTOR: a bump moves the sha, the table's row no longer matches the
# line, and the gate fires rather than degrading the document silently.
test_a_pin_with_no_table_row_is_refused if {
	some v in violation with input as workflows([pin], [])
	v.rule == "sbom-action-unmapped"
}

# A STALE SHA IS THE DRIFT, so a row naming the same repository at a different
# commit must not satisfy the pin.
test_a_row_naming_a_different_sha_does_not_map_the_pin if {
	some v in violation with input as workflows(
		[pin],
		["actions/checkout@0000000000000000000000000000000000000000\tMIT\tGitHub"],
	)
	v.rule == "sbom-action-unmapped"
}

# ANTI-VACUITY: a workflow line that is not a SHA-pinned `uses:` is not a pin, so
# the clause cannot be satisfied by matching every line in every workflow.
test_an_unpinned_uses_is_not_read_as_a_pin if {
	count(violation) == 0 with input as workflows(["      - uses: ./.github/actions/local", "    name: build"], [])
}

# COULD NOT READ THE TABLE is not "nothing is mapped". Without the guard this
# reports every pin in the tree as drift on a checkout that never read the file.
test_an_unreadable_table_reports_no_pin_as_unmapped if {
	ids := {v.rule | some v in violation} with input as {"tree": {
		"tool-verdict": {"sbom": clean},
		"lines": {
			"Cargo.lock": ["source = \"registry+one\"", "source = \"registry+two\""],
			".github/workflows/ci.yml": [pin],
		},
		"missing": {},
	}}
	not "sbom-action-unmapped" in ids
}

# COULD NOT READ THE LOCKFILE is not "zero sourced entries". Without `lock_lines`
# the comprehension yields 0 and every honest count reads as drift.
test_an_unreadable_lockfile_reports_no_drift if {
	ids := {v.rule | some v in violation} with input as {"tree": {
		"tool-verdict": {"sbom": clean},
		"lines": {"mise-tasks/sbom-actions.tsv": []},
		"missing": {},
	}}
	not "sbom-package-drift" in ids
}

# NOTHING HAS SCANNED THESE BYTES is not a verdict: the id is absent from the map,
# so there is nothing to refuse and a checkout whose globs never fired is clean.
test_an_unrecorded_scan_is_not_refused if {
	count(violation) == 0 with input as {"tree": {
		"tool-verdict": {},
		"lines": {"Cargo.lock": [], "mise-tasks/sbom-actions.tsv": []},
		"missing": {},
	}}
}

# PRESENT AND EMPTY is the producer having written nothing, which would let every
# count above pass over an absent key.
test_a_recorded_but_empty_scan_is_refused if {
	some v in violation with input as recorded({})
	v.rule == "sbom-unrecorded"
}

# COULD-NOT-LOOK, and without the `is_object` guard this case would fault rather
# than fail, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {
		"tool-verdict": null,
		"lines": {"Cargo.lock": [], "mise-tasks/sbom-actions.tsv": []},
		"missing": {},
	}}
}

# A SIBLING ROW'S RECORD IS NOT THIS MODULE'S TO JUDGE. `input.tree["tool-verdict"]`
# is built from every `[[rule.tools]]` row in the config, so a record of another
# shape reaches this module too — measured on `validator-verdict-clean`, where
# `hk-plan`'s per-step lines were read as seven findings over a clean tree.
test_another_rows_record_is_not_read_as_a_finding if {
	count(violation) == 0 with input as {"tree": {
		"tool-verdict": {"hk-plan": {"batten-check": "included"}},
		"lines": {"Cargo.lock": [], "mise-tasks/sbom-actions.tsv": []},
		"missing": {},
	}}
}

# A SOURCE THAT WOULD NOT PARSE is reported rather than skipped.
test_a_source_that_could_not_be_read_is_reported if {
	some v in violation with input as {"tree": {
		"tool-verdict": {},
		"lines": {},
		"missing": {"Cargo.lock": "Unparsed"},
	}}
	v.verdict == "tool read broken"
}

#MUTANT-SUITE crates/batten/tests/it/sbom_inventory.rs
#MUTANT package-drift-unread|s@^\tcount_of(format) != declared$@\tfalse@|a_drifted_cargo_count_is_refused_over_the_real_lockfile
